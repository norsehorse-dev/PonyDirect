// PonyDirectStreamSender.swift
// Sender half of the stream ARQ, with congestion control. Chunk-aligned windowed send over the
// outgoing byte buffer:
//   - RFC 6298 RTO retransmit (Karn's algorithm: no RTT sample on retransmits).
//   - Congestion window: slow start (exponential) up to ssthresh, then AIMD congestion avoidance
//     (about one MSS per RTT). A timeout halves ssthresh and restarts slow start at one MSS.
//   - Packet pacing: a token bucket at cwnd/srtt spreads a window across the RTT instead of bursting.
//   - Receiver flow control (rwnd): the effective window is min(cwnd, rwnd).
// Crypto-free: it emits (seq, payload) segments and a FIN marker, so it composes with
// PonyDirectStreamReceiver in tests and the driver builds the wire frames. Byte-identical intent to
// the Kotlin twin.

import Foundation

/// One thing the sender wants to put on the wire. The driver turns these into SDATA / SFIN frames.
public enum StreamOut {
    case data(seq: UInt64, payload: Data)
    case fin(finalSeq: UInt64)
}

public final class PonyDirectStreamSender {

    private let chunk = Int64(PonyDirectStream.maxPayload)   // 1024
    private let maxCwndBytes: Int
    private let minRtoMs: Int64
    private let maxRtoMs: Int64

    private var data = Data()
    private var finished = false

    private var baseChunk: Int64 = 0
    private var acked = Set<Int64>()
    private final class InFlight { var sentAt: Int64; var retransmitted: Bool
        init(_ sentAt: Int64, _ retransmitted: Bool) { self.sentAt = sentAt; self.retransmitted = retransmitted } }
    private var inflight: [Int64: InFlight] = [:]

    private var rwndBytes = 1 << 20

    private var cwnd: Int
    private var ssthresh: Int
    private var lastLossMs: Int64? = nil

    private var pacingTokens: Double
    private var lastPollMs: Int64 = .min

    private var rtoMs: Int64
    private var srtt = -1.0
    private var rttvar = 0.0

    public var cwndBytes: Int { cwnd }
    public var ssthreshBytes: Int { ssthresh }

    public init(initialCwndBytes: Int = 10 * PonyDirectStream.maxPayload,
                initialSsthreshBytes: Int = 64 * PonyDirectStream.maxPayload,
                maxCwndBytes: Int = 4 * 1024 * 1024,
                minRtoMs: Int64 = 200, maxRtoMs: Int64 = 10_000, initialRtoMs: Int64 = 1000) {
        self.cwnd = initialCwndBytes
        self.ssthresh = initialSsthreshBytes
        self.maxCwndBytes = maxCwndBytes
        self.minRtoMs = minRtoMs
        self.maxRtoMs = maxRtoMs
        self.rtoMs = initialRtoMs
        self.pacingTokens = Double(initialCwndBytes)
    }

    public func write(_ bytes: Data) { precondition(!finished, "already finished"); data.append(bytes) }
    public func finish() { finished = true }

    private func chunksReady() -> Int64 {
        let n = Int64(data.count)
        return finished ? (n + chunk - 1) / chunk : n / chunk
    }
    private func chunkBytes(_ i: Int64) -> Data {
        let start = Int(i * chunk)
        let end = Swift.min(start + Int(chunk), data.count)
        return data.subdata(in: start..<end)
    }
    private func totalBytes() -> Int64 { Int64(data.count) }

    public func isDone() -> Bool { finished && baseChunk >= chunksReady() }

    public func poll(_ nowMs: Int64) -> [StreamOut] {
        refillTokens(nowMs)
        var out: [StreamOut] = []
        let windowChunks = Int64(Swift.max(1, Swift.min(cwnd, rwndBytes) / Int(chunk)))
        let ready = chunksReady()
        let last = Swift.min(baseChunk + windowChunks, ready)
        var i = baseChunk
        while i < last {
            if !acked.contains(i) {
                if let inf = inflight[i] {
                    if nowMs - inf.sentAt >= rtoMs {
                        onLoss(nowMs)
                        out.append(.data(seq: UInt64(i * chunk), payload: chunkBytes(i)))
                        inf.sentAt = nowMs
                        inf.retransmitted = true
                        rtoMs = Swift.min(rtoMs * 2, maxRtoMs)     // exponential backoff on timeout
                    }
                } else {
                    if pacingTokens < Double(chunk) { break }      // paced out; remaining are new/acked
                    out.append(.data(seq: UInt64(i * chunk), payload: chunkBytes(i)))
                    inflight[i] = InFlight(nowMs, false)
                    pacingTokens -= Double(chunk)
                }
            }
            i += 1
        }
        if finished && baseChunk >= ready { out.append(.fin(finalSeq: UInt64(totalBytes()))) }
        return out
    }

    public func onAck(_ nowMs: Int64, cumAck: UInt64, rwnd: UInt32, blocks: [PonyDirectStream.SackBlock]) {
        rwndBytes = Int(rwnd)
        var newlyAcked = 0
        let ready = chunksReady()
        let cum = Int64(cumAck)
        let newBase = (finished && cum >= totalBytes()) ? ready : cum / chunk
        var i = baseChunk
        while i < newBase { acked.remove(i); if ackChunk(i, nowMs) { newlyAcked += Int(chunk) }; i += 1 }
        baseChunk = Swift.max(baseChunk, newBase)
        for b in blocks {
            let first = Int64(b.start) / chunk
            let count = (Int64(b.end) - Int64(b.start) + chunk - 1) / chunk
            var k = first
            while k < first + count {
                if k >= baseChunk && !acked.contains(k) { if ackChunk(k, nowMs) { newlyAcked += Int(chunk) }; acked.insert(k) }
                k += 1
            }
        }
        while acked.contains(baseChunk) { acked.remove(baseChunk); baseChunk += 1 }
        if newlyAcked > 0 { grow(newlyAcked) }
    }

    /// Returns true if this chunk was outstanding (genuinely newly acked).
    private func ackChunk(_ i: Int64, _ nowMs: Int64) -> Bool {
        guard let inf = inflight.removeValue(forKey: i) else { return false }
        if !inf.retransmitted { sampleRtt(nowMs - inf.sentAt) }   // Karn: skip retransmits
        return true
    }

    private func grow(_ newlyAckedBytes: Int) {
        if cwnd < ssthresh { cwnd += newlyAckedBytes }                                  // slow start
        else { cwnd += Swift.max(1, Int(chunk) * newlyAckedBytes / cwnd) }              // congestion avoidance
        if cwnd > maxCwndBytes { cwnd = maxCwndBytes }
    }

    private func onLoss(_ nowMs: Int64) {
        let guard0 = srtt > 0 ? srtt : 1000.0
        if let last = lastLossMs, Double(nowMs - last) < guard0 { return }   // one reduction per loss window
        ssthresh = Swift.max(cwnd / 2, 2 * Int(chunk))
        cwnd = Int(chunk)                                     // timeout: restart slow start at 1 MSS
        lastLossMs = nowMs
        if pacingTokens > Double(cwnd) { pacingTokens = Double(cwnd) }
    }

    private func refillTokens(_ nowMs: Int64) {
        if lastPollMs == .min { lastPollMs = nowMs; return }
        let dt = nowMs - lastPollMs
        if dt > 0 {
            let rtt = srtt > 0 ? srtt : 50.0
            let rate = Double(cwnd) / rtt
            pacingTokens = Swift.min(Double(cwnd), pacingTokens + rate * Double(dt))
            lastPollMs = nowMs
        }
    }

    private func sampleRtt(_ r: Int64) {
        let rd = Double(r)
        if srtt < 0 { srtt = rd; rttvar = rd / 2 }
        else { rttvar = 0.75 * rttvar + 0.25 * Swift.abs(srtt - rd); srtt = 0.875 * srtt + 0.125 * rd }
        rtoMs = Swift.min(Swift.max(Int64(srtt + 4 * rttvar), minRtoMs), maxRtoMs)
    }
}
