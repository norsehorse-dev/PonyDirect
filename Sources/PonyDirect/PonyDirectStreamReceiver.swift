// PonyDirectStreamReceiver.swift
// Receiver half of the stream ARQ: reassembles SDATA payloads into an in-order byte stream and
// reports the SACK state (cumulative ack + selective ranges + receive window) the sender needs.
//
// The engine sends SDATA chunk-aligned (each at a 1024-byte offset), so reassembly is indexed by
// chunk. The wire stays byte-offset, so this is an engine choice, not a protocol one. Pure logic,
// no I/O and no timers, so it is exhaustively testable against loss, reordering and duplication.
// Byte-identical intent to the Kotlin twin.

import Foundation

public final class PonyDirectStreamReceiver {

    private let chunk = Int64(PonyDirectStream.maxPayload)  // 1024
    private let capacity: Int

    private var nextChunk: Int64 = 0        // next in-order chunk index still needed
    private var deliveredBytes: Int64 = 0   // total bytes handed in order to the readable queue
    private var bufferedBytes = 0           // out-of-order bytes held above nextChunk
    private var buffered: [Int64: Data] = [:]
    private var readable: [Data] = []
    private var readHead = 0
    private var finalSeq: Int64?

    public init(capacity: Int = 1 << 20) { self.capacity = capacity }

    /// Integrate one SDATA payload at byte offset `seq`. Ignores duplicates, old and non-aligned.
    public func onData(seq: UInt64, payload: Data) {
        if payload.isEmpty { return }
        let s = Int64(seq)
        if s % chunk != 0 { return }
        let idx = s / chunk
        if idx < nextChunk || buffered[idx] != nil { return }
        if (idx - nextChunk) * chunk >= Int64(capacity) { return }   // beyond the receive window
        buffered[idx] = payload
        bufferedBytes += payload.count
        while let p = buffered[nextChunk] {
            buffered[nextChunk] = nil
            bufferedBytes -= p.count
            readable.append(p)
            deliveredBytes += Int64(p.count)
            nextChunk += 1
        }
    }

    public func onFin(finalSeq: UInt64) { self.finalSeq = Int64(finalSeq) }

    /// True once every byte up to the sender's FIN has been delivered in order.
    public func isComplete() -> Bool { if let f = finalSeq { return deliveredBytes >= f }; return false }

    /// Drain up to `max` in-order bytes for the app.
    public func read(_ max: Int) -> Data {
        var out = Data()
        var need = max
        while need > 0, let head = readable.first {
            let avail = head.count - readHead
            let take = Swift.min(need, avail)
            out.append(contentsOf: head.dropFirst(readHead).prefix(take))
            readHead += take; need -= take
            if readHead == head.count { readable.removeFirst(); readHead = 0 }
        }
        return out
    }

    public func cumAck() -> UInt64 { UInt64(deliveredBytes) }
    public func rwnd() -> UInt32 { UInt32(Swift.max(0, capacity - readableBytes() - bufferedBytes)) }

    /// Selective-ack ranges [start, end) in byte offsets, one per contiguous run of buffered chunks.
    public func sackBlocks() -> [PonyDirectStream.SackBlock] {
        if buffered.isEmpty { return [] }
        let idxs = buffered.keys.sorted()
        var blocks: [PonyDirectStream.SackBlock] = []
        var i = 0
        while i < idxs.count && blocks.count < PonyDirectStream.maxSackBlocks {
            let startChunk = idxs[i]
            var j = i
            var bytes: Int64 = 0
            while j < idxs.count && idxs[j] == startChunk + Int64(j - i) { bytes += Int64(buffered[idxs[j]]!.count); j += 1 }
            let startByte = UInt64(startChunk * chunk)
            blocks.append(PonyDirectStream.SackBlock(start: startByte, end: startByte + UInt64(bytes)))
            i = j
        }
        return blocks
    }

    private func readableBytes() -> Int { var t = -readHead; for c in readable { t += c.count }; return t }
}
