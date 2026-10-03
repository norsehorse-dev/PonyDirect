// PonyDirectStreamEngine.swift
// Ties the stream sender and receiver to the wire: builds SDATA/SFIN frames from the sender,
// dispatches and authenticates incoming SDATA/SACK/SFIN/SRST, and replies with SACKs. This is the
// driver core PonyDirectWan runs on its socket and timer; it is transport-agnostic (outgoing frames
// go through onDatagram), so it is testable end to end over a simulated wire. The blocking
// ByteReader/ByteWriter wrapper and the timer thread live with the real socket in the app driver.
// Byte-identical intent to the Kotlin twin.

import Foundation

public final class PonyDirectStreamEngine {

    private let pairKey: Data
    private let sessionNonce: Data
    private let onDatagram: (Data) -> Void
    private let sender = PonyDirectStreamSender()
    private let receiver = PonyDirectStreamReceiver()

    public init(pairKey: Data, sessionNonce: Data, onDatagram: @escaping (Data) -> Void) {
        self.pairKey = pairKey
        self.sessionNonce = sessionNonce
        self.onDatagram = onDatagram
    }

    public func write(_ bytes: Data) { sender.write(bytes) }
    public func finishSending() { sender.finish() }
    public func read(_ max: Int) -> Data { receiver.read(max) }
    public func sendComplete() -> Bool { sender.isDone() }
    /// Outbound bytes written but not yet acknowledged. A streaming writer waits for this to fall.
    public func sendBufferedBytes() -> Int64 { sender.bufferedBytes }
    public func recvComplete() -> Bool { receiver.isComplete() }

    /// Drive the sender: emit due SDATA/SFIN frames. Call on a timer.
    public func tick(_ nowMs: Int64) {
        for o in sender.poll(nowMs) {
            switch o {
            case let .data(seq, payload):
                onDatagram(PonyDirectStream.data(pairKey: pairKey, sessionNonce: sessionNonce, seq: seq, payload: payload))
            case let .fin(finalSeq):
                onDatagram(PonyDirectStream.fin(pairKey: pairKey, sessionNonce: sessionNonce, finalSeq: finalSeq))
            }
        }
    }

    /// Feed one received wire datagram. Ignores anything that fails auth or session binding.
    public func onWireDatagram(_ nowMs: Int64, _ d: Data) {
        guard let first = d.first else { return }
        switch first {
        case PonyDirectStream.Packet.data.rawValue:
            guard let p = PonyDirectStream.parseData(d), p.sessionNonce == sessionNonce,
                  PonyDirectStream.verifyData(p, pairKey: pairKey) else { return }
            receiver.onData(seq: p.seq, payload: p.payload)
            sendAck()
        case PonyDirectStream.Packet.fin.rawValue:
            guard let p = PonyDirectStream.parseFin(d), p.sessionNonce == sessionNonce,
                  PonyDirectStream.verifyFin(p, pairKey: pairKey) else { return }
            receiver.onFin(finalSeq: p.finalSeq)
            sendAck()
        case PonyDirectStream.Packet.ack.rawValue:
            guard let p = PonyDirectStream.parseAck(d), p.sessionNonce == sessionNonce,
                  PonyDirectStream.verifyAck(p, pairKey: pairKey) else { return }
            sender.onAck(nowMs, cumAck: p.cumAck, rwnd: p.rwnd, blocks: p.blocks)
        default:
            break     // SRST or unknown: nothing to tear down in the codec-level engine
        }
    }

    private func sendAck() {
        onDatagram(PonyDirectStream.ack(pairKey: pairKey, sessionNonce: sessionNonce,
                                        cumAck: receiver.cumAck(), rwnd: receiver.rwnd(), blocks: receiver.sackBlocks()))
    }
}
