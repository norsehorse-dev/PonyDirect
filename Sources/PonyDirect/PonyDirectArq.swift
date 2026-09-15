// PonyDirectArq.swift
// The reliable-datagram codec for the WAN path: a payload larger than one UDP
// datagram is split into authenticated DATA chunks; the receiver ACKs a bitmap of
// what it has and the sender retransmits the gaps. Pure byte functions built on
// PonyDirectWire's per-pair tags; the state machine lives in PonyDirectWan. Must
// stay byte-identical to the Kotlin twin.

import Foundation

public enum PonyDirectArq {

    public enum Packet: UInt8 {
        case data = 0x14   // one chunk of a message
        case ack = 0x15    // bitmap of received chunks for a message
    }

    /// Max bytes of application payload per DATA chunk. Kept well under a safe path
    /// MTU (~1200) after the 25-byte header and 32-byte tag.
    public static let maxChunkPayload = 1024

    // MARK: DATA  = type(1) | sessionNonce(16) | msgSeq(4) | chunkIndex(2) | chunkCount(2) | payload | tag(32)

    public static func data(pairKey: Data, sessionNonce: Data, msgSeq: UInt32,
                            chunkIndex: UInt16, chunkCount: UInt16, payload: Data) -> Data {
        let header = sessionNonce + u32(msgSeq) + u16(chunkIndex) + u16(chunkCount)
        let tag = PonyDirectWire.dataTag(pairKey: pairKey, header: header, payload: payload)
        var out = Data([Packet.data.rawValue]); out.append(header); out.append(payload); out.append(tag)
        return out
    }

    public struct DataPacket {
        public let sessionNonce: Data
        public let msgSeq: UInt32
        public let chunkIndex: UInt16
        public let chunkCount: UInt16
        public let payload: Data
        fileprivate let header: Data
        fileprivate let tag: Data
    }

    public static func parseData(_ d: Data) -> DataPacket? {
        let b = [UInt8](d)
        guard b.count >= 1 + 24 + 32, b[0] == Packet.data.rawValue else { return nil }
        let payloadEnd = b.count - 32
        guard payloadEnd >= 25 else { return nil }
        return DataPacket(
            sessionNonce: Data(b[1..<17]),
            msgSeq: readU32(b, 17),
            chunkIndex: readU16(b, 21),
            chunkCount: readU16(b, 23),
            payload: Data(b[25..<payloadEnd]),
            header: Data(b[1..<25]),
            tag: Data(b[payloadEnd..<b.count])
        )
    }

    public static func verifyData(_ p: DataPacket, pairKey: Data) -> Bool {
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.dataTag(pairKey: pairKey, header: p.header, payload: p.payload))
    }

    // MARK: ACK  = type(1) | sessionNonce(16) | msgSeq(4) | chunkCount(2) | bitmap | tag(32)

    public static func ack(pairKey: Data, sessionNonce: Data, msgSeq: UInt32,
                           chunkCount: UInt16, bitmap: Data) -> Data {
        let header = sessionNonce + u32(msgSeq) + u16(chunkCount)
        let tag = PonyDirectWire.ackTag(pairKey: pairKey, header: header, bitmap: bitmap)
        var out = Data([Packet.ack.rawValue]); out.append(header); out.append(bitmap); out.append(tag)
        return out
    }

    public struct AckPacket {
        public let sessionNonce: Data
        public let msgSeq: UInt32
        public let chunkCount: UInt16
        public let bitmap: Data
        fileprivate let header: Data
        fileprivate let tag: Data
    }

    public static func parseAck(_ d: Data) -> AckPacket? {
        let b = [UInt8](d)
        guard b.count >= 1 + 22 + 32, b[0] == Packet.ack.rawValue else { return nil }
        let chunkCount = readU16(b, 21)
        let bitmapLen = Int((Int(chunkCount) + 7) / 8)
        guard b.count == 1 + 22 + bitmapLen + 32 else { return nil }
        return AckPacket(
            sessionNonce: Data(b[1..<17]),
            msgSeq: readU32(b, 17),
            chunkCount: chunkCount,
            bitmap: Data(b[23..<23 + bitmapLen]),
            header: Data(b[1..<23]),
            tag: Data(b[23 + bitmapLen..<b.count])
        )
    }

    public static func verifyAck(_ p: AckPacket, pairKey: Data) -> Bool {
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.ackTag(pairKey: pairKey, header: p.header, bitmap: p.bitmap))
    }

    // MARK: Bitmap + chunking helpers

    public static func bitmapLen(chunkCount: Int) -> Int { (chunkCount + 7) / 8 }

    public static func bitmapSet(_ bitmap: inout Data, _ index: Int) {
        let byte = index / 8, bit = index % 8
        guard byte < bitmap.count else { return }
        bitmap[bitmap.startIndex + byte] |= UInt8(1 << bit)
    }

    public static func bitmapGet(_ bitmap: Data, _ index: Int) -> Bool {
        let byte = index / 8, bit = index % 8
        guard byte < bitmap.count else { return false }
        return (bitmap[bitmap.startIndex + byte] & UInt8(1 << bit)) != 0
    }

    /// Split a payload into <= maxChunkPayload-byte chunks (at least one, empty ok).
    public static func chunk(_ payload: Data, max: Int = maxChunkPayload) -> [Data] {
        if payload.isEmpty { return [Data()] }
        var out: [Data] = []
        var i = payload.startIndex
        while i < payload.endIndex {
            let end = payload.index(i, offsetBy: max, limitedBy: payload.endIndex) ?? payload.endIndex
            out.append(payload.subdata(in: i..<end))
            i = end
        }
        return out
    }

    // MARK: private byte helpers
    private static func u32(_ v: UInt32) -> Data { var b = v.bigEndian; return withUnsafeBytes(of: &b) { Data($0) } }
    private static func u16(_ v: UInt16) -> Data { var b = v.bigEndian; return withUnsafeBytes(of: &b) { Data($0) } }
    private static func readU32(_ b: [UInt8], _ i: Int) -> UInt32 {
        (UInt32(b[i]) << 24) | (UInt32(b[i+1]) << 16) | (UInt32(b[i+2]) << 8) | UInt32(b[i+3])
    }
    private static func readU16(_ b: [UInt8], _ i: Int) -> UInt16 { (UInt16(b[i]) << 8) | UInt16(b[i+1]) }
}
