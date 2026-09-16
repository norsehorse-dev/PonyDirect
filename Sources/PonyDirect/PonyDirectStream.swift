// PonyDirectStream.swift
// The reliable-stream (bulk) codec for the WAN path: an ordered byte stream over the
// hole-punched UDP socket, for payloads too large for the message ARQ (files). Pure byte
// functions built on PonyDirectWire's per-pair stream tags; the sliding-window ARQ, flow
// control and congestion control that use them live in the stream engine. Must stay
// byte-identical to the Kotlin twin - see WIRE-PROTOCOL.md.
//
// Sequence numbers are byte offsets (8 bytes), so a stream can carry gigabytes without
// wrapping and a resumed transfer can name an exact offset.

import Foundation

public enum PonyDirectStream {

    public enum Packet: UInt8 {
        case data = 0x16   // a run of stream bytes at an offset
        case ack = 0x17    // cumulative ack + selective (SACK) ranges + receive window
        case fin = 0x18    // clean close of the sender's half
        case rst = 0x19    // abort
    }

    /// Max application bytes per SDATA datagram, same safe-MTU discipline as the message ARQ.
    public static let maxPayload = 1024
    /// Max SACK ranges carried in one SACK datagram.
    public static let maxSackBlocks = 16

    // MARK: SDATA = type(1) | sessionNonce(16) | seq(8) | len(2) | payload | tag(32)

    public static func data(pairKey: Data, sessionNonce: Data, seq: UInt64, payload: Data) -> Data {
        let header = sessionNonce + u64(seq) + u16(UInt16(payload.count))
        let tag = PonyDirectWire.streamDataTag(pairKey: pairKey, header: header, payload: payload)
        var out = Data([Packet.data.rawValue]); out.append(header); out.append(payload); out.append(tag)
        return out
    }

    public struct DataPacket {
        public let sessionNonce: Data
        public let seq: UInt64
        public let payload: Data
        fileprivate let header: Data
        fileprivate let tag: Data
    }

    public static func parseData(_ d: Data) -> DataPacket? {
        let b = [UInt8](d)
        guard b.count >= 1 + 26 + 32, b[0] == Packet.data.rawValue else { return nil }
        let len = Int(readU16(b, 25))
        guard b.count == 1 + 26 + len + 32 else { return nil }
        return DataPacket(sessionNonce: Data(b[1..<17]), seq: readU64(b, 17),
                          payload: Data(b[27..<27 + len]), header: Data(b[1..<27]),
                          tag: Data(b[27 + len..<b.count]))
    }

    public static func verifyData(_ p: DataPacket, pairKey: Data) -> Bool {
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.streamDataTag(pairKey: pairKey, header: p.header, payload: p.payload))
    }

    // MARK: SACK = type(1) | sessionNonce(16) | cumAck(8) | rwnd(4) | nblk(1) | nblk*[start(8) end(8)] | tag(32)

    public struct SackBlock: Equatable {
        public let start: UInt64
        public let end: UInt64
        public init(start: UInt64, end: UInt64) { self.start = start; self.end = end }
    }

    public static func ack(pairKey: Data, sessionNonce: Data, cumAck: UInt64, rwnd: UInt32, blocks: [SackBlock]) -> Data {
        let n = min(blocks.count, maxSackBlocks)
        let header = sessionNonce + u64(cumAck) + u32(rwnd) + Data([UInt8(n)])
        var blk = Data()
        for i in 0..<n { blk.append(u64(blocks[i].start)); blk.append(u64(blocks[i].end)) }
        let tag = PonyDirectWire.streamAckTag(pairKey: pairKey, header: header, blocks: blk)
        var out = Data([Packet.ack.rawValue]); out.append(header); out.append(blk); out.append(tag)
        return out
    }

    public struct AckPacket {
        public let sessionNonce: Data
        public let cumAck: UInt64
        public let rwnd: UInt32
        public let blocks: [SackBlock]
        fileprivate let header: Data
        fileprivate let blk: Data
        fileprivate let tag: Data
    }

    public static func parseAck(_ d: Data) -> AckPacket? {
        let b = [UInt8](d)
        guard b.count >= 1 + 29 + 32, b[0] == Packet.ack.rawValue else { return nil }
        let n = Int(b[29])
        let blkLen = n * 16
        guard b.count == 1 + 29 + blkLen + 32 else { return nil }
        var blocks: [SackBlock] = []
        var off = 30
        for _ in 0..<n { blocks.append(SackBlock(start: readU64(b, off), end: readU64(b, off + 8))); off += 16 }
        return AckPacket(sessionNonce: Data(b[1..<17]), cumAck: readU64(b, 17), rwnd: readU32(b, 25),
                         blocks: blocks, header: Data(b[1..<30]),
                         blk: Data(b[30..<30 + blkLen]), tag: Data(b[30 + blkLen..<b.count]))
    }

    public static func verifyAck(_ p: AckPacket, pairKey: Data) -> Bool {
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.streamAckTag(pairKey: pairKey, header: p.header, blocks: p.blk))
    }

    // MARK: SFIN = type(1) | sessionNonce(16) | finalSeq(8) | tag(32)

    public static func fin(pairKey: Data, sessionNonce: Data, finalSeq: UInt64) -> Data {
        let header = sessionNonce + u64(finalSeq)
        let tag = PonyDirectWire.streamFinTag(pairKey: pairKey, header: header)
        var out = Data([Packet.fin.rawValue]); out.append(header); out.append(tag)
        return out
    }

    public struct FinPacket {
        public let sessionNonce: Data
        public let finalSeq: UInt64
        fileprivate let header: Data
        fileprivate let tag: Data
    }

    public static func parseFin(_ d: Data) -> FinPacket? {
        let b = [UInt8](d)
        guard b.count == 1 + 24 + 32, b[0] == Packet.fin.rawValue else { return nil }
        return FinPacket(sessionNonce: Data(b[1..<17]), finalSeq: readU64(b, 17),
                         header: Data(b[1..<25]), tag: Data(b[25..<b.count]))
    }

    public static func verifyFin(_ p: FinPacket, pairKey: Data) -> Bool {
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.streamFinTag(pairKey: pairKey, header: p.header))
    }

    // MARK: SRST = type(1) | sessionNonce(16) | tag(32)

    public static func rst(pairKey: Data, sessionNonce: Data) -> Data {
        let tag = PonyDirectWire.streamRstTag(pairKey: pairKey, sessionNonce: sessionNonce)
        var out = Data([Packet.rst.rawValue]); out.append(sessionNonce); out.append(tag)
        return out
    }

    public struct RstPacket {
        public let sessionNonce: Data
        fileprivate let tag: Data
    }

    public static func parseRst(_ d: Data) -> RstPacket? {
        let b = [UInt8](d)
        guard b.count == 1 + 16 + 32, b[0] == Packet.rst.rawValue else { return nil }
        return RstPacket(sessionNonce: Data(b[1..<17]), tag: Data(b[17..<b.count]))
    }

    public static func verifyRst(_ p: RstPacket, pairKey: Data) -> Bool {
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.streamRstTag(pairKey: pairKey, sessionNonce: p.sessionNonce))
    }

    // MARK: private byte helpers
    private static func u64(_ v: UInt64) -> Data { var b = v.bigEndian; return withUnsafeBytes(of: &b) { Data($0) } }
    private static func u32(_ v: UInt32) -> Data { var b = v.bigEndian; return withUnsafeBytes(of: &b) { Data($0) } }
    private static func u16(_ v: UInt16) -> Data { var b = v.bigEndian; return withUnsafeBytes(of: &b) { Data($0) } }
    private static func readU64(_ b: [UInt8], _ i: Int) -> UInt64 { var v: UInt64 = 0; for k in 0..<8 { v = (v << 8) | UInt64(b[i+k]) }; return v }
    private static func readU32(_ b: [UInt8], _ i: Int) -> UInt32 { (UInt32(b[i]) << 24) | (UInt32(b[i+1]) << 16) | (UInt32(b[i+2]) << 8) | UInt32(b[i+3]) }
    private static func readU16(_ b: [UInt8], _ i: Int) -> UInt16 { (UInt16(b[i]) << 8) | UInt16(b[i+1]) }
}
