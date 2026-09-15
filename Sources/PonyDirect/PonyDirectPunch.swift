// PonyDirectPunch.swift
// The UDP hole-punch datagram codec: authenticated PROBE / PONG / KEEPALIVE
// packets. Pure byte functions built on PonyDirectWire's per-pair tags; no sockets.
// Datagrams are self-delimiting, so unlike the TCP frame() there is no length
// prefix - just a one-byte type. Must stay byte-identical to the Kotlin twin.

import Foundation

/// Byte layout of the three control datagrams a hole-punch exchanges. The peers
/// have already agreed a `sessionNonce` over sealed signaling; every datagram
/// carries it so a receiver can bind the packet to the right session, and the tag
/// authenticates it with the per-pair key so an off-path or spoofing attacker can
/// neither forge a probe/pong nor hijack the path.
public enum PonyDirectPunch {

    /// UDP datagram type byte (distinct range from the TCP Frame bytes).
    public enum Packet: UInt8 {
        case probe = 0x11      // prober -> peer: "are you there, and it's really me"
        case pong = 0x12       // peer -> prober: "yes, and it's really me"
        case keepalive = 0x13  // either -> either: hold the NAT mapping open
    }

    public static let nonceLen = 16
    public static let tagLen = 32
    // type(1) | sessionNonce(16) | probeNonce(16) | tag(32)
    public static let probeLen = 1 + 16 + 16 + 32
    public static let pongLen = 1 + 16 + 16 + 32
    // type(1) | sessionNonce(16)
    public static let keepaliveLen = 1 + 16

    /// Build a PROBE. `probeNonce` is fresh per probe; keep it to match the PONG.
    public static func probe(pairKey: Data, sessionNonce: Data, probeNonce: Data) -> Data {
        var out = Data([Packet.probe.rawValue])
        out.append(sessionNonce)
        out.append(probeNonce)
        out.append(PonyDirectWire.probeTag(pairKey: pairKey, sessionNonce: sessionNonce, probeNonce: probeNonce))
        return out
    }

    /// Build the PONG that answers a PROBE carrying `probeNonce`.
    public static func pong(pairKey: Data, sessionNonce: Data, probeNonce: Data) -> Data {
        var out = Data([Packet.pong.rawValue])
        out.append(sessionNonce)
        out.append(probeNonce)
        out.append(PonyDirectWire.pongTag(pairKey: pairKey, sessionNonce: sessionNonce, probeNonce: probeNonce))
        return out
    }

    public static func keepalive(sessionNonce: Data) -> Data {
        var out = Data([Packet.keepalive.rawValue])
        out.append(sessionNonce)
        return out
    }

    public struct Parsed {
        public let type: Packet
        public let sessionNonce: Data
        public let probeNonce: Data   // empty for keepalive
        public let tag: Data          // empty for keepalive
    }

    /// Split a datagram into its fields without verifying the tag. Returns nil on any
    /// length/type error. Callers verify with `verifyProbe` / `verifyPong`.
    public static func parse(_ data: Data) -> Parsed? {
        guard let first = data.first, let type = Packet(rawValue: first) else { return nil }
        let b = [UInt8](data)
        switch type {
        case .probe, .pong:
            guard b.count == probeLen else { return nil }
            let session = Data(b[1..<17])
            let nonce = Data(b[17..<33])
            let tag = Data(b[33..<65])
            return Parsed(type: type, sessionNonce: session, probeNonce: nonce, tag: tag)
        case .keepalive:
            guard b.count == keepaliveLen else { return nil }
            return Parsed(type: type, sessionNonce: Data(b[1..<17]), probeNonce: Data(), tag: Data())
        }
    }

    /// Verify a parsed PROBE's tag under the pair key (constant time).
    public static func verifyProbe(_ p: Parsed, pairKey: Data) -> Bool {
        guard p.type == .probe else { return false }
        let expected = PonyDirectWire.probeTag(pairKey: pairKey, sessionNonce: p.sessionNonce, probeNonce: p.probeNonce)
        return PonyDirectWire.constantTimeEquals(p.tag, expected)
    }

    /// Verify a parsed PONG's tag under the pair key (constant time).
    public static func verifyPong(_ p: Parsed, pairKey: Data) -> Bool {
        guard p.type == .pong else { return false }
        let expected = PonyDirectWire.pongTag(pairKey: pairKey, sessionNonce: p.sessionNonce, probeNonce: p.probeNonce)
        return PonyDirectWire.constantTimeEquals(p.tag, expected)
    }
}
