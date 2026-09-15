// PonyDirectWire.swift
// The wire crypto and framing. Dependency-free (CryptoKit only). Must stay
// byte-identical to the Kotlin implementation - see WIRE-PROTOCOL.md.

import Foundation
import CryptoKit
import Security

/// The byte-level protocol: framing, the per-peer authenticated tags used by the
/// identify handshake (LAN) and the hole-punch probes (WAN), and constant-time
/// comparison. The application supplies the per-peer key; this type never derives
/// or stores it.
public enum PonyDirectWire {

    /// Sent once at the start of every connection/stream. "PonyDirect wire v1".
    public static let magic = Data("PDR1".utf8)

    /// Frame type byte. Framing is `type(1) | length(4, big-endian) | payload`.
    public enum Frame: UInt8 {
        case hello = 0x01      // dialer -> listener: identify request
        case helloAck = 0x02   // listener -> dialer: identify match
        case noMatch = 0x03    // listener -> dialer: no match (ack-shaped padding)
        case envelope = 0x04   // an opaque application payload
    }

    // Fixed domain-separation labels (ASCII, no NUL).
    private static let labelIdentify = Data("ponydirect/id/v1".utf8)
    private static let labelIdentifyAck = Data("ponydirect/id-ack/v1".utf8)
    private static let labelProbe = Data("ponydirect/wan-probe/v1".utf8)
    private static let labelPong = Data("ponydirect/wan-pong/v1".utf8)
    private static let labelData = Data("ponydirect/wan-data/v1".utf8)
    private static let labelAck = Data("ponydirect/wan-ack/v1".utf8)

    public static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }

    private static func hmac(key: Data, _ message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    // LAN identify handshake.
    public static func identifyTag(pairKey: Data, dialerNonce: Data) -> Data {
        hmac(key: pairKey, labelIdentify + dialerNonce)
    }
    public static func identifyAckTag(pairKey: Data, dialerNonce: Data, listenerNonce: Data) -> Data {
        hmac(key: pairKey, labelIdentifyAck + dialerNonce + listenerNonce)
    }

    // WAN hole-punch authentication.
    public static func probeTag(pairKey: Data, sessionNonce: Data, probeNonce: Data) -> Data {
        hmac(key: pairKey, labelProbe + sessionNonce + probeNonce)
    }
    public static func pongTag(pairKey: Data, sessionNonce: Data, probeNonce: Data) -> Data {
        hmac(key: pairKey, labelPong + sessionNonce + probeNonce)
    }

    // WAN reliable-datagram (ARQ) authentication. `header` is the fixed fields, the
    // chunk `payload` is appended, so the tag covers the whole datagram.
    public static func dataTag(pairKey: Data, header: Data, payload: Data) -> Data {
        hmac(key: pairKey, labelData + header + payload)
    }
    public static func ackTag(pairKey: Data, header: Data, bitmap: Data) -> Data {
        hmac(key: pairKey, labelAck + header + bitmap)
    }

    /// Length-prefixed frame: `type(1) | length(4, big-endian) | payload`.
    public static func frame(_ type: Frame, _ payload: Data) -> Data {
        var out = Data([type.rawValue])
        let n = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: n) { out.append(contentsOf: $0) }
        out.append(payload)
        return out
    }

    /// Parse one frame from the front of `buffer`. Returns the frame and the number
    /// of bytes consumed, or nil if `buffer` does not yet hold a whole frame.
    public static func parseFrame(_ buffer: Data) -> (type: Frame, payload: Data, consumed: Int)? {
        guard buffer.count >= 5 else { return nil }
        let b = [UInt8](buffer)
        guard let type = Frame(rawValue: b[0]) else { return nil }
        let len = (Int(b[1]) << 24) | (Int(b[2]) << 16) | (Int(b[3]) << 8) | Int(b[4])
        guard len >= 0, buffer.count >= 5 + len else { return nil }
        let payload = buffer.subdata(in: buffer.index(buffer.startIndex, offsetBy: 5)..<buffer.index(buffer.startIndex, offsetBy: 5 + len))
        return (type, payload, 5 + len)
    }

    public static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        let aa = [UInt8](a), bb = [UInt8](b)
        for i in 0..<aa.count { diff |= aa[i] ^ bb[i] }
        return diff == 0
    }
}
