// PonyDirectStun.swift
// A minimal STUN client codec (RFC 5389): build a Binding request and parse the
// server-reflexive address out of a Binding success response. This is only ever
// used to learn our own public ip:port from the self-hosted STUN server; STUN sees
// no message content. Pure byte functions, no sockets - the platform socket layer
// sends the request bytes and hands the response bytes back here. Must stay
// byte-identical to the Kotlin implementation.

import Foundation

/// STUN Binding request/response codec, scoped to exactly what NAT-reflexive
/// candidate gathering needs. No attributes are sent; only MAPPED-ADDRESS /
/// XOR-MAPPED-ADDRESS are read back.
public enum PonyDirectStun {

    /// RFC 5389 magic cookie, fixed for all STUN messages.
    public static let magicCookie: UInt32 = 0x2112_A442

    private static let bindingRequest: UInt16 = 0x0001
    private static let bindingSuccess: UInt16 = 0x0101
    private static let attrMappedAddress: UInt16 = 0x0001
    private static let attrXorMappedAddress: UInt16 = 0x0020

    /// A public transport address learned from STUN.
    public struct MappedAddress: Equatable {
        public let ip: String   // dotted-quad IPv4 or colon-hex IPv6
        public let port: UInt16
        public init(ip: String, port: UInt16) { self.ip = ip; self.port = port }
    }

    /// Build a 20-byte Binding request with the given 12-byte transaction id.
    /// The caller keeps `transactionID` to match the response.
    public static func bindingRequest(transactionID: Data) -> Data {
        precondition(transactionID.count == 12, "STUN transaction id must be 12 bytes")
        var out = Data()
        out.append(uint16: bindingRequest)   // message type
        out.append(uint16: 0)                // message length (no attributes)
        out.append(uint32: magicCookie)      // magic cookie
        out.append(transactionID)            // transaction id
        return out
    }

    /// A fresh random 12-byte transaction id.
    public static func newTransactionID() -> Data {
        PonyDirectWire.randomBytes(12)
    }

    /// Parse a Binding success response. Returns the reflexive address if the message
    /// is a well-formed success response for `transactionID` carrying a mapped
    /// address, else nil. XOR-MAPPED-ADDRESS is preferred; MAPPED-ADDRESS is a
    /// fallback for older servers.
    public static func parseResponse(_ data: Data, transactionID: Data) -> MappedAddress? {
        let b = [UInt8](data)
        guard b.count >= 20 else { return nil }
        let type = (UInt16(b[0]) << 8) | UInt16(b[1])
        guard type == bindingSuccess else { return nil }
        let length = Int((UInt16(b[2]) << 8) | UInt16(b[3]))
        let cookie = (UInt32(b[4]) << 24) | (UInt32(b[5]) << 16) | (UInt32(b[6]) << 8) | UInt32(b[7])
        guard cookie == magicCookie else { return nil }
        let txn = Data(b[8..<20])
        guard txn == transactionID else { return nil }
        guard b.count >= 20 + length else { return nil }

        var xor: MappedAddress? = nil
        var plain: MappedAddress? = nil
        var i = 20
        let end = 20 + length
        while i + 4 <= end {
            let attrType = (UInt16(b[i]) << 8) | UInt16(b[i + 1])
            let attrLen = Int((UInt16(b[i + 2]) << 8) | UInt16(b[i + 3]))
            let valueStart = i + 4
            guard valueStart + attrLen <= end else { break }
            let value = Array(b[valueStart..<valueStart + attrLen])
            if attrType == attrXorMappedAddress {
                xor = decodeAddress(value, xored: true, transactionID: b)
            } else if attrType == attrMappedAddress {
                plain = decodeAddress(value, xored: false, transactionID: b)
            }
            // Attributes are padded to a 4-byte boundary.
            i = valueStart + attrLen + ((4 - (attrLen % 4)) % 4)
        }
        return xor ?? plain
    }

    // value layout: reserved(1) | family(1) | port(2) | address(4 or 16)
    // `header` is the full 20-byte STUN header (for the XOR seed: cookie||txn).
    private static func decodeAddress(_ value: [UInt8], xored: Bool, transactionID header: [UInt8]) -> MappedAddress? {
        guard value.count >= 4 else { return nil }
        let family = value[1]
        var port = (UInt16(value[2]) << 8) | UInt16(value[3])
        if xored { port ^= UInt16(magicCookie >> 16) }

        if family == 0x01 {                       // IPv4
            guard value.count >= 8 else { return nil }
            var a = [value[4], value[5], value[6], value[7]]
            if xored {
                let cookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
                for k in 0..<4 { a[k] ^= cookie[k] }
            }
            return MappedAddress(ip: "\(a[0]).\(a[1]).\(a[2]).\(a[3])", port: port)
        } else if family == 0x02 {                // IPv6
            guard value.count >= 20 else { return nil }
            var a = Array(value[4..<20])
            if xored {
                // XOR seed is the 4-byte cookie followed by the 12-byte transaction id.
                let seed: [UInt8] = [0x21, 0x12, 0xA4, 0x42] + Array(header[8..<20])
                for k in 0..<16 { a[k] ^= seed[k] }
            }
            return MappedAddress(ip: ipv6String(a), port: port)
        }
        return nil
    }

    private static func ipv6String(_ a: [UInt8]) -> String {
        var groups: [String] = []
        var k = 0
        while k < 16 {
            let g = (UInt16(a[k]) << 8) | UInt16(a[k + 1])
            groups.append(String(format: "%x", g))
            k += 2
        }
        return groups.joined(separator: ":")
    }
}

private extension Data {
    mutating func append(uint16 v: UInt16) {
        append(UInt8(v >> 8)); append(UInt8(v & 0xFF))
    }
    mutating func append(uint32 v: UInt32) {
        append(UInt8((v >> 24) & 0xFF)); append(UInt8((v >> 16) & 0xFF))
        append(UInt8((v >> 8) & 0xFF));  append(UInt8(v & 0xFF))
    }
}
