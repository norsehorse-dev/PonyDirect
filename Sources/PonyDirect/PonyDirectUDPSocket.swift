// PonyDirectUDPSocket.swift
// A single bound UDP socket (BSD/POSIX). Hole punching needs one socket that can
// sendto/recvfrom arbitrary peers on the SAME local port the STUN server observed,
// which Network.framework's connection-per-endpoint model does not give cleanly, so
// this drops to POSIX sockets. Pure system calls, no dependency. The Kotlin twin is
// java.net.DatagramSocket over the same layout.

import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// A bound IPv4 UDP socket with a background receive loop. One instance backs one
/// WAN session: STUN request, host-candidate port, and all probes/pongs/keepalives
/// go through it so the public mapping stays stable.
public final class PonyDirectUDPSocket {

    public struct Source: Equatable {
        public let host: String
        public let port: UInt16
    }

    private let fd: Int32
    private let recvQueue = DispatchQueue(label: "ponydirect.udp.recv")
    private var running = false

    /// The local port the OS bound (host candidates advertise this).
    public let localPort: UInt16

    /// Called on the receive queue for every datagram. `source` is the sender.
    public var onDatagram: ((Data, Source) -> Void)?

    /// Bind an IPv4 UDP socket to an ephemeral port with address/port reuse so the
    /// STUN-reflexive mapping and the punch traffic share one port. Throws on failure.
    public init() throws {
        // Use a local handle throughout init: referencing the `fd` member inside the
        // pointer closures below would capture self before `localPort` is set.
        let handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard handle >= 0 else { throw PonyDirectSocketError.create(errno) }
        fd = handle

        var yes: Int32 = 1
        setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        #if canImport(Darwin)
        setsockopt(handle, SOL_SOCKET, SO_REUSEPORT, &yes, socklen_t(MemoryLayout<Int32>.size))
        #endif

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = INADDR_ANY   // 0.0.0.0
        addr.sin_port = 0                    // ephemeral
        let bindOK = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(handle, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindOK == 0 else {
            #if canImport(Darwin)
            Darwin.close(handle)
            #else
            Glibc.close(handle)
            #endif
            throw PonyDirectSocketError.bind(errno)
        }

        // Read back the assigned port.
        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(handle, $0, &len)
            }
        }
        localPort = UInt16(bigEndian: bound.sin_port)
    }

    /// Send one datagram to `host:port` (host is a dotted-quad IPv4 string).
    public func send(_ data: Data, toHost host: String, port: UInt16) {
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else { return }
        let n = data.count
        data.withUnsafeBytes { raw in
            _ = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fd, raw.baseAddress, n, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    /// Start the background recvfrom loop. Idempotent.
    public func start() {
        guard !running else { return }
        running = true
        recvQueue.async { [weak self] in self?.loop() }
    }

    private func loop() {
        var buf = [UInt8](repeating: 0, count: 2048)
        while running {
            var from = sockaddr_in()
            var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    recvfrom(fd, &buf, buf.count, 0, sa, &fromLen)
                }
            }
            if n <= 0 { if running { continue } else { break } }
            let data = Data(buf[0..<n])
            var ipbuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &from.sin_addr, &ipbuf, socklen_t(INET_ADDRSTRLEN))
            let host = String(cString: ipbuf)
            let port = UInt16(bigEndian: from.sin_port)
            onDatagram?(data, Source(host: host, port: port))
        }
    }

    public func close() {
        running = false
        #if canImport(Darwin)
        Darwin.close(fd)
        #else
        Glibc.close(fd)
        #endif
    }

    /// Local IPv4 host candidates (non-loopback interface addresses) for this device.
    public static func hostIPv4Addresses() -> [String] {
        var result: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return result }
        defer { freeifaddrs(ifaddr) }
        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = ptr {
            if let sa = cur.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) {
                let flags = Int32(cur.pointee.ifa_flags)
                let up = (flags & Int32(IFF_UP)) != 0
                let loopback = (flags & Int32(IFF_LOOPBACK)) != 0
                if up && !loopback {
                    var addrIn = sockaddr_in()
                    memcpy(&addrIn, sa, MemoryLayout<sockaddr_in>.size)
                    var ipbuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    inet_ntop(AF_INET, &addrIn.sin_addr, &ipbuf, socklen_t(INET_ADDRSTRLEN))
                    let ip = String(cString: ipbuf)
                    if !ip.isEmpty && ip != "0.0.0.0" { result.append(ip) }
                }
            }
            ptr = cur.pointee.ifa_next
        }
        return result
    }
}

public enum PonyDirectSocketError: Error {
    case create(Int32)
    case bind(Int32)
}
