// PonyDirect.swift
// The application boundary. PonyDirect moves opaque bytes between already-paired
// peers; the app supplies the per-peer key, the out-of-band signaling channel, and
// the sink for delivered payloads. The app owns all encryption and key exchange.

import Foundation

/// Supplies the single 32-byte symmetric key PonyDirect shares with a peer. Both
/// sides must derive the same value out of band (in CarrierPony, from the sealed
/// pair keys). PonyDirect uses it only for the identify handshake and hole-punch
/// probe MACs; it never sees the app's raw key material.
public protocol PonyDirectKeyProvider: AnyObject {
    func pairKey(forPeer peerID: String) -> Data?
}

/// One WAN signaling message. The app relays these to the peer over its own
/// confidential channel (CarrierPony uses its sealed control ops over the relay),
/// so the relay only ever sees opaque traffic and learns nothing about the P2P setup.
public struct PonyDirectSignal {
    public enum Kind: String { case offer, answer, ice }
    public var kind: Kind
    public var candidates: [String]     // "ip:port" list, for offer/answer
    public var sessionNonce: Data?      // binds a hole-punch session, for offer/answer
    public var candidate: String?       // a single trickled "ip:port", for ice
    public init(kind: Kind, candidates: [String] = [], sessionNonce: Data? = nil, candidate: String? = nil) {
        self.kind = kind; self.candidates = candidates; self.sessionNonce = sessionNonce; self.candidate = candidate
    }
}

/// The app's out-of-band channel for relaying signaling to a peer.
public protocol PonyDirectSignaling: AnyObject {
    func sendSignal(_ signal: PonyDirectSignal, toPeer peerID: String)
}

/// Receives payloads delivered directly from a peer. The bytes are whatever the app
/// asked PonyDirect to carry (in CarrierPony, an already-sealed envelope).
public protocol PonyDirectEnvelopeSink: AnyObject {
    func received(_ payload: Data, fromPeer peerID: String)
}

/// A device seen on the local network, identified only by a per-launch random node
/// id until the identify handshake matches it to a known peer.
public struct DiscoveredNode: Hashable {
    public let nodeID: String
    public init(nodeID: String) { self.nodeID = nodeID }
}

/// Discovery on the local network (mDNS). Platform-supplied: the concrete
/// implementation lives with the app because it needs platform APIs
/// (NsdManager / Network framework); the transport logic here is platform-neutral.
public protocol PonyDirectDiscovery: AnyObject {
    func start()
    func stop()
    var nearby: [DiscoveredNode] { get }
}
