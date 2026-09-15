// PonyDirectWanPath.swift
// The WAN path manager: one shared UDP socket, per-peer hole-punch sessions.
// Gathers host + STUN-reflexive candidates, exchanges them over the app's sealed
// signaling, punches with authenticated PROBE/PONG, and holds the mapping with
// KEEPALIVE. M2 proves an authenticated path; envelope delivery is M3. The socket
// and timers are platform primitives; the state machine is platform-neutral and
// mirrors the Kotlin twin.

import Foundation

public protocol PonyDirectWanDelegate: AnyObject {
    /// Path state for a peer changed (surface "direct path: connected" from here).
    func wan(_ wan: PonyDirectWan, peer peerID: String, didChangeState state: PonyDirectWan.PathState)
    /// A verified application datagram arrived on the path. (M3 feeds this to the
    /// envelope sink; in M2 no envelope datagrams are sent.)
    func wan(_ wan: PonyDirectWan, peer peerID: String, didReceivePayload payload: Data)
}

/// Manages authenticated UDP paths to peers over one bound socket.
public final class PonyDirectWan {

    public enum PathState: String { case idle, gathering, punching, connected, failed }

    public enum Role { case initiator, responder }

    public struct StunServer {
        public let host: String
        public let port: UInt16
        public init(host: String, port: UInt16) { self.host = host; self.port = port }
    }

    private final class Session {
        let peerID: String
        let role: Role
        var sessionNonce: Data
        var remoteCandidates: [String] = []       // "ip:port"
        var triedCandidates = Set<String>()
        var activeRemote: PonyDirectUDPSocket.Source?
        var state: PathState = .idle
        var probeRounds = 0
        var offerRounds = 0
        init(peerID: String, role: Role, sessionNonce: Data) {
            self.peerID = peerID; self.role = role; self.sessionNonce = sessionNonce
        }
    }

    private let socket: PonyDirectUDPSocket
    private let stun: StunServer
    private let keys: PonyDirectKeyProvider
    private let signaling: PonyDirectSignaling
    public weak var delegate: PonyDirectWanDelegate?

    private let queue = DispatchQueue(label: "ponydirect.wan")
    private var sessions: [String: Session] = [:]        // by peerID
    private var stunTxn: Data?
    private var reflexive: String?                        // "ip:port"
    private var hostCandidates: [String] = []
    private var probeTimer: DispatchSourceTimer?
    private var offerTimer: DispatchSourceTimer?
    private var keepaliveTimer: DispatchSourceTimer?

    // Tunables.
    private let probeIntervalMs = 250
    private let maxProbeRounds = 40          // ~10s of punching before giving up
    private let keepaliveIntervalMs = 15_000
    private let offerIntervalMs = 2000       // re-send the offer until answered
    private let maxOfferRounds = 15          // fast-retry burst (~30s), then slow back-off

    public init(stun: StunServer, keys: PonyDirectKeyProvider, signaling: PonyDirectSignaling) throws {
        self.socket = try PonyDirectUDPSocket()
        self.stun = stun
        self.keys = keys
        self.signaling = signaling
        self.socket.onDatagram = { [weak self] data, source in
            self?.queue.async { self?.handleDatagram(data, from: source) }
        }
        self.socket.start()
    }

    /// Open a path to `peerID`. The initiator mints the session nonce and sends the
    /// offer; the responder waits for the offer via `handleSignal`.
    public func open(peer peerID: String, as role: Role) {
        queue.async { [weak self] in
            guard let self = self else { return }
            if self.sessions[peerID] != nil { return }
            let nonce = role == .initiator ? PonyDirectWire.randomBytes(16) : Data()
            let session = Session(peerID: peerID, role: role, sessionNonce: nonce)
            self.sessions[peerID] = session
            self.setState(session, .gathering)
            self.gatherCandidates()
            if role == .initiator {
                // Send the offer now, then re-send it on a timer until an answer
                // arrives, so the order the two sides enable WAN does not matter.
                self.pendingOfferPeers.insert(peerID)
                self.sendOfferIfReady(session)
                self.ensureOfferTimer()
            }
        }
    }

    /// Tear down the path to a peer.
    public func close(peer peerID: String) {
        queue.async { [weak self] in
            guard let self = self, let s = self.sessions[peerID] else { return }
            self.setState(s, .idle)
            self.sessions.removeValue(forKey: peerID)
            if self.sessions.isEmpty { self.stopTimers() }
        }
    }

    /// Feed a signaling message the app received from the peer.
    public func handleSignal(_ signal: PonyDirectSignal, fromPeer peerID: String) {
        queue.async { [weak self] in
            guard let self = self else { return }
            switch signal.kind {
            case .offer:
                let session = self.sessions[peerID] ?? {
                    let s = Session(peerID: peerID, role: .responder, sessionNonce: signal.sessionNonce ?? Data())
                    self.sessions[peerID] = s
                    self.setState(s, .gathering)
                    self.gatherCandidates()
                    return s
                }()
                if let n = signal.sessionNonce { session.sessionNonce = n }
                session.remoteCandidates = self.merge(session.remoteCandidates, signal.candidates)
                // Responder answers with its own candidates.
                self.sendAnswerIfReady(session)
                self.startPunching(session)
            case .answer:
                guard let session = self.sessions[peerID] else { return }
                if let n = signal.sessionNonce { session.sessionNonce = n }
                session.remoteCandidates = self.merge(session.remoteCandidates, signal.candidates)
                self.startPunching(session)
            case .ice:
                guard let session = self.sessions[peerID], let c = signal.candidate else { return }
                session.remoteCandidates = self.merge(session.remoteCandidates, [c])
                self.startPunching(session)
            }
        }
    }

    // MARK: - Candidate gathering

    private var pendingOfferPeers = Set<String>()

    private func gatherCandidates() {
        if hostCandidates.isEmpty {
            hostCandidates = PonyDirectUDPSocket.hostIPv4Addresses().map { "\($0):\(socket.localPort)" }
        }
        if reflexive == nil && stunTxn == nil {
            let txn = PonyDirectStun.newTransactionID()
            stunTxn = txn
            socket.send(PonyDirectStun.bindingRequest(transactionID: txn), toHost: stun.host, port: stun.port)
            // If STUN never answers, proceed with host candidates only after a delay.
            queue.asyncAfter(deadline: .now() + 1.0) { [weak self] in
                guard let self = self else { return }
                if self.reflexive == nil {
                    self.stunTxn = nil
                    self.flushPendingOffers()
                    self.flushPendingAnswers()
                }
            }
        }
    }

    private func localCandidates() -> [String] {
        var all = hostCandidates
        if let r = reflexive { all.append(r) }
        return all
    }

    // MARK: - Offer / answer emission

    private func sendOfferIfReady(_ session: Session) {
        // Send the offer now with whatever we have; trickle the reflexive as ICE if
        // it arrives later. This keeps setup latency low.
        let sig = PonyDirectSignal(kind: .offer, candidates: localCandidates(), sessionNonce: session.sessionNonce)
        signaling.sendSignal(sig, toPeer: session.peerID)
        pendingOfferPeers.remove(session.peerID)
    }

    private var pendingAnswerPeers = Set<String>()
    private func sendAnswerIfReady(_ session: Session) {
        let sig = PonyDirectSignal(kind: .answer, candidates: localCandidates(), sessionNonce: session.sessionNonce)
        signaling.sendSignal(sig, toPeer: session.peerID)
        pendingAnswerPeers.remove(session.peerID)
    }

    private func flushPendingOffers() {
        for pid in pendingOfferPeers {
            if let s = sessions[pid] { sendOfferIfReady(s) }
        }
    }
    private func flushPendingAnswers() {
        for pid in pendingAnswerPeers {
            if let s = sessions[pid] { sendAnswerIfReady(s) }
        }
    }

    // MARK: - Punching

    private func startPunching(_ session: Session) {
        guard session.state == .gathering || session.state == .punching else { return }
        if session.state != .punching { setState(session, .punching) }
        ensureProbeTimer()
    }

    private func ensureOfferTimer() {
        guard offerTimer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .milliseconds(offerIntervalMs), repeating: .milliseconds(offerIntervalMs))
        t.setEventHandler { [weak self] in self?.offerTick() }
        offerTimer = t
        t.resume()
    }

    private func offerTick() {
        var anyWaiting = false
        for session in sessions.values where session.role == .initiator && session.state == .gathering {
            anyWaiting = true
            session.offerRounds += 1
            // Re-send every tick for the first burst (~30s), then back off to about
            // every 16s and keep trying as long as WAN is on and no answer has come,
            // so the peer can enable WAN at any later time and still connect.
            if session.offerRounds <= maxOfferRounds || session.offerRounds % 8 == 0 {
                sendOfferIfReady(session)
            }
        }
        if !anyWaiting { offerTimer?.cancel(); offerTimer = nil }
    }

    private func ensureProbeTimer() {
        guard probeTimer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: .milliseconds(probeIntervalMs))
        t.setEventHandler { [weak self] in self?.probeTick() }
        probeTimer = t
        t.resume()
    }

    private func probeTick() {
        var anyPunching = false
        for session in sessions.values where session.state == .punching {
            anyPunching = true
            guard let pairKey = keys.pairKey(forPeer: session.peerID) else { continue }
            session.probeRounds += 1
            if session.probeRounds > maxProbeRounds {
                setState(session, .failed)
                continue
            }
            for cand in session.remoteCandidates {
                guard let (host, port) = splitHostPort(cand) else { continue }
                let probeNonce = PonyDirectWire.randomBytes(16)
                let pkt = PonyDirectPunch.probe(pairKey: pairKey, sessionNonce: session.sessionNonce, probeNonce: probeNonce)
                socket.send(pkt, toHost: host, port: port)
            }
        }
        if !anyPunching { stopProbeTimer() }
    }

    private func stopProbeTimer() {
        probeTimer?.cancel(); probeTimer = nil
    }

    // MARK: - Datagram intake

    private func handleDatagram(_ data: Data, from source: PonyDirectUDPSocket.Source) {
        // STUN response?
        if let txn = stunTxn, let mapped = PonyDirectStun.parseResponse(data, transactionID: txn) {
            stunTxn = nil
            reflexive = "\(mapped.ip):\(mapped.port)"
            // Trickle the reflexive candidate to peers we're setting up.
            for session in sessions.values {
                signaling.sendSignal(PonyDirectSignal(kind: .ice, candidate: reflexive), toPeer: session.peerID)
            }
            flushPendingOffers(); flushPendingAnswers()
            return
        }
        // Punch packet?
        guard let parsed = PonyDirectPunch.parse(data) else { return }
        guard let session = sessions.values.first(where: {
            PonyDirectWire.constantTimeEquals($0.sessionNonce, parsed.sessionNonce)
        }) else { return }
        guard let pairKey = keys.pairKey(forPeer: session.peerID) else { return }

        switch parsed.type {
        case .probe:
            guard PonyDirectPunch.verifyProbe(parsed, pairKey: pairKey) else { return }
            // Answer with a matching PONG to the exact source we heard from.
            let pong = PonyDirectPunch.pong(pairKey: pairKey, sessionNonce: session.sessionNonce, probeNonce: parsed.probeNonce)
            socket.send(pong, toHost: source.host, port: source.port)
            // A verified probe also proves the peer can reach us here.
            markConnected(session, remote: source)
        case .pong:
            guard PonyDirectPunch.verifyPong(parsed, pairKey: pairKey) else { return }
            markConnected(session, remote: source)
        case .keepalive:
            // Keepalives are unauthenticated NAT-hold traffic; ignore beyond noting liveness.
            break
        }
    }

    private func markConnected(_ session: Session, remote: PonyDirectUDPSocket.Source) {
        session.activeRemote = remote
        if session.state != .connected {
            setState(session, .connected)
        }
        ensureKeepalive()
        // Once every session is connected or failed, stop probing.
        if !sessions.values.contains(where: { $0.state == .punching }) { stopProbeTimer() }
    }

    // MARK: - Keepalive

    private func ensureKeepalive() {
        guard keepaliveTimer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .milliseconds(keepaliveIntervalMs), repeating: .milliseconds(keepaliveIntervalMs))
        t.setEventHandler { [weak self] in self?.keepaliveTick() }
        keepaliveTimer = t
        t.resume()
    }

    private func keepaliveTick() {
        for session in sessions.values where session.state == .connected {
            guard let remote = session.activeRemote else { continue }
            socket.send(PonyDirectPunch.keepalive(sessionNonce: session.sessionNonce), toHost: remote.host, port: remote.port)
        }
    }

    private func stopTimers() {
        stopProbeTimer()
        offerTimer?.cancel(); offerTimer = nil
        keepaliveTimer?.cancel(); keepaliveTimer = nil
    }

    // MARK: - Helpers

    /// Send an application payload over an established path (used by M3 delivery).
    /// Returns false if no path is connected.
    @discardableResult
    public func sendPayload(_ payload: Data, toPeer peerID: String) -> Bool {
        var ok = false
        queue.sync {
            guard let s = sessions[peerID], s.state == .connected, let r = s.activeRemote else { return }
            socket.send(PonyDirectWire.frame(.envelope, payload), toHost: r.host, port: r.port)
            ok = true
        }
        return ok
    }

    public func state(ofPeer peerID: String) -> PathState {
        queue.sync { sessions[peerID]?.state ?? .idle }
    }

    private func setState(_ session: Session, _ state: PathState) {
        session.state = state
        let pid = session.peerID
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.delegate?.wan(self, peer: pid, didChangeState: state)
        }
    }

    private func merge(_ a: [String], _ b: [String]) -> [String] {
        var seen = Set(a); var out = a
        for c in b where !seen.contains(c) { seen.insert(c); out.append(c) }
        return out
    }

    private func splitHostPort(_ s: String) -> (String, UInt16)? {
        guard let idx = s.lastIndex(of: ":") else { return nil }
        let host = String(s[s.startIndex..<idx])
        guard let port = UInt16(s[s.index(after: idx)...]) else { return nil }
        return (host, port)
    }
}
