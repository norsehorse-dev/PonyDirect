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
    /// Bytes delivered in order over a reliable stream (bulk transfer). Default: ignored.
    func wan(_ wan: PonyDirectWan, peer peerID: String, didReceiveStreamBytes bytes: Data)
    /// The inbound stream from this peer finished (all bytes delivered). Default: ignored.
    func wanStreamReceiveDidComplete(_ wan: PonyDirectWan, peer peerID: String)
    /// The outbound stream to this peer finished (true) or gave up (false). Default: ignored.
    func wanStreamSendDidComplete(_ wan: PonyDirectWan, peer peerID: String, success: Bool)
}

public extension PonyDirectWanDelegate {
    func wan(_ wan: PonyDirectWan, peer peerID: String, didReceiveStreamBytes bytes: Data) {}
    func wanStreamReceiveDidComplete(_ wan: PonyDirectWan, peer peerID: String) {}
    func wanStreamSendDidComplete(_ wan: PonyDirectWan, peer peerID: String, success: Bool) {}
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

    private final class OutgoingMsg {
        let peerID: String
        let sessionNonce: Data
        let chunks: [Data]
        var ackedBitmap: Data
        var roundsLeft: Int
        var onComplete: ((Bool) -> Void)?
        init(peerID: String, sessionNonce: Data, chunks: [Data], rounds: Int, onComplete: ((Bool) -> Void)?) {
            self.peerID = peerID; self.sessionNonce = sessionNonce; self.chunks = chunks
            self.ackedBitmap = Data(repeating: 0, count: PonyDirectArq.bitmapLen(chunkCount: chunks.count))
            self.roundsLeft = rounds
            self.onComplete = onComplete
        }
    }

    private final class Reassembly {
        let chunkCount: Int
        var chunks: [Data?]
        var bitmap: Data
        var received = 0
        init(chunkCount: Int) {
            self.chunkCount = chunkCount
            self.chunks = Array(repeating: nil, count: chunkCount)
            self.bitmap = Data(repeating: 0, count: PonyDirectArq.bitmapLen(chunkCount: chunkCount))
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
    private var arqTimer: DispatchSourceTimer?
    private var nextMsgSeq: UInt32 = 1
    private var outgoing: [UInt32: OutgoingMsg] = [:]
    private var incoming: [String: Reassembly] = [:]
    private var completed: [String] = []
    private var streamEngines: [String: PonyDirectStreamEngine] = [:]
    private var streamRecvDone = Set<String>()
    private var streamSendDone = Set<String>()
    private var streamTimer: DispatchSourceTimer?
    private let streamIntervalMs = 20
    // Outbound backpressure, readable from any thread: bytes handed to writeStream but not yet in the
    // engine, and the engine's unacknowledged bytes as of the last write or tick.
    private let backpressureLock = NSLock()
    private var streamQueued: [String: Int64] = [:]
    private var streamHeld: [String: Int64] = [:]
    private func adjustQueued(_ peerID: String, by delta: Int64) {
        backpressureLock.lock(); streamQueued[peerID, default: 0] += delta; backpressureLock.unlock()
    }
    private func setHeld(_ peerID: String, _ value: Int64?) {
        backpressureLock.lock(); streamHeld[peerID] = value; backpressureLock.unlock()
    }

    // Tunables.
    private let probeIntervalMs = 250
    private let maxProbeRounds = 40          // ~10s of punching before giving up
    private let keepaliveIntervalMs = 15_000
    private let offerIntervalMs = 2000       // re-send the offer until answered
    private let maxOfferRounds = 15          // fast-retry burst (~30s), then slow back-off
    private let arqIntervalMs = 500          // retransmit unacked chunks this often
    private let arqRounds = 20               // ~10s to deliver before giving up (relay covers it)
    private let maxChunks = 256              // 256 KB cap; larger payloads go by relay
    private let completedCap = 256

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
            if let existing = self.sessions[peerID] {
                // Already tracking this peer; if it is a not-yet-connected initiator,
                // make sure it is still offering (recover a stalled session without a
                // manual re-toggle).
                if existing.role == .initiator && existing.state != .connected {
                    self.ensureOfferTimer()
                }
                return
            }
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
            self.streamEngines.removeValue(forKey: peerID)
            self.streamRecvDone.remove(peerID)
            self.streamSendDone.remove(peerID)
            self.backpressureLock.lock()
            self.streamQueued.removeValue(forKey: peerID)
            self.streamHeld.removeValue(forKey: peerID)
            self.backpressureLock.unlock()
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

    /// A human-readable snapshot for on-device debugging. No secrets: candidates are ip:port only.
    public func diagnostics() -> String {
        queue.sync {
            var lines: [String] = []
            lines.append("STUN reflexive: " + (reflexive ?? "NONE (no public addr)"))
            lines.append("host candidates: \(hostCandidates.count)")
            if sessions.isEmpty { lines.append("(no sessions yet)") }
            for (pid, s) in sessions {
                lines.append("peer \(String(pid.prefix(10)))… state=\(s.state.rawValue) remoteCands=\(s.remoteCandidates.count) probe=\(s.probeRounds)/\(maxProbeRounds)")
            }
            return lines.joined(separator: "\n")
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
                // Punch attempt exhausted. Fall back to re-offering (fresh candidates)
                // rather than a terminal failure, so it keeps trying while WAN is on
                // and reconnects on its own after a network change, no re-toggle.
                session.probeRounds = 0
                session.remoteCandidates = []
                setState(session, .gathering)
                ensureOfferTimer()
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
        // Reliable-datagram (ARQ) packets.
        if let first = data.first, first == PonyDirectArq.Packet.data.rawValue {
            guard let dp = PonyDirectArq.parseData(data),
                  let session = sessions.values.first(where: { PonyDirectWire.constantTimeEquals($0.sessionNonce, dp.sessionNonce) }),
                  let pairKey = keys.pairKey(forPeer: session.peerID),
                  PonyDirectArq.verifyData(dp, pairKey: pairKey) else { return }
            handleData(dp, session: session, pairKey: pairKey)
            return
        }
        if let first = data.first, first == PonyDirectArq.Packet.ack.rawValue {
            guard let ap = PonyDirectArq.parseAck(data),
                  let session = sessions.values.first(where: { PonyDirectWire.constantTimeEquals($0.sessionNonce, ap.sessionNonce) }),
                  let pairKey = keys.pairKey(forPeer: session.peerID),
                  PonyDirectArq.verifyAck(ap, pairKey: pairKey) else { return }
            handleAck(ap, session: session)
            return
        }
        // Reliable-stream (bulk) frames: route to the peer's stream engine by session nonce.
        if let first = data.first,
           first == PonyDirectStream.Packet.data.rawValue || first == PonyDirectStream.Packet.ack.rawValue ||
           first == PonyDirectStream.Packet.fin.rawValue || first == PonyDirectStream.Packet.rst.rawValue {
            guard data.count >= 17 else { return }
            let nonce = data.subdata(in: 1..<17)
            guard let session = sessions.values.first(where: { PonyDirectWire.constantTimeEquals($0.sessionNonce, nonce) }),
                  let e = streamEngine(for: session) else { return }
            e.onWireDatagram(nowMs(), data)
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
        arqTimer?.cancel(); arqTimer = nil
        streamTimer?.cancel(); streamTimer = nil
    }

    // MARK: - Helpers

    /// Send an application payload over an established path (used by M3 delivery).
    /// Returns false if no path is connected.
    /// Queue a payload for reliable delivery over the connected direct path. Returns
    /// false (so the caller uses the relay) if there is no live path or the payload
    /// exceeds the direct-path size cap.
    /// Queue a payload for reliable delivery. Returns false immediately (use the
    /// relay) if there is no live path or the payload exceeds the size cap. When it
    /// returns true, `onComplete` fires later with true once every chunk is acked, or
    /// false if the deadline passes first.
    @discardableResult
    public func sendPayload(_ payload: Data, toPeer peerID: String, onComplete: ((Bool) -> Void)? = nil) -> Bool {
        var ok = false
        queue.sync {
            guard let s = sessions[peerID], s.state == .connected, let remote = s.activeRemote,
                  let pairKey = keys.pairKey(forPeer: peerID) else { return }
            let chunks = PonyDirectArq.chunk(payload)
            guard chunks.count <= maxChunks else { return }
            let seq = nextMsgSeq; nextMsgSeq = nextMsgSeq &+ 1
            let msg = OutgoingMsg(peerID: peerID, sessionNonce: s.sessionNonce, chunks: chunks, rounds: arqRounds, onComplete: onComplete)
            outgoing[seq] = msg
            sendUnacked(seq: seq, msg: msg, pairKey: pairKey, remote: remote)
            ensureArqTimer()
            ok = true
        }
        return ok
    }

    private func sendUnacked(seq: UInt32, msg: OutgoingMsg, pairKey: Data, remote: PonyDirectUDPSocket.Source) {
        let count = msg.chunks.count
        for i in 0..<count where !PonyDirectArq.bitmapGet(msg.ackedBitmap, i) {
            let pkt = PonyDirectArq.data(pairKey: pairKey, sessionNonce: msg.sessionNonce, msgSeq: seq,
                                         chunkIndex: UInt16(i), chunkCount: UInt16(count), payload: msg.chunks[i])
            socket.send(pkt, toHost: remote.host, port: remote.port)
        }
    }

    private func ensureArqTimer() {
        guard arqTimer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .milliseconds(arqIntervalMs), repeating: .milliseconds(arqIntervalMs))
        t.setEventHandler { [weak self] in self?.arqTick() }
        arqTimer = t
        t.resume()
    }

    private func arqTick() {
        for (seq, msg) in outgoing {
            guard let s = sessions[msg.peerID], s.state == .connected, let remote = s.activeRemote,
                  let pairKey = keys.pairKey(forPeer: msg.peerID) else {
                outgoing[seq] = nil; msg.onComplete?(false); continue
            }
            msg.roundsLeft -= 1
            if msg.roundsLeft <= 0 { outgoing[seq] = nil; msg.onComplete?(false); continue }
            sendUnacked(seq: seq, msg: msg, pairKey: pairKey, remote: remote)
        }
        if outgoing.isEmpty { arqTimer?.cancel(); arqTimer = nil }
    }

    private func markCompleted(_ key: String) {
        completed.append(key)
        if completed.count > completedCap { completed.removeFirst(completed.count - completedCap) }
    }

    private func handleData(_ dp: PonyDirectArq.DataPacket, session: Session, pairKey: Data) {
        let key = "\(session.peerID)#\(dp.msgSeq)"
        let count = Int(dp.chunkCount)
        guard count > 0, count <= maxChunks else { return }
        if completed.contains(key) {
            // Already delivered; re-ACK fully so the sender stops retransmitting.
            let full = Data(repeating: 0xFF, count: PonyDirectArq.bitmapLen(chunkCount: count))
            if let remote = session.activeRemote {
                socket.send(PonyDirectArq.ack(pairKey: pairKey, sessionNonce: session.sessionNonce,
                                              msgSeq: dp.msgSeq, chunkCount: dp.chunkCount, bitmap: full),
                            toHost: remote.host, port: remote.port)
            }
            return
        }
        let r = incoming[key] ?? Reassembly(chunkCount: count)
        incoming[key] = r
        let idx = Int(dp.chunkIndex)
        if idx < r.chunkCount, r.chunks[idx] == nil {
            r.chunks[idx] = dp.payload
            PonyDirectArq.bitmapSet(&r.bitmap, idx)
            r.received += 1
        }
        if let remote = session.activeRemote {
            socket.send(PonyDirectArq.ack(pairKey: pairKey, sessionNonce: session.sessionNonce,
                                          msgSeq: dp.msgSeq, chunkCount: UInt16(r.chunkCount), bitmap: r.bitmap),
                        toHost: remote.host, port: remote.port)
        }
        if r.received == r.chunkCount {
            var full = Data()
            for c in r.chunks { full.append(c ?? Data()) }
            incoming[key] = nil
            markCompleted(key)
            let pid = session.peerID
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                self.delegate?.wan(self, peer: pid, didReceivePayload: full)
            }
        }
    }

    private func handleAck(_ ap: PonyDirectArq.AckPacket, session: Session) {
        guard let msg = outgoing[ap.msgSeq], msg.peerID == session.peerID else { return }
        let count = msg.chunks.count
        for i in 0..<count where PonyDirectArq.bitmapGet(ap.bitmap, i) {
            PonyDirectArq.bitmapSet(&msg.ackedBitmap, i)
        }
        var allAcked = true
        for i in 0..<count where !PonyDirectArq.bitmapGet(msg.ackedBitmap, i) { allAcked = false; break }
        if allAcked { outgoing[ap.msgSeq] = nil; msg.onComplete?(true) }
    }

    // MARK: - Reliable stream (bulk transfer)

    /// Open (or reuse) a reliable byte-stream to a connected peer.
    public func openStream(toPeer peerID: String) {
        queue.async { [weak self] in
            guard let self = self, let s = self.sessions[peerID] else { return }
            _ = self.streamEngine(for: s)
        }
    }

    /// Append bytes to the outbound stream to a peer. Returns at once; the bytes are held until the
    /// peer acknowledges them. A caller streaming more than fits in memory should wait while
    /// streamSendBufferedBytes(toPeer:) is above its own high-water mark before writing more.
    public func writeStream(_ bytes: Data, toPeer peerID: String) {
        let n = Int64(bytes.count)
        adjustQueued(peerID, by: n)
        queue.async { [weak self] in
            guard let self = self else { return }
            self.adjustQueued(peerID, by: -n)
            guard let s = self.sessions[peerID], let e = self.streamEngine(for: s) else { return }
            e.write(bytes)
            self.setHeld(peerID, e.sendBufferedBytes())
        }
    }

    /// Outbound bytes to a peer not yet acknowledged, including ones still queued for the stream
    /// queue. Safe from any thread. Falls as the peer acknowledges; stays flat if the peer stalls.
    public func streamSendBufferedBytes(toPeer peerID: String) -> Int64 {
        backpressureLock.lock(); defer { backpressureLock.unlock() }
        return (streamQueued[peerID] ?? 0) + (streamHeld[peerID] ?? 0)
    }

    /// Signal end-of-stream for the outbound stream to a peer.
    public func finishStream(toPeer peerID: String) {
        queue.async { [weak self] in
            guard let self = self, let s = self.sessions[peerID], let e = self.streamEngine(for: s) else { return }
            e.finishSending()
        }
    }

    private func streamEngine(for session: Session) -> PonyDirectStreamEngine? {
        if let e = streamEngines[session.peerID] { return e }
        guard let pairKey = keys.pairKey(forPeer: session.peerID) else { return nil }
        let peerID = session.peerID
        let e = PonyDirectStreamEngine(pairKey: pairKey, sessionNonce: session.sessionNonce, onDatagram: { [weak self] frame in
            guard let self = self, let s = self.sessions[peerID], let remote = s.activeRemote else { return }
            self.socket.send(frame, toHost: remote.host, port: remote.port)
        })
        streamEngines[peerID] = e
        ensureStreamTimer()
        return e
    }

    private func ensureStreamTimer() {
        guard streamTimer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: .milliseconds(streamIntervalMs))
        t.setEventHandler { [weak self] in self?.streamTick() }
        streamTimer = t
        t.resume()
    }

    private func streamTick() {
        let now = nowMs()
        for (peerID, e) in streamEngines {
            e.tick(now)
            setHeld(peerID, e.sendBufferedBytes())
            let bytes = e.read(1 << 20)
            if !bytes.isEmpty {
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.delegate?.wan(self, peer: peerID, didReceiveStreamBytes: bytes)
                }
            }
            if e.recvComplete() && !streamRecvDone.contains(peerID) {
                streamRecvDone.insert(peerID)
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.delegate?.wanStreamReceiveDidComplete(self, peer: peerID)
                }
            }
            if e.sendComplete() && !streamSendDone.contains(peerID) {
                streamSendDone.insert(peerID)
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.delegate?.wanStreamSendDidComplete(self, peer: peerID, success: true)
                }
            }
        }
        if streamEngines.isEmpty { streamTimer?.cancel(); streamTimer = nil }
    }

    private func nowMs() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000) }

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
