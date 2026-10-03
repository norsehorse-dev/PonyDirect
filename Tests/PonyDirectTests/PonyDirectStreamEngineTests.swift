import XCTest
@testable import PonyDirect

/// End-to-end over a simulated wire: two engines sharing a per-pair key and session nonce move a
/// payload through real SDATA/SACK/SFIN frames across a lossy, reordering channel. Exercises the full
/// stack (codec, tags, ARQ, congestion control) the way PonyDirectWan will run it.
final class PonyDirectStreamEngineTests: XCTestCase {

    private final class Rng {
        private var s: UInt64
        init(_ seed: UInt64) { s = seed }
        func next() -> Int { s = s &* 6364136223846793005 &+ 1442695040888963407; return Int((s >> 33) & 0x7fffffff) }
        func dropped(_ pct: Int) -> Bool { next() % 100 < pct }
        func jitter(_ n: Int) -> Int64 { n <= 0 ? 0 : Int64(next() % n) }
    }

    private struct Item { let at: Int64; let d: Data }

    private func run(_ totalBytes: Int, dropPct: Int, seed: UInt64) {
        let key = Data((0..<32).map { UInt8(($0 * 7 + 1) % 256) })
        let nonce = Data((0..<16).map { UInt8($0 + 3) })
        var original = Data(count: totalBytes)
        for i in 0..<totalBytes { original[i] = UInt8((i * 31 + 7) % 251) }
        let rng = Rng(seed)
        let baseLat: Int64 = 30; let jit = 40
        var aToB: [Item] = []; var bToA: [Item] = []
        var now: Int64 = 0

        let a = PonyDirectStreamEngine(pairKey: key, sessionNonce: nonce) { d in
            if !rng.dropped(dropPct) { aToB.append(Item(at: now + baseLat + rng.jitter(jit), d: d)) }
        }
        let b = PonyDirectStreamEngine(pairKey: key, sessionNonce: nonce) { d in
            if !rng.dropped(dropPct) { bToA.append(Item(at: now + baseLat + rng.jitter(jit), d: d)) }
        }
        a.write(original); a.finishSending()

        var steps = 0
        while !b.recvComplete() && steps < 400_000 {
            a.tick(now); b.tick(now)
            let ad = aToB.filter { $0.at <= now }; aToB.removeAll { $0.at <= now }
            for it in ad { b.onWireDatagram(now, it.d) }
            let bd = bToA.filter { $0.at <= now }; bToA.removeAll { $0.at <= now }
            for it in bd { a.onWireDatagram(now, it.d) }
            now += 20; steps += 1
        }
        XCTAssertTrue(b.recvComplete(), "transfer did not complete within the step budget")
        XCTAssertEqual(b.read(totalBytes), original)
    }

    func testCleanWire() { run(80 * 1024 + 21, dropPct: 0, seed: 7) }
    func testLossyReorderingWire() { run(150 * 1024 + 99, dropPct: 20, seed: 0x51EED10D) }
}
