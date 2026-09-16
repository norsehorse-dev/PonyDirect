import XCTest
@testable import PonyDirect

/// Drives a real PonyDirectStreamSender and PonyDirectStreamReceiver against a virtual-clock channel
/// with deterministic loss, reordering (latency jitter) and delay, and asserts the whole transfer
/// arrives byte-identical. This is what validates the ARQ end to end under adversarial conditions.
final class PonyDirectStreamLoopbackTests: XCTestCase {

    private final class Rng {
        private var s: UInt64
        init(_ seed: UInt64) { s = seed }
        func next() -> Int { s = s &* 6364136223846793005 &+ 1442695040888963407; return Int((s >> 33) & 0x7fffffff) }
        func dropped(_ pct: Int) -> Bool { next() % 100 < pct }
        func jitter(_ n: Int) -> Int64 { n <= 0 ? 0 : Int64(next() % n) }
    }

    private struct Item {
        let at: Int64; let kind: Int; let seq: UInt64; let payload: Data
        let cumAck: UInt64; let rwnd: UInt32; let blocks: [PonyDirectStream.SackBlock]
    }

    private func run(_ totalBytes: Int, dropFwd: Int, dropRev: Int, seed: UInt64) {
        var original = Data(count: totalBytes)
        for i in 0..<totalBytes { original[i] = UInt8((i * 31 + 7) % 251) }
        let s = PonyDirectStreamSender()
        let r = PonyDirectStreamReceiver()
        s.write(original); s.finish()
        let rng = Rng(seed)
        let baseLat: Int64 = 30; let jitter = 40

        var fwd: [Item] = []; var rev: [Item] = []
        var now: Int64 = 0; let step: Int64 = 20; var steps = 0
        while !r.isComplete() && steps < 400_000 {
            for o in s.poll(now) {
                switch o {
                case let .data(seq, payload):
                    if !rng.dropped(dropFwd) {
                        fwd.append(Item(at: now + baseLat + rng.jitter(jitter), kind: 0, seq: seq,
                                        payload: payload, cumAck: 0, rwnd: 0, blocks: []))
                    }
                case let .fin(finalSeq):
                    if !rng.dropped(dropFwd) {
                        fwd.append(Item(at: now + baseLat + rng.jitter(jitter), kind: 1, seq: finalSeq,
                                        payload: Data(), cumAck: 0, rwnd: 0, blocks: []))
                    }
                }
            }
            let fdue = fwd.filter { $0.at <= now }; fwd.removeAll { $0.at <= now }
            for it in fdue { if it.kind == 0 { r.onData(seq: it.seq, payload: it.payload) } else { r.onFin(finalSeq: it.seq) } }

            if !rng.dropped(dropRev) {
                rev.append(Item(at: now + baseLat + rng.jitter(jitter), kind: 2, seq: 0, payload: Data(),
                                cumAck: r.cumAck(), rwnd: r.rwnd(), blocks: r.sackBlocks()))
            }
            let rdue = rev.filter { $0.at <= now }; rev.removeAll { $0.at <= now }
            for it in rdue { s.onAck(now, cumAck: it.cumAck, rwnd: it.rwnd, blocks: it.blocks) }

            now += step; steps += 1
        }
        XCTAssertTrue(r.isComplete(), "transfer did not complete within the step budget")
        XCTAssertEqual(r.read(totalBytes), original)
        XCTAssertTrue(s.isDone())
    }

    func testCleanChannel() { run(100 * 1024 + 137, dropFwd: 0, dropRev: 0, seed: 42) }
    func testLossAndReorder() { run(200 * 1024 + 500, dropFwd: 20, dropRev: 10, seed: 0x12345678) }
    func testHeavyLoss() { run(64 * 1024 + 33, dropFwd: 40, dropRev: 30, seed: 0xC0FFEE) }
}
