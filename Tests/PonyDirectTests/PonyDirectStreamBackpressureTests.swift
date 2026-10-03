import XCTest
import CryptoKit
@testable import PonyDirect

/// Streaming sends: the sender holds bytes only until they are acknowledged, so a writer that waits
/// on sendBufferedBytes moves a stream far larger than its high-water mark with bounded memory.
/// Mirrors the Kotlin PonyDirectStreamBackpressureTest.
final class PonyDirectStreamBackpressureTests: XCTestCase {

    func testAckedChunksAreReleased() {
        let s = PonyDirectStreamSender()
        s.write(Data(count: 10 * 1024))
        XCTAssertEqual(s.bufferedBytes, 10 * 1024)
        _ = s.poll(0)
        s.onAck(10, cumAck: 4 * 1024, rwnd: 1 << 20, blocks: [])
        XCTAssertEqual(s.bufferedBytes, 6 * 1024)
        s.write(Data(count: 500)); s.finish()
        XCTAssertEqual(s.bufferedBytes, 6 * 1024 + 500)
        _ = s.poll(20)
        s.onAck(30, cumAck: 10 * 1024 + 500, rwnd: 1 << 20, blocks: [])
        XCTAssertEqual(s.bufferedBytes, 0)
        XCTAssertTrue(s.isDone())
    }

    func testPartialChunksAcrossWritesStayInOrder() {
        let s = PonyDirectStreamSender()
        let r = PonyDirectStreamReceiver()
        let original = Data((0..<5000).map { UInt8($0 % 251) })
        for (a, b) in [(0, 700), (700, 2100), (2100, 2101), (2101, 5000)] {
            s.write(original.subdata(in: a..<b))
        }
        s.finish()
        var now: Int64 = 0
        while !s.isDone() {
            for o in s.poll(now) {
                switch o {
                case let .data(seq, payload): r.onData(seq: seq, payload: payload)
                case let .fin(f): r.onFin(finalSeq: f)
                }
            }
            s.onAck(now, cumAck: r.cumAck(), rwnd: r.rwnd(), blocks: r.sackBlocks())
            now += 20
        }
        XCTAssertEqual(r.read(10_000), original)
    }

    func testLargeStreamWithHighWaterMark_memoryStaysBounded() {
        let key = Data((0..<32).map { UInt8(($0 * 5 + 2) & 0xff) })
        let nonce = Data((0..<16).map { UInt8($0 + 9) })
        let total: Int64 = 24 << 20                 // 24 MiB through a 1 MiB high-water mark
        let highWater: Int64 = 1 << 20
        let piece = 64 * 1024
        var aToB: [Data] = [], bToA: [Data] = []
        let a = PonyDirectStreamEngine(pairKey: key, sessionNonce: nonce, onDatagram: { aToB.append($0) })
        let b = PonyDirectStreamEngine(pairKey: key, sessionNonce: nonce, onDatagram: { bToA.append($0) })
        var sent = SHA256(), got = SHA256()
        var written: Int64 = 0, received: Int64 = 0, peak: Int64 = 0, now: Int64 = 0
        var counter = 0, steps = 0
        while !b.recvComplete() && steps < 2_000_000 {
            while written < total && a.sendBufferedBytes() < highWater {
                let n = Int(Swift.min(Int64(piece), total - written))
                var chunk = Data(count: n)
                for i in 0..<n { chunk[i] = UInt8(counter % 253); counter += 1 }
                sent.update(data: chunk); a.write(chunk); written += Int64(n)
                if written == total { a.finishSending() }
            }
            peak = Swift.max(peak, a.sendBufferedBytes())
            a.tick(now); b.tick(now)
            let toB = aToB; aToB.removeAll(); toB.forEach { b.onWireDatagram(now, $0) }
            let toA = bToA; bToA.removeAll(); toA.forEach { a.onWireDatagram(now, $0) }
            let r = b.read(1 << 20); got.update(data: r); received += Int64(r.count)
            now += 5; steps += 1
        }
        let rest = b.read(Int.max); got.update(data: rest); received += Int64(rest.count)
        XCTAssertTrue(b.recvComplete(), "stream did not complete")
        XCTAssertEqual(received, total)
        XCTAssertEqual(Data(sent.finalize()), Data(got.finalize()))
        XCTAssertLessThanOrEqual(peak, highWater + Int64(piece))
    }
}
