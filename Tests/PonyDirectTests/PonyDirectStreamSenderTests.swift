import XCTest
@testable import PonyDirect

final class PonyDirectStreamSenderTests: XCTestCase {

    private func seqs(_ o: [StreamOut]) -> [UInt64] {
        o.compactMap { if case let .data(seq, _) = $0 { return seq } else { return nil } }
    }
    private func hasFin(_ o: [StreamOut], _ at: UInt64) -> Bool {
        o.contains { if case let .fin(f) = $0 { return f == at } else { return false } }
    }

    func testSendsWindowThenFinAfterAck() {
        let s = PonyDirectStreamSender()
        s.write(Data(count: 2500)); s.finish()          // 3 chunks: 1024, 1024, 452
        let f0 = s.poll(0)
        XCTAssertEqual(seqs(f0), [0, 1024, 2048])
        XCTAssertFalse(f0.contains { if case .fin = $0 { return true } else { return false } })
        s.onAck(1, cumAck: 2500, rwnd: 1 << 20, blocks: [])
        XCTAssertTrue(s.isDone())
        XCTAssertTrue(hasFin(s.poll(2), 2500))
    }

    func testRetransmitsUnackedAfterRto() {
        let s = PonyDirectStreamSender(minRtoMs: 1000, initialRtoMs: 1000)
        s.write(Data(count: 2 * 1024)); s.finish()
        XCTAssertEqual(seqs(s.poll(0)), [0, 1024])
        s.onAck(10, cumAck: 1024, rwnd: 1 << 20, blocks: [])   // chunk 0 acked; chunk 1 in-flight
        XCTAssertEqual(seqs(s.poll(500)), [])                    // before RTO
        XCTAssertEqual(seqs(s.poll(1100)), [1024])              // after RTO: resend chunk 1
        s.onAck(1200, cumAck: 2048, rwnd: 1 << 20, blocks: [])
        XCTAssertTrue(s.isDone())
    }

    func testRespectsReceiveWindow() {
        let s = PonyDirectStreamSender()
        s.write(Data(count: 10 * 1024)); s.finish()
        s.onAck(0, cumAck: 0, rwnd: 2 * 1024, blocks: [])       // room for 2 chunks
        XCTAssertEqual(seqs(s.poll(0)), [0, 1024])
    }

    func testSackAcksOutOfOrderSoOnlyGapResends() {
        let s = PonyDirectStreamSender(minRtoMs: 1000, initialRtoMs: 1000)
        s.write(Data(count: 3 * 1024)); s.finish()
        XCTAssertEqual(seqs(s.poll(0)), [0, 1024, 2048])
        s.onAck(10, cumAck: 1024, rwnd: 1 << 20, blocks: [PonyDirectStream.SackBlock(start: 2048, end: 3072)])
        XCTAssertEqual(seqs(s.poll(1100)), [1024])              // only the gap
        s.onAck(1200, cumAck: 3072, rwnd: 1 << 20, blocks: [])
        XCTAssertTrue(s.isDone())
    }
}
