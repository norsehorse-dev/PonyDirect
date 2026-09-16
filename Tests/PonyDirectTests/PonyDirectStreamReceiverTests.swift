import XCTest
@testable import PonyDirect

final class PonyDirectStreamReceiverTests: XCTestCase {

    private let stream = Data((0..<(4 * 1024 + 500)).map { UInt8($0 % 251) })

    private func feed(_ r: PonyDirectStreamReceiver, _ i: Int) {
        let start = i * 1024
        let end = Swift.min(start + 1024, stream.count)
        r.onData(seq: UInt64(start), payload: stream.subdata(in: start..<end))
    }

    func testReassemblesOutOfOrderWithGapDupAndFin() {
        let r = PonyDirectStreamReceiver()
        feed(r, 2)
        XCTAssertEqual(r.cumAck(), 0)
        XCTAssertEqual(r.sackBlocks(), [PonyDirectStream.SackBlock(start: 2048, end: 3072)])

        feed(r, 0); feed(r, 1); feed(r, 1); feed(r, 4); feed(r, 3)
        XCTAssertEqual(r.cumAck(), UInt64(stream.count))
        XCTAssertEqual(r.sackBlocks(), [])

        r.onFin(finalSeq: UInt64(stream.count))
        XCTAssertTrue(r.isComplete())
        XCTAssertEqual(r.read(stream.count), stream)
    }

    func testTwoDisjointGapsGiveTwoSackBlocks() {
        let r = PonyDirectStreamReceiver()
        feed(r, 1); feed(r, 3)
        XCTAssertEqual(r.cumAck(), 0)
        XCTAssertEqual(r.sackBlocks(), [
            PonyDirectStream.SackBlock(start: 1024, end: 2048),
            PonyDirectStream.SackBlock(start: 3072, end: 4096),
        ])
    }

    func testRwndShrinksWhileBufferingOutOfOrder() {
        let r = PonyDirectStreamReceiver(capacity: 8 * 1024)
        let full = r.rwnd()
        feed(r, 1)
        XCTAssertLessThan(r.rwnd(), full)
        XCTAssertEqual(r.rwnd(), full - 1024)
    }
}
