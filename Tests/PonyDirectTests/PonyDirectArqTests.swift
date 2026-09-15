import XCTest
@testable import PonyDirect

final class PonyDirectArqTests: XCTestCase {

    func testDataRoundTripAndAuth() {
        let key = Data(repeating: 7, count: 32)
        let session = Data(repeating: 1, count: 16)
        let payload = Data((0..<200).map { UInt8($0 % 256) })
        let pkt = PonyDirectArq.data(pairKey: key, sessionNonce: session, msgSeq: 0x01020304,
                                     chunkIndex: 5, chunkCount: 10, payload: payload)
        guard let p = PonyDirectArq.parseData(pkt) else { return XCTFail("no parse") }
        XCTAssertEqual(p.sessionNonce, session)
        XCTAssertEqual(p.msgSeq, 0x01020304)
        XCTAssertEqual(p.chunkIndex, 5)
        XCTAssertEqual(p.chunkCount, 10)
        XCTAssertEqual(p.payload, payload)
        XCTAssertTrue(PonyDirectArq.verifyData(p, pairKey: key))
        XCTAssertFalse(PonyDirectArq.verifyData(p, pairKey: Data(repeating: 9, count: 32)))
    }

    func testDataTamperRejected() {
        let key = Data(repeating: 7, count: 32)
        let session = Data(repeating: 1, count: 16)
        var pkt = [UInt8](PonyDirectArq.data(pairKey: key, sessionNonce: session, msgSeq: 1,
                                             chunkIndex: 0, chunkCount: 1, payload: Data([1, 2, 3])))
        pkt[26] ^= 0x01   // flip a payload byte
        guard let p = PonyDirectArq.parseData(Data(pkt)) else { return XCTFail("no parse") }
        XCTAssertFalse(PonyDirectArq.verifyData(p, pairKey: key))
    }

    func testEmptyPayloadChunk() {
        let key = Data(repeating: 2, count: 32)
        let session = Data(repeating: 3, count: 16)
        let pkt = PonyDirectArq.data(pairKey: key, sessionNonce: session, msgSeq: 1,
                                     chunkIndex: 0, chunkCount: 1, payload: Data())
        XCTAssertEqual(pkt.count, 57)
        guard let p = PonyDirectArq.parseData(pkt) else { return XCTFail("no parse") }
        XCTAssertEqual(p.payload.count, 0)
        XCTAssertTrue(PonyDirectArq.verifyData(p, pairKey: key))
    }

    func testAckRoundTripAndAuth() {
        let key = Data(repeating: 4, count: 32)
        let session = Data(repeating: 5, count: 16)
        var bitmap = Data(repeating: 0, count: PonyDirectArq.bitmapLen(chunkCount: 10))
        PonyDirectArq.bitmapSet(&bitmap, 0)
        PonyDirectArq.bitmapSet(&bitmap, 9)
        let pkt = PonyDirectArq.ack(pairKey: key, sessionNonce: session, msgSeq: 42, chunkCount: 10, bitmap: bitmap)
        guard let p = PonyDirectArq.parseAck(pkt) else { return XCTFail("no parse") }
        XCTAssertEqual(p.msgSeq, 42)
        XCTAssertEqual(p.chunkCount, 10)
        XCTAssertTrue(PonyDirectArq.verifyAck(p, pairKey: key))
        XCTAssertTrue(PonyDirectArq.bitmapGet(p.bitmap, 0))
        XCTAssertTrue(PonyDirectArq.bitmapGet(p.bitmap, 9))
        XCTAssertFalse(PonyDirectArq.bitmapGet(p.bitmap, 5))
    }

    func testChunking() {
        let payload = Data(repeating: 0xAB, count: 2500)
        let chunks = PonyDirectArq.chunk(payload)
        XCTAssertEqual(chunks.count, 3)
        XCTAssertEqual(chunks[0].count, 1024)
        XCTAssertEqual(chunks[1].count, 1024)
        XCTAssertEqual(chunks[2].count, 452)
        XCTAssertEqual(chunks.reduce(Data(), +), payload)
    }
}
