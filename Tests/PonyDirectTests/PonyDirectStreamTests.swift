import XCTest
@testable import PonyDirect

// Cross-platform stream-frame vectors, shared with the Kotlin PonyDirectStreamTest. pairKey =
// bytes 0x00..0x1f, sessionNonce = bytes 0x00..0x0f.
final class PonyDirectStreamTests: XCTestCase {

    private let key = Data((0..<32).map { UInt8($0) })
    private let sn = Data((0..<16).map { UInt8($0) })
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func testSdataVectorAndRoundTrip() {
        let f = PonyDirectStream.data(pairKey: key, sessionNonce: sn, seq: 100000, payload: Data("hello stream".utf8))
        XCTAssertEqual(hex(f), "16000102030405060708090a0b0c0d0e0f00000000000186a0000c68656c6c6f2073747265616d81a4d6bb3f3639126352ee4035ae20595e51380b6749cf0e329989583795c35a")
        let p = PonyDirectStream.parseData(f)!
        XCTAssertEqual(p.sessionNonce, sn)
        XCTAssertEqual(p.seq, 100000)
        XCTAssertEqual(p.payload, Data("hello stream".utf8))
        XCTAssertTrue(PonyDirectStream.verifyData(p, pairKey: key))
        XCTAssertFalse(PonyDirectStream.verifyData(p, pairKey: Data(repeating: 9, count: 32)))
    }

    func testSackVectorAndRoundTrip() {
        let blocks = [PonyDirectStream.SackBlock(start: 70000, end: 71024),
                      PonyDirectStream.SackBlock(start: 72048, end: 73072)]
        let f = PonyDirectStream.ack(pairKey: key, sessionNonce: sn, cumAck: 65536, rwnd: 262144, blocks: blocks)
        XCTAssertEqual(hex(f), "17000102030405060708090a0b0c0d0e0f000000000001000000040000020000000000011170000000000001157000000000000119700000000000011d70dc1fa9c5c6d5cc419e21e5df35f7003deedf1e37cadd5af6141155760d48a162")
        let p = PonyDirectStream.parseAck(f)!
        XCTAssertEqual(p.cumAck, 65536)
        XCTAssertEqual(p.rwnd, 262144)
        XCTAssertEqual(p.blocks, blocks)
        XCTAssertTrue(PonyDirectStream.verifyAck(p, pairKey: key))
    }

    func testSackZeroBlocks() {
        let f = PonyDirectStream.ack(pairKey: key, sessionNonce: sn, cumAck: 65536, rwnd: 262144, blocks: [])
        XCTAssertEqual(hex(f), "17000102030405060708090a0b0c0d0e0f0000000000010000000400000099217d50aefd2beabe7d29ff5f45c8db5e851737bb7aa739155eab05c4b4ca8a")
        XCTAssertEqual(PonyDirectStream.parseAck(f)!.blocks, [])
    }

    func testFinVectorAndRoundTrip() {
        let f = PonyDirectStream.fin(pairKey: key, sessionNonce: sn, finalSeq: 999999)
        XCTAssertEqual(hex(f), "18000102030405060708090a0b0c0d0e0f00000000000f423f54d7b924e43840818ee903b236e4f9d65413ffbf3c911cbab3263cad78e005e7")
        let p = PonyDirectStream.parseFin(f)!
        XCTAssertEqual(p.finalSeq, 999999)
        XCTAssertTrue(PonyDirectStream.verifyFin(p, pairKey: key))
    }

    func testRstVectorAndRoundTrip() {
        let f = PonyDirectStream.rst(pairKey: key, sessionNonce: sn)
        XCTAssertEqual(hex(f), "19000102030405060708090a0b0c0d0e0f9e158760dbf00de7046140c7ea88495241193b8dd83805f7f11e61b31fec232a")
        let p = PonyDirectStream.parseRst(f)!
        XCTAssertEqual(p.sessionNonce, sn)
        XCTAssertTrue(PonyDirectStream.verifyRst(p, pairKey: key))
    }

    func testLargePayloadAndHighSeqRoundTrip() {
        let payload = Data((0..<1024).map { UInt8($0 % 256) })
        let f = PonyDirectStream.data(pairKey: key, sessionNonce: sn, seq: 0xFFFFFFFF00, payload: payload)
        let p = PonyDirectStream.parseData(f)!
        XCTAssertEqual(p.seq, 0xFFFFFFFF00)
        XCTAssertEqual(p.payload, payload)
        XCTAssertTrue(PonyDirectStream.verifyData(p, pairKey: key))
    }
}
