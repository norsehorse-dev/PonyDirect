import XCTest
@testable import PonyDirect

final class PonyDirectPunchTests: XCTestCase {

    func testProbeRoundTripAndAuth() {
        let key = Data(repeating: 5, count: 32)
        let session = Data(repeating: 1, count: 16)
        let nonce = Data(repeating: 2, count: 16)
        let pkt = PonyDirectPunch.probe(pairKey: key, sessionNonce: session, probeNonce: nonce)
        XCTAssertEqual(pkt.count, PonyDirectPunch.probeLen)
        guard let parsed = PonyDirectPunch.parse(pkt) else { return XCTFail("no parse") }
        XCTAssertEqual(parsed.type, .probe)
        XCTAssertEqual(parsed.sessionNonce, session)
        XCTAssertEqual(parsed.probeNonce, nonce)
        XCTAssertTrue(PonyDirectPunch.verifyProbe(parsed, pairKey: key))
        XCTAssertFalse(PonyDirectPunch.verifyProbe(parsed, pairKey: Data(repeating: 9, count: 32)))
        XCTAssertFalse(PonyDirectPunch.verifyPong(parsed, pairKey: key))    // wrong type
    }

    func testPongRoundTripAndAuth() {
        let key = Data(repeating: 6, count: 32)
        let session = Data(repeating: 3, count: 16)
        let nonce = Data(repeating: 4, count: 16)
        let pkt = PonyDirectPunch.pong(pairKey: key, sessionNonce: session, probeNonce: nonce)
        guard let parsed = PonyDirectPunch.parse(pkt) else { return XCTFail("no parse") }
        XCTAssertEqual(parsed.type, .pong)
        XCTAssertTrue(PonyDirectPunch.verifyPong(parsed, pairKey: key))
    }

    func testTamperedTagRejected() {
        let key = Data(repeating: 6, count: 32)
        let session = Data(repeating: 3, count: 16)
        let nonce = Data(repeating: 4, count: 16)
        var pkt = [UInt8](PonyDirectPunch.probe(pairKey: key, sessionNonce: session, probeNonce: nonce))
        pkt[pkt.count - 1] ^= 0x01
        guard let parsed = PonyDirectPunch.parse(Data(pkt)) else { return XCTFail("no parse") }
        XCTAssertFalse(PonyDirectPunch.verifyProbe(parsed, pairKey: key))
    }

    func testKeepaliveShape() {
        let session = Data(repeating: 7, count: 16)
        let ka = PonyDirectPunch.keepalive(sessionNonce: session)
        XCTAssertEqual(ka.count, PonyDirectPunch.keepaliveLen)
        guard let parsed = PonyDirectPunch.parse(ka) else { return XCTFail("no parse") }
        XCTAssertEqual(parsed.type, .keepalive)
        XCTAssertEqual(parsed.sessionNonce, session)
    }

    func testWrongLengthRejected() {
        XCTAssertNil(PonyDirectPunch.parse(Data([0x11, 0x00, 0x00])))
    }
}
