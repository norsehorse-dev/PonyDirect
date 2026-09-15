import XCTest
@testable import PonyDirect

final class PonyDirectWireTests: XCTestCase {
    func testFrameRoundTrip() {
        let payload = Data("hello world".utf8)
        let framed = PonyDirectWire.frame(.envelope, payload)
        guard let parsed = PonyDirectWire.parseFrame(framed) else { return XCTFail("no frame") }
        XCTAssertEqual(parsed.type, .envelope)
        XCTAssertEqual(parsed.payload, payload)
        XCTAssertEqual(parsed.consumed, framed.count)
    }

    func testPartialFrameReturnsNil() {
        let framed = PonyDirectWire.frame(.hello, Data([1,2,3,4]))
        XCTAssertNil(PonyDirectWire.parseFrame(framed.prefix(6)))
    }

    func testTagsAreDeterministicAndKeyed() {
        let key = Data(repeating: 7, count: 32)
        let other = Data(repeating: 9, count: 32)
        let nonce = Data(repeating: 1, count: 16)
        let a = PonyDirectWire.identifyTag(pairKey: key, dialerNonce: nonce)
        let b = PonyDirectWire.identifyTag(pairKey: key, dialerNonce: nonce)
        let c = PonyDirectWire.identifyTag(pairKey: other, dialerNonce: nonce)
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.count, 32)
        XCTAssertNotEqual(a, c)
        XCTAssertTrue(PonyDirectWire.constantTimeEquals(a, b))
        XCTAssertFalse(PonyDirectWire.constantTimeEquals(a, c))
    }

    func testAckBindsBothNonces() {
        let key = Data(repeating: 3, count: 32)
        let dn = Data(repeating: 1, count: 16), ln = Data(repeating: 2, count: 16)
        let t1 = PonyDirectWire.identifyAckTag(pairKey: key, dialerNonce: dn, listenerNonce: ln)
        let t2 = PonyDirectWire.identifyAckTag(pairKey: key, dialerNonce: ln, listenerNonce: dn)
        XCTAssertNotEqual(t1, t2)
    }
}
