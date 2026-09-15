import XCTest
@testable import PonyDirect

final class PonyDirectStunTests: XCTestCase {

    func testBindingRequestShape() {
        let txn = Data((0..<12).map { UInt8($0) })
        let req = PonyDirectStun.bindingRequest(transactionID: txn)
        XCTAssertEqual(req.count, 20)
        let b = [UInt8](req)
        XCTAssertEqual(b[0], 0x00); XCTAssertEqual(b[1], 0x01)     // Binding request
        XCTAssertEqual(b[2], 0x00); XCTAssertEqual(b[3], 0x00)     // length 0
        XCTAssertEqual(b[4], 0x21); XCTAssertEqual(b[5], 0x12)
        XCTAssertEqual(b[6], 0xA4); XCTAssertEqual(b[7], 0x42)     // magic cookie
        XCTAssertEqual(Data(b[8..<20]), txn)
    }

    // A hand-built XOR-MAPPED-ADDRESS success response for 203.0.113.5:51234.
    func testParseXorMappedAddress() {
        let txn = Data((0..<12).map { UInt8($0) })
        var msg: [UInt8] = [
            0x01, 0x01,             // Binding success
            0x00, 0x0C,             // length = 12 (one 12-byte attribute)
            0x21, 0x12, 0xA4, 0x42, // magic cookie
        ]
        msg += [UInt8](txn)
        msg += [
            0x00, 0x20,             // XOR-MAPPED-ADDRESS
            0x00, 0x08,             // attr length 8
            0x00, 0x01,             // reserved, family IPv4
            0xE9, 0x30,             // X-Port = 51234 ^ 0x2112
            0xEA, 0x12, 0xD5, 0x47, // X-Address = 203.0.113.5 ^ cookie
        ]
        let parsed = PonyDirectStun.parseResponse(Data(msg), transactionID: txn)
        XCTAssertEqual(parsed?.ip, "203.0.113.5")
        XCTAssertEqual(parsed?.port, 51234)
    }

    func testWrongTransactionRejected() {
        let txn = Data((0..<12).map { UInt8($0) })
        let wrong = Data((0..<12).map { _ in UInt8(0xFF) })
        var msg: [UInt8] = [0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42]
        msg += [UInt8](txn)
        msg += [0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xE9, 0x30, 0xEA, 0x12, 0xD5, 0x47]
        XCTAssertNil(PonyDirectStun.parseResponse(Data(msg), transactionID: wrong))
    }

    func testPlainMappedAddressFallback() {
        let txn = Data(repeating: 0xAB, count: 12)
        var msg: [UInt8] = [0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42]
        msg += [UInt8](txn)
        msg += [
            0x00, 0x01,             // MAPPED-ADDRESS
            0x00, 0x08,
            0x00, 0x01,
            0xC8, 0x22,             // port 51234, not XORed
            0xCB, 0x00, 0x71, 0x05, // 203.0.113.5, not XORed
        ]
        let parsed = PonyDirectStun.parseResponse(Data(msg), transactionID: txn)
        XCTAssertEqual(parsed?.ip, "203.0.113.5")
        XCTAssertEqual(parsed?.port, 51234)
    }
}
