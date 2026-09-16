import XCTest
@testable import PonyDirect

final class PonyDirectStreamCongestionTests: XCTestCase {

    func testSlowStartGrowsThenTimeoutCollapses() {
        let s = PonyDirectStreamSender(minRtoMs: 1000, initialRtoMs: 1000)
        s.write(Data(count: 100 * 1024)); s.finish()
        let initC = s.cwndBytes
        _ = s.poll(0)
        s.onAck(50, cumAck: 4 * 1024, rwnd: 1 << 20, blocks: [])   // 4 chunks acked in slow start
        XCTAssertGreaterThan(s.cwndBytes, initC)
        let grown = s.cwndBytes
        _ = s.poll(2000)                                            // outstanding chunks time out
        XCTAssertLessThan(s.cwndBytes, grown)
        XCTAssertEqual(s.cwndBytes, 1024)                          // timeout restarts slow start at 1 MSS
    }

    func testCongestionAvoidanceGrowsSlowerThanSlowStart() {
        let s = PonyDirectStreamSender(initialCwndBytes: 4096, initialSsthreshBytes: 4096,
                                       minRtoMs: 1000, initialRtoMs: 1000)
        s.write(Data(count: 200 * 1024)); s.finish()
        _ = s.poll(0)
        let before = s.cwndBytes
        s.onAck(50, cumAck: 4 * 1024, rwnd: 1 << 20, blocks: [])   // ack 4 chunks while in avoidance
        let delta = s.cwndBytes - before
        XCTAssertGreaterThanOrEqual(delta, 1)
        XCTAssertLessThan(delta, 4 * 1024)
    }
}
