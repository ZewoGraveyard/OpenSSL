import XCTest
@testable import OpenSSL

class OpenSSLTests: XCTestCase {
	func testReality() {
		XCTAssert(2 + 2 == 4, "Something is severely wrong here.")
	}
}

extension OpenSSLTests {
	static var allTests: [(String, (OpenSSLTests) -> () throws -> Void)] {
		return [
		   ("testReality", testReality),
		]
	}
}
