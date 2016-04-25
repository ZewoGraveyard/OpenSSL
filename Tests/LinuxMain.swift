#if os(Linux)

import XCTest
@testable import OpenSSLTestSuite

XCTMain([
    testCase(OpenSSLTests.allTests)
])

#endif
