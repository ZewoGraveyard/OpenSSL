import XCTest
@testable import OpenSSL

class CertificateTests: XCTestCase {
    /**
        Test for https://github.com/Zewo/OpenSSL/pull/20
    */
    func testRand() throws {
        let key = Key.generate(keyLength: 2048)
        let cn = "example.com"
        
        let cert = try Certificate(privateKey:key, commonName:cn)
		
        let first = Random.number()
        let second = Random.number()
        
        XCTAssert(
            first != second,
            "Two successive random numbers really shouldn't be the same"
        )
    }
}

extension CertificateTests {
    static var allTests: [(String, (CertificateTests) -> () throws -> Void)] {
        return [
            ("testRand", testRand),
        ]
    }
}
