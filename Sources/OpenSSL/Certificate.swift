// SSLCertificate.swift
//
// The MIT License (MIT)
//
// Copyright (c) 2015 Zewo
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDINbG BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import COpenSSL

#if os(OSX) || os(iOS) || os(tvOS) || os(watchOS)
    import Darwin
#elseif os(Linux)
    import Glibc
#endif

private extension UInt8 {
	var hexString: String {
		let str = String(self, radix: 16)
		return (self < 16 ? "0"+str : str)
	}
}

private extension X509 {

	var validityNotBefore: UnsafeMutablePointer<ASN1_TIME> {
		return cert_info.pointee.validity.pointee.notBefore
	}

	var validityNotAfter: UnsafeMutablePointer<ASN1_TIME> {
		return cert_info.pointee.validity.pointee.notAfter
	}

}

public class Certificate {

	public enum Error: ErrorProtocol {
		case Certificate
		case Subject
		case PrivateKey
		case Extension
		case Sign
	}

	var certificate: UnsafeMutablePointer<X509>?

	public var fingerprint: String {
		let md = UnsafeMutablePointer<UInt8>(allocatingCapacity: Int(EVP_MAX_MD_SIZE))
		defer { md.deinitialize(); md.deallocateCapacity(Int(EVP_MAX_MD_SIZE)) }
		var n: UInt32 = 0
		X509_digest(certificate, EVP_sha256(), md, &n)
		return UnsafeMutableBufferPointer(start: md, count: Int(EVP_MAX_MD_SIZE)).makeIterator().prefix(Int(n)).map({ $0.hexString }).joined(separator: ":")
	}

	public init(certificate: UnsafeMutablePointer<X509>) {
		OpenSSL.initialize()
		self.certificate = certificate
	}

	public init(privateKey: Key, commonName: String, expiresInDays: Int = 365, subjectAltName: String? = nil) throws {
		OpenSSL.initialize()

		let privateKey = privateKey.key
		var ret: Int32 = 0

		certificate = X509_new()

		guard let certificate = certificate else {
			throw Error.Certificate
		}

		let subject = X509_NAME_new()
		var ext = X509_EXTENSION_new()

        let serial = rand()
		ASN1_INTEGER_set(X509_get_serialNumber(certificate), Int(serial))

		ret = X509_NAME_add_entry_by_txt(subject, "CN", (MBSTRING_FLAG|1), commonName, Int32(commonName.utf8.count), -1, 0)
		guard ret >= 0 else { throw Error.Subject }

		ret = X509_set_issuer_name(certificate, subject)
		guard ret >= 0 else { throw Error.Subject }
		ret = X509_set_subject_name(certificate, subject)
		guard ret >= 0 else { throw Error.Subject }

		X509_gmtime_adj(certificate.pointee.validityNotBefore, 0)
		X509_gmtime_adj(certificate.pointee.validityNotAfter, expiresInDays*86400)

		ret = X509_set_pubkey(certificate, privateKey)
		guard ret >= 0 else { throw Error.PrivateKey }

		if let subjectAltName = subjectAltName {
			try subjectAltName.withCString { strPtr in
				ext = X509V3_EXT_conf_nid(nil, nil, NID_subject_alt_name, UnsafeMutablePointer<CChar>(strPtr))
				ret = X509_add_ext(certificate, ext, -1)
				X509_EXTENSION_free(ext)
				guard ret >= 0 else { throw Error.Extension }
			}
		}

		try "CA:FALSE".withCString { strPtr in
			ext = X509V3_EXT_conf_nid(nil, nil, NID_basic_constraints, UnsafeMutablePointer<CChar>(strPtr))
			ret = X509_add_ext(certificate, ext, -1)
			X509_EXTENSION_free(ext)
			guard ret >= 0 else { throw Error.Extension }
		}

		// TODO: add extensions NID_subject_key_identifier and NID_authority_key_identifier

		ret = X509_sign(certificate, privateKey, EVP_sha256())
		guard ret >= 0 else { throw Error.Sign }
	}
    
    /**
        Generates a random Int for use
       
        -returns: Int
     */
    func rand() -> Int {
        #if os(OSX) || os(iOS) || os(tvOS) || os(watchOS)
            return Int(arc4random())
        #elseif os(Linux)
            while true {
                let x = Glibc.random()
                let y = Glibc.random()
                guard x == y else { return Int(x) }
            }
        #endif
    }
}
