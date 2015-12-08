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

private extension UInt8 {
	var hexString: String {
		let str = String(self, radix: 16)
		return (self < 16 ? "0"+str : str)
	}
}

private extension X509 {

	var validityNotBefore: UnsafeMutablePointer<ASN1_TIME> {
		return cert_info.memory.validity.memory.notBefore
	}

	var validityNotAfter: UnsafeMutablePointer<ASN1_TIME> {
		return cert_info.memory.validity.memory.notAfter
	}

}

public class SSLCertificate {

	internal let cert: X509
	
	public var fingerprint: String {
		var cert = self.cert
		return withUnsafeMutablePointer(&cert) { ptr in
			let md = UnsafeMutablePointer<UInt8>.alloc(Int(EVP_MAX_MD_SIZE))
			defer { md.destroy(); md.dealloc(Int(EVP_MAX_MD_SIZE)) }
			var n: UInt32 = 0
			X509_digest(ptr, EVP_sha256(), md, &n)
			return UnsafeMutableBufferPointer(start: md, count: Int(EVP_MAX_MD_SIZE)).generate().prefix(Int(n)).map({ $0.hexString }).joinWithSeparator(":")
		}
	}

	public init(privateKey: SSLKey, commonName: String, expireDays: Int = 365, subjectAltName: String? = nil) {
		var privateKey = privateKey.key

		let cert = X509_new()
		let subject = X509_NAME_new()
		let ext = X509_EXTENSION_new()

		let serial = rand()
		ASN1_INTEGER_set(X509_get_serialNumber(cert), Int(serial))

		X509_NAME_add_entry_by_txt(subject, "CN", (MBSTRING_FLAG|1), commonName, Int32(commonName.utf8.count), -1, 0)
		X509_set_issuer_name(cert, subject)
		X509_set_subject_name(cert, subject)

		X509_gmtime_adj(cert.memory.validityNotBefore, 0)
		X509_gmtime_adj(cert.memory.validityNotAfter, expireDays*86400)

		X509_set_pubkey(cert, &privateKey)

		if let subjectAltName = subjectAltName {
			subjectAltName.withCString { strPtr in
				X509V3_EXT_conf_nid(nil, nil, NID_subject_alt_name, UnsafeMutablePointer<CChar>(strPtr))
			}
		}

		"CA:FALSE".withCString { strPtr in
			X509V3_EXT_conf_nid(nil, nil, NID_basic_constraints, UnsafeMutablePointer<CChar>(strPtr))
		}

		X509_add_ext(cert, ext, -1)
		X509_EXTENSION_free(ext)

		// TODO: add extensions NID_subject_key_identifier and NID_authority_key_identifier

		X509_sign(cert, &privateKey, EVP_sha256())

		self.cert = cert.memory
	}

}
