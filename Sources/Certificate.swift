// Certificate.swift
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
		return cert_info.pointee.validity.pointee.notBefore
	}

	var validityNotAfter: UnsafeMutablePointer<ASN1_TIME> {
		return cert_info.pointee.validity.pointee.notAfter
	}

}

public class Certificate {

	public enum Error: ErrorProtocol {
		case certificate
		case subject
		case privateKey
		case `extension`
		case sign
	}

	var certificate: UnsafeMutablePointer<X509>?

	public func getFingerprint(function: Hash.Function = .sha256) -> String {
		let md = UnsafeMutablePointer<UInt8>(allocatingCapacity: Int(EVP_MAX_MD_SIZE))
		defer { md.deinitialize(); md.deallocateCapacity(Int(EVP_MAX_MD_SIZE)) }
		var n: UInt32 = 0
		X509_digest(certificate, function.evp, md, &n)
		return UnsafeMutableBufferPointer(start: md, count: Int(EVP_MAX_MD_SIZE)).makeIterator().prefix(Int(n)).map({ $0.hexString }).joined(separator: ":")
	}

	init(certificate: UnsafeMutablePointer<X509>) {
		initialize()
		self.certificate = certificate
	}

	public init(privateKey: Key, commonName: String, expiresInDays: Int = 365, subjectAltName: String? = nil, function: Hash.Function = .sha256) throws {
		initialize()

		let privateKey = privateKey.key
		var ret: Int32 = 0

		certificate = X509_new()

		guard let certificate = certificate else {
			throw Error.certificate
		}

		let subject = X509_NAME_new()
		var ext = X509_EXTENSION_new()
		
        let serial = Random.number()
		ASN1_INTEGER_set(X509_get_serialNumber(certificate), Int(serial))

		ret = X509_NAME_add_entry_by_txt(subject, "CN", (MBSTRING_FLAG|1), commonName, Int32(commonName.utf8.count), -1, 0)
		guard ret >= 0 else { throw Error.subject }

		ret = X509_set_issuer_name(certificate, subject)
		guard ret >= 0 else { throw Error.subject }
		ret = X509_set_subject_name(certificate, subject)
		guard ret >= 0 else { throw Error.subject }

		X509_gmtime_adj(certificate.pointee.validityNotBefore, 0)
		X509_gmtime_adj(certificate.pointee.validityNotAfter, expiresInDays*86400)

		ret = X509_set_pubkey(certificate, privateKey)
		guard ret >= 0 else { throw Error.privateKey }

		if let subjectAltName = subjectAltName {
			try subjectAltName.withCString { strPtr in
				ext = X509V3_EXT_conf_nid(nil, nil, NID_subject_alt_name, UnsafeMutablePointer<CChar>(strPtr))
				ret = X509_add_ext(certificate, ext, -1)
				X509_EXTENSION_free(ext)
				guard ret >= 0 else { throw Error.extension }
			}
		}

		try "CA:FALSE".withCString { strPtr in
			ext = X509V3_EXT_conf_nid(nil, nil, NID_basic_constraints, UnsafeMutablePointer<CChar>(strPtr))
			ret = X509_add_ext(certificate, ext, -1)
			X509_EXTENSION_free(ext)
			guard ret >= 0 else { throw Error.extension }
		}

		// TODO: add extensions NID_subject_key_identifier and NID_authority_key_identifier
		
		ret = X509_sign(certificate, privateKey, function.evp)
		guard ret >= 0 else { throw Error.sign }
	}
	
	deinit {
		X509_free(certificate)
	}
    
}
