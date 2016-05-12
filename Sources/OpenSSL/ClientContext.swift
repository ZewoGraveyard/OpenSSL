// SSLClientContext.swift
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

typealias CCallback = @convention(c) (Void) -> Void

public final class SSLClientContext: Context {
	public init(verifyBundle: String? = nil,
	  certificate: String? = nil,
	  privateKey: String? = nil,
	  certificateChain: String? = nil) throws {
		try super.init(method: .SSLv23, type: .Client)

		SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nil)
		SSL_CTX_set_verify_depth(context, 4)
		SSL_CTX_set_options(context, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION)

		if SSL_CTX_set_default_verify_paths(context) != 1 {
			throw Context.Error.Certificate(description: lastSSLErrorDescription)
		}

		if let verifyBundle = verifyBundle {
			if SSL_CTX_load_verify_locations(context, verifyBundle, nil) != 1 {
				throw Context.Error.Certificate(description: lastSSLErrorDescription)
			}
		}

		if let certificateChain = certificateChain {
			if SSL_CTX_use_certificate_chain_file(context, certificateChain) != 1 {
				throw Context.Error.Certificate(description: lastSSLErrorDescription)
			}
		}

		if let certificate = certificate {
			if SSL_CTX_use_certificate_file(context, certificate, SSL_FILETYPE_PEM) != 1 {
				throw Context.Error.Certificate(description: lastSSLErrorDescription)
			}
		}

		if let privateKey = privateKey {
			if SSL_CTX_use_PrivateKey_file(context, privateKey, SSL_FILETYPE_PEM) != 1 {
				throw Context.Error.Certificate(description: lastSSLErrorDescription)
			}

			if SSL_CTX_check_private_key(context) != 1 {
				throw Context.Error.Certificate(description: lastSSLErrorDescription)
			}
		}
	}
}

func verify(_ preverify: Int32, _ X509Context: UnsafeMutablePointer<X509_STORE_CTX>!) -> Int32 {
//    let depth = X509_STORE_CTX_get_error_depth(X509Context)
	let cert = X509_STORE_CTX_get_current_cert(X509Context)
	let issuerName = X509_get_issuer_name(cert)
	let subjectName = X509_get_subject_name(cert)

	printCertificate("Issuer (cn)", issuerName)
	printCertificate("Subject (cn)", subjectName)

//    if depth == 0 {
//        print_san_name("Subject (san)", cert)
//    }

	return preverify
}

func SSL_CTX_set_options(_ ctx: UnsafeMutablePointer<SSL_CTX>?, _ op: CLong) {
	SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, op, nil)
}

func SSL_session_reused(_ ssl: UnsafeMutablePointer<SSL>) -> CLong {
	return SSL_ctrl(ssl, SSL_CTRL_GET_SESSION_REUSED, 0, nil)
}

func printCertificate(_ label: String, _ name: UnsafeMutablePointer<X509_NAME>?) {
	var success = false
	var utf8: UnsafeMutablePointer<UInt8>? = nil

	defer {
		if let utf8 = utf8 {
			OPENSSL_free(utf8)
		}

		if !success {
			print("  \(label): <not available>")
		}
	}

	if name == nil {
		return
	}

	let idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1)

	if idx < 0 {
		return
	}

	guard let entry = X509_NAME_get_entry(name, idx) else {
		return
	}

	guard let data = X509_NAME_ENTRY_get_data(entry) else {
		return
	}

	let length = ASN1_STRING_to_UTF8(&utf8, data)

	guard let string = utf8 where length > 0 else {
		return
	}

	print("  \(label): \(String(cString: UnsafeMutablePointer<CChar>(string)))")
	success = true
}
