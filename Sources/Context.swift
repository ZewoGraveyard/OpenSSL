// Context.swift
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

public class Context {
	
	public enum Error: ErrorProtocol {
		case context(description: String)
		case certificate(description: String)
		case key(description: String)
	}
	
	let mode: SSLMethod.Mode
	var context: UnsafeMutablePointer<SSL_CTX>?
	var sniHostname: String? = nil
	
	public init(method: SSLMethod = .sslv23, mode: SSLMethod.Mode = .client) throws {
		self.mode = mode
		
		initialize()
		context = SSL_CTX_new(method.getMethod(mode: mode))

		if context == nil {
			throw Error.context(description: lastSSLErrorDescription)
		}
		
		if mode == .client {
			SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nil)
			SSL_CTX_set_verify_depth(context, 4)
			SSL_CTX_ctrl(context, SSL_CTRL_OPTIONS, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION, nil)
			try useDefaultVerifyPaths()
		} else {
			SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
		}
	}
	
	public convenience init(method: SSLMethod = .sslv23, mode: SSLMethod.Mode = .client, verifyBundle: String? = nil, certificate: String? = nil, privateKey: String? = nil, certificateChain: String? = nil, SNIHostname: String? = nil) throws {
		try self.init(method: method, mode: mode)
		
		if let verifyBundle = verifyBundle {
			try useVerifyBundle(verifyBundle: verifyBundle)
		}
		
		if let certificateChain = certificateChain {
			try useCertificateChainFile(certificateChainFile: certificateChain)
		}
		
		if let certificate = certificate {
			try useCertificateFile(certificateFile: certificate)
		}
		
		if let privateKey = privateKey {
			try usePrivateKeyFile(privateKeyFile: privateKey)
		}
		
		if let SNIHostname = SNIHostname {
			try setServerNameIndication(hostname: SNIHostname)
		}
	}

	deinit {
		SSL_CTX_free(context)
	}

	public func useDefaultVerifyPaths() throws {
		if SSL_CTX_set_default_verify_paths(context) != 1 {
			throw Error.context(description: lastSSLErrorDescription)
		}
	}
	
	public func useVerifyBundle(verifyBundle: String) throws {
		if SSL_CTX_load_verify_locations(context, verifyBundle, nil) != 1 {
			throw Error.context(description: lastSSLErrorDescription)
		}
	}
	
	public func useCertificate(certificate: Certificate) throws {
		if SSL_CTX_use_certificate(context, certificate.certificate) != 1 {
			throw Error.certificate(description: lastSSLErrorDescription)
		}
	}
	
	public func useCertificateFile(certificateFile: String) throws {
		if SSL_CTX_use_certificate_file(context, certificateFile, SSL_FILETYPE_PEM) != 1 {
			throw Error.certificate(description: lastSSLErrorDescription)
		}
	}
	
	public func useCertificateChainFile(certificateChainFile: String) throws {
		if SSL_CTX_use_certificate_chain_file(context, certificateChainFile) != 1 {
			throw Error.certificate(description: lastSSLErrorDescription)
		}
	}

	public func usePrivateKey(privateKey: Key, check: Bool = true) throws {
		if SSL_CTX_use_PrivateKey(context, privateKey.key) != 1 {
			throw Error.key(description: lastSSLErrorDescription)
		}
		if check {
			try checkPrivateKey()
		}
	}
	
	public func usePrivateKeyFile(privateKeyFile: String, check: Bool = true) throws {
		if SSL_CTX_use_PrivateKey_file(context, privateKeyFile, SSL_FILETYPE_PEM) != 1 {
			throw Error.key(description: lastSSLErrorDescription)
		}
		if check {
			try checkPrivateKey()
		}
	}
	
	private func checkPrivateKey() throws {
		if SSL_CTX_check_private_key(context) != 1 {
			throw Error.key(description: lastSSLErrorDescription)
		}
	}

	public func setCipherSuites(cipherSuites: String) throws {
		if SSL_CTX_set_cipher_list(context, cipherSuites) != 1 {
			throw Error.context(description: lastSSLErrorDescription)
		}
	}

	public func setSrtpProfiles(srtpProfiles: String) throws {
		if SSL_CTX_set_tlsext_use_srtp(context, srtpProfiles) != 1 {
			throw Error.context(description: lastSSLErrorDescription)
		}
	}
	
	public func setServerNameIndication(hostname: String) throws {
		sniHostname = hostname
	}

}
