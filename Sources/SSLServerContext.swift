// SSLServerContext.swift
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

#if os(Linux)
	import Glibc
#else
	import Darwin.C
#endif

import SSL
import COpenSSL

public final class SSLServerContext: SSLContext, SSLServerContextType {
	
	public let ctx: UnsafeMutablePointer<SSL_CTX>
	
	public var streamType: SSLServerStreamType.Type {
		return SSLServerStream.self
	}
	
	public init(certificate: String, privateKey: String, certificateChain: String? = nil) throws {
		self.ctx = SSL_CTX_new(SSLv23_method())
		if ctx == nil {
			throw SSLContextError.GenericError
		}
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)
		SSL_CTX_set_ecdh_auto(ctx, 1)
		if let certificateChain = certificateChain {
			if SSL_CTX_use_certificate_chain_file(ctx, certificateChain) < 0 {
				throw SSLContextError.CertificateError
			}
		}
		if SSL_CTX_use_certificate_file(ctx, certificate, SSL_FILETYPE_PEM) < 0 {
			throw SSLContextError.CertificateError
		}
		if SSL_CTX_use_PrivateKey_file(ctx, privateKey, SSL_FILETYPE_PEM) < 0 {
			throw SSLContextError.CertificateError
		}
	}
	
}
