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

import SSL
import COpenSSL

public final class SSLServerContext: SSLContext, SSLServerContextType {
	
	public var streamType: SSLServerStreamType.Type {
		return SSLServerStream.self
	}
	
	public init(certificate: String, privateKey: String, certificateChain: String? = nil) throws {
		super.init(method: .SSLv23, type: .Server)
		
		try self.withContext { context in
			SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
			SSL_CTX_set_ecdh_auto(context, 1)
			if let certificateChain = certificateChain {
				if SSL_CTX_use_certificate_chain_file(context, certificateChain) < 0 {
					throw SSLContextError.Certificate
				}
			}
			if SSL_CTX_use_certificate_file(context, certificate, SSL_FILETYPE_PEM) < 0 {
				throw SSLContextError.Certificate
			}
			if SSL_CTX_use_PrivateKey_file(context, privateKey, SSL_FILETYPE_PEM) < 0 {
				throw SSLContextError.Certificate
			}
		}
	}
	
}
