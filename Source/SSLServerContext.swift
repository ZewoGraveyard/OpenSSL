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

import COpenSSL

public final class SSLServerContext: SSLContext {
	public init(certificate: String, privateKey: String, certificateChain: String? = nil) throws {
		try super.init(method: .SSLv23, type: .Server)
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)

        if SSL_CTX_ctrl(context, SSL_CTRL_SET_ECDH_AUTO, 1, nil) != 1 {
            throw SSLContextError.Certificate(description: lastSSLErrorDescription)
        }

        if let certificateChain = certificateChain {
            if SSL_CTX_use_certificate_chain_file(context, certificateChain) != 1 {
                throw SSLContextError.Certificate(description: lastSSLErrorDescription)
            }
        }

        if SSL_CTX_use_certificate_file(context, certificate, SSL_FILETYPE_PEM) != 1 {
            throw SSLContextError.Certificate(description: lastSSLErrorDescription)
        }

        if SSL_CTX_use_PrivateKey_file(context, privateKey, SSL_FILETYPE_PEM) != 1 {
            throw SSLContextError.Certificate(description: lastSSLErrorDescription)
        }

        if SSL_CTX_check_private_key(context) != 1 {
            throw SSLContextError.Certificate(description: lastSSLErrorDescription)
        }
	}
}
