// SSLContext.swift
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

public enum SSLContextError: ErrorType {
	case Context(description: String)
    case Certificate(description: String)
}

public class SSLContext {
	internal var context: UnsafeMutablePointer<SSL_CTX>

	public init(method: SSLMethod = .SSLv23, type: SSLMethodType = .Unspecified) throws {
		OpenSSL.initialize()
        context = SSL_CTX_new(getMethod(method, type: type))

        if context == nil {
            throw SSLContextError.Context(description: lastSSLErrorDescription)
        }
	}

	public func useCertificate(certificate: SSLCertificate) throws {
        if SSL_CTX_use_certificate(context, certificate.certificate) != 1 {
            throw SSLContextError.Context(description: lastSSLErrorDescription)
        }
	}

	public func usePrivateKey(privateKey: SSLKey) throws {
        if SSL_CTX_use_PrivateKey(context, privateKey.privateKey) != 1 {
            throw SSLContextError.Context(description: lastSSLErrorDescription)
        }
	}

	public func setCipherSuites(cipherSuites: String) throws {
        if SSL_CTX_set_cipher_list(context, cipherSuites) != 1 {
            throw SSLContextError.Context(description: lastSSLErrorDescription)
        }
	}

	public func setSrtpProfiles(srtpProfiles: String) throws {
        if SSL_CTX_set_tlsext_use_srtp(context, srtpProfiles) != 1 {
            throw SSLContextError.Context(description: lastSSLErrorDescription)
        }
	}

}
