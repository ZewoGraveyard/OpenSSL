// Method.swift
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

public enum SSLMethod {
	public enum Mode {
		case server, client
	}
	
	case sslv23		// Negotiate highest available SSL/TLS version
	case tlsv1		// TLSv1.0
	case tlsv1_1	// TLSv1.1
	case tlsv1_2	// TLSv1.2
	case dtlsv1		// DTLSv1.0
//	case dtlsv1_2	// DTLSv1.2
//	case dtls		// DTLS 1.0 and 1.2
	
	func getMethod(mode: Mode = .client) -> UnsafePointer<SSL_METHOD> {
		switch self {
		case .sslv23:
			switch mode {
			case .server:
				return SSLv23_server_method()
			case .client:
				return SSLv23_client_method()
			}
		case .tlsv1:
			switch mode {
			case .server:
				return TLSv1_server_method()
			case .client:
				return TLSv1_client_method()
			}
		case .tlsv1_1:
			switch mode {
			case .server:
				return TLSv1_1_server_method()
			case .client:
				return TLSv1_1_client_method()
			}
		case .tlsv1_2:
			switch mode {
			case .server:
				return TLSv1_2_server_method()
			case .client:
				return TLSv1_2_client_method()
			}
		case .dtlsv1:
			switch mode {
			case .server:
				return DTLSv1_server_method()
			case .client:
				return DTLSv1_client_method()
			}
		/*case .DTLSv1_2:
			switch type {
			case .Unspecified:
				return DTLSv1_2_method()
			case .Server:
				return DTLSv1_2_server_method()
			case .Client:
				return DTLSv1_2_client_method()
			}
		case .DTLS:
			switch type {
			case .Unspecified:
				return DTLS_method()
			case .Server:
				return DTLS_server_method()
			case .Client:
				return DTLS_client_method()
			}*/
		}
	}
}
