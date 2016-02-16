// SSLMethod.swift
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

public enum SSLMethodType {
	case Unspecified, Server, Client
}

public enum SSLMethod {
//	case SSLv2		// SSLv2
	case SSLv3		// SSLv3
	case SSLv23		// Negotiate highest available SSL/TLS version
	case TLSv1		// TLSv1.0
	case TLSv1_1	// TLSv1.1
	case TLSv1_2	// TLSv1.2
	case DTLSv1		// DTLSv1.0
//	case DTLSv1_2	// DTLSv1.2
//	case DTLS		// DTLS 1.0 and 1.2
}

func getMethod(method: SSLMethod, type: SSLMethodType = .Unspecified) -> UnsafePointer<SSL_METHOD> {
	switch method {
	/*case .SSLv2:
		switch type {
		case .Unspecified:
			return SSLv2_method()
		case .Server:
			return SSLv2_server_method()
		case .Client:
			return SSLv2_client_method()
		}*/
	case .SSLv3:
		switch type {
		case .Unspecified:
			return SSLv3_method()
		case .Server:
			return SSLv3_server_method()
		case .Client:
			return SSLv3_client_method()
		}
	case .SSLv23:
		switch type {
		case .Unspecified:
			return SSLv23_method()
		case .Server:
			return SSLv23_server_method()
		case .Client:
			return SSLv23_client_method()
		}
	case .TLSv1:
		switch type {
		case .Unspecified:
			return TLSv1_method()
		case .Server:
			return TLSv1_server_method()
		case .Client:
			return TLSv1_client_method()
		}
	case .TLSv1_1:
		switch type {
		case .Unspecified:
			return TLSv1_1_method()
		case .Server:
			return TLSv1_1_server_method()
		case .Client:
			return TLSv1_1_client_method()
		}
	case .TLSv1_2:
		switch type {
		case .Unspecified:
			return TLSv1_2_method()
		case .Server:
			return TLSv1_2_server_method()
		case .Client:
			return TLSv1_2_client_method()
		}
	case .DTLSv1:
		switch type {
		case .Unspecified:
			return DTLSv1_method()
		case .Server:
			return DTLSv1_server_method()
		case .Client:
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
