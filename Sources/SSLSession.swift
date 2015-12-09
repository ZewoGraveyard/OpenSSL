// SSLSession.swift
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

public class SSLSession {
	
	public enum State: Int32 {
		case Connect		= 0x1000
		case Accept			= 0x2000
		case Mask			= 0x0FFF
		case Init			= 0x3000
		case Before			= 0x4000
		case OK				= 0x03
		case Renegotiate	= 0x3004
		case Error			= 0x05
	}

	internal var ssl: SSL
	
	public func withSSL<Result>(body: UnsafeMutablePointer<SSL> throws -> Result) rethrows -> Result {
		return try withUnsafeMutablePointer(&ssl) { try body($0) }
	}
	
	public init(ssl: SSL) {
		self.ssl = ssl
	}

	public init(context: SSLContext) {
		self.ssl = context.withContext { SSL_new($0).memory }
	}
	
	deinit {
		self.shutdown()
		withSSL { SSL_free($0) }
	}
	
	var state: State {
		let state = withSSL { SSL_state($0) }
		return State(rawValue: state) ?? .Error
	}
	
	public func setIO(readIO readIO: SSLIO, writeIO: SSLIO) {
		withSSL { ssl in
			readIO.withBIO { rbio in
				writeIO.withBIO { wbio in
					SSL_set_bio(ssl, rbio, wbio)
				}
			}
		}
	}
	
	public func doHandshake() {
		withSSL { SSL_do_handshake($0) }
	}
	
	public func write(data: [Int8]) {
		var data = data
		withSSL { SSL_write($0, &data, Int32(data.count)) }
	}
	
	public func read() -> [Int8] {
		var buffer: [Int8] = Array(count: DEFAULT_BUFFER_SIZE, repeatedValue: 0)
		let readSize = withSSL { SSL_read($0, &buffer, Int32(buffer.count)) }
		return Array(buffer.prefix(Int(readSize)))
	}
	
	public func shutdown() {
		withSSL { SSL_shutdown($0) }
	}

}
