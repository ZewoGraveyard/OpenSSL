// SSLClientStream.swift
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

import Core
import COpenSSL

public final class SSLClientStream: SSLClientStreamType {
	let rawStream: StreamType
	private let context: SSLClientContext
	private let ssl: SSLSession
	private let readIO: SSLIO
	private let writeIO: SSLIO

	public enum Error: ErrorType {
		case UnsupportedContext
	}

	public init(context: SSLClientContextType, rawStream: StreamType) throws {
		guard let sslContext = context as? SSLClientContext else {
			throw Error.UnsupportedContext
		}

		OpenSSL.initialize()

		self.context = sslContext
		self.rawStream = rawStream

		self.ssl = SSLSession(context: sslContext)

		self.readIO = SSLIO(method: .Memory)
		self.writeIO = SSLIO(method: .Memory)
		self.ssl.setIO(readIO: self.readIO, writeIO: self.writeIO)

		self.ssl.withSSL { ssl in
			SSL_set_connect_state(ssl)
		}
	}

	public func receive(completion: (Void throws -> [Int8]) -> Void) {
		self.rawStream.receive { result in
			do {
				let data = try result()
				guard data.count > 0 else { return }
				self.readIO.write(data)
				print("data: \(data)")
				print("ssl.state: \(self.ssl.state)")
				//if self.ssl.state != .OK {
					self.ssl.doHandshake()
					self.checkSslOutput() { result in
						do {
							try result()

							let data = self.ssl.read()
							print("decrypted data: \(data)")
							if data.count > 0 {
								completion({ data })
							}
						} catch {
							completion({ throw error })
						}
					}
				/*} else {

				}*/
			} catch {
				completion({ throw error })
			}
		}
	}

	public func send(data: [Int8], completion: (Void throws -> Void) -> Void) {
		self.checkSslOutput(completion)
		//self.ssl.write(data)
		//
	}

	public func close() {
		self.rawStream.close()
	}

	public func pipe() -> StreamType {
		return try! SSLClientStream(context: self.context, rawStream: self.rawStream.pipe())
	}

	private func checkSslOutput(completion: (Void throws -> Void) -> Void) {
		let data = self.writeIO.read()
		guard data.count > 0 else { completion({}); return }
		print("encrypted data: \(data)")
		self.rawStream.send(data) { serializeResult in
			do {
				try serializeResult()
				completion({})
			} catch {
				completion({ throw error })
			}
		}
	}
}
