// IO.swift
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

import C7
import COpenSSL

public class IO {
	
	public enum Error: ErrorProtocol {
		case io(description: String)
		case shouldRetry(description: String)
		case unsupportedMethod(description: String)
	}

	public enum Method {
		case memory

		var method: UnsafeMutablePointer<BIO_METHOD> {
			switch self {
			case .memory:
				return BIO_s_mem()
			}
		}
	}
	
	var bio: UnsafeMutablePointer<BIO>?
	
	public init(method: Method = .memory) throws {
		initialize()
		bio = BIO_new(method.method)

		if bio == nil {
			throw Error.io(description: lastSSLErrorDescription)
		}
	}
	
	public convenience init(buffer: Data) throws {
		try self.init()
		try write(buffer)
	}
	
	// TODO: crash???
//	deinit {
//		BIO_free(bio)
//	}
	
	public var pending: Int {
		return BIO_ctrl_pending(bio)
	}
	
	public var shouldRetry: Bool {
		return (bio!.pointee.flags & BIO_FLAGS_SHOULD_RETRY) != 0
	}

	@discardableResult
	public func write(_ data: Data) throws -> Int {
		let result = data.withUnsafeBufferPointer {
			BIO_write(bio, $0.baseAddress, Int32($0.count))
		}
		
		if result < 0 {
			if shouldRetry {
				throw Error.shouldRetry(description: lastSSLErrorDescription)
			} else {
				throw Error.io(description: lastSSLErrorDescription)
			}
		}

		return Int(result)
	}

	public func read(upTo byteCount: Int) throws -> Data {
		var data = Data.buffer(with: byteCount)
		let result = data.withUnsafeMutableBufferPointer {
			BIO_read(bio, $0.baseAddress, Int32($0.count))
		}

		if result < 0 {
			if shouldRetry {
				throw Error.shouldRetry(description: lastSSLErrorDescription)
			} else {
				throw Error.io(description: lastSSLErrorDescription)
			}
		}

		return Data(data.prefix(Int(result)))
	}
	
}
