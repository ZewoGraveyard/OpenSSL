// Random.swift
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

#if os(OSX) || os(iOS) || os(tvOS) || os(watchOS)
	import Darwin
#elseif os(Linux)
	import Glibc
#endif

import C7
import COpenSSL

public class Random {
	
	public enum Error: ErrorProtocol {
		case error(description: String)
	}
	
	public static func number(max: Int = Int(UInt32.max)) -> Int {
		#if os(OSX) || os(iOS) || os(tvOS) || os(watchOS)
			return Int(arc4random_uniform(UInt32(max)))
		#elseif os(Linux)
			return Int(random() % (max + 1))
		#endif
	}
	
	public static func bytes(_ size: Int) throws -> Data {
		var buf = Data.buffer(with: size)
		guard (buf.withUnsafeMutableBufferPointer{ RAND_bytes($0.baseAddress, Int32($0.count)) }) == 1 else {
			throw Error.error(description: lastSSLErrorDescription)
		}
		return buf
	}

}
