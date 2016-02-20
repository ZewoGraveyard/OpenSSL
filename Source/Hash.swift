// Hash.swift
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
@_exported import Data

public enum HashType {
	case SHA1, SHA224, SHA256, SHA384, SHA512
}

private extension HashType {
	var function: ((UnsafePointer<UInt8>, Int, UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>) {
		switch self {
		case .SHA1:
			return COpenSSL.SHA1
		case .SHA224:
			return COpenSSL.SHA224
		case .SHA256:
			return COpenSSL.SHA256
		case .SHA384:
			return COpenSSL.SHA384
		case .SHA512:
			return COpenSSL.SHA512
		}
	}
}

public struct SHA {
	
	public static func hash(type: HashType, message: Data) -> Data {
		var hashBuf = Data.bufferWithSize(Int(SHA_DIGEST_LENGTH))
		message.withUnsafeBufferPointer { ptr in
			hashBuf.withUnsafeMutableBufferPointer { bufPtr in
				type.function(ptr.baseAddress, ptr.count, bufPtr.baseAddress)
			}
		}
		return hashBuf
	}
	
}
