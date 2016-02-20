// HMAC.swift
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

private extension HashType {
	var evp: UnsafePointer<EVP_MD> {
		switch self {
		case .SHA1:
			return EVP_sha1()
		case .SHA224:
			return EVP_sha224()
		case .SHA256:
			return EVP_sha256()
		case .SHA384:
			return EVP_sha384()
		case .SHA512:
			return EVP_sha512()
		}
	}
}

public struct HMAC {
	
	public static func hash(type: HashType, key: Data, message: Data) -> Data {
		var resultLen: UInt32 = 0
		let result = UnsafeMutablePointer<Byte>.alloc(Int(EVP_MAX_MD_SIZE))
		key.withUnsafeBufferPointer { keyPtr in
			message.withUnsafeBufferPointer { msgPtr in
				COpenSSL.HMAC(type.evp, keyPtr.baseAddress, Int32(key.count), msgPtr.baseAddress, message.count, result, &resultLen)
			}
		}
		let data = Data(Array(UnsafeBufferPointer<Byte>(start: result, count: Int(resultLen))))
		result.destroy(Int(resultLen))
		result.dealloc(Int(EVP_MAX_MD_SIZE))
		return data
	}
	
}
