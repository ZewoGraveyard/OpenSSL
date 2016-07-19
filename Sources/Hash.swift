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

import C7
import COpenSSL

internal extension Hash.Function {
	var digestLength: Int {
		switch self {
		case .md5:
			return Int(MD5_DIGEST_LENGTH)
		case .sha1:
			return Int(SHA_DIGEST_LENGTH)
		case .sha224:
			return Int(SHA224_DIGEST_LENGTH)
		case .sha256:
			return Int(SHA256_DIGEST_LENGTH)
		case .sha384:
			return Int(SHA384_DIGEST_LENGTH)
		case .sha512:
			return Int(SHA512_DIGEST_LENGTH)
		}
	}

	var function: ((UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>!) {
		switch self {
		case .md5:
			return { MD5($0!, $1, $2!) }
		case .sha1:
			return { SHA1($0!, $1, $2!) }
		case .sha224:
			return { SHA224($0!, $1, $2!) }
		case .sha256:
			return { SHA256($0!, $1, $2!) }
		case .sha384:
			return { SHA384($0!, $1, $2!) }
		case .sha512:
			return { SHA512($0!, $1, $2!) }
		}
	}

	var evp: UnsafePointer<EVP_MD> {
		switch self {
		case .md5:
			return EVP_md5()
		case .sha1:
			return EVP_sha1()
		case .sha224:
			return EVP_sha224()
		case .sha256:
			return EVP_sha256()
		case .sha384:
			return EVP_sha384()
		case .sha512:
			return EVP_sha512()
		}
	}
}

public struct Hash {

	public enum Error: ErrorProtocol {
		case error(description: String)
	}
	
	public enum Function {
		case md5, sha1, sha224, sha256, sha384, sha512
	}

	// MARK: - Hash

	public static func hash(_ function: Function, message: Data) -> Data {
		initialize()

		var hashBuf = Data.buffer(with: function.digestLength)
		_ = message.withUnsafeBufferPointer { ptr in
			hashBuf.withUnsafeMutableBufferPointer { bufPtr in
				function.function(ptr.baseAddress, ptr.count, bufPtr.baseAddress)
			}
		}
		return hashBuf
	}

	// MARK: - HMAC

	public static func hmac(_ function: Function, key: Data, message: Data) -> Data {
		initialize()

		var resultLen: UInt32 = 0
		let result = UnsafeMutablePointer<Byte>(allocatingCapacity: Int(EVP_MAX_MD_SIZE))
		_ = key.withUnsafeBufferPointer { keyPtr in
			message.withUnsafeBufferPointer { msgPtr in
				COpenSSL.HMAC(function.evp, keyPtr.baseAddress, Int32(key.count), msgPtr.baseAddress, msgPtr.count, result, &resultLen)
			}
		}
		let data = Data(Array(UnsafeBufferPointer<Byte>(start: result, count: Int(resultLen))))
		result.deinitialize(count: Int(resultLen))
		result.deallocateCapacity(Int(EVP_MAX_MD_SIZE))
		return data
	}

	// MARK: - RSA

	public static func rsa(_ function: Function, key: Key, message: Data) throws -> Data {
		initialize()

		let ctx = EVP_MD_CTX_create()
		guard ctx != nil else {
			throw Error.error(description: lastSSLErrorDescription)
		}

		return message.withUnsafeBufferPointer { digestPtr in
			EVP_DigestInit_ex(ctx, function.evp, nil)
			EVP_DigestUpdate(ctx, UnsafePointer<Void>(digestPtr.baseAddress), digestPtr.count)
			var signLen: UInt32 = 0
			var buf = Data.buffer(with: Int(EVP_PKEY_size(key.key)))
			_ = buf.withUnsafeMutableBufferPointer { ptr in
				EVP_SignFinal(ctx, ptr.baseAddress, &signLen, key.key)
			}
			return Data(buf.prefix(Int(signLen)))
		}
	}

}
