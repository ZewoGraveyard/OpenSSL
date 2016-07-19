// Key.swift
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

public class Key {
	
	public enum Error: ErrorProtocol {
		case error(description: String)
	}
	
	var key: UnsafeMutablePointer<EVP_PKEY>

	init(key: UnsafeMutablePointer<EVP_PKEY>) {
		initialize()
		self.key = key
	}
	
	init(io: IO) throws {
		initialize()
		guard let _key = PEM_read_bio_PrivateKey(io.bio, nil, nil, nil) else {
			throw Error.error(description: lastSSLErrorDescription)
		}
		self.key = _key
	}
	
	public convenience init(pemString: String) throws {
		try self.init(io: IO(buffer: pemString.data))
	}
	
	deinit {
		EVP_PKEY_free(key)
	}
	
	public static func generate(keyLength: Int32 = 2048) -> Key {
		let key = Key(key: EVP_PKEY_new())
		let rsa = RSA_new()
		let exponent = BN_new()
		BN_set_word(exponent, 0x10001)
		RSA_generate_key_ex(rsa, keyLength, exponent, nil)
		EVP_PKEY_set1_RSA(key.key, rsa)
		return key
	}
	
}
