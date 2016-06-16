// MessageDigestContext.swift
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

public enum MessageDigestContextError: ErrorProtocol {
    case initializationFailed
    case updateFailed
    case signFailed
}

public final class MessageDigestContext {
    let context: UnsafeMutablePointer<EVP_MD_CTX>

    deinit {
        EVP_MD_CTX_destroy(context)
    }

    public convenience init(_ messageDigest: MessageDigestAlgorith) throws {
        try self.init(MessageDigest(messageDigest))
    }

    public init(_ messageDigest: MessageDigest) throws {
        let context: UnsafeMutablePointer<EVP_MD_CTX>! = EVP_MD_CTX_create()

        if EVP_DigestInit(context, messageDigest.messageDigest) == 0 {
            throw MessageDigestContextError.initializationFailed
        }

        guard let c = context else {
            throw MessageDigestContextError.initializationFailed
        }

        self.context = c
    }

    public func update(_ data: Data) throws {
        var data = data
        if EVP_DigestUpdate(context, &data.bytes, data.count) == 0 {
            throw MessageDigestContextError.initializationFailed
        }
    }

    public func sign(privateKey: Data, passPhrase: String? = nil) throws -> Data {
        var privateKey = privateKey

        guard let bp = BIO_new_mem_buf(&privateKey.bytes, Int32(privateKey.count)) else {
            throw MessageDigestContextError.signFailed
        }

        let pkey: UnsafeMutablePointer<EVP_PKEY>?

        if let passPhrase = passPhrase {
            pkey = passPhrase.withCString {
                return PEM_read_bio_PrivateKey(bp, nil, cryptoPemCallback, UnsafeMutablePointer<Void>($0))
            }
        } else {
            pkey = PEM_read_bio_PrivateKey(bp, nil, cryptoPemCallback, nil)
        }

        guard let ppKey = pkey else {
            throw MessageDigestContextError.signFailed
        }

        if ERR_peek_error() != 0 {
            throw MessageDigestContextError.signFailed
        }

        var length: UInt32 = 8192
        var signature = [UInt8](repeating: 0, count: Int(length))

        if EVP_SignFinal(context, &signature, &length, ppKey) == 0 {
            throw MessageDigestContextError.signFailed
        }

        EVP_PKEY_free(ppKey)
        BIO_free_all(bp)

        return Data(signature.prefix(upTo: Int(length)))
    }
}

func cryptoPemCallback(_ buffer: UnsafeMutablePointer<Int8>?, _ size: Int32, _ rwflag: Int32, _ u: UnsafeMutablePointer<Void>?) -> Int32 {
    if let u = u {
        let bufferLength = size
        var length = Int32(strlen(UnsafePointer<Int8>(u)))
        length = length > bufferLength ? bufferLength : length
        if let buffer = buffer {
            memcpy(buffer, u, Int(length))
        }
        return length
    }

    return 0
}

