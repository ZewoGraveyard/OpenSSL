// MessageDigest.swift
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

public enum MessageDigestError: ErrorProtocol {
    case unknownDigest
}

public enum MessageDigestAlgorith {
    case null
//    case md2
    case md5
    case sha
    case sha1
    case sha224
    case sha256
    case sha384
    case sha512
    case dss
    case dss1
    case mdc2
    case ripemd160

    var algorithm: UnsafePointer<EVP_MD>! {
        switch self {
        case .null: return EVP_md_null()
//        case .md2: return EVP_md2()
        case .md5: return EVP_md5()
        case .sha: return EVP_sha()
        case .sha1: return EVP_sha1()
        case .sha224: return EVP_sha224()
        case .sha256: return EVP_sha256()
        case .sha384: return EVP_sha384()
        case .sha512: return EVP_sha512()
        case .dss: return EVP_dss()
        case .dss1: return EVP_dss1()
        case .mdc2: return EVP_mdc2()
        case .ripemd160: return EVP_ripemd160()
        }
    }
}

public final class MessageDigest {
    static var addedAllDigests = false
    let messageDigest: UnsafeMutablePointer<EVP_MD>

    public init(_ messageDigest: MessageDigestAlgorith) {
        self.messageDigest = UnsafeMutablePointer(messageDigest.algorithm)
    }

    public init(_ messageDigest: String) throws {
        if !MessageDigest.addedAllDigests {
            OpenSSL_add_all_digests()
            MessageDigest.addedAllDigests = true
        }

        guard let messageDigest = messageDigest.withCString({EVP_get_digestbyname($0)}) else {
            throw MessageDigestError.unknownDigest
        }

        self.messageDigest = UnsafeMutablePointer(messageDigest)
    }
}

