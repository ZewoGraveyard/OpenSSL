// SHA256.swift
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

public class SHA256 {
    let context:  UnsafeMutablePointer<SHA256_CTX>!

    deinit {
        context.deallocateCapacity(1)
    }

    public init() {
        let context = UnsafeMutablePointer<SHA256_CTX>(allocatingCapacity: 1)
        SHA256_Init(context)
        self.context = context
    }

    public func update(_ data: Data) {
        var data = data
        SHA256_Update(context, &data.bytes, data.count)
    }

    public func final() -> Data {
        var hash = Data.buffer(with: Int(SHA256_DIGEST_LENGTH))
        SHA256_Final(&hash.bytes, context)
        return hash
    }
}
