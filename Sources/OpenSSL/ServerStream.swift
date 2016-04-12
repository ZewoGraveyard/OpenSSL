// SSLServerStream.swift
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

public final class SSLServerStream: Stream {
	private let context: SSLServerContext
    private let rawStream: Stream
    private let readIO: IO
    private let writeIO: IO
	private let ssl: Session

    public var closed: Bool = false

	public init(context: SSLServerContext, rawStream: Stream) throws {
		OpenSSL.initialize()

        self.context = context
        self.rawStream = rawStream

        readIO = try IO(method: .Memory)
        writeIO = try IO(method: .Memory)

		ssl = try Session(context: context)
		ssl.setIO(readIO: readIO, writeIO: writeIO)
		ssl.setAcceptState()
	}

    public func receive(upTo byteCount: Int, timingOut deadline: Double) throws -> Data {
        let data = try rawStream.receive(upTo: byteCount, timingOut: deadline)
        try readIO.write(data)

        while !ssl.initializationFinished {
            do {
                try ssl.handshake()
            } catch Session.Error.WantRead {}
            try send()
            try rawStream.flush()
            let data = try rawStream.receive(upTo: byteCount, timingOut: deadline)
            try readIO.write(data)
        }

        var decriptedData = Data()

        while true {
            do {
                decriptedData += try ssl.read()
            } catch Session.Error.WantRead {
                if decriptedData.count > 0 {
                    return decriptedData
                }
                let data = try rawStream.receive(upTo: byteCount, timingOut: deadline)
                try readIO.write(data)
            }
        }
	}

	public func send(data: Data, timingOut deadline: Double) throws {
		ssl.write(data)
		try send()
	}

    public func flush(timingOut deadline: Double) throws {
        try rawStream.flush(timingOut: deadline)
    }

	public func close() -> Bool {
        return rawStream.close()
	}

	private func send() throws {
        do {
            let data = try writeIO.read()
            try rawStream.send(data)
        } catch IO.Error.ShouldRetry {
            return
        }
	}
}
