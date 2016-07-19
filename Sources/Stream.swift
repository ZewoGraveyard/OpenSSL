// Stream.swift
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

public final class Stream: C7.Stream {
	
	public enum Mode {
		case connect, accept
	}
	
	private let mode: Mode
	private let rawStream: C7.Stream
	private let context: Context
	private let session: Session
	private let readIO: IO
	private let writeIO: IO
	
	public var closed: Bool = false
	
	public init(mode: Mode, context: Context, rawStream: C7.Stream, timingOut deadline: Double = .never) throws {
		initialize()
		
		self.mode = mode
		self.context = context
		self.rawStream = rawStream
		
		readIO = try IO()
		writeIO = try IO()
		
		session = try Session(context: context)
		session.setIO(readIO: readIO, writeIO: writeIO)
		
		if let hostname = context.sniHostname {
			try session.setServerNameIndication(hostname: hostname)
		}
		
		if mode == .accept {
			session.setAcceptState()
		} else {
			session.setConnectState()
		}
		
		try handshake(timingOut: deadline)
	}
	
	private func handshake(timingOut deadline: Double) throws {
		guard mode == .connect else { return }
		while !session.initializationFinished {
			do {
				try session.handshake()
			} catch Session.Error.wantRead {
				try self.flush(timingOut: deadline)
				let data = try rawStream.receive(upTo: 1024, timingOut: deadline)
				try readIO.write(data)
			}
		}
		print("### handshake done")
	}
	
	public func receive(upTo byteCount: Int, timingOut deadline: Double) throws -> Data {
		while true {
			do {
				let decryptedData = try session.read(upTo: byteCount)
				if decryptedData.count > 0 {
					return decryptedData
				}
			} catch Session.Error.wantRead {
				do {
					let data = try rawStream.receive(upTo: byteCount, timingOut: deadline)
					try readIO.write(data)
				} catch StreamError.closedStream(let data) {
					try readIO.write(data)
				}
			} catch Session.Error.zeroReturn {
				throw StreamError.closedStream(data: [])
			}
		}
	}
	
	public func send(_ data: Data, timingOut deadline: Double) throws {
		try send(data, flushing: true, timingOut: deadline)
	}
	
	public func send(_ data: Data, flushing flush: Bool, timingOut deadline: Double) throws {
		session.write(data)
		if flush {
			try self.flush(timingOut: deadline)
		}
	}
	
	public func flush(timingOut deadline: Double) throws {
		do {
			let data = try writeIO.read(upTo: writeIO.pending)
			try rawStream.send(data, timingOut: deadline)
			try rawStream.flush(timingOut: deadline)
		} catch IO.Error.shouldRetry { }
	}
	
	public func close() throws {
		// TODO: http://stackoverflow.com/questions/28056056/handling-ssl-shutdown-correctly
//		session.shutdown()
		try rawStream.close()
	}
	
}
