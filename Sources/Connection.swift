// Connection.swift
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

public final class SSLConnection: C7.Connection {
	
	private enum Raw {
		case stream(C7.Stream)
		case connection(C7.Connection)
		
		var stream: C7.Stream {
			switch self {
			case .stream(let stream):
				return stream
			case .connection(let connection):
				return connection
			}
		}
	}
	
	private let raw: Raw
	private let context: Context
	private let session: Session
	private let readIO: IO
	private let writeIO: IO
	
	public var closed: Bool = false
	
	public convenience init(context: Context, rawStream: C7.Stream) throws {
		try self.init(context: context, raw: .stream(rawStream))
	}
	
	public convenience init(context: Context, rawConnection: C7.Connection) throws {
		try self.init(context: context, raw: .connection(rawConnection))
	}
	
	private init(context: Context, raw: Raw) throws {
		initialize()
		
		self.context = context
		self.raw = raw
		
		readIO = try IO()
		writeIO = try IO()
		
		session = try Session(context: context)
		session.setIO(readIO: readIO, writeIO: writeIO)
		
		if let hostname = context.sniHostname {
			try session.setServerNameIndication(hostname: hostname)
		}
		
		if context.mode == .server {
			session.setAcceptState()
		} else {
			session.setConnectState()
		}
	}
	
	public func open(timingOut deadline: Double) throws {
		if case .connection(let rawConnection) = raw {
			print("~~~ rawConnection")
			try rawConnection.open(timingOut: deadline)
		}
		
		try handshake(timingOut: deadline)
	}
	
	private func handshake(timingOut deadline: Double) throws {
		let flushAndReceive = {
			try self.flush(timingOut: deadline)
			let data = try self.raw.stream.receive(upTo: 1024, timingOut: deadline)
			try self.readIO.write(data)
		}
		while !session.initializationFinished {
			do {
				try session.handshake()
			} catch Session.Error.wantRead {
				if context.mode == .client {
					try flushAndReceive()
				}
			}
			if context.mode == .server {
				try flushAndReceive()
			}
		}
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
					let data = try raw.stream.receive(upTo: byteCount, timingOut: deadline)
					try readIO.write(data)
				} catch StreamError.closedStream(let data) {
					if data.count > 0 {
						try readIO.write(data)
					} else {
						throw StreamError.closedStream(data: [])
					}
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
			try raw.stream.send(data, timingOut: deadline)
			try raw.stream.flush(timingOut: deadline)
		} catch IO.Error.shouldRetry { }
	}
	
	public func close() throws {
		// TODO: http://stackoverflow.com/questions/28056056/handling-ssl-shutdown-correctly
//		session.shutdown()
		try raw.stream.close()
	}
	
}
