//	====================================================================
//
//	Copyright (c) 2007-2008, Eric Rescorla and Derek MacDonald
//	All rights reserved.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are
//	met:
//
//	1. Redistributions of source code must retain the above copyright
//	   notice, this list of conditions and the following disclaimer.
//
//	2. Redistributions in binary form must reproduce the above copyright
//	   notice, this list of conditions and the following disclaimer in the
//	   documentation and/or other materials provided with the distribution.
//
//	3. None of the contributors names may be used to endorse or promote
//	   products derived from this software without specific prior written
//	   permission.
//
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//	====================================================================

import COpenSSL

public let BIO_TYPE_DWRAP: Int32 = (50 | 0x0400 | 0x0200)

private var methods_dwrap = BIO_METHOD(type: BIO_TYPE_DWRAP, name: "dtls_wrapper", bwrite: dwrap_write, bread: dwrap_read, bputs: dwrap_puts, bgets: dwrap_gets, ctrl: dwrap_ctrl, create: dwrap_new, destroy: dwrap_free, callback_ctrl: { bio, cmd, fp in
	return BIO_callback_ctrl(bio!.pointee.next_bio, cmd, fp)
})

private func getPointer<T>(_ arg: UnsafeMutablePointer<T>) -> UnsafeMutablePointer<T> {
	return arg
}

public func BIO_f_dwrap() -> UnsafeMutablePointer<BIO_METHOD> {
	return getPointer(&methods_dwrap)
}

func OPENSSL_malloc(_ num: Int, file: String = #file, line: Int = #line) -> UnsafeMutablePointer<Void>? {
	return CRYPTO_malloc(Int32(num), file, Int32(line))
}

func OPENSSL_free(_ ptr: UnsafeMutablePointer<Void>) {
	CRYPTO_free(ptr)
}

let BIO_FLAGS_RWS = (BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL)
func BIO_clear_retry_flags(_ b: UnsafeMutablePointer<BIO>) {
	BIO_clear_flags(b, BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY)
}

private struct BIO_F_DWRAP_CTX {
	var dgram_timer_exp: Bool
}

private func dwrap_new(bio: UnsafeMutablePointer<BIO>?) -> Int32 {
	let maybeCtx = OPENSSL_malloc(sizeof(BIO_F_DWRAP_CTX.self))
	guard let ctx = maybeCtx else { return 0 }

	memset(ctx, 0, sizeof(BIO_F_DWRAP_CTX.self))

	let b = bio!.pointee
	bio!.pointee = BIO(method: b.method, callback: b.callback, cb_arg: b.cb_arg, init: 1, shutdown: b.shutdown, flags: 0, retry_reason: b.retry_reason, num: b.num, ptr: ctx, next_bio: b.next_bio, prev_bio: b.prev_bio, references: b.references, num_read: b.num_read, num_write: b.num_write, ex_data: b.ex_data)

	return 1
}

private func dwrap_free(bio: UnsafeMutablePointer<BIO>?) -> Int32 {
	guard let bio = bio else { return 0 }

	OPENSSL_free(bio.pointee.ptr)

	let b = bio.pointee
	bio.pointee = BIO(method: b.method, callback: b.callback, cb_arg: b.cb_arg, init: 0, shutdown: b.shutdown, flags: 0, retry_reason: b.retry_reason, num: b.num, ptr: nil, next_bio: b.next_bio, prev_bio: b.prev_bio, references: b.references, num_read: b.num_read, num_write: b.num_write, ex_data: b.ex_data)

	return 1
}

private func dwrap_read(bio: UnsafeMutablePointer<BIO>?, data: UnsafeMutablePointer<Int8>?, length: Int32) -> Int32 {
	guard let bio = bio, data = data else { return 0 }

	BIO_clear_retry_flags(bio)

	let ret = BIO_read(bio.pointee.next_bio, data, length)

	if ret <= 0 {
		BIO_copy_next_retry(bio)
	}

	return ret
}

private func dwrap_write(bio: UnsafeMutablePointer<BIO>?, data: UnsafePointer<Int8>?, length: Int32) -> Int32 {
	guard let bio = bio, let data = data where length > 0 else { return 0 }
	return BIO_write(bio.pointee.next_bio, data, length)
}

private func dwrap_puts(bio: UnsafeMutablePointer<BIO>?, data: UnsafePointer<Int8>?) -> Int32 {
	fatalError()
}

private func dwrap_gets(bio: UnsafeMutablePointer<BIO>?, data: UnsafeMutablePointer<Int8>?, length: Int32) -> Int32 {
	fatalError()
}

private func dwrap_ctrl(bio: UnsafeMutablePointer<BIO>?, cmd: Int32, num: Int, ptr: UnsafeMutablePointer<Void>?) -> Int {
	let ctx = UnsafeMutablePointer<BIO_F_DWRAP_CTX>(bio!.pointee.ptr)!
	var ret: Int
	switch cmd {
	case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
		if ctx.pointee.dgram_timer_exp {
			ret = 1
			ctx.pointee.dgram_timer_exp = false
		} else {
			ret = 0
		}
	case BIO_CTRL_DGRAM_SET_RECV_TIMEOUT:
		ctx.pointee.dgram_timer_exp = true
		ret = 1
	default:
		ret = BIO_ctrl(bio!.pointee.next_bio, cmd, num, ptr)
	}
	return ret
}
