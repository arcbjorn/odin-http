package http

import "core:net"
import "core:time"

/*
The byte transport underneath a connection.

Everything above this point speaks bytes, not sockets. TLS is the reason: an
encrypted connection is still a bidirectional byte stream, so the parser, the
response writer, and the streaming body code need no knowledge of it.

This matches the direction the Odin core team stated for TLS — a swappable
backend behind a compatible API rather than a single blessed implementation. A
pure-Odin TLS stack, a system library, or the OpenSSL backend here all satisfy
the same three operations.

`read` and `write` return the number of bytes moved and whether the connection
is still usable. Partial writes are the caller's problem, matching the socket
API they wrap; `transport_write_all` handles the loop.
*/
Transport :: struct {
	read:        proc(t: ^Transport, buf: []byte) -> (n: int, ok: bool),
	write:       proc(t: ^Transport, buf: []byte) -> (n: int, ok: bool),
	close:       proc(t: ^Transport),
	// Applies a receive or send deadline. Separate from read/write so a driver
	// can set it once per phase rather than per call.
	set_timeout: proc(t: ^Transport, recv: bool, d: time.Duration),

	// Backend state. `Plain_Transport` stores the socket here directly; the TLS
	// backend stores its session object.
	data:        rawptr,
	// Kept for logging and for handlers that need the peer address, which is
	// otherwise unreachable once the socket is behind this interface.
	peer:        net.Endpoint,
}

/*
Writes an entire buffer, looping over partial writes.

A short write is normal on a socket under load, so every caller needs this;
having it once here keeps that loop out of the response paths.
*/
transport_write_all :: proc(t: ^Transport, data: []byte) -> bool {
	sent := 0
	for sent < len(data) {
		n, ok := t->write(data[sent:])
		if !ok    { return false }
		if n <= 0 { return false }
		sent += n
	}
	return true
}

/*
A plaintext TCP transport.

The struct embeds `Transport` so a `^Plain_Transport` converts to a
`^Transport` without an allocation or a back-pointer.
*/
Plain_Transport :: struct {
	using base: Transport,
	socket:     net.TCP_Socket,
}

plain_transport_init :: proc(pt: ^Plain_Transport, socket: net.TCP_Socket, peer: net.Endpoint) {
	pt.socket = socket
	pt.peer   = peer

	pt.read = proc(t: ^Transport, buf: []byte) -> (n: int, ok: bool) {
		pt := cast(^Plain_Transport)t
		got, err := net.recv_tcp(pt.socket, buf)
		if err != nil { return 0, false }
		// A zero-length read means the peer closed cleanly.
		return got, got > 0
	}

	pt.write = proc(t: ^Transport, buf: []byte) -> (n: int, ok: bool) {
		pt := cast(^Plain_Transport)t
		sent, err := net.send_tcp(pt.socket, buf)
		if err != nil { return 0, false }
		return sent, sent > 0
	}

	pt.close = proc(t: ^Transport) {
		pt := cast(^Plain_Transport)t
		net.close(pt.socket)
	}

	pt.set_timeout = proc(t: ^Transport, recv: bool, d: time.Duration) {
		pt := cast(^Plain_Transport)t
		net.set_option(pt.socket, .Receive_Timeout if recv else .Send_Timeout, d)
	}
}
