package tests

import "core:mem/virtual"
import "core:testing"

import http "../http"

/*
Outbound flow control.

RFC 9113 6.9.1: a sender must not send DATA beyond the window the peer has
advertised. The receive side of flow control is covered in h2_stream_test; what
is exercised here is the connection loop actually honouring the send window when
it writes a response body, which is only observable by counting the DATA bytes
that reach the wire.
*/

@(private)
LARGE_BODY_SIZE :: 100 * 1024

/*
Serves a body larger than the default 65535-byte window.

The size matters: anything at or below the window would pass whether or not the
limit is enforced.
*/
@(private)
h2_large_body_server :: proc(srv: ^http.Server, router: ^http.Router) {
	http.router_init(router)
	http.router_handle_proc(router, "GET /big", proc(q: ^http.Request, s: ^http.Response) {
		body := make([]byte, LARGE_BODY_SIZE, q.headers.allocator)
		for i in 0 ..< len(body) { body[i] = 'a' }
		http.respond_plain(s, .OK, string(body))
	})

	srv.opts = http.DEFAULT_SERVER_OPTS
	srv.handler = http.router_handler(router)
}

// Sums the payload lengths of every DATA frame the server wrote.
@(private)
h2_data_bytes :: proc(out: []byte) -> int {
	total := 0
	pos := 0
	for pos < len(out) {
		f, consumed, result, _ := http.h2_frame_decode(out[pos:], http.H2_MAX_ALLOWED_FRAME_SIZE)
		if result != .Ok { break }
		if f.type == .Data { total += len(f.payload) }
		pos += consumed
	}
	return total
}

/*
Runs a script and returns the server's output, copied into `arena`.

The transport's own buffer is freed here rather than handed back: a 100KB body
makes it large enough that leaking it shows up in the test runner's memory
tracking as noise that looks like a library bug.
*/
@(private)
h2_run_large_body :: proc(script: []byte, arena: ^virtual.Arena) -> []byte {
	srv := new(http.Server, context.allocator)
	router := new(http.Router, context.allocator)
	defer {
		http.router_destroy(router)
		free(router)
		free(srv)
	}

	h2_large_body_server(srv, router)

	mt: http.Memory_Transport
	http.memory_transport_init(&mt, script)
	defer http.memory_transport_destroy(&mt)

	http.h2_serve_memory(&mt, srv, virtual.arena_allocator(arena))

	out := make([]byte, len(mt.output), virtual.arena_allocator(arena))
	copy(out, mt.output[:])
	return out
}

// GET /big, ending the stream so the handler runs immediately.
@(private)
h2_append_big_get :: proc(script: ^[dynamic]byte, stream_id: u32) {
	block := make([dynamic]byte, 0, 64, context.temp_allocator)
	http.hpack_encode_integer(&block, 2, 7, 0x80) // :method GET
	http.hpack_encode_integer(&block, 6, 7, 0x80) // :scheme http
	http.hpack_encode_integer(&block, 4, 4, 0x00) // :path literal
	http.hpack_encode_string(&block, "/big")
	http.hpack_encode_integer(&block, 1, 4, 0x00) // :authority literal
	http.hpack_encode_string(&block, "x")

	http.h2_frame_encode(script, .Headers,
		http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, stream_id, block[:])
}

/*
A body larger than the peer's window must stop at the window.

With no WINDOW_UPDATE from the client, the server may send only the 65535 bytes
the default window allows. Sending the whole 100KB is a flow-control violation:
a conforming peer is entitled to treat the overrun as a connection error, so the
practical result is a broken connection against strict clients.
*/
@(test)
test_h2_send_respects_initial_window :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	script := h2_script()
	h2_append_big_get(&script, 1)

	out := h2_run_large_body(script[:], &arena)

	sent := h2_data_bytes(out)
	testing.expect(t, sent <= http.H2_DEFAULT_WINDOW_SIZE,
		"must not send DATA beyond the peer's advertised window")
}

/*
A WINDOW_UPDATE must release the rest of the body.

This is the other half of the same rule: stopping at the window is only correct
if the stall is resumable, otherwise a large response would simply hang.
*/
@(test)
test_h2_send_resumes_after_window_update :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	script := h2_script()
	h2_append_big_get(&script, 1)

	// Grant enough headroom on both the stream and the connection for the rest.
	http.h2_window_update_encode(&script, 1, LARGE_BODY_SIZE)
	http.h2_window_update_encode(&script, 0, LARGE_BODY_SIZE)

	out := h2_run_large_body(script[:], &arena)

	sent := h2_data_bytes(out)
	testing.expect_value(t, sent, LARGE_BODY_SIZE)
}

/*
A peer that stalls the window and then vanishes must not wedge the connection.

`h2_await_window` pumps the frame loop, so a disconnect has to break the wait.
The memory transport reports a closed peer once its script is exhausted, which
is exactly what a client dropping mid-body looks like.
*/
@(test)
test_h2_send_stall_ends_when_peer_disconnects :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	script := h2_script()
	h2_append_big_get(&script, 1)
	// No WINDOW_UPDATE ever arrives, and the script simply ends.

	out := h2_run_large_body(script[:], &arena)

	// The point is that the call returned at all rather than spinning forever;
	// the partial body is the window's worth and no more.
	sent := h2_data_bytes(out)
	testing.expect(t, sent <= http.H2_DEFAULT_WINDOW_SIZE, "partial body stops at the window")
}
