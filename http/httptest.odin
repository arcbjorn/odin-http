package http

import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

/*
Test helpers, modelled on Go's net/http/httptest.

Two levels are provided, and they catch different classes of bug:

  - `Recorder` runs a handler against a synthetic request with no sockets at
    all. Fast, deterministic, and the right tool for asserting what a handler
    does.

  - `Test_Server` binds a real loopback socket and runs the actual accept loop,
    which is the only way to cover framing, keep-alive, and the parse loop in
    `serve_one`. A handler that passes against a Recorder can still deadlock on
    a real connection, so both matter.

These live in the main package rather than a submodule so tests can reach
package-private behaviour, matching how Go exposes httptest's internals.
*/

/*
Runs handlers against synthetic requests, capturing the response.

The arena owns everything the request and response allocate, so a Recorder is
destroyed in one call regardless of what the handler did.
*/
Recorder :: struct {
	arena: virtual.Arena,
	req:   Request,
	res:   Response,
}

/*
Prepares a recorder for a request.

`target` is the raw request-target and `body` is the decoded body as a handler
would see it. Add headers with `recorder_set_header` before serving.
*/
recorder_init :: proc(rec: ^Recorder, method: Method, target: string, body := "") -> mem.Allocator_Error {
	virtual.arena_init_growing(&rec.arena) or_return

	allocator := virtual.arena_allocator(&rec.arena)
	request_init(&rec.req, allocator)
	response_init(&rec.res, allocator)

	rec.req.method  = method
	rec.req.target  = target
	rec.req.version = {1, 1}
	rec.req.body    = body
	rec.req.client  = {address = net.IP4_Loopback, port = 0}

	// Every HTTP/1.1 request carries Host, so a synthetic one should too, or
	// handlers that read it behave differently under test than in production.
	headers_set(&rec.req.headers, "host", "test.local")
	return nil
}

recorder_destroy :: proc(rec: ^Recorder) {
	virtual.arena_destroy(&rec.arena)
}

recorder_set_header :: proc(rec: ^Recorder, name: string, value: string) -> bool {
	return headers_set(&rec.req.headers, name, value)
}

/*
Runs a handler against the recorded request.

The request is marked readonly first, exactly as the server does, so a handler
that mistakenly writes to the request fails under test rather than in
production.
*/
recorder_serve :: proc(rec: ^Recorder, h: ^Handler) {
	rec.req.headers.readonly = true
	handler_serve(h, &rec.req, &rec.res)
}

recorder_status :: #force_inline proc(rec: ^Recorder) -> Status {
	return rec.res.status
}

recorder_body :: #force_inline proc(rec: ^Recorder) -> string {
	return strings.to_string(rec.res.body)
}

recorder_header :: proc(rec: ^Recorder, name: string) -> (value: string, ok: bool) #optional_ok {
	return headers_get(rec.res.headers, name)
}

/*
Serializes the recorded response exactly as the server would.

Useful for asserting on framing (Content-Length, bodyless statuses, Set-Cookie
appearing once per cookie) rather than only on handler-visible state.
*/
recorder_raw_response :: proc(rec: ^Recorder, date := "") -> string {
	out := strings.builder_make(virtual.arena_allocator(&rec.arena))
	response_write(&rec.res, &out, date)
	return strings.to_string(out)
}

// How long a test client waits before giving up, so failures surface as failed
// assertions rather than a hung test run.
TEST_TIMEOUT :: 5 * time.Second

/*
Adjusts the active-connection count directly.

Exists so the drain can be tested without depending on accept-loop timing: on
some platforms `accept_tcp` only unblocks when the listening socket closes, by
which point a handler has usually finished, making the race unreachable through
the public API.
*/
server_test_add_active :: proc(s: ^Server, delta: int) {
	sync.mutex_lock(&s.mutex)
	s.active += delta
	sync.mutex_unlock(&s.mutex)
}

// Runs the shutdown drain, for tests that exercise it in isolation.
server_test_drain :: proc(s: ^Server) {
	server_drain(s)
}

/*
A server bound to an ephemeral loopback port, running its real accept loop on a
background thread.

Binding port 0 lets the OS pick a free port, so parallel tests never collide on
a hardcoded one.
*/
Test_Server :: struct {
	server:   Server,
	endpoint: net.Endpoint,
	handler:  Handler,
	thread:   ^thread.Thread,
	ready:    sync.Sema,
	// Connections still active at the moment `server_serve` returned. Must be
	// zero: anything else means connection threads outlived the server.
	active_at_return: int,
}

/*
Starts a test server on an ephemeral port.

Blocks until the socket is bound and accepting, so a test can issue a request
immediately without racing the listener.
*/
test_server_start :: proc(ts: ^Test_Server, handler: Handler, opts := DEFAULT_SERVER_OPTS) -> net.Network_Error {
	ts.handler = handler

	// Port 0 asks the OS for any free port.
	server_listen(&ts.server, {address = net.IP4_Loopback, port = 0}, opts) or_return

	// Recover the port the OS actually assigned.
	bound, err := net.bound_endpoint(ts.server.socket)
	if err != nil {
		server_shutdown(&ts.server)
		return err
	}
	ts.endpoint = bound

	ts.thread = thread.create_and_start_with_poly_data(ts, proc(ts: ^Test_Server) {
		// The listening socket already exists, so a client that connects now
		// will be accepted once the loop starts.
		sync.sema_post(&ts.ready)
		server_serve(&ts.server, ts.handler)

		// Sampled the instant `server_serve` returns. Checking after the join
		// would be useless: a detached connection thread usually finishes on
		// its own in the meantime, hiding a missing drain.
		ts.active_at_return = server_active_connections(&ts.server)
	})

	sync.sema_wait(&ts.ready)
	return nil
}

/*
Stops the server and waits for its thread to exit.

Closing the listening socket unblocks the accept loop.
*/
test_server_stop :: proc(ts: ^Test_Server) {
	server_shutdown(&ts.server)
	if ts.thread != nil {
		thread.join(ts.thread)
		thread.destroy(ts.thread)
		ts.thread = nil
	}
}

/*
Sends raw bytes over a fresh connection and returns everything read back.

Deliberately speaks bytes rather than offering a structured client: the point is
to assert on exact wire output, including malformed input a well-behaved client
could not produce.
*/
test_request_raw :: proc(
	endpoint: net.Endpoint,
	raw: string,
	allocator := context.temp_allocator,
) -> (response: string, err: net.Network_Error) {
	return test_exchange(endpoint, {raw}, allocator)
}

/*
Sends several requests over ONE connection and returns the combined response.

This is what exercises keep-alive and pipelining; issuing them on separate
connections would pass even if connection reuse were broken.
*/
test_request_raw_keepalive :: proc(
	endpoint: net.Endpoint,
	raws: []string,
	allocator := context.temp_allocator,
) -> (response: string, err: net.Network_Error) {
	return test_exchange(endpoint, raws, allocator)
}

@(private)
test_exchange :: proc(
	endpoint: net.Endpoint,
	raws: []string,
	allocator: mem.Allocator,
) -> (response: string, err: net.Network_Error) {
	sock := net.dial_tcp(endpoint) or_return
	defer net.close(sock)

	// Bound the exchange so a server bug fails the test instead of hanging it.
	net.set_option(sock, .Send_Timeout,    TEST_TIMEOUT)
	net.set_option(sock, .Receive_Timeout, TEST_TIMEOUT)

	for raw in raws {
		data := transmute([]byte)raw
		sent := 0
		for sent < len(data) {
			n := net.send_tcp(sock, data[sent:]) or_return
			if n <= 0 { break }
			sent += n
		}
	}

	out := strings.builder_make(allocator)
	buf: [4096]byte
	for {
		// Reads until the server closes, or the timeout fires for a keep-alive
		// connection the server is holding open.
		n, rerr := net.recv_tcp(sock, buf[:])
		if rerr != nil { break }
		if n <= 0      { break }
		strings.write_bytes(&out, buf[:n])
	}

	return strings.to_string(out), nil
}

/*
An in-memory transport, for driving a connection loop without sockets.

Reads come from a fixed script and writes are captured, so a protocol test can
supply exact bytes — including bytes no real client would send — and assert on
exactly what the server wrote back. That is how the h2 flood defences are tested:
a socket-based test cannot reliably produce thousands of frames in a single
read, which is precisely the condition being defended against.
*/
Memory_Transport :: struct {
	using base: Transport,
	// Bytes the server will read, consumed front to back.
	input:  []byte,
	pos:    int,
	// Everything the server wrote.
	output: [dynamic]byte,
	// Set once the script is exhausted, so the loop sees a closed peer rather
	// than blocking forever.
	closed: bool,
}

memory_transport_init :: proc(mt: ^Memory_Transport, input: []byte, allocator := context.allocator) {
	mt.input = input
	mt.output.allocator = allocator

	mt.read = proc(t: ^Transport, buf: []byte) -> (n: int, ok: bool) {
		mt := cast(^Memory_Transport)t
		if mt.pos >= len(mt.input) {
			// The script is finished: report a closed peer, which is what a
			// real client disconnecting looks like.
			return 0, false
		}
		n = min(len(buf), len(mt.input) - mt.pos)
		copy(buf, mt.input[mt.pos:mt.pos + n])
		mt.pos += n
		return n, true
	}

	mt.write = proc(t: ^Transport, buf: []byte) -> (n: int, ok: bool) {
		mt := cast(^Memory_Transport)t
		append(&mt.output, ..buf)
		return len(buf), true
	}

	mt.close = proc(t: ^Transport) {
		mt := cast(^Memory_Transport)t
		mt.closed = true
	}

	mt.set_timeout = proc(t: ^Transport, recv: bool, d: time.Duration) {
		// No deadlines to apply without a socket.
	}
}

memory_transport_destroy :: proc(mt: ^Memory_Transport) {
	delete(mt.output)
}

// Runs the HTTP/2 connection loop against a scripted byte stream.
h2_serve_memory :: proc(mt: ^Memory_Transport, s: ^Server, allocator: mem.Allocator) {
	h2_serve(&mt.base, s, allocator)
}
