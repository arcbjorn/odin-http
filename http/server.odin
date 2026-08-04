package http

import "base:runtime"

import "core:fmt"
import "core:log"
import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

/*
A blocking, thread-per-connection HTTP/1.1 server.

Handler code is straight-line, a request's lifetime is the stack frame, and a
handler that blocks affects only its own connection.

The cost is one OS thread per connection, which caps concurrency in the low
thousands and holds a thread per idle keep-alive connection. Deployments needing
more should sit behind a reverse proxy.

No throughput figure is quoted: measuring one honestly needs a load generator on
separate hardware, since driving connection-per-request load from the same
machine exhausts the ephemeral port range within seconds and the numbers then
describe the harness rather than the server.
*/

Server_Opts :: struct {
	// Parser limits applied to every request.
	limits:            Limits,
	// Maximum concurrent connections. Each holds one OS thread, so this
	// directly bounds thread count and therefore memory.
	max_connections:   int,
	// How long a connection may stay idle between requests before being closed.
	// This is the Slowloris defence: without it an attacker holds threads open
	// for free.
	idle_timeout:      time.Duration,
	// How long a single request may take to arrive in full.
	read_timeout:      time.Duration,
	// How long writing a response may take.
	write_timeout:     time.Duration,
	// Size of each connection's read buffer.
	read_buffer_size:  int,
	// How long `server_serve` waits for in-flight connections after shutdown
	// before giving up and returning anyway.
	shutdown_timeout:  time.Duration,
	// Bytes read per iteration when streaming a file body. Bounds peak memory
	// per connection independently of file size.
	file_chunk_size:   int,
	// When set, connections are wrapped in TLS using this config. The config
	// must outlive the server; it is shared by every connection.
	tls:               ^TLS_Config,
}

DEFAULT_SERVER_OPTS :: Server_Opts {
	limits           = DEFAULT_LIMITS,
	max_connections  = 1024,
	idle_timeout     = 60  * time.Second,
	read_timeout     = 30  * time.Second,
	write_timeout    = 30  * time.Second,
	read_buffer_size = 16 * 1024,
	shutdown_timeout = 30 * time.Second,
	file_chunk_size  = 64 * 1024,
}

Server :: struct {
	opts:     Server_Opts,
	handler:  Handler,
	socket:   net.TCP_Socket,
	// The address actually bound, needed to wake the accept loop at shutdown.
	endpoint: net.Endpoint,

	closing:  bool,
	// Number of connections currently being served, used to enforce
	// `max_connections` and to wait for drain during shutdown.
	active:   int,
	mutex:    sync.Mutex,

	// Cached Date header, refreshed once a second rather than per response.
	date_buf: [DATE_LENGTH]byte,
	date_len: int,
	date_at:  time.Time,
	date_mu:  sync.Mutex,
}

/*
Binds and listens.

Reuse_Address is set so a restart does not fail while old sockets sit in
TIME_WAIT, which otherwise makes redeploys flaky.
*/
server_listen :: proc(s: ^Server, endpoint: net.Endpoint, opts := DEFAULT_SERVER_OPTS) -> net.Network_Error {
	s.opts = opts

	sock, err := net.listen_tcp(endpoint)
	if err != nil { return err }

	net.set_option(sock, .Reuse_Address, true)
	s.socket = sock

	// Recorded now because shutdown needs somewhere to connect to, and a
	// port-0 bind means the caller's endpoint is not the real one.
	if bound, berr := net.bound_endpoint(sock); berr == nil {
		s.endpoint = bound
	} else {
		s.endpoint = endpoint
	}
	return nil
}

/*
Accepts connections until `server_shutdown` is called.

Each connection is handed to its own thread. The accept loop itself does no
per-request work, so a slow handler cannot delay accepting.
*/
server_serve :: proc(s: ^Server, handler: Handler) -> net.Network_Error {
	s.handler = handler
	server_date_refresh(s)

	for {
		sync.mutex_lock(&s.mutex)
		closing := s.closing
		sync.mutex_unlock(&s.mutex)
		if closing { break }

		client, source, err := net.accept_tcp(s.socket)
		if err != nil {
			sync.mutex_lock(&s.mutex)
			closing := s.closing
			sync.mutex_unlock(&s.mutex)
			if closing { break }

			log.errorf("accept failed: %v", err)
			continue
		}

		// Shed load rather than spawning unbounded threads. Closing immediately
		// is a clearer signal to the client than accepting and stalling.
		sync.mutex_lock(&s.mutex)
		at_capacity := s.active >= s.opts.max_connections
		if !at_capacity { s.active += 1 }
		sync.mutex_unlock(&s.mutex)

		if at_capacity {
			log.warn("connection limit reached, rejecting")
			net.close(client)
			continue
		}

		conn := new(Connection)
		conn.server = s
		conn.client = source
		conn.socket = client

		// The TLS handshake is deliberately NOT performed here. It reads from
		// the client, so a peer that completes the TCP connect and then sends
		// nothing would block this loop indefinitely — one socket is enough to
		// stop the server accepting anything at all. Doing it on the connection
		// thread costs that peer a thread and nobody else anything.
		if s.opts.tls == nil {
			plain_transport_init(&conn.plain, client, source)
			conn.transport = &conn.plain.base
		}

		// `self_cleanup` is essential, not a convenience: `thread.destroy`
		// JOINS the thread, so calling it here would block the accept loop for
		// the whole life of the connection. With keep-alive that is the entire
		// session, so the server would serve exactly one client at a time.
		t := thread.create_and_start_with_poly_data(conn, connection_thread, self_cleanup = true)
		if t == nil {
			log.error("failed to start connection thread")
			net.close(client)
			free(conn)
			sync.mutex_lock(&s.mutex)
			s.active -= 1
			sync.mutex_unlock(&s.mutex)
			continue
		}
	}

	server_drain(s)
	return nil
}

/*
Waits for in-flight connections to finish.

Connection threads are detached, so returning from `server_serve` while they run
would leave them dereferencing a `Server` the caller may already have freed.

Polls rather than using a condition variable: shutdown happens once, so a
condvar would add a wakeup path to every connection exit for nothing.
*/
@(private)
server_drain :: proc(s: ^Server) {
	deadline := time.time_add(time.now(), s.opts.shutdown_timeout)

	for {
		sync.mutex_lock(&s.mutex)
		remaining := s.active
		sync.mutex_unlock(&s.mutex)

		if remaining <= 0 { return }

		if time.diff(time.now(), deadline) <= 0 {
			// A handler is wedged past every per-connection timeout. Returning
			// is still wrong in principle, but hanging shutdown forever is
			// worse, so report it rather than blocking indefinitely.
			log.warnf("shutdown timed out with %d connection(s) still active", remaining)
			return
		}

		time.sleep(DRAIN_POLL_INTERVAL)
	}
}

@(private)
DRAIN_POLL_INTERVAL :: 2 * time.Millisecond

/*
Returns the number of connections currently being served.

Exposed mainly so shutdown can be asserted on: after `server_serve` returns,
this must be zero, or connection threads are still running against a Server the
caller may free.
*/
server_active_connections :: proc(s: ^Server) -> int {
	sync.mutex_lock(&s.mutex)
	defer sync.mutex_unlock(&s.mutex)
	return s.active
}

/*
Stops the accept loop.

Closing the listening socket is not enough on its own: on Linux a thread already
blocked in `accept()` is not reliably woken by another thread closing the
descriptor, so shutdown would hang until the next client happened to connect.
Connecting to ourselves guarantees one more `accept` returns, at which point the
loop observes `closing` and exits.

The wake connection is closed immediately. If the loop accepts it first it is
served as an empty connection and closed by the read timeout, which costs one
short-lived thread at shutdown and nothing afterwards.
*/
server_shutdown :: proc(s: ^Server) {
	sync.mutex_lock(&s.mutex)
	already := s.closing
	s.closing = true
	sync.mutex_unlock(&s.mutex)

	if already { return }

	// Wake a blocked accept before closing, so the loop sees `closing`.
	if s.endpoint.port != 0 {
		target := s.endpoint
		if target.address == nil { target.address = net.IP4_Loopback }
		if waker, err := net.dial_tcp(target); err == nil {
			net.close(waker)
		}
	}

	net.close(s.socket)
}

Connection :: struct {
	server: ^Server,
	client: net.Endpoint,
	// Kept so the connection thread can perform the TLS handshake itself; the
	// accept loop must not, because the handshake reads from the peer.
	socket: net.TCP_Socket,

	// The byte transport for this connection. Owned inline so a plaintext
	// connection costs no extra allocation; TLS swaps this out without the
	// request/response code noticing.
	transport: ^Transport,
	plain:     Plain_Transport,
	tls:       TLS_Transport,
}

/*
The request this thread is currently serving, for panic diagnostics.

Thread-local so each connection reports its own request. Holding borrowed
strings is safe here because the panic handler runs on this same thread while
the request is still live.
*/
@(thread_local)
in_flight_method: Method
@(thread_local)
in_flight_target: string
@(thread_local)
in_flight_client: net.Endpoint

/*
Reports which request was being served when the process died.

A handler panic kills the process, so naming the responsible request is the only
salvage available. Writes to stderr directly, since a custom logger may itself
be unusable by this point.
*/
@(private)
handler_panic_handler :: proc(prefix, message: string, loc: runtime.Source_Code_Location) -> ! {
	fmt.eprintfln("%s(%d:%d) %s: %s", loc.file_path, loc.line, loc.column, prefix, message)
	fmt.eprintfln(
		"  while serving: %s %s from %v",
		method_string(in_flight_method), in_flight_target, in_flight_client,
	)
	fmt.eprintln("  NOTE: a panic in a handler terminates the whole server; handle errors instead of panicking")

	runtime.trap()
}

/*
Serves every request on one connection.

The arena is created once here and reset between requests, so a keep-alive
connection performs no further allocation after its first request has sized the
arena. This mirrors the lifetime rule the parser assumes: request strings borrow
from the read buffer, and both live exactly as long as the connection.
*/
@(private)
connection_thread :: proc(conn: ^Connection) {
	s := conn.server

	// A failed handshake is routine — scanners, clients with no shared cipher,
	// plain HTTP sent to a TLS port — so the socket is closed quietly and the
	// active count released, exactly as a normal connection exit would.
	if s.opts.tls != nil && conn.transport == nil {
		// The handshake must be bounded before it starts. `SSL_accept` reads
		// from the peer, and without a deadline a client that connects and then
		// says nothing holds this thread forever. That is a slow-loris needing
		// one socket per slot and no traffic at all: `max_connections` silent
		// sockets take the server offline permanently.
		net.set_option(conn.socket, .Receive_Timeout, s.opts.read_timeout)
		net.set_option(conn.socket, .Send_Timeout, s.opts.write_timeout)

		if !tls_transport_init(&conn.tls, s.opts.tls, conn.socket, conn.client) {
			net.close(conn.socket)
			sync.mutex_lock(&s.mutex)
			s.active -= 1
			sync.mutex_unlock(&s.mutex)
			free(conn)
			return
		}
		conn.transport = &conn.tls.base
	}

	// A TLS client that selected h2 via ALPN speaks a different protocol from
	// here on, so it is handed to the h2 connection loop rather than the
	// HTTP/1.1 driver below.
	if s.opts.tls != nil && tls_negotiated_h2(&conn.tls) {
		arena: virtual.Arena
		if virtual.arena_init_growing(&arena) == nil {
			h2_serve(conn.transport, s, virtual.arena_allocator(&arena))
			virtual.arena_destroy(&arena)
		}
		conn.transport->close()
		sync.mutex_lock(&s.mutex)
		s.active -= 1
		sync.mutex_unlock(&s.mutex)
		free(conn)
		return
	}

	// Odin has no way to recover from a panic: `Assertion_Failure_Proc` returns
	// `!`, so a panicking handler always takes the process down. What CAN be
	// salvaged is the diagnosis — without this the process dies with no
	// indication of which request was responsible, which is the difference
	// between a one-line fix and an afternoon of guessing.
	context.assertion_failure_proc = handler_panic_handler

	defer {
		conn.transport->close()
		sync.mutex_lock(&s.mutex)
		s.active -= 1
		sync.mutex_unlock(&s.mutex)
		free(conn)
	}

	arena: virtual.Arena
	if err := virtual.arena_init_growing(&arena); err != nil {
		log.errorf("failed to create connection arena: %v", err)
		return
	}
	defer virtual.arena_destroy(&arena)

	allocator := virtual.arena_allocator(&arena)

	// The read buffer deliberately lives OUTSIDE the arena. Request strings
	// borrow from it, and `free_all` between requests would otherwise free the
	// very bytes holding the pipelined next request. Keeping it on the heap for
	// the connection's lifetime makes that impossible to get wrong.
	buf := make([]byte, s.opts.read_buffer_size)
	defer delete(buf)

	// Bytes read but not yet consumed by the parser, carried across requests
	// because a client may pipeline the next request into the same packet.
	buffered := 0

	for {
		keep_alive, next_buffered := serve_one(conn, buf, buffered, allocator)
		if !keep_alive { return }

		buffered = next_buffered

		// Safe now: everything the last request borrowed is dead, and the
		// pipelined bytes live in `buf`, which the arena does not own.
		free_all(allocator)
	}
}

/*
Serves a single request.

Returns whether the connection may be reused and how many bytes of the next
request are already buffered.
*/
@(private)
serve_one :: proc(
	conn: ^Connection,
	buf: []byte,
	initial_buffered: int,
	allocator: mem.Allocator,
) -> (keep_alive: bool, leftover: int) {
	s := conn.server

	req: Request
	request_init(&req, allocator)
	req.client = conn.client

	res: Response
	response_init(&res, allocator)

	p: Parser
	parser_init(&p, &req, s.opts.limits)

	body := strings.builder_make(allocator)

	filled := initial_buffered
	consumed := 0
	// An idle connection waiting for its first byte gets the longer idle
	// timeout; once a request starts, the stricter read timeout applies.
	deadline := s.opts.idle_timeout
	started := false

	parse_loop: for {
		// Drive the parser until it can make no further progress on the bytes
		// already buffered. Note that a message can complete without consuming
		// anything: a bodyless request emits .Message_Done from an empty buffer,
		// so this must run even when `consumed == filled`, or the loop below
		// would block on a read that never returns.
		//
		// NOTE: `continue` inside a switch binds to the switch in Odin rather
		// than the enclosing loop, hence the explicit flag.
		for {
			n, ev := parser_feed(&p, buf[consumed:filled])
			consumed += n

			stalled := false
			#partial switch ev {
			case .Headers_Done:
				started = true
				deadline = s.opts.read_timeout

				// The request line and headers are slices INTO `buf`. Reading a
				// body larger than the buffer compacts it, moving those bytes
				// out from under the request, so it must own them before any
				// further reads. Without this the target silently aliases body
				// content, letting a crafted body choose the routed path.
				request_detach(&req, allocator)

				// A client that sent `Expect: 100-continue` is waiting for
				// permission before it sends the body. Staying silent does not
				// break the request — the client gives up and sends anyway —
				// but it costs that client's full grace period, a full second
				// in curl's case, on every such request.
				if !send_continue_if_expected(conn, &req, &res, allocator) {
					return false, 0
				}
			case .Body_Chunk:
				strings.write_bytes(&body, p.chunk)
			case .Message_Done:
				break parse_loop
			case .Error:
				respond_parse_error(&res, p.err)
				write_response(conn, &res, allocator)
				return false, 0
			case .Need_More:
				stalled = true
			}

			// Without consuming input the parser cannot advance further.
			if stalled || n == 0 { break }
		}

		if consumed >= filled {
			// Everything buffered has been consumed; reset to the front so a
			// large request is not limited by earlier offsets.
			if consumed > 0 {
				copy(buf, buf[consumed:filled])
				filled -= consumed
				consumed = 0
			}
		}

		if filled >= len(buf) {
			// The parser needs more input but the buffer is full, meaning a
			// single token exceeds the buffer. The limits should have caught
			// this first; treat it as a bad request rather than growing without
			// bound.
			respond_parse_error(&res, .Headers_Too_Long)
			write_response(conn, &res, allocator)
			return false, 0
		}

		conn.transport->set_timeout(true, deadline)
		n, read_ok := conn.transport->read(buf[filled:])
		if !read_ok {
			// The transport reports a closed peer and a read error the same
			// way, because the server's response is identical either way: stop
			// serving this connection. An idle timeout with no request started
			// is the ordinary keep-alive exit rather than a failure.
			if started {
				log.debug("connection lost mid-request")
			}
			return false, 0
		}
		filled += n
	}

	req.body = strings.to_string(body)
	res._version = req.version

	// A HEAD response must be byte-identical to the GET response minus the
	// body, so the handler runs as if it were a GET.
	is_head := req.method == .Head
	if is_head {
		req.method = .Get
		res._write_body = false
	}

	req.headers.readonly = true

	should_keep := parser_should_keep_alive(&p)
	if !should_keep { res._close = true }

	// Recorded so a panic inside the handler can name the request responsible.
	in_flight_method = req.method
	in_flight_target = req.target
	in_flight_client = req.client

	handler := s.handler
	handler_serve(&handler, &req, &res)

	if !write_response(conn, &res, allocator) { return false, 0 }
	if res._close { return false, 0 }

	// Hand any pipelined bytes to the next request.
	remaining := filled - consumed
	if remaining > 0 {
		copy(buf, buf[consumed:filled])
	}
	return should_keep, remaining
}

@(private)
write_response :: proc(conn: ^Connection, res: ^Response, allocator: mem.Allocator) -> bool {
	out := strings.builder_make(allocator)

	// The Date lives on this thread's stack, so no other connection can rewrite
	// it while the response is being serialized.
	date_buf: [DATE_LENGTH]byte
	response_write(res, &out, server_date(conn.server, date_buf[:]))

	conn.transport->set_timeout(false, conn.server.opts.write_timeout)

	// The handler owns the file until here; close it however this returns so an
	// early error cannot leak the descriptor.
	file, streaming := response_body_is_file(res)
	defer if f, has := res.file.?; has {
		os.close(f.handle)
		res.file = nil
	}

	if !write_all(conn, transmute([]byte)strings.to_string(out)) { return false }

	if streaming {
		return write_file_body(conn, file, allocator)
	}

	if stream, is_stream := response_body_is_stream(res); is_stream {
		return write_stream_body(conn, stream)
	}
	return true
}

/*
Runs a streaming handler, framing its output as chunked transfer encoding.

The terminating zero-length chunk is what tells the client the body ended, so it
must be written even if the producer wrote nothing. Skipping it on a producer
error would instead leave the client waiting for a body that never ends, so a
failed stream closes the connection rather than sending a terminator that would
imply the body was complete.
*/
@(private)
write_stream_body :: proc(conn: ^Connection, stream: Stream_Body) -> bool {
	w := Stream_Writer{
		_conn  = conn,
		_write = proc(c: rawptr, data: []byte) -> bool {
			return write_all(cast(^Connection)c, data)
		},
		// HTTP/1.1 has no other way to delimit a body of unknown length.
		_chunked = true,
	}

	stream.proc_(&w, stream.data)

	if w.err {
		// The body is now truncated and the framing cannot be repaired: the
		// client must not be told this was a complete response.
		log.debug("stream producer failed, closing connection")
		return false
	}

	// last-chunk = "0" CRLF, then an empty trailer section.
	return write_all(conn, transmute([]byte)string("0\r\n\r\n"))
}

@(private)
write_all :: proc(conn: ^Connection, data: []byte) -> bool {
	// send_tcp may write fewer bytes than requested, so loop until drained.
	return transport_write_all(conn.transport, data)
}

/*
Streams a file body to the socket in bounded chunks.

Peak memory is one chunk regardless of file size, which is the entire point:
buffering the file would cost a full copy of it per concurrent request, so a
handful of requests for a large file could exhaust memory.

`read_at` is used rather than seek+read because it needs no per-connection file
position, so the same handle could later be shared without a lock.
*/
@(private)
write_file_body :: proc(conn: ^Connection, file: File_Body, allocator: mem.Allocator) -> bool {
	chunk := make([]byte, conn.server.opts.file_chunk_size, allocator)

	remaining := file.length
	offset    := file.offset

	for remaining > 0 {
		want := min(i64(len(chunk)), remaining)

		n, err := os.read_at(file.handle, chunk[:want], offset)
		if err != nil {
			log.errorf("file read error: %v", err)
			// The headers already promised Content-Length bytes, so the body is
			// now short. The connection cannot be reused: a client would read
			// the next response as the remainder of this one.
			return false
		}
		if n <= 0 {
			// The file shrank after it was stat'd; same framing problem.
			log.error("file ended before Content-Length was satisfied")
			return false
		}

		if !write_all(conn, chunk[:n]) { return false }

		offset    += i64(n)
		remaining -= i64(n)
	}
	return true
}

/*
Maps a parse failure to a response.

Every parse error closes the connection. Once framing is ambiguous the byte
stream cannot be trusted to resynchronize, and continuing to read is exactly
what turns a malformed request into a smuggled one.
*/
@(private)
respond_parse_error :: proc(res: ^Response, err: Parse_Error) {
	status: Status
	#partial switch err {
	case .Request_Line_Too_Long:
		status = .URI_Too_Long
	case .Headers_Too_Long:
		status = .Request_Header_Fields_Too_Large
	case .Body_Too_Large:
		status = .Payload_Too_Large
	case .Invalid_Method:
		status = .Not_Implemented
	case .Unsupported_Version:
		status = .HTTP_Version_Not_Supported
	case:
		status = .Bad_Request
	}

	respond_status(res, status)
	response_set_close(res)
}

/*
Copies the cached Date header into `buf` and returns the filled slice.

Formatting a date costs more than it looks when done per response, and the value
only changes once a second, so it is computed at most that often.

The copy is the point. Returning a slice of `s.date_buf` would hand callers a
borrow of shared mutable state: the lock is released on return, and a refreshing
thread can then rewrite those bytes while the caller is still copying them into
its response. Today that is harmless — IMF-fixdate is fixed width, so a torn
read splices two nearly identical timestamps and can never produce a malformed
header — but it is a data race, and it only stays benign for as long as the
format never changes. `buf` is the caller's stack, so the copy costs nothing.
*/
@(private)
server_date :: proc(s: ^Server, buf: []byte) -> string {
	assert(len(buf) >= DATE_LENGTH)
	now := time.now()

	sync.mutex_lock(&s.date_mu)
	defer sync.mutex_unlock(&s.date_mu)

	if s.date_len == 0 || time.diff(s.date_at, now) >= time.Second {
		formatted := date_write(s.date_buf[:], now)
		s.date_len = len(formatted)
		s.date_at = now
	}

	copy(buf, s.date_buf[:s.date_len])
	return string(buf[:s.date_len])
}

@(private)
server_date_refresh :: proc(s: ^Server) {
	sync.mutex_lock(&s.date_mu)
	defer sync.mutex_unlock(&s.date_mu)

	now := time.now()
	formatted := date_write(s.date_buf[:], now)
	s.date_len = len(formatted)
	s.date_at = now
}

/*
Answers `Expect: 100-continue` before the body is read.

RFC 9110 10.1.1: a server receiving a 100-continue expectation either responds
with 100 to invite the body, or with a final status to refuse it. An unknown
expectation must be answered with 417, since silently ignoring it leaves the
client waiting for a response it will never recognise.

Returns false when the connection can no longer be used.
*/
@(private)
send_continue_if_expected :: proc(
	conn: ^Connection,
	req: ^Request,
	res: ^Response,
	allocator: mem.Allocator,
) -> bool {
	expect, has := headers_get(req.headers, "expect")
	if !has { return true }

	// HTTP/1.0 predates the expectation mechanism, so a 1.0 client sending it
	// would not understand the interim response.
	if req.version.minor < 1 { return true }

	if !equal_fold(trim_ows(expect), "100-continue") {
		respond_status(res, .Expectation_Failed)
		response_set_close(res)
		write_response(conn, res, allocator)
		return false
	}

	// An interim response is just a status line and a blank line: no headers,
	// no body, and crucially no Content-Length, since the real response still
	// follows on the same connection.
	conn.transport->set_timeout(false, conn.server.opts.write_timeout)
	return transport_write_all(conn.transport, transmute([]byte)string("HTTP/1.1 100 Continue\r\n\r\n"))
}
