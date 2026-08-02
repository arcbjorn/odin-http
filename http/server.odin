package http

import "core:log"
import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

/*
A blocking, thread-per-connection HTTP/1.1 server.

This is the first of two planned drivers over the sans-I/O parser. It is chosen
first deliberately: handler code is straight-line, the request's lifetime is the
stack frame, and a handler that blocks on a database call blocks only its own
connection. An nbio-based driver over the same parser can follow without any
parser changes, which is the point of keeping I/O out of the parser.

The trade-off is honest: one OS thread per connection caps concurrency in the
low thousands, and idle keep-alive connections hold a thread each. Deployments
that need C10k should use the event-loop driver when it lands, or put this
behind a reverse proxy.
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
}

DEFAULT_SERVER_OPTS :: Server_Opts {
	limits           = DEFAULT_LIMITS,
	max_connections  = 1024,
	idle_timeout     = 60  * time.Second,
	read_timeout     = 30  * time.Second,
	write_timeout    = 30  * time.Second,
	read_buffer_size = 16 * 1024,
}

Server :: struct {
	opts:     Server_Opts,
	handler:  Handler,
	socket:   net.TCP_Socket,

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
		conn.socket = client
		conn.client = source

		t := thread.create_and_start_with_poly_data(conn, connection_thread)
		if t == nil {
			log.error("failed to start connection thread")
			net.close(client)
			free(conn)
			sync.mutex_lock(&s.mutex)
			s.active -= 1
			sync.mutex_unlock(&s.mutex)
			continue
		}
		// The thread owns itself; nothing joins it, so release the handle.
		thread.destroy(t)
	}

	return nil
}

server_shutdown :: proc(s: ^Server) {
	sync.mutex_lock(&s.mutex)
	s.closing = true
	sync.mutex_unlock(&s.mutex)

	// Unblocks the accept loop.
	net.close(s.socket)
}

Connection :: struct {
	server: ^Server,
	socket: net.TCP_Socket,
	client: net.Endpoint,
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

	defer {
		net.close(conn.socket)
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

		net.set_option(conn.socket, .Receive_Timeout, deadline)
		n, err := net.recv_tcp(conn.socket, buf[filled:])
		if err != nil {
			// A timeout on an idle connection is the normal keep-alive exit.
			if !started {
				return false, 0
			}
			log.debugf("read error: %v", err)
			return false, 0
		}
		if n == 0 {
			// Peer closed. Clean if no request was in flight.
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
	response_write(res, &out, server_date(conn.server))

	data := transmute([]byte)strings.to_string(out)

	net.set_option(conn.socket, .Send_Timeout, conn.server.opts.write_timeout)

	// send_tcp may write fewer bytes than requested, so loop until drained.
	sent := 0
	for sent < len(data) {
		n, err := net.send_tcp(conn.socket, data[sent:])
		if err != nil {
			log.debugf("write error: %v", err)
			return false
		}
		if n <= 0 { return false }
		sent += n
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
Returns the cached Date header value.

Formatting a date costs more than it looks when done per response, and the
value only changes once a second, so it is computed at most that often.
*/
@(private)
server_date :: proc(s: ^Server) -> string {
	now := time.now()

	sync.mutex_lock(&s.date_mu)
	defer sync.mutex_unlock(&s.date_mu)

	if s.date_len == 0 || time.diff(s.date_at, now) >= time.Second {
		formatted := date_write(s.date_buf[:], now)
		s.date_len = len(formatted)
		s.date_at = now
	}
	return string(s.date_buf[:s.date_len])
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
