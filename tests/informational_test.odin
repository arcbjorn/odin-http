package tests

import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

import http "../http"

/*
Interim 1xx responses.

RFC 9110 15.2: a client must be prepared for one or more informational
responses before the final one. `100 Continue` and `103 Early Hints` are both
sent by deployed servers, so a client that treats the first status line as the
answer returns the wrong status and an empty body.

These tests need a server that emits raw bytes, since this package's own server
never sends a 1xx.
*/

@(private)
Raw_Server :: struct {
	response: string,
	socket:   net.TCP_Socket,
	endpoint: net.Endpoint,
	thread:   ^thread.Thread,
	// Written by the stopping thread and read by the accept loop, so it must be
	// atomic: a plain bool here is a data race, which ThreadSanitizer reports
	// and which can leave the accept loop spinning after a test has finished.
	stop:     bool,
}

@(private)
raw_server_run :: proc(rs: ^Raw_Server) {
	for !sync.atomic_load(&rs.stop) {
		client, _, err := net.accept_tcp(rs.socket)
		if err != nil { return }

		// Read the request so the client's write completes, then reply with the
		// canned bytes and close.
		buf: [4096]byte
		net.recv_tcp(client, buf[:])
		net.send_tcp(client, transmute([]byte)rs.response)
		net.close(client)
	}
}

@(private)
raw_server_start :: proc(rs: ^Raw_Server, response: string) -> bool {
	rs.response = response

	sock, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if err != nil { return false }
	rs.socket = sock

	bound, berr := net.bound_endpoint(sock)
	if berr != nil { net.close(sock); return false }
	rs.endpoint = bound

	rs.thread = thread.create_and_start_with_poly_data(rs, raw_server_run)
	// Give the accept loop a moment to reach `accept_tcp`.
	time.sleep(50 * time.Millisecond)
	return true
}

@(private)
raw_server_stop :: proc(rs: ^Raw_Server) {
	sync.atomic_store(&rs.stop, true)
	net.close(rs.socket)
	if rs.thread != nil {
		thread.terminate(rs.thread, 0)
		thread.destroy(rs.thread)
		rs.thread = nil
	}
}

@(private)
fetch_raw :: proc(t: ^testing.T, response: string, arena: ^virtual.Arena) -> (http.Client_Response, http.Client_Error) {
	rs: Raw_Server
	if !raw_server_start(&rs, response) {
		testing.fail_now(t, "could not start raw server")
	}
	defer raw_server_stop(&rs)

	alloc := virtual.arena_allocator(arena)

	url := strings.builder_make(alloc)
	strings.write_string(&url, "http://127.0.0.1:")
	strings.write_int(&url, int(rs.endpoint.port))
	strings.write_string(&url, "/")

	c := http.DEFAULT_CLIENT
	return http.client_get(&c, strings.to_string(url), alloc)
}

@(test)
test_client_skips_100_continue :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res, err := fetch_raw(t,
		"HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nreal", &arena)

	testing.expect_value(t, err, http.Client_Error.None)
	// Before the fix this returned .Continue with an empty body.
	testing.expect_value(t, res.status, http.Status.OK)
	testing.expect_value(t, res.body, "real")
}

@(test)
test_client_skips_early_hints :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res, err := fetch_raw(t,
		"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Final: yes\r\n\r\nhi", &arena)

	testing.expect_value(t, err, http.Client_Error.None)
	testing.expect_value(t, res.status, http.Status.OK)
	testing.expect_value(t, res.body, "hi")

	// Interim headers describe the interim response only. Leaking an Early
	// Hints Link header into the final response would misreport what the
	// server actually said.
	_, leaked := http.headers_get(res.headers, "link")
	testing.expect(t, !leaked, "interim headers must not leak into the final response")

	final, has := http.headers_get(res.headers, "x-final")
	testing.expect(t, has, "final headers must survive")
	testing.expect_value(t, final, "yes")
}

@(test)
test_client_skips_several_interim_responses :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res, err := fetch_raw(t,
		"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n" +
		"HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\ndone", &arena)

	testing.expect_value(t, err, http.Client_Error.None)
	testing.expect_value(t, res.status, http.Status.Created)
	testing.expect_value(t, res.body, "done")
}

@(test)
test_client_bounds_interim_responses :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	// A peer that never sends a final response would otherwise keep the client
	// reading forever.
	b := strings.builder_make(context.temp_allocator)
	for _ in 0 ..< 50 {
		strings.write_string(&b, "HTTP/1.1 100 Continue\r\n\r\n")
	}
	strings.write_string(&b, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")

	_, err := fetch_raw(t, strings.to_string(b), &arena)

	testing.expect_value(t, err, http.Client_Error.Parse_Failed)
}

@(test)
test_client_reads_close_delimited_body :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	// No Content-Length and no Transfer-Encoding: the body runs until the
	// connection closes (RFC 9112 6.3). A request can never be framed this way,
	// which is why the response path needs its own rule.
	res, err := fetch_raw(t,
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" +
		"body until close", &arena)

	testing.expect_value(t, err, http.Client_Error.None)
	testing.expect_value(t, res.status, http.Status.OK)
	testing.expect_value(t, res.body, "body until close")
	testing.expect(t, res.until_close, "the connection cannot be reused")
}

@(test)
test_client_rejects_truncated_body :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	// Content-Length promises 100 bytes but the peer closes after 4. Returning
	// the short body as if it were complete would silently corrupt the caller's
	// data.
	res, err := fetch_raw(t,
		"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nreal", &arena)

	testing.expect_value(t, err, http.Client_Error.Read_Failed)
	testing.expect(t, len(res.body) < 100, "")
}

@(test)
test_parser_does_not_report_interim_headers :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res: http.Client_Response
	http.headers_init(&res.headers, virtual.arena_allocator(&arena))

	p: http.Parser
	http.parser_init_response(&p, &res, .Get)

	input := "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nreal"
	data := transmute([]byte)input

	// A .Headers_Done for the interim response would tell a driver the answer
	// had arrived. Only the final response may produce one.
	headers_done := 0
	consumed := 0
	for _ in 0 ..< 32 {
		n, ev := http.parser_feed(&p, data[consumed:])
		consumed += n

		#partial switch ev {
		case .Headers_Done: headers_done += 1
		case .Message_Done: 
			testing.expect_value(t, headers_done, 1)
			testing.expect_value(t, res.status, http.Status.OK)
			return
		case .Error:
			testing.expect(t, false, "unexpected parse error")
			return
		}
		if n == 0 && ev == .Need_More { break }
	}
	testing.expect(t, false, "parser did not finish")
}

/*
A mute peer must not stall the client forever.

`read_timeout` only applies once a connection is usable, so it cannot bound the
TLS handshake: a host that accepts TCP and then never sends a ServerHello left
the client blocked indefinitely inside `SSL_connect`. `connect_timeout` now
covers both, since both are the same thing — waiting on a peer that may never
answer.
*/
@(private)
Mute_Server :: struct {
	socket:   net.TCP_Socket,
	endpoint: net.Endpoint,
	thread:   ^thread.Thread,
}

@(private)
mute_server_run :: proc(ms: ^Mute_Server) {
	for {
		client, _, err := net.accept_tcp(ms.socket)
		if err != nil { return }
		// Accepted, and deliberately never spoken to.
		_ = client
	}
}

@(test)
test_client_handshake_is_bounded :: proc(t: ^testing.T) {
	sock, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	testing.expect(t, err == nil, "could not listen")
	defer net.close(sock)

	bound, berr := net.bound_endpoint(sock)
	testing.expect(t, berr == nil, "could not read bound port")

	ms := Mute_Server{socket = sock, endpoint = bound}
	ms.thread = thread.create_and_start_with_poly_data(&ms, mute_server_run)
	defer {
		thread.terminate(ms.thread, 0)
		thread.destroy(ms.thread)
	}
	time.sleep(50 * time.Millisecond)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	url := strings.builder_make(alloc)
	strings.write_string(&url, "https://127.0.0.1:")
	strings.write_int(&url, int(bound.port))
	strings.write_string(&url, "/")

	c := http.DEFAULT_CLIENT
	c.connect_timeout = 1 * time.Second

	start := time.now()
	_, cerr := http.client_get(&c, strings.to_string(url), alloc)
	elapsed := time.since(start)

	// The request must fail, and must do so promptly rather than hanging.
	testing.expect(t, cerr != .None, "a mute peer should not produce a response")
	testing.expectf(t, elapsed < 5 * time.Second,
		"client took %v against a mute peer; the handshake is unbounded", elapsed)
}

/*
Response-side smuggling and pool safety.

A client is the mirror of a server here: a malicious or compromised server that
can make the client disagree with it about where a response ends can inject a
forged response into the *next* request on a reused connection. That is response
smuggling, and pooling is what makes it exploitable — without connection reuse
there is no next request to poison.
*/

@(test)
test_client_rejects_response_with_te_and_content_length :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	// The response-side CL.TE desync. Whichever header the client honours, a
	// peer that picks the other injects everything after this response.
	_, err := fetch_raw(t,
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ninjected", &arena)

	testing.expect_value(t, err, http.Client_Error.Parse_Failed)
}

@(test)
test_client_rejects_conflicting_content_lengths :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	_, err := fetch_raw(t,
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello", &arena)

	testing.expect_value(t, err, http.Client_Error.Parse_Failed)
}

@(test)
test_client_reads_chunked_response_with_trailers :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	// Trailers are legal after the terminating chunk. They are parsed and
	// discarded, not merged: a trailer must not retroactively change a header
	// the caller has already acted on.
	res, err := fetch_raw(t,
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n0\r\nX-Trailer: late\r\n\r\n", &arena)

	testing.expect_value(t, err, http.Client_Error.None)
	testing.expect_value(t, res.body, "hello")
	testing.expect(t, !http.headers_has(res.headers, "x-trailer"),
		"a trailer must not become a response header")
}

@(test)
test_client_rejects_bad_chunk_size :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	// A non-hex chunk size is the framing ambiguity that lets two hops disagree
	// about where the body ends.
	_, err := fetch_raw(t,
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n", &arena)

	testing.expect_value(t, err, http.Client_Error.Parse_Failed)
}

@(test)
test_client_rejects_invalid_status_line :: proc(t: ^testing.T) {
	bad := []string{
		"HTTP/1.1 20 OK\r\n\r\n",          // status must be three digits
		"HTTP/1.1 2000 OK\r\n\r\n",
		"HTTP/1.1 abc OK\r\n\r\n",
		"HTTP/9.9 200 OK\r\n\r\n",         // unsupported major version
		"NOTHTTP 200 OK\r\n\r\n",
	}

	for raw in bad {
		arena: virtual.Arena
		_ = virtual.arena_init_growing(&arena)
		defer virtual.arena_destroy(&arena)

		_, err := fetch_raw(t, raw, &arena)
		testing.expectf(t, err != .None, "status line %q must be rejected", raw)
	}
}

@(test)
test_client_rejects_response_header_injection :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	// A header name with a space before the colon is the ambiguity that lets a
	// proxy and a client disagree about which fields exist.
	_, err := fetch_raw(t,
		"HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\nhello", &arena)

	testing.expect_value(t, err, http.Client_Error.Parse_Failed)
}

/*
A server that over-sends must not poison the next pooled request.

The client reads into a buffer, so a server that writes more than its declared
response leaves those extra bytes unconsumed. If the connection then returns to
the pool, the next request on it reads the leftovers first and treats them as
its own response — a forged reply the caller cannot distinguish from a real one.
This is response smuggling, and pooling is what makes it reachable: without
reuse there is no next request to poison.
*/
@(private)
Overshare_Server :: struct {
	socket:   net.TCP_Socket,
	endpoint: net.Endpoint,
	thread:   ^thread.Thread,
}

@(private)
overshare_run :: proc(s: ^Overshare_Server) {
	for {
		client, _, err := net.accept_tcp(s.socket)
		if err != nil { return }

		buf: [4096]byte
		net.recv_tcp(client, buf[:])

		// One well-formed response, immediately followed by a second the client
		// never asked for.
		// The first response, then a forged one. Sent as two writes so the
		// forged bytes are likely to still be in the socket rather than in the
		// client's buffer when the first response completes — the case where
		// discarding the buffer alone would not save us.
		net.send_tcp(client, transmute([]byte)string("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nfirst!"))
		time.sleep(100 * time.Millisecond)
		net.send_tcp(client, transmute([]byte)string("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nFORGED"))

		/*
		Held open so the client keeps the connection in its pool, then closed.

		The connection must still be poolable when the second request looks for
		one — that is the whole scenario — but this loop is serial, so a peer
		held too long leaves the next `accept` pending and the client's retry
		finds nobody listening. Both failure modes are timing, not smuggling.

		The window is therefore closed from the *client* side instead: the test
		makes its second request while this sleep is still running, and the
		duration only has to outlast that. It is generous because a slow CI
		machine delays the client, not this thread.
		*/
		time.sleep(1500 * time.Millisecond)
		net.close(client)
	}
}

@(test)
test_client_does_not_pool_a_connection_with_leftovers :: proc(t: ^testing.T) {
	sock, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	testing.expect(t, err == nil, "could not listen")
	defer net.close(sock)

	bound, berr := net.bound_endpoint(sock)
	testing.expect(t, berr == nil, "could not read bound port")

	s := Overshare_Server{socket = sock, endpoint = bound}
	s.thread = thread.create_and_start_with_poly_data(&s, overshare_run)
	defer { thread.terminate(s.thread, 0); thread.destroy(s.thread) }
	time.sleep(50 * time.Millisecond)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	url := strings.builder_make(alloc)
	strings.write_string(&url, "http://127.0.0.1:")
	strings.write_int(&url, int(bound.port))
	strings.write_string(&url, "/")

	pool: http.Pool
	http.pool_init(&pool)
	defer http.pool_destroy(&pool)

	c := http.DEFAULT_CLIENT
	c.pool = &pool

	first, err1 := http.client_get(&c, strings.to_string(url), alloc)
	testing.expect_value(t, err1, http.Client_Error.None)
	testing.expect_value(t, first.body, "first!")

	// Give the peer time to send the unsolicited response, so the poisoned
	// connection is sitting in the pool when the next request looks for one.
	time.sleep(200 * time.Millisecond)

	// The forged bytes must never be returned as a response. Retiring the
	// connection is the correct outcome; whether the retry then succeeds
	// depends on the peer, and either way the caller is not lied to.
	second, err2 := http.client_get(&c, strings.to_string(url), alloc)
	testing.expectf(t, second.body != "FORGED",
		"the pooled connection served a forged response (err=%v)", err2)
	testing.expect(t, second.body == "first!" || err2 != .None,
		"a poisoned connection must yield either a genuine response or an error")
}
