package tests

import "core:mem/virtual"
import "core:net"
import "core:strings"
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
	stop:     bool,
}

@(private)
raw_server_run :: proc(rs: ^Raw_Server) {
	for !rs.stop {
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
	rs.stop = true
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
