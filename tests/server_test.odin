package tests

import "core:net"
import "core:strings"
import "core:testing"
import "core:time"

import http "../http"

/*
End-to-end server tests over real loopback sockets.

These cover what a Recorder cannot: the parse loop in `serve_one`, connection
reuse, framing on the wire, and the paths where the server must close rather
than continue. Every case here was previously only verified by hand with curl.
*/

@(private)
echo_router :: proc(r: ^http.Router) {
	http.router_init(r)

	http.router_handle_proc(r, "GET /hello", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "hello")
	})
	http.router_handle_proc(r, "POST /echo", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, req.body)
	})
	http.router_handle_proc(r, "GET /empty", proc(req: ^http.Request, res: ^http.Response) {
		res.status = .No_Content
	})
}

/*
Runs `body` against a started test server.

Centralizes setup and teardown so a failed assertion cannot leak a listening
socket into the next test.
*/
@(private)
with_server :: proc(t: ^testing.T, body: proc(t: ^testing.T, ts: ^http.Test_Server)) {
	r: http.Router
	echo_router(&r)
	defer http.router_destroy(&r)

	handler := http.router_handler(&r)

	ts: http.Test_Server
	if err := http.test_server_start(&ts, handler); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	body(t, &ts)
}

@(test)
test_server_simple_get :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, err := http.test_request_raw(ts.endpoint,
			"GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, err == nil, "request should succeed")
		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK\r\n"), "status line")
		testing.expect(t, strings.has_suffix(resp, "hello"), "body")
		testing.expect(t, strings.contains(resp, "content-length: 5\r\n"), "framing")
	})
}

@(test)
test_server_post_with_body :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\nConnection: close\r\n\r\nround trip")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "")
		// Content-Length is 9, so only "round tri" is part of this message; the
		// server must not read past the declared length.
		testing.expect(t, strings.has_suffix(resp, "round tri"), "body honours Content-Length")
	})
}

@(test)
test_server_chunked_request :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
			"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "")
		testing.expect(t, strings.has_suffix(resp, "hello world"), "chunks are reassembled")
	})
}

@(test)
test_server_keep_alive_reuses_connection :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// Both requests go down ONE connection; separate connections would pass
		// even if keep-alive were broken.
		resp, _ := http.test_request_raw_keepalive(ts.endpoint, {
			"GET /hello HTTP/1.1\r\nHost: x\r\n\r\n",
			"GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
		})

		count := strings.count(resp, "HTTP/1.1 200 OK")
		testing.expectf(t, count == 2, "expected 2 responses on one connection, got %d", count)
	})
}

@(test)
test_server_pipelining :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// Both requests arrive in a single write, so the server must serve the
		// second from bytes already buffered rather than waiting on the socket.
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /hello HTTP/1.1\r\nHost: x\r\n\r\n" +
			"GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		count := strings.count(resp, "HTTP/1.1 200 OK")
		testing.expectf(t, count == 2, "expected 2 pipelined responses, got %d", count)
	})
}

@(test)
test_server_head_omits_body :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"HEAD /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		// RFC 9110 9.3.2: HEAD reports the length a GET would, without the body.
		testing.expect(t, strings.contains(resp, "content-length: 5\r\n"), "length is reported")
		testing.expect(t, strings.has_suffix(resp, "\r\n\r\n"), "no body is sent")
		testing.expect(t, !strings.contains(resp, "hello\r\n\r\nhello"), "")
	})
}

@(test)
test_server_204_has_no_body_or_length :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /empty HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 204 No Content"), "")
		// Sending either on a 204 desynchronizes a reused connection.
		testing.expect(t, !strings.contains(resp, "content-length"), "no Content-Length on 204")
		testing.expect(t, strings.has_suffix(resp, "\r\n\r\n"), "no body on 204")
	})
}

@(test)
test_server_404_and_405 :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		missing, _ := http.test_request_raw(ts.endpoint,
			"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		testing.expect(t, strings.has_prefix(missing, "HTTP/1.1 404 Not Found"), "")

		// The path exists under another method, so 405 with Allow, not 404.
		wrong_method, _ := http.test_request_raw(ts.endpoint,
			"DELETE /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		testing.expect(t, strings.has_prefix(wrong_method, "HTTP/1.1 405 Method Not Allowed"), "")
		testing.expect(t, strings.contains(wrong_method, "allow: GET, HEAD\r\n"), "Allow is required on 405")
	})
}

@(test)
test_server_always_sends_date :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		// RFC 9110 6.6.1 requires Date on an origin server's responses.
		testing.expect(t, strings.contains(resp, "\r\ndate: "), "Date header is required")
		testing.expect(t, strings.contains(resp, " GMT\r\n"), "Date must be IMF-fixdate")
	})
}

// --- Malformed input must be refused on the wire, not just in the parser ---

@(test)
test_server_rejects_smuggling_over_socket :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		attacks := []string{
			// CL.TE desync.
			"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
			// Conflicting duplicate Content-Length.
			"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
			// Space before the colon.
			"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\nhello",
			// Obsolete line folding.
			"GET /hello HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n  folded\r\n\r\n",
			// Non-decimal Content-Length.
			"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello",
			// Unknown transfer coding.
			"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n",
			// Missing Host on HTTP/1.1.
			"GET /hello HTTP/1.1\r\n\r\n",
			// Invalid header name.
			"GET /hello HTTP/1.1\r\nHost: x\r\nBad(Name): v\r\n\r\n",
		}

		for attack, i in attacks {
			resp, _ := http.test_request_raw(ts.endpoint, attack)

			testing.expectf(t, strings.has_prefix(resp, "HTTP/1.1 4"),
				"attack %d must be refused with a 4xx, got %q", i,
				resp[:min(len(resp), 40)])

			// Framing is ambiguous once a parse error occurs, so the connection
			// must not be reused for a possibly-smuggled second request.
			testing.expectf(t, strings.contains(resp, "connection: close"),
				"attack %d must close the connection", i)
		}
	})
}

@(test)
test_server_rejects_oversized_headers :: proc(t: ^testing.T) {
	r: http.Router
	echo_router(&r)
	defer http.router_destroy(&r)

	opts := http.DEFAULT_SERVER_OPTS
	opts.limits.max_request_line = 64

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r), opts); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	long := strings.repeat("a", 200, context.temp_allocator)
	resp, _ := http.test_request_raw(ts.endpoint,
		strings.concatenate({"GET /", long, " HTTP/1.1\r\nHost: x\r\n\r\n"}, context.temp_allocator))

	testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 414 URI Too Long"), "")
}

// --- Recorder ---

@(test)
test_recorder_runs_handler :: proc(t: ^testing.T) {
	rec: http.Recorder
	http.recorder_init(&rec, .Get, "/anything")
	defer http.recorder_destroy(&rec)

	h := http.handler_from_proc(proc(req: ^http.Request, res: ^http.Response) {
		http.respond_json(res, .Created, `{"ok":true}`)
	})
	http.recorder_serve(&rec, &h)

	testing.expect_value(t, http.recorder_status(&rec), http.Status.Created)
	testing.expect_value(t, http.recorder_body(&rec), `{"ok":true}`)
	testing.expect_value(t, http.recorder_header(&rec, "content-type"), "application/json")
}

@(test)
test_recorder_passes_request_details :: proc(t: ^testing.T) {
	rec: http.Recorder
	http.recorder_init(&rec, .Post, "/submit?x=1", "payload")
	defer http.recorder_destroy(&rec)

	http.recorder_set_header(&rec, "x-token", "secret")

	h := http.handler_from_proc(proc(req: ^http.Request, res: ^http.Response) {
		token, _ := http.headers_get(req.headers, "x-token")
		http.respond_plain(res, .OK, strings.concatenate(
			{req.body, "|", token, "|", http.request_path(req)},
			req.headers.allocator))
	})
	http.recorder_serve(&rec, &h)

	testing.expect_value(t, http.recorder_body(&rec), "payload|secret|/submit")
}

@(test)
test_recorder_raw_response_shows_framing :: proc(t: ^testing.T) {
	rec: http.Recorder
	http.recorder_init(&rec, .Get, "/")
	defer http.recorder_destroy(&rec)

	h := http.handler_from_proc(proc(req: ^http.Request, res: ^http.Response) {
		http.response_set_cookie(res, http.cookie_session("a", "1"))
		http.response_set_cookie(res, http.cookie_session("b", "2"))
		http.respond_plain(res, .OK, "x")
	})
	http.recorder_serve(&rec, &h)

	raw := http.recorder_raw_response(&rec, "Mon, 02 Jan 2006 15:04:05 GMT")

	testing.expect_value(t, strings.count(raw, "set-cookie:"), 2)
	testing.expect(t, strings.contains(raw, "content-length: 1\r\n"), "")
}

@(test)
test_server_answers_expect_100_continue :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// RFC 9110 10.1.1: the client waits for permission before sending the
		// body. Staying silent still works — the client eventually gives up and
		// sends — but costs it a full grace period (a second, in curl) on every
		// such request.
		resp, _ := http.test_request_raw(ts.endpoint,
			"POST /echo HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n" +
			"Content-Length: 5\r\nConnection: close\r\n\r\nhello")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 100 Continue\r\n\r\n"),
			"the interim response must come first")
		testing.expect(t, strings.contains(resp, "HTTP/1.1 200 OK"),
			"the final response follows on the same connection")
		testing.expect(t, strings.has_suffix(resp, "hello"), "the body still arrives")
	})
}

@(test)
test_server_rejects_unknown_expectation :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// Ignoring an expectation we cannot satisfy leaves the client waiting
		// for a response it will not recognise.
		resp, _ := http.test_request_raw(ts.endpoint,
			"POST /echo HTTP/1.1\r\nHost: x\r\nExpect: something-else\r\n" +
			"Content-Length: 5\r\n\r\nhello")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 417 Expectation Failed"), "")
	})
}

@(test)
test_server_ignores_expect_from_http10 :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// HTTP/1.0 predates the mechanism, so such a client would not
		// understand an interim response.
		resp, _ := http.test_request_raw(ts.endpoint,
			"POST /echo HTTP/1.0\r\nHost: x\r\nExpect: 100-continue\r\n" +
			"Content-Length: 5\r\n\r\nhello")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"),
			"no interim response for an HTTP/1.0 client")
		testing.expect(t, !strings.contains(resp, "100 Continue"), "")
	})
}

// --- Request-target forms (RFC 9112 3.2) ---

@(test)
test_server_accepts_absolute_form :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// RFC 9112 3.2.2: a server MUST accept absolute-form, because that is
		// how every HTTP/1.1 proxy forwards a request. Routing on the raw
		// target instead 404s, so the server cannot sit behind a proxy.
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET http://example.com/hello HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "")
		testing.expect(t, strings.has_suffix(resp, "hello"), "")
	})
}

@(test)
test_server_absolute_form_with_query :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET http://example.com/hello?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "")
	})
}

@(test)
test_server_absolute_form_does_not_trust_authority :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// The authority in the target must not override Host for routing; only
		// the path is used, so a target cannot claim to be another host.
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET http://evil.example/hello HTTP/1.1\r\nHost: real.example\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "")
		testing.expect(t, strings.has_suffix(resp, "hello"), "routes on path only")
	})
}

@(test)
test_server_answers_options_asterisk :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// RFC 9112 3.2.4: `OPTIONS *` asks about the server as a whole, so no
		// path route can match it and 404 would be wrong.
		resp, _ := http.test_request_raw(ts.endpoint,
			"OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 204 No Content"), "")
		testing.expect(t, strings.contains(resp, "allow: "), "OPTIONS must report Allow")
		testing.expect(t, strings.contains(resp, "OPTIONS"), "")
	})
}

@(test)
test_server_rejects_asterisk_for_other_methods :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// `*` names no resource, so any method but OPTIONS is malformed.
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 400 Bad Request"), "")
	})
}

@(test)
test_server_rejects_authority_form :: proc(t: ^testing.T) {
	with_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// authority-form is CONNECT-only, and tunnelling is not supported.
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET example.com:443 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 400 Bad Request"), "")
	})
}

/*
A request delivered one byte at a time must route and parse identically.

The server parses into `buf` and the request borrows slices from it — the
request line, every header name and value. Compacting that buffer while the
header block is still incomplete slides bytes out from under what was already
parsed. `consumed >= filled` is true after almost every read when a peer sends a
byte at a time, so that path is reached constantly under fragmented delivery and
never under a single write.

Measured before the guard: `GET /greet/{name}` sent byte by byte routed to 404
while the identical request in one write returned 200. Nothing rejects such a
request — it simply names a different path than the peer asked for, which is a
routing decision made from corrupted memory.
*/
@(test)
test_request_dribbled_byte_at_a_time_is_intact :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	// Echoes the routed parameter and a header, so corruption in either shows
	// up in the body rather than as a silent mis-route.
	http.router_handle_proc(&r, "GET /greet/{name}", proc(req: ^http.Request, res: ^http.Response) {
		marker, _ := http.headers_get(req.headers, "x-marker")
		http.respond_plain(res, .OK, strings.concatenate(
			{http.request_param(req, "name"), "|", marker}, req.headers.allocator))
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	raw :=
		"GET /greet/marker-intact HTTP/1.1\r\n" +
		"Host: x\r\n" +
		"X-Marker: marker-value-intact\r\n" +
		"User-Agent: probe\r\n" +
		"Connection: close\r\n\r\n"

	// The reference: one write, which never compacts mid-block.
	whole, _ := http.test_request_raw(ts.endpoint, raw)
	testing.expect(t, strings.contains(whole, "200 OK"), "the whole-write request must route")
	testing.expect(t, strings.has_suffix(whole, "marker-intact|marker-value-intact"),
		"the whole-write request must parse intact")

	// The same bytes, one per write.
	sock, derr := net.dial_tcp(ts.endpoint)
	testing.expect(t, derr == nil, "could not connect")
	defer net.close(sock)

	// Each byte needs its own read on the server, so a pause is required: sent
	// back to back they coalesce in the socket buffer and arrive together,
	// which is the whole-write case again and does not exercise compaction.
	data := transmute([]byte)raw
	for i in 0 ..< len(data) {
		if _, serr := net.send_tcp(sock, data[i:i + 1]); serr != nil {
			testing.fail_now(t, "could not dribble the request")
		}
		time.sleep(time.Millisecond)
	}

	buf: [4096]byte
	total := 0
	for total < len(buf) {
		n, rerr := net.recv_tcp(sock, buf[total:])
		if rerr != nil || n <= 0 { break }
		total += n
	}
	dribbled := string(buf[:total])

	testing.expect(t, strings.contains(dribbled, "200 OK"),
		"a byte-at-a-time request must route the same as one sent whole")
	testing.expect(t, strings.has_suffix(dribbled, "marker-intact|marker-value-intact"),
		"the target and headers must survive buffer compaction")
}
