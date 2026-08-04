package tests

import "core:net"
import "core:strings"
import "core:time"
import "core:testing"

import http "../http"

/*
Chunked response streaming.

The framing is what matters here: a wrong chunk size, a missing terminator, or a
stray zero-length chunk mid-body all desynchronize the connection rather than
producing a visibly wrong body, so these assert on exact wire bytes.
*/

@(private)
Rows :: struct {
	values: []string,
}

@(private)
stream_rows :: proc(w: ^http.Stream_Writer, rows: ^Rows) {
	for v in rows.values {
		http.stream_write_string(w, v)
	}
}

@(private)
with_stream_server :: proc(
	t: ^testing.T,
	rows: ^Rows,
	body: proc(t: ^testing.T, ts: ^http.Test_Server),
) {
	h := http.handler_from_poly(rows, proc(rows: ^Rows, req: ^http.Request, res: ^http.Response) {
		http.headers_set(&res.headers, "content-type", "text/plain")
		http.response_set_stream(res, rows, stream_rows)
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, h); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	body(t, &ts)
}

@(test)
test_stream_uses_chunked_encoding :: proc(t: ^testing.T) {
	rows := Rows{values = {"hello", " ", "world"}}

	with_stream_server(t, &rows, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "")
		testing.expect(t, strings.contains(resp, "transfer-encoding: chunked\r\n"),
			"a body of unknown length must be chunked")
		// Content-Length and Transfer-Encoding together is the smuggling shape
		// the parser rejects on input; it must never be produced on output.
		testing.expect(t, !strings.contains(resp, "content-length:"),
			"chunked responses must not carry Content-Length")
	})
}

@(test)
test_stream_chunk_framing_is_exact :: proc(t: ^testing.T) {
	rows := Rows{values = {"hello", " ", "world"}}

	with_stream_server(t, &rows, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		idx := strings.index(resp, "\r\n\r\n")
		testing.expect(t, idx >= 0, "headers must terminate")
		body := resp[idx + 4:]

		// Sizes are hex, each chunk is size CRLF data CRLF, and the body ends
		// with the zero-length chunk plus an empty trailer section.
		testing.expect_value(t, body, "5\r\nhello\r\n1\r\n \r\n5\r\nworld\r\n0\r\n\r\n")
	})
}

@(test)
test_stream_chunk_size_is_hex :: proc(t: ^testing.T) {
	// 16 bytes must be "10", not "16": chunk sizes are hexadecimal, and a
	// decimal size makes the client read the wrong number of bytes.
	rows := Rows{values = {"0123456789abcdef"}}

	with_stream_server(t, &rows, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.contains(resp, "\r\n\r\n10\r\n0123456789abcdef\r\n"),
			"chunk size must be hexadecimal")
	})
}

@(test)
test_stream_empty_body_still_terminates :: proc(t: ^testing.T) {
	// A producer that writes nothing must still emit the terminator, or the
	// client waits forever for a body that never ends.
	rows := Rows{values = {}}

	with_stream_server(t, &rows, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_suffix(resp, "0\r\n\r\n"),
			"an empty stream must still send the last chunk")
	})
}

@(test)
test_stream_skips_zero_length_writes :: proc(t: ^testing.T) {
	// A zero-size chunk IS the terminator, so writing one mid-stream would end
	// the body early. Empty writes must be dropped instead.
	rows := Rows{values = {"a", "", "b"}}

	with_stream_server(t, &rows, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		idx := strings.index(resp, "\r\n\r\n")
		body := resp[idx + 4:]

		testing.expect_value(t, body, "1\r\na\r\n1\r\nb\r\n0\r\n\r\n")
	})
}

@(test)
test_stream_keep_alive_survives :: proc(t: ^testing.T) {
	rows := Rows{values = {"one", "two"}}

	with_stream_server(t, &rows, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// Correct chunked framing is exactly what lets the connection be
		// reused; a missing terminator would stall the second request.
		resp, _ := http.test_request_raw_keepalive(ts.endpoint, {
			"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
		})

		count := strings.count(resp, "HTTP/1.1 200 OK")
		testing.expectf(t, count == 2, "connection must survive a chunked body, got %d", count)
	})
}

@(test)
test_stream_head_sends_no_chunks :: proc(t: ^testing.T) {
	rows := Rows{values = {"hello"}}

	with_stream_server(t, &rows, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		// HEAD advertises the framing a GET would use but sends no body at all,
		// not even the terminating chunk.
		testing.expect(t, strings.contains(resp, "transfer-encoding: chunked\r\n"), "")
		testing.expect(t, strings.has_suffix(resp, "\r\n\r\n"), "")
		testing.expect(t, !strings.contains(resp, "5\r\nhello"), "HEAD must not send chunks")
	})
}

@(test)
test_stream_writer_latches_errors :: proc(t: ^testing.T) {
	// A writer with no transport reports failure and stays failed, so a
	// producer loop can run to the end and be checked once.
	w := http.Stream_Writer{
		_conn  = nil,
		_write = proc(c: rawptr, data: []byte) -> bool { return false },
	}

	testing.expect(t, !http.stream_write_string(&w, "x"), "first write fails")
	testing.expect(t, w.err, "error latches")
	testing.expect(t, !http.stream_write_string(&w, "y"), "subsequent writes stay failed")
}

/*
A failed write must latch, so a producer cannot keep streaming into a dead peer.

`stream_write` returns false and sets `err`; every later call short-circuits on
that flag. Without the latch a producer that ignores return values — which is
most of them, since the signature invites it — would keep formatting chunks and
handing them to a transport that is already gone, turning a disconnected client
into an unbounded amount of work.
*/
@(private)
Failing_Sink :: struct {
	writes:     int,
	fail_after: int,
}

@(private)
failing_writer :: proc(sink: ^Failing_Sink, chunked: bool) -> http.Stream_Writer {
	return http.Stream_Writer{
		_conn = sink,
		_write = proc(raw: rawptr, data: []byte) -> bool {
			s := cast(^Failing_Sink)raw
			s.writes += 1
			return s.writes <= s.fail_after
		},
		_chunked = chunked,
	}
}

@(test)
test_stream_write_latches_failure :: proc(t: ^testing.T) {
	sink := Failing_Sink{fail_after = 1}
	w := failing_writer(&sink, false)

	testing.expect(t, http.stream_write(&w, transmute([]byte)string("one")),
		"the first write succeeds")
	testing.expect(t, !w.err, "no error yet")

	testing.expect(t, !http.stream_write(&w, transmute([]byte)string("two")),
		"the second write fails")
	testing.expect(t, w.err, "the failure must be recorded")

	// Every later call is refused without touching the transport.
	before := sink.writes
	testing.expect(t, !http.stream_write(&w, transmute([]byte)string("three")), "")
	testing.expect(t, !http.stream_write(&w, transmute([]byte)string("four")), "")
	testing.expect_value(t, sink.writes, before)
}

/*
The same latch applies to the chunked path, which writes three times per call.

A chunk is a size header, the payload and a trailing CRLF. If the header goes
out and the payload does not, the peer is left mid-frame — so the failure has to
stop the sequence rather than press on to the next write.
*/
@(test)
test_stream_write_latches_mid_chunk :: proc(t: ^testing.T) {
	// Fails on the payload, after the size header has already gone out.
	sink := Failing_Sink{fail_after = 1}
	w := failing_writer(&sink, true)

	testing.expect(t, !http.stream_write(&w, transmute([]byte)string("body")),
		"a mid-chunk failure must be reported")
	testing.expect(t, w.err, "")

	// The trailing CRLF must not be attempted once the payload failed.
	testing.expect_value(t, sink.writes, 2)
}

/*
A truncated stream must not be terminated as though it were whole.

The last-chunk marker is what tells a client the body is complete. Writing it
after a producer failure would present a truncated response as a finished one —
the client has no other way to tell, since a chunked body has no declared
length.

The client here disconnects mid-body, which is what makes the writes fail. That
requires a real socket: a Recorder drives the producer directly and never
reaches `write_stream_body`, so it cannot observe the marker at all.
*/
@(test)
test_truncated_stream_is_not_terminated :: proc(t: ^testing.T) {
	Feed :: struct { chunks: int }
	feed := new(Feed, context.allocator)
	defer free(feed)
	feed.chunks = 2000

	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	// Large enough that the client can disconnect long before the producer is
	// finished, so the writes genuinely fail partway.
	http.router_handle(&r, "GET /firehose", http.handler_from_poly(feed,
		proc(f: ^Feed, req: ^http.Request, res: ^http.Response) {
			http.response_set_stream(res, f, proc(w: ^http.Stream_Writer, f: ^Feed) {
				for _ in 0 ..< f.chunks {
					http.stream_write_string(w, "0123456789012345678901234567890123456789")
				}
			})
		}))

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	// Read a little, then hang up while the producer is still writing.
	sock, derr := net.dial_tcp(ts.endpoint)
	testing.expect(t, derr == nil, "could not connect")

	req := "GET /firehose HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
	_, serr := net.send_tcp(sock, transmute([]byte)req)
	testing.expect(t, serr == nil, "could not send request")

	buf: [512]byte
	_, _ = net.recv_tcp(sock, buf[:])
	net.close(sock)

	/*
	What is observable from here is that the server survives the disconnect and
	keeps serving.

	The `w.err` check in `write_stream_body` cannot be killed by a black-box
	test, and deliberately so: with the peer already gone, suppressing the
	last-chunk marker and attempting to write it produce the same outcome —
	`write_all` fails and the connection closes either way. The check earns its
	place by making the intent explicit and logging the cause, not by changing
	what reaches the wire. The latch tests above are what pin the behaviour that
	is observable.
	*/
	time.sleep(50 * time.Millisecond)

	resp, _ := http.test_request_raw(ts.endpoint,
		"GET /firehose HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	testing.expect(t, strings.contains(resp, "200 OK"),
		"the server must still serve after a client hangs up mid-stream")
}
