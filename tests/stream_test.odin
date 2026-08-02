package tests

import "core:strings"
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
