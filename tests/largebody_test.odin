package tests

import "core:strings"
import "core:testing"

import http "../http"

/*
Requests whose body exceeds the connection read buffer.

`Request.target` and the header values are slices INTO the read buffer, not
copies. Anything that moves bytes within that buffer while a request is still
live invalidates them. A body larger than the buffer forces exactly that
situation, so these tests pin the aliasing rule that the rest of the design
depends on.
*/

@(private)
echo_target_router :: proc(r: ^http.Router) {
	http.router_init(r)

	// Echoes what the server actually parsed, so a corrupted target shows up as
	// a wrong body rather than only as a 404.
	http.router_handle_proc(r, "POST /upload", proc(req: ^http.Request, res: ^http.Response) {
		host, _ := http.headers_get(req.headers, "host")
		http.respond_plain(res, .OK, strings.concatenate(
			{req.target, "|", host, "|", itoa(len(req.body))},
			req.headers.allocator))
	})
}

@(private)
itoa :: proc(v: int) -> string {
	b := strings.builder_make(context.temp_allocator)
	strings.write_int(&b, v)
	return strings.to_string(b)
}

@(private)
with_upload_server :: proc(
	t: ^testing.T,
	body: proc(t: ^testing.T, ts: ^http.Test_Server),
	opts := http.DEFAULT_SERVER_OPTS,
) {
	r: http.Router
	echo_target_router(&r)
	defer http.router_destroy(&r)

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r), opts); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	body(t, &ts)
}

@(private)
make_request :: proc(size: int) -> string {
	payload := strings.repeat("A", size, context.temp_allocator)
	return strings.concatenate({
		"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: ",
		itoa(size),
		"\r\nConnection: close\r\n\r\n",
		payload,
	}, context.temp_allocator)
}

@(test)
test_body_smaller_than_buffer :: proc(t: ^testing.T) {
	with_upload_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint, make_request(1024))

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "")
		testing.expect(t, strings.has_suffix(resp, "/upload|example.com|1024"),
			"target, host and body length must all survive")
	})
}

@(test)
test_body_larger_than_buffer_preserves_request :: proc(t: ^testing.T) {
	// The default read buffer is 16 KiB, so this body forces the buffer to be
	// compacted mid-request. Before the fix, compaction moved bytes out from
	// under `req.target`, which then aliased body content: the server routed on
	// attacker-supplied bytes and answered 404.
	with_upload_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint, make_request(20_000))

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"),
			"a body larger than the read buffer must still route correctly")
		testing.expect(t, strings.has_suffix(resp, "/upload|example.com|20000"),
			"target and headers must not alias recycled buffer space")
	})
}

@(test)
test_body_spanning_many_buffers :: proc(t: ^testing.T) {
	// Several times the buffer, so compaction happens repeatedly.
	with_upload_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint, make_request(200_000))

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "")
		testing.expect(t, strings.has_suffix(resp, "/upload|example.com|200000"), "")
	})
}

@(test)
test_chunked_body_larger_than_buffer :: proc(t: ^testing.T) {
	// The chunked path consumes the buffer differently from Content-Length, so
	// it needs its own coverage of the same aliasing rule.
	with_upload_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		b := strings.builder_make(context.temp_allocator)
		strings.write_string(&b, "POST /upload HTTP/1.1\r\nHost: example.com\r\n")
		strings.write_string(&b, "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")

		// 40 chunks of 1000 bytes = 40000 bytes, well past the 16 KiB buffer.
		chunk := strings.repeat("B", 1000, context.temp_allocator)
		for _ in 0 ..< 40 {
			strings.write_string(&b, "3e8\r\n")
			strings.write_string(&b, chunk)
			strings.write_string(&b, "\r\n")
		}
		strings.write_string(&b, "0\r\n\r\n")

		resp, _ := http.test_request_raw(ts.endpoint, strings.to_string(b))

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "")
		testing.expect(t, strings.has_suffix(resp, "/upload|example.com|40000"),
			"chunked bodies must not corrupt the request either")
	})
}

@(test)
test_body_at_exact_buffer_boundary :: proc(t: ^testing.T) {
	// The header block plus body lands the compaction exactly on the boundary,
	// which is where off-by-one errors in the copy would show up.
	opts := http.DEFAULT_SERVER_OPTS
	opts.read_buffer_size = 4096

	with_upload_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		for size in ([]int{4095, 4096, 4097, 8192}) {
			resp, _ := http.test_request_raw(ts.endpoint, make_request(size))

			testing.expectf(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"),
				"body of %d bytes should be accepted", size)
			testing.expectf(t, strings.has_suffix(resp,
				strings.concatenate({"/upload|example.com|", itoa(size)}, context.temp_allocator)),
				"body of %d bytes must preserve the request", size)
		}
	}, opts)
}

@(test)
test_body_over_limit_is_rejected :: proc(t: ^testing.T) {
	opts := http.DEFAULT_SERVER_OPTS
	opts.limits.max_body = 1024

	with_upload_server(t, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint, make_request(4096))

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 413 Payload Too Large"),
			"a body past max_body must be refused, not buffered")
	}, opts)
}
