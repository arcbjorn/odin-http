package tests

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

import http "../http"

/*
Range requests and file streaming.

`parse_range_header` is pure, so most cases are covered without touching the
filesystem. The end-to-end tests then confirm the parsed range actually reaches
the socket, since an off-by-one in Content-Range is invisible to a unit test of
the parser alone.
*/

@(test)
test_parse_range_explicit :: proc(t: ^testing.T) {
	spec, ok := http.parse_range_header("bytes=0-3", 10)
	testing.expect(t, ok, "")
	testing.expect(t, spec.satisfiable, "")
	testing.expect_value(t, spec.start, i64(0))
	// The end is inclusive per RFC 9110 14.1.2, so 0-3 is four bytes.
	testing.expect_value(t, spec.end, i64(3))
}

@(test)
test_parse_range_open_ended :: proc(t: ^testing.T) {
	spec, ok := http.parse_range_header("bytes=4-", 10)
	testing.expect(t, ok, "")
	testing.expect_value(t, spec.start, i64(4))
	testing.expect_value(t, spec.end, i64(9))
}

@(test)
test_parse_range_suffix :: proc(t: ^testing.T) {
	// "-3" means the LAST three bytes, not bytes 0..3.
	spec, ok := http.parse_range_header("bytes=-3", 10)
	testing.expect(t, ok, "")
	testing.expect_value(t, spec.start, i64(7))
	testing.expect_value(t, spec.end, i64(9))
}

@(test)
test_parse_range_suffix_larger_than_file :: proc(t: ^testing.T) {
	// Asking for more trailing bytes than exist yields the whole file.
	spec, ok := http.parse_range_header("bytes=-100", 10)
	testing.expect(t, ok, "")
	testing.expect_value(t, spec.start, i64(0))
	testing.expect_value(t, spec.end, i64(9))
}

@(test)
test_parse_range_clamps_past_eof :: proc(t: ^testing.T) {
	// A range running past EOF is clamped rather than rejected.
	spec, ok := http.parse_range_header("bytes=5-999", 10)
	testing.expect(t, ok, "")
	testing.expect(t, spec.satisfiable, "")
	testing.expect_value(t, spec.start, i64(5))
	testing.expect_value(t, spec.end, i64(9))
}

@(test)
test_parse_range_unsatisfiable :: proc(t: ^testing.T) {
	// A start at or past EOF cannot be served.
	spec, ok := http.parse_range_header("bytes=10-20", 10)
	testing.expect(t, ok, "header was understood")
	testing.expect(t, !spec.satisfiable, "but cannot be satisfied")

	spec2, ok2 := http.parse_range_header("bytes=100-", 10)
	testing.expect(t, ok2, "")
	testing.expect(t, !spec2.satisfiable, "")
}

@(test)
test_parse_range_ignored_forms :: proc(t: ^testing.T) {
	// Each of these means "serve the whole file", not "error".
	ignored := []string{
		"bytes=0-1,3-4",  // multi-range needs a multipart body
		"items=0-1",      // unknown unit
		"bytes=abc-def",  // not numbers
		"bytes=",         // no range
		"0-1",            // missing unit
		"bytes=-",        // neither side present
		"bytes=-0",       // a zero-length suffix is meaningless
	}

	for header in ignored {
		_, ok := http.parse_range_header(header, 10)
		testing.expectf(t, !ok, "range %q should be ignored, serving the whole file", header)
	}
}

// --- End to end ---

@(private)
Range_Fixture :: struct {
	dir:      string,
	contents: string,
}

/*
Writes a temporary file and serves the directory containing it.

Uses a real file because the streaming path is exactly what is under test;
faking the filesystem would skip the code that matters.
*/
@(private)
with_file_server :: proc(
	t: ^testing.T,
	contents: string,
	body: proc(t: ^testing.T, ts: ^http.Test_Server),
	loc := #caller_location,
) {
	// The test runner runs tests in parallel, so a shared fixture directory
	// would be removed out from under a still-running test. The caller's line
	// number makes each one unique without needing a counter.
	dir := fmt.tprintf("/tmp/odin_http_range_test_%d", loc.line)
	os.remove_all(dir)
	os.make_directory(dir)
	defer os.remove_all(dir)

	path := strings.concatenate({dir, "/data.txt"}, context.temp_allocator)
	if err := os.write_entire_file(path, transmute([]byte)contents); err != nil {
		testing.fail_now(t, "could not write fixture file")
	}

	fs := new(http.File_Server, context.allocator)
	defer free(fs)
	fs^ = http.DEFAULT_FILE_SERVER
	fs.root = dir

	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)
	http.router_handle(&r, "GET /files/{path...}", http.file_server_handler(fs))

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	body(t, &ts)
}

@(test)
test_server_serves_whole_file :: proc(t: ^testing.T) {
	with_file_server(t, "0123456789", proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "")
		testing.expect(t, strings.contains(resp, "content-length: 10\r\n"), "")
		// Streaming must produce exactly the same bytes as buffering would.
		testing.expect(t, strings.has_suffix(resp, "0123456789"), "body streams intact")
		testing.expect(t, strings.contains(resp, "accept-ranges: bytes\r\n"), "")
	})
}

@(test)
test_server_serves_byte_range :: proc(t: ^testing.T) {
	with_file_server(t, "0123456789", proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 206 Partial Content"), "")
		testing.expect(t, strings.contains(resp, "content-range: bytes 2-5/10\r\n"), "")
		testing.expect(t, strings.contains(resp, "content-length: 4\r\n"), "inclusive end")
		testing.expect(t, strings.has_suffix(resp, "2345"), "exact bytes")
	})
}

@(test)
test_server_serves_suffix_range :: proc(t: ^testing.T) {
	with_file_server(t, "0123456789", proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=-3\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 206 Partial Content"), "")
		testing.expect(t, strings.contains(resp, "content-range: bytes 7-9/10\r\n"), "")
		testing.expect(t, strings.has_suffix(resp, "789"), "last three bytes")
	})
}

@(test)
test_server_unsatisfiable_range :: proc(t: ^testing.T) {
	with_file_server(t, "0123456789", proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=50-60\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 416 Range Not Satisfiable"), "")
		// RFC 9110 14.4: report the real length so the client can retry.
		testing.expect(t, strings.contains(resp, "content-range: bytes */10\r\n"), "")
	})
}

@(test)
test_server_if_range_with_stale_validator :: proc(t: ^testing.T) {
	with_file_server(t, "0123456789", proc(t: ^testing.T, ts: ^http.Test_Server) {
		// The file changed since the client's copy, so serving a range of the
		// new content against their stale prefix would corrupt the result.
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\n" +
			"Range: bytes=0-1\r\nIf-Range: W/\"999-1\"\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"),
			"a stale If-Range must fall back to the whole file")
		testing.expect(t, strings.has_suffix(resp, "0123456789"), "")
	})
}

@(test)
test_server_head_on_file_sends_no_body :: proc(t: ^testing.T) {
	with_file_server(t, "0123456789", proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"HEAD /files/data.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		// The length a GET would report, without streaming the file.
		testing.expect(t, strings.contains(resp, "content-length: 10\r\n"), "")
		testing.expect(t, strings.has_suffix(resp, "\r\n\r\n"), "no body for HEAD")
	})
}

@(test)
test_server_keep_alive_after_streamed_body :: proc(t: ^testing.T) {
	with_file_server(t, "0123456789", proc(t: ^testing.T, ts: ^http.Test_Server) {
		// Streaming writes the body outside the header builder, so a framing
		// mistake there would desynchronize the next request on the connection.
		resp, _ := http.test_request_raw_keepalive(ts.endpoint, {
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\n\r\n",
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
		})

		count := strings.count(resp, "HTTP/1.1 200 OK")
		testing.expectf(t, count == 2, "connection must survive a streamed body, got %d", count)
	})
}
