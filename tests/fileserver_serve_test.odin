package tests

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

import http "../http"

/*
End-to-end file serving: conditional requests, directory indexes, SPA fallback.

`file_path_resolve` and `parse_range_header` are pure and tested directly
elsewhere. What is exercised here is the part that only exists once a real file
is on disk and a real socket is involved: the validators the server computes
from `os.stat`, and the branches that turn one request path into a different
file. A revalidation bug is invisible to a unit test, because the ETag the
client echoes back is one the server produced from a real file's size and mtime.
*/

@(private)
Fixture_File :: struct {
	name:     string,
	contents: string,
}

/*
Writes files into a temporary root and serves it.

`configure` runs before the server starts, so a test can enable an index or a
SPA fallback without a second fixture. The caller's line number names the
directory: tests run in parallel, and a shared path would be removed out from
under a still-running test.
*/
@(private)
with_files :: proc(
	t: ^testing.T,
	files: []Fixture_File,
	configure: proc(fs: ^http.File_Server),
	body: proc(t: ^testing.T, ts: ^http.Test_Server),
	loc := #caller_location,
) {
	dir := fmt.tprintf("/tmp/odin_http_fs_test_%d", loc.line)
	os.remove_all(dir)
	os.make_directory(dir)
	defer os.remove_all(dir)

	for f in files {
		path := strings.concatenate({dir, "/", f.name}, context.temp_allocator)

		// A name like "sub/page.html" needs its parent to exist first.
		if slash := strings.last_index_byte(f.name, '/'); slash >= 0 {
			parent := strings.concatenate({dir, "/", f.name[:slash]}, context.temp_allocator)
			os.make_directory(parent)
		}

		if err := os.write_entire_file(path, transmute([]byte)f.contents); err != nil {
			testing.fail_now(t, "could not write fixture file")
		}
	}

	// Heap-allocated because the handler stores the pointer and outlives this
	// frame's locals only by way of the server thread.
	fs := new(http.File_Server, context.allocator)
	defer free(fs)
	fs^ = http.DEFAULT_FILE_SERVER
	fs.root = dir
	if configure != nil { configure(fs) }

	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)
	// Registered without a method so that every request reaches the file server.
	// Binding this to GET would make the router answer 405 first, and the file
	// server's own method check would never run.
	http.router_handle(&r, "/files/{path...}", http.file_server_handler(fs))

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	body(t, &ts)
}

// Pulls a header value out of a raw response, for echoing a validator back.
@(private)
header_value :: proc(resp: string, name: string) -> (string, bool) {
	key := strings.concatenate({"\r\n", name, ": "}, context.temp_allocator)
	idx := strings.index(resp, key)
	if idx < 0 { return "", false }

	start := idx + len(key)
	end := strings.index(resp[start:], "\r\n")
	if end < 0 { return "", false }
	return resp[start:start + end], true
}

/*
The revalidation round trip: fetch, echo the ETag back, expect 304.

RFC 9110 15.4.5 requires a 304 to carry no body, which matters here beyond
framing: a 304 that still streamed the file would waste exactly the bandwidth
the conditional request exists to save.
*/
@(test)
test_server_revalidates_with_etag :: proc(t: ^testing.T) {
	with_files(t, {{"data.txt", "0123456789"}}, nil, proc(t: ^testing.T, ts: ^http.Test_Server) {
		first, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		testing.expect(t, strings.has_prefix(first, "HTTP/1.1 200 OK"), "")

		etag, ok := header_value(first, "etag")
		testing.expect(t, ok, "a file response must carry an ETag")

		req := fmt.tprintf(
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nIf-None-Match: %s\r\nConnection: close\r\n\r\n",
			etag)
		second, _ := http.test_request_raw(ts.endpoint, req)

		testing.expect(t, strings.has_prefix(second, "HTTP/1.1 304 Not Modified"),
			"an unchanged file must revalidate")
		testing.expect(t, !strings.contains(second, "0123456789"), "304 must not carry the body")
		testing.expect(t, !strings.contains(second, "content-length:"), "304 must not be framed")
	})
}

// A validator from a different file must miss, or clients would be served stale
// content forever.
@(test)
test_server_sends_body_when_etag_differs :: proc(t: ^testing.T) {
	with_files(t, {{"data.txt", "0123456789"}}, nil, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\n" +
			`If-None-Match: W/"999-deadbeef"` + "\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 200 OK"), "a stale validator must miss")
		testing.expect(t, strings.has_suffix(resp, "0123456789"), "the body must be sent")
	})
}

/*
"*" matches any existing representation (RFC 9110 13.1.2), and a comma-separated
list matches on any member. The list form is what a client sends when it holds
several cached variants.
*/
@(test)
test_server_etag_star_and_list_match :: proc(t: ^testing.T) {
	with_files(t, {{"data.txt", "0123456789"}}, nil, proc(t: ^testing.T, ts: ^http.Test_Server) {
		star, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\nConnection: close\r\n\r\n")
		testing.expect(t, strings.has_prefix(star, "HTTP/1.1 304 Not Modified"), "* must match")

		first, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		etag, _ := header_value(first, "etag")

		req := fmt.tprintf(
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nIf-None-Match: %s, %s\r\nConnection: close\r\n\r\n",
			`W/"1-1"`, etag)
		listed, _ := http.test_request_raw(ts.endpoint, req)
		testing.expect(t, strings.has_prefix(listed, "HTTP/1.1 304 Not Modified"),
			"a match anywhere in the list must revalidate")
	})
}

// If-Modified-Since is the weaker validator, and the one a client falls back to
// when it has no ETag.
@(test)
test_server_revalidates_with_modified_since :: proc(t: ^testing.T) {
	with_files(t, {{"data.txt", "0123456789"}}, nil, proc(t: ^testing.T, ts: ^http.Test_Server) {
		first, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		modified, ok := header_value(first, "last-modified")
		testing.expect(t, ok, "a file response must carry Last-Modified")

		req := fmt.tprintf(
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: %s\r\nConnection: close\r\n\r\n",
			modified)
		second, _ := http.test_request_raw(ts.endpoint, req)

		testing.expect(t, strings.has_prefix(second, "HTTP/1.1 304 Not Modified"),
			"an unchanged timestamp must revalidate")
	})
}

/*
ETag beats If-Modified-Since when both are present (RFC 9110 13.1.3).

A stale timestamp alongside a matching ETag must still produce 304: honouring
the weaker validator here would re-send a file the client already holds.
*/
@(test)
test_server_prefers_etag_over_modified_since :: proc(t: ^testing.T) {
	with_files(t, {{"data.txt", "0123456789"}}, nil, proc(t: ^testing.T, ts: ^http.Test_Server) {
		first, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		etag, _ := header_value(first, "etag")

		req := fmt.tprintf(
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nIf-None-Match: %s\r\n" +
			"If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\nConnection: close\r\n\r\n",
			etag)
		resp, _ := http.test_request_raw(ts.endpoint, req)

		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 304 Not Modified"),
			"the stronger validator wins")
	})
}

// A directory request serves the configured index file.
@(test)
test_server_serves_directory_index :: proc(t: ^testing.T) {
	files := []Fixture_File{{"index.html", "<h1>root</h1>"}, {"sub/index.html", "<h1>sub</h1>"}}
	with_files(t, files, nil, proc(t: ^testing.T, ts: ^http.Test_Server) {
		root, _ := http.test_request_raw(ts.endpoint,
			"GET /files/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		testing.expect(t, strings.has_prefix(root, "HTTP/1.1 200 OK"), "")
		testing.expect(t, strings.has_suffix(root, "<h1>root</h1>"), "root index")
		testing.expect(t, strings.contains(root, "content-type: text/html"), "index MIME type")

		sub, _ := http.test_request_raw(ts.endpoint,
			"GET /files/sub HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		testing.expect(t, strings.has_suffix(sub, "<h1>sub</h1>"), "nested index")
	})
}

/*
With no index configured, a directory request is refused while files inside it
still serve.

There is no directory-listing code path at all, so this pins the configuration
boundary rather than the absence of a listing: `index = ""` must disable the
index lookup without disabling the file server.

Note that deleting the `len(fs.index) == 0` guard does not fail this test, and
no black-box test can make it fail: with the guard gone the empty index name
produces a path that `os.stat` rejects anyway. The guard is defence in depth
over an outcome that is already 404, kept because it states the intent
explicitly rather than relying on a stat failure.
*/
@(test)
test_server_directory_without_index_is_404 :: proc(t: ^testing.T) {
	files := []Fixture_File{{"sub/secret.txt", "shh"}, {"sub/index.html", "<h1>sub</h1>"}}
	configure := proc(fs: ^http.File_Server) { fs.index = "" }

	with_files(t, files, configure, proc(t: ^testing.T, ts: ^http.Test_Server) {
		// An index file exists, but no index is configured, so it must not be
		// served implicitly.
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /files/sub HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 404 Not Found"),
			"a directory must not resolve without a configured index")
		testing.expect(t, !strings.contains(resp, "<h1>sub</h1>"), "index must not be implicit")
		testing.expect(t, !strings.contains(resp, "secret.txt"), "filenames must not leak")

		// Naming the file directly still works.
		direct, _ := http.test_request_raw(ts.endpoint,
			"GET /files/sub/secret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		testing.expect(t, strings.has_suffix(direct, "shh"), "files below the directory still serve")
	})
}

/*
SPA fallback: an unmatched path serves the app shell so client-side routing can
take over, while a real file still wins.
*/
@(test)
test_server_spa_fallback :: proc(t: ^testing.T) {
	files := []Fixture_File{{"app.html", "<div id=app>"}, {"real.txt", "real"}}
	configure := proc(fs: ^http.File_Server) { fs.spa_fallback = "app.html" }

	with_files(t, files, configure, proc(t: ^testing.T, ts: ^http.Test_Server) {
		missing, _ := http.test_request_raw(ts.endpoint,
			"GET /files/some/client/route HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		testing.expect(t, strings.has_prefix(missing, "HTTP/1.1 200 OK"), "unmatched path serves shell")
		testing.expect(t, strings.has_suffix(missing, "<div id=app>"), "")

		existing, _ := http.test_request_raw(ts.endpoint,
			"GET /files/real.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		testing.expect(t, strings.has_suffix(existing, "real"), "a real file must not be shadowed")
	})
}

// The fallback must not defeat containment: a traversal attempt is refused
// before the fallback is ever considered.
@(test)
test_server_spa_fallback_does_not_serve_traversal :: proc(t: ^testing.T) {
	files := []Fixture_File{{"app.html", "<div id=app>"}}
	configure := proc(fs: ^http.File_Server) { fs.spa_fallback = "app.html" }

	with_files(t, files, configure, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /files/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, !strings.contains(resp, "root:"), "must never serve outside the root")
		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1 404 Not Found"),
			"traversal is refused, not redirected to the shell")
	})
}

/*
Every file response carries `nosniff`.

Without it a browser may ignore the declared Content-Type and sniff the body,
which is what turns a user-uploaded .txt into executable HTML.
*/
@(test)
test_server_sets_nosniff_on_files :: proc(t: ^testing.T) {
	with_files(t, {{"data.txt", "0123456789"}}, nil, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"GET /files/data.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.contains(resp, "x-content-type-options: nosniff\r\n"), "")
		testing.expect(t, strings.contains(resp, "cache-control: public, max-age=3600\r\n"), "")
	})
}

// Static content answers GET and HEAD only; anything else is 405 with Allow.
@(test)
test_server_rejects_non_get_methods :: proc(t: ^testing.T) {
	with_files(t, {{"data.txt", "0123456789"}}, nil, proc(t: ^testing.T, ts: ^http.Test_Server) {
		resp, _ := http.test_request_raw(ts.endpoint,
			"POST /files/data.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

		testing.expect(t, strings.contains(resp, "405 Method Not Allowed"), "")
		testing.expect(t, strings.contains(resp, "allow: GET, HEAD\r\n"),
			"405 must name the allowed methods")
	})
}
