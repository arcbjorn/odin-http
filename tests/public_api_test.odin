package tests

import "core:strings"
import "core:testing"

import http "../http"

/*
Public API with no other coverage.

Everything here is exported and documented, but nothing in the library, the
examples or the rest of the suite calls it, so a regression would reach users
before it reached a test. That combination is what produced the h2 send-window
bug: an exported helper with no caller and no test was simply wrong.
*/

/*
`request_host` must answer for both protocols.

HTTP/1.1 carries the authority in a Host header; h2 carries it in the
`:authority` pseudo-header and the request builder copies it into `host` so
handlers do not have to branch on protocol version. That copy is the invariant
worth pinning — losing it would break every handler that does virtual hosting,
and only over h2.
*/
@(test)
test_request_host_reads_host_header :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /host", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, http.request_host(req))
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	resp, _ := http.test_request_raw(ts.endpoint,
		"GET /host HTTP/1.1\r\nHost: example.test:8080\r\nConnection: close\r\n\r\n")

	testing.expect(t, strings.has_suffix(resp, "example.test:8080"),
		"the Host header must reach the handler verbatim, port included")
}

// A request with no Host yields an empty string rather than misbehaving. The
// parser rejects a bare HTTP/1.1 request without Host, so this is reachable
// only through an explicitly constructed request.
@(test)
test_request_host_absent_is_empty :: proc(t: ^testing.T) {
	req: http.Request
	http.request_init(&req, context.temp_allocator)

	testing.expect_value(t, http.request_host(&req), "")
}

/*
`response_write_bytes` must be byte-transparent.

The string variant is used everywhere; the byte variant is not, and it is the
one a handler reaches for when the body is binary. NUL and high bytes are the
cases that would expose a length-versus-terminator mistake.
*/
@(test)
test_response_write_bytes_is_binary_safe :: proc(t: ^testing.T) {
	rec: http.Recorder
	if err := http.recorder_init(&rec, .Get, "/"); err != nil {
		testing.fail_now(t, "could not init recorder")
	}
	defer http.recorder_destroy(&rec)

	payload := []byte{0x00, 0xFF, 0x41, 0x00, 0x80, 0x0A}
	http.response_write_bytes(&rec.res, payload)

	body := strings.to_string(rec.res.body)
	testing.expect_value(t, len(body), len(payload))
	// Slices are not comparable in Odin; comparing as strings is byte-exact.
	testing.expect_value(t, body, string(payload))
}

// The two writers must compose: mixing them is the normal way to build a body
// with a binary section between text.
@(test)
test_response_write_bytes_appends :: proc(t: ^testing.T) {
	rec: http.Recorder
	if err := http.recorder_init(&rec, .Get, "/"); err != nil {
		testing.fail_now(t, "could not init recorder")
	}
	defer http.recorder_destroy(&rec)

	http.response_write_string(&rec.res, "head")
	http.response_write_bytes(&rec.res, []byte{0x00, 0x01})
	http.response_write_string(&rec.res, "tail")

	body := strings.to_string(rec.res.body)
	testing.expect_value(t, len(body), 10)
	testing.expect(t, strings.has_prefix(body, "head"), "")
	testing.expect(t, strings.has_suffix(body, "tail"), "")
}

/*
`headers_get_fold` looks up a header whose name is not already lowercase.

`headers_get` requires a lowercase key because the parser and writer know their
keys are literals; user code does not, and calling the wrong one silently
returns nothing rather than failing.
*/
@(test)
test_headers_get_fold_matches_any_case :: proc(t: ^testing.T) {
	h: http.Headers
	http.headers_init(&h, context.temp_allocator)
	http.headers_set(&h, "content-type", "text/plain")

	v, ok := http.headers_get_fold(h, "Content-Type")
	testing.expect(t, ok, "a mixed-case lookup must find the header")
	testing.expect_value(t, v, "text/plain")

	upper, upper_ok := http.headers_get_fold(h, "CONTENT-TYPE")
	testing.expect(t, upper_ok, "case must not matter at all")
	testing.expect_value(t, upper, "text/plain")

	// The exact-match entry point still requires lowercase, which is the reason
	// the folding variant exists.
	_, exact_ok := http.headers_get(h, "Content-Type")
	testing.expect(t, !exact_ok, "headers_get is deliberately case-sensitive")
}

// A name longer than the fold's stack buffer must still match, since that path
// allocates instead of folding in place.
@(test)
test_headers_get_fold_handles_long_names :: proc(t: ^testing.T) {
	h: http.Headers
	http.headers_init(&h, context.temp_allocator)

	// Longer than the 64-byte buffer `fold_key` folds into.
	name := strings.repeat("x", 100, context.temp_allocator)
	http.headers_set(&h, name, "value")

	upper := strings.to_upper(name, context.temp_allocator)
	v, ok := http.headers_get_fold(h, upper)
	testing.expect(t, ok, "a long mixed-case name must fold via the heap path")
	testing.expect_value(t, v, "value")
}

/*
The h2 half of the same invariant.

`:authority` must arrive as `host`, or a handler that does virtual hosting works
over HTTP/1.1 and silently sees nothing over h2.
*/
@(test)
test_request_host_reads_h2_authority :: proc(t: ^testing.T) {
	fields := []http.Header_Entry{
		{":method", "GET"},
		{":scheme", "https"},
		{":path", "/host"},
		{":authority", "example.test:8443"},
	}

	// `h2_request_from_fields` initialises the request itself.
	req: http.Request
	err := http.h2_request_from_fields(&req, fields, context.temp_allocator)
	testing.expect_value(t, err, http.H2_Request_Error.None)
	testing.expect_value(t, http.request_host(&req), "example.test:8443")
}

/*
Query and form accessors.

Go exposes these as `r.URL.Query()` and `r.PostFormValue`. Reading form input is
the most common thing a handler does after routing, and until these existed a
caller had to reach through `request_url` into `raw_query` and remember to check
the content type themselves — which is the kind of thing that gets skipped.
*/
@(test)
test_request_query_decodes_parameters :: proc(t: ^testing.T) {
	req: http.Request
	http.request_init(&req, context.temp_allocator)
	req.target = "/search?q=hello+world&page=2&flag"

	q := http.request_query(&req, context.temp_allocator)

	// '+' is a space in a query string, whatever the path rules say.
	testing.expect_value(t, q["q"], "hello world")
	testing.expect_value(t, q["page"], "2")

	// A key with no '=' is present with an empty value.
	bare, has := q["flag"]
	testing.expect(t, has, "a bare key must be present")
	testing.expect_value(t, bare, "")
}

// A target with no query yields an empty map rather than misparsing the path.
@(test)
test_request_query_without_query_is_empty :: proc(t: ^testing.T) {
	req: http.Request
	http.request_init(&req, context.temp_allocator)
	req.target = "/plain"

	q := http.request_query(&req, context.temp_allocator)
	testing.expect_value(t, len(q), 0)
}

/*
A urlencoded body is parsed; anything else is not.

The content-type check is the point: a JSON body is not key/value pairs, and
running the urlencoded parser over it produces plausible-looking garbage — a
key of `{"name"` — rather than nothing.
*/
@(test)
test_request_form_parses_urlencoded_body :: proc(t: ^testing.T) {
	req: http.Request
	http.request_init(&req, context.temp_allocator)
	http.headers_set(&req.headers, "content-type", "application/x-www-form-urlencoded")
	req.body = "name=ada+lovelace&id=42"

	f := http.request_form(&req, context.temp_allocator)
	testing.expect_value(t, f["name"], "ada lovelace")
	testing.expect_value(t, f["id"], "42")
}

// The type may carry parameters, which must not defeat the match.
@(test)
test_request_form_ignores_charset_parameter :: proc(t: ^testing.T) {
	req: http.Request
	http.request_init(&req, context.temp_allocator)
	http.headers_set(&req.headers, "content-type",
		"application/x-www-form-urlencoded; charset=utf-8")
	req.body = "a=1"

	f := http.request_form(&req, context.temp_allocator)
	testing.expect_value(t, f["a"], "1")
}

@(test)
test_request_form_refuses_other_content_types :: proc(t: ^testing.T) {
	// JSON must not be parsed as key/value pairs.
	{
		req: http.Request
		http.request_init(&req, context.temp_allocator)
		http.headers_set(&req.headers, "content-type", "application/json")
		req.body = `{"name":"ada"}`

		f := http.request_form(&req, context.temp_allocator)
		testing.expect_value(t, len(f), 0)
	}

	// multipart needs a boundary-aware reader; an empty map is honest, a partial
	// parse of the raw bytes is not.
	{
		req: http.Request
		http.request_init(&req, context.temp_allocator)
		http.headers_set(&req.headers, "content-type",
			"multipart/form-data; boundary=xyz")
		req.body = "--xyz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--xyz--"

		f := http.request_form(&req, context.temp_allocator)
		testing.expect_value(t, len(f), 0)
	}

	// A body with no content type at all is not guessed at.
	//
	// Deleting the `!has` early return does not fail this: an absent header
	// yields an empty string, which fails the type comparison just below it.
	// The guard is kept because it states the intent at the point the header is
	// read, rather than relying on a comparison against "" to mean "missing".
	{
		req: http.Request
		http.request_init(&req, context.temp_allocator)
		req.body = "a=1"

		f := http.request_form(&req, context.temp_allocator)
		testing.expect_value(t, len(f), 0)
	}
}
