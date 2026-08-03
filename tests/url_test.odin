package tests

import "core:strings"
import "core:testing"

import http "../http"

/*
Request-target parsing and percent-decoding.

`percent_decode` runs on every request path the router handles, so it takes
attacker-controlled input on the very first thing a server does with a
connection. The tests below lean on malformed escapes rather than valid ones,
because the valid path was already exercised indirectly by routing tests while
the malformed path was not exercised at all.
*/

/*
A truncated escape must fail rather than overrun the output buffer.

This is a regression test for a remotely triggerable crash: the decoder sized
its buffer as `len(s) - count*2`, assuming every '%' began a complete
three-byte escape. "/ab%" has one '%' but still copies two literal bytes, so
the write ran past a two-byte buffer and killed the connection thread before
the truncated escape was ever detected. `GET /ab% HTTP/1.1` was enough.
*/
@(test)
test_percent_decode_rejects_truncated_escapes :: proc(t: ^testing.T) {
	// Every shape where a '%' is not followed by two hex digits. The literal
	// bytes before the '%' are what overran the old buffer, so the length of
	// the prefix is varied deliberately.
	for bad in ([]string{"%", "%4", "/a%", "/ab%", "/abc%", "/abcd%",
	                     "/a%2", "%%", "/a%%", "/%%%", "/a%zzb", "/a%2z"}) {
		_, ok := http.percent_decode(bad, context.temp_allocator)
		testing.expect(t, !ok, "a malformed escape must fail, not decode")
	}
}

// The valid forms must still decode, including an escape that ends the string —
// the boundary immediately next to the truncated case.
@(test)
test_percent_decode_accepts_valid_escapes :: proc(t: ^testing.T) {
	Case :: struct { input, want: string }
	cases := []Case{
		{"%41",         "A"},
		{"%41%42%43",   "ABC"},
		{"/a%20b",      "/a b"},
		{"/end%41",     "/endA"},   // escape flush against the end
		{"/a%2fb",      "/a/b"},
		{"/%2e%2e%2f",  "/../"},    // only dangerous once decoded
		{"/plain",      "/plain"},  // no escapes: returned as-is, no allocation
		{"",            ""},
	}

	for c in cases {
		got, ok := http.percent_decode(c.input, context.temp_allocator)
		testing.expect(t, ok, "a well-formed escape must decode")
		testing.expect_value(t, got, c.want)
	}
}

// '+' is a literal in a path. Treating it as a space is a form-encoding rule,
// and applying it here corrupts filenames that legitimately contain '+'.
@(test)
test_percent_decode_leaves_plus_alone :: proc(t: ^testing.T) {
	got, ok := http.percent_decode("/a+b", context.temp_allocator)
	testing.expect(t, ok, "")
	testing.expect_value(t, got, "/a+b")
}

/*
A malformed escape in the request target must not take the server down.

The unit test above pins the decoder; this pins the path that reaches it, since
the router decodes before matching. A 404 is the correct answer — the point is
that there is an answer at all.
*/
@(test)
test_server_survives_malformed_escape_in_path :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /hi", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "hi")
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	for target in ([]string{"/ab%", "/a%2", "/%", "/a%zz"}) {
		req := strings.concatenate(
			{"GET ", target, " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"},
			context.temp_allocator)
		resp, _ := http.test_request_raw(ts.endpoint, req)

		testing.expect(t, len(resp) > 0, "the server must answer a malformed target")
		testing.expect(t, strings.has_prefix(resp, "HTTP/1.1"), "the answer must be a response")
	}

	// The server is still serving afterwards.
	ok_resp, _ := http.test_request_raw(ts.endpoint,
		"GET /hi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	testing.expect(t, strings.contains(ok_resp, "200 OK"), "the server must still be healthy")
}

@(test)
test_url_parse_splits_components :: proc(t: ^testing.T) {
	u := http.url_parse("/path?a=1#frag", context.temp_allocator)
	testing.expect_value(t, u.path, "/path")
	testing.expect_value(t, u.raw_query, "a=1")
	testing.expect_value(t, u.fragment, "frag")

	// absolute-form: the scheme and authority are stripped, path onwards kept.
	abs := http.url_parse("http://example.test/p?q=1", context.temp_allocator)
	testing.expect_value(t, abs.path, "/p")
	testing.expect_value(t, abs.raw_query, "q=1")

	// An absolute-form target with no path at all still yields a rooted path.
	bare := http.url_parse("http://example.test", context.temp_allocator)
	testing.expect_value(t, bare.path, "/")

	// The path is decoded; the raw form is preserved alongside it.
	esc := http.url_parse("/a%20b", context.temp_allocator)
	testing.expect_value(t, esc.path, "/a b")
	testing.expect_value(t, esc.raw_path, "/a%20b")
}

/*
Form decoding differs from path decoding in exactly one rule: '+' is a space.

`query_parse` is the only caller, and a pair whose key or value is malformed is
skipped rather than aborting the whole query — one bad parameter must not
discard the rest.
*/
@(test)
test_query_parse_decodes_form_encoding :: proc(t: ^testing.T) {
	v := http.query_parse("a=hello+world&b=%41&c=1", context.temp_allocator)
	testing.expect_value(t, v["a"], "hello world")
	testing.expect_value(t, v["b"], "A")
	testing.expect_value(t, v["c"], "1")

	// A key with no '=' maps to an empty value.
	bare := http.query_parse("flag", context.temp_allocator)
	present, has := bare["flag"]
	testing.expect(t, has, "a bare key must be present")
	testing.expect_value(t, present, "")

	// A malformed escape drops that pair only.
	partial := http.query_parse("good=1&bad=%2", context.temp_allocator)
	testing.expect_value(t, partial["good"], "1")
	_, kept := partial["bad"]
	testing.expect(t, !kept, "a pair with a bad escape is skipped")

	// An empty query yields an empty map rather than a nil deref.
	empty := http.query_parse("", context.temp_allocator)
	testing.expect_value(t, len(empty), 0)
}

/*
`url_path_is_safe` judges a decoded path.

The escaped forms are the ones that matter: "%2e%2e%2f" is harmless as written
and only becomes traversal after decoding, which is why the check must run
afterwards.
*/
@(test)
test_url_path_is_safe_rejects_traversal_and_bad_bytes :: proc(t: ^testing.T) {
	testing.expect(t, http.url_path_is_safe("/a/b/c"), "")
	testing.expect(t, http.url_path_is_safe("/"), "")
	testing.expect(t, http.url_path_is_safe("/a/..b/c"), "'..b' is a normal segment")

	testing.expect(t, !http.url_path_is_safe("/a/../b"), "parent traversal")
	testing.expect(t, !http.url_path_is_safe("/.."), "trailing traversal")
	testing.expect(t, !http.url_path_is_safe("/a/b/.."), "")
	testing.expect(t, !http.url_path_is_safe("relative"), "a path must be rooted")
	testing.expect(t, !http.url_path_is_safe(""), "")
	testing.expect(t, !http.url_path_is_safe("/a\x00b"), "NUL truncates in C APIs")
	testing.expect(t, !http.url_path_is_safe("/a\\b"), "backslash separates on Windows")
}
