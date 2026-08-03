package tests

import "core:mem/virtual"
import "core:strings"
import "core:testing"

import http "../http"

@(private)
render :: proc(res: ^http.Response, arena: ^virtual.Arena) -> string {
	out := strings.builder_make(virtual.arena_allocator(arena))
	http.response_write(res, &out, "Mon, 02 Jan 2006 15:04:05 GMT")
	return strings.to_string(out)
}

@(test)
test_response_basic_framing :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res: http.Response
	http.response_init(&res, virtual.arena_allocator(&arena))
	http.respond_plain(&res, .OK, "hello")

	out := render(&res, &arena)

	testing.expect(t, strings.has_prefix(out, "HTTP/1.1 200 OK\r\n"), "status line")
	testing.expect(t, strings.contains(out, "content-length: 5\r\n"), "length is computed from the body")
	testing.expect(t, strings.has_suffix(out, "\r\n\r\nhello"), "body follows the blank line")
}

@(test)
test_response_no_body_statuses_omit_length :: proc(t: ^testing.T) {
	// RFC 9110 6.4.1: 204 and 304 carry no body and no Content-Length. Sending
	// either desynchronizes a reused connection.
	for status in ([]http.Status{.No_Content, .Not_Modified}) {
		arena: virtual.Arena
		_ = virtual.arena_init_growing(&arena)
		defer virtual.arena_destroy(&arena)

		res: http.Response
		http.response_init(&res, virtual.arena_allocator(&arena))
		res.status = status
		http.response_write_string(&res, "should not be sent")

		out := render(&res, &arena)

		testing.expectf(t, !strings.contains(out, "content-length"),
			"%v must not carry Content-Length", status)
		testing.expectf(t, strings.has_suffix(out, "\r\n\r\n"),
			"%v must not carry a body", status)
	}
}

@(test)
test_response_head_omits_body_but_keeps_length :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res: http.Response
	http.response_init(&res, virtual.arena_allocator(&arena))
	http.respond_plain(&res, .OK, "hello")
	// What the server sets when the request was a HEAD.
	res._write_body = false

	out := render(&res, &arena)

	testing.expect(t, strings.contains(out, "content-length: 5\r\n"),
		"HEAD reports the length the GET would have")
	testing.expect(t, strings.has_suffix(out, "\r\n\r\n"), "HEAD sends no body")
}

@(test)
test_response_rejects_header_injection :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res: http.Response
	http.response_init(&res, virtual.arena_allocator(&arena))

	// The response-splitting primitive: a CRLF smuggled into a header value.
	ok := http.headers_set(&res.headers, "x-user", "value\r\nX-Injected: yes")
	testing.expect(t, !ok, "CRLF in a header value must be rejected")

	// A newline alone is equally dangerous.
	ok2 := http.headers_set(&res.headers, "x-user", "value\nX-Injected: yes")
	testing.expect(t, !ok2, "LF in a header value must be rejected")

	// An invalid field name must also be refused.
	ok3 := http.headers_set(&res.headers, "bad name", "v")
	testing.expect(t, !ok3, "space in a header name must be rejected")

	out := render(&res, &arena)
	testing.expect(t, !strings.contains(out, "X-Injected"), "nothing injected reaches the wire")
}

@(test)
test_response_close_header :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res: http.Response
	http.response_init(&res, virtual.arena_allocator(&arena))
	http.respond_plain(&res, .OK, "bye")
	http.response_set_close(&res)

	out := render(&res, &arena)
	testing.expect(t, strings.contains(out, "connection: close\r\n"), "")
}

@(test)
test_response_includes_date :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res: http.Response
	http.response_init(&res, virtual.arena_allocator(&arena))
	http.respond_plain(&res, .OK, "x")

	out := render(&res, &arena)
	// RFC 9110 6.6.1 requires an origin server to send Date.
	testing.expect(t, strings.contains(out, "date: Mon, 02 Jan 2006 15:04:05 GMT\r\n"), "")
}

@(test)
test_headers_are_case_insensitive_and_joined :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	h: http.Headers
	http.headers_init(&h, virtual.arena_allocator(&arena))

	http.headers_set(&h, "Content-Type", "text/plain")
	v, ok := http.headers_get(h, "content-type")
	testing.expect(t, ok, "lookup is case-insensitive via lowercased storage")
	testing.expect_value(t, v, "text/plain")

	// Repeated fields are joined per RFC 9110 5.3.
	http.headers_add(&h, "Accept", "text/html")
	http.headers_add(&h, "Accept", "application/json")
	a, _ := http.headers_get(h, "accept")
	testing.expect_value(t, a, "text/html, application/json")
}

@(test)
test_date_formatting :: proc(t: ^testing.T) {
	// IMF-fixdate is fixed-width, so the length is a meaningful invariant.
	buf: [http.DATE_LENGTH]byte
	// 2021-03-04 05:06:07 UTC, a Thursday.
	formatted := http.date_write(buf[:], {_nsec = 1614834367 * 1_000_000_000})

	testing.expect_value(t, len(formatted), http.DATE_LENGTH)
	testing.expect(t, strings.has_suffix(formatted, " GMT"), "must end in GMT")
	testing.expect(t, strings.has_prefix(formatted, "Thu, 04 Mar 2021"), "")
}

/*
Wire output, cross-checked against Go's response parser.

Every response shape below was served by a real server on a real socket and read
back with Go 1.26's `http.ReadResponse`, which parsed all of them cleanly. These
tests pin the byte-level decisions that made that work, since a round-trip test
against our own parser would agree with itself no matter what we emitted.
*/

// Duplicate headers are joined with ", " per RFC 9110 5.3. Go's `Header.Values`
// splits the joined field back into two, so both ends agree.
@(test)
test_response_joins_duplicate_headers :: proc(t: ^testing.T) {
	rec: http.Recorder
	if err := http.recorder_init(&rec, .Get, "/"); err != nil {
		testing.fail_now(t, "could not init recorder")
	}
	defer http.recorder_destroy(&rec)

	http.headers_add(&rec.res.headers, "x-multi", "a")
	http.headers_add(&rec.res.headers, "x-multi", "b")
	http.respond_plain(&rec.res, .OK, "many")

	raw := http.recorder_raw_response(&rec)
	testing.expect(t, strings.contains(raw, "x-multi: a, b\r\n"),
		"repeated fields are joined, not emitted twice")
}

/*
Set-Cookie is the exception and must never be joined.

An Expires attribute contains a comma, so a joined pair is ambiguous and clients
parse it differently — which is why RFC 6265 4.1 requires separate fields.
*/
@(test)
test_response_never_joins_set_cookie :: proc(t: ^testing.T) {
	rec: http.Recorder
	if err := http.recorder_init(&rec, .Get, "/"); err != nil {
		testing.fail_now(t, "could not init recorder")
	}
	defer http.recorder_destroy(&rec)

	http.response_set_cookie(&rec.res, http.cookie_session("sid", "abc"))
	http.response_set_cookie(&rec.res, http.Cookie{name = "t", value = "1", max_age = -1})
	http.respond_plain(&rec.res, .OK, "ck")

	raw := http.recorder_raw_response(&rec)

	count := strings.count(raw, "set-cookie: ")
	testing.expect_value(t, count, 2)
	testing.expect(t, !strings.contains(raw, "set-cookie: sid=abc, "),
		"two cookies must never share one field")
}

// obs-text (0x80-0xFF) is legal in a field value and must survive the writer
// unmodified; Go reads it back byte-identical.
@(test)
test_response_preserves_obs_text_in_values :: proc(t: ^testing.T) {
	rec: http.Recorder
	if err := http.recorder_init(&rec, .Get, "/"); err != nil {
		testing.fail_now(t, "could not init recorder")
	}
	defer http.recorder_destroy(&rec)

	// "café" in UTF-8: the two trailing bytes are obs-text.
	http.headers_set(&rec.res.headers, "x-obs", "caf\xc3\xa9")
	http.respond_plain(&rec.res, .OK, "obs")

	raw := http.recorder_raw_response(&rec)
	testing.expect(t, strings.contains(raw, "x-obs: caf\xc3\xa9\r\n"),
		"high bytes must pass through unchanged")
}

/*
A handler-supplied Content-Length is trusted rather than recomputed.

This is an escape hatch for handlers that know their length before writing, and
a wrong value desynchronizes the connection: a client reading the declared
number of bytes gets `unexpected EOF`. Go's net/http behaves identically — a
handler that sets Content-Length: 999 and writes five bytes produces exactly the
same broken response — so this is a documented sharp edge rather than a defect,
and the test exists to keep the behaviour deliberate.
*/
@(test)
test_response_trusts_handler_content_length :: proc(t: ^testing.T) {
	rec: http.Recorder
	if err := http.recorder_init(&rec, .Get, "/"); err != nil {
		testing.fail_now(t, "could not init recorder")
	}
	defer http.recorder_destroy(&rec)

	http.headers_set(&rec.res.headers, "content-length", "999")
	http.respond_plain(&rec.res, .OK, "short")

	raw := http.recorder_raw_response(&rec)
	testing.expect(t, strings.contains(raw, "content-length: 999\r\n"),
		"the handler's value wins, as in Go")
	testing.expect(t, !strings.contains(raw, "content-length: 5\r\n"),
		"the writer must not silently emit a second length")
}

/*
A bodyless status drops the body and any framing header set for it.

The handler here sets Content-Length and Transfer-Encoding explicitly, which is
the case that matters: without them the writer simply never adds framing to a
204, so the deletion in `finalize_response_headers` looks redundant. It is not.
A 204 carrying `content-length: 42` and no body desynchronizes the connection,
because the peer waits for 42 bytes that will never arrive.
*/
@(test)
test_response_drops_body_on_bodyless_status :: proc(t: ^testing.T) {
	rec: http.Recorder
	if err := http.recorder_init(&rec, .Get, "/"); err != nil {
		testing.fail_now(t, "could not init recorder")
	}
	defer http.recorder_destroy(&rec)

	rec.res.status = .No_Content
	http.headers_set(&rec.res.headers, "content-length", "42")
	http.headers_set(&rec.res.headers, "transfer-encoding", "chunked")
	http.response_write_string(&rec.res, "should not be sent")

	raw := http.recorder_raw_response(&rec)
	testing.expect(t, !strings.contains(raw, "should not be sent"), "204 carries no body")
	testing.expect(t, !strings.contains(raw, "content-length:"),
		"a handler-set length must be stripped, not emitted")
	testing.expect(t, !strings.contains(raw, "transfer-encoding:"),
		"likewise chunked framing")
}
