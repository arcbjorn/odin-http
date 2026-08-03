package tests

import "core:testing"

import http "../http"

/*
Transport write loop and HTTP-version parsing.

Both are small, total functions that everything above them depends on, and a
whole-library mutation sweep found every guard in them unprotected: disabling
any single check failed no test. Neither had a dedicated test file, and the
paths that reach them indirectly only ever exercise the success branch.
*/

/*
A transport that reports a fixed per-call write size.

`chunk` bytes are accepted per `write`, so a value below the payload length
exercises the short-write loop that a real socket under load produces.
*/
@(private)
Chunked_Transport :: struct {
	using base: http.Transport,
	chunk:      int,
	written:    int,
	calls:      int,
	fail_after: int,
	// A transport that claims success while accepting nothing, which is what
	// makes the `n <= 0` guard load-bearing rather than defensive.
	report_zero: bool,
}

@(private)
chunked_transport_init :: proc(ct: ^Chunked_Transport) {
	ct.write = proc(t: ^http.Transport, buf: []byte) -> (n: int, ok: bool) {
		ct := cast(^Chunked_Transport)t
		ct.calls += 1

		// Reports a positive count alongside the failure, so the `!ok` branch is
		// what ends the loop. Returning `0, false` would be caught by the
		// `n <= 0` check first, leaving `!ok` untested.
		if ct.fail_after > 0 && ct.calls > ct.fail_after { return 1, false }
		if ct.report_zero { return 0, true }

		take := min(ct.chunk, len(buf))
		ct.written += take
		return take, true
	}
}

/*
A short write is resumed until the whole payload is sent.

Sockets accept partial writes under load, so a writer that treats one `write`
call as complete silently truncates responses.
*/
@(test)
test_transport_write_all_resumes_short_writes :: proc(t: ^testing.T) {
	ct: Chunked_Transport
	chunked_transport_init(&ct)
	ct.chunk = 3

	payload := transmute([]byte)string("0123456789")
	ok := http.transport_write_all(&ct.base, payload)

	testing.expect(t, ok, "a short write must be resumed, not abandoned")
	testing.expect_value(t, ct.written, len(payload))
	// 3+3+3+1: the final call carries the remainder.
	testing.expect_value(t, ct.calls, 4)
}

// A transport that fails mid-payload stops the loop rather than spinning.
@(test)
test_transport_write_all_stops_on_failure :: proc(t: ^testing.T) {
	ct: Chunked_Transport
	chunked_transport_init(&ct)
	ct.chunk = 2
	ct.fail_after = 2

	payload := transmute([]byte)string("0123456789")
	ok := http.transport_write_all(&ct.base, payload)

	testing.expect(t, !ok, "a failed write must be reported")
	testing.expect_value(t, ct.written, 4)
}

/*
A transport reporting `n = 0, ok = true` must terminate the loop.

This is the guard the sweep flagged: without the `n <= 0` check the loop makes
no progress and never exits, so a peer that stalls its receive window would hang
a connection thread forever rather than time out.
*/
@(test)
test_transport_write_all_refuses_zero_progress :: proc(t: ^testing.T) {
	ct: Chunked_Transport
	chunked_transport_init(&ct)
	ct.report_zero = true

	payload := transmute([]byte)string("0123456789")
	ok := http.transport_write_all(&ct.base, payload)

	testing.expect(t, !ok, "no progress must end the loop, not spin")
	testing.expect_value(t, ct.written, 0)
	// One call is enough to learn the transport is not accepting bytes.
	testing.expect_value(t, ct.calls, 1)
}

/*
HTTP-version parsing accepts exactly "HTTP/<digit>.<digit>".

The version sits in the request line, so a lenient parse is a framing question:
two hops that disagree about whether "HTTP/1x1" names a version disagree about
whether the message is well formed at all. Every rejected form below has its own
guard, and all four survived mutation because nothing called this directly.
*/
@(test)
test_version_parse_accepts_only_well_formed :: proc(t: ^testing.T) {
	v, ok := http.version_parse("HTTP/1.1")
	testing.expect(t, ok, "")
	testing.expect_value(t, v.major, u8(1))
	testing.expect_value(t, v.minor, u8(1))

	zero, zok := http.version_parse("HTTP/1.0")
	testing.expect(t, zok, "")
	testing.expect_value(t, zero.minor, u8(0))

	// An unrecognised minor is still well formed; RFC 9110 2.5 requires it to
	// be treated as compatible rather than refused here.
	nine, nok := http.version_parse("HTTP/1.9")
	testing.expect(t, nok, "")
	testing.expect_value(t, nine.minor, u8(9))
}

@(test)
test_version_parse_rejects_malformed :: proc(t: ^testing.T) {
	cases := []string{
		"",           // empty
		"HTTP/1.1 ",  // trailing space makes the length wrong
		"HTTP/1.1x",  // too long
		"HTTP/1.",    // too short
		"XXXX/1.1",   // wrong name
		"HTTP.1.1",   // missing solidus
		"HTTP/1x1",   // missing '.'
		"HTTP/a.1",   // non-digit major
		"HTTP/1.a",   // non-digit minor
		"HTTP/11.1",  // multi-digit fields are not this grammar
	}

	for c in cases {
		_, ok := http.version_parse(c)
		testing.expectf(t, !ok, "version %q must be rejected", c)
	}

	// The version token is case-sensitive (RFC 9112 2.3), so the lowercase form
	// is not an alternative spelling.
	_, lower := http.version_parse("http/1.1")
	testing.expect(t, !lower, "the version token is uppercase")
}
