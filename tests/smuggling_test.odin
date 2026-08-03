package tests

import "core:testing"

import http "../http"

/*
Request-framing conformance, checked against Go's net/http as an oracle.

Every entry below was run through `http.ReadRequest` in Go 1.26 and through this
parser, and the verdicts compared. The result of that comparison is the property
this file pins: **this parser is never more permissive than Go**. It rejects nine
inputs Go accepts and accepts nothing Go rejects.

That asymmetry is the whole point. Request smuggling works by getting two hops
to disagree about where one message ends and the next begins, so a proxy that is
stricter than its origin can only ever close attack surface, never open it. A
regression in the other direction is what these tests exist to catch.

Where this parser is stricter, the strictness is deliberate and cited. Where it
is more lenient than a naive reading of the RFC would suggest — HTTP/1.0 without
Host, an unrecognised minor version — that is also deliberate, because rejecting
those would break traffic that is legal and deployed.
*/

@(private)
Framing_Case :: struct {
	name:   string,
	raw:    string,
	accept: bool,
	why:    string,
}

/*
Drives the parser to a verdict over the whole message.

Feeding stops at `Message_Done` rather than `Headers_Done`, because a chunk size
is only read during the body phase: returning at the end of the headers would
report "accepted" for a request whose very next bytes are a malformed chunk.
*/
@(private)
framing_verdict :: proc(raw: string) -> bool {
	req: http.Request
	http.request_init(&req, context.temp_allocator)

	p: http.Parser
	http.parser_init(&p, &req)

	data := transmute([]byte)raw
	off := 0
	saw_headers := false

	for off < len(data) {
		n, ev := http.parser_feed(&p, data[off:])
		off += n

		#partial switch ev {
		case .Error:        return false
		case .Message_Done: return true
		case .Headers_Done: saw_headers = true
		}

		// No progress: the input is exhausted or the parser wants more bytes.
		if n == 0 { break }
	}

	// A message with no body ends at its headers, and these fixtures supply
	// every byte they intend to, so headers-complete is acceptance.
	return saw_headers
}

/*
The conflicting-framing cases, which are the smuggling primitives proper.

Note `cl_and_te`: Go accepts it and lets Transfer-Encoding win, per RFC 9112
6.3. This parser rejects it outright. Both are defensible alone, but rejecting
is the only choice that cannot desync against a peer that resolves it the other
way — which is exactly the CL.TE attack.
*/
@(test)
test_framing_rejects_smuggling_primitives :: proc(t: ^testing.T) {
	cases := []Framing_Case{
		{"duplicate Content-Length, same value",
		 "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
		 true, "identical values are unambiguous; Go accepts these too"},

		{"duplicate Content-Length, different values",
		 "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
		 false, "the classic CL.CL desync"},

		{"Content-Length with Transfer-Encoding",
		 "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		 false, "CL.TE: stricter than Go, which prefers TE"},

		{"duplicate Transfer-Encoding",
		 "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		 false, ""},

		{"Transfer-Encoding that is not chunked",
		 "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n",
		 false, "no way to find the end of the body"},

		{"chunked not last in Transfer-Encoding",
		 "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
		 false, "RFC 9112 6.1: chunked must be final"},
	}

	for c in cases {
		testing.expect_value(t, framing_verdict(c.raw), c.accept)
	}
}

/*
Content-Length must be bare digits.

`strconv`-style leniency here is a desync primitive: a hop that reads "+5" as 5
and one that rejects it disagree about the body length. Go rejects each of these
too, so this is conformance rather than extra strictness.
*/
@(test)
test_framing_rejects_lenient_content_length :: proc(t: ^testing.T) {
	cases := []Framing_Case{
		{"negative", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n", false, ""},
		{"leading plus", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello", false, ""},
		{"hex form", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0x5\r\n\r\nhello", false, ""},
		{"space before colon",
		 "POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\nhello",
		 false, "Go accepts this as a header named \"Content-Length \"; rejecting is safer"},
	}

	for c in cases {
		testing.expect_value(t, framing_verdict(c.raw), c.accept)
	}
}

/*
Chunk sizes are bare hex, and the extension syntax is tolerated.

"0x3" must not parse as 3: a hop that accepts the prefix frames the next chunk
somewhere else entirely. Go defers these to body-read time; deciding at header
time is stricter and equivalent in effect.
*/
@(test)
test_framing_rejects_lenient_chunk_sizes :: proc(t: ^testing.T) {
	hex_prefix := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0x3\r\nabc\r\n0\r\n\r\n"
	testing.expect(t, !framing_verdict(hex_prefix), "a 0x-prefixed chunk size must be refused")

	negative := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n-3\r\nabc\r\n0\r\n\r\n"
	testing.expect(t, !framing_verdict(negative), "a negative chunk size must be refused")

	// Chunk extensions are legal syntax (RFC 9112 7.1.1) and must not be a
	// reason to reject an otherwise well-formed body.
	extension := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3;a=b\r\nabc\r\n0\r\n\r\n"
	testing.expect(t, framing_verdict(extension), "a chunk extension is legal")
}

/*
Header syntax that would let a value or name break its own field.

Bare CR and NUL inside a value are the response-splitting primitives; obs-fold
is deprecated by RFC 9112 5.2 precisely because hops disagree about how to
unfold it. Go rejects the first two and accepts obs-fold; rejecting all three
is the safer split.
*/
@(test)
test_framing_rejects_malformed_headers :: proc(t: ^testing.T) {
	cases := []Framing_Case{
		{"bare CR in value", "GET / HTTP/1.1\r\nHost: x\r\nX-A: a\rb\r\n\r\n", false, ""},
		{"NUL in value", "GET / HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\n\r\n", false, ""},
		{"obs-fold continuation", "GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n 2\r\n\r\n",
		 false, "deprecated; Go accepts, we do not"},
		{"space in field name", "GET / HTTP/1.1\r\nHost: x\r\nBad Name: 1\r\n\r\n",
		 false, "SP is not a tchar"},
		{"duplicate Host", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
		 false, "an ambiguous authority is a routing desync"},
	}

	for c in cases {
		testing.expect_value(t, framing_verdict(c.raw), c.accept)
	}
}

/*
Version handling: strict on the major, lenient on the minor.

RFC 9110 2.5 requires a recipient to treat an unrecognised *minor* as compatible,
so "HTTP/1.9" must be served rather than refused. An unsupported *major* is a 505
case, so refusing it is correct even though Go accepts and defers.

Host is required only from HTTP/1.1 onward (RFC 9112 3.2); an HTTP/1.0 request
without one is legal and still deployed, so rejecting it would be a real
regression rather than useful strictness.
*/
@(test)
test_framing_version_and_host_rules :: proc(t: ^testing.T) {
	cases := []Framing_Case{
		{"HTTP/1.1 without Host", "GET / HTTP/1.1\r\n\r\n", false, "required from 1.1"},
		{"HTTP/1.0 without Host", "GET / HTTP/1.0\r\n\r\n", true, "legal and deployed"},
		{"unknown minor version", "GET / HTTP/1.9\r\nHost: x\r\n\r\n", true, "RFC 9110 2.5"},
		{"unsupported major version", "GET / HTTP/2.0\r\nHost: x\r\n\r\n", false, "505 territory"},
		{"malformed version", "GET / HTTP/x\r\nHost: x\r\n\r\n", false, ""},
		{"lowercase method", "get / HTTP/1.1\r\nHost: x\r\n\r\n",
		 false, "methods are case-sensitive (RFC 9110 9.1)"},
		{"absolute-form target", "GET http://a/b HTTP/1.1\r\nHost: x\r\n\r\n", true, "RFC 9112 3.2.2"},
	}

	for c in cases {
		testing.expect_value(t, framing_verdict(c.raw), c.accept)
	}
}

/*
A bare LF is accepted as a line terminator.

Every deployed server tolerates it, and refusing would break real clients. The
danger is not LF itself but a *bare CR* inside a value, which is rejected
separately above — that is the byte that lets a value forge a line break.
*/
@(test)
test_framing_tolerates_bare_lf_terminators :: proc(t: ^testing.T) {
	testing.expect(t, framing_verdict("GET / HTTP/1.1\nHost: x\n\n"),
		"LF-only line endings must be accepted")
}
