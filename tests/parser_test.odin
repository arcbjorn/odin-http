package tests

import "core:mem/virtual"
import "core:strings"
import "core:testing"

import http "../http"

/*
Parser tests.

The parser is sans-I/O, so these drive it with plain byte slices. Most cases
feed a whole message; a couple use `feed_byte_at_a_time`, and
`test_parse_is_independent_of_read_boundaries` takes a corpus and checks every
single split point against the whole-message result. That last one is what
actually proves the state machine never depends on a boundary falling in a
convenient place — the property the sans-I/O split exists for, and exactly what
a socket-coupled parser cannot test.
*/

@(private)
Harness :: struct {
	arena: virtual.Arena,
	req:   http.Request,
	p:     http.Parser,
}

@(private)
harness_init :: proc(h: ^Harness, limits := http.DEFAULT_LIMITS) {
	err := virtual.arena_init_growing(&h.arena)
	assert(err == nil)
	http.request_init(&h.req, virtual.arena_allocator(&h.arena))
	http.parser_init(&h.p, &h.req, limits)
}

@(private)
harness_destroy :: proc(h: ^Harness) {
	virtual.arena_destroy(&h.arena)
}

/*
Feeds the whole input, collecting the body, and returns the final event.

Mirrors what a driver does: keep feeding from where the parser stopped.
*/
@(private)
feed_all :: proc(h: ^Harness, input: string) -> (body: string, ev: http.Parse_Event) {
	data := transmute([]byte)input
	body_buf := make([dynamic]byte, virtual.arena_allocator(&h.arena))

	consumed := 0
	for {
		n, e := http.parser_feed(&h.p, data[consumed:])
		consumed += n

		// NOTE: `continue` inside a switch binds to the switch in Odin, so the
		// loop is driven by an explicit flag instead.
		keep_going := false
		#partial switch e {
		case .Body_Chunk:
			append(&body_buf, ..h.p.chunk)
			keep_going = true
		case .Headers_Done:
			keep_going = true
		}

		if !keep_going {
			return string(body_buf[:]), e
		}
	}
}

/*
Feeds one byte per call.

Any state the parser wrongly keeps in the caller's buffer, or any place it
assumes a token arrives whole, shows up here as a wrong result.
*/
@(private)
feed_byte_at_a_time :: proc(h: ^Harness, input: string) -> (body: string, ev: http.Parse_Event) {
	data := transmute([]byte)input
	body_buf := make([dynamic]byte, virtual.arena_allocator(&h.arena))

	// Grows the visible window one byte at a time. The parser may consume less
	// than the window, so `consumed` and the window end advance independently.
	consumed := 0
	for end := 1; end <= len(data); {
		n, e := http.parser_feed(&h.p, data[consumed:end])
		consumed += n

		#partial switch e {
		case .Error:
			return string(body_buf[:]), .Error
		case .Message_Done:
			return string(body_buf[:]), .Message_Done
		case .Body_Chunk:
			append(&body_buf, ..h.p.chunk)
			// A chunk may have used the whole window; reveal another byte only
			// once the parser stops making progress on what it already has.
			if n == 0 { end += 1 }
		case:
			// .Need_More or .Headers_Done: only reveal more input when the
			// parser could not advance, otherwise it may still have work to do.
			if n == 0 { end += 1 }
		}
	}

	// Input exhausted. Drain the events the parser can still emit with no more
	// bytes. Each state transition emits at most one event, so a small bound is
	// enough and guarantees a test can never hang.
	for _ in 0 ..< 8 {
		_, e := http.parser_feed(&h.p, data[len(data):])

		#partial switch e {
		case .Body_Chunk:
			append(&body_buf, ..h.p.chunk)
			continue
		case .Headers_Done:
			continue
		}
		return string(body_buf[:]), e
	}
	return string(body_buf[:]), .Need_More
}

@(test)
test_simple_get :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	_, ev := feed_all(&h, "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n")

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	testing.expect_value(t, h.req.method, http.Method.Get)
	testing.expect_value(t, h.req.target, "/hello")
	testing.expect_value(t, h.req.version.major, u8(1))
	testing.expect_value(t, h.req.version.minor, u8(1))

	host, ok := http.headers_get(h.req.headers, "host")
	testing.expect(t, ok, "Host header should be present")
	testing.expect_value(t, host, "example.com")
}

@(test)
test_header_name_is_case_insensitive :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	_, ev := feed_all(&h, "GET / HTTP/1.1\r\nHOST: example.com\r\nContent-Type: text/plain\r\n\r\n")

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)

	ct, ok := http.headers_get(h.req.headers, "content-type")
	testing.expect(t, ok, "mixed-case name should be found lowercased")
	testing.expect_value(t, ct, "text/plain")
}

@(test)
test_content_length_body :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	body, ev := feed_all(&h, "POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	testing.expect_value(t, body, "hello")
}

@(test)
test_content_length_body_split_across_reads :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	body, ev := feed_byte_at_a_time(&h, "POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world")

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	testing.expect_value(t, body, "hello world")
}

@(test)
test_chunked_body :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	input := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
	         "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	body, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	testing.expect_value(t, body, "hello world")
}

@(test)
test_chunked_body_byte_at_a_time :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	input := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
	         "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	body, ev := feed_byte_at_a_time(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	testing.expect_value(t, body, "hello world")
}

@(test)
test_chunk_extensions_are_ignored :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	input := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
	         "5;name=value\r\nhello\r\n0\r\n\r\n"
	body, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	testing.expect_value(t, body, "hello")
}

@(test)
test_chunked_trailers_are_not_merged :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	// A trailer must not be able to introduce a header the handler already
	// made decisions about.
	input := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
	         "5\r\nhello\r\n0\r\nX-Trailer: sneaky\r\n\r\n"
	body, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	testing.expect_value(t, body, "hello")
	testing.expect(t, !http.headers_has(h.req.headers, "x-trailer"),
		"trailer fields must not be merged into the header map")
}

// --- Request smuggling and framing ---

@(test)
test_rejects_te_and_content_length :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	// The classic CL.TE desync. Dropping one header silently is what lets two
	// hops disagree, so this must be a hard error.
	input := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
	_, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Transfer_Encoding_And_Content_Length)
}

@(test)
test_rejects_conflicting_content_lengths :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	input := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"
	_, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Conflicting_Content_Length)
}

@(test)
test_allows_identical_duplicate_content_length :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	// RFC 9110 8.6 permits repeated identical values.
	input := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"
	body, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	testing.expect_value(t, body, "hello")
}

@(test)
test_rejects_whitespace_before_colon :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	// "Content-Length : 5" is read as a framing header by lenient parsers and
	// as an unknown field by strict ones.
	input := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\nhello"
	_, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Whitespace_Before_Colon)
}

@(test)
test_rejects_obsolete_line_folding :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	input := "GET / HTTP/1.1\r\nHost: x\r\nX-Long: first\r\n  continued\r\n\r\n"
	_, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Obsolete_Line_Folding)
}

@(test)
test_rejects_non_decimal_content_length :: proc(t: ^testing.T) {
	// Each of these is accepted by at least one permissive integer parser and
	// rejected by others, which is what makes them desync primitives.
	// Surrounding OWS is NOT in this list: RFC 9110 5.5 requires field values to
	// be trimmed, so "5 " is legitimately the value 5 (see the test below).
	for value in ([]string{"+5", "-5", "0x5", "5.0", "0_5", "", "5a"}) {
		h: Harness
		harness_init(&h)
		defer harness_destroy(&h)

		input := concat("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: ", value, "\r\n\r\nhello")
		_, ev := feed_all(&h, input)

		testing.expectf(t, ev == .Error, "Content-Length %q must be rejected", value)
	}
}

@(test)
test_content_length_surrounding_ows_is_trimmed :: proc(t: ^testing.T) {
	// RFC 9110 5.5: OWS around a field value is not part of the value, so this
	// is the number 5 rather than a parse error.
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	body, ev := feed_all(&h, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length:  5 \r\n\r\nhello")

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	testing.expect_value(t, body, "hello")
}

@(test)
test_rejects_bare_cr_in_request_line :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	_, ev := feed_all(&h, "GET / HTTP/1.1\rHost: x\r\n\r\n")

	testing.expect_value(t, ev, http.Parse_Event.Error)
}

@(test)
test_rejects_unknown_transfer_encoding :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	// "chunked" must be the final coding; anything we cannot decode means we
	// cannot know where the message ends.
	input := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n"
	_, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Unsupported_Transfer_Encoding)
}

@(test)
test_rejects_missing_host_on_http11 :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	_, ev := feed_all(&h, "GET / HTTP/1.1\r\n\r\n")

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Missing_Host)
}

@(test)
test_rejects_duplicate_host :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	input := "GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n"
	_, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Multiple_Hosts)
}

@(test)
test_http10_without_host_is_allowed :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	// Host only became mandatory in 1.1.
	_, ev := feed_all(&h, "GET / HTTP/1.0\r\n\r\n")

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
}

@(test)
test_rejects_invalid_header_name :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	input := "GET / HTTP/1.1\r\nHost: x\r\nBad(Name): v\r\n\r\n"
	_, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Invalid_Header_Name)
}

@(test)
test_rejects_invalid_chunk_size :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	input := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\nhello\r\n0\r\n\r\n"
	_, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Invalid_Chunk_Size)
}

@(test)
test_rejects_oversized_request_line :: proc(t: ^testing.T) {
	h: Harness
	limits := http.DEFAULT_LIMITS
	limits.max_request_line = 32
	harness_init(&h, limits)
	defer harness_destroy(&h)

	input := "GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\nHost: x\r\n\r\n"
	_, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Request_Line_Too_Long)
}

@(test)
test_rejects_body_over_limit :: proc(t: ^testing.T) {
	h: Harness
	limits := http.DEFAULT_LIMITS
	limits.max_body = 10
	harness_init(&h, limits)
	defer harness_destroy(&h)

	input := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n"
	_, ev := feed_all(&h, input)

	testing.expect_value(t, ev, http.Parse_Event.Error)
	testing.expect_value(t, h.p.err, http.Parse_Error.Body_Too_Large)
}

@(test)
test_leading_crlf_is_skipped :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	// RFC 9112 2.2 robustness allowance for clients that append a stray CRLF.
	_, ev := feed_all(&h, "\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")

	testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	testing.expect_value(t, h.req.target, "/")
}

@(test)
test_truncated_request_needs_more :: proc(t: ^testing.T) {
	h: Harness
	harness_init(&h)
	defer harness_destroy(&h)

	_, ev := feed_all(&h, "GET / HTTP/1.1\r\nHost: exa")

	testing.expect_value(t, ev, http.Parse_Event.Need_More)
}

@(test)
test_keep_alive_defaults :: proc(t: ^testing.T) {
	{
		h: Harness
		harness_init(&h)
		defer harness_destroy(&h)
		feed_all(&h, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		testing.expect(t, http.parser_should_keep_alive(&h.p), "HTTP/1.1 defaults to keep-alive")
	}
	{
		h: Harness
		harness_init(&h)
		defer harness_destroy(&h)
		feed_all(&h, "GET / HTTP/1.0\r\n\r\n")
		testing.expect(t, !http.parser_should_keep_alive(&h.p), "HTTP/1.0 defaults to close")
	}
	{
		h: Harness
		harness_init(&h)
		defer harness_destroy(&h)
		feed_all(&h, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		testing.expect(t, !http.parser_should_keep_alive(&h.p), "explicit close must win")
	}
	{
		h: Harness
		harness_init(&h)
		defer harness_destroy(&h)
		feed_all(&h, "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
		testing.expect(t, http.parser_should_keep_alive(&h.p), "HTTP/1.0 opt-in keep-alive")
	}
}

@(test)
test_connection_token_list :: proc(t: ^testing.T) {
	// Connection is a list, so a naive equality check misses "close" here.
	testing.expect(t, http.token_list_contains("keep-alive, close", "close"), "")
	testing.expect(t, http.token_list_contains("Close", "close"), "matching is case-insensitive")
	testing.expect(t, !http.token_list_contains("keep-alive", "close"), "")
}

@(private)
concat :: proc(parts: ..string) -> string {
	total := 0
	for p in parts { total += len(p) }

	buf := make([]byte, total, context.temp_allocator)
	i := 0
	for p in parts {
		copy(buf[i:], p)
		i += len(p)
	}
	return string(buf)
}

/*
A failed parse never keeps the connection alive.

This is the branch that matters most and the one the other keep-alive cases do
not reach: once framing is ambiguous the byte stream cannot be resynchronized,
so the next request read from the same connection would start at an offset the
peer chose. Every `Connection: keep-alive` below is honoured on a well-formed
request and must be ignored here.
*/
@(test)
test_failed_parse_never_keeps_alive :: proc(t: ^testing.T) {
	// Each input is malformed in a different way, and each asks for keep-alive
	// so the header cannot be what produces the answer.
	cases := []string{
		// Conflicting framing: the CL.TE smuggling primitive.
		"POST / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n" +
			"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		// A header name that is not a token.
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\nBad Name: 1\r\n\r\n",
		// Content-Length that is not bare digits.
		"POST / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\nContent-Length: +5\r\n\r\nhello",
		// A bare CR inside a value.
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\nX-A: a\rb\r\n\r\n",
		// Missing Host on HTTP/1.1.
		"GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n",
	}

	for raw in cases {
		h: Harness
		harness_init(&h)
		defer harness_destroy(&h)

		feed_all(&h, raw)

		testing.expectf(t, !http.parser_should_keep_alive(&h.p),
			"a failed parse must close the connection: %q", raw[:min(len(raw), 40)])
	}
}

/*
Limits are enforced at their exact edges.

The existing limit tests overshoot: a 59-byte request line against a 32-byte
limit passes whether the limit is 32 or 58. What decides whether a conforming
client is disconnected is the edge, so each limit is measured at the last
accepted value and the first rejected one.

The two limits below are not the same shape, which is the kind of detail that
gets assumed wrong: `max_request_line` is exclusive (a line of exactly the limit
is refused) while `max_header_count` is inclusive (exactly the limit is served).
Both were measured rather than read off the source.
*/
@(test)
test_request_line_limit_boundary :: proc(t: ^testing.T) {
	LIMIT :: 40

	build :: proc(line_len: int) -> string {
		pad := strings.repeat("a", line_len - len("GET / HTTP/1.1"), context.temp_allocator)
		line := strings.concatenate({"GET /", pad, " HTTP/1.1"}, context.temp_allocator)
		return strings.concatenate({line, "\r\nHost: x\r\n\r\n"}, context.temp_allocator)
	}

	// One byte under the limit is served.
	{
		h: Harness
		limits := http.DEFAULT_LIMITS
		limits.max_request_line = LIMIT
		harness_init(&h, limits)
		defer harness_destroy(&h)

		_, ev := feed_all(&h, build(LIMIT - 1))
		testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	}

	// A line of exactly the limit is refused: the check is `i >= limit`.
	{
		h: Harness
		limits := http.DEFAULT_LIMITS
		limits.max_request_line = LIMIT
		harness_init(&h, limits)
		defer harness_destroy(&h)

		_, ev := feed_all(&h, build(LIMIT))
		testing.expect_value(t, ev, http.Parse_Event.Error)
		testing.expect_value(t, h.p.err, http.Parse_Error.Request_Line_Too_Long)
	}
}

@(test)
test_header_count_limit_boundary :: proc(t: ^testing.T) {
	LIMIT :: 4

	build :: proc(count: int) -> string {
		b := strings.builder_make(context.temp_allocator)
		strings.write_string(&b, "GET / HTTP/1.1\r\nHost: x\r\n")
		// Host is itself one of the counted fields.
		for i in 0 ..< count - 1 {
			strings.write_string(&b, "x-h")
			strings.write_int(&b, i)
			strings.write_string(&b, ": v\r\n")
		}
		strings.write_string(&b, "\r\n")
		return strings.to_string(b)
	}

	// Exactly the limit is served.
	{
		h: Harness
		limits := http.DEFAULT_LIMITS
		limits.max_header_count = LIMIT
		harness_init(&h, limits)
		defer harness_destroy(&h)

		_, ev := feed_all(&h, build(LIMIT))
		testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	}

	// One more is refused.
	{
		h: Harness
		limits := http.DEFAULT_LIMITS
		limits.max_header_count = LIMIT
		harness_init(&h, limits)
		defer harness_destroy(&h)

		_, ev := feed_all(&h, build(LIMIT + 1))
		testing.expect_value(t, ev, http.Parse_Event.Error)
		testing.expect_value(t, h.p.err, http.Parse_Error.Headers_Too_Long)
	}
}

/*
The total header-byte budget is enforced.

`max_headers` bounds the bytes spent on the header block as a whole, which is
what `max_header_count` alone does not: a hundred-field limit still permits
unbounded memory if each field may be arbitrarily long, and a per-line limit
still permits unbounded total across many short lines.

A whole-suite mutation sweep found this unprotected — the budget could be left
undecremented, disabling it entirely, with no test failing.

The third case below is why the parser refuses an already-negative budget rather
than relying on `scan_line`: that procedure treats a negative limit as "no
limit", so overspending the budget is precisely what would stop it being
enforced. The server never reached that state, because it feeds the parser its
whole accumulated buffer and `scan_line`'s own length check fires first — but
that is a property of one caller, not of the parser, and this is a sans-I/O
parser whose contract has to hold for any feeding pattern.
*/
@(test)
test_header_byte_budget_is_enforced :: proc(t: ^testing.T) {
	BUDGET :: 64

	// "Host: x\r\n" is 9 bytes and each added line is 12, so four extra lines
	// stay inside the budget and six exceed it.
	build :: proc(extra_lines: int) -> string {
		b := strings.builder_make(context.temp_allocator)
		strings.write_string(&b, "GET / HTTP/1.1\r\nHost: x\r\n")
		for _ in 0 ..< extra_lines {
			strings.write_string(&b, "x-hdr: val\r\n")
		}
		strings.write_string(&b, "\r\n")
		return strings.to_string(b)
	}

	// Inside the budget: served.
	{
		h: Harness
		limits := http.DEFAULT_LIMITS
		limits.max_headers = BUDGET
		harness_init(&h, limits)
		defer harness_destroy(&h)

		_, ev := feed_all(&h, build(4))
		testing.expect_value(t, ev, http.Parse_Event.Message_Done)
	}

	// Past the budget: refused, and for the right reason. Note the field count
	// is far below `max_header_count`, so only the byte budget can be what
	// rejects this.
	{
		h: Harness
		limits := http.DEFAULT_LIMITS
		limits.max_headers = BUDGET
		harness_init(&h, limits)
		defer harness_destroy(&h)

		_, ev := feed_all(&h, build(5))
		testing.expect_value(t, ev, http.Parse_Event.Error)
		testing.expect_value(t, h.p.err, http.Parse_Error.Headers_Too_Long)
	}

	// Many short fields must also be bounded: the budget is about total bytes,
	// not line length, so no single line here is anywhere near the limit.
	{
		h: Harness
		limits := http.DEFAULT_LIMITS
		limits.max_headers = BUDGET
		harness_init(&h, limits)
		defer harness_destroy(&h)

		b := strings.builder_make(context.temp_allocator)
		strings.write_string(&b, "GET / HTTP/1.1\r\nHost: x\r\n")
		for i in 0 ..< 40 {
			strings.write_string(&b, "a")
			strings.write_int(&b, i)
			strings.write_string(&b, ": v\r\n")
		}
		strings.write_string(&b, "\r\n")

		_, ev := feed_all(&h, strings.to_string(b))
		testing.expect_value(t, ev, http.Parse_Event.Error)
		testing.expect_value(t, h.p.err, http.Parse_Error.Headers_Too_Long)
	}
}

/*
The verdict must not depend on where the reads fall.

This is the property the sans-I/O split exists for, and the file comment above
claims every full-message case is checked against it — but only two were. A
parser that keeps state in the caller's buffer, or assumes a token arrives
whole, produces a different answer when a boundary lands mid-token, and a
socket-coupled parser cannot be tested for it at all.

Each message below is fed at every possible single split point and compared
against the whole-message result. A wrong answer at one offset is a real bug: on
a socket that offset is chosen by the network, not by the caller.
*/
@(private)
Split_Case :: struct {
	name: string,
	raw:  string,
}

/*
Feeds `raw` as two slices divided at `at`, returning the final verdict and body.

The parser may consume less than it is offered, so the window is advanced by
what it actually took rather than assuming a full read.
*/
@(private)
feed_split :: proc(h: ^Harness, raw: string, at: int) -> (body: string, ev: http.Parse_Event) {
	data := transmute([]byte)raw
	body_buf := make([dynamic]byte, virtual.arena_allocator(&h.arena))

	consumed := 0
	for bound in ([]int{at, len(data)}) {
		// Bounded rather than `for consumed < bound`: a parser that returns an
		// event without consuming would otherwise spin here forever, turning a
		// bug into a hung test instead of a failing one.
		for _ in 0 ..< len(data) + 8 {
			if consumed >= bound { break }

			n, e := http.parser_feed(&h.p, data[consumed:bound])
			consumed += n

			#partial switch e {
			case .Error:        return string(body_buf[:]), .Error
			case .Message_Done: return string(body_buf[:]), .Message_Done
			case .Body_Chunk:   append(&body_buf, ..h.p.chunk)
			}

			// No progress on the bytes revealed so far: wait for the next slice.
			if n == 0 { break }
		}
	}

	// Drain anything still emittable with no further input.
	for _ in 0 ..< 8 {
		_, e := http.parser_feed(&h.p, data[len(data):])
		#partial switch e {
		case .Body_Chunk:   append(&body_buf, ..h.p.chunk); continue
		case .Error:        return string(body_buf[:]), .Error
		case .Message_Done: return string(body_buf[:]), .Message_Done
		}
		break
	}
	return string(body_buf[:]), .Need_More
}

@(test)
test_parse_is_independent_of_read_boundaries :: proc(t: ^testing.T) {
	cases := []Split_Case{
		{"simple GET", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"},
		{"body", "POST /s HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world"},
		{"chunked", "POST /s HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
			"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"},
		{"chunk extension", "POST /s HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
			"3;a=b\r\nabc\r\n0\r\n\r\n"},
		{"trailers", "POST /s HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
			"3\r\nabc\r\n0\r\nx-trail: v\r\n\r\n"},
		{"many headers", "GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n"},
		{"LF terminators", "GET / HTTP/1.1\nHost: x\n\n"},
		{"absolute-form", "GET http://h/p HTTP/1.1\r\nHost: x\r\n\r\n"},
		// Malformed inputs must also be refused at every split, not only when
		// the offending bytes happen to arrive together.
		{"conflicting framing", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
		{"bad header name", "GET / HTTP/1.1\r\nHost: x\r\nBad Name: 1\r\n\r\n"},
	}

	for c in cases {
		// The whole-message result is the reference every split must match.
		want_body: string
		want_ev: http.Parse_Event
		{
			h: Harness
			harness_init(&h)
			defer harness_destroy(&h)
			b, e := feed_all(&h, c.raw)
			want_body, want_ev = strings.clone(b, context.temp_allocator), e
		}

		for at in 1 ..< len(c.raw) {
			h: Harness
			harness_init(&h)
			defer harness_destroy(&h)

			got_body, got_ev := feed_split(&h, c.raw, at)

			testing.expectf(t, got_ev == want_ev,
				"%s: split at %d gave %v, whole message gave %v", c.name, at, got_ev, want_ev)
			testing.expectf(t, got_body == want_body,
				"%s: split at %d gave body %q, whole message gave %q",
				c.name, at, got_body, want_body)
		}
	}
}
