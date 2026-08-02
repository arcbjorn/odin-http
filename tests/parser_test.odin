package tests

import "core:mem/virtual"
import "core:testing"

import http "../http"

/*
Parser tests.

The parser is sans-I/O, so these drive it with plain byte slices. Every case
that parses a full message is also run through `feed_byte_at_a_time`, which
proves the state machine never depends on a boundary falling in a convenient
place. That property is the whole reason for the sans-I/O split, and it is
exactly what a socket-coupled parser cannot test.
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
