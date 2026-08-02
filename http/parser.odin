package http

/*
A sans-I/O incremental HTTP/1.1 request parser.

This parser never touches a socket. It is fed bytes and reports how many it
consumed, which makes it usable from a blocking driver, an event loop, or a
test that hands it one byte at a time. All three exercise identical code.

Ownership: the parser borrows the caller's buffer and returns strings that
point into it. Nothing is copied and nothing is allocated. The caller must not
reuse or free the buffer while the resulting `Request` is still live. In the
server this is upheld by the connection arena outliving the request.

Usage:

	p: Parser
	parser_init(&p, &req, limits)
	for {
		n, ev := parser_feed(&p, buf[consumed:])
		consumed += n
		switch ev {
		case .Need_More:      // read more into buf, call again
		case .Headers_Done:   // req.method/target/headers are populated
		case .Body_Chunk:     // p.chunk holds the latest body bytes
		case .Message_Done:   // request fully parsed
		case .Error:          // p.err says why; the connection must be closed
		}
	}
*/

Parse_Error :: enum u8 {
	None,
	Request_Line_Too_Long,
	Headers_Too_Long,
	Invalid_Method,
	Invalid_Target,
	Invalid_Version,
	Invalid_Header,
	Invalid_Header_Name,
	Invalid_Header_Value,
	Obsolete_Line_Folding,
	Whitespace_Before_Colon,
	Duplicate_Content_Length,
	Conflicting_Content_Length,
	Invalid_Content_Length,
	Transfer_Encoding_And_Content_Length,
	Unsupported_Transfer_Encoding,
	Chunked_Not_Final,
	Invalid_Chunk_Size,
	Invalid_Chunk_Terminator,
	Body_Too_Large,
	Missing_Host,
	Multiple_Hosts,
	Bare_CR,
	Unsupported_Version,
}

Parse_Event :: enum u8 {
	Need_More,
	Headers_Done,
	Body_Chunk,
	Message_Done,
	Error,
}

Parse_State :: enum u8 {
	Request_Line,
	Header_Line,
	Body_Length,
	Chunk_Size,
	Chunk_Data,
	Chunk_Data_CRLF,
	Trailer_Line,
	Done,
	Failed,
}

Limits :: struct {
	// Maximum bytes in the request line. RFC 9112 3 recommends supporting at
	// least 8000; beyond that a peer is either broken or probing.
	max_request_line: int,
	// Maximum total bytes across all header lines.
	max_headers:      int,
	// Maximum number of header fields, bounding hash-collision and memory work.
	max_header_count: int,
	// Maximum decoded body size. -1 disables the check.
	max_body:         int,
}

DEFAULT_LIMITS :: Limits {
	max_request_line = 8000,
	max_headers      = 16 * 1024,
	max_header_count = 100,
	max_body         = 8 * 1024 * 1024,
}

Body_Framing :: enum u8 {
	None,
	Content_Length,
	Chunked,
}

Parser :: struct {
	req:            ^Request,
	limits:         Limits,
	state:          Parse_State,
	err:            Parse_Error,

	// Body bytes produced by the most recent .Body_Chunk event. Borrowed from
	// the input buffer, valid until the caller reuses that memory.
	chunk:          []byte,

	framing:        Body_Framing,
	// Remaining bytes in the current body or chunk.
	remaining:      int,
	body_seen:      int,

	header_budget:  int,
	header_count:   int,
	seen_host:      bool,
	// Set when the terminating 0-length chunk has been read, so trailers are
	// parsed instead of another chunk size.
	in_trailers:    bool,
}

parser_init :: proc(p: ^Parser, req: ^Request, limits := DEFAULT_LIMITS) {
	p^ = Parser {
		req           = req,
		limits        = limits,
		state         = .Request_Line,
		header_budget = limits.max_headers,
	}
}

/*
Consumes as much of `data` as possible.

Returns the number of bytes consumed and the event that stopped consumption.
A `.Need_More` result means every byte was consumed and more input is required.
Any other event may leave bytes unconsumed, and the caller must resume from
there. On `.Error`, `p.err` holds the reason and the parser is latched: further
calls keep returning `.Error`.
*/
parser_feed :: proc(p: ^Parser, data: []byte) -> (consumed: int, ev: Parse_Event) {
	for {
		switch p.state {
		case .Request_Line:
			line, n, found := scan_line(data[consumed:], p.limits.max_request_line)
			if !found {
				if n < 0 { return consumed, fail(p, .Request_Line_Too_Long) }
				return consumed, .Need_More
			}
			consumed += n

			// RFC 9112 2.2: a server SHOULD ignore at least one empty line
			// received before the request line, for robustness against clients
			// that append a stray CRLF to the previous request.
			if len(line) == 0 { continue }

			if !parse_request_line(p, line) { return consumed, .Error }
			p.state = .Header_Line

		case .Header_Line:
			line, n, found := scan_line(data[consumed:], p.header_budget)
			if !found {
				if n < 0 { return consumed, fail(p, .Headers_Too_Long) }
				return consumed, .Need_More
			}
			consumed += n
			p.header_budget -= n

			if len(line) == 0 {
				if !finalize_headers(p) { return consumed, .Error }
				// Report headers now; the caller dispatches to a handler before
				// any body arrives, matching how handlers are actually written.
				return consumed, .Headers_Done
			}

			if !parse_header_line(p, line) { return consumed, .Error }

		case .Body_Length:
			if p.remaining == 0 {
				p.state = .Done
				return consumed, .Message_Done
			}
			avail := len(data) - consumed
			if avail == 0 { return consumed, .Need_More }

			n := min(avail, p.remaining)
			p.chunk = data[consumed:][:n]
			consumed += n
			p.remaining -= n
			p.body_seen += n
			return consumed, .Body_Chunk

		case .Chunk_Size:
			line, n, found := scan_line(data[consumed:], MAX_CHUNK_SIZE_LINE)
			if !found {
				if n < 0 { return consumed, fail(p, .Invalid_Chunk_Size) }
				return consumed, .Need_More
			}
			consumed += n

			// chunk-ext is permitted but carries no meaning for us; drop it.
			size_str := line
			if semi := index_byte(size_str, ';'); semi >= 0 {
				size_str = size_str[:semi]
			}
			size_str = trim_ows(size_str)

			size, ok := parse_hex(size_str)
			if !ok { return consumed, fail(p, .Invalid_Chunk_Size) }

			if size == 0 {
				p.in_trailers = true
				p.state = .Trailer_Line
				continue
			}

			if p.limits.max_body >= 0 && p.body_seen + size > p.limits.max_body {
				return consumed, fail(p, .Body_Too_Large)
			}

			p.remaining = size
			p.state = .Chunk_Data

		case .Chunk_Data:
			if p.remaining == 0 {
				p.state = .Chunk_Data_CRLF
				continue
			}
			avail := len(data) - consumed
			if avail == 0 { return consumed, .Need_More }

			n := min(avail, p.remaining)
			p.chunk = data[consumed:][:n]
			consumed += n
			p.remaining -= n
			p.body_seen += n
			return consumed, .Body_Chunk

		case .Chunk_Data_CRLF:
			// Each chunk's data is followed by a bare CRLF. Anything else means
			// the sender's framing disagrees with ours, so refuse to continue.
			line, n, found := scan_line(data[consumed:], 2)
			if !found {
				if n < 0 { return consumed, fail(p, .Invalid_Chunk_Terminator) }
				return consumed, .Need_More
			}
			if len(line) != 0 { return consumed, fail(p, .Invalid_Chunk_Terminator) }
			consumed += n
			p.state = .Chunk_Size

		case .Trailer_Line:
			line, n, found := scan_line(data[consumed:], p.header_budget)
			if !found {
				if n < 0 { return consumed, fail(p, .Headers_Too_Long) }
				return consumed, .Need_More
			}
			consumed += n
			p.header_budget -= n

			if len(line) == 0 {
				p.state = .Done
				return consumed, .Message_Done
			}

			// Trailers are parsed for well-formedness but discarded. Merging
			// them into the header map would let a trailer retroactively change
			// a framing header the handler has already acted on.
			name, _, ok := split_header_line(line)
			if !ok || !is_token(name) { return consumed, fail(p, .Invalid_Header) }

		case .Done:
			return consumed, .Message_Done

		case .Failed:
			return consumed, .Error
		}
	}
}

// Bounds the chunk-size line so a peer cannot stream unbounded chunk extensions.
@(private)
MAX_CHUNK_SIZE_LINE :: 1024

@(private)
fail :: proc(p: ^Parser, err: Parse_Error) -> Parse_Event {
	p.state = .Failed
	p.err   = err
	return .Error
}

/*
Finds the next line terminator.

Returns the line without its terminator, the number of bytes to consume
(including the terminator), and whether a full line was present. A `limit`
overrun is signalled with n < 0 so the caller can distinguish "too long" from
"incomplete".

A bare CR (not followed by LF) is rejected. Accepting it is a classic desync:
implementations that treat lone CR as a terminator will frame the message
differently from those that require CRLF.
*/
@(private)
scan_line :: proc(data: []byte, limit: int) -> (line: string, n: int, found: bool) {
	for i in 0..<len(data) {
		switch data[i] {
		case '\n':
			// A lone LF is tolerated as a terminator, matching every deployed
			// server, but the preceding byte must not be a stray CR.
			end := i
			if i > 0 && data[i - 1] == '\r' {
				end = i - 1
			}
			return string(data[:end]), i + 1, true

		case '\r':
			// Defer judgement: the LF may simply not have arrived yet.
			if i + 1 < len(data) && data[i + 1] != '\n' {
				return "", -1, false
			}
		}

		if limit >= 0 && i >= limit {
			return "", -1, false
		}
	}

	if limit >= 0 && len(data) > limit {
		return "", -1, false
	}
	return "", 0, false
}

@(private)
index_byte :: proc(s: string, c: byte) -> int {
	for i in 0..<len(s) {
		if s[i] == c { return i }
	}
	return -1
}

/*
Parses "method SP request-target SP HTTP-version".

Exactly one space between each element: RFC 9112 3 forbids the tolerant
"skip runs of whitespace" behaviour that older servers had, because a target
containing a space would otherwise be split differently by different hops.
*/
@(private)
parse_request_line :: proc(p: ^Parser, line: string) -> bool {
	sp1 := index_byte(line, ' ')
	if sp1 < 0 { fail(p, .Invalid_Method); return false }

	method, mok := method_parse(line[:sp1])
	if !mok { fail(p, .Invalid_Method); return false }

	rest := line[sp1 + 1:]
	sp2 := index_byte(rest, ' ')
	if sp2 < 0 { fail(p, .Invalid_Target); return false }

	target := rest[:sp2]
	if len(target) == 0 { fail(p, .Invalid_Target); return false }
	for i in 0..<len(target) {
		// The target must be printable ASCII with no whitespace or controls.
		if target[i] <= 0x20 || target[i] == 0x7F {
			fail(p, .Invalid_Target)
			return false
		}
	}

	version, vok := version_parse(rest[sp2 + 1:])
	if !vok { fail(p, .Invalid_Version); return false }

	// HTTP/1.0 is accepted and handled via connection defaults; 0.9 and 2+ are
	// different protocols and must not be parsed as 1.x.
	if version.major != 1 { fail(p, .Unsupported_Version); return false }

	p.req.method  = method
	p.req.target  = target
	p.req.version = version
	return true
}

/*
Splits "name: value", rejecting the forms that enable smuggling.

RFC 9112 5.1 is explicit that no whitespace is allowed between the field name
and the colon, and that a server MUST reject such a message rather than
normalize it. `Content-Length : 5` being read as a header by one hop and as
garbage by another is precisely the desync being prevented.
*/
@(private)
split_header_line :: proc(line: string) -> (name: string, value: string, ok: bool) {
	colon := index_byte(line, ':')
	if colon <= 0 { return "", "", false }

	name = line[:colon]
	if is_ows(name[len(name) - 1]) { return "", "", false }

	return name, trim_ows(line[colon + 1:]), true
}

@(private)
parse_header_line :: proc(p: ^Parser, line: string) -> bool {
	// Obsolete line folding: a continuation line starting with SP/HTAB. RFC 9112
	// 5.2 requires servers to reject it outright.
	if is_ows(line[0]) { fail(p, .Obsolete_Line_Folding); return false }

	name, value, ok := split_header_line(line)
	if !ok { fail(p, .Whitespace_Before_Colon); return false }
	if !is_token(name) { fail(p, .Invalid_Header_Name); return false }
	if !is_field_value(value) { fail(p, .Invalid_Header_Value); return false }

	p.header_count += 1
	if p.header_count > p.limits.max_header_count {
		fail(p, .Headers_Too_Long)
		return false
	}

	// Framing headers are handled here rather than in the map, because their
	// duplicate rules are stricter than for ordinary fields.
	if equal_fold(name, "content-length") {
		n, nok := parse_decimal(value)
		if !nok { fail(p, .Invalid_Content_Length); return false }

		if existing, has := headers_get(p.req.headers, "content-length"); has {
			// RFC 9110 8.6: multiple Content-Length values are acceptable only
			// if identical; differing values are a smuggling attempt.
			prev, _ := parse_decimal(existing)
			if prev != n { fail(p, .Conflicting_Content_Length); return false }
			return true
		}

		if p.limits.max_body >= 0 && n > p.limits.max_body {
			fail(p, .Body_Too_Large)
			return false
		}

	} else if equal_fold(name, "transfer-encoding") {
		// Only bare "chunked" is supported. Rejecting unknown codings avoids
		// guessing at framing we cannot actually decode.
		if !equal_fold(trim_ows(value), "chunked") {
			fail(p, .Unsupported_Transfer_Encoding)
			return false
		}
		if _, has := headers_get(p.req.headers, "transfer-encoding"); has {
			fail(p, .Chunked_Not_Final)
			return false
		}

	} else if equal_fold(name, "host") {
		if p.seen_host { fail(p, .Multiple_Hosts); return false }
		p.seen_host = true
	}

	headers_set_parsed(&p.req.headers, name, value)
	return true
}

/*
Decides body framing once all headers are known.

This is the single most security-sensitive decision in the parser: it
determines where this message ends and the next begins on a reused connection.
*/
@(private)
finalize_headers :: proc(p: ^Parser) -> bool {
	// RFC 9112 3.2: HTTP/1.1 requests must carry Host. Without it a request is
	// ambiguous for any virtual-hosted or proxying deployment.
	if p.req.version.minor >= 1 && !p.seen_host {
		fail(p, .Missing_Host)
		return false
	}

	has_te := headers_has(p.req.headers, "transfer-encoding")
	cl_str, has_cl := headers_get(p.req.headers, "content-length")

	switch {
	case has_te && has_cl:
		// RFC 9112 6.1 permits dropping Content-Length here, but that only
		// works if every hop makes the same choice. Rejecting is the only
		// option that cannot desync.
		fail(p, .Transfer_Encoding_And_Content_Length)
		return false

	case has_te:
		p.framing = .Chunked
		p.state   = .Chunk_Size

	case has_cl:
		n, _ := parse_decimal(cl_str)
		p.framing   = .Content_Length
		p.remaining = n
		p.state     = .Body_Length

	case:
		// No framing headers: the request has no body. A request body cannot be
		// delimited by connection close, since the server would never know the
		// request had ended.
		p.framing = .None
		p.state   = .Body_Length
	}

	p.req.has_body = p.framing != .None && p.remaining != 0 || p.framing == .Chunked
	return true
}

/*
Reports whether the connection may be reused after this message.

Defaults follow the version: HTTP/1.1 is keep-alive unless refused, HTTP/1.0
is close unless "keep-alive" is requested.
*/
parser_should_keep_alive :: proc(p: ^Parser) -> bool {
	if p.state == .Failed { return false }

	if conn, ok := headers_get(p.req.headers, "connection"); ok {
		if token_list_contains(conn, "close")      { return false }
		if token_list_contains(conn, "keep-alive") { return true  }
	}
	return p.req.version.minor >= 1
}

/*
Reports whether a comma-separated list contains the given token.

Used for `Connection`, whose value is a list rather than a single token.
*/
token_list_contains :: proc(list: string, want: string) -> bool {
	start := 0
	for i := 0; i <= len(list); i += 1 {
		if i == len(list) || list[i] == ',' {
			if equal_fold(trim_ows(list[start:i]), want) { return true }
			start = i + 1
		}
	}
	return false
}
