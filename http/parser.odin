package http

import "core:strings"

/*
Sans-I/O incremental HTTP/1.1 parser.

Fed bytes, reports how many it consumed. Never touches a socket, so the same
code is driven by the blocking server, by the client, and by tests feeding one
byte at a time.

Strings returned point into the caller's buffer — nothing is copied or
allocated. The buffer must outlive the resulting `Request`.

	p: Parser
	parser_init(&p, &req, limits)
	for {
		n, ev := parser_feed(&p, buf[consumed:])
		consumed += n
		switch ev {
		case .Need_More:    // read more, call again
		case .Headers_Done: // req is populated
		case .Body_Chunk:   // p.chunk holds the latest body bytes
		case .Message_Done: // complete
		case .Error:        // p.err says why; close the connection
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
	Invalid_Status,
	// The peer closed before the message was complete.
	Bad_Read_Count,
	Too_Many_Informational,
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
	// A response with no framing headers: the body ends when the peer closes.
	Body_Until_Close,
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
	// Response-only: delimited by the connection closing (RFC 9112 6.3).
	Until_Close,
}

/*
Which side of the conversation is being parsed.

Message framing, chunked decoding and header validation are identical in both
directions; only the first line and a few framing rules differ. Sharing the
state machine means a bug fixed on one side is fixed on the other, which matters
most for the smuggling defences.
*/
Parse_Role :: enum u8 {
	Request,
	Response,
}

Parser :: struct {
	role:           Parse_Role,
	req:            ^Request,
	// Set instead of `req` when parsing a response.
	res:            ^Client_Response,
	// The method of the request this response answers. Response framing depends
	// on it: a HEAD response carries Content-Length but no body at all.
	req_method:     Method,

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
	// Interim 1xx responses seen before the final one, bounded so a peer cannot
	// stream them indefinitely.
	informational_count: int,
}

// A handful covers 100-continue plus a few Early Hints; more is a peer keeping
// the client busy for free.
MAX_INFORMATIONAL_RESPONSES :: 8

parser_init :: proc(p: ^Parser, req: ^Request, limits := DEFAULT_LIMITS) {
	p^ = Parser {
		role          = .Request,
		req           = req,
		limits        = limits,
		state         = .Request_Line,
		header_budget = limits.max_headers,
	}
}

/*
Prepares the parser to read a response to a request that used `method`.

The method is required because response framing depends on it: RFC 9112 6.3
says a HEAD response has the header fields of the GET it mirrors but never a
body, so Content-Length must be reported without any bytes being consumed.
*/
parser_init_response :: proc(p: ^Parser, res: ^Client_Response, method: Method, limits := DEFAULT_LIMITS) {
	p^ = Parser {
		role          = .Response,
		res           = res,
		req_method    = method,
		limits        = limits,
		state         = .Request_Line,
		header_budget = limits.max_headers,
	}
}

// The headers being filled in, whichever direction is being parsed.
@(private)
parser_headers :: #force_inline proc(p: ^Parser) -> ^Headers {
	return &p.res.headers if p.role == .Response else &p.req.headers
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

			ok := parse_status_line(p, line) if p.role == .Response else parse_request_line(p, line)
			if !ok { return consumed, .Error }
			p.state = .Header_Line

		case .Header_Line:
			// A budget already spent must fail here rather than at the next
			// `scan_line`: that call treats a negative limit as "no limit", so
			// overspending is exactly what would stop the limit being enforced.
			if p.header_budget < 0 { return consumed, fail(p, .Headers_Too_Long) }

			line, n, found := scan_line(data[consumed:], p.header_budget)
			if !found {
				if n < 0 { return consumed, fail(p, .Headers_Too_Long) }
				return consumed, .Need_More
			}
			consumed += n
			p.header_budget -= n

			if len(line) == 0 {
				if !finalize_headers(p) { return consumed, .Error }

				// An interim 1xx put the parser back at the status line. It is
				// not the answer, so the caller must not be told the headers
				// are ready — doing so would hand it the wrong status and an
				// empty body.
				if p.state == .Request_Line { continue }

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

		case .Body_Until_Close:
			// Everything up to EOF is body. The driver signals EOF by calling
			// `parser_finish`, since a zero-length feed is indistinguishable
			// from "no data has arrived yet".
			avail := len(data) - consumed
			if avail == 0 { return consumed, .Need_More }

			p.chunk = data[consumed:][:avail]
			consumed += avail
			p.body_seen += avail

			if p.limits.max_body >= 0 && p.body_seen > p.limits.max_body {
				return consumed, fail(p, .Body_Too_Large)
			}
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
			// Same reasoning as `.Header_Line`: trailers share the budget, and
			// a negative one would disable the check.
			if p.header_budget < 0 { return consumed, fail(p, .Headers_Too_Long) }

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

	// asterisk-form is only meaningful for a server-wide OPTIONS (RFC 9112
	// 3.2.4). Anywhere else it is not a resource anyone can name, so accepting
	// it would hand handlers a path they cannot interpret.
	if target == "*" && method != .Options { fail(p, .Invalid_Target); return false }

	// Every other form must start with '/' or name a scheme. A target that is
	// neither is authority-form, which only CONNECT may use, and CONNECT needs
	// tunnelling support this server does not have.
	if target != "*" && target[0] != '/' && strings.index(target, "://") < 0 {
		fail(p, .Invalid_Target)
		return false
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

		if existing, has := headers_get(parser_headers(p)^, "content-length"); has {
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
		if _, has := headers_get(parser_headers(p)^, "transfer-encoding"); has {
			fail(p, .Chunked_Not_Final)
			return false
		}

	} else if equal_fold(name, "host") {
		if p.seen_host { fail(p, .Multiple_Hosts); return false }
		p.seen_host = true
	}

	headers_set_parsed(parser_headers(p), name, value)
	return true
}

/*
Decides body framing once all headers are known.

This is the single most security-sensitive decision in the parser: it
determines where this message ends and the next begins on a reused connection.
*/
@(private)
finalize_headers :: proc(p: ^Parser) -> bool {
	if p.role == .Response { return finalize_response_headers(p) }

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
Decides body framing for a response.

Differs from the request rules in two ways that matter:

  - Some statuses never carry a body regardless of their headers (RFC 9112 6.3),
    and a HEAD response never does. Reading a body there would consume the next
    response on a reused connection.
  - A response with no framing headers is delimited by the connection closing.
    A request cannot be, because the server would never learn it had ended.
*/
@(private)
finalize_response_headers :: proc(p: ^Parser) -> bool {
	/*
	A 1xx is interim, not the answer. RFC 9110 15.2: a client must be prepared
	for one or more informational responses before the real one, and `100
	Continue` and `103 Early Hints` are both sent by servers in the wild.

	Treating one as final returns an empty body and the wrong status, so the
	parser discards it and starts over on the next status line. The count is
	bounded because a peer could otherwise stream interim responses forever.
	*/
	if status_is_informational(p.res.status) {
		p.informational_count += 1
		if p.informational_count > MAX_INFORMATIONAL_RESPONSES {
			fail(p, .Too_Many_Informational)
			return false
		}

		// Interim headers describe the interim response only; keeping them
		// would leak Early Hints link headers into the final response.
		p.res.status = {}
		clear(&p.res.headers.entries)
		clear(&p.res.headers._index)

		p.header_budget = p.limits.max_headers
		p.header_count  = 0
		p.state         = .Request_Line
		return true
	}

	has_te := headers_has(p.res.headers, "transfer-encoding")
	cl_str, has_cl := headers_get(p.res.headers, "content-length")

	if has_te && has_cl {
		fail(p, .Transfer_Encoding_And_Content_Length)
		return false
	}

	// A bodyless status or a HEAD response ends here, whatever the headers say.
	if !status_can_have_body(p.res.status) || p.req_method == .Head {
		p.framing   = .None
		p.remaining = 0
		p.state     = .Body_Length
		return true
	}

	switch {
	case has_te:
		p.framing = .Chunked
		p.state   = .Chunk_Size

	case has_cl:
		n, _ := parse_decimal(cl_str)
		p.framing   = .Content_Length
		p.remaining = n
		p.state     = .Body_Length

	case:
		// No framing headers: the body runs until the peer closes. The client
		// reads until EOF and must not reuse the connection.
		p.framing        = .Until_Close
		p.res.until_close = true
		p.state          = .Body_Until_Close
	}

	return true
}

/*
Parses "HTTP-version SP status-code SP [reason-phrase]".

The reason phrase is optional and ignored: it carries no meaning and trusting it
would be a mistake, since it is attacker-controlled text.
*/
@(private)
parse_status_line :: proc(p: ^Parser, line: string) -> bool {
	sp1 := index_byte(line, ' ')
	if sp1 < 0 { fail(p, .Invalid_Version); return false }

	version, vok := version_parse(line[:sp1])
	if !vok { fail(p, .Invalid_Version); return false }
	if version.major != 1 { fail(p, .Unsupported_Version); return false }

	rest := line[sp1 + 1:]

	// The status code is exactly three digits; a reason phrase may follow.
	code_str := rest
	if sp2 := index_byte(rest, ' '); sp2 >= 0 {
		code_str = rest[:sp2]
	}
	if len(code_str) != 3 { fail(p, .Invalid_Status); return false }

	code, cok := parse_decimal(code_str)
	if !cok { fail(p, .Invalid_Status); return false }

	p.res.version = version
	p.res.status  = Status(code)
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

/*
Signals that the peer closed the connection.

Only meaningful for a response whose body is delimited by connection close: for
any other framing an early close is a truncated message, which must not be
reported as a complete one.
*/
parser_finish :: proc(p: ^Parser) -> Parse_Event {
	#partial switch p.state {
	case .Body_Until_Close:
		p.state = .Done
		return .Message_Done
	case .Done:
		return .Message_Done
	case .Failed:
		return .Error
	}

	// Closed mid-message: the body is incomplete and must not be handed over as
	// if it were whole.
	return fail(p, .Bad_Read_Count)
}
