package http

import "core:mem"
import "core:strings"

/*
Turning a decoded h2 header list into a Request (RFC 9113 8.1 to 8.3).

This is HTTP/2's equivalent of the HTTP/1.1 parser's smuggling defences, and it
matters for the same reason: a server that accepts a malformed header list can
be made to disagree with whatever is downstream of it. The specific danger is an
h2-to-HTTP/1.1 gateway — a `transfer-encoding` smuggled through h2 becomes a
framing header on the other side, which is exactly the desync the HTTP/1.1
parser refuses to create.

So this rejects rather than normalizes, the same as `parse_header_line`.
*/

H2_Request_Error :: enum u8 {
	None,
	// A pseudo-header after a regular field, or an unknown one.
	Malformed_Pseudo_Header,
	Duplicate_Pseudo_Header,
	Missing_Pseudo_Header,
	// An uppercase field name (RFC 9113 8.2.1).
	Uppercase_Field_Name,
	// Connection-specific headers have no meaning in h2 and are a gateway
	// smuggling vector.
	Connection_Specific_Header,
	Invalid_Method,
	Invalid_Path,
	Invalid_Field,
}

/*
Builds a Request from a decoded header list.

`fields` must be in wire order: the pseudo-header ordering rule cannot be
checked once the fields have been sorted or de-duplicated into a map.

The Request's strings borrow from `fields`, which in turn borrow from the header
block or the HPACK dynamic table. The connection layer owns both for the
lifetime of the stream.
*/
h2_request_from_fields :: proc(
	req: ^Request,
	fields: []Header_Entry,
	allocator: mem.Allocator,
) -> H2_Request_Error {
	request_init(req, allocator)
	req.version = {2, 0}

	method, scheme, authority, path: string
	seen_regular := false

	for f in fields {
		if len(f.name) == 0 { return .Invalid_Field }

		if f.name[0] == ':' {
			// RFC 9113 8.3: pseudo-headers must all precede regular fields, so
			// one appearing after any regular field is malformed.
			if seen_regular { return .Malformed_Pseudo_Header }

			switch f.name {
			case ":method":
				if len(method) > 0 { return .Duplicate_Pseudo_Header }
				method = f.value
			case ":scheme":
				if len(scheme) > 0 { return .Duplicate_Pseudo_Header }
				scheme = f.value
			case ":authority":
				if len(authority) > 0 { return .Duplicate_Pseudo_Header }
				authority = f.value
			case ":path":
				if len(path) > 0 { return .Duplicate_Pseudo_Header }
				path = f.value
			case:
				// Request pseudo-headers are a closed set; anything else
				// (including a response's :status) is malformed here.
				return .Malformed_Pseudo_Header
			}
			continue
		}

		seen_regular = true

		// RFC 9113 8.2.1: field names are lowercase on the wire. An uppercase
		// name is malformed rather than something to fold, because folding is
		// exactly what lets two hops disagree about a header's identity.
		for i in 0 ..< len(f.name) {
			c := f.name[i]
			if c >= 'A' && c <= 'Z' { return .Uppercase_Field_Name }
			if !is_tchar(c)         { return .Invalid_Field }
		}

		if !is_field_value(f.value) { return .Invalid_Field }

		if h2_is_connection_specific(f.name) {
			return .Connection_Specific_Header
		}

		/*
		RFC 9113 8.2.2: TE may appear but must carry nothing other than
		"trailers".

		The comparison is case-insensitive because "trailers" is a
		transfer-coding name and RFC 9110 7.5 makes those case-insensitive.
		Matching the lowercase spelling alone rejected `TE: Trailers` — a legal
		field — as a connection-specific header, failing the whole request
		rather than the field.

		Anything else is still refused, including a list that merely contains
		"trailers": the RFC permits the one value, not a list with it in.
		*/
		if f.name == "te" && !equal_fold(f.value, "trailers") {
			return .Connection_Specific_Header
		}

		/*
		RFC 9113 8.2.3: an h2 client may split Cookie across several fields to
		improve HPACK compression, and the server must rejoin them with "; ".
		Every other header joins with ", ", which for Cookie produces a string
		no parser can split — every cookie after the first is silently lost.
		*/
		if f.name == "cookie" {
			if existing, has := headers_get(req.headers, "cookie"); has {
				headers_set_joined(&req.headers, "cookie",
					strings.concatenate({existing, "; ", f.value}, allocator))
				continue
			}
		}

		headers_set_parsed(&req.headers, f.name, f.value)
	}

	// :method and :scheme are always required; :path is required for every
	// method this server handles.
	if len(method) == 0 { return .Missing_Pseudo_Header }
	if len(scheme) == 0 { return .Missing_Pseudo_Header }

	m, method_ok := method_parse(method)
	if !method_ok { return .Invalid_Method }
	req.method = m

	// CONNECT omits :scheme and :path and is not supported here, so it is
	// rejected rather than half-handled.
	if m == .Connect { return .Invalid_Method }

	if len(path) == 0 { return .Missing_Pseudo_Header }

	// asterisk-form is legal only for OPTIONS, the same rule the HTTP/1.1
	// parser enforces.
	if path == "*" {
		if m != .Options { return .Invalid_Path }
	} else if path[0] != '/' {
		return .Invalid_Path
	}

	for i in 0 ..< len(path) {
		// The target must be printable ASCII with no whitespace or controls.
		if path[i] <= 0x20 || path[i] == 0x7f { return .Invalid_Path }
	}

	req.target = path

	// h2 carries the authority in a pseudo-header; HTTP/1.1 handlers read Host,
	// so it is surfaced there rather than making every handler know which
	// protocol served it.
	if len(authority) > 0 && !headers_has(req.headers, "host") {
		headers_set_parsed(&req.headers, "host", authority)
	}

	return .None
}

/*
Reports whether a field is connection-specific and therefore forbidden in h2.

RFC 9113 8.2.2 lists these because h2 has its own connection management. They
are refused rather than dropped: silently discarding a `transfer-encoding` would
let a client believe it had framed a body one way while the server read it
another.
*/
@(private)
h2_is_connection_specific :: proc(name: string) -> bool {
	switch name {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
		return true
	}
	return false
}

/*
Maps a request-construction failure to the h2 error code to send.

All of these are stream errors rather than connection errors: the header list
was malformed, but the connection's framing and HPACK state are still intact, so
resetting the one stream is both sufficient and less disruptive than a GOAWAY.
*/
h2_request_error_code :: proc(e: H2_Request_Error) -> H2_Error {
	if e == .None { return .No_Error }
	return .Protocol_Error
}
