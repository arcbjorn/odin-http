package tests

import "core:mem/virtual"
import "core:testing"

import http "../http"

/*
Building a Request from an h2 header list (RFC 9113 8.1 to 8.3).

These are HTTP/2's smuggling defences. The danger case is an h2-to-HTTP/1.1
gateway: a `transfer-encoding` accepted here becomes a framing header on the
other side, which is precisely the desync the HTTP/1.1 parser refuses to create.
So the rejection tests matter more than the happy path.
*/

@(private)
h2_fields :: proc(pairs: ..string) -> []http.Header_Entry {
	// Pairs are name, value, name, value... in wire order, which the
	// pseudo-header ordering rule depends on.
	out := make([]http.Header_Entry, len(pairs) / 2, context.temp_allocator)
	for i in 0 ..< len(out) {
		out[i] = {name = pairs[i * 2], value = pairs[i * 2 + 1]}
	}
	return out
}

@(private)
h2_build :: proc(fields: []http.Header_Entry, arena: ^virtual.Arena) -> (http.Request, http.H2_Request_Error) {
	req: http.Request
	err := http.h2_request_from_fields(&req, fields, virtual.arena_allocator(arena))
	return req, err
}

@(test)
test_h2_request_basic :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	req, err := h2_build(h2_fields(
		":method", "GET",
		":scheme", "https",
		":authority", "example.com",
		":path", "/users/42",
		"accept", "*/*",
	), &arena)

	testing.expect_value(t, err, http.H2_Request_Error.None)
	testing.expect_value(t, req.method, http.Method.Get)
	testing.expect_value(t, req.target, "/users/42")
	testing.expect_value(t, req.version.major, u8(2))

	// h2 carries the authority in a pseudo-header, but handlers read Host, so
	// it is surfaced there rather than making handlers protocol-aware.
	host, ok := http.headers_get(req.headers, "host")
	testing.expect(t, ok, "authority should surface as Host")
	testing.expect_value(t, host, "example.com")

	accept, _ := http.headers_get(req.headers, "accept")
	testing.expect_value(t, accept, "*/*")
}

@(test)
test_h2_request_rejects_pseudo_after_regular :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	// RFC 9113 8.3: pseudo-headers must all precede regular fields.
	_, err := h2_build(h2_fields(
		":method", "GET",
		"accept", "*/*",
		":path", "/",
	), &arena)

	testing.expect_value(t, err, http.H2_Request_Error.Malformed_Pseudo_Header)
}

@(test)
test_h2_request_rejects_unknown_pseudo_header :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	// Request pseudo-headers are a closed set; :status belongs to responses.
	_, err := h2_build(h2_fields(
		":method", "GET",
		":scheme", "https",
		":path", "/",
		":status", "200",
	), &arena)

	testing.expect_value(t, err, http.H2_Request_Error.Malformed_Pseudo_Header)
}

@(test)
test_h2_request_rejects_duplicate_pseudo_header :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	// Two :path values would let a gateway pick a different one than we did.
	_, err := h2_build(h2_fields(
		":method", "GET",
		":scheme", "https",
		":path", "/a",
		":path", "/b",
	), &arena)

	testing.expect_value(t, err, http.H2_Request_Error.Duplicate_Pseudo_Header)
}

@(test)
test_h2_request_requires_pseudo_headers :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	// No :path
	_, no_path := h2_build(h2_fields(":method", "GET", ":scheme", "https"), &arena)
	testing.expect_value(t, no_path, http.H2_Request_Error.Missing_Pseudo_Header)

	// No :method
	_, no_method := h2_build(h2_fields(":scheme", "https", ":path", "/"), &arena)
	testing.expect_value(t, no_method, http.H2_Request_Error.Missing_Pseudo_Header)

	// No :scheme
	_, no_scheme := h2_build(h2_fields(":method", "GET", ":path", "/"), &arena)
	testing.expect_value(t, no_scheme, http.H2_Request_Error.Missing_Pseudo_Header)
}

@(test)
test_h2_request_rejects_uppercase_field_names :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	// RFC 9113 8.2.1. Folding instead of rejecting is what lets two hops
	// disagree about a header's identity.
	_, err := h2_build(h2_fields(
		":method", "GET",
		":scheme", "https",
		":path", "/",
		"Accept", "*/*",
	), &arena)

	testing.expect_value(t, err, http.H2_Request_Error.Uppercase_Field_Name)
}

@(test)
test_h2_request_rejects_connection_specific_headers :: proc(t: ^testing.T) {
	// RFC 9113 8.2.2. Each of these has no meaning in h2 and, if forwarded to
	// an HTTP/1.1 backend, becomes a framing or connection directive there.
	forbidden := [][2]string{
		{"connection", "keep-alive"},
		{"keep-alive", "timeout=5"},
		{"proxy-connection", "keep-alive"},
		{"transfer-encoding", "chunked"},
		{"upgrade", "websocket"},
	}

	for f in forbidden {
		arena := test_arena()
		defer test_arena_destroy(&arena)

		_, err := h2_build(h2_fields(
			":method", "GET",
			":scheme", "https",
			":path", "/",
			f[0], f[1],
		), &arena)

		testing.expectf(t, err == .Connection_Specific_Header,
			"%q must be rejected, got %v", f[0], err)
	}
}

@(test)
test_h2_request_te_only_allows_trailers :: proc(t: ^testing.T) {
	{
		arena := test_arena()
		defer test_arena_destroy(&arena)
		// The one permitted value.
		_, ok := h2_build(h2_fields(
			":method", "GET", ":scheme", "https", ":path", "/",
			"te", "trailers",
		), &arena)
		testing.expect_value(t, ok, http.H2_Request_Error.None)
	}
	{
		arena := test_arena()
		defer test_arena_destroy(&arena)
		// Anything else, including a value that merely contains it.
		_, err := h2_build(h2_fields(
			":method", "GET", ":scheme", "https", ":path", "/",
			"te", "gzip",
		), &arena)
		testing.expect_value(t, err, http.H2_Request_Error.Connection_Specific_Header)
	}
}

/*
"trailers" is a transfer-coding name, so the comparison is case-insensitive.

RFC 9110 7.5 makes transfer-coding names case-insensitive, and RFC 9113 8.2.2
permits TE to carry that one value. Matching only the lowercase spelling
rejected `TE: Trailers` as a connection-specific header — failing the whole
request rather than the field, for a value that is legal.

The rejected forms below still matter: 8.2.2 permits the single value, not a
list containing it, so `trailers, gzip` is refused however it is spelled.
*/
@(test)
test_h2_request_te_trailers_is_case_insensitive :: proc(t: ^testing.T) {
	for accepted in ([]string{"trailers", "Trailers", "TRAILERS", "TrAiLeRs"}) {
		arena := test_arena()
		defer test_arena_destroy(&arena)

		_, err := h2_build(h2_fields(
			":method", "GET", ":scheme", "https", ":path", "/",
			"te", accepted,
		), &arena)
		testing.expectf(t, err == http.H2_Request_Error.None,
			"TE: %q is legal and must be accepted, got %v", accepted, err)
	}

	for refused in ([]string{"trailers, gzip", "Trailers, gzip", "gzip", "", " trailers"}) {
		arena := test_arena()
		defer test_arena_destroy(&arena)

		_, err := h2_build(h2_fields(
			":method", "GET", ":scheme", "https", ":path", "/",
			"te", refused,
		), &arena)
		testing.expectf(t, err == http.H2_Request_Error.Connection_Specific_Header,
			"TE: %q must be refused, got %v", refused, err)
	}
}

@(test)
test_h2_request_rejects_bad_paths :: proc(t: ^testing.T) {
	bad := []string{
		"",                 // empty
		"relative/path",    // not origin-form
		"/with space",      // whitespace is not allowed in a target
		"/with\x00nul",
	}

	for p in bad {
		arena := test_arena()
		defer test_arena_destroy(&arena)

		_, err := h2_build(h2_fields(
			":method", "GET", ":scheme", "https", ":path", p,
		), &arena)

		testing.expectf(t, err != .None, "path %q must be rejected", p)
	}
}

@(test)
test_h2_request_asterisk_only_for_options :: proc(t: ^testing.T) {
	{
		arena := test_arena()
		defer test_arena_destroy(&arena)
		req, err := h2_build(h2_fields(
			":method", "OPTIONS", ":scheme", "https", ":path", "*",
		), &arena)
		testing.expect_value(t, err, http.H2_Request_Error.None)
		testing.expect_value(t, req.target, "*")
	}
	{
		arena := test_arena()
		defer test_arena_destroy(&arena)
		// The same rule the HTTP/1.1 parser enforces: `*` names no resource.
		_, err := h2_build(h2_fields(
			":method", "GET", ":scheme", "https", ":path", "*",
		), &arena)
		testing.expect_value(t, err, http.H2_Request_Error.Invalid_Path)
	}
}

@(test)
test_h2_request_rejects_connect :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	// CONNECT uses a different pseudo-header set entirely and needs tunnelling
	// support this server does not have, so it is refused rather than
	// half-handled.
	_, err := h2_build(h2_fields(
		":method", "CONNECT",
		":scheme", "https",
		":path", "/",
		":authority", "example.com:443",
	), &arena)

	testing.expect_value(t, err, http.H2_Request_Error.Invalid_Method)
}

@(test)
test_h2_request_errors_are_stream_level :: proc(t: ^testing.T) {
	// A malformed header list leaves framing and HPACK state intact, so
	// resetting the one stream is enough; a GOAWAY would be more disruptive
	// than the fault warrants.
	testing.expect_value(t, http.h2_request_error_code(.None), http.H2_Error.No_Error)
	testing.expect_value(t,
		http.h2_request_error_code(.Connection_Specific_Header),
		http.H2_Error.Protocol_Error)
}

@(test)
test_h2_rejoins_split_cookie_fields :: proc(t: ^testing.T) {
	// RFC 9113 8.2.3: an h2 client may split Cookie into several fields to
	// improve HPACK compression, and the server must rejoin them with "; ".
	// Joining with ", " — the rule for every other header — produces a cookie
	// string no parser can read, so every cookie after the first is lost.
	arena := test_arena()
	defer test_arena_destroy(&arena)

	req, err := h2_build(h2_fields(
		":method", "GET",
		":scheme", "https",
		":path", "/",
		"cookie", "a=1",
		"cookie", "b=2",
		"cookie", "c=3",
	), &arena)

	testing.expect_value(t, err, http.H2_Request_Error.None)

	joined, ok := http.headers_get(req.headers, "cookie")
	testing.expect(t, ok, "cookie should be present")
	testing.expect_value(t, joined, "a=1; b=2; c=3")

	// And the cookie parser must then find every one of them.
	b, has_b := http.request_cookie(&req, "b")
	testing.expect(t, has_b, "a split cookie must still be readable")
	testing.expect_value(t, b, "2")

	c, has_c := http.request_cookie(&req, "c")
	testing.expect(t, has_c, "the last split cookie must be readable")
	testing.expect_value(t, c, "3")
}

/*
Pseudo-header values are validated like any other field value.

The field-value check applies to regular headers only — a pseudo-header
`continue`s before reaching it — so a CR or LF in `:authority` reached the
`host` header intact. Host is what virtual hosting routes on, and h2 itself has
no CRLF framing to be broken; the damage lands at an h2-to-HTTP/1.1 gateway,
which re-emits that value onto a wire where CRLF *is* framing.
*/
@(test)
test_h2_request_rejects_control_bytes_in_pseudo_headers :: proc(t: ^testing.T) {
	hostile := []string{
		"example.test\r\nX-Injected: 1",
		"example.test\rX",
		"example.test\nX",
		"example.test\x00x",
	}

	for value in hostile {
		{
			arena := test_arena()
			defer test_arena_destroy(&arena)
			_, err := h2_build(h2_fields(
				":method", "GET", ":scheme", "https", ":path", "/",
				":authority", value,
			), &arena)
			testing.expectf(t, err == http.H2_Request_Error.Invalid_Field,
				":authority %q must be refused, got %v", value, err)
		}
		// The same rule applies to every pseudo-header, not just :authority.
		{
			arena := test_arena()
			defer test_arena_destroy(&arena)
			_, err := h2_build(h2_fields(
				":method", "GET", ":scheme", value, ":path", "/",
				":authority", "x",
			), &arena)
			testing.expectf(t, err == http.H2_Request_Error.Invalid_Field,
				":scheme %q must be refused, got %v", value, err)
		}
	}
}

/*
`:authority` must not carry userinfo (RFC 9113 8.3.1).

It becomes the Host header, so `user@evil.test` would let a request name one
host while a log or a naive parser reads another — the same ambiguity that makes
userinfo in URLs a phishing primitive.
*/
@(test)
test_h2_request_rejects_userinfo_in_authority :: proc(t: ^testing.T) {
	for bad in ([]string{
		"user@example.test",
		"user:pass@example.test",
		"@example.test",
		"example.test@evil.test",
	}) {
		arena := test_arena()
		defer test_arena_destroy(&arena)

		_, err := h2_build(h2_fields(
			":method", "GET", ":scheme", "https", ":path", "/",
			":authority", bad,
		), &arena)
		testing.expectf(t, err == http.H2_Request_Error.Invalid_Authority,
			":authority %q must be refused, got %v", bad, err)
	}

	// An ordinary authority, with and without a port, is still accepted.
	for good in ([]string{"example.test", "example.test:8443", "127.0.0.1:80"}) {
		arena := test_arena()
		defer test_arena_destroy(&arena)

		req, err := h2_build(h2_fields(
			":method", "GET", ":scheme", "https", ":path", "/",
			":authority", good,
		), &arena)
		testing.expectf(t, err == http.H2_Request_Error.None,
			":authority %q is legal, got %v", good, err)

		host, _ := http.headers_get(req.headers, "host")
		testing.expectf(t, host == good, "authority %q became host %q", good, host)
	}
}
