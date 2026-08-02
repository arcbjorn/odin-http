package http

import "core:strings"
import "core:time"

/*
Cookie handling (RFC 6265).

Set-Cookie is the one header that must never be joined with ", ": the date in an
Expires attribute contains a comma, so a joined value is ambiguous and clients
parse it differently. `Headers` keeps each Set-Cookie as its own entry for
exactly this reason.
*/

Same_Site :: enum u8 {
	// Attribute omitted entirely, leaving the browser default (Lax in modern
	// browsers). Prefer an explicit value.
	Unspecified,
	Strict,
	Lax,
	// Requires Secure; browsers reject `SameSite=None` without it.
	None,
}

Cookie :: struct {
	name:      string,
	value:     string,

	domain:    string,
	path:      string,

	// Zero means no Expires attribute.
	expires:   time.Time,
	// Negative means no Max-Age attribute. Zero is meaningful: it tells the
	// client to delete the cookie immediately.
	max_age:   int,

	// Withheld from cross-origin requests unless SameSite=None.
	secure:    bool,
	// Hidden from document.cookie, which is the main defence against a stored
	// XSS being able to exfiltrate a session.
	http_only: bool,
	same_site: Same_Site,

	// Emits the `Partitioned` attribute (CHIPS), which scopes a third-party
	// cookie to the embedding site.
	partitioned: bool,
}

/*
A session cookie with the defaults that are safe for auth tokens.

Secure + HttpOnly + SameSite=Lax is the combination that resists XSS
exfiltration and CSRF without breaking top-level navigation. Callers wanting a
different trade-off should set the fields explicitly rather than starting from
a permissive default.
*/
cookie_session :: proc(name: string, value: string) -> Cookie {
	return Cookie{
		name      = name,
		value     = value,
		path      = "/",
		max_age   = -1,
		secure    = true,
		http_only = true,
		same_site = .Lax,
	}
}

/*
Adds a Set-Cookie header to the response.

Returns false if the cookie is malformed, rather than emitting a header that a
client would reject or, worse, misparse. Validation is strict because a
newline or a stray semicolon in a cookie value is a header-injection primitive.
*/
response_set_cookie :: proc(res: ^Response, c: Cookie) -> bool {
	serialized, ok := cookie_serialize(c, res.headers.allocator)
	if !ok { return false }

	// Bypasses `headers_set`, which would treat this as a single-valued field.
	// Multiple Set-Cookie headers are the correct representation.
	append(&res.headers.entries, Header_Entry{"set-cookie", serialized})
	return true
}

/*
Adds a Set-Cookie that deletes a cookie on the client.

Deletion is expressed as an empty value with Max-Age=0. Domain and Path must
match the original cookie or the browser will create a second cookie instead of
removing the first, which is the usual reason "logout" appears not to work.
*/
response_delete_cookie :: proc(res: ^Response, name: string, path := "/", domain := "") -> bool {
	return response_set_cookie(res, Cookie{
		name    = name,
		value   = "",
		path    = path,
		domain  = domain,
		max_age = 0,
	})
}

/*
Serializes a cookie into a Set-Cookie field value.

Attribute order follows RFC 6265 5.2, which clients parse leniently, but a
consistent order keeps output reproducible for tests.
*/
cookie_serialize :: proc(c: Cookie, allocator := context.temp_allocator) -> (value: string, ok: bool) {
	if !is_cookie_name(c.name)          { return "", false }
	if !is_cookie_value(c.value)        { return "", false }
	if !is_cookie_attr(c.domain)        { return "", false }
	if !is_cookie_attr(c.path)          { return "", false }

	// Browsers reject SameSite=None unless Secure is also set, so emitting it
	// would produce a cookie that is silently dropped.
	if c.same_site == .None && !c.secure { return "", false }

	b := strings.builder_make(allocator)

	strings.write_string(&b, c.name)
	strings.write_byte(&b, '=')
	strings.write_string(&b, c.value)

	if len(c.domain) > 0 {
		strings.write_string(&b, "; Domain=")
		strings.write_string(&b, c.domain)
	}

	if len(c.path) > 0 {
		strings.write_string(&b, "; Path=")
		strings.write_string(&b, c.path)
	}

	if c.expires._nsec != 0 {
		buf: [DATE_LENGTH]byte
		strings.write_string(&b, "; Expires=")
		strings.write_string(&b, date_write(buf[:], c.expires))
	}

	if c.max_age >= 0 {
		strings.write_string(&b, "; Max-Age=")
		strings.write_int(&b, c.max_age)
	}

	if c.secure    { strings.write_string(&b, "; Secure")   }
	if c.http_only { strings.write_string(&b, "; HttpOnly") }

	switch c.same_site {
	case .Strict:      strings.write_string(&b, "; SameSite=Strict")
	case .Lax:         strings.write_string(&b, "; SameSite=Lax")
	case .None:        strings.write_string(&b, "; SameSite=None")
	case .Unspecified: // Attribute omitted.
	}

	if c.partitioned { strings.write_string(&b, "; Partitioned") }

	return strings.to_string(b), true
}

/*
Returns a named cookie from the request.

The Cookie header is a single field holding "name=value" pairs separated by
"; ". Only the name and value exist on the request side; attributes are
set-only and never sent back by the client.
*/
request_cookie :: proc(req: ^Request, name: string) -> (value: string, ok: bool) #optional_ok {
	header := headers_get(req.headers, "cookie") or_return

	start := 0
	for i := 0; i <= len(header); i += 1 {
		if i != len(header) && header[i] != ';' { continue }

		pair := trim_ows(header[start:i])
		start = i + 1
		if len(pair) == 0 { continue }

		eq := index_byte(pair, '=')
		if eq < 0 { continue }

		// Cookie names are case-sensitive (RFC 6265 4.1.1). The name is trimmed
		// but the value is not: RFC 6265 5.2 strips whitespace around the name,
		// while a leading space in the value is part of it. Go's net/http draws
		// the line in the same place.
		if trim_ows(pair[:eq]) == name {
			return trim_cookie_quotes(pair[eq + 1:]), true
		}
	}
	return "", false
}

/*
Parses every cookie on the request into a map.

Prefer `request_cookie` when only one cookie is needed; this allocates a map.
On duplicate names the first occurrence wins, matching browser behaviour of
sending the most specific path first.
*/
request_cookies :: proc(req: ^Request, allocator := context.temp_allocator) -> (cookies: map[string]string) {
	cookies.allocator = allocator

	header, has := headers_get(req.headers, "cookie")
	if !has { return }

	start := 0
	for i := 0; i <= len(header); i += 1 {
		if i != len(header) && header[i] != ';' { continue }

		pair := trim_ows(header[start:i])
		start = i + 1
		if len(pair) == 0 { continue }

		eq := index_byte(pair, '=')
		if eq < 0 { continue }

		// Trimmed to match `request_cookie`: a key the map holds but that
		// accessor cannot find would be worse than either behaviour alone.
		key := trim_ows(pair[:eq])
		if key in cookies { continue }
		cookies[key] = trim_cookie_quotes(pair[eq + 1:])
	}
	return
}

/*
Strips the optional DQUOTE wrapper from a cookie value.

RFC 6265 allows a quoted form; the quotes are part of the syntax, not the value.
*/
@(private)
trim_cookie_quotes :: proc(s: string) -> string {
	if len(s) >= 2 && s[0] == '"' && s[len(s) - 1] == '"' {
		return s[1:len(s) - 1]
	}
	return s
}

/*
A cookie name must be a `token`, the same production as a header field name.

This excludes the separators that would let a name break out of its pair, such
as '=' and ';'.
*/
@(private)
is_cookie_name :: proc(s: string) -> bool {
	return is_token(s)
}

/*
cookie-octet excludes CTLs, whitespace, DQUOTE, comma, semicolon, and backslash.

Comma and semicolon are the attribute and pair separators, so allowing them
would let a value forge attributes such as `; HttpOnly` or inject a second
cookie. CR and LF would split the header entirely.
*/
@(private)
is_cookie_value :: proc(s: string) -> bool {
	// An empty value is legitimate and is how a cookie is deleted.
	v := trim_cookie_quotes(s)
	for i in 0..<len(v) {
		c := v[i]
		if c < 0x21 || c > 0x7E { return false }
		switch c {
		case '"', ',', ';', '\\': return false
		}
	}
	return true
}

/*
Attribute values (Domain, Path) may not contain the separators or controls that
would let them terminate the attribute early.
*/
@(private)
is_cookie_attr :: proc(s: string) -> bool {
	for i in 0..<len(s) {
		c := s[i]
		if c < 0x20 || c == 0x7F { return false }
		if c == ';' || c == ','  { return false }
	}
	return true
}
