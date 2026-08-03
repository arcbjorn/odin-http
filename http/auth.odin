package http

import "core:crypto"
import "core:encoding/base64"
import "core:strings"

/*
HTTP Basic authentication (RFC 7617).

Go exposes this as `r.BasicAuth()` plus a hand-written comparison; the
comparison is the part that goes wrong, so `basic_auth_check` is provided
alongside the parser rather than left to the caller.

Basic auth sends the password in cleartext, base64 being an encoding and not a
cipher. It is only safe over TLS, and `basic_auth_required` says so by refusing
to be useful on its own.
*/

Basic_Auth :: struct {
	username: string,
	password: string,
}

/*
Parses an `Authorization: Basic` header.

Returns ok=false when the header is absent, names a different scheme, or does
not decode — never a partially-parsed credential, since a caller that gets
`("admin", "")` from malformed input may well compare it against something.

The scheme token is matched case-insensitively (RFC 9110 11.1 makes it a
case-insensitive token), which real clients rely on: "Basic" and "basic" are
both deployed.
*/
request_basic_auth :: proc(
	r: ^Request,
	allocator := context.temp_allocator,
) -> (auth: Basic_Auth, ok: bool) {
	header := headers_get(r.headers, "authorization") or_return

	value := trim_ows(header)
	sp := index_byte(value, ' ')
	if sp < 0 { return {}, false }

	if !equal_fold(value[:sp], "basic") { return {}, false }

	encoded := trim_ows(value[sp + 1:])
	if len(encoded) == 0 { return {}, false }

	decoded, err := base64.decode(encoded, base64.DEC_TABLE, nil, allocator)
	if err != nil { return {}, false }

	// user-pass = userid ":" password. The userid may not contain a colon, so
	// the first one delimits; any later colons belong to the password.
	text := string(decoded)
	colon := index_byte(text, ':')
	if colon < 0 { return {}, false }

	return Basic_Auth{username = text[:colon], password = text[colon + 1:]}, true
}

/*
Compares credentials without leaking their contents through timing.

A byte-by-byte `==` returns as soon as it finds a mismatch, so the time taken
reveals how many leading bytes were correct. That is enough to recover a secret
one byte at a time over enough requests, which is why this exists as a named
procedure rather than as advice in a doc comment.

Both fields are compared even when the username has already failed, so the work
done does not depend on which field was wrong.
*/
basic_auth_check :: proc(auth: Basic_Auth, username: string, password: string) -> bool {
	u := crypto.compare_constant_time(transmute([]byte)auth.username, transmute([]byte)username)
	p := crypto.compare_constant_time(transmute([]byte)auth.password, transmute([]byte)password)
	return u == 1 && p == 1
}

/*
Answers 401 with a `WWW-Authenticate` challenge.

RFC 9110 11.6.1 requires the challenge: a 401 without one tells a client it was
refused but not how to authenticate, so browsers show an error page instead of a
credential prompt.

`realm` names the protection space. It is written into a quoted-string, so a
realm containing a quote or a control character would let the header be forged;
such a realm is replaced rather than escaped, because a caller passing one has a
bug worth surfacing at the point it appears.
*/
basic_auth_required :: proc(res: ^Response, realm := "restricted") {
	safe := realm
	for i in 0 ..< len(realm) {
		c := realm[i]
		if c == '"' || c == '\\' || c < 0x20 || c == 0x7F {
			safe = "restricted"
			break
		}
	}

	challenge := strings.concatenate({`Basic realm="`, safe, `", charset="UTF-8"`},
		res.headers.allocator)

	headers_set(&res.headers, "www-authenticate", challenge)
	respond_status(res, .Unauthorized)
}

/*
Builds the `Authorization` header value a client sends.

Provided so the client side does not have to reimplement the encoding, and so
the colon rule is enforced in one place: a username containing ':' cannot be
represented, and encoding it anyway would silently move part of the username
into the password.
*/
basic_auth_header :: proc(
	username: string,
	password: string,
	allocator := context.temp_allocator,
) -> (value: string, ok: bool) {
	if index_byte(username, ':') >= 0 { return "", false }

	joined := strings.concatenate({username, ":", password}, allocator)
	encoded := base64.encode(transmute([]byte)joined, base64.ENC_TABLE, allocator)
	return strings.concatenate({"Basic ", encoded}, allocator), true
}
