package tests

import "core:encoding/base64"
import "core:os"
import "core:strings"
import "core:testing"

import http "../http"

/*
HTTP Basic authentication (RFC 7617).

Go leaves the credential comparison to the caller, which is where it goes wrong:
a `==` on secrets returns early on the first mismatched byte and leaks how many
leading bytes were correct. `basic_auth_check` exists so that comparison happens
once, in constant time, rather than in every handler that needs it.
*/

@(private)
auth_request :: proc(header: string) -> http.Request {
	req: http.Request
	http.request_init(&req, context.temp_allocator)
	if len(header) > 0 {
		http.headers_set(&req.headers, "authorization", header)
	}
	return req
}

@(private)
auth_encode :: proc(user, pass: string) -> string {
	joined := strings.concatenate({user, ":", pass}, context.temp_allocator)
	enc := base64.encode(transmute([]byte)joined, base64.ENC_TABLE, context.temp_allocator)
	return strings.concatenate({"Basic ", enc}, context.temp_allocator)
}

@(test)
test_basic_auth_parses_credentials :: proc(t: ^testing.T) {
	req := auth_request(auth_encode("ada", "s3cret"))

	auth, ok := http.request_basic_auth(&req, context.temp_allocator)
	testing.expect(t, ok, "a well-formed header must parse")
	testing.expect_value(t, auth.username, "ada")
	testing.expect_value(t, auth.password, "s3cret")
}

/*
The scheme token is case-insensitive (RFC 9110 11.1).

Both spellings are deployed, so matching only "Basic" would reject real clients.
*/
@(test)
test_basic_auth_scheme_is_case_insensitive :: proc(t: ^testing.T) {
	for scheme in ([]string{"Basic", "basic", "BASIC", "BaSiC"}) {
		enc := base64.encode(transmute([]byte)string("u:p"), base64.ENC_TABLE,
			context.temp_allocator)
		header := strings.concatenate({scheme, " ", enc}, context.temp_allocator)

		req := auth_request(header)
		auth, ok := http.request_basic_auth(&req, context.temp_allocator)
		testing.expectf(t, ok, "scheme %q must be accepted", scheme)
		testing.expect_value(t, auth.username, "u")
	}
}

/*
Only the first colon delimits.

RFC 7617 forbids a colon in the userid but allows one in the password, so
splitting on the last colon — or rejecting extra ones — breaks passwords that
legitimately contain them.
*/
@(test)
test_basic_auth_password_may_contain_colons :: proc(t: ^testing.T) {
	req := auth_request(auth_encode("ada", "a:b:c"))

	auth, ok := http.request_basic_auth(&req, context.temp_allocator)
	testing.expect(t, ok, "")
	testing.expect_value(t, auth.username, "ada")
	testing.expect_value(t, auth.password, "a:b:c")
}

// An empty password is legal and must not be confused with a parse failure.
@(test)
test_basic_auth_allows_empty_password :: proc(t: ^testing.T) {
	req := auth_request(auth_encode("ada", ""))

	auth, ok := http.request_basic_auth(&req, context.temp_allocator)
	testing.expect(t, ok, "an empty password is legal")
	testing.expect_value(t, auth.username, "ada")
	testing.expect_value(t, auth.password, "")
}

/*
Malformed input yields no credential at all.

Returning a partially-parsed pair would be worse than failing: a caller that
gets `("admin", "")` from garbage may compare it against something and let it
through.
*/
@(test)
test_basic_auth_rejects_malformed :: proc(t: ^testing.T) {
	cases := []string{
		"",                          // header absent
		"Basic",                     // scheme with no credential
		"Basic ",                    // scheme with empty credential
		"Bearer abc123",             // a different scheme
		"Basic !!!not-base64!!!",    // undecodable
		"Basic " + "bm9jb2xvbg==",   // decodes to "nocolon": no delimiter
		"Digest username=\"ada\"",   // another scheme entirely
	}

	for header in cases {
		req := auth_request(header)
		_, ok := http.request_basic_auth(&req, context.temp_allocator)
		testing.expectf(t, !ok, "header %q must not parse", header)
	}
}

/*
`basic_auth_check` accepts only an exact match on both fields.

The constant-time property cannot be asserted by a timing measurement without
flakiness, so what is pinned here is correctness; the guarantee itself comes
from `crypto.compare_constant_time`, which is used precisely so this test does
not have to prove it.
*/
@(test)
test_basic_auth_check_matches_exactly :: proc(t: ^testing.T) {
	auth := http.Basic_Auth{username = "ada", password = "s3cret"}

	testing.expect(t, http.basic_auth_check(auth, "ada", "s3cret"), "exact match")

	testing.expect(t, !http.basic_auth_check(auth, "ada", "s3cre"), "short password")
	testing.expect(t, !http.basic_auth_check(auth, "ada", "s3cretx"), "long password")
	testing.expect(t, !http.basic_auth_check(auth, "Ada", "s3cret"), "username is case-sensitive")
	testing.expect(t, !http.basic_auth_check(auth, "eve", "s3cret"), "wrong username")
	testing.expect(t, !http.basic_auth_check(auth, "", ""), "empty credentials")

	// A prefix must not match: a length-insensitive compare would be the
	// classic way to make this wrong.
	testing.expect(t, !http.basic_auth_check(auth, "ad", "s3cret"), "username prefix")
}

/*
A 401 must carry a challenge (RFC 9110 11.6.1).

Without `WWW-Authenticate` a browser shows an error page rather than a
credential prompt, so the response is refused but unusable.
*/
@(test)
test_basic_auth_required_sends_challenge :: proc(t: ^testing.T) {
	rec: http.Recorder
	if err := http.recorder_init(&rec, .Get, "/"); err != nil {
		testing.fail_now(t, "could not init recorder")
	}
	defer http.recorder_destroy(&rec)

	http.basic_auth_required(&rec.res, "admin area")

	raw := http.recorder_raw_response(&rec)
	testing.expect(t, strings.contains(raw, "401 Unauthorized"), "")
	testing.expect(t, strings.contains(raw, `www-authenticate: Basic realm="admin area"`),
		"the challenge must name the realm")
}

/*
A realm that would break out of its quoted-string is replaced, not escaped.

A quote or CR in the realm is a header-injection primitive; substituting a safe
default surfaces the caller's bug without emitting a forged header.
*/
@(test)
test_basic_auth_realm_cannot_inject :: proc(t: ^testing.T) {
	for hostile in ([]string{`a" evil="1`, "a\r\nX-Injected: 1", "a\x00b"}) {
		rec: http.Recorder
		if err := http.recorder_init(&rec, .Get, "/"); err != nil {
			testing.fail_now(t, "could not init recorder")
		}
		defer http.recorder_destroy(&rec)

		http.basic_auth_required(&rec.res, hostile)

		raw := http.recorder_raw_response(&rec)
		testing.expect(t, !strings.contains(raw, "X-Injected"), "no forged header")
		testing.expect(t, strings.contains(raw, `realm="restricted"`),
			"a hostile realm falls back to the default")
	}
}

/*
The client-side encoder round-trips with the parser.

Sharing one implementation is what keeps the two from drifting: a client that
encodes differently than the server parses is a bug neither side's unit tests
would show.
*/
@(test)
test_basic_auth_header_round_trips :: proc(t: ^testing.T) {
	header, ok := http.basic_auth_header("ada", "p:ss word", context.temp_allocator)
	testing.expect(t, ok, "")

	req := auth_request(header)
	auth, parsed := http.request_basic_auth(&req, context.temp_allocator)

	testing.expect(t, parsed, "what the client encodes, the server must parse")
	testing.expect_value(t, auth.username, "ada")
	testing.expect_value(t, auth.password, "p:ss word")
}

// A username containing ':' cannot be represented, so encoding is refused
// rather than silently moving part of it into the password.
@(test)
test_basic_auth_header_rejects_colon_in_username :: proc(t: ^testing.T) {
	_, ok := http.basic_auth_header("ad:a", "secret", context.temp_allocator)
	testing.expect(t, !ok, "a colon in the userid has no representation")
}

/*
The comparison must stay constant-time.

No functional test can tell `crypto.compare_constant_time` from `==`: both
accept exactly the right credential and reject everything else. A timing
measurement would be flaky enough to be worse than useless in CI.

So this asserts the implementation rather than the behaviour. It is a blunt
instrument, and deliberately so — swapping in `==` is a one-character edit that
reintroduces a byte-at-a-time credential oracle while every other test in this
file keeps passing.
*/
@(test)
test_basic_auth_check_uses_constant_time_compare :: proc(t: ^testing.T) {
	// Tests run with the repository root as the working directory. Treating a
	// missing file as "skip" would make this assertion vanish silently, which
	// is the failure mode it exists to prevent.
	source, err := os.read_entire_file("http/auth.odin", context.temp_allocator)
	if err != nil {
		testing.fail_now(t, "could not read http/auth.odin")
	}

	body := string(source)
	start := strings.index(body, "basic_auth_check :: proc")
	testing.expect(t, start >= 0, "basic_auth_check must exist")

	rest := body[start:]
	end := strings.index(rest, "\n}")
	testing.expect(t, end >= 0, "")
	fn := rest[:end]

	testing.expect(t, strings.contains(fn, "compare_constant_time"),
		"basic_auth_check must compare in constant time")
	testing.expect(t, !strings.contains(fn, "auth.username == username"),
		"a direct string compare leaks credential contents through timing")
	testing.expect(t, !strings.contains(fn, "auth.password == password"),
		"a direct string compare leaks credential contents through timing")
}
