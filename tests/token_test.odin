package tests

import "core:testing"

import http "../http"

/*
HTTP grammar classification (RFC 9110 5.6.2).

`token.odin` calls itself the security foundation of the parser, and it is: every
header name, every header value and every length on the wire passes through
these predicates. They had no dedicated tests, which is the worst place in the
library for that to be true — a validator that is too permissive does not fail
loudly, it just lets something through.

Request smuggling generally works by getting two implementations to disagree
about whether a byte sequence is well formed, so the cases below are chosen to
be the ones a lenient parser would accept.
*/

@(test)
test_is_token_accepts_tchar_only :: proc(t: ^testing.T) {
	testing.expect(t, http.is_token("content-type"), "a normal field name")
	testing.expect(t, http.is_token("X-Custom_Header~1"), "the odd tchars are legal")
	testing.expect(t, http.is_token("!#$%&'*+-.^_`|~"), "every punctuation tchar")

	// An empty token is not a token: `token = 1*tchar`.
	testing.expect(t, !http.is_token(""), "")

	// Separators are what a name would have to contain to break out of its own
	// field, so each one must be refused.
	for bad in ([]string{"a b", "a:b", "a,b", "a;b", "a=b", "a(b", "a/b", "a@b", `a"b`}) {
		testing.expect(t, !http.is_token(bad), "separators are not tchars")
	}

	// Control and high bytes are outside the table entirely.
	testing.expect(t, !http.is_token("a\x00b"), "NUL")
	testing.expect(t, !http.is_token("a\nb"), "LF")
	testing.expect(t, !http.is_token("a\x80"), "obs-text is not a tchar")
}

/*
Field values admit obs-text but never CR, LF or NUL.

The high bytes are deliberate: RFC 9110 allows obs-text (0x80-0xFF) in a field
value, and rejecting it would break legitimate traffic carrying legacy encodings.
CR and LF are the response-splitting primitive and must never pass.
*/
@(test)
test_is_field_value_rejects_only_the_dangerous_bytes :: proc(t: ^testing.T) {
	testing.expect(t, http.is_field_value("text/plain; charset=utf-8"), "")
	testing.expect(t, http.is_field_value("a\tb"), "HTAB is legal inside a value")
	testing.expect(t, http.is_field_value("caf\xc3\xa9"), "obs-text must be allowed")
	testing.expect(t, http.is_field_value("\x80\xff"), "the whole obs-text range")

	// An empty value is legal; a header may carry no bytes at all.
	testing.expect(t, http.is_field_value(""), "")

	testing.expect(t, !http.is_field_value("a\rb"), "CR splits the header")
	testing.expect(t, !http.is_field_value("a\nb"), "LF splits the header")
	testing.expect(t, !http.is_field_value("a\x00b"), "NUL truncates in C consumers")
	testing.expect(t, !http.is_field_value("a\x7Fb"), "DEL is a control character")

	// The classic injection payload, which must be refused whole.
	testing.expect(t, !http.is_field_value("x\r\nSet-Cookie: admin=1"), "response splitting")
}

/*
`parse_decimal` accepts exactly the digits and nothing else.

`strconv.parse_int` would take "+5", "5_0" and "0x10". A Content-Length parsed
leniently by one hop and strictly by another is a request-smuggling desync, so
each of those forms must be a hard error rather than a value.
*/
@(test)
test_parse_decimal_rejects_lenient_forms :: proc(t: ^testing.T) {
	n, ok := http.parse_decimal("0")
	testing.expect(t, ok, "")
	testing.expect_value(t, n, 0)

	n2, ok2 := http.parse_decimal("1234567890")
	testing.expect(t, ok2, "")
	testing.expect_value(t, n2, 1234567890)

	for bad in ([]string{"", "+5", "-5", "5_0", "0x10", " 5", "5 ", "5.0", "1e3", "abc"}) {
		_, bad_ok := http.parse_decimal(bad)
		testing.expect(t, !bad_ok, "only bare digits are a decimal")
	}
}

// Overflow must be refused rather than wrapped: a wrapped Content-Length would
// frame the next request at an attacker-chosen offset.
@(test)
test_parse_decimal_refuses_overflow :: proc(t: ^testing.T) {
	max_ok, ok := http.parse_decimal("9223372036854775807")
	testing.expect(t, ok, "i64 max must parse")
	testing.expect_value(t, max_ok, 9223372036854775807)

	for over in ([]string{"9223372036854775808", "99999999999999999999",
	                      "179769313486231570000000000000000000000"}) {
		_, over_ok := http.parse_decimal(over)
		testing.expect(t, !over_ok, "overflow must fail, not wrap")
	}
}

/*
`parse_hex` reads a chunk size, with the same strictness.

"0x10" must be an error rather than 16: a hop that accepts the prefix and one
that does not will disagree about where the next chunk begins.
*/
@(test)
test_parse_hex_rejects_lenient_forms :: proc(t: ^testing.T) {
	n, ok := http.parse_hex("ff")
	testing.expect(t, ok, "")
	testing.expect_value(t, n, 255)

	upper, upper_ok := http.parse_hex("FF")
	testing.expect(t, upper_ok, "hex is case-insensitive")
	testing.expect_value(t, upper, 255)

	for bad in ([]string{"", "0x10", "+f", "-f", "f f", "g", "ff ", " ff"}) {
		_, bad_ok := http.parse_hex(bad)
		testing.expect(t, !bad_ok, "only bare hex digits are a chunk size")
	}
}

@(test)
test_parse_hex_refuses_overflow :: proc(t: ^testing.T) {
	max_ok, ok := http.parse_hex("7fffffffffffffff")
	testing.expect(t, ok, "i64 max must parse")
	testing.expect_value(t, max_ok, 9223372036854775807)

	// One past the top bit: the next value would wrap negative.
	_, over := http.parse_hex("8000000000000000")
	testing.expect(t, !over, "overflow must fail, not wrap")

	_, way_over := http.parse_hex("ffffffffffffffffff")
	testing.expect(t, !way_over, "")
}

@(test)
test_trim_ows_strips_only_sp_and_htab :: proc(t: ^testing.T) {
	testing.expect_value(t, http.trim_ows("  value  "), "value")
	testing.expect_value(t, http.trim_ows("\tvalue\t"), "value")
	testing.expect_value(t, http.trim_ows(" \t value \t "), "value")
	testing.expect_value(t, http.trim_ows("value"), "value")
	testing.expect_value(t, http.trim_ows(""), "")
	testing.expect_value(t, http.trim_ows("   "), "")

	// Interior whitespace is part of the value.
	testing.expect_value(t, http.trim_ows("  a b  "), "a b")

	// OWS is SP and HTAB only: CR and LF are not whitespace to be trimmed away,
	// since silently accepting them here would undo the field-value check.
	testing.expect_value(t, http.trim_ows("\r\nvalue"), "\r\nvalue")
}

// Header names compare case-insensitively, but only over ASCII: a locale fold
// would make matching depend on the environment.
@(test)
test_equal_fold_is_ascii_case_insensitive :: proc(t: ^testing.T) {
	testing.expect(t, http.equal_fold("Content-Type", "content-type"), "")
	testing.expect(t, http.equal_fold("CONTENT-TYPE", "content-type"), "")
	testing.expect(t, http.equal_fold("", ""), "")

	testing.expect(t, !http.equal_fold("content-type", "content-length"), "")
	testing.expect(t, !http.equal_fold("abc", "ab"), "length must match first")

	// Bytes adjacent to the alphabetic range must not fold into it. '[' is 'Z'+1
	// and '{' is 'z'+1, which a naive |0x20 fold would conflate.
	testing.expect(t, !http.equal_fold("[", "{"), "only A-Z folds")
	testing.expect(t, !http.equal_fold("@", "`"), "")
}
