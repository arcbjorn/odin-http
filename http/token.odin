package http

/*
Character classification for HTTP grammar (RFC 9110 5.6.2, RFC 5234 B.1).

These tables are the security foundation of the parser. Nearly every HTTP
request smuggling technique works by getting two implementations to disagree
about whether some byte sequence is valid. The defense is to be strict at the
edge: reject anything that is not unambiguously well-formed, rather than
guessing at intent.
*/

/*
tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
        "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
*/
@(rodata)
is_tchar_table := [256]bool {
	'!' = true, '#' = true, '$'  = true, '%' = true, '&' = true,
	'\''= true, '*' = true, '+'  = true, '-' = true, '.' = true,
	'^' = true, '_' = true, '`'  = true, '|' = true, '~' = true,

	'0' = true, '1' = true, '2' = true, '3' = true, '4' = true,
	'5' = true, '6' = true, '7' = true, '8' = true, '9' = true,

	'a' = true, 'b' = true, 'c' = true, 'd' = true, 'e' = true, 'f' = true,
	'g' = true, 'h' = true, 'i' = true, 'j' = true, 'k' = true, 'l' = true,
	'm' = true, 'n' = true, 'o' = true, 'p' = true, 'q' = true, 'r' = true,
	's' = true, 't' = true, 'u' = true, 'v' = true, 'w' = true, 'x' = true,
	'y' = true, 'z' = true,

	'A' = true, 'B' = true, 'C' = true, 'D' = true, 'E' = true, 'F' = true,
	'G' = true, 'H' = true, 'I' = true, 'J' = true, 'K' = true, 'L' = true,
	'M' = true, 'N' = true, 'O' = true, 'P' = true, 'Q' = true, 'R' = true,
	'S' = true, 'T' = true, 'U' = true, 'V' = true, 'W' = true, 'X' = true,
	'Y' = true, 'Z' = true,
}

is_tchar :: #force_inline proc(c: byte) -> bool {
	return is_tchar_table[c]
}

// Reports whether the whole string is a valid `token` (at least one tchar).
is_token :: proc(s: string) -> bool {
	if len(s) == 0 { return false }
	for i in 0..<len(s) {
		if !is_tchar_table[s[i]] { return false }
	}
	return true
}

/*
Reports whether c is valid in a field value.

field-vchar = VCHAR / obs-text, plus SP and HTAB as optional whitespace.
Critically this excludes CR, LF and NUL: embedding those in a header value is
the response-splitting primitive.
*/
is_field_vchar :: #force_inline proc(c: byte) -> bool {
	return c == '\t' || (c >= 0x20 && c != 0x7F)
}

// Reports whether the whole string is a legal header field value.
is_field_value :: proc(s: string) -> bool {
	for i in 0..<len(s) {
		if !is_field_vchar(s[i]) { return false }
	}
	return true
}

is_ows :: #force_inline proc(c: byte) -> bool {
	return c == ' ' || c == '\t'
}

// Trims leading and trailing optional whitespace (SP / HTAB) from a field value.
trim_ows :: proc(s: string) -> string {
	start := 0
	for start < len(s) && is_ows(s[start]) {
		start += 1
	}
	end := len(s)
	for end > start && is_ows(s[end - 1]) {
		end -= 1
	}
	return s[start:end]
}

/*
ASCII-only lowercase of a single byte.

Header field names are case-insensitive but restricted to ASCII, so a
locale-independent ASCII fold is both correct and branch-predictable.
*/
to_lower_ascii :: #force_inline proc(c: byte) -> byte {
	return c + 32 if c >= 'A' && c <= 'Z' else c
}

// Case-insensitive ASCII comparison, used for header names and token values.
equal_fold :: proc(a, b: string) -> bool {
	if len(a) != len(b) { return false }
	for i in 0..<len(a) {
		if to_lower_ascii(a[i]) != to_lower_ascii(b[i]) { return false }
	}
	return true
}

/*
Parses a non-negative decimal integer with no tolerance for the forms the
grammar does not allow.

`strconv.parse_int` accepts leading '+'/'-', underscores as digit separators,
and other conveniences that are wrong here: "+5" and "5" must not both be
accepted as a Content-Length, because a peer that disagrees about which are
valid gives an attacker a desync. Overflow returns false rather than wrapping.
*/
parse_decimal :: proc(s: string) -> (n: int, ok: bool) {
	if len(s) == 0 { return 0, false }

	MAX :: int(max(i64))
	for i in 0..<len(s) {
		c := s[i]
		if !is_digit(c) { return 0, false }

		d := int(c - '0')
		if n > (MAX - d) / 10 { return 0, false }
		n = n * 10 + d
	}
	return n, true
}

/*
Parses a hexadecimal chunk size.

Same reasoning as `parse_decimal`: no "0x" prefix, no sign, no separators.
A chunk size of `0x10` must be a parse error, not 16.
*/
parse_hex :: proc(s: string) -> (n: int, ok: bool) {
	if len(s) == 0 { return 0, false }

	MAX :: int(max(i64))
	for i in 0..<len(s) {
		c := s[i]
		d: int
		switch {
		case c >= '0' && c <= '9': d = int(c - '0')
		case c >= 'a' && c <= 'f': d = int(c - 'a') + 10
		case c >= 'A' && c <= 'F': d = int(c - 'A') + 10
		case:                      return 0, false
		}

		if n > (MAX - d) / 16 { return 0, false }
		n = n * 16 + d
	}
	return n, true
}
