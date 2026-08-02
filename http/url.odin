package http

import "core:mem"
import "core:strings"

/*
A parsed request-target.

Fields borrow from the input string; only `query` values that require
percent-decoding allocate.
*/
URL :: struct {
	// Path with percent-escapes still intact, as received.
	raw_path: string,
	// Percent-decoded path. Use this for routing and never for filesystem
	// access without `url_path_is_safe`.
	path:     string,
	// Raw query string, without the leading '?'.
	raw_query: string,
	fragment: string,
}

/*
Parses a request-target into its components.

Only origin-form ("/path?query") and absolute-form ("http://host/path") are
recognised, which together cover every request a server sees in practice.
*/
url_parse :: proc(target: string, allocator := context.temp_allocator) -> (u: URL) {
	rest := target

	// absolute-form: strip scheme and authority, keeping the path onwards.
	if i := strings.index(rest, "://"); i >= 0 {
		after := rest[i + 3:]
		if slash := index_byte(after, '/'); slash >= 0 {
			rest = after[slash:]
		} else {
			rest = "/"
		}
	}

	if i := index_byte(rest, '#'); i >= 0 {
		u.fragment = rest[i + 1:]
		rest = rest[:i]
	}

	if i := index_byte(rest, '?'); i >= 0 {
		u.raw_query = rest[i + 1:]
		rest = rest[:i]
	}

	u.raw_path = rest
	u.path = percent_decode(rest, allocator) or_else rest
	return
}

/*
Percent-decodes a string.

Returns the input unchanged when it contains no escapes, which avoids an
allocation on the overwhelming majority of paths. Invalid escapes fail rather
than being passed through: "%2" or "%zz" reaching a filesystem path is how
decoders end up disagreeing.

'+' is deliberately NOT decoded as a space here. That rule belongs to
application/x-www-form-urlencoded, not to paths, and applying it to a path
corrupts filenames that legitimately contain '+'.
*/
percent_decode :: proc(s: string, allocator := context.temp_allocator) -> (decoded: string, ok: bool) {
	count := 0
	for i in 0..<len(s) {
		if s[i] == '%' { count += 1 }
	}
	if count == 0 { return s, true }

	buf := make([]byte, len(s) - count * 2, allocator)
	w := 0
	for i := 0; i < len(s); {
		if s[i] != '%' {
			buf[w] = s[i]
			w += 1
			i += 1
			continue
		}

		if i + 2 >= len(s) { return "", false }
		hi := hex_value(s[i + 1]) or_return
		lo := hex_value(s[i + 2]) or_return

		buf[w] = hi << 4 | lo
		w += 1
		i += 3
	}
	return string(buf[:w]), true
}

@(private)
hex_value :: proc(c: byte) -> (v: byte, ok: bool) {
	switch {
	case c >= '0' && c <= '9': return c - '0', true
	case c >= 'a' && c <= 'f': return c - 'a' + 10, true
	case c >= 'A' && c <= 'F': return c - 'A' + 10, true
	}
	return 0, false
}

/*
Reports whether a decoded path is safe to join to a filesystem root.

Rejects absolute-looking escapes, parent traversal, NUL bytes, and backslashes.
This must run on the DECODED path: checking before decoding is the classic
bypass, since "%2e%2e%2f" only becomes "../" afterwards.

Backslash is rejected because Windows treats it as a separator, so a path that
looks harmless on Linux can escape the root on another platform.
*/
url_path_is_safe :: proc(path: string) -> bool {
	if !path_has_safe_bytes(path) { return false }

	// Walk segments, rejecting any "..".
	start := 1
	for i := 1; i <= len(path); i += 1 {
		if i == len(path) || path[i] == '/' {
			seg := path[start:i]
			if seg == ".." { return false }
			start = i + 1
		}
	}
	return true
}

/*
Reports whether a path is absolute and free of bytes that are dangerous
wherever they appear.

Split out from `url_path_is_safe` because these rules hold before normalization,
whereas ".." is only meaningful after it: "/a/b/../c" is a legitimate path that
cleans to "/a/c".

NUL is rejected because it truncates a path in any C filesystem API, so
"safe.txt\0../../etc/passwd" would pass a naive suffix check and then open
something else entirely. Backslash is rejected because Windows treats it as a
separator, making a path that looks contained on Linux escape elsewhere.
*/
path_has_safe_bytes :: proc(path: string) -> bool {
	if len(path) == 0 { return false }
	if path[0] != '/' { return false }

	for i in 0..<len(path) {
		c := path[i]
		if c == 0    { return false }
		if c == '\\' { return false }
	}
	return true
}

/*
Parses an application/x-www-form-urlencoded string into a map.

Here '+' does decode to a space, per the form-encoding rules.
*/
query_parse :: proc(query: string, allocator := context.temp_allocator) -> (values: map[string]string) {
	values.allocator = allocator
	if len(query) == 0 { return }

	start := 0
	for i := 0; i <= len(query); i += 1 {
		if i != len(query) && query[i] != '&' { continue }

		pair := query[start:i]
		start = i + 1
		if len(pair) == 0 { continue }

		key, val: string
		if eq := index_byte(pair, '='); eq >= 0 {
			key, val = pair[:eq], pair[eq + 1:]
		} else {
			key, val = pair, ""
		}

		dk := form_decode(key, allocator) or_continue
		dv := form_decode(val, allocator) or_continue
		values[dk] = dv
	}
	return
}

@(private)
form_decode :: proc(s: string, allocator: mem.Allocator) -> (decoded: string, ok: bool) {
	has_plus := index_byte(s, '+') >= 0
	if !has_plus {
		return percent_decode(s, allocator)
	}

	swapped := make([]byte, len(s), allocator)
	for i in 0..<len(s) {
		swapped[i] = ' ' if s[i] == '+' else s[i]
	}
	return percent_decode(string(swapped), allocator)
}
