package http

Method :: enum u8 {
	Get,
	Head,
	Post,
	Put,
	Patch,
	Delete,
	Connect,
	Options,
	Trace,
}

@(rodata)
method_strings := [Method]string {
	.Get     = "GET",
	.Head    = "HEAD",
	.Post    = "POST",
	.Put     = "PUT",
	.Patch   = "PATCH",
	.Delete  = "DELETE",
	.Connect = "CONNECT",
	.Options = "OPTIONS",
	.Trace   = "TRACE",
}

method_string :: #force_inline proc(m: Method) -> string {
	return method_strings[m]
}

/*
Parses a method token.

Method names are case-sensitive (RFC 9110 9.1), so this does an exact match.
Comparing length first lets the common GET/POST cases resolve without a full
string scan.
*/
method_parse :: proc(s: string) -> (m: Method, ok: bool) {
	switch len(s) {
	case 3:
		switch s {
		case "GET": return .Get, true
		case "PUT": return .Put, true
		}
	case 4:
		switch s {
		case "HEAD": return .Head, true
		case "POST": return .Post, true
		}
	case 5:
		switch s {
		case "PATCH": return .Patch, true
		case "TRACE": return .Trace, true
		}
	case 6:
		switch s {
		case "DELETE": return .Delete, true
		}
	case 7:
		switch s {
		case "CONNECT": return .Connect, true
		case "OPTIONS": return .Options, true
		}
	}
	return {}, false
}

// Reports whether a request with this method is expected to carry a body.
method_can_have_body :: proc(m: Method) -> bool {
	#partial switch m {
	case .Get, .Head, .Delete, .Connect, .Options, .Trace: return false
	}
	return true
}

Version :: struct {
	major: u8,
	minor: u8,
}

/*
Parses an HTTP-version token, e.g. "HTTP/1.1".

RFC 9110 2.5 fixes the format at exactly 8 characters with single digits for
major and minor, so anything else is rejected rather than leniently accepted.
*/
version_parse :: proc(s: string) -> (v: Version, ok: bool) {
	if len(s) != 8               { return {}, false }
	if s[:5] != "HTTP/"          { return {}, false }
	if s[6] != '.'               { return {}, false }
	if !is_digit(s[5])           { return {}, false }
	if !is_digit(s[7])           { return {}, false }

	v.major = s[5] - '0'
	v.minor = s[7] - '0'
	return v, true
}

@(private)
is_digit :: #force_inline proc(c: byte) -> bool {
	return c >= '0' && c <= '9'
}
