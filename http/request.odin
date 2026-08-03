package http

import "core:mem"
import "core:net"
import "core:strings"

/*
A parsed HTTP request.

All string fields borrow from the connection's read buffer and stay valid for
the lifetime of the request. Copy anything that needs to outlive the handler.
*/
Request :: struct {
	method:   Method,
	// The raw request-target, exactly as it appeared on the wire.
	target:   string,
	version:  Version,
	headers:  Headers,

	// Populated lazily by `request_url`; parsing is skipped for handlers that
	// only look at the target.
	_url:     Maybe(URL),

	has_body: bool,
	// The decoded body. Empty until the server has finished reading it.
	body:     string,

	// The peer address, for logging and rate limiting.
	client:   net.Endpoint,

	// Path parameters captured by the router, if one is in use.
	params:   Params,
}

// Returns a path parameter captured by the router, e.g. "id" for "/users/{id}".
request_param :: #force_inline proc(r: ^Request, name: string) -> (value: string, ok: bool) #optional_ok {
	return params_get(r.params, name)
}

request_init :: proc(r: ^Request, allocator: mem.Allocator) {
	r^ = {}
	headers_init(&r.headers, allocator)
}

/*
Copies every borrowed string into `allocator`, so the request no longer aliases
the buffer it was parsed from.

The parser borrows from the caller's read buffer, which is what makes it
allocation-free. That is safe only while the buffer holds the request. A body
larger than the buffer forces the driver to recycle it mid-request, at which
point the target and headers would point at body bytes — the routed path would
be attacker-controlled.

Called once, right after the headers are parsed and before any further reads.
Header values that were already copied (folded keys, joined duplicates) are
copied again; that is a handful of small allocations on a path that has just
read a full header block, and the arena reclaims them with the request.
*/
request_detach :: proc(r: ^Request, allocator: mem.Allocator) {
	r.target = strings.clone(r.target, allocator)

	for &entry in r.headers.entries {
		if len(entry.name) == 0 { continue }
		entry.name  = strings.clone(entry.name, allocator)
		entry.value = strings.clone(entry.value, allocator)
	}

	// The index keys must match the cloned names, not the originals.
	clear(&r.headers._index)
	for entry, i in r.headers.entries {
		if len(entry.name) == 0 { continue }
		if entry.name == "set-cookie" { continue }
		if _, existing := r.headers._index[entry.name]; existing { continue }
		r.headers._index[entry.name] = i
	}
}

// Returns the Host header, which HTTP/1.1 requires to be present.
request_host :: proc(r: ^Request) -> string {
	host, _ := headers_get(r.headers, "host")
	return host
}

/*
Returns the parsed request-target, parsing on first use.

Handlers that only need the raw target never pay for this.
*/
request_url :: proc(r: ^Request, allocator := context.temp_allocator) -> URL {
	if u, ok := r._url.?; ok { return u }
	u := url_parse(r.target, allocator)
	r._url = u
	return u
}

/*
Returns the decoded query-string parameters.

Go spells this `r.URL.Query()`. Values are percent-decoded and '+' is a space,
per application/x-www-form-urlencoded — the encoding a browser uses for a query
string, whatever the path-decoding rules say.

Repeated keys keep the first occurrence. A pair whose key or value is malformed
is skipped rather than aborting the whole query, so one bad parameter does not
discard the rest.

	if page, ok := http.request_query(req)["page"]; ok { ... }
*/
request_query :: proc(r: ^Request, allocator := context.temp_allocator) -> map[string]string {
	u := request_url(r, allocator)
	return query_parse(u.raw_query, allocator)
}

/*
Returns the decoded form body of a urlencoded request.

Go's `r.PostFormValue` covers this. Only `application/x-www-form-urlencoded` is
parsed: `multipart/form-data` needs a boundary-aware reader and is not
implemented, so it yields an empty map rather than a partial parse of bytes that
are not urlencoded at all.

The content type is checked before parsing because a body of any other type —
JSON, say — is not key/value pairs, and treating it as though it were would
produce plausible-looking nonsense instead of nothing.

	name := http.request_form(req)["name"]
*/
request_form :: proc(r: ^Request, allocator := context.temp_allocator) -> map[string]string {
	empty: map[string]string
	empty.allocator = allocator

	ct, has := headers_get(r.headers, "content-type")
	if !has { return empty }

	// The type may carry parameters, as in "...; charset=utf-8".
	semi := index_byte(ct, ';')
	base := trim_ows(ct if semi < 0 else ct[:semi])
	if !equal_fold(base, "application/x-www-form-urlencoded") { return empty }

	return query_parse(r.body, allocator)
}

/*
Returns the request path: the target with any absolute-form prefix, query, and
fragment removed.

RFC 9112 3.2 defines four target forms and a server must handle three of them:

  - origin-form     `/where?q=now`      the common case
  - absolute-form   `http://h/where`    required of every server (3.2.2), since
                                        this is how a proxy forwards a request
  - asterisk-form   `*`                 server-wide OPTIONS
  - authority-form  `host:port`         CONNECT only, not supported here

Routing on the raw target means an absolute-form request matches no route and
404s, so a server that only handles origin-form cannot sit behind a proxy.
*/
request_path :: proc(r: ^Request) -> string {
	target := r.target

	// Asterisk-form has no path to speak of; report it verbatim so a caller can
	// recognise it rather than seeing an empty string.
	if target == "*" { return target }

	// absolute-form: drop scheme and authority, keeping the path onwards. The
	// authority is not used for routing — Host is the authoritative source, and
	// trusting the target instead would let a request claim any host.
	if i := strings.index(target, "://"); i >= 0 {
		after := target[i + 3:]
		if slash := index_byte(after, '/'); slash >= 0 {
			target = after[slash:]
		} else {
			// "http://example.com" with no path means the root.
			return "/"
		}
	}

	if i := index_byte(target, '?'); i >= 0 {
		target = target[:i]
	}
	if i := index_byte(target, '#'); i >= 0 {
		target = target[:i]
	}
	return target
}

// Reports whether the target was the asterisk-form used by server-wide OPTIONS.
request_is_asterisk :: #force_inline proc(r: ^Request) -> bool {
	return r.target == "*"
}
