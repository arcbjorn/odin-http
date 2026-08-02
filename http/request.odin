package http

import "core:mem"
import "core:net"

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

// Returns the request path with the query string removed.
request_path :: proc(r: ^Request) -> string {
	target := r.target
	if i := index_byte(target, '?'); i >= 0 {
		return target[:i]
	}
	if i := index_byte(target, '#'); i >= 0 {
		return target[:i]
	}
	return target
}
