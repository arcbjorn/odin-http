package http

import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:time"

/*
A blocking HTTP/1.1 client.

Shares the parser with the server, so framing and smuggling defences are the
same code rather than a second implementation that drifts, and shares
`Transport`, so HTTPS needs no client-specific handling.

Response bodies are buffered up to `limits.max_body`. Callers almost always want
the whole body, and an unbounded one is a denial-of-service vector against the
client itself.
*/

Client_Response :: struct {
	status:  Status,
	version: Version,
	headers: Headers,
	body:    string,

	// Set when the response was delimited by the connection closing, in which
	// case the connection cannot be reused.
	until_close: bool,
	/*
	Set when the peer sent bytes past the end of this response.

	This client does not pipeline, so it has exactly one request outstanding at
	a time: anything after the response was never asked for. Reusing such a
	connection lets those bytes become the *next* response — a forged reply the
	caller cannot distinguish from a real one. The connection is therefore
	retired rather than pooled.
	*/
	unsolicited_data: bool,
}

Client_Error :: enum u8 {
	None,
	Invalid_URL,
	DNS_Failed,
	Connect_Failed,
	TLS_Failed,
	Write_Failed,
	Read_Failed,
	Parse_Failed,
	Too_Many_Redirects,
	// A redirect tried to move the request from https to http.
	Insecure_Redirect,
}

Client :: struct {
	// Applied to every response parsed. `max_body` bounds how much a hostile or
	// broken server can make the client allocate.
	limits:        Limits,
	connect_timeout: time.Duration,
	// Applied to each individual read. A peer that sends *something* before
	// every deadline resets it, so this alone does not bound the exchange.
	read_timeout:  time.Duration,
	write_timeout: time.Duration,
	/*
	Ceiling on one request/response exchange, headers and body together.

	`read_timeout` is per-read, so a server dribbling one byte just under each
	deadline holds the caller's thread indefinitely: measured at 38 seconds
	against a 1-second read timeout, ending only when the hostile server gave
	up. `max_body` bounds how much such a peer can send, not how long it may
	take. Go's `http.Client.Timeout` covers the same ground for the same reason.

	Zero disables the ceiling, for callers streaming something genuinely slow.
	*/
	total_timeout: time.Duration,
	// Maximum 3xx hops followed. Zero disables redirect following.
	max_redirects: int,
	// Sent unless the caller sets their own.
	user_agent:    string,
	// When set, connections are reused across requests to the same origin.
	// Opening a connection dominates the cost of a small request, so pooling
	// removes most of that from every request after the first. See `Pool` for
	// the measurement.
	pool:          ^Pool,
}

DEFAULT_CLIENT :: Client {
	limits          = DEFAULT_LIMITS,
	connect_timeout = 10 * time.Second,
	read_timeout    = 30 * time.Second,
	write_timeout   = 30 * time.Second,
	total_timeout   = 120 * time.Second,
	max_redirects   = 5,
	user_agent      = "odin-http/0.1",
}

/*
A parsed absolute URL, as a client needs it.

Distinct from `URL`, which describes a request-target: a client additionally
needs the scheme, host and port in order to open a connection at all.
*/
Client_URL :: struct {
	scheme: string,
	host:   string,
	port:   int,
	// Path plus query, i.e. what goes on the request line.
	target: string,
	is_tls: bool,
}

/*
Parses an absolute http/https URL.

Rejects anything without a scheme: a bare host is ambiguous about whether TLS is
wanted, and guessing would silently downgrade a request to plaintext.
*/
client_url_parse :: proc(raw: string, allocator := context.temp_allocator) -> (u: Client_URL, ok: bool) {
	rest := raw

	switch {
	case strings.has_prefix(rest, "https://"):
		u.scheme = "https"
		u.is_tls = true
		u.port   = 443
		rest = rest[len("https://"):]
	case strings.has_prefix(rest, "http://"):
		u.scheme = "http"
		u.port   = 80
		rest = rest[len("http://"):]
	case:
		return {}, false
	}

	authority := rest
	if slash := index_byte(rest, '/'); slash >= 0 {
		authority = rest[:slash]
		u.target  = rest[slash:]
	} else {
		// An empty path on the wire must be sent as "/".
		u.target = "/"
	}

	if len(authority) == 0 { return {}, false }

	// Userinfo is not supported: it has been deprecated since RFC 3986 and is a
	// phishing vector, so a URL carrying it is refused rather than stripped.
	if index_byte(authority, '@') >= 0 { return {}, false }

	u.host = authority
	if colon := last_index_byte(authority, ':'); colon >= 0 {
		// A colon inside brackets belongs to an IPv6 literal, not a port.
		if authority[len(authority) - 1] != ']' {
			port, pok := parse_decimal(authority[colon + 1:])
			if !pok || port <= 0 || port > 65535 { return {}, false }
			u.host = authority[:colon]
			u.port = port
		}
	}

	if len(u.host) == 0 { return {}, false }
	return u, true
}

/*
Reports whether two URLs share an origin: scheme, host and port.

Origin — not just host — is the right unit, because a token issued for
https://example.com was not issued for http://example.com or for a different
port on the same machine.
*/
@(private)
client_same_origin :: proc(a, b: Client_URL) -> bool {
	return a.scheme == b.scheme && equal_fold(a.host, b.host) && a.port == b.port
}

/*
Drops headers that must not cross an origin boundary.

Authorization and Cookie carry credentials; Proxy-Authorization likewise. The
rest of the caller's headers are preserved, since dropping everything would
break content negotiation on an ordinary redirect.
*/
@(private)
client_strip_sensitive :: proc(headers: []Header_Entry, allocator: mem.Allocator) -> []Header_Entry {
	if len(headers) == 0 { return headers }

	kept := make([dynamic]Header_Entry, 0, len(headers), allocator)
	for h in headers {
		if equal_fold(h.name, "authorization")       { continue }
		if equal_fold(h.name, "proxy-authorization") { continue }
		if equal_fold(h.name, "cookie")              { continue }
		append(&kept, h)
	}
	return kept[:]
}

@(private)
last_index_byte :: proc(s: string, c: byte) -> int {
	for i := len(s) - 1; i >= 0; i -= 1 {
		if s[i] == c { return i }
	}
	return -1
}

/*
Performs a GET.

The response and everything it borrows live in `allocator`; an arena the caller
destroys is the intended pattern.
*/
client_get :: proc(
	c: ^Client,
	url: string,
	allocator: mem.Allocator,
) -> (res: Client_Response, err: Client_Error) {
	return client_request(c, .Get, url, "", allocator)
}

/*
Performs a request with an optional body.

Follows redirects up to `max_redirects`, with two rules browsers and curl both
enforce: an https-to-http redirect fails with `.Insecure_Redirect` rather than
silently dropping TLS, and credential headers are stripped when the redirect
crosses an origin.

The body is dropped when the method changes to GET, per the 301/302/303 rules
every deployed client implements.
*/
client_request :: proc(
	c: ^Client,
	method: Method,
	url: string,
	body: string,
	allocator: mem.Allocator,
    headers: []Header_Entry = nil,
) -> (res: Client_Response, err: Client_Error) {
	current_url     := url
	current_method  := method
	current_body    := body
	current_headers := headers

	for hop := 0; ; hop += 1 {
		res, err = client_do_once(c, current_method, current_url, current_body, allocator, current_headers)
		if err != .None { return res, err }

		if !status_is_redirect(res.status) || c.max_redirects <= 0 { return res, .None }
		if hop >= c.max_redirects { return res, .Too_Many_Redirects }

		location, has := headers_get(res.headers, "location")
		if !has { return res, .None }

		// A relative Location is resolved against the URL just fetched.
		next, resolved := client_resolve_location(current_url, location, allocator)
		if !resolved { return res, .None }

		from, from_ok := client_url_parse(current_url, allocator)
		to,   to_ok   := client_url_parse(next, allocator)
		if !from_ok || !to_ok { return res, .None }

		// A redirect from https to http strips TLS. An attacker who can inject
		// or influence a Location header would otherwise silently downgrade the
		// connection and read everything sent afterwards.
		if from.is_tls && !to.is_tls { return res, .Insecure_Redirect }

		// Credentials are scoped to the origin they were issued for. Following
		// a cross-origin redirect with them attached hands an Authorization
		// header or a Cookie to whatever host the redirect names, which is the
		// standard way a redirect turns into credential theft.
		if !client_same_origin(from, to) {
			current_headers = client_strip_sensitive(current_headers, allocator)
		}

		// RFC 9110 15.4: 303 always becomes GET, and 301/302 do in practice
		// because that is what every deployed client does.
		#partial switch res.status {
		case .See_Other, .Moved_Permanently, .Found:
			if current_method != .Head {
				current_method = .Get
			}
			current_body = ""
		}

		current_url = next
	}
}

/*
Resolves a Location header against the URL it came from.

Only absolute URLs and absolute paths are handled; anything else is refused
rather than guessed at, since a mis-resolved redirect can send credentials to
the wrong origin.
*/
@(private)
client_resolve_location :: proc(base: string, location: string, allocator: mem.Allocator) -> (string, bool) {
	loc := trim_ows(location)
	if len(loc) == 0 { return "", false }

	if strings.has_prefix(loc, "http://") || strings.has_prefix(loc, "https://") {
		return loc, true
	}

	if loc[0] != '/' { return "", false }

	u, ok := client_url_parse(base, allocator)
	if !ok { return "", false }

	port_suffix := ""
	default_port := 443 if u.is_tls else 80
	if u.port != default_port {
		port_suffix = strings.concatenate({":", itoa_str(allocator, i64(u.port))}, allocator)
	}

	return strings.concatenate({u.scheme, "://", u.host, port_suffix, loc}, allocator), true
}

@(private)
client_do_once :: proc(
	c: ^Client,
	method: Method,
	url: string,
	body: string,
	allocator: mem.Allocator,
	extra_headers: []Header_Entry,
) -> (res: Client_Response, err: Client_Error) {
	u, url_ok := client_url_parse(url, allocator)
	if !url_ok { return {}, .Invalid_URL }

	// Without a pool the connection is opened, used and closed here, exactly as
	// before. The pooled path differs only in where the connection comes from
	// and where it goes afterwards.
	if c.pool == nil {
		conn, dial_err := client_dial(c, u, allocator)
		if dial_err != .None { return {}, dial_err }
		defer pooled_conn_close(conn, allocator)

		return client_exchange(c, conn, method, u, body, allocator, extra_headers, false)
	}

	origin := pool_origin_key(u, allocator)

	// A pooled connection may have been closed by the peer while idle, which
	// only shows up on the next read. One retry on a fresh connection turns
	// that into a normal request rather than a spurious failure the caller
	// would have to handle.
	for attempt in 0 ..< 2 {
		conn := pool_take(c.pool, origin)
		reused := conn != nil

		/*
		A pooled connection is only safe if nothing arrived while it sat idle.
		Bytes waiting here were sent with no request outstanding, so they would
		become this request's response — a forged reply indistinguishable from a
		real one. Checking at pool time is not enough: the peer may send them
		after the connection was already returned.
		*/
		if reused && conn.transport->has_pending() {
			pooled_conn_close(conn, c.pool.allocator)
			conn = nil
			reused = false
		}

		if conn == nil {
			dial_err: Client_Error
			conn, dial_err = client_dial(c, u, c.pool.allocator)
			if dial_err != .None { return {}, dial_err }
		}


		res, err = client_exchange(c, conn, method, u, body, allocator, extra_headers, true)

		if err != .None {
			pooled_conn_close(conn, c.pool.allocator)
			// Only a reused connection earns a retry: a failure on a connection
			// this call just opened is a real error, and retrying would double
			// every genuine failure.
			if reused && attempt == 0 { continue }
			return res, err
		}

		// The peer decides whether the connection survives the response — and
		// so does anything it sent afterwards, which may not have arrived until
		// after the response was parsed.
		if conn_should_close(&res)         { conn.reusable = false }
		if conn.transport->has_pending()   { conn.reusable = false }
		pool_put(c.pool, origin, conn)
		return res, .None
	}

	return res, err
}

/*
Reports whether the peer indicated the connection must not be reused.

A response delimited by connection close is by definition unreusable, and an
explicit `Connection: close` says so directly. HTTP/1.0 responses default to
close unless they opt in.
*/
@(private)
conn_should_close :: proc(res: ^Client_Response) -> bool {
	if res.until_close      { return true }
	// A peer that over-sent cannot be trusted to have framed anything else
	// correctly either, and the extra bytes would poison the next request.
	if res.unsolicited_data { return true }

	if conn, has := headers_get(res.headers, "connection"); has {
		if token_list_contains(conn, "close")      { return true  }
		if token_list_contains(conn, "keep-alive") { return false }
	}
	return res.version.minor < 1
}

@(private)
client_dial :: proc(c: ^Client, u: Client_URL, allocator: mem.Allocator) -> (^Pooled_Conn, Client_Error) {
	endpoint, dns_err := client_resolve(u, allocator)
	if dns_err != .None { return nil, dns_err }

	// The connect timeout bounds the TLS handshake too: both are "waiting for a
	// peer that may never answer", and neither is covered by `read_timeout`,
	// which only applies once the connection is usable.
	return pooled_conn_dial(u, endpoint, allocator, c.connect_timeout)
}

@(private)
client_exchange :: proc(
	c: ^Client,
	conn: ^Pooled_Conn,
	method: Method,
	u: Client_URL,
	body: string,
	allocator: mem.Allocator,
	extra_headers: []Header_Entry,
	keep_alive: bool,
) -> (res: Client_Response, err: Client_Error) {
	conn.transport->set_timeout(false, c.write_timeout)
	if !client_send_request(conn.transport, c, method, u, body, extra_headers, allocator, keep_alive) {
		return {}, .Write_Failed
	}

	conn.transport->set_timeout(true, c.read_timeout)
	return client_read_response(conn.transport, c, method, allocator)
}

@(private)
client_resolve :: proc(u: Client_URL, allocator: mem.Allocator) -> (net.Endpoint, Client_Error) {
	// An IP literal needs no DNS round trip.
	if addr := net.parse_address(u.host); addr != nil {
		return net.Endpoint{address = addr, port = u.port}, .None
	}

	ep4, ep6, dns_err := net.resolve(u.host)
	if dns_err != nil { return {}, .DNS_Failed }

	// Prefer IPv4 only because it is the more reliably reachable of the two on
	// a typical developer machine; either is correct.
	chosen := ep4 if ep4.address != nil else ep6
	if chosen.address == nil { return {}, .DNS_Failed }

	return net.Endpoint{address = chosen.address, port = u.port}, .None
}

@(private)
client_send_request :: proc(
	t: ^Transport,
	c: ^Client,
	method: Method,
	u: Client_URL,
	body: string,
	extra_headers: []Header_Entry,
	allocator: mem.Allocator,
	keep_alive: bool,
) -> bool {
	b := strings.builder_make(allocator)

	strings.write_string(&b, method_string(method))
	strings.write_byte(&b, ' ')
	strings.write_string(&b, u.target)
	strings.write_string(&b, " HTTP/1.1\r\n")

	// Host carries the port unless it is the scheme default.
	strings.write_string(&b, "host: ")
	strings.write_string(&b, u.host)
	default_port := 443 if u.is_tls else 80
	if u.port != default_port {
		strings.write_byte(&b, ':')
		strings.write_int(&b, u.port)
	}
	strings.write_string(&b, "\r\n")

	has_ua, has_len, has_conn := false, false, false
	for h in extra_headers {
		// Values are validated here for the same reason the server validates
		// them: a CRLF in a header value is request splitting.
		if !is_token(h.name) || !is_field_value(h.value) { return false }

		if equal_fold(h.name, "host")           { continue }
		if equal_fold(h.name, "user-agent")     { has_ua = true }
		if equal_fold(h.name, "content-length") { has_len = true }
		if equal_fold(h.name, "connection")     { has_conn = true }

		strings.write_string(&b, h.name)
		strings.write_string(&b, ": ")
		strings.write_string(&b, h.value)
		strings.write_string(&b, "\r\n")
	}

	if !has_ua && len(c.user_agent) > 0 {
		strings.write_string(&b, "user-agent: ")
		strings.write_string(&b, c.user_agent)
		strings.write_string(&b, "\r\n")
	}

	// Content-Length is always sent for a body, and for a body-carrying method
	// even when empty, so the server never has to guess at framing.
	if !has_len && (len(body) > 0 || method_can_have_body(method)) {
		strings.write_string(&b, "content-length: ")
		strings.write_int(&b, len(body))
		strings.write_string(&b, "\r\n")
	}

	// Without pooling, closing after each response is the polite default: it
	// leaves no idle connection on the server. With a pool, the connection is
	// the thing being reused, so asking for close would defeat the point.
	if !has_conn && !keep_alive {
		strings.write_string(&b, "connection: close\r\n")
	}

	strings.write_string(&b, "\r\n")
	strings.write_string(&b, body)

	return transport_write_all(t, transmute([]byte)strings.to_string(b))
}

@(private)
client_read_response :: proc(
	t: ^Transport,
	c: ^Client,
	method: Method,
	allocator: mem.Allocator,
) -> (res: Client_Response, err: Client_Error) {
	headers_init(&res.headers, allocator)

	// Ceiling on the exchange, checked before each read. See `total_timeout`.
	started  := time.now()
	deadline := c.total_timeout

	p: Parser
	parser_init_response(&p, &res, method, c.limits)

	buf := make([]byte, CLIENT_READ_BUFFER, allocator)
	body := strings.builder_make(allocator)

	filled, consumed := 0, 0

	for {
		for {
			n, ev := parser_feed(&p, buf[consumed:filled])
			consumed += n

			stalled := false
			#partial switch ev {
			case .Body_Chunk:
				strings.write_bytes(&body, p.chunk)
			case .Message_Done:
				res.body = strings.to_string(body)
				// Anything still buffered was sent unprompted; see
				// `unsolicited_data`.
				res.unsolicited_data = consumed < filled
				return res, .None
			case .Error:
				return res, .Parse_Failed
			case .Need_More:
				stalled = true
			case .Headers_Done:
				// Same aliasing rule as the server: the parser borrows from
				// `buf`, which is about to be recycled for the body.
				response_detach(&res, allocator)
			}

			if stalled || n == 0 { break }
		}

		if consumed > 0 {
			copy(buf, buf[consumed:filled])
			filled -= consumed
			consumed = 0
		}

		if filled >= len(buf) { return res, .Parse_Failed }

		// The per-read deadline is reset by any byte, so a peer that dribbles
		// just fast enough never trips it. This is the ceiling on the whole
		// exchange.
		if deadline > 0 && time.since(started) > deadline {
			return res, .Read_Failed
		}

		n, ok := t->read(buf[filled:])
		if !ok {
			// EOF. Only a close-delimited body may treat this as completion.
			if parser_finish(&p) == .Message_Done {
				res.body = strings.to_string(body)
				return res, .None
			}
			return res, .Read_Failed
		}
		filled += n
	}
}

@(private)
CLIENT_READ_BUFFER :: 16 * 1024

/*
Copies the response's borrowed strings into `allocator`.

The mirror of `request_detach`: header values point into the read buffer, which
is recycled while the body is still arriving.
*/
@(private)
response_detach :: proc(res: ^Client_Response, allocator: mem.Allocator) {
	for &entry in res.headers.entries {
		if len(entry.name) == 0 { continue }
		entry.name  = strings.clone(entry.name, allocator)
		entry.value = strings.clone(entry.value, allocator)
	}

	clear(&res.headers._index)
	for entry, i in res.headers.entries {
		if len(entry.name) == 0 { continue }
		if entry.name == "set-cookie" { continue }
		if _, existing := res.headers._index[entry.name]; existing { continue }
		res.headers._index[entry.name] = i
	}
}

/*
Runs `body` with an arena that owns everything the response allocated.

The intended usage pattern, since a response borrows heavily from its arena:

	http.client_with_arena(&c, "https://example.com", proc(res: ^http.Client_Response) {
		fmt.println(res.status, len(res.body))
	})
*/
client_with_arena :: proc(
	c: ^Client,
	url: string,
	body: proc(res: ^Client_Response, err: Client_Error),
) {
	arena: virtual.Arena
	if virtual.arena_init_growing(&arena) != nil {
		body(nil, .Connect_Failed)
		return
	}
	defer virtual.arena_destroy(&arena)

	res, err := client_get(c, url, virtual.arena_allocator(&arena))
	body(&res, err)
}
