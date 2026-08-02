package http

import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:time"

/*
A blocking HTTP/1.1 client.

Shares the parser with the server, so the framing and smuggling defences are
literally the same code rather than a second implementation that drifts. It also
shares `Transport`, which is what makes HTTPS work with no client-specific TLS
handling.

Response bodies are buffered up to `limits.max_body`. A streaming variant would
mirror the server's `Stream_Body`, but buffering is the right default for a
client: callers almost always want the whole body, and an unbounded one is a
denial-of-service vector against the client itself.
*/

Client_Response :: struct {
	status:  Status,
	version: Version,
	headers: Headers,
	body:    string,

	// Set when the response was delimited by the connection closing, in which
	// case the connection cannot be reused.
	until_close: bool,
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
}

Client :: struct {
	// Applied to every response parsed. `max_body` bounds how much a hostile or
	// broken server can make the client allocate.
	limits:        Limits,
	connect_timeout: time.Duration,
	read_timeout:  time.Duration,
	write_timeout: time.Duration,
	// Maximum 3xx hops followed. Zero disables redirect following.
	max_redirects: int,
	// Sent unless the caller sets their own.
	user_agent:    string,
}

DEFAULT_CLIENT :: Client {
	limits          = DEFAULT_LIMITS,
	connect_timeout = 10 * time.Second,
	read_timeout    = 30 * time.Second,
	write_timeout   = 30 * time.Second,
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

Follows redirects up to `max_redirects`. A redirect to a different host is
followed, but the body is dropped when the method changes to GET, matching the
303 and 301/302 rules every browser implements.
*/
client_request :: proc(
	c: ^Client,
	method: Method,
	url: string,
	body: string,
	allocator: mem.Allocator,
    headers: []Header_Entry = nil,
) -> (res: Client_Response, err: Client_Error) {
	current_url    := url
	current_method := method
	current_body   := body

	for hop := 0; ; hop += 1 {
		res, err = client_do_once(c, current_method, current_url, current_body, allocator, headers)
		if err != .None { return res, err }

		if !status_is_redirect(res.status) || c.max_redirects <= 0 { return res, .None }
		if hop >= c.max_redirects { return res, .Too_Many_Redirects }

		location, has := headers_get(res.headers, "location")
		if !has { return res, .None }

		// A relative Location is resolved against the URL just fetched.
		next, resolved := client_resolve_location(current_url, location, allocator)
		if !resolved { return res, .None }

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

	endpoint, dns_err := client_resolve(u, allocator)
	if dns_err != .None { return {}, dns_err }

	socket, dial_err := net.dial_tcp(endpoint)
	if dial_err != nil { return {}, .Connect_Failed }

	// The transport owns the socket from here, including closing it.
	transport: ^Transport
	plain: Plain_Transport
	tls: TLS_Transport

	if u.is_tls {
		if !tls_client_transport_init(&tls, socket, endpoint, u.host) {
			net.close(socket)
			return {}, .TLS_Failed
		}
		transport = &tls.base
	} else {
		plain_transport_init(&plain, socket, endpoint)
		transport = &plain.base
	}
	defer transport->close()

    transport->set_timeout(false, c.write_timeout)
	if !client_send_request(transport, c, method, u, body, extra_headers, allocator) {
		return {}, .Write_Failed
	}

	transport->set_timeout(true, c.read_timeout)
	return client_read_response(transport, c, method, allocator)
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

	// Connections are not pooled yet, so each request closes cleanly rather than
	// leaving the server holding an idle connection.
	if !has_conn {
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
