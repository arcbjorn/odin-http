package tests

import "core:mem/virtual"
import "core:net"
import "core:sync"
import "core:thread"
import "core:time"
import "core:strings"
import "core:testing"

import http "../http"

/*
Client tests.

Run against this package's own server, which exercises both directions at once:
a framing disagreement between the request writer and the response parser shows
up here even though each side passes its own unit tests.
*/

@(private)
client_router :: proc(r: ^http.Router) {
	http.router_init(r)

	http.router_handle_proc(r, "GET /hello", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "hello client")
	})

	http.router_handle_proc(r, "POST /echo", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, req.body)
	})

	http.router_handle_proc(r, "GET /empty", proc(req: ^http.Request, res: ^http.Response) {
		res.status = .No_Content
	})

	http.router_handle_proc(r, "GET /headers", proc(req: ^http.Request, res: ^http.Response) {
		ua, _ := http.headers_get(req.headers, "user-agent")
		custom, _ := http.headers_get(req.headers, "x-custom")
		http.respond_plain(res, .OK, strings.concatenate({ua, "|", custom}, req.headers.allocator))
	})

	// Chunked, so the client must decode a body of unknown length.
	http.router_handle_proc(r, "GET /chunked", proc(req: ^http.Request, res: ^http.Response) {
		http.response_set_stream(res, req, proc(w: ^http.Stream_Writer, req: ^http.Request) {
			http.stream_write_string(w, "one")
			http.stream_write_string(w, "two")
			http.stream_write_string(w, "three")
		})
	})

	http.router_handle_proc(r, "GET /redirect", proc(req: ^http.Request, res: ^http.Response) {
		http.headers_set(&res.headers, "location", "/hello")
		res.status = .Found
	})

	http.router_handle_proc(r, "GET /loop", proc(req: ^http.Request, res: ^http.Response) {
		http.headers_set(&res.headers, "location", "/loop")
		res.status = .Found
	})
}

@(private)
with_client :: proc(
	t: ^testing.T,
	body: proc(t: ^testing.T, c: ^http.Client, base: string, arena: ^virtual.Arena),
) {
	r: http.Router
	client_router(&r)
	defer http.router_destroy(&r)

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	port := strings.builder_make(virtual.arena_allocator(&arena))
	strings.write_string(&port, "http://127.0.0.1:")
	strings.write_int(&port, int(ts.endpoint.port))

	c := http.DEFAULT_CLIENT
	body(t, &c, strings.to_string(port), &arena)
}

@(test)
test_client_get :: proc(t: ^testing.T) {
	with_client(t, proc(t: ^testing.T, c: ^http.Client, base: string, arena: ^virtual.Arena) {
		alloc := virtual.arena_allocator(arena)
		res, err := http.client_get(c, strings.concatenate({base, "/hello"}, alloc), alloc)

		testing.expect_value(t, err, http.Client_Error.None)
		testing.expect_value(t, res.status, http.Status.OK)
		testing.expect_value(t, res.body, "hello client")
	})
}

@(test)
test_client_post_with_body :: proc(t: ^testing.T) {
	with_client(t, proc(t: ^testing.T, c: ^http.Client, base: string, arena: ^virtual.Arena) {
		alloc := virtual.arena_allocator(arena)
		res, err := http.client_request(c, .Post,
			strings.concatenate({base, "/echo"}, alloc), "round trip", alloc)

		testing.expect_value(t, err, http.Client_Error.None)
		testing.expect_value(t, res.status, http.Status.OK)
		// Proves the client sent a correct Content-Length: the server echoes
		// exactly what it framed.
		testing.expect_value(t, res.body, "round trip")
	})
}

@(test)
test_client_reads_chunked_response :: proc(t: ^testing.T) {
	with_client(t, proc(t: ^testing.T, c: ^http.Client, base: string, arena: ^virtual.Arena) {
		alloc := virtual.arena_allocator(arena)
		res, err := http.client_get(c, strings.concatenate({base, "/chunked"}, alloc), alloc)

		testing.expect_value(t, err, http.Client_Error.None)
		// Chunk boundaries must not appear in the decoded body.
		testing.expect_value(t, res.body, "onetwothree")
	})
}

@(test)
test_client_no_content_has_empty_body :: proc(t: ^testing.T) {
	with_client(t, proc(t: ^testing.T, c: ^http.Client, base: string, arena: ^virtual.Arena) {
		alloc := virtual.arena_allocator(arena)
		res, err := http.client_get(c, strings.concatenate({base, "/empty"}, alloc), alloc)

		testing.expect_value(t, err, http.Client_Error.None)
		testing.expect_value(t, res.status, http.Status.No_Content)
		// A 204 never carries a body; reading one would consume the next
		// response on a reused connection.
		testing.expect_value(t, len(res.body), 0)
	})
}

@(test)
test_client_sends_headers :: proc(t: ^testing.T) {
	with_client(t, proc(t: ^testing.T, c: ^http.Client, base: string, arena: ^virtual.Arena) {
		alloc := virtual.arena_allocator(arena)

		extra := []http.Header_Entry{{name = "x-custom", value = "set-by-caller"}}
		res, err := http.client_request(c, .Get,
			strings.concatenate({base, "/headers"}, alloc), "", alloc, extra)

		testing.expect_value(t, err, http.Client_Error.None)
		testing.expect_value(t, res.body, "odin-http/0.1|set-by-caller")
	})
}

@(test)
test_client_follows_redirect :: proc(t: ^testing.T) {
	with_client(t, proc(t: ^testing.T, c: ^http.Client, base: string, arena: ^virtual.Arena) {
		alloc := virtual.arena_allocator(arena)
		res, err := http.client_get(c, strings.concatenate({base, "/redirect"}, alloc), alloc)

		testing.expect_value(t, err, http.Client_Error.None)
		// The redirect is followed to /hello rather than surfaced as a 302.
		testing.expect_value(t, res.status, http.Status.OK)
		testing.expect_value(t, res.body, "hello client")
	})
}

@(test)
test_client_redirect_loop_is_bounded :: proc(t: ^testing.T) {
	with_client(t, proc(t: ^testing.T, c: ^http.Client, base: string, arena: ^virtual.Arena) {
		alloc := virtual.arena_allocator(arena)
		_, err := http.client_get(c, strings.concatenate({base, "/loop"}, alloc), alloc)

		// A server can otherwise keep a client looping forever.
		testing.expect_value(t, err, http.Client_Error.Too_Many_Redirects)
	})
}

@(test)
test_client_respects_max_body :: proc(t: ^testing.T) {
	with_client(t, proc(t: ^testing.T, c: ^http.Client, base: string, arena: ^virtual.Arena) {
		alloc := virtual.arena_allocator(arena)

		// A hostile server must not be able to make the client allocate freely.
		c.limits.max_body = 4
		_, err := http.client_get(c, strings.concatenate({base, "/hello"}, alloc), alloc)

		testing.expect_value(t, err, http.Client_Error.Parse_Failed)
	})
}

// --- URL parsing ---

@(test)
test_client_url_parse :: proc(t: ^testing.T) {
	u, ok := http.client_url_parse("https://example.com/path?q=1", context.temp_allocator)
	testing.expect(t, ok, "")
	testing.expect_value(t, u.scheme, "https")
	testing.expect_value(t, u.host, "example.com")
	testing.expect_value(t, u.port, 443)
	testing.expect_value(t, u.target, "/path?q=1")
	testing.expect(t, u.is_tls, "")

	plain, ok2 := http.client_url_parse("http://example.com", context.temp_allocator)
	testing.expect(t, ok2, "")
	testing.expect_value(t, plain.port, 80)
	// An absent path is sent as "/" on the wire.
	testing.expect_value(t, plain.target, "/")
	testing.expect(t, !plain.is_tls, "")

	ported, ok3 := http.client_url_parse("http://example.com:8080/x", context.temp_allocator)
	testing.expect(t, ok3, "")
	testing.expect_value(t, ported.host, "example.com")
	testing.expect_value(t, ported.port, 8080)
}

@(test)
test_client_url_rejects_bad_input :: proc(t: ^testing.T) {
	bad := []string{
		"example.com/path",            // no scheme: TLS intent is ambiguous
		"ftp://example.com",           // unsupported scheme
		"http://",                     // no host
		"http://user@example.com",     // userinfo is a phishing vector
		"http://example.com:0/x",      // invalid port
		"http://example.com:99999/x",
		"http://example.com:abc/x",
	}

	for raw in bad {
		_, ok := http.client_url_parse(raw, context.temp_allocator)
		testing.expectf(t, !ok, "URL %q must be rejected", raw)
	}
}

// --- Redirect safety ---

@(private)
redirect_router :: proc(r: ^http.Router, target: string) {
	http.router_init(r)

	// Echoes whether credentials survived the hop.
	http.router_handle_proc(r, "GET /dest", proc(req: ^http.Request, res: ^http.Response) {
		auth, has_auth := http.headers_get(req.headers, "authorization")
		cookie, has_cookie := http.headers_get(req.headers, "cookie")
		other, _ := http.headers_get(req.headers, "x-harmless")

		_ = has_auth; _ = has_cookie
		http.respond_plain(res, .OK, strings.concatenate(
			{"auth=", auth, "|cookie=", cookie, "|other=", other},
			req.headers.allocator))
	})
}

@(test)
test_client_strips_credentials_across_origin :: proc(t: ^testing.T) {
	// Two servers: the first redirects to the second, which is a different
	// origin (different port). A credential must not follow.
	dest_router: http.Router
	redirect_router(&dest_router, "")
	defer http.router_destroy(&dest_router)

	dest: http.Test_Server
	if err := http.test_server_start(&dest, http.router_handler(&dest_router)); err != nil {
		testing.fail_now(t, "could not start destination server")
	}
	defer http.test_server_stop(&dest)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	dest_url := strings.builder_make(alloc)
	strings.write_string(&dest_url, "http://127.0.0.1:")
	strings.write_int(&dest_url, int(dest.endpoint.port))
	strings.write_string(&dest_url, "/dest")

	// The redirecting server points at the other origin.
	Redirect_To :: struct { url: string }
	target := Redirect_To{url = strings.to_string(dest_url)}

	src_router: http.Router
	http.router_init(&src_router)
	defer http.router_destroy(&src_router)
	http.router_handle(&src_router, "GET /start", http.handler_from_poly(&target,
		proc(tg: ^Redirect_To, req: ^http.Request, res: ^http.Response) {
			http.headers_set(&res.headers, "location", tg.url)
			res.status = .Found
		}))

	src: http.Test_Server
	if err := http.test_server_start(&src, http.router_handler(&src_router)); err != nil {
		testing.fail_now(t, "could not start source server")
	}
	defer http.test_server_stop(&src)

	src_url := strings.builder_make(alloc)
	strings.write_string(&src_url, "http://127.0.0.1:")
	strings.write_int(&src_url, int(src.endpoint.port))
	strings.write_string(&src_url, "/start")

	c := http.DEFAULT_CLIENT
	sensitive := []http.Header_Entry{
		{name = "authorization", value = "Bearer secret-token"},
		{name = "cookie",        value = "session=secret"},
		{name = "x-harmless",    value = "kept"},
	}

	res, err := http.client_request(&c, .Get, strings.to_string(src_url), "", alloc, sensitive)

	testing.expect_value(t, err, http.Client_Error.None)
	// A redirect that carried these would hand the caller's credentials to
	// whatever host the Location header named.
	testing.expect_value(t, res.body, "auth=|cookie=|other=kept")
}

@(test)
test_client_keeps_credentials_on_same_origin :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /start", proc(req: ^http.Request, res: ^http.Response) {
		// A relative Location stays on this origin.
		http.headers_set(&res.headers, "location", "/dest")
		res.status = .Found
	})
	http.router_handle_proc(&r, "GET /dest", proc(req: ^http.Request, res: ^http.Response) {
		auth, _ := http.headers_get(req.headers, "authorization")
		http.respond_plain(res, .OK, auth)
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	url := strings.builder_make(alloc)
	strings.write_string(&url, "http://127.0.0.1:")
	strings.write_int(&url, int(ts.endpoint.port))
	strings.write_string(&url, "/start")

	c := http.DEFAULT_CLIENT
	res, err := http.client_request(&c, .Get, strings.to_string(url), "", alloc,
		[]http.Header_Entry{{name = "authorization", value = "Bearer keep-me"}})

	testing.expect_value(t, err, http.Client_Error.None)
	// Stripping on a same-origin redirect would break ordinary authenticated
	// flows, so the header must survive here.
	testing.expect_value(t, res.body, "Bearer keep-me")
}

// --- Connection pooling ---

@(test)
test_pool_reuses_connection :: proc(t: ^testing.T) {
	// The server counts connections, so reuse is observable rather than
	// inferred from timing.
	Counter :: struct { conns: int }

	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)
	http.router_handle_proc(&r, "GET /ping", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "pong")
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	url := strings.builder_make(alloc)
	strings.write_string(&url, "http://127.0.0.1:")
	strings.write_int(&url, int(ts.endpoint.port))
	strings.write_string(&url, "/ping")

	pool: http.Pool
	http.pool_init(&pool)
	defer http.pool_destroy(&pool)

	c := http.DEFAULT_CLIENT
	c.pool = &pool

	for i in 0 ..< 3 {
		res, err := http.client_get(&c, strings.to_string(url), alloc)
		testing.expectf(t, err == .None, "request %d failed: %v", i, err)
		testing.expect_value(t, res.body, "pong")
	}

	// One idle connection is retained for the single origin used.
	testing.expect_value(t, http.pool_idle_count(&pool), 1)
}

@(test)
test_pool_separates_origins :: proc(t: ^testing.T) {
	make_server :: proc(r: ^http.Router, ts: ^http.Test_Server, t: ^testing.T) {
		http.router_init(r)
		http.router_handle_proc(r, "GET /ping", proc(req: ^http.Request, res: ^http.Response) {
			http.respond_plain(res, .OK, "pong")
		})
		if err := http.test_server_start(ts, http.router_handler(r)); err != nil {
			testing.fail_now(t, "could not start test server")
		}
	}

	r1, r2: http.Router
	ts1, ts2: http.Test_Server
	make_server(&r1, &ts1, t)
	defer { http.test_server_stop(&ts1); http.router_destroy(&r1) }
	make_server(&r2, &ts2, t)
	defer { http.test_server_stop(&ts2); http.router_destroy(&r2) }

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	pool: http.Pool
	http.pool_init(&pool)
	defer http.pool_destroy(&pool)

	c := http.DEFAULT_CLIENT
	c.pool = &pool

	for ep in ([]int{int(ts1.endpoint.port), int(ts2.endpoint.port)}) {
		u := strings.builder_make(alloc)
		strings.write_string(&u, "http://127.0.0.1:")
		strings.write_int(&u, ep)
		strings.write_string(&u, "/ping")

		res, err := http.client_get(&c, strings.to_string(u), alloc)
		testing.expect_value(t, err, http.Client_Error.None)
		testing.expect_value(t, res.body, "pong")
	}

	// Different ports are different origins, so a connection to one must never
	// be handed out for the other.
	testing.expect_value(t, http.pool_idle_count(&pool), 2)
}

@(test)
test_pool_discards_closed_connections :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	// The server closes after every response, so nothing may be pooled.
	http.router_handle_proc(&r, "GET /once", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "bye")
		http.response_set_close(res)
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	url := strings.builder_make(alloc)
	strings.write_string(&url, "http://127.0.0.1:")
	strings.write_int(&url, int(ts.endpoint.port))
	strings.write_string(&url, "/once")

	pool: http.Pool
	http.pool_init(&pool)
	defer http.pool_destroy(&pool)

	c := http.DEFAULT_CLIENT
	c.pool = &pool

	for i in 0 ..< 2 {
		res, err := http.client_get(&c, strings.to_string(url), alloc)
		testing.expectf(t, err == .None, "request %d failed: %v", i, err)
		testing.expect_value(t, res.body, "bye")
	}

	// Pooling a connection the peer said it would close would fail the next
	// request for no reason the caller could act on.
	testing.expect_value(t, http.pool_idle_count(&pool), 0)
}

@(test)
test_client_without_pool_still_works :: proc(t: ^testing.T) {
	with_client(t, proc(t: ^testing.T, c: ^http.Client, base: string, arena: ^virtual.Arena) {
		// The unpooled path must stay intact: it is the default.
		alloc := virtual.arena_allocator(arena)
		testing.expect(t, c.pool == nil, "default client has no pool")

		res, err := http.client_get(c, strings.concatenate({base, "/hello"}, alloc), alloc)
		testing.expect_value(t, err, http.Client_Error.None)
		testing.expect_value(t, res.body, "hello client")
	})
}

/*
Hostile Location headers.

A redirect target is chosen by the origin, so `Location` is attacker-controlled
whenever the origin is. The property under test is that no value can steer the
client to a host the caller did not name: an unresolvable form must stop the
redirect chain rather than be guessed at, because a mis-resolved redirect is how
credentials reach the wrong origin.
*/
@(private)
Hostile_Location :: struct { value: string }

/*
Serves a redirect to `value`, plus a catch-all that echoes the requested target.

The echo is what makes the assertion meaningful: it distinguishes "the client
refused" from "the client followed the redirect somewhere else entirely", which
a status code alone cannot.
*/
@(private)
hostile_redirect_server :: proc(r: ^http.Router, loc: ^Hostile_Location) {
	http.router_init(r)

	http.router_handle(r, "GET /start", http.handler_from_poly(loc,
		proc(l: ^Hostile_Location, req: ^http.Request, res: ^http.Response) {
			http.headers_set(&res.headers, "location", l.value)
			res.status = .Found
		}))

	http.router_handle(r, "/{rest...}", http.handler_from_proc(
		proc(req: ^http.Request, res: ^http.Response) {
			http.respond_plain(res, .OK,
				strings.concatenate({"PATH=", req.target}, req.headers.allocator))
		}))
}

/*
A protocol-relative Location must not become a new host.

"//evil.test/x" begins with '/', so a resolver that only checks the first byte
treats it as an absolute path and joins it to the current origin — which is the
safe outcome, and the one asserted here. Treating it as a scheme-relative URL
instead would send the request, and any same-origin credentials, to evil.test.
*/
@(test)
test_client_refuses_protocol_relative_redirect :: proc(t: ^testing.T) {
	loc := Hostile_Location{value = "//evil.test/x"}

	r: http.Router
	hostile_redirect_server(&r, &loc)
	defer http.router_destroy(&r)

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	b := strings.builder_make(alloc)
	strings.write_string(&b, "http://127.0.0.1:")
	strings.write_int(&b, int(ts.endpoint.port))
	strings.write_string(&b, "/start")
	url := strings.to_string(b)

	c := http.DEFAULT_CLIENT
	res, err := http.client_request(&c, .Get, url, "", alloc)

	testing.expect_value(t, err, http.Client_Error.None)
	// The request stayed on the original host, carrying the whole thing as a
	// path. Reaching evil.test would have failed to resolve instead.
	testing.expect_value(t, res.body, "PATH=//evil.test/x")
}

/*
A Location the resolver cannot make absolute stops the chain.

The client returns the redirect response itself rather than guessing at a
target. Relative references ("next") are refused because resolving them
correctly requires the full RFC 3986 algorithm, and a wrong guess changes which
host receives the request; non-HTTP schemes are refused because there is nothing
to dial.

Two layers enforce this independently, so deleting the `loc[0] != '/'` guard in
`client_resolve_location` does not fail this test: `client_url_parse` rejects
any target without a scheme, and a relative reference has none. Both would have
to regress before a relative Location was followed. The guard is kept because it
refuses at the point where the intent is legible, rather than relying on a
downstream parse to fail.
*/
@(test)
test_client_stops_on_unresolvable_location :: proc(t: ^testing.T) {
	cases := []string{
		"next",                 // relative reference
		"",                     // empty
		"   ",                  // whitespace only
		"ftp://evil.test/x",    // non-HTTP scheme
		"file:///etc/passwd",   // local file scheme
	}

	for value in cases {
		loc := Hostile_Location{value = value}

		r: http.Router
		hostile_redirect_server(&r, &loc)
		defer http.router_destroy(&r)

		ts: http.Test_Server
		if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
			testing.fail_now(t, "could not start test server")
		}
		defer http.test_server_stop(&ts)

		arena: virtual.Arena
		_ = virtual.arena_init_growing(&arena)
		defer virtual.arena_destroy(&arena)
		alloc := virtual.arena_allocator(&arena)

		b := strings.builder_make(alloc)
		strings.write_string(&b, "http://127.0.0.1:")
		strings.write_int(&b, int(ts.endpoint.port))
		strings.write_string(&b, "/start")
		url := strings.to_string(b)

		c := http.DEFAULT_CLIENT
		res, err := http.client_request(&c, .Get, url, "", alloc)

		testing.expect_value(t, err, http.Client_Error.None)
		// The 302 is handed back unfollowed.
		testing.expect_value(t, res.status, http.Status.Found)
	}
}

// Percent-escapes in a Location are not decoded before the host is decided, so
// "%2f%2f" cannot smuggle in a second authority.
@(test)
test_client_does_not_decode_location_before_dialing :: proc(t: ^testing.T) {
	loc := Hostile_Location{value = "/%2f%2fevil.test/x"}

	r: http.Router
	hostile_redirect_server(&r, &loc)
	defer http.router_destroy(&r)

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	b := strings.builder_make(alloc)
	strings.write_string(&b, "http://127.0.0.1:")
	strings.write_int(&b, int(ts.endpoint.port))
	strings.write_string(&b, "/start")
	url := strings.to_string(b)

	c := http.DEFAULT_CLIENT
	res, err := http.client_request(&c, .Get, url, "", alloc)

	testing.expect_value(t, err, http.Client_Error.None)
	testing.expect_value(t, res.body, "PATH=/%2f%2fevil.test/x")
}

/*
Caller-supplied headers are validated before they reach the wire.

This is the client-side mirror of response splitting: a CRLF in a header name or
value would let attacker-influenced input forge an extra header, or an entire
second request, on a connection the caller believes carries one. The request is
refused rather than sanitised, so the bug surfaces at the call site that
introduced it instead of silently changing what was sent.

A whole-library mutation sweep found this guard unprotected — disabling the
`is_token`/`is_field_value` check in `client_send_request` failed no test.
*/
@(test)
test_client_rejects_header_injection :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /ok", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "ok")
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	b := strings.builder_make(alloc)
	strings.write_string(&b, "http://127.0.0.1:")
	strings.write_int(&b, int(ts.endpoint.port))
	strings.write_string(&b, "/ok")
	url := strings.to_string(b)

	hostile := [][]http.Header_Entry{
		{{name = "x-a", value = "v\r\nX-Injected: 1"}},  // CRLF in the value
		{{name = "x-a\r\nEvil: 1", value = "v"}},        // CRLF in the name
		{{name = "x a", value = "v"}},                   // SP is not a tchar
		{{name = "x-a", value = "v\x00b"}},              // NUL truncates in C
	}

	for headers in hostile {
		c := http.DEFAULT_CLIENT
		_, err := http.client_request(&c, .Get, url, "", alloc, headers)

		// The request is never sent, so the failure surfaces as a write error
		// rather than a response the caller might mistake for success.
		testing.expect(t, err != http.Client_Error.None,
			"a header carrying CRLF, NUL or a bad name must not be sent")
	}

	// A well-formed header on the same path still works, so the check is not
	// simply rejecting everything.
	c := http.DEFAULT_CLIENT
	good := []http.Header_Entry{{name = "x-fine", value = "value"}}
	res, err := http.client_request(&c, .Get, url, "", alloc, good)
	testing.expect_value(t, err, http.Client_Error.None)
	testing.expect_value(t, res.status, http.Status.OK)
}

/*
A server that dribbles a response must not hold the client indefinitely.

`read_timeout` applies to each read, so any byte arriving before the deadline
resets it. A hostile origin sending one byte just under that interval keeps a
client thread — and, with a pool, a connection — for as long as it likes.
Measured before `total_timeout` existed: **38 seconds against a 1-second read
timeout**, ending only when the test server gave up rather than the client.

`max_body` bounds how much such a peer can send but not how long it may take,
the same asymmetry the server side has for Slowloris. Go's
`http.Client.Timeout` covers this ground for the same reason.
*/
@(private)
Dribble_Server :: struct {
	socket:   net.TCP_Socket,
	endpoint: net.Endpoint,
	thread:   ^thread.Thread,
	stop:     bool,
}

@(private)
dribble_run :: proc(ds: ^Dribble_Server) {
	for !sync.atomic_load(&ds.stop) {
		client, _, err := net.accept_tcp(ds.socket)
		if err != nil { return }

		buf: [4096]byte
		net.recv_tcp(client, buf[:])

		// Headers promise a body far larger than will ever arrive.
		_, serr := net.send_tcp(client,
			transmute([]byte)string("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n"))
		if serr != nil { net.close(client); continue }

		// One byte per interval, chosen to stay inside the client's per-read
		// deadline so only a total ceiling can end it.
		for !sync.atomic_load(&ds.stop) {
			if _, e := net.send_tcp(client, transmute([]byte)string("X")); e != nil { break }
			time.sleep(50 * time.Millisecond)
		}
		net.close(client)
	}
}

@(test)
test_client_bounds_a_dribbling_server :: proc(t: ^testing.T) {
	sock, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	testing.expect(t, err == nil, "could not listen")

	bound, berr := net.bound_endpoint(sock)
	testing.expect(t, berr == nil, "could not read bound port")

	ds := new(Dribble_Server, context.allocator)
	defer free(ds)
	ds.socket = sock
	ds.endpoint = bound
	ds.thread = thread.create_and_start_with_poly_data(ds, dribble_run)
	defer {
		sync.atomic_store(&ds.stop, true)
		net.close(sock)
		thread.terminate(ds.thread, 0)
		thread.destroy(ds.thread)
	}

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	b := strings.builder_make(alloc)
	strings.write_string(&b, "http://127.0.0.1:")
	strings.write_int(&b, int(bound.port))
	strings.write_string(&b, "/")

	c := http.DEFAULT_CLIENT
	// The per-read deadline is never reached, since the peer sends every 50 ms.
	c.read_timeout  = 2 * time.Second
	c.total_timeout = 400 * time.Millisecond

	start := time.now()
	_, cerr := http.client_get(&c, strings.to_string(b), alloc)
	elapsed := time.since(start)

	testing.expect_value(t, cerr, http.Client_Error.Read_Failed)
	testing.expectf(t, elapsed < 2 * time.Second,
		"the total ceiling must end the exchange, took %v", elapsed)
}

/*
Header values must survive a response delivered one byte at a time.

The client parses into `buf` and the response borrows slices from it, so
compacting that buffer while the header block is still incomplete slides bytes
out from under values already parsed. A peer sending its response in one write
never triggers it — the block is complete before any compaction — which is why
every existing redirect test passed.

Against a server dribbling byte by byte, `Location` came back as
"ngth: 0\r\n7.0.0.1:8044/next": fragments of `Content-Length` spliced into it.
The redirect then resolved to nonsense and was silently abandoned, so the caller
got a 302 it had asked the client to follow.
*/
@(private)
Dribble_Header_Server :: struct {
	socket:   net.TCP_Socket,
	endpoint: net.Endpoint,
	thread:   ^thread.Thread,
	response: string,
	stop:     bool,
}

@(private)
dribble_header_run :: proc(ds: ^Dribble_Header_Server) {
	for !sync.atomic_load(&ds.stop) {
		client, _, err := net.accept_tcp(ds.socket)
		if err != nil { return }

		buf: [4096]byte
		net.recv_tcp(client, buf[:])

		// One byte per write: the client's buffer is compacted between almost
		// every pair of bytes, which is the condition under test.
		data := transmute([]byte)ds.response
		for i in 0 ..< len(data) {
			if _, e := net.send_tcp(client, data[i:i + 1]); e != nil { break }
		}
		net.close(client)
	}
}

@(test)
test_client_parses_dribbled_headers_intact :: proc(t: ^testing.T) {
	sock, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	testing.expect(t, err == nil, "could not listen")

	bound, berr := net.bound_endpoint(sock)
	testing.expect(t, berr == nil, "could not read bound port")

	ds := new(Dribble_Header_Server, context.allocator)
	defer free(ds)
	ds.socket = sock
	ds.endpoint = bound
	// Several headers, so a corrupted value splices in a recognisable neighbour.
	ds.response =
		"HTTP/1.1 200 OK\r\n" +
		"Content-Length: 2\r\n" +
		"X-Marker: marker-value-intact\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\nhi"
	ds.thread = thread.create_and_start_with_poly_data(ds, dribble_header_run)
	defer {
		sync.atomic_store(&ds.stop, true)
		net.close(sock)
		thread.terminate(ds.thread, 0)
		thread.destroy(ds.thread)
	}

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	b := strings.builder_make(alloc)
	strings.write_string(&b, "http://127.0.0.1:")
	strings.write_int(&b, int(bound.port))
	strings.write_string(&b, "/")

	c := http.DEFAULT_CLIENT
	res, cerr := http.client_get(&c, strings.to_string(b), alloc)

	testing.expect_value(t, cerr, http.Client_Error.None)
	testing.expect_value(t, res.status, http.Status.OK)
	testing.expect_value(t, res.body, "hi")

	marker, has := http.headers_get(res.headers, "x-marker")
	testing.expect(t, has, "the header must be present")
	testing.expect_value(t, marker, "marker-value-intact")

	ctype, has_ct := http.headers_get(res.headers, "content-type")
	testing.expect(t, has_ct, "")
	testing.expect_value(t, ctype, "text/plain")
}

/*
The client's parsed response must not depend on how the server's bytes arrive.

This is where the first of the aliasing defects lived: header names and values
are slices into the read buffer, and compacting that buffer while the header
block was incomplete slid bytes out from under them. A `Location` header came
back as "ngth: 0\r\n7.0.0.1:8044/next" — fragments of `Content-Length` spliced
in — and the redirect silently went nowhere.

A server replying in one write never triggers it, which is why every existing
client test passed. Driving the read loop over a memory transport with a capped
read size reproduces a dribbling origin without sockets or sleeps.
*/
@(private)
Client_Delivery_Case :: struct {
	name:   string,
	raw:    string,
	method: http.Method,
}

/*
Parses a response with a capped read size, flattening it to a comparable string.

The status, body and every header are included: a defect that corrupts one
header while leaving the body intact must still show up.
*/
@(private)
client_parse_chunked :: proc(raw: string, method: http.Method, read_chunk: int) -> string {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	mt: http.Memory_Transport
	http.memory_transport_init(&mt, transmute([]byte)raw)
	defer http.memory_transport_destroy(&mt)
	mt.read_chunk = read_chunk

	c := http.DEFAULT_CLIENT
	res, err := http.client_read_memory(&mt, &c, method, alloc)

	b := strings.builder_make(context.temp_allocator)
	// The numeric value rather than a name: a hand-written formatter drifts
	// from the enum, and what matters here is only that two runs agree.
	strings.write_string(&b, "err=")
	strings.write_int(&b, int(err))
	strings.write_string(&b, " status=")
	strings.write_int(&b, int(res.status))
	strings.write_string(&b, " body=")
	strings.write_string(&b, res.body)
	for e in res.headers.entries {
		strings.write_string(&b, " [")
		strings.write_string(&b, e.name)
		strings.write_string(&b, "=")
		strings.write_string(&b, e.value)
		strings.write_string(&b, "]")
	}
	return strings.clone(strings.to_string(b), context.temp_allocator)
}

@(test)
test_client_parse_is_independent_of_read_sizes :: proc(t: ^testing.T) {
	cases := []Client_Delivery_Case{
		{"content-length", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n" +
			"X-Marker: marker-value-intact\r\nContent-Type: text/plain\r\n\r\nhello", .Get},
		{"redirect", "HTTP/1.1 302 Found\r\nLocation: http://example.test/next\r\n" +
			"Content-Length: 0\r\nX-Marker: marker-value-intact\r\n\r\n", .Get},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" +
			"X-Marker: marker-value-intact\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", .Get},
		{"no content", "HTTP/1.1 204 No Content\r\nX-Marker: marker-value-intact\r\n\r\n", .Get},
		{"head", "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n" +
			"X-Marker: marker-value-intact\r\n\r\n", .Head},
		{"many headers", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nA: 1\r\nB: 2\r\nC: 3\r\n" +
			"D: 4\r\nX-Marker: marker-value-intact\r\n\r\nhi", .Get},
		// Malformed: the same verdict must be reached however the bytes arrive.
		{"conflicting framing", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", .Get},
	}

	for c in cases {
		reference := client_parse_chunked(c.raw, c.method, 0)

		for chunk in ([]int{1, 3, 17}) {
			got := client_parse_chunked(c.raw, c.method, chunk)
			testing.expectf(t, got == reference,
				"%s: read size %d gave %q, single delivery gave %q",
				c.name, chunk, got, reference)
		}
	}
}

/*
A response body past the read buffer must not corrupt its own headers.

The mirror of the server's rule, and the case `response_detach` exists for. The
compaction guard above withholds recycling only until the header block is done;
past that the body recycles the buffer freely, and the copy is the only thing
keeping the already-parsed headers valid.

The client's buffer is a fixed 16 KiB rather than an option, so unlike the
server this cannot be reached by shrinking the buffer — the body has to actually
exceed it. No other client test sends one that large, which left the copy
load-bearing but unpinned: deleting it kept the whole suite green.

The body is filled with plausible header lines, so a lapse produces a
`Location` an origin never sent rather than obvious garbage — a redirect the
body's author chose.
*/
@(test)
test_client_oversized_body_preserves_headers :: proc(t: ^testing.T) {
	// Comfortably past CLIENT_READ_BUFFER (16 KiB), so the buffer is recycled
	// many times over while the parsed headers are still live.
	filler := strings.repeat("Location: http://evil.test/spoofed\r\nX-Marker: spoofed\r\n",
		512, context.temp_allocator)

	raw := strings.concatenate({
		"HTTP/1.1 200 OK\r\n",
		"Location: http://origin.test/authentic\r\n",
		"X-Marker: marker-value-intact\r\n",
		"Content-Length: ", itoa(len(filler)), "\r\n\r\n",
		filler,
	}, context.temp_allocator)

	reference := client_parse_chunked(raw, .Get, 0)

	// Whole delivery still compacts here (the body outruns the buffer either
	// way), so the reference alone would not catch a lapse — hence the explicit
	// value checks below.
	for chunk in ([]int{1, 7, 4096}) {
		got := client_parse_chunked(raw, .Get, chunk)
		testing.expectf(t, got == reference,
			"read size %d gave %q, single delivery gave %q", chunk, got, reference)
	}

	/*
	Checked against the headers alone, at every delivery pattern.

	Two things this shape is deliberate about. The flattened form above includes
	the body, which legitimately contains the decoy lines, so a substring search
	over it would fire on correct output — these read the headers directly.

	And the sweep matters as much as it does for the server: with the copy
	removed, whole delivery corrupts the headers while one byte at a time leaves
	them intact, so a single read size would report a pass either way.
	*/
	for chunk in ([]int{0, 1, 7, 4096}) {
		loc, marker := client_oversized_headers(raw, chunk)

		testing.expectf(t, loc == "http://origin.test/authentic",
			"read size %d: the origin's Location must survive a body that recycles the buffer, got %q",
			chunk, loc)
		testing.expectf(t, marker == "marker-value-intact",
			"read size %d: header values must not alias recycled buffer space, got %q",
			chunk, marker)
	}
}

// Parses the response and returns just the two canary header values.
@(private)
client_oversized_headers :: proc(raw: string, read_chunk: int) -> (location: string, marker: string) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	mt: http.Memory_Transport
	http.memory_transport_init(&mt, transmute([]byte)raw)
	defer http.memory_transport_destroy(&mt)
	mt.read_chunk = read_chunk

	c := http.DEFAULT_CLIENT
	res, _ := http.client_read_memory(&mt, &c, .Get, alloc)

	l, _ := http.headers_get(res.headers, "location")
	m, _ := http.headers_get(res.headers, "x-marker")
	// Copied out before the arena holding them is destroyed.
	return strings.clone(l, context.temp_allocator),
	       strings.clone(m, context.temp_allocator)
}

/*
An over-sending peer is caught wherever its extra bytes happen to be.

Two guards cover this, and which one fires depends entirely on read boundaries:

  - `unsolicited_data` is set when the parser finishes a response with bytes
    still in the read buffer.
  - `has_pending` asks the transport whether the socket holds unread bytes.

They look redundant and are not. Delivered whole, the forged response is already
buffered when parsing completes, so `unsolicited_data` catches it and
`has_pending` sees nothing. Delivered a byte at a time, the parser finishes
exactly as the last legitimate byte arrives — the forged bytes are still in the
socket, `consumed == filled`, and only `has_pending` catches it.

Removing either leaves a delivery pattern under which a poisoned connection
returns to the pool, so the next request on it reads a response the origin never
sent for it.
*/
@(test)
test_oversending_peer_is_caught_at_any_read_size :: proc(t: ^testing.T) {
	// A complete response immediately followed by one that was never requested.
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst" +
	       "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nFORGED"

	Observation :: struct {
		unsolicited: bool,
		pending:     bool,
	}
	seen := make([dynamic]Observation, 0, 4, context.temp_allocator)

	for chunk in ([]int{0, 1, 7, 44}) {
		arena: virtual.Arena
		_ = virtual.arena_init_growing(&arena)
		defer virtual.arena_destroy(&arena)

		mt: http.Memory_Transport
		http.memory_transport_init(&mt, transmute([]byte)raw)
		defer http.memory_transport_destroy(&mt)
		mt.read_chunk = chunk

		c := http.DEFAULT_CLIENT
		res, err := http.client_read_memory(&mt, &c, .Get, virtual.arena_allocator(&arena))

		// The legitimate response is returned intact regardless of delivery.
		testing.expectf(t, err == http.Client_Error.None, "read size %d: %v", chunk, err)
		testing.expectf(t, res.body == "first",
			"read size %d returned %q, not the first response", chunk, res.body)

		pending := mt.has_pending(&mt.base)
		append(&seen, Observation{res.unsolicited_data, pending})

		// Whichever guard fired, the connection must not be reused.
		testing.expectf(t, res.unsolicited_data || pending,
			"read size %d: an over-sending peer went undetected", chunk)
	}

	// Both guards must be load-bearing: if one alone sufficed for every read
	// size, the other could be deleted without a failing test.
	only_unsolicited, only_pending := false, false
	for o in seen {
		if  o.unsolicited && !o.pending { only_unsolicited = true }
		if !o.unsolicited &&  o.pending { only_pending     = true }
	}
	testing.expect(t, only_unsolicited,
		"some delivery must be caught by unsolicited_data alone")
	testing.expect(t, only_pending,
		"some delivery must be caught by has_pending alone")
}

/*
The URL scheme is case-insensitive (RFC 3986 3.1, RFC 9110 4.2.3).

Matching only the lowercase spelling refused `HTTPS://host/path`, which is legal
and which Go's `net/url` normalises without complaint. The failure mode was
quiet: an absolute Location in uppercase fell through to the relative-reference
path, the leading-slash check refused it, and the caller got the bare 302 back —
indistinguishable from an origin that simply chose not to redirect.

The stored scheme is always normalised, so the checks downstream of parsing see
one spelling. That is what keeps the https-to-http downgrade guard from being
bypassable by spelling the target `HTTP://`, which the last case below pins.
*/
@(test)
test_client_url_scheme_is_case_insensitive :: proc(t: ^testing.T) {
	Case :: struct {
		raw:    string,
		scheme: string,
		tls:    bool,
		port:   int,
	}

	cases := []Case{
		{"http://example.test/x",  "http",  false, 80},
		{"HTTP://example.test/x",  "http",  false, 80},
		{"HtTp://example.test/x",  "http",  false, 80},
		{"https://example.test/x", "https", true,  443},
		{"HTTPS://example.test/x", "https", true,  443},
		{"hTtPs://example.test/x", "https", true,  443},
	}

	for c in cases {
		u, ok := http.client_url_parse(c.raw, context.temp_allocator)
		testing.expectf(t, ok, "%q must parse", c.raw)
		if !ok { continue }

		// Normalised, not echoed: downstream comparisons must see one spelling.
		testing.expectf(t, u.scheme == c.scheme,
			"%q gave scheme %q, want %q", c.raw, u.scheme, c.scheme)
		testing.expectf(t, u.is_tls == c.tls, "%q gave is_tls %v", c.raw, u.is_tls)
		testing.expectf(t, u.port == c.port, "%q gave port %v", c.raw, u.port)
		testing.expectf(t, u.host == "example.test", "%q gave host %q", c.raw, u.host)
	}

	// A scheme this client does not speak is still refused, whatever its case.
	for bad in ([]string{"ftp://example.test/x", "FTP://example.test/x",
	                     "file:///etc/passwd", "next", "//example.test/x"}) {
		_, ok := http.client_url_parse(bad, context.temp_allocator)
		testing.expectf(t, !ok, "%q must not parse as an HTTP URL", bad)
	}
}

/*
An uppercase scheme must not smuggle a redirect past the downgrade check.

`is_tls` is derived from the normalised scheme, so `HTTP://` and `http://` are
the same target as far as the https-to-http rule is concerned. Case-sensitive
matching upstream could have made an uppercase downgrade take a different path
through the resolver than the lowercase one it is meant to mirror.
*/
@(test)
test_client_downgrade_check_ignores_scheme_case :: proc(t: ^testing.T) {
	Loc :: struct { value: string }
	loc := new(Loc, context.allocator)
	defer free(loc)

	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle(&r, "GET /start", http.handler_from_poly(loc,
		proc(l: ^Loc, q: ^http.Request, s: ^http.Response) {
			http.headers_set(&s.headers, "location", l.value)
			s.status = .Found
		}))
	http.router_handle_proc(&r, "GET /landed", proc(q: ^http.Request, s: ^http.Response) {
		http.respond_plain(s, .OK, "LANDED")
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)
	alloc := virtual.arena_allocator(&arena)

	origin := strings.builder_make(alloc)
	strings.write_string(&origin, "http://127.0.0.1:")
	strings.write_int(&origin, int(ts.endpoint.port))

	// An absolute Location in either case must be followed identically.
	for prefix in ([]string{"http://127.0.0.1:", "HTTP://127.0.0.1:"}) {
		target := strings.builder_make(alloc)
		strings.write_string(&target, prefix)
		strings.write_int(&target, int(ts.endpoint.port))
		strings.write_string(&target, "/landed")
		loc.value = strings.to_string(target)

		c := http.DEFAULT_CLIENT
		res, err := http.client_get(&c,
			strings.concatenate({strings.to_string(origin), "/start"}, alloc), alloc)

		testing.expectf(t, err == http.Client_Error.None, "%q: %v", prefix, err)
		testing.expectf(t, res.status == http.Status.OK,
			"%q was not followed, status %v", prefix, res.status)
		testing.expectf(t, res.body == "LANDED", "%q gave body %q", prefix, res.body)
	}
}
