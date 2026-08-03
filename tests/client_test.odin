package tests

import "core:mem/virtual"
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
