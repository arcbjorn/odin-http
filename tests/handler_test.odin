package tests

import "core:mem/virtual"
import "core:strings"
import "core:testing"

import http "../http"

/*
Handler and middleware tests.

Odin has no interfaces, so `Handler` is a procedure pointer plus untyped state.
That makes these tests worth more than they would be in Go: a wrong cast is not
a compile error here, it is a silent memory bug.
*/

@(private)
Ctx :: struct {
	arena: virtual.Arena,
	req:   http.Request,
	res:   http.Response,
}

@(private)
ctx_init :: proc(c: ^Ctx) {
	err := virtual.arena_init_growing(&c.arena)
	assert(err == nil)
	allocator := virtual.arena_allocator(&c.arena)
	http.request_init(&c.req, allocator)
	http.response_init(&c.res, allocator)
}

@(private)
ctx_destroy :: proc(c: ^Ctx) {
	virtual.arena_destroy(&c.arena)
}

@(test)
test_handler_from_proc :: proc(t: ^testing.T) {
	c: Ctx
	ctx_init(&c)
	defer ctx_destroy(&c)

	h := http.handler_from_proc(proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "from proc")
	})

	http.handler_serve(&h, &c.req, &c.res)

	testing.expect_value(t, c.res.status, http.Status.OK)
	testing.expect_value(t, strings.to_string(c.res.body), "from proc")
}

@(test)
test_handler_from_poly_carries_typed_state :: proc(t: ^testing.T) {
	c: Ctx
	ctx_init(&c)
	defer ctx_destroy(&c)

	Counter :: struct { hits: int }
	counter := Counter{}

	h := http.handler_from_poly(&counter, proc(state: ^Counter, req: ^http.Request, res: ^http.Response) {
		state.hits += 1
		http.respond_status(res, .OK)
	})

	http.handler_serve(&h, &c.req, &c.res)
	http.handler_serve(&h, &c.req, &c.res)
	http.handler_serve(&h, &c.req, &c.res)

	// State must be shared through the pointer, not copied into the handler.
	testing.expect_value(t, counter.hits, 3)
}

@(test)
test_middleware_wraps_handler :: proc(t: ^testing.T) {
	c: Ctx
	ctx_init(&c)
	defer ctx_destroy(&c)

	inner := http.handler_from_proc(proc(req: ^http.Request, res: ^http.Response) {
		http.response_write_string(res, "inner")
	})

	outer := http.middleware(&inner, proc(h: ^http.Handler, req: ^http.Request, res: ^http.Response) {
		http.response_write_string(res, "[")
		http.handler_serve(h.next, req, res)
		http.response_write_string(res, "]")
	})

	http.handler_serve(&outer, &c.req, &c.res)

	// The middleware must run around the wrapped handler, not instead of it.
	testing.expect_value(t, strings.to_string(c.res.body), "[inner]")
}

@(test)
test_middleware_can_short_circuit :: proc(t: ^testing.T) {
	c: Ctx
	ctx_init(&c)
	defer ctx_destroy(&c)

	inner := http.handler_from_proc(proc(req: ^http.Request, res: ^http.Response) {
		http.response_write_string(res, "should not run")
	})

	// An auth middleware rejects before the wrapped handler ever sees the
	// request; this is the whole point of the pattern.
	auth := http.middleware(&inner, proc(h: ^http.Handler, req: ^http.Request, res: ^http.Response) {
		if _, ok := http.headers_get(req.headers, "authorization"); !ok {
			http.respond_status(res, .Unauthorized)
			return
		}
		http.handler_serve(h.next, req, res)
	})

	http.handler_serve(&auth, &c.req, &c.res)

	testing.expect_value(t, c.res.status, http.Status.Unauthorized)
	testing.expect(t, !strings.contains(strings.to_string(c.res.body), "should not run"),
		"wrapped handler must not run when middleware short-circuits")
}

@(test)
test_middleware_chain_order :: proc(t: ^testing.T) {
	c: Ctx
	ctx_init(&c)
	defer ctx_destroy(&c)

	inner := http.handler_from_proc(proc(req: ^http.Request, res: ^http.Response) {
		http.response_write_string(res, "H")
	})

	mw1 := http.middleware(&inner, proc(h: ^http.Handler, req: ^http.Request, res: ^http.Response) {
		http.response_write_string(res, "1")
		http.handler_serve(h.next, req, res)
		http.response_write_string(res, "1")
	})

	mw2 := http.middleware(&mw1, proc(h: ^http.Handler, req: ^http.Request, res: ^http.Response) {
		http.response_write_string(res, "2")
		http.handler_serve(h.next, req, res)
		http.response_write_string(res, "2")
	})

	http.handler_serve(&mw2, &c.req, &c.res)

	// Outermost middleware runs first and finishes last.
	testing.expect_value(t, strings.to_string(c.res.body), "21H12")
}

@(test)
test_middleware_wrapping_poly_handler :: proc(t: ^testing.T) {
	c: Ctx
	ctx_init(&c)
	defer ctx_destroy(&c)

	// A poly handler stores its user procedure separately from `next`, so it
	// must still be wrappable. Storing both in one field would corrupt this.
	State :: struct { label: string }
	state := State{label = "poly"}

	inner := http.handler_from_poly(&state, proc(s: ^State, req: ^http.Request, res: ^http.Response) {
		http.response_write_string(res, s.label)
	})

	outer := http.middleware(&inner, proc(h: ^http.Handler, req: ^http.Request, res: ^http.Response) {
		http.response_write_string(res, "<")
		http.handler_serve(h.next, req, res)
		http.response_write_string(res, ">")
	})

	http.handler_serve(&outer, &c.req, &c.res)

	testing.expect_value(t, strings.to_string(c.res.body), "<poly>")
}

@(test)
test_router_as_handler_dispatches :: proc(t: ^testing.T) {
	c: Ctx
	ctx_init(&c)
	defer ctx_destroy(&c)

	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /users/{id}", proc(req: ^http.Request, res: ^http.Response) {
		id := http.request_param(req, "id")
		http.respond_plain(res, .OK, id)
	})

	c.req.method = .Get
	c.req.target = "/users/99"

	h := http.router_handler(&r)
	http.handler_serve(&h, &c.req, &c.res)

	// The router must place captured params on the request before dispatching.
	testing.expect_value(t, strings.to_string(c.res.body), "99")
}

@(test)
test_router_handler_404_and_405 :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /only-get", proc(req: ^http.Request, res: ^http.Response) {})

	{
		c: Ctx
		ctx_init(&c)
		defer ctx_destroy(&c)
		c.req.method = .Get
		c.req.target = "/missing"

		h := http.router_handler(&r)
		http.handler_serve(&h, &c.req, &c.res)
		testing.expect_value(t, c.res.status, http.Status.Not_Found)
	}
	{
		c: Ctx
		ctx_init(&c)
		defer ctx_destroy(&c)
		c.req.method = .Post
		c.req.target = "/only-get"

		h := http.router_handler(&r)
		http.handler_serve(&h, &c.req, &c.res)

		testing.expect_value(t, c.res.status, http.Status.Method_Not_Allowed)
		allow, has := http.headers_get(c.res.headers, "allow")
		testing.expect(t, has, "RFC 9110 15.5.6 requires Allow on a 405")
		testing.expect_value(t, allow, "GET, HEAD")
	}
}

@(test)
test_router_decodes_before_matching :: proc(t: ^testing.T) {
	c: Ctx
	ctx_init(&c)
	defer ctx_destroy(&c)

	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /files/{name}", proc(req: ^http.Request, res: ^http.Response) {
		name := http.request_param(req, "name")
		http.respond_plain(res, .OK, name)
	})

	// %20 is a space within one segment, so it must not create a new segment.
	c.req.method = .Get
	c.req.target = "/files/my%20file.txt"

	h := http.router_handler(&r)
	http.handler_serve(&h, &c.req, &c.res)

	testing.expect_value(t, strings.to_string(c.res.body), "my file.txt")
}
