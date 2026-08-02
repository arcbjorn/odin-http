package http

/*
The handler abstraction.

Go expresses this as an interface:

	type Handler interface { ServeHTTP(ResponseWriter, *Request) }

Odin has no interfaces, so the equivalent is an explicit closure: a procedure
pointer plus the data it needs. That is what a Go interface value is at runtime
anyway (a pair of pointers), the difference being that Odin makes the pair
visible.

`data` is untyped so that handlers can carry arbitrary state. Prefer
`handler_from_proc` for stateless handlers and `handler_from_poly` when the
state has a concrete type, since the latter keeps the cast in one place instead
of scattering `cast(^T)` through user code.
*/
Handler :: struct {
	proc_: proc(h: ^Handler, req: ^Request, res: ^Response),
	data:  rawptr,
	// Set by middleware to reach the handler it wraps.
	next:  ^Handler,
	// Storage for a user procedure when `proc_` is a generated trampoline.
	// Kept separate from `next` so that a poly handler can still be wrapped.
	_user_proc: rawptr,
}

handler_serve :: #force_inline proc(h: ^Handler, req: ^Request, res: ^Response) {
	h.proc_(h, req, res)
}

// Builds a Handler from a plain procedure that needs no state.
handler_from_proc :: proc(p: proc(req: ^Request, res: ^Response)) -> Handler {
	return Handler{
		proc_ = proc(h: ^Handler, req: ^Request, res: ^Response) {
			p := cast(proc(req: ^Request, res: ^Response))h._user_proc
			p(req, res)
		},
		_user_proc = rawptr(p),
	}
}

/*
Builds a Handler from a procedure plus typed state, keeping `rawptr` handling
out of handler bodies.

`data` is shared by every connection and handlers run concurrently, so mutation
must be synchronized. A plain `n += 1` loses about one update in several
thousand under load — enough to pass casual testing and corrupt counts in
production.

	c := Counter{}
	h := handler_from_poly(&c, proc(c: ^Counter, req: ^Request, res: ^Response) {
		sync.atomic_add(&c.n, 1)
	})

Read-only state needs no synchronization.
*/
handler_from_poly :: proc(
	data: ^$T,
	p: proc(data: ^T, req: ^Request, res: ^Response),
) -> Handler {
	return Handler{
		proc_ = proc(h: ^Handler, req: ^Request, res: ^Response) {
			p := cast(proc(data: ^T, req: ^Request, res: ^Response))h._user_proc
			p(cast(^T)h.data, req, res)
		},
		data = data,
		_user_proc = rawptr(p),
	}
}

/*
Middleware: a handler that wraps another handler.

Go writes this as `func(http.Handler) http.Handler`. Here the wrapped handler
goes in `next`, and the middleware decides whether to call it.

	logging := middleware(&inner, proc(h: ^Handler, req: ^Request, res: ^Response) {
		log.info(req.target)
		handler_serve(h.next, req, res)
	})
*/
middleware :: proc(
	next: ^Handler,
	p: proc(h: ^Handler, req: ^Request, res: ^Response),
) -> Handler {
	return Handler{proc_ = p, next = next}
}
