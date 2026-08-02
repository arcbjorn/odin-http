package http

import "core:mem"
import "core:strings"

/*
A request multiplexer, modelled on Go 1.22's enhanced ServeMux.

Patterns are "[METHOD ]/path", where a path segment of the form `{name}` matches
one segment and `{name...}` matches the remaining path:

	router_handle(&r, "GET /users/{id}", h)
	router_handle(&r, "GET /static/{path...}", h)
	router_handle(&r, "/health", h)              // any method

Matching is by specificity rather than registration order, so route order in the
source has no effect on behaviour. That property is worth the extra scoring
work: order-dependent routing is a common source of "why is this 404" bugs.
*/
Router :: struct {
	routes:    [dynamic]Route,
	not_found: Maybe(Handler),
	allocator: mem.Allocator,
}

Route :: struct {
	method:   Maybe(Method),
	segments: []Segment,
	handler:  Handler,
}

Segment_Kind :: enum u8 {
	Literal,
	Wildcard,
	Wildcard_Rest,
}

Segment :: struct {
	kind:  Segment_Kind,
	value: string,
}

// Path parameters captured by a wildcard, valid for the request's lifetime.
Params :: struct {
	keys:   [16]string,
	values: [16]string,
	count:  int,
}

params_get :: proc(p: Params, name: string) -> (value: string, ok: bool) #optional_ok {
	for i in 0..<p.count {
		if p.keys[i] == name { return p.values[i], true }
	}
	return "", false
}

router_init :: proc(r: ^Router, allocator := context.allocator) {
	r.allocator = allocator
	r.routes.allocator = allocator
}

router_destroy :: proc(r: ^Router) {
	for route in r.routes {
		delete(route.segments, r.allocator)
	}
	delete(r.routes)
}

/*
Registers a handler for a pattern.

Returns false if the pattern is malformed, rather than panicking, so that
routes built from configuration cannot take the process down.
*/
router_handle :: proc(r: ^Router, pattern: string, handler: Handler) -> bool {
	method: Maybe(Method)
	path := pattern

	if sp := index_byte(pattern, ' '); sp >= 0 {
		m, ok := method_parse(pattern[:sp])
		if !ok { return false }
		method = m
		path = trim_ows(pattern[sp + 1:])
	}

	if len(path) == 0 || path[0] != '/' { return false }

	segments, ok := parse_pattern(path, r.allocator)
	if !ok { return false }

	append(&r.routes, Route{method = method, segments = segments, handler = handler})
	return true
}

// Convenience wrapper for the common stateless case.
router_handle_proc :: proc(r: ^Router, pattern: string, p: proc(req: ^Request, res: ^Response)) -> bool {
	return router_handle(r, pattern, handler_from_proc(p))
}

@(private)
parse_pattern :: proc(path: string, allocator: mem.Allocator) -> (segments: []Segment, ok: bool) {
	count := 0
	for i in 0..<len(path) {
		if path[i] == '/' { count += 1 }
	}

	segs := make([dynamic]Segment, 0, count, allocator)

	start := 1
	for i := 1; i <= len(path); i += 1 {
		if i != len(path) && path[i] != '/' { continue }

		seg := path[start:i]
		start = i + 1

		// A trailing slash produces an empty final segment, which is not a
		// meaningful path component.
		if len(seg) == 0 { continue }

		if len(seg) >= 2 && seg[0] == '{' && seg[len(seg) - 1] == '}' {
			name := seg[1:len(seg) - 1]
			if strings.has_suffix(name, "...") {
				// A rest wildcard only makes sense as the final segment.
				if i != len(path) {
					delete(segs)
					return nil, false
				}
				append(&segs, Segment{.Wildcard_Rest, name[:len(name) - 3]})
			} else {
				if len(name) == 0 {
					delete(segs)
					return nil, false
				}
				append(&segs, Segment{.Wildcard, name})
			}
			continue
		}

		append(&segs, Segment{.Literal, seg})
	}

	return segs[:], true
}

/*
Finds the best route for a request.

Scoring prefers literal segments over wildcards and single wildcards over rest
wildcards, so `/users/me` wins over `/users/{id}` regardless of which was
registered first.
*/
router_match :: proc(r: ^Router, method: Method, path: string) -> (handler: ^Handler, params: Params, found: bool) {
	best_score := -1
	best: ^Route

	for &route in r.routes {
		if m, has := route.method.?; has && m != method {
			continue
		}

		p, score, ok := match_route(&route, path)
		if !ok { continue }

		if score > best_score {
			best_score = score
			best = &route
			params = p
		}
	}

	if best == nil { return nil, {}, false }
	return &best.handler, params, true
}

@(private)
match_route :: proc(route: ^Route, path: string) -> (params: Params, score: int, ok: bool) {
	seg_index := 0
	start := 1

	for i := 1; i <= len(path); i += 1 {
		if i != len(path) && path[i] != '/' { continue }

		seg := path[start:i]
		next_start := i + 1

		if len(seg) == 0 {
			start = next_start
			continue
		}

		if seg_index >= len(route.segments) { return {}, 0, false }

		pattern := route.segments[seg_index]
		switch pattern.kind {
		case .Literal:
			if seg != pattern.value { return {}, 0, false }
			score += 3

		case .Wildcard:
			if params.count < len(params.keys) {
				params.keys[params.count] = pattern.value
				params.values[params.count] = seg
				params.count += 1
			}
			score += 2

		case .Wildcard_Rest:
			// Consumes the remainder of the path, including any slashes.
			if params.count < len(params.keys) {
				params.keys[params.count] = pattern.value
				params.values[params.count] = path[start:]
				params.count += 1
			}
			return params, score + 1, true
		}

		seg_index += 1
		start = next_start
	}

	// A trailing rest wildcard may legitimately match zero segments.
	if seg_index == len(route.segments) - 1 &&
	   route.segments[seg_index].kind == .Wildcard_Rest {
		if params.count < len(params.keys) {
			params.keys[params.count] = route.segments[seg_index].value
			params.values[params.count] = ""
			params.count += 1
		}
		return params, score + 1, true
	}

	if seg_index != len(route.segments) { return {}, 0, false }
	return params, score, true
}

/*
Builds a Handler that dispatches through the router.

The matched parameters are stashed on the request so handlers can read them with
`request_param`.
*/
router_handler :: proc(r: ^Router) -> Handler {
	return Handler{
		proc_ = proc(h: ^Handler, req: ^Request, res: ^Response) {
			r := cast(^Router)h.data

			// Routing uses the decoded path so that %2F cannot be used to fake
			// an extra segment boundary.
			path := request_path(req)
			decoded := percent_decode(path, req.headers.allocator) or_else path

			handler, params, found := router_match(r, req.method, decoded)
			if !found {
				if nf, has := r.not_found.?; has {
					nf := nf
					handler_serve(&nf, req, res)
					return
				}
				respond_status(res, .Not_Found)
				return
			}

			req.params = params
			handler_serve(handler, req, res)
		},
		data = r,
	}
}
