package http

import "core:mem"
import "core:strings"

/*
A request multiplexer, modelled on Go 1.22's enhanced ServeMux.

Patterns are "[METHOD ]/path", where `{name}` matches one segment and
`{name...}` matches the rest:

	router_handle(&r, "GET /users/{id}", h)
	router_handle(&r, "GET /static/{path...}", h)
	router_handle(&r, "/health", h)              // any method

Matching is by specificity, not registration order, so route order in the source
does not affect behaviour.
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
	// Index of the value captured by a `{name...}` segment, or -1. Recorded so
	// that a mounted sub-handler can find the un-prefixed remainder of the path
	// without having to know the pattern it was mounted under.
	rest:   int,
}

params_get :: proc(p: Params, name: string) -> (value: string, ok: bool) #optional_ok {
	for i in 0..<p.count {
		if p.keys[i] == name { return p.values[i], true }
	}
	return "", false
}

/*
Returns the value captured by a `{name...}` segment.

Guarded against a zero-valued Params (no route matched, or a route with no rest
wildcard), where `rest` is 0 but `count` is 0 as well.
*/
params_rest :: proc(p: Params) -> (value: string, ok: bool) #optional_ok {
	if p.rest < 0 || p.rest >= p.count { return "", false }
	return p.values[p.rest], true
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
	h, p, res := router_match_ex(r, method, path)
	return h, p, res == .Found
}

Match_Result :: enum u8 {
	Found,
	Not_Found,
	// The path matched a route, but not for this method. RFC 9110 15.5.6
	// distinguishes this from 404 so a client can tell "no such resource" from
	// "wrong verb".
	Method_Not_Allowed,
}

/*
Like `router_match`, but distinguishes a method mismatch from a missing route.

Returns which methods are allowed via `params` being unset and the result being
`.Method_Not_Allowed`; use `router_allowed_methods` to build the Allow header.
*/
router_match_ex :: proc(r: ^Router, method: Method, path: string) -> (handler: ^Handler, params: Params, result: Match_Result) {
	best_score := -1
	best: ^Route
	path_matched := false

	for &route in r.routes {
		p, score, ok := match_route(&route, path)
		if !ok { continue }

		// The path matches this route's shape, so a 404 is no longer correct
		// even if the method turns out to be wrong.
		path_matched = true

		if m, has := route.method.?; has && m != method {
			continue
		}

		if score > best_score {
			best_score = score
			best = &route
			params = p
		}
	}

	if best == nil {
		return nil, {}, .Method_Not_Allowed if path_matched else .Not_Found
	}
	return &best.handler, params, .Found
}

/*
Collects the methods registered for a path, for the Allow header.

RFC 9110 15.5.6 requires a 405 response to carry Allow.
*/
router_allowed_methods :: proc(r: ^Router, path: string, allocator := context.temp_allocator) -> string {
	b := strings.builder_make(allocator)
	seen: bit_set[Method]

	for &route in r.routes {
		_, _, ok := match_route(&route, path)
		if !ok { continue }

		m, has := route.method.?
		if !has {
			// A method-less route accepts everything, so enumerating is moot.
			return "GET, HEAD, POST, PUT, PATCH, DELETE, CONNECT, OPTIONS, TRACE"
		}
		if m in seen { continue }
		seen += {m}

		if strings.builder_len(b) > 0 {
			strings.write_string(&b, ", ")
		}
		strings.write_string(&b, method_string(m))

		// A registered GET implies HEAD, which the server serves by running the
		// GET handler and dropping the body.
		if m == .Get {
			strings.write_string(&b, ", HEAD")
		}
	}

	return strings.to_string(b)
}

@(private)
match_route :: proc(route: ^Route, path: string) -> (params: Params, score: int, ok: bool) {
	params.rest = -1

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
				params.rest = params.count
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
			params.rest = params.count
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

			// `OPTIONS *` asks about the server as a whole rather than any
			// resource, so no path route can match it (RFC 9112 3.2.4). The
			// router answers it directly instead of 404ing.
			if request_is_asterisk(req) {
				headers_set(&res.headers, "allow", router_server_methods(r, req.headers.allocator))
				res.status = .No_Content
				return
			}

			// Routing uses the decoded path so that %2F cannot be used to fake
			// an extra segment boundary.
			path := request_path(req)
			decoded := percent_decode(path, req.headers.allocator) or_else path

			handler, params, result := router_match_ex(r, req.method, decoded)

			switch result {
			case .Found:
				req.params = params
				handler_serve(handler, req, res)

			case .Method_Not_Allowed:
				// RFC 9110 15.5.6 requires Allow on a 405.
				allow := router_allowed_methods(r, decoded, req.headers.allocator)
				if len(allow) > 0 {
					headers_set(&res.headers, "allow", allow)
				}
				respond_status(res, .Method_Not_Allowed)

			case .Not_Found:
				if nf, has := r.not_found.?; has {
					nf := nf
					handler_serve(&nf, req, res)
					return
				}
				respond_status(res, .Not_Found)
			}
		},
		data = r,
	}
}

/*
Collects every method any route responds to, for `OPTIONS *`.

RFC 9112 3.2.4: the asterisk target asks what the server as a whole supports,
not what a particular resource supports, so this is the union across all routes
rather than a per-path answer.
*/
router_server_methods :: proc(r: ^Router, allocator := context.temp_allocator) -> string {
	seen: bit_set[Method]
	for &route in r.routes {
		m, has := route.method.?
		if !has {
			// A method-less route accepts anything, so enumerating stops here.
			return "GET, HEAD, POST, PUT, PATCH, DELETE, CONNECT, OPTIONS, TRACE"
		}
		seen += {m}
	}

	// OPTIONS is always answerable, since this handler is answering it.
	seen += {.Options}
	// A registered GET implies HEAD, which the server serves from the same
	// handler with the body dropped.
	if .Get in seen { seen += {.Head} }

	b := strings.builder_make(allocator)
	for m in Method {
		if m not_in seen { continue }
		if strings.builder_len(b) > 0 { strings.write_string(&b, ", ") }
		strings.write_string(&b, method_string(m))
	}
	return strings.to_string(b)
}
