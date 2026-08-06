package tests

import "core:strings"
import "core:testing"

import http "../http"

@(private)
noop :: proc(req: ^http.Request, res: ^http.Response) {}

@(test)
test_router_literal_match :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	testing.expect(t, http.router_handle_proc(&r, "GET /health", noop), "")

	_, _, found := http.router_match(&r, .Get, "/health")
	testing.expect(t, found, "exact path should match")

	_, _, missing := http.router_match(&r, .Get, "/other")
	testing.expect(t, !missing, "different path must not match")
}

@(test)
test_router_method_is_significant :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /users", noop)

	_, _, get_found := http.router_match(&r, .Get, "/users")
	testing.expect(t, get_found, "GET should match")

	_, _, post_found := http.router_match(&r, .Post, "/users")
	testing.expect(t, !post_found, "POST must not match a GET-only route")
}

@(test)
test_router_method_optional :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	// No method prefix means any method matches.
	http.router_handle_proc(&r, "/any", noop)

	_, _, a := http.router_match(&r, .Get, "/any")
	_, _, b := http.router_match(&r, .Delete, "/any")
	testing.expect(t, a && b, "method-less pattern should match every method")
}

@(test)
test_router_captures_wildcard :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /users/{id}", noop)

	_, params, found := http.router_match(&r, .Get, "/users/42")
	testing.expect(t, found, "wildcard should match one segment")

	id, ok := http.params_get(params, "id")
	testing.expect(t, ok, "id should be captured")
	testing.expect_value(t, id, "42")
}

@(test)
test_router_wildcard_matches_single_segment_only :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /users/{id}", noop)

	_, _, found := http.router_match(&r, .Get, "/users/42/posts")
	testing.expect(t, !found, "{id} must not span a '/'")
}

@(test)
test_router_rest_wildcard :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /static/{path...}", noop)

	_, params, found := http.router_match(&r, .Get, "/static/css/app.css")
	testing.expect(t, found, "rest wildcard should span slashes")

	p, _ := http.params_get(params, "path")
	testing.expect_value(t, p, "css/app.css")
}

@(test)
test_router_prefers_literal_over_wildcard :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	// Registered wildcard-first on purpose: specificity must win over order,
	// otherwise routing becomes dependent on source ordering.
	http.router_handle_proc(&r, "GET /users/{id}", noop)
	http.router_handle_proc(&r, "GET /users/me", noop)

	_, params, found := http.router_match(&r, .Get, "/users/me")
	testing.expect(t, found, "")
	_, captured := http.params_get(params, "id")
	testing.expect(t, !captured, "the literal route should win, capturing nothing")
}

@(test)
test_router_rejects_bad_patterns :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	testing.expect(t, !http.router_handle_proc(&r, "GET relative", noop), "must start with /")
	testing.expect(t, !http.router_handle_proc(&r, "BREW /coffee", noop), "unknown method")
	testing.expect(t, !http.router_handle_proc(&r, "GET /a/{}", noop), "empty wildcard name")
	testing.expect(t, !http.router_handle_proc(&r, "GET /{rest...}/tail", noop), "rest must be last")
}

// --- URL and path safety ---

@(test)
test_percent_decoding :: proc(t: ^testing.T) {
	d1, ok1 := http.percent_decode("/a%20b", context.temp_allocator)
	testing.expect(t, ok1, "")
	testing.expect_value(t, d1, "/a b")

	// Invalid escapes must fail rather than pass through, so that a decoded
	// path can be trusted by callers.
	_, ok2 := http.percent_decode("/a%2", context.temp_allocator)
	testing.expect(t, !ok2, "truncated escape must fail")

	_, ok3 := http.percent_decode("/a%zz", context.temp_allocator)
	testing.expect(t, !ok3, "non-hex escape must fail")
}

@(test)
test_path_traversal_is_rejected :: proc(t: ^testing.T) {
	testing.expect(t, http.url_path_is_safe("/static/app.css"), "ordinary path is safe")

	testing.expect(t, !http.url_path_is_safe("/../etc/passwd"), "parent traversal")
	testing.expect(t, !http.url_path_is_safe("/static/../../etc/passwd"), "nested traversal")
	testing.expect(t, !http.url_path_is_safe("relative/path"), "must be absolute")
	testing.expect(t, !http.url_path_is_safe("/static/\\..\\x"), "backslash is a separator on Windows")

	// The check must run on the DECODED path; this is the encoded form that
	// bypasses naive pre-decode checks.
	decoded, ok := http.percent_decode("/%2e%2e/etc/passwd", context.temp_allocator)
	testing.expect(t, ok, "")
	testing.expect(t, !http.url_path_is_safe(decoded), "encoded traversal must fail after decoding")
}

@(test)
test_url_parse_splits_query_and_fragment :: proc(t: ^testing.T) {
	u := http.url_parse("/search?q=odin&n=10#frag", context.temp_allocator)
	testing.expect_value(t, u.path, "/search")
	testing.expect_value(t, u.raw_query, "q=odin&n=10")
	testing.expect_value(t, u.fragment, "frag")
}

@(test)
test_query_parse :: proc(t: ^testing.T) {
	v := http.query_parse("q=hello+world&n=10", context.temp_allocator)
	// '+' means space in form encoding, but not in a path.
	testing.expect_value(t, v["q"], "hello world")
	testing.expect_value(t, v["n"], "10")
}

@(test)
test_router_405_when_path_matches_other_method :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /users", noop)
	http.router_handle_proc(&r, "DELETE /users", noop)

	// RFC 9110 15.5.6: the path exists, so the wrong verb is 405, not 404.
	_, _, result := http.router_match_ex(&r, .Post, "/users")
	testing.expect_value(t, result, http.Match_Result.Method_Not_Allowed)

	// A path that matches no route at all is still 404.
	_, _, missing := http.router_match_ex(&r, .Get, "/nope")
	testing.expect_value(t, missing, http.Match_Result.Not_Found)

	_, _, ok := http.router_match_ex(&r, .Get, "/users")
	testing.expect_value(t, ok, http.Match_Result.Found)
}

@(test)
test_router_allowed_methods :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /users", noop)
	http.router_handle_proc(&r, "DELETE /users", noop)

	allow := http.router_allowed_methods(&r, "/users", context.temp_allocator)
	// A registered GET implies HEAD, which the server serves from the same
	// handler with the body dropped.
	testing.expect_value(t, allow, "GET, HEAD, DELETE")
}

/*
`Allow` must name the methods that would actually work.

RFC 9110 15.5.6 requires the header on a 405; what it contains is what a client
uses to decide whether to retry. The existing tests assert the header is
present, or that it equals "GET, HEAD" for one route — neither notices if the
set is computed from the wrong routes, or if a registered GET stops implying
HEAD.

The server serves HEAD by running the GET handler and dropping the body, so a
route registered for GET must advertise both. Omitting HEAD tells a client the
one method it can safely use is unavailable.
*/
@(test)
test_allowed_methods_names_what_works :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	noop :: proc(req: ^http.Request, res: ^http.Response) {}

	http.router_handle_proc(&r, "GET /only-get", noop)
	http.router_handle_proc(&r, "POST /multi", noop)
	http.router_handle_proc(&r, "DELETE /multi", noop)
	http.router_handle_proc(&r, "GET /mixed", noop)
	http.router_handle_proc(&r, "PUT /mixed", noop)

	Case :: struct {
		path: string,
		want: string,
	}

	cases := []Case{
		// A registered GET implies HEAD, in that order.
		{"/only-get", "GET, HEAD"},
		// Registration order is preserved, and unrelated routes are excluded.
		{"/multi", "POST, DELETE"},
		{"/mixed", "GET, HEAD, PUT"},
	}

	for c in cases {
		got := http.router_allowed_methods(&r, c.path, context.temp_allocator)
		testing.expectf(t, got == c.want, "%s allowed %q, want %q", c.path, got, c.want)
	}

	// A path matching no route allows nothing, rather than reporting a set
	// borrowed from some other path.
	none := http.router_allowed_methods(&r, "/nothing-here", context.temp_allocator)
	testing.expect_value(t, none, "")
}

/*
`OPTIONS *` reports the union across every route (RFC 9112 3.2.4).

It asks about the server as a whole, so the answer is not any one route's set.
The existing test checks only that the header exists and mentions OPTIONS, which
a wrong union would still satisfy.
*/
@(test)
test_options_asterisk_reports_the_union :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	noop :: proc(req: ^http.Request, res: ^http.Response) {}

	http.router_handle_proc(&r, "GET /a", noop)
	http.router_handle_proc(&r, "POST /b", noop)
	http.router_handle_proc(&r, "DELETE /c", noop)

	got := http.router_server_methods(&r, context.temp_allocator)

	// GET implies HEAD, and OPTIONS is answerable because this is answering it.
	for want in ([]string{"GET", "HEAD", "POST", "DELETE", "OPTIONS"}) {
		testing.expectf(t, strings.contains(got, want),
			"OPTIONS * reported %q, missing %s", got, want)
	}

	// Methods no route serves must not be advertised.
	for absent in ([]string{"PUT", "PATCH", "TRACE"}) {
		testing.expectf(t, !strings.contains(got, absent),
			"OPTIONS * reported %q, which advertises %s with no route", got, absent)
	}
}
