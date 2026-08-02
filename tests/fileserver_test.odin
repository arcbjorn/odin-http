package tests

import "core:testing"

import http "../http"

@(test)
test_path_clean :: proc(t: ^testing.T) {
	cases := [][2]string{
		{"/",                  "/"},
		{"/a/b",               "/a/b"},
		{"/a//b",              "/a/b"},          // repeated separators collapse
		{"/a/./b",             "/a/b"},          // "." is a no-op
		{"/a/b/..",            "/a"},            // ".." pops a segment
		{"/a/b/../c",          "/a/c"},
		{"/a/../..",           "/"},             // cannot rise above the root
		{"/../../etc/passwd",  "/etc/passwd"},   // leading ".." is dropped
		{"/a/b/",              "/a/b"},          // trailing slash is removed
		{"//",                 "/"},
	}

	for c in cases {
		got := http.path_clean(c[0], context.temp_allocator)
		testing.expectf(t, got == c[1], "path_clean(%q) = %q, want %q", c[0], got, c[1])
	}
}

@(test)
test_file_path_resolve_blocks_traversal :: proc(t: ^testing.T) {
	// Each of these must be refused outright rather than resolved to something
	// outside the root.
	attacks := []string{
		"../etc/passwd",
		"/../etc/passwd",
		"a/../../etc/passwd",
		"..\\windows\\system32",   // backslash is a separator on Windows
		"a/\x00b",                 // NUL truncates the path in C APIs
	}

	for attack in attacks {
		_, ok := http.file_path_resolve("/srv/www", attack, context.temp_allocator)
		testing.expectf(t, !ok, "path %q must be rejected", attack)
	}
}

@(test)
test_file_path_resolve_allows_normal_paths :: proc(t: ^testing.T) {
	full, ok := http.file_path_resolve("/srv/www", "css/app.css", context.temp_allocator)
	testing.expect(t, ok, "ordinary relative path should resolve")
	testing.expect_value(t, full, "/srv/www/css/app.css")

	rooted, ok2 := http.file_path_resolve("/srv/www", "/img/logo.png", context.temp_allocator)
	testing.expect(t, ok2, "rooted path should resolve")
	testing.expect_value(t, rooted, "/srv/www/img/logo.png")

	// Interior ".." that stays inside the root is fine once cleaned.
	inner, ok3 := http.file_path_resolve("/srv/www", "a/b/../c.txt", context.temp_allocator)
	testing.expect(t, ok3, "interior .. that stays in root is allowed")
	testing.expect_value(t, inner, "/srv/www/a/c.txt")
}

@(test)
test_file_path_resolve_after_percent_decoding :: proc(t: ^testing.T) {
	// The encoded traversal only becomes dangerous once decoded, which is why
	// the safety check must run on the decoded form.
	decoded, ok := http.percent_decode("%2e%2e%2fetc%2fpasswd", context.temp_allocator)
	testing.expect(t, ok, "")
	testing.expect_value(t, decoded, "../etc/passwd")

	_, resolved := http.file_path_resolve("/srv/www", decoded, context.temp_allocator)
	testing.expect(t, !resolved, "decoded traversal must be rejected")
}

@(test)
test_mime_by_extension :: proc(t: ^testing.T) {
	testing.expect_value(t, http.mime_by_extension("/a/index.html"), "text/html; charset=utf-8")
	testing.expect_value(t, http.mime_by_extension("app.css"), "text/css; charset=utf-8")
	testing.expect_value(t, http.mime_by_extension("bundle.js"), "text/javascript; charset=utf-8")
	testing.expect_value(t, http.mime_by_extension("logo.PNG"), "image/png")

	// An unknown or absent extension must not be guessed at: serving unknown
	// bytes as text/html is a stored-XSS vector.
	testing.expect_value(t, http.mime_by_extension("data.unknown"), http.DEFAULT_CONTENT_TYPE)
	testing.expect_value(t, http.mime_by_extension("README"), http.DEFAULT_CONTENT_TYPE)

	// A dot in a directory name is not an extension.
	testing.expect_value(t, http.mime_by_extension("/v1.0/README"), http.DEFAULT_CONTENT_TYPE)
	// A leading dot means a dotfile, not an extension.
	testing.expect_value(t, http.mime_by_extension("/etc/.bashrc"), http.DEFAULT_CONTENT_TYPE)
}

@(test)
test_router_rest_param_accessor :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /static/{path...}", noop)

	_, params, found := http.router_match(&r, .Get, "/static/css/app.css")
	testing.expect(t, found, "")

	rest, ok := http.params_rest(params)
	testing.expect(t, ok, "rest capture should be reported")
	testing.expect_value(t, rest, "css/app.css")
}

@(test)
test_params_rest_absent_on_plain_wildcard :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /users/{id}", noop)

	_, params, found := http.router_match(&r, .Get, "/users/42")
	testing.expect(t, found, "")

	// A zero-valued `rest` index must not be mistaken for a real capture.
	_, ok := http.params_rest(params)
	testing.expect(t, !ok, "a single wildcard is not a rest capture")
}
