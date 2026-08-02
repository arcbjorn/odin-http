package tests

import "core:mem/virtual"
import "core:strings"
import "core:testing"
import "core:time"

import http "../http"

@(test)
test_cookie_serialize_basic :: proc(t: ^testing.T) {
	got, ok := http.cookie_serialize(http.Cookie{
		name    = "sid",
		value   = "abc123",
		path    = "/",
		max_age = -1,
	}, context.temp_allocator)

	testing.expect(t, ok, "")
	testing.expect_value(t, got, "sid=abc123; Path=/")
}

@(test)
test_cookie_session_defaults_are_hardened :: proc(t: ^testing.T) {
	got, ok := http.cookie_serialize(http.cookie_session("sid", "abc"), context.temp_allocator)

	testing.expect(t, ok, "")
	// HttpOnly keeps a stored XSS from reading the token; Secure keeps it off
	// plaintext connections; SameSite=Lax blunts CSRF.
	testing.expect_value(t, got, "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
}

@(test)
test_cookie_all_attributes :: proc(t: ^testing.T) {
	got, ok := http.cookie_serialize(http.Cookie{
		name        = "a",
		value       = "b",
		domain      = "example.com",
		path        = "/app",
		expires     = {_nsec = 1614834367 * 1_000_000_000},
		max_age     = 3600,
		secure      = true,
		http_only   = true,
		same_site   = .Strict,
		partitioned = true,
	}, context.temp_allocator)

	testing.expect(t, ok, "")
	testing.expect_value(t, got,
		"a=b; Domain=example.com; Path=/app; Expires=Thu, 04 Mar 2021 05:06:07 GMT; " +
		"Max-Age=3600; Secure; HttpOnly; SameSite=Strict; Partitioned")
}

@(test)
test_cookie_max_age_zero_is_emitted :: proc(t: ^testing.T) {
	// Max-Age=0 is how a cookie is deleted, so it must not be treated as unset.
	got, ok := http.cookie_serialize(http.Cookie{name = "a", value = "", max_age = 0}, context.temp_allocator)

	testing.expect(t, ok, "")
	testing.expect_value(t, got, "a=; Max-Age=0")
}

@(test)
test_cookie_rejects_injection :: proc(t: ^testing.T) {
	// Each of these would let a value forge an attribute or split the header.
	attacks := []http.Cookie{
		{name = "a", value = "b; HttpOnly",       max_age = -1}, // forge an attribute
		{name = "a", value = "b\r\nX-Evil: 1",    max_age = -1}, // response splitting
		{name = "a", value = "b\nX-Evil: 1",      max_age = -1},
		{name = "a", value = "b,c",               max_age = -1}, // pair separator
		{name = "a", value = "b\\c",              max_age = -1},
		{name = "a b", value = "c",               max_age = -1}, // invalid name
		{name = "a=b", value = "c",               max_age = -1},
		{name = "a", value = "b", domain = "x;Secure", max_age = -1},
		{name = "a", value = "b", path = "/x\r\ny", max_age = -1},
	}

	for c in attacks {
		_, ok := http.cookie_serialize(c, context.temp_allocator)
		testing.expectf(t, !ok, "cookie %q=%q must be rejected", c.name, c.value)
	}
}

@(test)
test_cookie_samesite_none_requires_secure :: proc(t: ^testing.T) {
	// Browsers drop `SameSite=None` without Secure, so emitting it would
	// produce a cookie that silently never gets set.
	_, ok := http.cookie_serialize(http.Cookie{
		name = "a", value = "b", same_site = .None, secure = false, max_age = -1,
	}, context.temp_allocator)
	testing.expect(t, !ok, "SameSite=None without Secure must be rejected")

	got, ok2 := http.cookie_serialize(http.Cookie{
		name = "a", value = "b", same_site = .None, secure = true, max_age = -1,
	}, context.temp_allocator)
	testing.expect(t, ok2, "SameSite=None with Secure is valid")
	testing.expect(t, strings.contains(got, "SameSite=None"), "")
}

@(test)
test_request_cookie_parsing :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	req: http.Request
	http.request_init(&req, virtual.arena_allocator(&arena))
	http.headers_set(&req.headers, "cookie", `sid=abc123; theme=dark; quoted="q"`)

	sid, ok := http.request_cookie(&req, "sid")
	testing.expect(t, ok, "sid should be found")
	testing.expect_value(t, sid, "abc123")

	theme, _ := http.request_cookie(&req, "theme")
	testing.expect_value(t, theme, "dark")

	// The DQUOTE wrapper is syntax, not part of the value.
	q, _ := http.request_cookie(&req, "quoted")
	testing.expect_value(t, q, "q")

	_, missing := http.request_cookie(&req, "nope")
	testing.expect(t, !missing, "absent cookie reports not-found")
}

@(test)
test_request_cookie_names_are_case_sensitive :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	req: http.Request
	http.request_init(&req, virtual.arena_allocator(&arena))
	http.headers_set(&req.headers, "cookie", "SID=upper")

	// RFC 6265 4.1.1: unlike header names, cookie names are case-sensitive.
	_, lower := http.request_cookie(&req, "sid")
	testing.expect(t, !lower, "cookie names must not be folded")

	upper, ok := http.request_cookie(&req, "SID")
	testing.expect(t, ok, "")
	testing.expect_value(t, upper, "upper")
}

@(test)
test_request_cookies_map :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	req: http.Request
	http.request_init(&req, virtual.arena_allocator(&arena))
	http.headers_set(&req.headers, "cookie", "a=1; b=2; a=3")

	all := http.request_cookies(&req, context.temp_allocator)
	testing.expect_value(t, all["a"], "1")   // first occurrence wins
	testing.expect_value(t, all["b"], "2")
	testing.expect_value(t, len(all), 2)
}

@(test)
test_set_cookie_headers_are_not_joined :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res: http.Response
	http.response_init(&res, virtual.arena_allocator(&arena))
	http.respond_plain(&res, .OK, "x")

	testing.expect(t, http.response_set_cookie(&res, http.cookie_session("a", "1")), "")
	testing.expect(t, http.response_set_cookie(&res, http.cookie_session("b", "2")), "")

	out := strings.builder_make(virtual.arena_allocator(&arena))
	http.response_write(&res, &out, "Mon, 02 Jan 2006 15:04:05 GMT")
	rendered := strings.to_string(out)

	// Joining Set-Cookie with ", " is the classic bug: an Expires date contains
	// a comma, so a joined value is ambiguous to the client.
	testing.expect(t, strings.contains(rendered, "set-cookie: a=1;"), "first cookie")
	testing.expect(t, strings.contains(rendered, "set-cookie: b=2;"), "second cookie")
	testing.expect(t, !strings.contains(rendered, "set-cookie: a=1; Path=/; Secure; HttpOnly; SameSite=Lax, b=2"),
		"cookies must be separate headers, never joined")
}

@(test)
test_delete_cookie :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	res: http.Response
	http.response_init(&res, virtual.arena_allocator(&arena))
	testing.expect(t, http.response_delete_cookie(&res, "sid"), "")

	out := strings.builder_make(virtual.arena_allocator(&arena))
	http.response_write(&res, &out, "")
	rendered := strings.to_string(out)

	testing.expect(t, strings.contains(rendered, "set-cookie: sid=; Path=/; Max-Age=0"),
		"deletion is an empty value with Max-Age=0")
}

@(test)
test_cookie_expires_omitted_when_zero :: proc(t: ^testing.T) {
	got, ok := http.cookie_serialize(http.Cookie{
		name = "a", value = "b", max_age = -1, expires = time.Time{},
	}, context.temp_allocator)

	testing.expect(t, ok, "")
	testing.expect(t, !strings.contains(got, "Expires"), "a zero time must not emit Expires")
}
