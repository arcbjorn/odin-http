# odin-http

An HTTP/1.1 server for Odin, written as if it were a standard library package.

Built on a sans-I/O parser: the protocol logic never touches a socket, so the
same code is driven by the blocking server, by tests one byte at a time, and
(later) by an event loop.

## Status

HTTP/1.1 server, blocking thread-per-connection driver, router, middleware,
cookies, chunked streaming responses, and static file serving with byte
ranges. 124 tests passing, including end-to-end coverage over real sockets.

Not yet implemented: TLS, HTTP client, HTTP/2, the `core:nbio` event-loop driver.

## Example

```odin
package main

import "core:net"
import http "path/to/http"

main :: proc() {
	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	http.router_handle_proc(&router, "GET /", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_html(res, .OK, "<h1>Hello from Odin</h1>")
	})

	http.router_handle_proc(&router, "GET /greet/{name}", proc(req: ^http.Request, res: ^http.Response) {
		name := http.request_param(req, "name")
		http.respond_plain(res, .OK, name)
	})

	server: http.Server
	http.server_listen(&server, {address = net.IP4_Loopback, port = 8080})
	http.server_serve(&server, http.router_handler(&router))
}
```

## Design

**Sans-I/O parser.** `parser_feed` takes bytes and returns `(consumed, event)`.
It allocates nothing and borrows all strings from the caller's buffer. This is
what makes the byte-at-a-time tests possible, and those tests are what catch the
bugs that only appear when a token straddles a TCP segment boundary.

**Arena per connection, reset per request.** The arena is created once when a
connection opens and `free_all`'d between requests, so a keep-alive connection
stops allocating entirely after its first request. The read buffer lives outside
the arena on purpose: request strings borrow from it, and a pipelined next
request may already be sitting in it when the reset happens.

**Borrowed strings are detached once headers are parsed.** The parser returns
slices into the read buffer, which is what makes it allocation-free — but a body
larger than the buffer forces the driver to recycle that buffer mid-request. The
server therefore calls `request_detach` at `Headers_Done`, copying the target and
headers into the arena before any further read. This is not an optimization
detail: without it a 20 KB upload had its target silently aliased to body bytes,
so the routed path became attacker-controlled. `tests/largebody_test.odin` pins
the rule on both the Content-Length and chunked paths.

**Strict parsing.** Nearly every request smuggling technique works by getting
two implementations to disagree about framing. The parser rejects rather than
normalizes:

| Input | Result |
|---|---|
| `Transfer-Encoding` + `Content-Length` | 400, close |
| Conflicting duplicate `Content-Length` | 400, close |
| `Content-Length : 5` (space before colon) | 400, close |
| Obsolete line folding | 400, close |
| `Content-Length: +5` / `0x5` | 400, close |
| Bare CR not followed by LF | 400, close |
| Unknown `Transfer-Encoding` | 400, close |
| Missing/duplicate `Host` on HTTP/1.1 | 400, close |
| Chunked trailers | parsed, never merged into headers |

Every parse error closes the connection: once framing is ambiguous, the stream
cannot be trusted to resynchronize.

Response-side, header values containing CR or LF are rejected at the call site
rather than sanitized, so response splitting fails loudly where it is introduced.

**Handlers.** Odin has no interfaces, so Go's `http.Handler` becomes an explicit
closure — a proc pointer plus its data, which is what a Go interface value is at
runtime anyway.

```odin
// Stateless.
h := http.handler_from_proc(proc(req: ^http.Request, res: ^http.Response) {
	http.respond_plain(res, .OK, "hi")
})

// With typed state; the cast lives in the library, not your handler.
counter := Counter{}
h := http.handler_from_poly(&counter, proc(c: ^Counter, req: ^http.Request, res: ^http.Response) {
	c.hits += 1
})

// Middleware wraps another handler and decides whether to call it.
auth := http.middleware(&inner, proc(h: ^http.Handler, req: ^http.Request, res: ^http.Response) {
	if _, ok := http.headers_get(req.headers, "authorization"); !ok {
		http.respond_status(res, .Unauthorized)
		return
	}
	http.handler_serve(h.next, req, res)
})
```

## Cookies

```odin
// Secure + HttpOnly + SameSite=Lax by default.
http.response_set_cookie(res, http.cookie_session("sid", token))

sid, ok := http.request_cookie(req, "sid")
http.response_delete_cookie(res, "sid")
```

`Set-Cookie` is emitted as one header per cookie, never joined — an `Expires`
date contains a comma, so a joined value is ambiguous to clients.

Values are validated rather than escaped, so a cookie carrying `; HttpOnly`,
a comma, a backslash, or CRLF is rejected at the call site instead of forging an
attribute or splitting the response. `SameSite=None` without `Secure` is also
refused, since browsers silently drop it.

**Router.** Modelled on Go 1.22's `ServeMux`: `GET /users/{id}` and
`GET /static/{path...}`. Matching is by specificity, not registration order, so
`/users/me` beats `/users/{id}` regardless of source order. A path that matches
a route under a different method returns 405 with `Allow`, not 404.

## Static files

```odin
fs := http.DEFAULT_FILE_SERVER
fs.root = "./public"
http.router_handle(&router, "GET /static/{path...}", http.file_server_handler(&fs))
```

Serves with `Content-Type` by extension, `ETag`, `Last-Modified`,
`Cache-Control`, and `X-Content-Type-Options: nosniff`. Honours `If-None-Match`
(including `*` and weak comparison) and `If-Modified-Since`, returning 304 with
no body.

**Bodies stream, they are not buffered.** Reading a file whole costs one full
copy of it per concurrent request, so a handful of requests for a large file
exhausts memory. Measured on a 200 MB file: **207 MB RSS buffered vs 1.8 MB
streamed**, for byte-identical output. `file_chunk_size` (64 KiB default) bounds
peak memory regardless of file size.

`Range` is supported — `bytes=2-5`, `bytes=4-`, and `bytes=-3` — returning 206
with `Content-Range`. A range past EOF is clamped; one starting at or past EOF
is 416 with `bytes */<size>` so the client can retry. Multi-range requests fall
back to the whole file rather than building a multipart body, which RFC 9110
14.2 permits. `If-Range` is honoured: a stale validator serves the full file
rather than a range of content the client never saw.

Path handling is layered, because this is where file servers get exploited:

1. The router percent-decodes before matching.
2. Bytes dangerous in any position are rejected — NUL (truncates paths in C
   APIs) and backslash (a separator on Windows).
3. The path is lexically cleaned, resolving `.` and `..` without touching the
   filesystem, so it cannot be raced or redirected through a symlink.
4. A `..` that would escape the root is **refused**, not clamped. Clamping is
   safe but silently serves a different file than the one requested; a 404
   makes the attempt visible.

Verified against `../secret`, `%2e%2e%2f`, `..%2f`, `....//`, and raw
socket-level traversal — all 404.

An unknown extension falls back to `application/octet-stream` rather than
sniffing content, since a wrong guess of `text/html` on user data is stored XSS.
Directory listing is not implemented; without an index file a directory is 404.

## Streaming responses

When the length is not known when the headers go out — generated exports,
server-sent events, proxied content — the handler sets a stream callback instead
of a body. The server frames each write as an HTTP chunk:

```odin
http.response_set_stream(res, &feed, proc(w: ^http.Stream_Writer, f: ^Feed) {
	for row in f.rows {
		http.stream_write_string(w, row)
	}
})
```

The response is sent with `Transfer-Encoding: chunked` and no `Content-Length` —
emitting both is the smuggling shape the parser rejects on input, so it is never
produced on output. Nothing is buffered: `examples/stream` generates 10,000 rows
(134 KB) with RSS flat at 1.8 MB.

Write errors latch on the writer, so a producer loop can run to completion and
be checked once rather than after every write. A failed stream closes the
connection instead of sending the terminating chunk, since a terminator would
tell the client a truncated body was complete.

## Panics

Odin has no `recover`: `Assertion_Failure_Proc` returns `!`, so a panic in a
handler terminates the whole server process, taking every other connection with
it. That cannot be fixed at the library level — but the diagnosis can be. Each
connection installs a handler that names the request before the process dies:

```
main.odin(13:3) panic: handler exploded
  while serving: GET /boom from Endpoint{address = [127, 0, 0, 1], port = 61396}
  NOTE: a panic in a handler terminates the whole server; handle errors instead of panicking
```

Handlers should return error responses rather than panic.

## I/O model

Blocking, one thread per connection. Handler code is straight-line, request
lifetime is the stack frame, and a blocking handler blocks only its own
connection.

The trade-off is real: one OS thread per connection caps concurrency in the low
thousands, and idle keep-alive connections each hold a thread. Timeouts
(`idle_timeout`, `read_timeout`, `write_timeout`) bound Slowloris; deployments
needing C10k should wait for the `core:nbio` driver or sit behind a proxy.

Because the parser is sans-I/O, that second driver requires no parser changes.

## Testing

```sh
odin test tests
odin run examples/hello
```

Two levels, because they catch different bugs. A `Recorder` runs a handler with
no sockets at all:

```odin
rec: http.Recorder
http.recorder_init(&rec, .Get, "/users/42")
defer http.recorder_destroy(&rec)

http.recorder_serve(&rec, &handler)
assert(http.recorder_status(&rec) == .OK)
```

A `Test_Server` binds an ephemeral loopback port and runs the real accept loop,
which is the only way to cover framing, keep-alive, and pipelining — a handler
that passes against a Recorder can still deadlock on a live connection:

```odin
ts: http.Test_Server
http.test_server_start(&ts, handler)
defer http.test_server_stop(&ts)

resp, _ := http.test_request_raw(ts.endpoint, "GET /hello HTTP/1.1\r\nHost: x\r\n\r\n")
```

The client speaks raw bytes on purpose: asserting on exact wire output requires
sending malformed input that a well-behaved client could not produce.

## Shutdown

`server_shutdown` stops the accept loop; `server_serve` then drains in-flight
connections before returning. Connection threads are detached, so returning
early would leave them dereferencing a `Server` the caller is free to free.
`shutdown_timeout` bounds the wait so one wedged handler cannot hang shutdown
forever.

## License

MIT
