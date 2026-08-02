# odin-http

An HTTP/1.1 server for Odin, written as if it were a standard library package.

Built on a sans-I/O parser: the protocol logic never touches a socket, so the
same code is driven by the blocking server, by tests one byte at a time, and
(later) by an event loop.

## Status

HTTP/1.1 server, blocking thread-per-connection driver. 48 tests passing.

Not yet implemented: TLS, HTTP client, static file serving, HTTP/2.

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

**Router.** Modelled on Go 1.22's `ServeMux`: `GET /users/{id}` and
`GET /static/{path...}`. Matching is by specificity, not registration order, so
`/users/me` beats `/users/{id}` regardless of source order.

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

## License

MIT
