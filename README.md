# odin-http

An HTTP/1.1 server for Odin, written as if it were a standard library package.

Built on a sans-I/O parser: the protocol logic never touches a socket, so the
same code is driven by the blocking server, by tests one byte at a time, and
(later) by an event loop.

## Status

HTTP/1.1 server and client, router, middleware, cookies, chunked streaming
responses, TLS with certificate verification, and static file serving with byte
ranges. 263 tests passing, including end-to-end coverage over real sockets.

Not yet implemented: HTTP/2, the `core:nbio` event-loop driver. The nbio driver needs more than a new transport: `serve_one` blocks on
`transport->read` in a loop, so an event-loop version has to invert that loop
into callbacks. The parser is reusable as-is; the driver is not.

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

**All three server-side request-target forms are handled** (RFC 9112 3.2).
Routing on the raw target meant an absolute-form request — `GET
http://host/path`, which is how every HTTP/1.1 proxy forwards — matched no route
and 404'd, so the server could not sit behind a proxy. `request_path` now strips
the scheme and authority; the authority is deliberately *not* used for routing,
since `Host` is the authoritative source and trusting the target would let a
request claim any host. `OPTIONS *` is answered server-wide with `Allow` rather
than 404. Asterisk-form for any other method, and authority-form (CONNECT only),
are rejected with 400.

**`Expect: 100-continue` is answered.** A client sending it waits for permission
before transmitting the body. Silence still works — the client eventually gives
up and sends — but costs it a full grace period: measured at **1.01 s per request
with curl, versus 0.012 s once answered**. An expectation the server cannot
satisfy gets 417 rather than being ignored, and HTTP/1.0 clients get no interim
response since the mechanism postdates them.

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
// The state is shared by every connection and handlers run concurrently, so
// mutation must be synchronized — see "Handler state" below.
counter := Counter{}
h := http.handler_from_poly(&counter, proc(c: ^Counter, req: ^http.Request, res: ^http.Response) {
	sync.atomic_add(&c.hits, 1)
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

### Handler state

`handler_from_poly` gives every connection the same state pointer, and the
server runs each connection on its own thread, so a handler body runs
concurrently with itself. Unsynchronized mutation is a data race.

It is a quiet one: a plain `c.hits += 1` measured **4799 of 4800** increments
under load. Rare enough to survive casual testing, wrong in production. Use an
atomic or a mutex. Read-only state — configuration, templates, a connection
handle that locks internally — needs nothing.

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

## Client

```odin
arena: virtual.Arena
virtual.arena_init_growing(&arena)
defer virtual.arena_destroy(&arena)

c := http.DEFAULT_CLIENT
res, err := http.client_get(&c, "https://example.com/", virtual.arena_allocator(&arena))
```

The response borrows from the arena, so one destroy frees everything.

The client shares the parser with the server rather than reimplementing one:
`Parse_Role` selects the first-line grammar and a few framing rules, and
everything else — chunked decoding, header validation, the smuggling defences —
is the same code. A fix on one side is a fix on both.

**Interim 1xx responses are skipped.** RFC 9110 15.2 requires a client to be
prepared for one or more informational responses before the real one, and both
`100 Continue` and `103 Early Hints` are sent by deployed servers. Treating the
first status line as the answer returned `Continue` with an empty body — the
client was broken against any such server. Interim headers are discarded rather
than merged, so an Early Hints `Link` never leaks into the final response, and
the count is bounded so a peer cannot stream interim responses indefinitely.

Response framing differs from requests in two ways that matter. Bodyless
statuses and HEAD responses are honoured regardless of headers (RFC 9112 6.3),
since reading a body there would consume the next response on a reused
connection. And a response with no framing headers is delimited by connection
close, which a request can never be.

**Certificates are verified, and there is no flag to disable it.** Chain
validation against the system trust store, hostname matching via `SSL_set1_host`,
and SNI are all mandatory. Verified against `badssl.com`:

| Host | Result |
|---|---|
| `expired.badssl.com` | `TLS_Failed` |
| `wrong.host.badssl.com` | `TLS_Failed` |
| `self-signed.badssl.com` | `TLS_Failed` |
| `untrusted-root.badssl.com` | `TLS_Failed` |
| `sha256.badssl.com` | 200 OK |

To talk to a self-signed development server, add its certificate to a trust
store. An insecure mode reliably ends up in production, so the library does not
offer one.

Redirects are followed up to `max_redirects` (5 by default), with 301/302/303
switching to GET and dropping the body, plus two safety rules browsers and curl
both enforce:

- **An https to http redirect fails** with `.Insecure_Redirect` rather than
  silently dropping TLS. Verified against `http.badssl.com`, which issues a real
  https-to-http 301 in the wild.
- **Credential headers are stripped when the redirect crosses an origin** —
  `Authorization`, `Proxy-Authorization`, and `Cookie`. Without this a redirect
  hands the caller's token to whatever host the `Location` header names, which
  is the standard way a redirect becomes credential theft. Same-origin redirects
  keep them, so ordinary authenticated flows still work. `limits.max_body` bounds what a hostile
server can make the client allocate, and `connect_timeout` bounds the TLS
handshake as well as the TCP connect. That matters because `read_timeout` only
applies once a connection is usable: a host that accepts TCP and then never
sends a ServerHello previously left the client blocked in `SSL_connect`
indefinitely. Measured against a mute peer — before, still stuck past 8 s with a
2 s timeout configured; after, returns in 2.009 s.

### Connection pooling

Opening a connection dominates the cost of a small request. Measured against
example.com over 5 requests:

| | Per request |
|---|---|
| HTTPS, no pool | 80.5 ms |
| HTTPS, pooled | **21.9 ms** |

A **3.7x speedup**, because the TLS handshake is paid once instead of per
request.

```odin
pool: http.Pool
http.pool_init(&pool)
defer http.pool_destroy(&pool)

c := http.DEFAULT_CLIENT
c.pool = &pool
```

Keyed by origin — scheme, host and port — so a connection to
`https://example.com` is never handed out for `http://example.com` or a
different port. Bounded by `max_idle` (32) and `idle_timeout` (60 s), evicting
oldest-first.

**A pooled connection carrying unread bytes is retired, not reused.** This
client does not pipeline, so it has exactly one request outstanding at a time —
anything the peer sends beyond the response was never asked for. Reusing such a
connection lets those bytes become the *next* response, a forged reply the
caller cannot distinguish from a real one. That is response smuggling, and
pooling is what makes it reachable: without reuse there is no next request to
poison. The check runs when a connection is taken from the pool as well as when
it is returned, because a peer can send the extra bytes after the connection has
already gone idle. Buffered-but-undelivered TLS data counts too, since it is
just as capable of becoming the next response.

A pooled connection may have been closed by the peer while idle, which only
surfaces on the next read. The client retries once on a fresh connection, so
that reads as a normal request rather than a spurious failure. Only a *reused*
connection earns the retry — retrying a connection just opened would double
every genuine failure. A response saying `Connection: close`, or one delimited
by connection close, is discarded rather than pooled.

Pooling is opt-in: without `c.pool` the client sends `Connection: close` and
closes after each response, which is the polite default for one-off requests.

## TLS

```odin
tls: http.TLS_Config
http.tls_config_init(&tls, "cert.pem", "key.pem")
defer http.tls_config_destroy(&tls)

opts := http.DEFAULT_SERVER_OPTS
opts.tls = &tls
http.server_listen(&server, {address = net.IP4_Loopback, port = 8443}, opts)
```

Everything above the socket speaks bytes through a `Transport` interface —
`read`, `write`, `close`, `set_timeout`. The parser, response writer, and
streaming code have no idea whether a connection is encrypted, so TLS is a
backend rather than a fork of the request path.

That shape is deliberate. Odin has no TLS in core; the maintainers estimate a
native implementation at "a man year's worth of work to do well" and plan a
swappable backend API instead. The OpenSSL backend here satisfies that
interface; a pure-Odin stack or SChannel would satisfy the same one.

Verified end to end: **TLSv1.3 / TLS_AES_256_GCM_SHA384**, keep-alive across
requests, TLS 1.1 refused (1.2 is the enforced minimum per RFC 8996), and plain
HTTP to the TLS port refused rather than served. A failed handshake — scanners,
no shared cipher — is logged at debug, since it is attacker-triggerable and must
not be a way to flood the log.

Server-side only. A client would need certificate verification against a trust
store, which is the genuinely hard part of TLS and not something to half-do.

On macOS the library is linked by path, since Apple removed libssl from the
system; Linux resolves `system:ssl` normally.

## I/O model

Blocking, one thread per connection. Handler code is straight-line, request
lifetime is the stack frame, and a blocking handler blocks only its own
connection.

Every read from a peer is bounded before it starts. That includes the TLS
handshake: unbounded, `max_connections` sockets that connect and send nothing
held every thread forever and took the server offline permanently, at a cost of
zero traffic. Measured with 4 slots and a 2 s timeout — before the fix, 4 of 4
threads were still held after 6 s; after, 0.

Nothing that reads from a peer runs on the accept thread. The TLS handshake in
particular happens on the connection thread: doing it during accept let a client
that connected and then sent nothing block the loop indefinitely, so a single
socket stopped the server accepting anything at all. Verified with a controlled
test — before the fix, a second client could not connect within 5 s; after, it
is served immediately.

Connection threads are started with `self_cleanup`, which matters more than it
looks: `thread.destroy` **joins**, so calling it in the accept loop would block
that loop for the entire life of the connection. With keep-alive that is the
whole session, and the server would serve exactly one client at a time.
Throughput now scales with load — 5,033 req/s at 1 thread, 12,675 at 4, 22,495
at 16.

The trade-off is real: one OS thread per connection caps concurrency in the low
thousands, and idle keep-alive connections each hold a thread. Timeouts
(`idle_timeout`, `read_timeout`, `write_timeout`) bound Slowloris; deployments
needing C10k should wait for the `core:nbio` driver or sit behind a proxy.

## HTTP/2

Negotiated over ALPN on the same port as HTTP/1.1; a client that does not offer
h2 falls back automatically. Verified end to end with curl:

```
curl --http2 https://127.0.0.1:8443/     -> version=2 status=200
curl --http1.1 https://127.0.0.1:8443/   -> version=1.1 status=200
```

Working: GET and POST with bodies, responses split across multiple DATA frames,
HEAD, and **ten parallel requests multiplexed over a single connection**
(`num_connects=1`).

All three response body kinds work over h2, not just buffered ones: the static
file server streams from disk (150 KB verified byte-exact across many DATA
frames) and streaming handlers produce DATA frames directly. Chunk framing is a
property of the transport rather than the handler — HTTP/1.1 wraps each write in
a size header and CRLF, h2 does not, because DATA frames already delimit
themselves. Handlers are written once and work on both; emitting chunk headers
over h2 would put `10\r\n` into the response body.

Built as layers, each sans-I/O and tested on its own before the connection loop
tied them together:

| Layer | Tested against |
|---|---|
| Frames | Hand-written wire bytes, plus real `curl --http2` traffic |
| HPACK | RFC 7541 Appendix C worked examples, plus a real curl header block |
| Streams and flow control | RFC 9113 5.1 / 6.9 rules directly |
| Request validation | RFC 9113 8.1–8.3 pseudo-header rules |

Feature parity with the HTTP/1.1 path is asserted rather than assumed, since
three separate audits found features that silently degraded over h2 while still
producing well-formed frames. Verified against real clients: a 500 KB upload
arrives with a checksum identical to the HTTP/1.1 path (proving flow-control
windows are replenished — the initial window is only 65535 bytes), `Range`
returns byte-exact 206 responses, `If-None-Match` returns 304, and three
interleaved streams never cross bodies. `HEAD` reports the Content-Length the
equivalent GET would (RFC 9110 9.3.2) without sending a body — omitting it left
clients unable to size a download before making it.

**Trailers are accepted.** A stream may carry HEADERS, then DATA, then a second
HEADERS with the trailing fields (RFC 9113 8.1). Treating that second frame as
an attempt to reopen the stream sent GOAWAY and destroyed the connection for a
legal request — gRPC sends its status as trailers, so every gRPC call would have
failed. The trailer fields are fed to the HPACK decoder, which is what keeps the
dynamic table in step with the peer, then discarded: merging them would let a
trailer retroactively change a header the handler already acted on, the same
reason the HTTP/1.1 parser drops chunked trailers.

`Cookie` is rejoined with `"; "` rather than the `", "` used for every other
repeated field. RFC 9113 8.2.3 lets an h2 client split Cookie across several
fields for better HPACK compression, and joining those the ordinary way produces
a string no cookie parser can split — every cookie after the first is silently
lost. Verified over real h2 and HTTP/1.1 with the same handler.

Request validation is HTTP/2's smuggling defence, for the same reason the
HTTP/1.1 one exists. An h2-to-HTTP/1.1 gateway that forwards a
`transfer-encoding` accepted here turns it into a framing header downstream.
So connection-specific headers (RFC 9113 8.2.2) are rejected rather than
dropped, uppercase field names are malformed rather than folded, and
pseudo-headers after a regular field are refused.

Stream rules are enforced for the same class of reason: identifiers must
strictly increase, because reusing one attaches new frames to a previous
request's state; DATA after END_STREAM is refused, because accepting it appends
to a request the handler may already have acted on; both the stream and
connection windows are debited, because charging only one lets a peer spread a
large body across streams that are each individually within budget. A header
block interrupted by any other frame is a connection error, since interleaving
would desynchronize HPACK and corrupt every later request.

### Flood resistance

h2 makes several attacks cheap for a client and expensive for a server, so the
connection loop is bounded against the known ones:

| Attack | Defence |
|---|---|
| **Rapid Reset** (CVE-2023-44487) | Closed streams are reaped past a bound. Open-then-reset never trips `max_concurrent` because each stream is short-lived, so retaining them all grows memory without limit. |
| **Ping flood** (CVE-2019-9512) | Acknowledgement-demanding frames are counted per read batch; past the bound the connection gets `ENHANCE_YOUR_CALM`. |
| **Settings flood** (CVE-2019-9515) | Same counter — SETTINGS also obliges a reply. |
| **Header block interleaving** | Any frame between HEADERS and its final CONTINUATION is a connection error; interleaving desynchronizes HPACK and corrupts every later request. |
| **Priority churn** (CVE-2019-9513) | PRIORITY is accepted and ignored, so there is no state to churn. |

Replies are also flushed mid-batch rather than only at the end, so a peer that
packs one read with cheap frames cannot make the server buffer a batch's worth
of responses before writing anything.

These are tested by driving real frames through the connection loop with an
in-memory transport. A socket-based test cannot reliably deliver a thousand
frames in a single read, which is exactly the condition being defended against.

The same harness checks that malformed frames get the *right* error, not merely
that the server survives them. "Did not crash" is a weak bar: a peer probing an
implementation learns from which malformed frames are tolerated, so the specific
code matters as much as the rejection. Fifteen cases are pinned — connection
frames on a stream and stream frames on connection 0, even stream identifiers,
wrong fixed-frame sizes, zero window increments, client `PUSH_PROMISE`, padding
longer than its payload, and corrupt header blocks. Frames for a stream that was
never opened are a connection error; frames for one that has merely finished are
ignored, since that is a race a correct peer can lose.

**Handlers run serially per connection.** h2 multiplexes concurrent streams, so
a slow handler head-of-line blocks the others on its connection. This is a
deliberate limit, not an oversight: `Handler` is synchronous, and running one
per stream would need writes from many threads serialized back onto one socket
plus per-stream flow-control interaction. h2 still wins here on connection
reuse, header compression, and no TCP-level head-of-line blocking.

Not implemented: server push (`PUSH_PROMISE` from a client is a protocol error),
CONNECT, priority signalling (accepted and ignored, as RFC 9113 5.3.1 deprecates
it), and h2c prior-knowledge over cleartext — h2 requires TLS here.

### Why not an event loop

The sans-I/O parser was written so an event-loop driver could reuse it, and the
`Transport` abstraction was meant to make that a drop-in. Measuring the premise
showed it does not pay:

| | |
|---|---|
| Thread spawn + join | **13.9 µs** |
| Server throughput, 32 threads | **78,094 req/s** (12.8 µs/req) |
| Parse + serialize, no I/O | **3.4 µs** |

The last row is the useful one: only about a quarter of a request is protocol
work. The rest is syscalls and scheduling, which an event loop reshapes rather
than removes.

With keep-alive a thread is created per *connection*, not per request, so that
13.9 µs amortizes across every request on the connection and disappears into the
noise.

The deeper problem is the API. `Handler` is synchronous, and on an event loop a
handler that blocks — one database call — stalls every connection sharing that
thread. Fixing that means either a second, non-blocking `Handler` type (splitting
the API in two) or running handlers on a worker pool (a thread hop per request,
reintroducing the cost the event loop was supposed to remove). Neither is worth
it at these numbers.

What the sans-I/O split *did* buy is real and was kept: byte-at-a-time parser
tests, one parser shared by the server and client, and a `Transport` seam that
made TLS a backend rather than a fork of the request path.

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
