package http

import "core:mem"
import "core:os"
import "core:strings"

/*
A response under construction.

The handler fills in `status`, `headers` and the body, and the server serializes
it once the handler returns. Buffering the body means Content-Length can be set
automatically, which is what keeps connections reusable by default.
*/
Response :: struct {
	status:  Status,
	headers: Headers,
	body:    strings.Builder,

	// When set, the body is streamed from this file instead of `body`.
	// Buffering a large file would cost one full copy of it per concurrent
	// request, so anything sizeable is streamed in bounded chunks.
	file:    Maybe(File_Body),

	// Mirrors the request so framing decisions can be made without it.
	_version:      Version,
	// Cleared when the request was a HEAD, so the body is built normally by the
	// handler and dropped at serialization time.
	_write_body:   bool,
	// Set when the connection must close after this response.
	_close:        bool,
	_sent:         bool,
}

/*
A body streamed from an open file.

The server reads `length` bytes starting at `offset` and writes them to the
socket in chunks, so peak memory is one chunk rather than the whole file. The
offset/length pair is also what makes Range responses possible without a
separate code path.

The server closes the file once the response is written.
*/
File_Body :: struct {
	handle: ^os.File,
	offset: i64,
	length: i64,
}

response_init :: proc(r: ^Response, allocator: mem.Allocator) {
	r^ = {}
	r.status = .OK
	r._version = {1, 1}
	r._write_body = true
	headers_init(&r.headers, allocator)
	r.body = strings.builder_make(allocator)
}

// Appends a string to the response body.
response_write_string :: proc(r: ^Response, s: string) {
	strings.write_string(&r.body, s)
}

response_write_bytes :: proc(r: ^Response, b: []byte) {
	strings.write_bytes(&r.body, b)
}

/*
Sets the response body and its Content-Type in one call.

The most common handler operation, so it is worth having a single entry point.
*/
respond_plain :: proc(r: ^Response, status: Status, body: string) {
	r.status = status
	headers_set(&r.headers, "content-type", "text/plain; charset=utf-8")
	response_write_string(r, body)
}

respond_html :: proc(r: ^Response, status: Status, body: string) {
	r.status = status
	headers_set(&r.headers, "content-type", "text/html; charset=utf-8")
	response_write_string(r, body)
}

respond_json :: proc(r: ^Response, status: Status, body: string) {
	r.status = status
	headers_set(&r.headers, "content-type", "application/json")
	response_write_string(r, body)
}

// Responds with just a status and its reason phrase as the body.
respond_status :: proc(r: ^Response, status: Status) {
	respond_plain(r, status, status_text(status))
}

/*
Marks the connection to be closed after this response.

Used for errors where the parser state is no longer trustworthy: once framing is
ambiguous, the only safe move is to stop reusing the connection.
*/
response_set_close :: proc(r: ^Response) {
	r._close = true
}

/*
Serializes the response into `out`.

Header values were validated when set, so no CR/LF can appear here; that check
lives at the mutation site rather than being repeated on every write.

The framing rules implemented here are the response-side mirror of the parser's:
statuses that cannot carry a body get neither Content-Length nor body bytes,
because sending either desynchronizes a reused connection.
*/
response_write :: proc(r: ^Response, out: ^strings.Builder, date: string) {
	body := strings.to_string(r.body)
	can_have_body := status_can_have_body(r.status)

	// Status line.
	strings.write_string(out, "HTTP/1.1 ")
	strings.write_int(out, int(r.status))
	strings.write_byte(out, ' ')
	strings.write_string(out, status_text(r.status))
	strings.write_string(out, "\r\n")

	// Date is required on all responses by RFC 9110 6.6.1, and is passed in
	// pre-formatted because formatting it per response is measurable overhead.
	if len(date) > 0 && !headers_has(r.headers, "date") {
		strings.write_string(out, "date: ")
		strings.write_string(out, date)
		strings.write_string(out, "\r\n")
	}

	if can_have_body {
		if !headers_has(r.headers, "content-length") && !headers_has(r.headers, "transfer-encoding") {
			// A file body's length is known from the file, so Content-Length is
			// still exact without having read a single byte of it.
			length := len(body)
			if f, streaming := r.file.?; streaming {
				length = int(f.length)
			}

			strings.write_string(out, "content-length: ")
			strings.write_int(out, length)
			strings.write_string(out, "\r\n")
		}
	} else {
		// These must never be present on a bodyless status.
		headers_delete(&r.headers, "content-length")
		headers_delete(&r.headers, "transfer-encoding")
	}

	if r._close {
		strings.write_string(out, "connection: close\r\n")
	} else if r._version.minor == 0 {
		// HTTP/1.0 peers need this stated explicitly to reuse the connection.
		strings.write_string(out, "connection: keep-alive\r\n")
	}

	for e in r.headers.entries {
		// Entries blanked by `headers_delete`.
		if len(e.name) == 0 { continue }
		if e.name == "connection" { continue }

		strings.write_string(out, e.name)
		strings.write_string(out, ": ")
		strings.write_string(out, e.value)
		strings.write_string(out, "\r\n")
	}

	strings.write_string(out, "\r\n")

	// A HEAD response carries the headers a GET would, including
	// Content-Length, but never the body itself (RFC 9110 9.3.2).
	//
	// A file body is deliberately NOT appended here: the whole point is to
	// avoid materializing it. `response_body_is_file` tells the server to
	// stream it after these headers go out.
	if can_have_body && r._write_body {
		if _, streaming := r.file.?; !streaming {
			strings.write_string(out, body)
		}
	}
}

/*
Reports whether the body must be streamed from a file after the headers.

Returns false for HEAD and for statuses that cannot carry a body, so the caller
does not have to repeat those rules.
*/
response_body_is_file :: proc(r: ^Response) -> (f: File_Body, ok: bool) {
	if !r._write_body                  { return {}, false }
	if !status_can_have_body(r.status) { return {}, false }
	return r.file.?
}

/*
Streams the body from an open file.

Takes ownership of the handle: the server closes it once the response is
written, including on a write error, so a handler cannot leak a descriptor by
returning early.
*/
response_set_file :: proc(r: ^Response, handle: ^os.File, offset: i64, length: i64) {
	r.file = File_Body{handle = handle, offset = offset, length = length}
}
