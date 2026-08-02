package http

import "core:log"
import "core:mem"
import "core:os"
import "core:mem/virtual"
import "core:strings"

/*
The HTTP/2 connection loop.

Reads frames from a `Transport`, demultiplexes them onto streams, and runs the
same `Handler` the HTTP/1.1 driver uses. Everything below this — frames, HPACK,
stream state, flow control — is sans-I/O and tested on its own; this file is the
part that touches a socket.

Handlers run serially on the connection thread. h2 multiplexes concurrent
streams, so a slow handler head-of-line blocks the others on its connection.
That is a deliberate first step rather than an oversight: `Handler` is
synchronous, and running one per stream would need writes from many threads
serialized back onto one socket plus per-stream flow-control interaction.
Serving streams in arrival order is correct, testable, and does not pretend to a
concurrency story the handler API cannot support. h2 still wins here on
connection reuse and header compression; it does not win on handler parallelism
within a connection.
*/

H2_Conn :: struct {
	transport: ^Transport,
	server:    ^Server,

	streams: H2_Streams,
	decoder: Hpack_Decoder,

	// What the peer told us, and what we told the peer.
	peer_settings: H2_Settings,
	our_settings:  H2_Settings,

	// Read buffer. Frames are decoded in place, so payloads borrow from here
	// and must be consumed before the buffer is compacted.
	buf:      []byte,
	filled:   int,
	consumed: int,

	// Frames pending write, flushed after each read batch so a response is not
	// split across many small writes, and sooner if the queue grows large.
	out: [dynamic]byte,
	// Acknowledgement-demanding frames seen in the current batch.
	control_frames: int,

	// Header blocks arrive as HEADERS plus zero or more CONTINUATION frames,
	// and cannot be decoded until complete: HPACK is stateful, so decoding a
	// partial block would desynchronize the dynamic table permanently.
	header_block:  [dynamic]byte,
	header_stream: u32,
	header_end_stream: bool,
	expecting_continuation: bool,

	allocator: mem.Allocator,
	goaway_sent: bool,
}

// Bounds a reassembled header block, since CONTINUATION frames are unlimited.
@(private)
H2_MAX_HEADER_BLOCK :: 64 * 1024

/*
Caps the pending write queue.

Frames are processed in batches and flushed afterwards, so a peer that packs one
read buffer with cheap frames — PING and SETTINGS both demand an acknowledgement
— can queue thousands of replies before a single byte is written. That is
CVE-2019-9512 and CVE-2019-9515. Flushing as soon as the queue grows past this
bounds the memory a batch can cost.
*/
@(private)
H2_MAX_PENDING_WRITE :: 64 * 1024

/*
Caps how many acknowledgement-demanding control frames one batch may contain.

A peer with nothing to say has no reason to send hundreds of PINGs in a single
read; doing so is a flood rather than traffic, and answering all of them is
work this server performs on the attacker's behalf.
*/
@(private)
H2_MAX_CONTROL_FRAMES_PER_BATCH :: 64

/*
Serves an HTTP/2 connection until the peer goes away or a connection error
occurs.

Returns when the connection is finished; the caller closes the transport.
*/
h2_serve :: proc(t: ^Transport, s: ^Server, allocator: mem.Allocator) {
	c: H2_Conn
	c.transport = t
	c.server    = s
	c.allocator = allocator

	h2_streams_init(&c.streams, allocator)
	defer h2_streams_destroy(&c.streams)

	hpack_decoder_init(&c.decoder, 4096, allocator)
	defer hpack_decoder_destroy(&c.decoder)

	c.peer_settings = H2_DEFAULT_SETTINGS
	c.our_settings  = H2_DEFAULT_SETTINGS

	c.buf = make([]byte, max(int(H2_DEFAULT_MAX_FRAME_SIZE) + H2_FRAME_HEADER_SIZE, 32 * 1024), allocator)
	c.out.allocator = allocator
	c.header_block.allocator = allocator

	c.streams.max_concurrent = 100

	if !h2_read_preface(&c) { return }

	// Our SETTINGS must be the first thing we send (RFC 9113 3.4).
	h2_settings_encode(&c.out, {
		{.Max_Concurrent_Streams, c.streams.max_concurrent},
		{.Initial_Window_Size, u32(c.streams.initial_recv_window)},
		{.Max_Frame_Size, H2_DEFAULT_MAX_FRAME_SIZE},
		{.Enable_Push, 0},
	})
	if !h2_flush(&c) { return }

	for {
		// A processing failure queues GOAWAY, so the flush must happen either
		// way. Returning first would drop the connection with no explanation,
		// leaving the peer to guess why.
		ok := h2_process_buffered(&c)
		h2_flush(&c)

		if !ok || c.goaway_sent { return }
		if !h2_fill(&c)         { return }
	}
}

/*
Reads and verifies the client connection preface.

A client that does not send it is not speaking h2, and continuing would mean
interpreting arbitrary bytes as frames.
*/
@(private)
h2_read_preface :: proc(c: ^H2_Conn) -> bool {
	preface := H2_CLIENT_PREFACE

	c.transport->set_timeout(true, c.server.opts.read_timeout)
	for c.filled < len(preface) {
		n, ok := c.transport->read(c.buf[c.filled:])
		if !ok { return false }
		c.filled += n
	}

	if string(c.buf[:len(preface)]) != preface {
		log.debug("h2: bad client preface")
		return false
	}

	c.consumed = len(preface)
	return true
}

/*
Reads more bytes, compacting first so a large frame always has room.

Compaction is safe only because every frame decoded from the buffer is fully
handled before returning here — payloads borrow from `buf`.
*/
@(private)
h2_fill :: proc(c: ^H2_Conn) -> bool {
	if c.consumed > 0 {
		copy(c.buf, c.buf[c.consumed:c.filled])
		c.filled -= c.consumed
		c.consumed = 0
	}

	if c.filled >= len(c.buf) {
		// A frame larger than the buffer means the peer ignored the
		// MAX_FRAME_SIZE we advertised.
		h2_goaway(c, .Frame_Size_Error, "frame exceeds advertised max")
		return false
	}

	c.transport->set_timeout(true, c.server.opts.idle_timeout)
	n, ok := c.transport->read(c.buf[c.filled:])
	if !ok { return false }
	c.filled += n
	return true
}

// Decodes and handles every complete frame currently buffered.
@(private)
h2_process_buffered :: proc(c: ^H2_Conn) -> bool {
	c.control_frames = 0

	for {
		frame, n, result, err := h2_frame_decode(c.buf[c.consumed:c.filled], c.our_settings.max_frame_size)

		#partial switch result {
		case .Need_More:
			return true
		case .Error:
			h2_goaway(c, err, "frame decode failed")
			return false
		}

		c.consumed += n
		if !h2_handle_frame(c, frame) { return false }

		// Flush mid-batch rather than letting replies pile up. Without this a
		// peer that fills one read with PINGs queues an ACK for each before
		// anything is written.
		if len(c.out) >= H2_MAX_PENDING_WRITE {
			if !h2_flush(c) { return false }
		}
	}
}

@(private)
h2_handle_frame :: proc(c: ^H2_Conn, frame: H2_Frame) -> bool {
	/*
	A header block must not be interrupted. RFC 9113 6.10: between HEADERS and
	its final CONTINUATION, no other frame may appear on any stream — allowing
	one would let a peer interleave blocks and desynchronize HPACK, which
	corrupts every later request on the connection.
	*/
	if c.expecting_continuation {
		if frame.type != .Continuation || frame.stream_id != c.header_stream {
			h2_goaway(c, .Protocol_Error, "expected CONTINUATION")
			return false
		}
		return h2_handle_continuation(c, frame)
	}

	#partial switch frame.type {
	case .Settings:      return h2_handle_settings(c, frame)
	case .Headers:       return h2_handle_headers(c, frame)
	case .Data:          return h2_handle_data(c, frame)
	case .Window_Update: return h2_handle_window_update(c, frame)
	case .Rst_Stream:    return h2_handle_rst_stream(c, frame)
	case .Ping:          return h2_handle_ping(c, frame)
	case .Goaway:
		// The peer is finishing; stop accepting new work.
		return false
	case .Priority:
		// Priority signalling is deprecated (RFC 9113 5.3.1), so the contents
		// are ignored — but the framing is still validated. A peer probing for
		// lenient implementations learns from which malformed frames survive.
		if frame.stream_id == 0 {
			h2_goaway(c, .Protocol_Error, "PRIORITY on stream 0")
			return false
		}
		if len(frame.payload) != 5 {
			h2_goaway(c, .Frame_Size_Error, "PRIORITY must be 5 octets")
			return false
		}
		return true
	case .Push_Promise:
		// Only servers may push, so a client sending this is in error.
		h2_goaway(c, .Protocol_Error, "client sent PUSH_PROMISE")
		return false
	case .Continuation:
		// Not preceded by HEADERS.
		h2_goaway(c, .Protocol_Error, "unexpected CONTINUATION")
		return false
	case:
		// RFC 9113 4.1: unknown frame types must be ignored.
		return true
	}
}

@(private)
h2_handle_settings :: proc(c: ^H2_Conn, frame: H2_Frame) -> bool {
	if frame.stream_id != 0 {
		h2_goaway(c, .Protocol_Error, "SETTINGS on non-zero stream")
		return false
	}

	if frame.flags & H2_FLAG_ACK != 0 {
		// An ACK carries no payload.
		if len(frame.payload) != 0 {
			h2_goaway(c, .Frame_Size_Error, "SETTINGS ACK with payload")
			return false
		}
		return true
	}

	if !h2_charge_control_frame(c) { return false }

	previous_window := c.peer_settings.initial_window_size

	if err := h2_settings_apply(&c.peer_settings, frame.payload); err != .No_Error {
		h2_goaway(c, err, "bad SETTINGS")
		return false
	}

	// A changed INITIAL_WINDOW_SIZE applies to streams that already exist.
	if c.peer_settings.initial_window_size != previous_window {
		if err := h2_flow_initial_window_changed(&c.streams, c.peer_settings.initial_window_size); err != .No_Error {
			h2_goaway(c, err, "window overflow after SETTINGS")
			return false
		}
	}

	h2_settings_ack(&c.out)
	return true
}

@(private)
h2_handle_headers :: proc(c: ^H2_Conn, frame: H2_Frame) -> bool {
	if frame.stream_id == 0 {
		h2_goaway(c, .Protocol_Error, "HEADERS on stream 0")
		return false
	}

	payload, pad_err := h2_strip_padding(frame.payload, frame.flags)
	if pad_err != .No_Error {
		h2_goaway(c, pad_err, "bad padding")
		return false
	}

	// A PRIORITY prefix is 5 bytes of deprecated stream dependency information.
	if frame.flags & H2_FLAG_PRIORITY != 0 {
		if len(payload) < 5 {
			h2_goaway(c, .Frame_Size_Error, "HEADERS priority prefix truncated")
			return false
		}
		payload = payload[5:]
	}

	clear(&c.header_block)
	append(&c.header_block, ..payload)
	c.header_stream = frame.stream_id
	c.header_end_stream = frame.flags & H2_FLAG_END_STREAM != 0

	if frame.flags & H2_FLAG_END_HEADERS == 0 {
		c.expecting_continuation = true
		return true
	}

	return h2_deliver_headers(c)
}

@(private)
h2_handle_continuation :: proc(c: ^H2_Conn, frame: H2_Frame) -> bool {
	if len(c.header_block) + len(frame.payload) > H2_MAX_HEADER_BLOCK {
		h2_goaway(c, .Enhance_Your_Calm, "header block too large")
		return false
	}

	append(&c.header_block, ..frame.payload)

	if frame.flags & H2_FLAG_END_HEADERS == 0 {
		return true
	}

	c.expecting_continuation = false
	return h2_deliver_headers(c)
}

/*
Decodes a complete header block and opens the stream.

HPACK state advances here whether or not the stream survives: the dynamic table
is connection-wide, so skipping the decode for a rejected stream would leave the
decoder out of step with the peer's encoder for every later request.
*/
@(private)
h2_deliver_headers :: proc(c: ^H2_Conn) -> bool {
	// Heap-allocated because the stream may outlive this call: `virtual.Arena`
	// holds a block pointer and a mutex, so it cannot be copied into the
	// stream by value.
	arena := new(virtual.Arena, c.allocator)
	if virtual.arena_init_growing(arena) != nil {
		free(arena, c.allocator)
		h2_goaway(c, .Internal_Error, "out of memory")
		return false
	}
	// The request borrows from this arena for the life of the stream.
	alloc := virtual.arena_allocator(arena)

	headers: Headers
	headers_init(&headers, alloc)

	limits := HPACK_DEFAULT_LIMITS
	limits.max_header_list_size = int(c.our_settings.max_header_list_size)
	if limits.max_header_list_size <= 0 { limits.max_header_list_size = 64 * 1024 }

	if err := hpack_decode(&c.decoder, c.header_block[:], &headers, limits); err != .None {
		// A compression error is connection-fatal: the dynamic table is now
		// unreliable, so every later block would decode wrongly.
		h2_release_arena(c, arena)
		h2_goaway(c, .Compression_Error, "HPACK decode failed")
		return false
	}

	/*
	A second HEADERS on a stream that is already open carries trailers, not a
	new request (RFC 9113 8.1). Treating it as an attempt to reopen the stream
	sends GOAWAY and destroys the connection for a legal request — gRPC sends
	its status this way, so that breaks every gRPC call.

	The fields have already been fed to the HPACK decoder above, which is what
	keeps the dynamic table in step with the peer. The values themselves are
	dropped: merging them into the request would let a trailer retroactively
	change a header the handler has already acted on, which is the same reason
	the HTTP/1.1 parser discards chunked trailers.
	*/
	if existing, found := h2_stream_get(&c.streams, c.header_stream); found {
		h2_release_arena(c, arena)

		if !c.header_end_stream {
			// Trailers are the last thing on a stream, so a second HEADERS
			// without END_STREAM is malformed.
			h2_rst_stream_encode(&c.out, existing.id, .Protocol_Error)
			h2_stream_close(&c.streams, existing)
			return true
		}

		if err := h2_stream_recv_end(&c.streams, existing); err != .No_Error {
			h2_rst_stream_encode(&c.out, existing.id, err)
			h2_stream_close(&c.streams, existing)
			return true
		}

		existing.request.body = string(existing.body[:])
		body_alloc := virtual.arena_allocator(existing.arena)
		ok := h2_run_handler(c, existing, body_alloc)
		h2_release_arena(c, existing.arena)
		existing.arena = nil
		return ok
	}

	stream, open_err := h2_stream_open(&c.streams, c.header_stream)
	if open_err != .No_Error {
		h2_release_arena(c, arena)

		if open_err == .Refused_Stream {
			// Over the concurrency limit: a stream error, so the connection
			// stays usable and the peer may retry.
			h2_rst_stream_encode(&c.out, c.header_stream, .Refused_Stream)
			return true
		}

		h2_goaway(c, open_err, "bad stream identifier")
		return false
	}

	req_err := h2_request_from_fields(&stream.request, headers.entries[:], alloc)
	if req_err != .None {
		log.debugf("h2: malformed request: %v", req_err)
		h2_rst_stream_encode(&c.out, stream.id, h2_request_error_code(req_err))
		h2_stream_close(&c.streams, stream)
		h2_release_arena(c, arena)
		return true
	}

	stream.request.client = c.transport.peer

	if c.header_end_stream {
		if err := h2_stream_recv_end(&c.streams, stream); err != .No_Error {
			h2_goaway(c, err, "bad END_STREAM")
			h2_release_arena(c, arena)
			return false
		}
		ok := h2_run_handler(c, stream, alloc)
		h2_release_arena(c, arena)
		return ok
	}

	// The body is still arriving; the arena is released when the stream ends.
	stream.arena = arena
	return true
}

@(private)
h2_handle_data :: proc(c: ^H2_Conn, frame: H2_Frame) -> bool {
	if frame.stream_id == 0 {
		h2_goaway(c, .Protocol_Error, "DATA on stream 0")
		return false
	}

	stream, found := h2_stream_get(&c.streams, frame.stream_id)
	if !found {
		err := h2_stream_missing_error(&c.streams, frame.stream_id)
		if err == .Stream_Closed {
			// A late frame for a stream we already finished: reset it rather
			// than tearing down the connection over a race the peer can lose.
			h2_rst_stream_encode(&c.out, frame.stream_id, .Stream_Closed)
			return true
		}
		h2_goaway(c, err, "DATA for unknown stream")
		return false
	}

	// Flow control is charged on the full payload including padding, because
	// that is what the peer actually spent (RFC 9113 6.9.1).
	if err := h2_flow_consume(&c.streams, stream, len(frame.payload)); err != .No_Error {
		h2_goaway(c, err, "flow control violation")
		return false
	}

	if err := h2_stream_can_recv_data(stream); err != .No_Error {
		h2_rst_stream_encode(&c.out, stream.id, err)
		return true
	}

	payload, pad_err := h2_strip_padding(frame.payload, frame.flags)
	if pad_err != .No_Error {
		h2_goaway(c, pad_err, "bad DATA padding")
		return false
	}

	if len(stream.body) + len(payload) > c.server.opts.limits.max_body {
		h2_rst_stream_encode(&c.out, stream.id, .Enhance_Your_Calm)
		h2_stream_close(&c.streams, stream)
		return true
	}

	append(&stream.body, ..payload)

	// Replenish the peer's windows so it can keep sending. Without this the
	// connection stalls once the initial window is spent.
	if len(frame.payload) > 0 {
		h2_window_update_encode(&c.out, 0, u32(len(frame.payload)))
		h2_window_update_encode(&c.out, stream.id, u32(len(frame.payload)))
		c.streams.recv_window += i64(len(frame.payload))
		stream.recv_window += i64(len(frame.payload))
	}

	if frame.flags & H2_FLAG_END_STREAM != 0 {
		if err := h2_stream_recv_end(&c.streams, stream); err != .No_Error {
			h2_goaway(c, err, "bad END_STREAM")
			return false
		}

		stream.request.body = string(stream.body[:])
		alloc := virtual.arena_allocator(stream.arena)
		ok := h2_run_handler(c, stream, alloc)
		h2_release_arena(c, stream.arena)
		stream.arena = nil
		return ok
	}

	return true
}

@(private)
h2_handle_window_update :: proc(c: ^H2_Conn, frame: H2_Frame) -> bool {
	increment, err := h2_window_update_decode(frame.payload)
	if err != .No_Error {
		h2_goaway(c, err, "bad WINDOW_UPDATE")
		return false
	}

	if frame.stream_id == 0 {
		if uerr := h2_flow_update(&c.streams, nil, increment); uerr != .No_Error {
			h2_goaway(c, uerr, "connection window overflow")
			return false
		}
		return true
	}

	// An identifier above the high-water mark names a stream that was never
	// opened, which is a protocol error rather than a race.
	if frame.stream_id > c.streams.last_peer_stream_id {
		h2_goaway(c, .Protocol_Error, "WINDOW_UPDATE for idle stream")
		return false
	}

	stream, found := h2_stream_get(&c.streams, frame.stream_id)
	if !found {
		// A finished stream: the update is harmless and must be ignored, or
		// well-behaved clients would be disconnected for losing a race.
		return true
	}

	if uerr := h2_flow_update(&c.streams, stream, increment); uerr != .No_Error {
		// A stream-level overflow is a stream error, not a connection one.
		h2_rst_stream_encode(&c.out, stream.id, uerr)
		h2_stream_close(&c.streams, stream)
	}
	return true
}

@(private)
h2_handle_rst_stream :: proc(c: ^H2_Conn, frame: H2_Frame) -> bool {
	if frame.stream_id == 0 {
		h2_goaway(c, .Protocol_Error, "RST_STREAM on stream 0")
		return false
	}

	code, err := h2_rst_stream_decode(frame.payload)
	if err != .No_Error {
		h2_goaway(c, err, "bad RST_STREAM")
		return false
	}

	// RFC 9113 6.4: RST_STREAM for an idle stream is a connection error.
	// Accepting it would let a peer manipulate state for streams it never
	// established. A stream at or below the high-water mark may simply have
	// finished, which is a race a correct peer can lose, so only identifiers
	// above it are rejected.
	if frame.stream_id > c.streams.last_peer_stream_id {
		h2_goaway(c, .Protocol_Error, "RST_STREAM for idle stream")
		return false
	}

	log.debugf("h2: stream %d reset by peer: %v", frame.stream_id, code)

	if stream, found := h2_stream_get(&c.streams, frame.stream_id); found {
		h2_release_arena(c, stream.arena)
		stream.arena = nil
		h2_stream_close(&c.streams, stream)
	}
	return true
}

@(private)
h2_handle_ping :: proc(c: ^H2_Conn, frame: H2_Frame) -> bool {
	if frame.stream_id != 0 {
		h2_goaway(c, .Protocol_Error, "PING on non-zero stream")
		return false
	}
	if len(frame.payload) != 8 {
		h2_goaway(c, .Frame_Size_Error, "PING payload must be 8 octets")
		return false
	}

	// An ACK is the peer's own probe coming back; nothing to do.
	if frame.flags & H2_FLAG_ACK != 0 { return true }

	if !h2_charge_control_frame(c) { return false }

	h2_ping_ack(&c.out, frame.payload)
	return true
}

/*
Runs the handler for a completed request and writes the response.

Serial by design: see the note at the top of this file.
*/
@(private)
h2_run_handler :: proc(c: ^H2_Conn, stream: ^H2_Stream, alloc: mem.Allocator) -> bool {
	res: Response
	response_init(&res, alloc)
	res._version = {2, 0}

	// A HEAD response carries the headers a GET would, without the body.
	is_head := stream.request.method == .Head
	if is_head {
		stream.request.method = .Get
		res._write_body = false
	}

	stream.request.headers.readonly = true

	handler := c.server.handler
	handler_serve(&handler, &stream.request, &res)

	return h2_write_response(c, stream, &res)
}

/*
Serializes a Response as HEADERS plus DATA.

Header fields are encoded without indexing, so the encoder holds no state that
could drift from the peer's decoder.
*/
@(private)
h2_write_response :: proc(c: ^H2_Conn, stream: ^H2_Stream, res: ^Response) -> bool {
	block := make([dynamic]byte, 0, 256, context.temp_allocator)

	// :status must come first (RFC 9113 8.3).
	hpack_encode_status(&block, res.status)

	date_buf: [DATE_LENGTH]byte
	hpack_encode_field(&block, "date", server_date(c.server, date_buf[:]))

	for e in res.headers.entries {
		if len(e.name) == 0 { continue }
		// Connection-specific headers are forbidden in h2 (RFC 9113 8.2.2), so
		// they are dropped here rather than forwarded.
		if h2_is_connection_specific(e.name) { continue }
		// h2 frames the body itself, so Content-Length is re-derived below
		// rather than carried over from whatever the handler set.
		if e.name == "content-length" { continue }
		hpack_encode_field(&block, e.name, e.value)
	}

	/*
	A response body reaches here in one of three shapes, all of which the
	HTTP/1.1 path supports and so must this one: buffered in `res.body`, backed
	by a file, or produced by a streaming callback. Handling only the first
	silently returned an empty response for every file the static server
	served.
	*/
	file, is_file := response_body_is_file(res)
	stream_body, is_stream := response_body_is_stream(res)

	buffered := strings.to_string(res.body)
	send_body := res._write_body && status_can_have_body(res.status)

	// The length is known for buffered and file bodies, so Content-Length is
	// still sent — h2 has no chunked encoding, but the header remains useful to
	// clients and is required to be accurate when present.
	if send_body && !is_stream {
		length := len(buffered)
		if is_file { length = int(file.length) }
		hpack_encode_field(&block, "content-length", h2_itoa(length))
	}

	has_body := send_body && (is_stream || is_file || len(buffered) > 0)

	flags := u8(H2_FLAG_END_HEADERS)
	if !has_body { flags |= H2_FLAG_END_STREAM }
	h2_frame_encode(&c.out, .Headers, flags, stream.id, block[:])

	if !has_body {
		// A file opened for a HEAD or a bodyless status still has to be closed.
		h2_close_response_file(res)
		h2_stream_send_end(&c.streams, stream)
		return true
	}

	ok := true
	switch {
	case is_file:   ok = h2_write_file_body(c, stream, file)
	case is_stream: ok = h2_write_stream_body(c, stream, stream_body)
	case:           ok = h2_write_data(c, stream, transmute([]byte)buffered, true)
	}

	h2_stream_send_end(&c.streams, stream)
	return ok
}

/*
Splits a body across DATA frames.

Frames are bounded by the peer's MAX_FRAME_SIZE, not ours: the limit that
matters is what the peer agreed to receive.
*/
@(private)
h2_write_data :: proc(c: ^H2_Conn, stream: ^H2_Stream, body: []byte, last: bool) -> bool {
	max_chunk := int(c.peer_settings.max_frame_size)
	if max_chunk <= 0 { max_chunk = H2_DEFAULT_MAX_FRAME_SIZE }

	if len(body) == 0 {
		if last {
			h2_frame_encode(&c.out, .Data, H2_FLAG_END_STREAM, stream.id, nil)
		}
		return true
	}

	offset := 0
	for offset < len(body) {
		chunk := min(max_chunk, len(body) - offset)
		is_final := last && offset + chunk >= len(body)

		flags := u8(0)
		if is_final { flags = H2_FLAG_END_STREAM }

		h2_frame_encode(&c.out, .Data, flags, stream.id, body[offset:offset + chunk])
		h2_flow_sent(&c.streams, stream, chunk)
		offset += chunk

		// Flush as the queue grows rather than buffering the whole body: a
		// large file would otherwise be held in memory twice.
		if len(c.out) >= H2_MAX_PENDING_WRITE {
			if !h2_flush(c) { return false }
		}
	}
	return true
}

/*
Streams a file body in bounded chunks.

Mirrors the HTTP/1.1 driver: peak memory is one chunk regardless of file size,
which is what keeps a few concurrent requests for a large file from exhausting
memory.
*/
@(private)
h2_write_file_body :: proc(c: ^H2_Conn, stream: ^H2_Stream, file: File_Body) -> bool {
	defer {
		os.close(file.handle)
		// Cleared so the caller cannot close it twice.
	}

	chunk := make([]byte, c.server.opts.file_chunk_size, context.temp_allocator)
	remaining := file.length
	offset := file.offset

	for remaining > 0 {
		want := min(i64(len(chunk)), remaining)

		n, err := os.read_at(file.handle, chunk[:want], offset)
		if err != nil || n <= 0 {
			// The headers already promised Content-Length bytes, so the body is
			// now short and the stream cannot be completed honestly.
			log.errorf("h2: file read failed: %v", err)
			h2_rst_stream_encode(&c.out, stream.id, .Internal_Error)
			return false
		}

		remaining -= i64(n)
		if !h2_write_data(c, stream, chunk[:n], remaining == 0) { return false }

		offset += i64(n)
	}
	return true
}

/*
Runs a streaming handler, framing its output as DATA frames.

h2 has no chunked transfer encoding — DATA frames are already self-delimiting —
so the writer emits one frame per `stream_write` rather than a chunk header.
*/
@(private)
h2_write_stream_body :: proc(c: ^H2_Conn, stream: ^H2_Stream, body: Stream_Body) -> bool {
	ctx := H2_Stream_Ctx{conn = c, stream = stream}

	w := Stream_Writer{
		_conn  = &ctx,
		_write = proc(raw: rawptr, data: []byte) -> bool {
			ctx := cast(^H2_Stream_Ctx)raw
			// Not the last frame: the producer may write again, and only the
			// caller knows when it has finished.
			return h2_write_data(ctx.conn, ctx.stream, data, false)
		},
	}

	body.proc_(&w, body.data)

	if w.err {
		// The body is incomplete and the promised length cannot be met, so the
		// stream is reset rather than ended as though it were whole.
		h2_rst_stream_encode(&c.out, stream.id, .Internal_Error)
		return false
	}

	// An empty DATA frame carries END_STREAM, which is how a streamed body ends.
	h2_frame_encode(&c.out, .Data, H2_FLAG_END_STREAM, stream.id, nil)
	return true
}

@(private)
H2_Stream_Ctx :: struct {
	conn:   ^H2_Conn,
	stream: ^H2_Stream,
}

// Closes a response's file if it has one, for paths that never send a body.
@(private)
h2_close_response_file :: proc(res: ^Response) {
	if f, has := res.file.?; has {
		os.close(f.handle)
		res.file = nil
	}
}

// Formats a length for a Content-Length header.
@(private)
h2_itoa :: proc(v: int) -> string {
	buf := make([]byte, 24, context.temp_allocator)
	if v == 0 {
		buf[0] = '0'
		return string(buf[:1])
	}

	n := 0
	value := v
    for value > 0 {
		buf[n] = u8('0' + value % 10)
		value /= 10
		n += 1
	}
	for i in 0 ..< n / 2 {
		buf[i], buf[n - 1 - i] = buf[n - 1 - i], buf[i]
	}
	return string(buf[:n])
}

/*
Counts a frame that obliges us to reply, refusing the connection past a bound.

ENHANCE_YOUR_CALM is the intended code for a peer generating excessive load
(RFC 9113 7): it says the traffic was well-formed but unreasonable, which is
exactly the case here.
*/
@(private)
h2_charge_control_frame :: proc(c: ^H2_Conn) -> bool {
	c.control_frames += 1
	if c.control_frames > H2_MAX_CONTROL_FRAMES_PER_BATCH {
		h2_goaway(c, .Enhance_Your_Calm, "control frame flood")
		return false
	}
	return true
}

// Destroys a per-stream arena and frees its handle.
@(private)
h2_release_arena :: proc(c: ^H2_Conn, arena: ^virtual.Arena) {
	if arena == nil { return }
	virtual.arena_destroy(arena)
	free(arena, c.allocator)
}

// Writes everything queued, then clears the queue.
@(private)
h2_flush :: proc(c: ^H2_Conn) -> bool {
	if len(c.out) == 0 { return true }

	c.transport->set_timeout(false, c.server.opts.write_timeout)
	ok := transport_write_all(c.transport, c.out[:])
	clear(&c.out)
	return ok
}

/*
Queues GOAWAY and marks the connection finished.

`last_peer_stream_id` tells the peer which streams were processed, so it knows
what is safe to retry elsewhere; claiming zero would make every in-flight
request look unprocessed.
*/
@(private)
h2_goaway :: proc(c: ^H2_Conn, code: H2_Error, debug: string) {
	if c.goaway_sent { return }
	log.debugf("h2: going away: %v (%s)", code, debug)

	h2_goaway_encode(&c.out, c.streams.last_peer_stream_id, code, debug)
	c.goaway_sent = true
}
