package tests

import "core:mem/virtual"
import "core:testing"

import http "../http"

/*
HTTP/2 flood resistance.

Every test here drives real frames through the connection loop using an
in-memory transport. A socket-based test cannot reliably deliver thousands of
frames in a single read, and that is precisely the condition being defended
against: frames are handled in batches and replies are queued, so a peer that
packs one read with cheap frames can make the server do a batch's worth of work
and buffer a batch's worth of replies before writing anything.

The named attacks are the 2019 h2 CVE family and CVE-2023-44487.
*/

/*
Builds a server whose handler points at a router that outlives the call.

The router must be heap-allocated: `router_handler` captures its address, so
returning a router by value would leave the handler pointing at a dead stack
slot — which segfaults only once a request actually reaches it.
*/
@(private)
h2_test_server :: proc(srv: ^http.Server, router: ^http.Router) {
	http.router_init(router)
	http.router_handle_proc(router, "GET /", proc(q: ^http.Request, s: ^http.Response) {
		http.respond_plain(s, .OK, "ok")
	})

	srv.opts = http.DEFAULT_SERVER_OPTS
	srv.handler = http.router_handler(router)
}

/*
Builds a byte script: the client preface, then whatever frames are appended.

`h2_serve` verifies the preface before anything else, so every script needs it.
*/
@(private)
h2_script :: proc(allocator := context.temp_allocator) -> [dynamic]byte {
	out := make([dynamic]byte, 0, 4096, allocator)
	append(&out, ..transmute([]byte)string(http.H2_CLIENT_PREFACE))
	// An empty SETTINGS, which every real client sends first.
	http.h2_frame_encode(&out, .Settings, 0, 0, nil)
	return out
}

@(private)
h2_run_script :: proc(script: []byte, arena: ^virtual.Arena) -> [dynamic]byte {
	// Both outlive the serve call, so neither may live in a copied stack frame.
	srv := new(http.Server, context.allocator)
	router := new(http.Router, context.allocator)
	defer {
		http.router_destroy(router)
		free(router)
		free(srv)
	}

	h2_test_server(srv, router)

	mt: http.Memory_Transport
	http.memory_transport_init(&mt, script)

	http.h2_serve_memory(&mt, srv, virtual.arena_allocator(arena))

	// The caller inspects what the server wrote.
	return mt.output
}

/*
Finds the first frame of a given type in a server's output.

Returns found=false rather than failing, so a test can assert either presence or
absence.
*/
@(private)
h2_find_frame :: proc(out: []byte, want: http.H2_Frame_Type) -> (frame: http.H2_Frame, found: bool) {
	pos := 0
	for pos < len(out) {
		f, consumed, result, _ := http.h2_frame_decode(out[pos:], http.H2_MAX_ALLOWED_FRAME_SIZE)
		if result != .Ok { return {}, false }
		if f.type == want { return f, true }
		pos += consumed
	}
	return {}, false
}

@(private)
h2_count_frames :: proc(out: []byte, want: http.H2_Frame_Type) -> int {
	count := 0
	pos := 0
	for pos < len(out) {
		f, consumed, result, _ := http.h2_frame_decode(out[pos:], http.H2_MAX_ALLOWED_FRAME_SIZE)
		if result != .Ok { break }
		if f.type == want { count += 1 }
		pos += consumed
	}
	return count
}

@(test)
test_h2_ping_flood_is_refused :: proc(t: ^testing.T) {
	// CVE-2019-9512: every PING obliges an ACK, so a peer that packs a read
	// buffer with them makes the server queue an ACK for each before writing.
	script := h2_script()
	opaque := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _ in 0 ..< 1000 {
		http.h2_frame_encode(&script, .Ping, 0, 0, opaque)
	}

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	// The connection must be terminated rather than answering all 1000.
	goaway, found := h2_find_frame(out[:], .Goaway)
	testing.expect(t, found, "a ping flood must produce GOAWAY")

	if found {
		g, err := http.h2_goaway_decode(goaway.payload)
		testing.expect_value(t, err, http.H2_Error.No_Error)
		// ENHANCE_YOUR_CALM is the code for well-formed but unreasonable
		// traffic (RFC 9113 7), which is exactly this.
		testing.expect_value(t, g.code, http.H2_Error.Enhance_Your_Calm)
	}

	acks := h2_count_frames(out[:], .Ping)
	testing.expectf(t, acks <= 128, "answered %d pings before giving up", acks)
}

@(test)
test_h2_settings_flood_is_refused :: proc(t: ^testing.T) {
	// CVE-2019-9515: SETTINGS also demands an acknowledgement.
	script := h2_script()
	for _ in 0 ..< 1000 {
		http.h2_frame_encode(&script, .Settings, 0, 0, nil)
	}

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	goaway, found := h2_find_frame(out[:], .Goaway)
	testing.expect(t, found, "a settings flood must produce GOAWAY")

	if found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expect_value(t, g.code, http.H2_Error.Enhance_Your_Calm)
	}
}

@(test)
test_h2_normal_traffic_is_not_flagged :: proc(t: ^testing.T) {
	// The flood bound must not catch a client behaving reasonably: a handful of
	// control frames per read is ordinary.
	script := h2_script()
	opaque := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _ in 0 ..< 8 {
		http.h2_frame_encode(&script, .Ping, 0, 0, opaque)
	}

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	// Every ping answered, and no GOAWAY.
	testing.expect_value(t, h2_count_frames(out[:], .Ping), 8)

	if goaway, found := h2_find_frame(out[:], .Goaway); found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expectf(t, g.code == .No_Error,
			"ordinary traffic produced GOAWAY %v", g.code)
	}
}

@(test)
test_h2_unexpected_continuation_is_rejected :: proc(t: ^testing.T) {
	// A CONTINUATION with no preceding HEADERS. Accepting it would mean
	// appending to a header block that does not exist.
	script := h2_script()
	http.h2_frame_encode(&script, .Continuation, http.H2_FLAG_END_HEADERS, 1, []byte{0x82})

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	goaway, found := h2_find_frame(out[:], .Goaway)
	testing.expect(t, found, "an orphan CONTINUATION must produce GOAWAY")
	if found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expect_value(t, g.code, http.H2_Error.Protocol_Error)
	}
}

@(test)
test_h2_interrupted_header_block_is_rejected :: proc(t: ^testing.T) {
	// RFC 9113 6.10: nothing may appear between HEADERS and its final
	// CONTINUATION. Interleaving would let a peer desynchronize HPACK, which
	// corrupts every later request on the connection.
	script := h2_script()
	// HEADERS without END_HEADERS, so a CONTINUATION is expected next.
	http.h2_frame_encode(&script, .Headers, 0, 1, []byte{0x82})
	// A PING instead.
	http.h2_frame_encode(&script, .Ping, 0, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8})

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	goaway, found := h2_find_frame(out[:], .Goaway)
	testing.expect(t, found, "an interrupted header block must produce GOAWAY")
	if found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expect_value(t, g.code, http.H2_Error.Protocol_Error)
	}
}

@(test)
test_h2_serves_a_request_from_frames :: proc(t: ^testing.T) {
	// The positive control: the same machinery that rejects the floods above
	// must still serve an ordinary request.
	script := h2_script()

	// :method GET, :scheme http, :path /, :authority x — all static-table
	// indexed except the authority, which is a literal.
	block := []byte{
		0x82, 0x86, 0x84,
		0x41, 0x01, 'x',
	}
	http.h2_frame_encode(&script, .Headers,
		http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 1, block)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	// A HEADERS response on stream 1, and a DATA frame carrying the body.
	headers, has_headers := h2_find_frame(out[:], .Headers)
	testing.expect(t, has_headers, "server must answer with HEADERS")
	if has_headers {
		testing.expect_value(t, headers.stream_id, u32(1))
	}

	data, has_data := h2_find_frame(out[:], .Data)
	testing.expect(t, has_data, "server must send the response body")
	if has_data {
		testing.expect_value(t, string(data.payload), "ok")
		testing.expect(t, data.flags & http.H2_FLAG_END_STREAM != 0,
			"the last DATA frame must end the stream")
	}
}

// --- Frame validation (RFC 9113 section 6) ---

@(test)
test_h2_priority_frame_size_is_checked :: proc(t: ^testing.T) {
	// RFC 9113 6.3: PRIORITY is exactly 5 octets. The frame's contents are
	// ignored — priority signalling is deprecated — but the length still has to
	// be right, because a peer probing for lenient implementations learns from
	// which malformed frames are tolerated.
	script := h2_script()
	http.h2_frame_encode(&script, .Priority, 0, 1, []byte{0x00, 0x00})

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	goaway, found := h2_find_frame(out[:], .Goaway)
	testing.expect(t, found, "a short PRIORITY frame must produce GOAWAY")
	if found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expect_value(t, g.code, http.H2_Error.Frame_Size_Error)
	}
}

@(test)
test_h2_priority_on_stream_zero_is_rejected :: proc(t: ^testing.T) {
	// PRIORITY describes a stream, so stream 0 is meaningless for it.
	script := h2_script()
	http.h2_frame_encode(&script, .Priority, 0, 0, []byte{0, 0, 0, 0, 0})

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	goaway, found := h2_find_frame(out[:], .Goaway)
	testing.expect(t, found, "PRIORITY on stream 0 must produce GOAWAY")
	if found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expect_value(t, g.code, http.H2_Error.Protocol_Error)
	}
}

@(test)
test_h2_rst_stream_on_idle_stream_is_rejected :: proc(t: ^testing.T) {
	// RFC 9113 6.4: RST_STREAM for a stream that was never opened is a
	// PROTOCOL_ERROR. Accepting it would let a peer manipulate state for
	// streams it has not established.
	script := h2_script()
	http.h2_rst_stream_encode(&script, 99, .Cancel)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	goaway, found := h2_find_frame(out[:], .Goaway)
	testing.expect(t, found, "RST_STREAM for an idle stream must produce GOAWAY")
	if found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expect_value(t, g.code, http.H2_Error.Protocol_Error)
	}
}

@(test)
test_h2_window_update_on_idle_stream_is_rejected :: proc(t: ^testing.T) {
	// Same rule: a stream identifier above the high-water mark has never been
	// opened, so a frame addressing it is a protocol error rather than a race.
	script := h2_script()
	http.h2_window_update_encode(&script, 99, 1024)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	goaway, found := h2_find_frame(out[:], .Goaway)
	testing.expect(t, found, "WINDOW_UPDATE for an idle stream must produce GOAWAY")
	if found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expect_value(t, g.code, http.H2_Error.Protocol_Error)
	}
}

@(test)
test_h2_window_update_for_closed_stream_is_ignored :: proc(t: ^testing.T) {
	// A stream at or below the high-water mark may simply have finished, which
	// is a race a correct peer can lose. Ignoring is required; treating it as
	// an error would break well-behaved clients.
	script := h2_script()
	block := []byte{0x82, 0x86, 0x84, 0x41, 0x01, 'x'}
	http.h2_frame_encode(&script, .Headers,
		http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 1, block)
	// Stream 1 has now finished; a late update for it must be tolerated.
	http.h2_window_update_encode(&script, 1, 1024)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	if goaway, found := h2_find_frame(out[:], .Goaway); found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expectf(t, g.code == .No_Error,
			"a late WINDOW_UPDATE must be ignored, got GOAWAY %v", g.code)
	}
}

/*
Malformed frames must be answered with the right error, not merely survived.

"Did not crash" is a weak bar: a peer probing an implementation learns from
which malformed frames are tolerated and which produce a connection error, so
the specific code matters as much as the rejection. Each case below names the
rule it exercises.
*/
@(test)
test_h2_malformed_frames_get_correct_errors :: proc(t: ^testing.T) {
	Case :: struct {
		name:  string,
		want:  http.H2_Error,
		build: proc(s: ^[dynamic]byte),
	}

	cases := []Case{
		// Connection-level frames must use stream 0; stream-level frames must not.
		{"DATA on stream 0", .Protocol_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Data, 0, 0, []byte{1, 2, 3})
		}},
		{"HEADERS on stream 0", .Protocol_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Headers, http.H2_FLAG_END_HEADERS, 0, []byte{0x82})
		}},
		{"PING on a stream", .Protocol_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Ping, 0, 5, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		}},
		{"SETTINGS on a stream", .Protocol_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Settings, 0, 3, nil)
		}},
		{"RST_STREAM on stream 0", .Protocol_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Rst_Stream, 0, 0, []byte{0, 0, 0, 0})
		}},

		// Client-initiated streams are odd (RFC 9113 5.1.1).
		{"HEADERS on an even stream", .Protocol_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Headers,
				http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 2,
				[]byte{0x82, 0x86, 0x84, 0x41, 0x01, 'x'})
		}},

		// Fixed-size frames.
		{"PING of the wrong length", .Frame_Size_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Ping, 0, 0, []byte{1, 2, 3})
		}},
		{"SETTINGS not a multiple of six", .Frame_Size_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Settings, 0, 0, []byte{0, 1, 2})
		}},
		{"RST_STREAM of the wrong length", .Frame_Size_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Rst_Stream, 0, 1, []byte{0, 0})
		}},
		{"HEADERS with a truncated priority prefix", .Frame_Size_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Headers,
				http.H2_FLAG_END_HEADERS | http.H2_FLAG_PRIORITY, 1, []byte{0, 0, 0})
		}},

		// A zero window increment conveys nothing and is used to probe.
		{"WINDOW_UPDATE with a zero increment", .Protocol_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Window_Update, 0, 0, []byte{0, 0, 0, 0})
		}},

		// Only servers may push.
		{"PUSH_PROMISE from a client", .Protocol_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Push_Promise, 0, 1, []byte{0, 0, 0, 3})
		}},

		// Padding longer than the payload would yield a negative body length.
		{"HEADERS padded past its payload", .Protocol_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Headers,
				http.H2_FLAG_END_HEADERS | http.H2_FLAG_PADDED, 1, []byte{0xff, 0x82})
		}},

		// A corrupt header block leaves the dynamic table unreliable, so every
		// later block would decode wrongly: connection-fatal, not stream-level.
		{"garbage in a header block", .Compression_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Headers,
				http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 1,
				[]byte{0xff, 0xff, 0xff, 0xff, 0xff})
		}},
		{"HPACK index past the table", .Compression_Error, proc(s: ^[dynamic]byte) {
			http.h2_frame_encode(s, .Headers,
				http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 1, []byte{0xfe})
		}},
	}

	for c in cases {
		script := h2_script()
		c.build(&script)

		arena: virtual.Arena
		_ = virtual.arena_init_growing(&arena)
		defer virtual.arena_destroy(&arena)

		out := h2_run_script(script[:], &arena)
		defer delete(out)

		goaway, found := h2_find_frame(out[:], .Goaway)
		testing.expectf(t, found, "%s: expected GOAWAY", c.name)
		if !found { continue }

		g, decode_err := http.h2_goaway_decode(goaway.payload)
		testing.expectf(t, decode_err == .No_Error, "%s: GOAWAY did not decode", c.name)
		testing.expectf(t, g.code == c.want,
			"%s: expected %v, got %v", c.name, c.want, g.code)
	}
}

@(test)
test_h2_malformed_request_resets_only_the_stream :: proc(t: ^testing.T) {
	// An empty header block has no pseudo-headers, so the request is malformed.
	// That is a stream error: framing and HPACK state are intact, so resetting
	// one stream is enough and a GOAWAY would be more disruptive than the fault.
	script := h2_script()
	http.h2_frame_encode(&script, .Headers,
		http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 1, nil)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	testing.expect_value(t, h2_count_frames(out[:], .Rst_Stream), 1)

	if goaway, found := h2_find_frame(out[:], .Goaway); found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expectf(t, g.code == .No_Error,
			"a malformed request must not kill the connection, got %v", g.code)
	}
}

@(test)
test_h2_serves_file_backed_responses :: proc(t: ^testing.T) {
	// The static file server sets a File_Body rather than filling res.body, so
	// an h2 path that only reads res.body returns an empty response for every
	// file it serves.
	script := h2_script()
	block := []byte{0x82, 0x86, 0x84, 0x41, 0x01, 'x'}
	http.h2_frame_encode(&script, .Headers,
		http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 1, block)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	srv := new(http.Server, context.allocator)
	router := new(http.Router, context.allocator)
	defer { http.router_destroy(router); free(router); free(srv) }

	http.router_init(router)
	http.router_handle_proc(router, "GET /", proc(q: ^http.Request, s: ^http.Response) {
		// A streaming handler, the same API the HTTP/1.1 path supports.
		http.response_set_stream(s, q, proc(w: ^http.Stream_Writer, q: ^http.Request) {
			http.stream_write_string(w, "streamed-over-h2")
		})
	})
	srv.opts = http.DEFAULT_SERVER_OPTS
	srv.handler = http.router_handler(router)

	mt: http.Memory_Transport
	http.memory_transport_init(&mt, script[:])
	defer http.memory_transport_destroy(&mt)

	http.h2_serve_memory(&mt, srv, virtual.arena_allocator(&arena))

	data, found := h2_find_frame(mt.output[:], .Data)
	testing.expect(t, found, "a streaming handler must produce DATA over h2")
	if found {
		testing.expect_value(t, string(data.payload), "streamed-over-h2")
	}
}

/*
Feature parity between the two protocols.

The h2 path reuses the same `Handler`, so features should carry over — but the
last two audits found cases where they silently did not, so parity is asserted
rather than assumed. Each case runs the same handler over h2 and checks the
result matches what HTTP/1.1 produces.
*/
@(private)
h2_get :: proc(path: string, router: ^http.Router, arena: ^virtual.Arena) -> [dynamic]byte {
	srv := new(http.Server, context.allocator)
	defer free(srv)
	srv.opts = http.DEFAULT_SERVER_OPTS
	srv.handler = http.router_handler(router)

	script := h2_script()

	// Encode ":method GET", ":scheme http", then a literal :path and
	// :authority, which is what a client sends for any non-root target.
	block := make([dynamic]byte, 0, 128, context.temp_allocator)
	http.hpack_encode_integer(&block, 2, 7, 0x80) // :method GET
	http.hpack_encode_integer(&block, 6, 7, 0x80) // :scheme http
	// Literal without indexing, name from static index 4 (:path).
	http.hpack_encode_integer(&block, 4, 4, 0x00)
	http.hpack_encode_string(&block, path)
	// Literal without indexing, name from static index 1 (:authority).
	http.hpack_encode_integer(&block, 1, 4, 0x00)
	http.hpack_encode_string(&block, "x")

	http.h2_frame_encode(&script, .Headers,
		http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 1, block[:])

	mt: http.Memory_Transport
	http.memory_transport_init(&mt, script[:])
	http.h2_serve_memory(&mt, srv, virtual.arena_allocator(arena))
	return mt.output
}

@(test)
test_h2_routing_captures_path_parameters :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	router := new(http.Router, context.allocator)
	defer { http.router_destroy(router); free(router) }
	http.router_init(router)
	http.router_handle_proc(router, "GET /users/{id}", proc(q: ^http.Request, s: ^http.Response) {
		id := http.request_param(q, "id")
		http.respond_plain(s, .OK, id)
	})

	out := h2_get("/users/42", router, &arena)
	defer delete(out)

	data, found := h2_find_frame(out[:], .Data)
	testing.expect(t, found, "a routed handler must produce DATA over h2")
	if found {
		// The router must see the same target it would over HTTP/1.1.
		testing.expect_value(t, string(data.payload), "42")
	}
}

@(test)
test_h2_routing_reports_404_and_405 :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	router := new(http.Router, context.allocator)
	defer { http.router_destroy(router); free(router) }
	http.router_init(router)
	http.router_handle_proc(router, "POST /only-post", proc(q: ^http.Request, s: ^http.Response) {})

	// No route at all.
	missing := h2_get("/nope", router, &arena)
	defer delete(missing)
	data, found := h2_find_frame(missing[:], .Data)
	testing.expect(t, found, "a 404 body must still be sent")
	if found {
		testing.expect_value(t, string(data.payload), "Not Found")
	}

	// The path exists under another method, which must be 405 with Allow —
	// the same distinction the HTTP/1.1 path makes.
	wrong := h2_get("/only-post", router, &arena)
	defer delete(wrong)
	body, has_body := h2_find_frame(wrong[:], .Data)
	testing.expect(t, has_body, "a 405 body must still be sent")
	if has_body {
		testing.expect_value(t, string(body.payload), "Method Not Allowed")
	}
}

@(test)
test_h2_query_strings_reach_handlers :: proc(t: ^testing.T) {
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	router := new(http.Router, context.allocator)
	defer { http.router_destroy(router); free(router) }
	http.router_init(router)
	http.router_handle_proc(router, "GET /search", proc(q: ^http.Request, s: ^http.Response) {
		u := http.request_url(q, q.headers.allocator)
		values := http.query_parse(u.raw_query, q.headers.allocator)
		http.respond_plain(s, .OK, values["q"])
	})

	// h2 carries the query in :path, so it must survive into the target and be
	// parsed the same way it is over HTTP/1.1.
	out := h2_get("/search?q=odin&n=1", router, &arena)
	defer delete(out)

	data, found := h2_find_frame(out[:], .Data)
	testing.expect(t, found, "query handler must produce DATA")
	if found {
		testing.expect_value(t, string(data.payload), "odin")
	}
}

@(test)
test_h2_trailers_do_not_kill_the_connection :: proc(t: ^testing.T) {
	/*
	RFC 9113 8.1: a stream may carry HEADERS, then DATA, then a second HEADERS
	carrying trailers. gRPC depends on this — its status is sent as trailers —
	so treating the second HEADERS as an attempt to reopen the stream takes down
	the whole connection for an entirely legal request.
	*/
	script := h2_script()

	// Opening HEADERS, no END_STREAM: a body follows.
	block := []byte{0x82, 0x86, 0x84, 0x41, 0x01, 'x'}
	http.h2_frame_encode(&script, .Headers, http.H2_FLAG_END_HEADERS, 1, block)

	// A body.
	http.h2_frame_encode(&script, .Data, 0, 1, transmute([]byte)string("hello"))

	// Trailers: a second HEADERS on the same stream, ending it.
	trailer := []byte{
		0x00,
		0x07, 'x', '-', 't', 'r', 'a', 'c', 'e',
		0x02, 'i', 'd',
	}
	http.h2_frame_encode(&script, .Headers,
		http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 1, trailer)

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	srv := new(http.Server, context.allocator)
	router := new(http.Router, context.allocator)
	defer { http.router_destroy(router); free(router); free(srv) }
	http.router_init(router)
	http.router_handle_proc(router, "GET /", proc(q: ^http.Request, s: ^http.Response) {
		http.respond_plain(s, .OK, q.body)
	})
	srv.opts = http.DEFAULT_SERVER_OPTS
	srv.handler = http.router_handler(router)

	mt: http.Memory_Transport
	http.memory_transport_init(&mt, script[:])
	defer http.memory_transport_destroy(&mt)
	http.h2_serve_memory(&mt, srv, virtual.arena_allocator(&arena))
	out := mt.output

	// The request must be answered, not the connection destroyed.
	if goaway, found := h2_find_frame(out[:], .Goaway); found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expectf(t, g.code == .No_Error,
			"trailers must not produce GOAWAY, got %v", g.code)
	}

	_, has_response := h2_find_frame(out[:], .Headers)
	testing.expect(t, has_response, "a request with trailers must still be answered")

	// The body sent before the trailers must have reached the handler intact:
	// the echo route returns whatever it received.
	data, has_data := h2_find_frame(out[:], .Data)
	testing.expect(t, has_data, "the response body must be sent")
	if has_data {
		testing.expect_value(t, string(data.payload), "hello")
	}
}

@(test)
test_h2_large_body_across_many_data_frames :: proc(t: ^testing.T) {
	/*
	A body larger than the initial flow-control window (65535 bytes) can only
	arrive if the server replenishes the peer's window as it consumes DATA.
	Without that the connection stalls partway through every large upload —
	which no small test would notice.
	*/
	BODY_SIZE :: 200_000
	CHUNK     :: 8_192

	script := h2_script()
	block := []byte{0x83, 0x86, 0x84, 0x41, 0x01, 'x'} // POST, http, /, authority
	http.h2_frame_encode(&script, .Headers, http.H2_FLAG_END_HEADERS, 1, block)

	// Fill with a repeating pattern so truncation or reordering is visible.
	payload := make([]byte, CHUNK, context.temp_allocator)
	for i in 0 ..< CHUNK { payload[i] = u8('a' + i % 26) }

	sent := 0
	for sent < BODY_SIZE {
		n := min(CHUNK, BODY_SIZE - sent)
		sent += n
		flags := u8(0)
		if sent >= BODY_SIZE { flags = http.H2_FLAG_END_STREAM }
		http.h2_frame_encode(&script, .Data, flags, 1, payload[:n])
	}

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	srv := new(http.Server, context.allocator)
	router := new(http.Router, context.allocator)
	defer { http.router_destroy(router); free(router); free(srv) }

	http.router_init(router)
	http.router_handle_proc(router, "POST /", proc(q: ^http.Request, s: ^http.Response) {
		// Report the length rather than echoing 200 KB back.
		http.respond_plain(s, .OK, h2_len_string(len(q.body)))
	})
	srv.opts = http.DEFAULT_SERVER_OPTS
	srv.handler = http.router_handler(router)

	mt: http.Memory_Transport
	http.memory_transport_init(&mt, script[:])
	defer http.memory_transport_destroy(&mt)
	http.h2_serve_memory(&mt, srv, virtual.arena_allocator(&arena))

	if goaway, found := h2_find_frame(mt.output[:], .Goaway); found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expectf(t, g.code == .No_Error,
			"a large body must not fail the connection, got %v", g.code)
	}

	data, has := h2_find_frame(mt.output[:], .Data)
	testing.expect(t, has, "the handler must have run")
	if has {
		testing.expect_value(t, string(data.payload), "200000")
	}

	// The server must have granted more window than the 65535 it started with,
	// or the peer could never have sent this much.
	updates := h2_count_frames(mt.output[:], .Window_Update)
	testing.expect(t, updates > 0, "the server must replenish the peer's window")
}

@(private)
h2_len_string :: proc(v: int) -> string {
	buf := make([]byte, 24, context.temp_allocator)
	if v == 0 { buf[0] = '0'; return string(buf[:1]) }
	n := 0
	value := v
	for value > 0 { buf[n] = u8('0' + value % 10); value /= 10; n += 1 }
	for i in 0 ..< n / 2 { buf[i], buf[n - 1 - i] = buf[n - 1 - i], buf[i] }
	return string(buf[:n])
}

@(test)
test_h2_interleaved_streams_stay_separate :: proc(t: ^testing.T) {
	/*
	Multiplexing is h2's defining feature, and the failure mode is silent: if
	stream state were shared, DATA for one request would land on another's body
	and each client would receive a plausible-looking but wrong response.

	Three streams are opened, then their bodies interleaved frame by frame.
	*/
	script := h2_script()

	ids := []u32{1, 3, 5}
	marks := []byte{'A', 'B', 'C'}

	for id in ids {
		block := []byte{0x83, 0x86, 0x84, 0x41, 0x01, 'x'}
		http.h2_frame_encode(&script, .Headers, http.H2_FLAG_END_HEADERS, id, block)
	}

	// Round-robin the bodies so no stream's frames are contiguous.
	for round in 0 ..< 4 {
		for id, i in ids {
			chunk := []byte{marks[i], marks[i], marks[i], marks[i]}
			last := round == 3
			flags := u8(0)
			if last { flags = http.H2_FLAG_END_STREAM }
			http.h2_frame_encode(&script, .Data, flags, id, chunk)
		}
	}

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	srv := new(http.Server, context.allocator)
	router := new(http.Router, context.allocator)
	defer { http.router_destroy(router); free(router); free(srv) }

	http.router_init(router)
	http.router_handle_proc(router, "POST /", proc(q: ^http.Request, s: ^http.Response) {
		http.respond_plain(s, .OK, q.body)
	})
	srv.opts = http.DEFAULT_SERVER_OPTS
	srv.handler = http.router_handler(router)

	mt: http.Memory_Transport
	http.memory_transport_init(&mt, script[:])
	defer http.memory_transport_destroy(&mt)
	http.h2_serve_memory(&mt, srv, virtual.arena_allocator(&arena))

	// Each stream must get back exactly its own bytes, never another's.
	expected_body :: proc(id: u32) -> (string, bool) {
		switch id {
		case 1: return "AAAAAAAAAAAAAAAA", true
		case 3: return "BBBBBBBBBBBBBBBB", true
		case 5: return "CCCCCCCCCCCCCCCC", true
		}
		return "", false
	}

	seen := 0
	pos := 0
	for pos < len(mt.output) {
		f, consumed, result, _ := http.h2_frame_decode(mt.output[pos:], http.H2_MAX_ALLOWED_FRAME_SIZE)
		if result != .Ok { break }
		pos += consumed

		if f.type != .Data || len(f.payload) == 0 { continue }

		want, known := expected_body(f.stream_id)
		testing.expectf(t, known, "DATA for unexpected stream %d", f.stream_id)
		if known {
			testing.expectf(t, string(f.payload) == want,
				"stream %d got %q, want %q — bodies crossed streams",
				f.stream_id, string(f.payload), want)
			seen += 1
		}
	}

	testing.expect_value(t, seen, 3)
}

@(test)
test_h2_head_reports_the_length_a_get_would :: proc(t: ^testing.T) {
	/*
	RFC 9110 9.3.2: a HEAD response carries the header fields the equivalent GET
	would, including Content-Length, but never the body. Clients size a download
	from that header before deciding to make it, so omitting it is a real
	regression even though nothing appears broken.
	*/
	script := h2_script()
	// :method HEAD is not in the static table, so it goes as a literal.
	block := make([dynamic]byte, 0, 64, context.temp_allocator)
	http.hpack_encode_integer(&block, 2, 4, 0x00) // literal, name = :method
	http.hpack_encode_string(&block, "HEAD")
	http.hpack_encode_integer(&block, 6, 7, 0x80) // :scheme http
	http.hpack_encode_integer(&block, 4, 7, 0x80) // :path /
	http.hpack_encode_integer(&block, 1, 4, 0x00) // literal, name = :authority
	http.hpack_encode_string(&block, "x")

	http.h2_frame_encode(&script, .Headers,
		http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 1, block[:])

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	srv := new(http.Server, context.allocator)
	router := new(http.Router, context.allocator)
	defer { http.router_destroy(router); free(router); free(srv) }

	http.router_init(router)
	http.router_handle_proc(router, "GET /", proc(q: ^http.Request, s: ^http.Response) {
		http.respond_plain(s, .OK, "0123456789")
	})
	srv.opts = http.DEFAULT_SERVER_OPTS
	srv.handler = http.router_handler(router)

	mt: http.Memory_Transport
	http.memory_transport_init(&mt, script[:])
	defer http.memory_transport_destroy(&mt)
	http.h2_serve_memory(&mt, srv, virtual.arena_allocator(&arena))

	// No DATA frame carrying the body.
	for pos := 0; pos < len(mt.output); {
		f, consumed, result, _ := http.h2_frame_decode(mt.output[pos:], http.H2_MAX_ALLOWED_FRAME_SIZE)
		if result != .Ok { break }
		if f.type == .Data {
			testing.expectf(t, len(f.payload) == 0,
				"HEAD must not send a body, got %d bytes", len(f.payload))
		}
		pos += consumed
	}

	// But the headers must still report the length.
	headers, found := h2_find_frame(mt.output[:], .Headers)
	testing.expect(t, found, "HEAD must produce a response")
	if !found { return }

	decoder: http.Hpack_Decoder
	http.hpack_decoder_init(&decoder)
	defer http.hpack_decoder_destroy(&decoder)

	decoded: http.Headers
	http.headers_init(&decoded, virtual.arena_allocator(&arena))
	err := http.hpack_decode(&decoder, headers.payload, &decoded)
	testing.expect_value(t, err, http.Hpack_Error.None)

	length, has_length := http.headers_get(decoded, "content-length")
	testing.expect(t, has_length, "HEAD must report Content-Length")
	testing.expect_value(t, length, "10")
}

/*
A header block genuinely split across CONTINUATION frames must be served.

The existing CONTINUATION tests are both negative — an orphan frame and an
interrupted block — so nothing proved the accumulate-and-decode path works at
all. A block reassembled in the wrong order, or one CONTINUATION dropped, would
produce HPACK garbage rather than a clean error, and only a positive test
catches that.
*/
@(test)
test_h2_header_block_split_across_continuations :: proc(t: ^testing.T) {
	block := make([dynamic]byte, 0, 64, context.temp_allocator)
	http.hpack_encode_integer(&block, 2, 7, 0x80) // :method GET
	http.hpack_encode_integer(&block, 6, 7, 0x80) // :scheme http
	http.hpack_encode_integer(&block, 4, 7, 0x80) // :path /
	http.hpack_encode_integer(&block, 1, 4, 0x00) // :authority literal
	http.hpack_encode_string(&block, "x")
	b := block[:]

	script := h2_script()
	// END_STREAM rides on HEADERS: CONTINUATION has no such flag (RFC 9113 6.10),
	// so the request is complete once the block ends.
	http.h2_frame_encode(&script, .Headers, http.H2_FLAG_END_STREAM, 1, b[:2])
	http.h2_frame_encode(&script, .Continuation, 0, 1, b[2:4])
	http.h2_frame_encode(&script, .Continuation, http.H2_FLAG_END_HEADERS, 1, b[4:])

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	_, found := h2_find_frame(out[:], .Headers)
	testing.expect(t, found, "a split header block must produce a response")

	_, refused := h2_find_frame(out[:], .Goaway)
	testing.expect(t, !refused, "a legal split must not tear down the connection")
}

/*
CONTINUATION carries no END_STREAM, and an undefined flag must be ignored.

RFC 9113 4.1 requires unknown flags to be ignored rather than rejected. Setting
0x1 on a CONTINUATION therefore leaves the stream open for a body, which is the
correct — and easily misread — outcome: the request is not delivered, and the
connection stays healthy.
*/
@(test)
test_h2_continuation_ignores_undefined_flags :: proc(t: ^testing.T) {
	block := make([dynamic]byte, 0, 64, context.temp_allocator)
	http.hpack_encode_integer(&block, 2, 7, 0x80)
	http.hpack_encode_integer(&block, 6, 7, 0x80)
	http.hpack_encode_integer(&block, 4, 7, 0x80)
	http.hpack_encode_integer(&block, 1, 4, 0x00)
	http.hpack_encode_string(&block, "x")
	b := block[:]

	script := h2_script()
	http.h2_frame_encode(&script, .Headers, 0, 1, b[:3])
	// 0x1 is END_STREAM on HEADERS/DATA but undefined on CONTINUATION.
	http.h2_frame_encode(&script, .Continuation,
		http.H2_FLAG_END_HEADERS | http.H2_FLAG_END_STREAM, 1, b[3:])

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	// Ignoring the flag means the stream is still awaiting a body, so no
	// response is due — but the connection must not be torn down for it.
	_, refused := h2_find_frame(out[:], .Goaway)
	testing.expect(t, !refused, "an undefined flag must be ignored, not rejected")
}

/*
A CONTINUATION naming a different stream than the open block is a protocol error.

Accepting one would let a peer splice two header blocks together and desynchronize
HPACK for the rest of the connection.
*/
@(test)
test_h2_continuation_on_wrong_stream_is_rejected :: proc(t: ^testing.T) {
	script := h2_script()
	http.h2_frame_encode(&script, .Headers, 0, 1, []byte{0x82})
	http.h2_frame_encode(&script, .Continuation, http.H2_FLAG_END_HEADERS, 3, []byte{0x86})

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	goaway, found := h2_find_frame(out[:], .Goaway)
	testing.expect(t, found, "a CONTINUATION for another stream must produce GOAWAY")
	if found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expect_value(t, g.code, http.H2_Error.Protocol_Error)
	}
}

// An unbounded run of CONTINUATION frames must be cut off rather than buffered.
@(test)
test_h2_continuation_flood_is_bounded :: proc(t: ^testing.T) {
	script := h2_script()
	http.h2_frame_encode(&script, .Headers, 0, 1, []byte{0x82})

	// 160KB of header block, well past the 64KB cap, never ending the block.
	chunk := make([]byte, 4096, context.temp_allocator)
	for _ in 0 ..< 40 {
		http.h2_frame_encode(&script, .Continuation, 0, 1, chunk)
	}

	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	defer virtual.arena_destroy(&arena)

	out := h2_run_script(script[:], &arena)
	defer delete(out)

	goaway, found := h2_find_frame(out[:], .Goaway)
	testing.expect(t, found, "an oversized header block must produce GOAWAY")
	if found {
		g, _ := http.h2_goaway_decode(goaway.payload)
		testing.expect_value(t, g.code, http.H2_Error.Enhance_Your_Calm)
	}
}
