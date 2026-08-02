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
