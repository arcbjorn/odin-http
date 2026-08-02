package tests

import "core:testing"

import http "../http"

/*
HTTP/2 frame layer.

The frame layer is sans-I/O like the HTTP/1.1 parser, so these run without
sockets. Round-trip tests alone would only prove the encoder and decoder agree
with each other, so the decode tests assert on hand-written wire bytes taken
from RFC 9113's field layout.
*/

@(test)
test_h2_decode_frame_header :: proc(t: ^testing.T) {
	// length=4, type=WINDOW_UPDATE(0x8), flags=0, stream=1, payload=increment 5
	wire := []byte{
		0x00, 0x00, 0x04,
		0x08,
		0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x05,
	}

	frame, consumed, result, err := http.h2_frame_decode(wire)

	testing.expect_value(t, result, http.H2_Decode_Result.Ok)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, frame.type, http.H2_Frame_Type.Window_Update)
	testing.expect_value(t, frame.stream_id, u32(1))
	testing.expect_value(t, consumed, 13)
	testing.expect_value(t, len(frame.payload), 4)
}

@(test)
test_h2_decode_needs_full_frame :: proc(t: ^testing.T) {
	// Header says 8 bytes of payload but only 2 are present.
	partial := []byte{0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb}

	_, _, result, _ := http.h2_frame_decode(partial)
	testing.expect_value(t, result, http.H2_Decode_Result.Need_More)

	// A truncated header is equally incomplete, not an error.
	_, _, short, _ := http.h2_frame_decode([]byte{0x00, 0x00})
	testing.expect_value(t, short, http.H2_Decode_Result.Need_More)
}

@(test)
test_h2_decode_rejects_oversized_frame :: proc(t: ^testing.T) {
	// Announces 0xFFFFFF bytes. Buffering that on a peer's say-so is how an
	// announced-but-never-sent frame becomes an allocation attack.
	wire := []byte{0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

	_, _, result, err := http.h2_frame_decode(wire)

	testing.expect_value(t, result, http.H2_Decode_Result.Error)
	testing.expect_value(t, err, http.H2_Error.Frame_Size_Error)
}

@(test)
test_h2_decode_ignores_reserved_bit :: proc(t: ^testing.T) {
	// The high bit of the stream identifier is reserved and must be masked off,
	// not read as part of the id (RFC 9113 4.1).
	wire := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x80, 0x00, 0x00, 0x01}

	frame, _, result, _ := http.h2_frame_decode(wire)

	testing.expect_value(t, result, http.H2_Decode_Result.Ok)
	testing.expect_value(t, frame.stream_id, u32(1))
}

@(test)
test_h2_decode_keeps_unknown_frame_types :: proc(t: ^testing.T) {
	// RFC 9113 4.1: an unknown type must be ignored, which means decoded and
	// discarded by the connection layer rather than rejected here.
	wire := []byte{0x00, 0x00, 0x01, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff}

	frame, consumed, result, err := http.h2_frame_decode(wire)

	testing.expect_value(t, result, http.H2_Decode_Result.Ok)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, u8(frame.type), u8(0x63))
	testing.expect_value(t, consumed, 10)
}

@(test)
test_h2_encode_matches_wire_layout :: proc(t: ^testing.T) {
	out := make([dynamic]byte, 0, 32, context.temp_allocator)
	http.h2_frame_encode(&out, .Headers, http.H2_FLAG_END_HEADERS, 3, []byte{0xde, 0xad})

	expected := []byte{
		0x00, 0x00, 0x02, // length
		0x01,             // HEADERS
		0x04,             // END_HEADERS
		0x00, 0x00, 0x00, 0x03,
		0xde, 0xad,
	}

	testing.expect_value(t, len(out), len(expected))
	for b, i in expected {
		testing.expectf(t, out[i] == b, "byte %d: got 0x%02x want 0x%02x", i, out[i], b)
	}
}

@(test)
test_h2_frame_round_trip :: proc(t: ^testing.T) {
	out := make([dynamic]byte, 0, 64, context.temp_allocator)
	payload := []byte{1, 2, 3, 4, 5}
	http.h2_frame_encode(&out, .Data, http.H2_FLAG_END_STREAM, 7, payload)

	frame, consumed, result, err := http.h2_frame_decode(out[:])

	testing.expect_value(t, result, http.H2_Decode_Result.Ok)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, frame.type, http.H2_Frame_Type.Data)
	testing.expect_value(t, frame.flags, u8(http.H2_FLAG_END_STREAM))
	testing.expect_value(t, frame.stream_id, u32(7))
	testing.expect_value(t, consumed, len(out))
	testing.expect_value(t, len(frame.payload), 5)
	testing.expect_value(t, frame.payload[4], u8(5))
}

// --- Padding ---

@(test)
test_h2_strip_padding :: proc(t: ^testing.T) {
	// pad length 2, then "hi", then two padding octets.
	payload := []byte{0x02, 'h', 'i', 0x00, 0x00}

	stripped, err := http.h2_strip_padding(payload, http.H2_FLAG_PADDED)

	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, string(stripped), "hi")
}

@(test)
test_h2_strip_padding_rejects_overlong_pad :: proc(t: ^testing.T) {
	// A pad length at or beyond the remaining payload would yield a negative
	// body length — the h2 analogue of a bad Content-Length.
	payload := []byte{0x10, 'h', 'i'}

	_, err := http.h2_strip_padding(payload, http.H2_FLAG_PADDED)
	testing.expect_value(t, err, http.H2_Error.Protocol_Error)

	// PADDED set with an empty payload has no room for the length octet.
	_, empty := http.h2_strip_padding([]byte{}, http.H2_FLAG_PADDED)
	testing.expect_value(t, empty, http.H2_Error.Protocol_Error)
}

@(test)
test_h2_strip_padding_passthrough :: proc(t: ^testing.T) {
	payload := []byte{'h', 'i'}
	stripped, err := http.h2_strip_padding(payload, 0)

	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, string(stripped), "hi")
}

// --- SETTINGS ---

@(test)
test_h2_settings_apply :: proc(t: ^testing.T) {
	s := http.H2_DEFAULT_SETTINGS

	// MAX_CONCURRENT_STREAMS = 100, INITIAL_WINDOW_SIZE = 65536
	payload := []byte{
		0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
		0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
	}

	err := http.h2_settings_apply(&s, payload)

	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, s.max_concurrent_streams, u32(100))
	testing.expect_value(t, s.initial_window_size, u32(65_536))
	// Untouched settings keep their defaults.
	testing.expect_value(t, s.max_frame_size, u32(http.H2_DEFAULT_MAX_FRAME_SIZE))
}

@(test)
test_h2_settings_ignores_unknown_ids :: proc(t: ^testing.T) {
	s := http.H2_DEFAULT_SETTINGS
	// Identifier 0xff is undefined; ignoring it is what lets new settings ship
	// without breaking older peers.
	payload := []byte{0x00, 0xff, 0x00, 0x00, 0x00, 0x01}

	err := http.h2_settings_apply(&s, payload)
	testing.expect_value(t, err, http.H2_Error.No_Error)
}

@(test)
test_h2_settings_rejects_invalid :: proc(t: ^testing.T) {
	{
		// A payload that is not a multiple of six cannot be a list of entries.
		s := http.H2_DEFAULT_SETTINGS
		err := http.h2_settings_apply(&s, []byte{0x00, 0x03, 0x00})
		testing.expect_value(t, err, http.H2_Error.Frame_Size_Error)
	}
	{
		// ENABLE_PUSH is boolean; anything else is a protocol error.
		s := http.H2_DEFAULT_SETTINGS
		err := http.h2_settings_apply(&s, []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x02})
		testing.expect_value(t, err, http.H2_Error.Protocol_Error)
	}
	{
		// A window above 2^31-1 is a flow-control error.
		s := http.H2_DEFAULT_SETTINGS
		err := http.h2_settings_apply(&s, []byte{0x00, 0x04, 0xff, 0xff, 0xff, 0xff})
		testing.expect_value(t, err, http.H2_Error.Flow_Control_Error)
	}
	{
		// MAX_FRAME_SIZE below the 16384 floor.
		s := http.H2_DEFAULT_SETTINGS
		err := http.h2_settings_apply(&s, []byte{0x00, 0x05, 0x00, 0x00, 0x00, 0x01})
		testing.expect_value(t, err, http.H2_Error.Protocol_Error)
	}
}

// --- WINDOW_UPDATE ---

@(test)
test_h2_window_update :: proc(t: ^testing.T) {
	inc, err := http.h2_window_update_decode([]byte{0x00, 0x00, 0x01, 0x00})
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, inc, u32(256))

	// A zero increment conveys nothing and is used to probe implementations
	// that fail to check for it.
	_, zero := http.h2_window_update_decode([]byte{0, 0, 0, 0})
	testing.expect_value(t, zero, http.H2_Error.Protocol_Error)

	_, short := http.h2_window_update_decode([]byte{0, 0, 0})
	testing.expect_value(t, short, http.H2_Error.Frame_Size_Error)
}

@(test)
test_h2_window_update_round_trip :: proc(t: ^testing.T) {
	out := make([dynamic]byte, 0, 16, context.temp_allocator)
	http.h2_window_update_encode(&out, 5, 1024)

	frame, _, result, _ := http.h2_frame_decode(out[:])
	testing.expect_value(t, result, http.H2_Decode_Result.Ok)
	testing.expect_value(t, frame.type, http.H2_Frame_Type.Window_Update)
	testing.expect_value(t, frame.stream_id, u32(5))

	inc, err := http.h2_window_update_decode(frame.payload)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, inc, u32(1024))
}

// --- GOAWAY and RST_STREAM ---

@(test)
test_h2_goaway_round_trip :: proc(t: ^testing.T) {
	out := make([dynamic]byte, 0, 64, context.temp_allocator)
	http.h2_goaway_encode(&out, 9, .Protocol_Error, "bad frame")

	frame, _, result, _ := http.h2_frame_decode(out[:])
	testing.expect_value(t, result, http.H2_Decode_Result.Ok)
	testing.expect_value(t, frame.type, http.H2_Frame_Type.Goaway)
	// GOAWAY is a connection-level frame and must use stream 0.
	testing.expect_value(t, frame.stream_id, u32(0))

	g, err := http.h2_goaway_decode(frame.payload)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	// last_stream_id tells the peer what was processed, so it knows what is
	// safe to retry elsewhere.
	testing.expect_value(t, g.last_stream_id, u32(9))
	testing.expect_value(t, g.code, http.H2_Error.Protocol_Error)
	testing.expect_value(t, string(g.debug), "bad frame")
}

@(test)
test_h2_goaway_rejects_short_payload :: proc(t: ^testing.T) {
	_, err := http.h2_goaway_decode([]byte{0, 0, 0, 1})
	testing.expect_value(t, err, http.H2_Error.Frame_Size_Error)
}

@(test)
test_h2_rst_stream_round_trip :: proc(t: ^testing.T) {
	out := make([dynamic]byte, 0, 16, context.temp_allocator)
	http.h2_rst_stream_encode(&out, 3, .Cancel)

	frame, _, result, _ := http.h2_frame_decode(out[:])
	testing.expect_value(t, result, http.H2_Decode_Result.Ok)
	testing.expect_value(t, frame.stream_id, u32(3))

	code, err := http.h2_rst_stream_decode(frame.payload)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, code, http.H2_Error.Cancel)
}

// --- PING ---

@(test)
test_h2_ping_ack_echoes_payload :: proc(t: ^testing.T) {
	out := make([dynamic]byte, 0, 32, context.temp_allocator)
	opaque := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	err := http.h2_ping_ack(&out, opaque)
	testing.expect_value(t, err, http.H2_Error.No_Error)

	frame, _, result, _ := http.h2_frame_decode(out[:])
	testing.expect_value(t, result, http.H2_Decode_Result.Ok)
	testing.expect_value(t, frame.type, http.H2_Frame_Type.Ping)
	testing.expect_value(t, frame.flags, u8(http.H2_FLAG_ACK))

	// The 8 octets are the peer's round-trip correlator and must come back
	// byte-identical.
	for b, i in opaque {
		testing.expectf(t, frame.payload[i] == b, "ping octet %d not echoed", i)
	}
}

@(test)
test_h2_ping_rejects_wrong_length :: proc(t: ^testing.T) {
	out := make([dynamic]byte, 0, 16, context.temp_allocator)
	err := http.h2_ping_ack(&out, []byte{1, 2, 3})
	testing.expect_value(t, err, http.H2_Error.Frame_Size_Error)
}

/*
Real bytes captured from `curl --http2-prior-knowledge`.

Round-trip tests only prove the encoder and decoder agree with each other. This
one proves the decoder agrees with nghttp2, which is what actually matters: a
misread of the spec that is self-consistent would pass every other test in this
file.
*/
@(test)
test_h2_decodes_real_curl_traffic :: proc(t: ^testing.T) {
	wire := []byte{
		0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32,
		0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
		0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
		0x00, 0x00, 0x64, 0x00, 0x04, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x3e, 0x7f, 0x00, 0x01, 0x00, 0x00, 0x23, 0x01, 0x05, 0x00, 0x00, 0x00,
		0x01, 0x82, 0x86, 0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70, 0xdc,
		0x78, 0x0f, 0x8b, 0x04, 0x84, 0x61, 0x25, 0x42, 0x7f, 0x7a, 0x88, 0x25,
		0xb6, 0x50, 0xc3, 0xcb, 0xba, 0xb8, 0x7f, 0x53, 0x03, 0x2a, 0x2f, 0x2a,
	}

	preface := http.H2_CLIENT_PREFACE
	testing.expect(t, len(wire) > len(preface), "capture is too short")
	testing.expect_value(t, string(wire[:len(preface)]), preface)

	rest := wire[len(preface):]
	settings := http.H2_DEFAULT_SETTINGS

	seen_settings, seen_window_update, seen_headers := false, false, false

	for len(rest) > 0 {
		frame, consumed, result, err := http.h2_frame_decode(rest)
		testing.expectf(t, result == .Ok, "decode failed: result=%v err=%v", result, err)
		if result != .Ok { break }

		#partial switch frame.type {
		case .Settings:
			seen_settings = true
			testing.expect_value(t, frame.stream_id, u32(0))
			e := http.h2_settings_apply(&settings, frame.payload)
			testing.expect_value(t, e, http.H2_Error.No_Error)

		case .Window_Update:
			seen_window_update = true
			_, e := http.h2_window_update_decode(frame.payload)
			testing.expect_value(t, e, http.H2_Error.No_Error)

		case .Headers:
			seen_headers = true
			// curl opens with the first client-initiated stream, which must be
			// odd (RFC 9113 5.1.1).
			testing.expect_value(t, frame.stream_id, u32(1))
			testing.expect(t, frame.flags & http.H2_FLAG_END_HEADERS != 0,
				"a single HEADERS frame must carry END_HEADERS")
		}

		rest = rest[consumed:]
	}

	testing.expect(t, seen_settings, "no SETTINGS frame decoded")
	testing.expect(t, seen_window_update, "no WINDOW_UPDATE frame decoded")
	testing.expect(t, seen_headers, "no HEADERS frame decoded")
	// Real traffic must consume exactly, with no trailing partial frame.
	testing.expect_value(t, len(rest), 0)
}
