package http

/*
HTTP/2 frame layer (RFC 9113 section 4 and 6).

Every h2 frame is a 9-octet header followed by a payload:

	+-----------------------------------------------+
	|                 Length (24)                   |
	+---------------+---------------+---------------+
	|   Type (8)    |   Flags (8)   |
	+-+-------------+---------------+-------------------------------+
	|R|                 Stream Identifier (31)                      |
	+=+=============================================================+
	|                   Frame Payload (0...)                      ...

Like the HTTP/1.1 parser, this layer is sans-I/O: it decodes from a byte slice
and encodes into a builder, so it can be tested without sockets and driven by
any transport. Payloads are borrowed from the caller's buffer, never copied.
*/

H2_FRAME_HEADER_SIZE :: 9

/*
The default and minimum SETTINGS_MAX_FRAME_SIZE (RFC 9113 6.5.2).

A peer may negotiate up to 2^24-1, but until it does, a frame larger than this
is a connection error — which is also what stops a peer from announcing a huge
length and making us buffer it.
*/
H2_DEFAULT_MAX_FRAME_SIZE :: 16_384
H2_MAX_ALLOWED_FRAME_SIZE :: 16_777_215

H2_Frame_Type :: enum u8 {
	Data          = 0x0,
	Headers       = 0x1,
	Priority      = 0x2,
	Rst_Stream    = 0x3,
	Settings      = 0x4,
	Push_Promise  = 0x5,
	Ping          = 0x6,
	Goaway        = 0x7,
	Window_Update = 0x8,
	Continuation  = 0x9,
}

/*
Frame flags.

The same bit means different things per frame type — 0x1 is END_STREAM on DATA
and HEADERS but ACK on SETTINGS and PING — so these are named per type rather
than shared, and the decoder never interprets a flag without knowing the type.
*/
H2_FLAG_END_STREAM  :: 0x1
H2_FLAG_ACK         :: 0x1
H2_FLAG_END_HEADERS :: 0x4
H2_FLAG_PADDED      :: 0x8
H2_FLAG_PRIORITY    :: 0x20

H2_Frame :: struct {
	type:      H2_Frame_Type,
	flags:     u8,
	stream_id: u32,
	// Borrowed from the caller's buffer, valid until that buffer is reused.
	payload:   []byte,
}

H2_Error :: enum u32 {
	No_Error            = 0x0,
	Protocol_Error      = 0x1,
	Internal_Error      = 0x2,
	Flow_Control_Error  = 0x3,
	Settings_Timeout    = 0x4,
	Stream_Closed       = 0x5,
	Frame_Size_Error    = 0x6,
	Refused_Stream      = 0x7,
	Cancel              = 0x8,
	Compression_Error   = 0x9,
	Connect_Error       = 0xa,
	Enhance_Your_Calm   = 0xb,
	Inadequate_Security = 0xc,
	Http_1_1_Required   = 0xd,
}

H2_Decode_Result :: enum u8 {
	Ok,
	// The buffer holds less than one complete frame; read more and retry.
	Need_More,
	// A connection error: the caller must send GOAWAY and close.
	Error,
}

/*
Decodes one frame from the front of `data`.

Returns the frame, how many bytes it occupied, and whether more input is needed.
The payload borrows from `data`, so the caller must finish with the frame before
reusing that memory — the same contract as the HTTP/1.1 parser.

`max_frame_size` is the value this endpoint advertised. A peer exceeding it is a
FRAME_SIZE_ERROR, which is what prevents an announced-but-never-sent 16 MB frame
from becoming an allocation attack.
*/
h2_frame_decode :: proc(
	data: []byte,
	max_frame_size := u32(H2_DEFAULT_MAX_FRAME_SIZE),
) -> (frame: H2_Frame, consumed: int, result: H2_Decode_Result, err: H2_Error) {
	if len(data) < H2_FRAME_HEADER_SIZE {
		return {}, 0, .Need_More, .No_Error
	}

	length := u32(data[0]) << 16 | u32(data[1]) << 8 | u32(data[2])

	if length > max_frame_size {
		return {}, 0, .Error, .Frame_Size_Error
	}

	// An unknown frame type must be ignored, not rejected (RFC 9113 4.1), so it
	// is decoded normally and left for the connection layer to discard.
	frame.type  = H2_Frame_Type(data[3])
	frame.flags = data[4]

	// The top bit is reserved and must be ignored on receipt, not treated as
	// part of the identifier.
	frame.stream_id = (u32(data[5]) << 24 | u32(data[6]) << 16 |
	                   u32(data[7]) << 8  | u32(data[8])) & 0x7fff_ffff

	total := H2_FRAME_HEADER_SIZE + int(length)
	if len(data) < total {
		return {}, 0, .Need_More, .No_Error
	}

	frame.payload = data[H2_FRAME_HEADER_SIZE:total]
	return frame, total, .Ok, .No_Error
}

/*
Writes a frame header followed by `payload`.

Length is derived from the payload rather than passed separately, so the two can
never disagree — a mismatch would desynchronize the peer's framing exactly the
way a wrong Content-Length does in HTTP/1.1.
*/
h2_frame_encode :: proc(
	out: ^[dynamic]byte,
	type: H2_Frame_Type,
	flags: u8,
	stream_id: u32,
	payload: []byte,
) {
	length := u32(len(payload))
	assert(length <= H2_MAX_ALLOWED_FRAME_SIZE, "frame payload exceeds the 24-bit length field")

	append(out, u8(length >> 16), u8(length >> 8), u8(length))
	append(out, u8(type), flags)

	// The reserved bit is always sent as 0.
	id := stream_id & 0x7fff_ffff
	append(out, u8(id >> 24), u8(id >> 16), u8(id >> 8), u8(id))

	append(out, ..payload)
}

/*
Strips the padding a DATA or HEADERS frame may carry.

RFC 9113 6.1: when PADDED is set the payload begins with a one-octet pad length.
A pad length at or beyond the remaining payload is a PROTOCOL_ERROR — accepting
it would produce a negative-length body, which is the h2 analogue of a bad
Content-Length.
*/
h2_strip_padding :: proc(payload: []byte, flags: u8) -> (stripped: []byte, err: H2_Error) {
	if flags & H2_FLAG_PADDED == 0 {
		return payload, .No_Error
	}
	if len(payload) < 1 {
		return nil, .Protocol_Error
	}

	pad := int(payload[0])
	rest := payload[1:]
	if pad > len(rest) {
		return nil, .Protocol_Error
	}

	return rest[:len(rest) - pad], .No_Error
}

// The 24-byte preface every h2 client sends before its first frame.
H2_CLIENT_PREFACE :: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

/*
Reads a u32 from the front of a payload.

h2 is big-endian throughout; doing this by hand rather than via a byte-order
helper keeps the frame layer free of endianness assumptions about the host.
*/
@(private)
h2_read_u32 :: #force_inline proc(b: []byte) -> u32 {
	return u32(b[0]) << 24 | u32(b[1]) << 16 | u32(b[2]) << 8 | u32(b[3])
}

@(private)
h2_write_u32 :: #force_inline proc(out: ^[dynamic]byte, v: u32) {
	append(out, u8(v >> 24), u8(v >> 16), u8(v >> 8), u8(v))
}

// --- SETTINGS (RFC 9113 6.5) ---

H2_Setting_Id :: enum u16 {
	Header_Table_Size      = 0x1,
	Enable_Push            = 0x2,
	Max_Concurrent_Streams = 0x3,
	Initial_Window_Size    = 0x4,
	Max_Frame_Size         = 0x5,
	Max_Header_List_Size   = 0x6,
}

/*
The peer's settings, seeded with the protocol defaults.

Defaults matter: they are in force from the first byte, before any SETTINGS
frame arrives, so a connection must be able to operate correctly using only
these.
*/
H2_Settings :: struct {
	header_table_size:      u32,
	enable_push:            bool,
	max_concurrent_streams: u32,
	initial_window_size:    u32,
	max_frame_size:         u32,
	max_header_list_size:   u32,
}

H2_DEFAULT_SETTINGS :: H2_Settings {
	header_table_size      = 4096,
	enable_push            = true,
	max_concurrent_streams = max(u32), // unlimited until the peer says otherwise
	initial_window_size    = 65_535,
	max_frame_size         = H2_DEFAULT_MAX_FRAME_SIZE,
	max_header_list_size   = max(u32),
}

// The largest legal flow-control window; going past it is a FLOW_CONTROL_ERROR.
H2_MAX_WINDOW_SIZE :: 2_147_483_647

/*
Applies a received SETTINGS payload.

Unknown identifiers are ignored rather than rejected (RFC 9113 6.5.2), which is
the extension point that lets new settings be added without breaking older
peers.
*/
h2_settings_apply :: proc(s: ^H2_Settings, payload: []byte) -> H2_Error {
	// Each entry is a 2-octet identifier and a 4-octet value.
	if len(payload) % 6 != 0 { return .Frame_Size_Error }

	for i := 0; i < len(payload); i += 6 {
		id    := H2_Setting_Id(u16(payload[i]) << 8 | u16(payload[i + 1]))
		value := h2_read_u32(payload[i + 2:])

		switch id {
		case .Header_Table_Size:
			s.header_table_size = value
		case .Enable_Push:
			// Only 0 and 1 are defined; anything else is a protocol error.
			if value > 1 { return .Protocol_Error }
			s.enable_push = value == 1
		case .Max_Concurrent_Streams:
			s.max_concurrent_streams = value
		case .Initial_Window_Size:
			if value > H2_MAX_WINDOW_SIZE { return .Flow_Control_Error }
			s.initial_window_size = value
		case .Max_Frame_Size:
			// Outside the legal range this would let a peer either fragment
			// pathologically or announce frames we refuse to buffer.
			if value < H2_DEFAULT_MAX_FRAME_SIZE || value > H2_MAX_ALLOWED_FRAME_SIZE {
				return .Protocol_Error
			}
			s.max_frame_size = value
		case .Max_Header_List_Size:
			s.max_header_list_size = value
		case:
			// Unknown setting: ignore.
		}
	}
	return .No_Error
}

// Encodes a SETTINGS frame carrying the given entries.
h2_settings_encode :: proc(out: ^[dynamic]byte, entries: []struct{id: H2_Setting_Id, value: u32}) {
	payload := make([dynamic]byte, 0, len(entries) * 6, context.temp_allocator)
	for e in entries {
		append(&payload, u8(u16(e.id) >> 8), u8(u16(e.id)))
		h2_write_u32(&payload, e.value)
	}
	h2_frame_encode(out, .Settings, 0, 0, payload[:])
}

// Encodes an empty SETTINGS frame with ACK set, acknowledging the peer's.
h2_settings_ack :: proc(out: ^[dynamic]byte) {
	h2_frame_encode(out, .Settings, H2_FLAG_ACK, 0, nil)
}

// --- WINDOW_UPDATE (RFC 9113 6.9) ---

/*
Decodes a window increment.

A zero increment is a protocol error: it conveys nothing and is used to probe
implementations that fail to check.
*/
h2_window_update_decode :: proc(payload: []byte) -> (increment: u32, err: H2_Error) {
	if len(payload) != 4 { return 0, .Frame_Size_Error }

	increment = h2_read_u32(payload) & 0x7fff_ffff
	if increment == 0 { return 0, .Protocol_Error }
	return increment, .No_Error
}

h2_window_update_encode :: proc(out: ^[dynamic]byte, stream_id: u32, increment: u32) {
	payload: [4]byte
	inc := increment & 0x7fff_ffff
	payload = {u8(inc >> 24), u8(inc >> 16), u8(inc >> 8), u8(inc)}
	h2_frame_encode(out, .Window_Update, 0, stream_id, payload[:])
}

// --- RST_STREAM (RFC 9113 6.4) ---

h2_rst_stream_decode :: proc(payload: []byte) -> (code: H2_Error, err: H2_Error) {
	if len(payload) != 4 { return .No_Error, .Frame_Size_Error }
	return H2_Error(h2_read_u32(payload)), .No_Error
}

h2_rst_stream_encode :: proc(out: ^[dynamic]byte, stream_id: u32, code: H2_Error) {
	payload := make([dynamic]byte, 0, 4, context.temp_allocator)
	h2_write_u32(&payload, u32(code))
	h2_frame_encode(out, .Rst_Stream, 0, stream_id, payload[:])
}

// --- GOAWAY (RFC 9113 6.8) ---

H2_Goaway :: struct {
	last_stream_id: u32,
	code:           H2_Error,
	debug:          []byte,
}

h2_goaway_decode :: proc(payload: []byte) -> (g: H2_Goaway, err: H2_Error) {
	if len(payload) < 8 { return {}, .Frame_Size_Error }

	g.last_stream_id = h2_read_u32(payload) & 0x7fff_ffff
	g.code           = H2_Error(h2_read_u32(payload[4:]))
	g.debug          = payload[8:]
	return g, .No_Error
}

/*
Encodes GOAWAY.

`last_stream_id` tells the peer which streams were processed, so it knows what
is safe to retry elsewhere. Sending 0 would claim nothing was handled.
*/
h2_goaway_encode :: proc(out: ^[dynamic]byte, last_stream_id: u32, code: H2_Error, debug := "") {
	payload := make([dynamic]byte, 0, 8 + len(debug), context.temp_allocator)
	h2_write_u32(&payload, last_stream_id & 0x7fff_ffff)
	h2_write_u32(&payload, u32(code))
	append(&payload, ..transmute([]byte)debug)
	h2_frame_encode(out, .Goaway, 0, 0, payload[:])
}

// --- PING (RFC 9113 6.7) ---

/*
Encodes a PING acknowledgement.

The 8 opaque octets must be echoed exactly; they are the peer's round-trip
correlator, not data we may interpret.
*/
h2_ping_ack :: proc(out: ^[dynamic]byte, opaque: []byte) -> H2_Error {
	if len(opaque) != 8 { return .Frame_Size_Error }
	h2_frame_encode(out, .Ping, H2_FLAG_ACK, 0, opaque)
	return .No_Error
}
