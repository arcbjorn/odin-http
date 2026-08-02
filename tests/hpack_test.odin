package tests

import "core:mem"
import "core:mem/virtual"
import "core:testing"

import http "../http"

/*
HPACK (RFC 7541).

The decode tests use the RFC's own worked examples from Appendix C, which are
published with exact hex and exact expected output. That matters more here than
anywhere else in this package: HPACK is stateful, so a decoder that drifts from
the encoder corrupts every later header block on the connection, and a
round-trip test against my own encoder would happily agree with a misreading.

The last test decodes a header block captured from curl, so nghttp2 is the
authority rather than my reading of the spec.
*/

// --- Integer coding (RFC 7541 5.1) ---

@(test)
test_hpack_integer_fits_in_prefix :: proc(t: ^testing.T) {
	// C.1.1: 10 encoded with a 5-bit prefix is a single octet.
	value, consumed, err := http.hpack_decode_integer([]byte{0x0a}, 5)

	testing.expect_value(t, err, http.Hpack_Error.None)
	testing.expect_value(t, value, u64(10))
	testing.expect_value(t, consumed, 1)
}

@(test)
test_hpack_integer_multi_octet :: proc(t: ^testing.T) {
	// C.1.2: 1337 with a 5-bit prefix is 31 + continuation octets.
	value, consumed, err := http.hpack_decode_integer([]byte{0x1f, 0x9a, 0x0a}, 5)

	testing.expect_value(t, err, http.Hpack_Error.None)
	testing.expect_value(t, value, u64(1337))
	testing.expect_value(t, consumed, 3)
}

@(test)
test_hpack_integer_ignores_prefix_flags :: proc(t: ^testing.T) {
	// The bits above the prefix carry the field type and must not leak into the
	// value: 0xea is 0b111_01010, so a 5-bit prefix reads 10.
	value, _, err := http.hpack_decode_integer([]byte{0xea}, 5)

	testing.expect_value(t, err, http.Hpack_Error.None)
	testing.expect_value(t, value, u64(10))
}

@(test)
test_hpack_integer_rejects_unbounded_continuation :: proc(t: ^testing.T) {
	// A peer can send continuation octets forever; the decoder must stop.
	runaway := make([]byte, 64, context.temp_allocator)
	runaway[0] = 0x1f
	for i in 1 ..< len(runaway) { runaway[i] = 0xff }

	_, _, err := http.hpack_decode_integer(runaway, 5)
	testing.expect_value(t, err, http.Hpack_Error.Integer_Overflow)
}

@(test)
test_hpack_integer_truncated :: proc(t: ^testing.T) {
	// Continuation bit set but the buffer ends.
	_, _, err := http.hpack_decode_integer([]byte{0x1f, 0x9a}, 5)
	testing.expect_value(t, err, http.Hpack_Error.Truncated)

	_, _, empty := http.hpack_decode_integer([]byte{}, 5)
	testing.expect_value(t, empty, http.Hpack_Error.Truncated)
}

@(test)
test_hpack_integer_round_trip :: proc(t: ^testing.T) {
	for value in ([]u64{0, 1, 30, 31, 32, 127, 128, 1337, 65_535, 1 << 30}) {
		out := make([dynamic]byte, 0, 16, context.temp_allocator)
		http.hpack_encode_integer(&out, value, 5, 0xe0)

		got, _, err := http.hpack_decode_integer(out[:], 5)
		testing.expectf(t, err == .None, "encoding %d failed to decode: %v", value, err)
		testing.expectf(t, got == value, "round trip changed %d into %d", value, got)
	}
}

// --- Huffman (RFC 7541 Appendix B, examples from C.4 and C.6) ---

@(test)
test_hpack_huffman_decodes_rfc_example :: proc(t: ^testing.T) {
	// C.4.1: "www.example.com" Huffman-coded.
	wire := []byte{
		0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0,
		0xab, 0x90, 0xf4, 0xff,
	}

	s, err := http.hpack_huffman_decode(wire, 256, context.temp_allocator)

	testing.expect_value(t, err, http.Hpack_Error.None)
	testing.expect_value(t, s, "www.example.com")
}

@(test)
test_hpack_huffman_decodes_status_phrase :: proc(t: ^testing.T) {
	// C.6.1: the Date value "Mon, 21 Oct 2013 20:13:21 GMT".
	wire := []byte{
		0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44,
		0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81, 0x66,
		0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff,
	}

	s, err := http.hpack_huffman_decode(wire, 256, context.temp_allocator)

	testing.expect_value(t, err, http.Hpack_Error.None)
	testing.expect_value(t, s, "Mon, 21 Oct 2013 20:13:21 GMT")
}

@(test)
test_hpack_huffman_rejects_bad_padding :: proc(t: ^testing.T) {
	// Padding must be the most significant bits of the EOS code, i.e. all ones.
	// Anything else means the encoder and decoder disagree about the boundary.
	wire := []byte{0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0x00}

	_, err := http.hpack_huffman_decode(wire, 256, context.temp_allocator)
	testing.expect_value(t, err, http.Hpack_Error.Invalid_Huffman)
}

@(test)
test_hpack_huffman_respects_max_len :: proc(t: ^testing.T) {
	// Huffman expands, so the limit must apply to the decoded length rather
	// than the wire length.
	wire := []byte{0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff}

	_, err := http.hpack_huffman_decode(wire, 4, context.temp_allocator)
	testing.expect_value(t, err, http.Hpack_Error.Too_Long)
}

// --- Header blocks ---

@(test)
test_hpack_decodes_indexed_field :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	d: http.Hpack_Decoder
	http.hpack_decoder_init(&d)
	defer http.hpack_decoder_destroy(&d)

	h: http.Headers
	http.headers_init(&h, test_alloc(&arena))

	// 0x82 is indexed field 2, which is ":method: GET" in the static table.
	err := http.hpack_decode(&d, []byte{0x82}, &h)

	testing.expect_value(t, err, http.Hpack_Error.None)
	method, ok := http.headers_get(h, ":method")
	testing.expect(t, ok, ":method should be present")
	testing.expect_value(t, method, "GET")
}

@(test)
test_hpack_decodes_rfc_literal_with_indexing :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	d: http.Hpack_Decoder
	http.hpack_decoder_init(&d)
	defer http.hpack_decoder_destroy(&d)

	h: http.Headers
	http.headers_init(&h, test_alloc(&arena))

	// C.2.1: literal header field with incremental indexing, custom name.
	//   "custom-key: custom-header"
	wire := []byte{
		0x40,
		0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y',
		0x0d, 'c', 'u', 's', 't', 'o', 'm', '-', 'h', 'e', 'a', 'd', 'e', 'r',
	}

	err := http.hpack_decode(&d, wire, &h)

	testing.expect_value(t, err, http.Hpack_Error.None)
	v, ok := http.headers_get(h, "custom-key")
	testing.expect(t, ok, "custom-key should be present")
	testing.expect_value(t, v, "custom-header")

	// Incremental indexing means it is now addressable as dynamic index 62.
	testing.expect_value(t, http.hpack_dynamic_count(&d), 1)
}

@(test)
test_hpack_decodes_rfc_request_sequence :: proc(t: ^testing.T) {
	// C.3: three requests on one connection, where later blocks depend on the
	// dynamic table built by earlier ones. This is the property that makes
	// HPACK stateful, and the one a single-block test cannot check.
	arena := test_arena()
	defer test_arena_destroy(&arena)

	d: http.Hpack_Decoder
	http.hpack_decoder_init(&d)
	defer http.hpack_decoder_destroy(&d)

	// C.3.1: :method GET, :scheme http, :path /, :authority www.example.com
	{
		h: http.Headers
		http.headers_init(&h, test_alloc(&arena))
		wire := []byte{
			0x82, 0x86, 0x84, 0x41, 0x0f, 'w', 'w', 'w', '.', 'e', 'x',
			'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		}
		err := http.hpack_decode(&d, wire, &h)
		testing.expect_value(t, err, http.Hpack_Error.None)

		m, _ := http.headers_get(h, ":method")
		p, _ := http.headers_get(h, ":path")
		a, _ := http.headers_get(h, ":authority")
		testing.expect_value(t, m, "GET")
		testing.expect_value(t, p, "/")
		testing.expect_value(t, a, "www.example.com")
	}

	// C.3.2: the same fields, but :authority now comes from the dynamic table
	// (index 62), plus a new cache-control entry.
	{
		h: http.Headers
		http.headers_init(&h, test_alloc(&arena))
		wire := []byte{
			0x82, 0x86, 0x84, 0xbe,
			0x58, 0x08, 'n', 'o', '-', 'c', 'a', 'c', 'h', 'e',
		}
		err := http.hpack_decode(&d, wire, &h)
		testing.expect_value(t, err, http.Hpack_Error.None)

		a, ok := http.headers_get(h, ":authority")
		testing.expect(t, ok, ":authority must resolve from the dynamic table")
		testing.expect_value(t, a, "www.example.com")

		cc, _ := http.headers_get(h, "cache-control")
		testing.expect_value(t, cc, "no-cache")
	}
}

@(test)
test_hpack_rejects_invalid_index :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	d: http.Hpack_Decoder
	http.hpack_decoder_init(&d)
	defer http.hpack_decoder_destroy(&d)

	h: http.Headers
	http.headers_init(&h, test_alloc(&arena))

	// Index 0 is not a reference to the first entry; it is an error.
	err := http.hpack_decode(&d, []byte{0x80}, &h)
	testing.expect_value(t, err, http.Hpack_Error.Invalid_Index)

	// An index past the end of both tables.
	h2: http.Headers
	http.headers_init(&h2, test_alloc(&arena))
	past := http.hpack_decode(&d, []byte{0xff, 0x00}, &h2)
	testing.expect_value(t, past, http.Hpack_Error.Invalid_Index)
}

@(test)
test_hpack_evicts_to_stay_within_size :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	d: http.Hpack_Decoder
	// Room for roughly one small entry once the 32-octet overhead is counted.
	http.hpack_decoder_init(&d, 64)
	defer http.hpack_decoder_destroy(&d)

	for i in 0 ..< 5 {
		h: http.Headers
		http.headers_init(&h, test_alloc(&arena))
		wire := []byte{
			0x40,
			0x03, 'a', 'a', u8('0' + i),
			0x03, 'v', 'v', u8('0' + i),
		}
		err := http.hpack_decode(&d, wire, &h)
		testing.expect_value(t, err, http.Hpack_Error.None)
	}

	// The table must have evicted rather than grown without bound.
	testing.expect(t, http.hpack_dynamic_size(&d) <= 64,
		"dynamic table exceeded its configured size")
}

@(test)
test_hpack_rejects_oversized_table_update :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	d: http.Hpack_Decoder
	http.hpack_decoder_init(&d, 4096)
	defer http.hpack_decoder_destroy(&d)

	h: http.Headers
	http.headers_init(&h, test_alloc(&arena))

	// 001xxxxx carrying 8192, twice what we advertised. Honouring it would let
	// a peer force unbounded memory by ignoring the limit it was given.
	err := http.hpack_decode(&d, []byte{0x3f, 0xe1, 0x3f}, &h)
	testing.expect_value(t, err, http.Hpack_Error.Invalid_Index)
}

@(test)
test_hpack_bounds_header_count :: proc(t: ^testing.T) {
	arena := test_arena()
	defer test_arena_destroy(&arena)

	d: http.Hpack_Decoder
	http.hpack_decoder_init(&d)
	defer http.hpack_decoder_destroy(&d)

	h: http.Headers
	http.headers_init(&h, test_alloc(&arena))

	// A small compressed block that expands into a huge header list is the
	// HPACK bomb; repeating one indexed byte is the cheapest form of it.
	block := make([]byte, 500, context.temp_allocator)
	for i in 0 ..< len(block) { block[i] = 0x82 }

	limits := http.HPACK_DEFAULT_LIMITS
	limits.max_header_count = 100

	err := http.hpack_decode(&d, block, &h, limits)
	testing.expect_value(t, err, http.Hpack_Error.Too_Long)
}

// --- Interoperability ---

@(test)
test_hpack_decodes_real_curl_headers :: proc(t: ^testing.T) {
	// The HEADERS payload from the same `curl --http2-prior-knowledge` capture
	// used in the frame tests. nghttp2 produced these bytes, so this checks the
	// decoder against a real encoder rather than against my own.
	arena := test_arena()
	defer test_arena_destroy(&arena)

	d: http.Hpack_Decoder
	http.hpack_decoder_init(&d)
	defer http.hpack_decoder_destroy(&d)

	h: http.Headers
	http.headers_init(&h, test_alloc(&arena))

	block := []byte{
		0x82, 0x86, 0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70,
		0xdc, 0x78, 0x0f, 0x8b, 0x04, 0x84, 0x61, 0x25, 0x42, 0x7f,
		0x7a, 0x88, 0x25, 0xb6, 0x50, 0xc3, 0xcb, 0xb6, 0xb8, 0x3f,
		0x53, 0x03, 0x2a, 0x2f, 0x2a,
	}

	err := http.hpack_decode(&d, block, &h)
	testing.expect_value(t, err, http.Hpack_Error.None)

	method, has_method := http.headers_get(h, ":method")
	testing.expect(t, has_method, ":method must decode")
	testing.expect_value(t, method, "GET")

	scheme, _ := http.headers_get(h, ":scheme")
	testing.expect_value(t, scheme, "http")

	// Huffman-coded literals: the authority and path curl actually sent.
	authority, has_auth := http.headers_get(h, ":authority")
	testing.expect(t, has_auth, ":authority must decode")
	testing.expect_value(t, authority, "127.0.0.1:8092")

	path, _ := http.headers_get(h, ":path")
	testing.expect_value(t, path, "/test")
}

// --- Test helpers ---

@(private)
test_arena :: proc() -> virtual.Arena {
	a: virtual.Arena
	_ = virtual.arena_init_growing(&a)
	return a
}

@(private)
test_arena_destroy :: proc(a: ^virtual.Arena) {
	virtual.arena_destroy(a)
}

@(private)
test_alloc :: proc(a: ^virtual.Arena) -> mem.Allocator {
	return virtual.arena_allocator(a)
}
