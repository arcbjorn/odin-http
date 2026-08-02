package http

/*
The HPACK Huffman code (RFC 7541 Appendix B).

Canonical and prefix-free: verified by sorting the table by (length, code) and
confirming no code is a prefix of the next, and that the Kraft sum is exactly
1.0. Both properties fail loudly on a single transcription error, which matters
because a wrong entry here would corrupt header values in ways that look like
application bugs.

Decoding walks bit by bit rather than using a multi-level lookup table. That is
slower per byte, but headers are small and correctness here is worth more than
throughput; a table-driven decoder can replace this without changing the API.
*/

@(private)
Huffman_Code :: struct {
	code: u32,
	bits: u8,
}

// Index 256 is EOS, which must never appear in a decoded string.
@(private)
HUFFMAN_EOS :: 256

@(private, rodata)
huffman_table := [257]Huffman_Code{
	{0x00001ff8, 13}, {0x007fffd8, 23}, {0x0fffffe2, 28}, {0x0fffffe3, 28},
	{0x0fffffe4, 28}, {0x0fffffe5, 28}, {0x0fffffe6, 28}, {0x0fffffe7, 28},
	{0x0fffffe8, 28}, {0x00ffffea, 24}, {0x3ffffffc, 30}, {0x0fffffe9, 28},
	{0x0fffffea, 28}, {0x3ffffffd, 30}, {0x0fffffeb, 28}, {0x0fffffec, 28},
	{0x0fffffed, 28}, {0x0fffffee, 28}, {0x0fffffef, 28}, {0x0ffffff0, 28},
	{0x0ffffff1, 28}, {0x0ffffff2, 28}, {0x3ffffffe, 30}, {0x0ffffff3, 28},
	{0x0ffffff4, 28}, {0x0ffffff5, 28}, {0x0ffffff6, 28}, {0x0ffffff7, 28},
	{0x0ffffff8, 28}, {0x0ffffff9, 28}, {0x0ffffffa, 28}, {0x0ffffffb, 28},
	{0x00000014,  6}, {0x000003f8, 10}, {0x000003f9, 10}, {0x00000ffa, 12},
	{0x00001ff9, 13}, {0x00000015,  6}, {0x000000f8,  8}, {0x000007fa, 11},
	{0x000003fa, 10}, {0x000003fb, 10}, {0x000000f9,  8}, {0x000007fb, 11},
	{0x000000fa,  8}, {0x00000016,  6}, {0x00000017,  6}, {0x00000018,  6},
	{0x00000000,  5}, {0x00000001,  5}, {0x00000002,  5}, {0x00000019,  6},
	{0x0000001a,  6}, {0x0000001b,  6}, {0x0000001c,  6}, {0x0000001d,  6},
	{0x0000001e,  6}, {0x0000001f,  6}, {0x0000005c,  7}, {0x000000fb,  8},
	{0x00007ffc, 15}, {0x00000020,  6}, {0x00000ffb, 12}, {0x000003fc, 10},
	{0x00001ffa, 13}, {0x00000021,  6}, {0x0000005d,  7}, {0x0000005e,  7},
	{0x0000005f,  7}, {0x00000060,  7}, {0x00000061,  7}, {0x00000062,  7},
	{0x00000063,  7}, {0x00000064,  7}, {0x00000065,  7}, {0x00000066,  7},
	{0x00000067,  7}, {0x00000068,  7}, {0x00000069,  7}, {0x0000006a,  7},
	{0x0000006b,  7}, {0x0000006c,  7}, {0x0000006d,  7}, {0x0000006e,  7},
	{0x0000006f,  7}, {0x00000070,  7}, {0x00000071,  7}, {0x00000072,  7},
	{0x000000fc,  8}, {0x00000073,  7}, {0x000000fd,  8}, {0x00001ffb, 13},
	{0x0007fff0, 19}, {0x00001ffc, 13}, {0x00003ffc, 14}, {0x00000022,  6},
	{0x00007ffd, 15}, {0x00000003,  5}, {0x00000023,  6}, {0x00000004,  5},
	{0x00000024,  6}, {0x00000005,  5}, {0x00000025,  6}, {0x00000026,  6},
	{0x00000027,  6}, {0x00000006,  5}, {0x00000074,  7}, {0x00000075,  7},
	{0x00000028,  6}, {0x00000029,  6}, {0x0000002a,  6}, {0x00000007,  5},
	{0x0000002b,  6}, {0x00000076,  7}, {0x0000002c,  6}, {0x00000008,  5},
	{0x00000009,  5}, {0x0000002d,  6}, {0x00000077,  7}, {0x00000078,  7},
	{0x00000079,  7}, {0x0000007a,  7}, {0x0000007b,  7}, {0x00007ffe, 15},
	{0x000007fc, 11}, {0x00003ffd, 14}, {0x00001ffd, 13}, {0x0ffffffc, 28},
	{0x000fffe6, 20}, {0x003fffd2, 22}, {0x000fffe7, 20}, {0x000fffe8, 20},
	{0x003fffd3, 22}, {0x003fffd4, 22}, {0x003fffd5, 22}, {0x007fffd9, 23},
	{0x003fffd6, 22}, {0x007fffda, 23}, {0x007fffdb, 23}, {0x007fffdc, 23},
	{0x007fffdd, 23}, {0x007fffde, 23}, {0x00ffffeb, 24}, {0x007fffdf, 23},
	{0x00ffffec, 24}, {0x00ffffed, 24}, {0x003fffd7, 22}, {0x007fffe0, 23},
	{0x00ffffee, 24}, {0x007fffe1, 23}, {0x007fffe2, 23}, {0x007fffe3, 23},
	{0x007fffe4, 23}, {0x001fffdc, 21}, {0x003fffd8, 22}, {0x007fffe5, 23},
	{0x003fffd9, 22}, {0x007fffe6, 23}, {0x007fffe7, 23}, {0x00ffffef, 24},
	{0x003fffda, 22}, {0x001fffdd, 21}, {0x000fffe9, 20}, {0x003fffdb, 22},
	{0x003fffdc, 22}, {0x007fffe8, 23}, {0x007fffe9, 23}, {0x001fffde, 21},
	{0x007fffea, 23}, {0x003fffdd, 22}, {0x003fffde, 22}, {0x00fffff0, 24},
	{0x001fffdf, 21}, {0x003fffdf, 22}, {0x007fffeb, 23}, {0x007fffec, 23},
	{0x001fffe0, 21}, {0x001fffe1, 21}, {0x003fffe0, 22}, {0x001fffe2, 21},
	{0x007fffed, 23}, {0x003fffe1, 22}, {0x007fffee, 23}, {0x007fffef, 23},
	{0x000fffea, 20}, {0x003fffe2, 22}, {0x003fffe3, 22}, {0x003fffe4, 22},
	{0x007ffff0, 23}, {0x003fffe5, 22}, {0x003fffe6, 22}, {0x007ffff1, 23},
	{0x03ffffe0, 26}, {0x03ffffe1, 26}, {0x000fffeb, 20}, {0x0007fff1, 19},
	{0x003fffe7, 22}, {0x007ffff2, 23}, {0x003fffe8, 22}, {0x01ffffec, 25},
	{0x03ffffe2, 26}, {0x03ffffe3, 26}, {0x03ffffe4, 26}, {0x07ffffde, 27},
	{0x07ffffdf, 27}, {0x03ffffe5, 26}, {0x00fffff1, 24}, {0x01ffffed, 25},
	{0x0007fff2, 19}, {0x001fffe3, 21}, {0x03ffffe6, 26}, {0x07ffffe0, 27},
	{0x07ffffe1, 27}, {0x03ffffe7, 26}, {0x07ffffe2, 27}, {0x00fffff2, 24},
	{0x001fffe4, 21}, {0x001fffe5, 21}, {0x03ffffe8, 26}, {0x03ffffe9, 26},
	{0x0ffffffd, 28}, {0x07ffffe3, 27}, {0x07ffffe4, 27}, {0x07ffffe5, 27},
	{0x000fffec, 20}, {0x00fffff3, 24}, {0x000fffed, 20}, {0x001fffe6, 21},
	{0x003fffe9, 22}, {0x001fffe7, 21}, {0x001fffe8, 21}, {0x007ffff3, 23},
	{0x003fffea, 22}, {0x003fffeb, 22}, {0x01ffffee, 25}, {0x01ffffef, 25},
	{0x00fffff4, 24}, {0x00fffff5, 24}, {0x03ffffea, 26}, {0x007ffff4, 23},
	{0x03ffffeb, 26}, {0x07ffffe6, 27}, {0x03ffffec, 26}, {0x03ffffed, 26},
	{0x07ffffe7, 27}, {0x07ffffe8, 27}, {0x07ffffe9, 27}, {0x07ffffea, 27},
	{0x07ffffeb, 27}, {0x0ffffffe, 28}, {0x07ffffec, 27}, {0x07ffffed, 27},
	{0x07ffffee, 27}, {0x07ffffef, 27}, {0x07fffff0, 27}, {0x03ffffee, 26},
	{0x3fffffff, 30},
}

/*
Decodes a Huffman-coded string.

Walks the input bit by bit, matching against the code table. Three conditions
are rejected rather than tolerated, because each is a way to smuggle a value
past a peer that decodes more leniently:

  - A code that decodes to EOS. RFC 7541 5.2 makes this a compression error.
  - More than 7 bits of trailing padding, which means a whole code was dropped.
  - Padding that is not all ones, which is not the padding the RFC specifies.
*/
hpack_huffman_decode :: proc(
	data: []byte,
	max_len: int,
	allocator := context.temp_allocator,
) -> (s: string, err: Hpack_Error) {
	// The shortest code is 5 bits, so output is at most 8/5 of the input. The
	// caller's limit still applies: a bounded ratio of an unbounded input is
	// not a bound.
	out := make([dynamic]byte, 0, (len(data) * 8) / 5 + 1, allocator)

	code: u32
	bits: u8

	for octet in data {
		for shift := 7; shift >= 0; shift -= 1 {
			code = code << 1 | u32(octet >> uint(shift) & 1)
			bits += 1

			// A code longer than the table's maximum cannot match anything.
			if bits > 30 { return "", .Invalid_Huffman }

			symbol, found := huffman_lookup(code, bits)
			if !found { continue }

			if symbol == HUFFMAN_EOS { return "", .Invalid_Huffman }

			if len(out) >= max_len { return "", .Too_Long }
			append(&out, u8(symbol))

			code = 0
			bits = 0
		}
	}

	// Whatever is left must be padding: fewer than 8 bits, all ones.
	if bits > 7 { return "", .Invalid_Huffman }
	if bits > 0 {
		expected := u32(1 << bits) - 1
		if code != expected { return "", .Invalid_Huffman }
	}

	return string(out[:]), .None
}

/*
Finds the symbol for a code of the given bit length.

Linear over the table, which is 257 entries; a code is resolved at most once per
output byte, so this is bounded by the decoded length rather than the input.
*/
@(private)
huffman_lookup :: proc(code: u32, bits: u8) -> (symbol: int, found: bool) {
	for entry, i in huffman_table {
		if entry.bits == bits && entry.code == code {
			return i, true
		}
	}
	return 0, false
}
