package http

/*
HPACK primitives: integer and string coding (RFC 7541 sections 5.1 and 5.2).

These are the two encodings every header field is built from, and both are
attacker-controlled on every request, so both are written to fail closed:

  - Integers use a continuation encoding with no inherent bound. A peer can send
    an arbitrarily long run of continuation octets, so decoding stops at a
    length no legitimate value needs.
  - Huffman strings expand on decode. The ratio is bounded (the shortest code is
    5 bits, so at most 8/5), but the caller still supplies the limit, because
    "smaller than 1.6x of a huge input" is not a useful bound.

Like the frame layer, this is sans-I/O: it decodes from a slice and encodes into
a buffer, so it is testable against the RFC's published vectors directly.
*/

Hpack_Error :: enum u8 {
	None,
	// The buffer ends mid-value.
	Truncated,
	// A continuation run longer than any real value needs.
	Integer_Overflow,
	// A Huffman code that is not in the table, or padding that is not all ones.
	Invalid_Huffman,
	// A decoded string longer than the caller allows.
	Too_Long,
	// An index outside the static and dynamic tables.
	Invalid_Index,
}

/*
Decodes an HPACK variable-length integer.

`prefix_bits` is how many bits of the first octet belong to the value; the
higher bits carry flags identifying the field type. When those bits are all set
the value continues in following octets, seven bits at a time.

Bounded at ten continuation octets: 7 bits each already exceeds any value this
implementation can use, and without a bound a peer could stream continuations
indefinitely.
*/
hpack_decode_integer :: proc(data: []byte, prefix_bits: uint) -> (value: u64, consumed: int, err: Hpack_Error) {
	if len(data) == 0 { return 0, 0, .Truncated }

	prefix_max := u64(1 << prefix_bits) - 1
	value = u64(data[0]) & prefix_max

	// A value below the prefix maximum is complete in the first octet.
	if value < prefix_max {
		return value, 1, .None
	}

	shift := uint(0)
	i := 1
	for {
		if i >= len(data) { return 0, 0, .Truncated }
		// 7 bits per octet: 10 octets is 70 bits, already past u64.
		if i > 10 { return 0, 0, .Integer_Overflow }

		octet := data[i]
		i += 1

		add := u64(octet & 0x7f) << shift
		// Detect wraparound rather than silently accepting a folded value.
		if add >> shift != u64(octet & 0x7f) { return 0, 0, .Integer_Overflow }

		new_value := value + add
		if new_value < value { return 0, 0, .Integer_Overflow }
		value = new_value

		if octet & 0x80 == 0 { break }
		shift += 7
	}

	return value, i, .None
}

/*
Encodes an HPACK variable-length integer.

`flags` supplies the bits above the prefix, so the caller writes the field type
and the value in one call and they cannot disagree.
*/
hpack_encode_integer :: proc(out: ^[dynamic]byte, value: u64, prefix_bits: uint, flags: u8) {
	prefix_max := u64(1 << prefix_bits) - 1

	if value < prefix_max {
		append(out, flags | u8(value))
		return
	}

	append(out, flags | u8(prefix_max))

	remainder := value - prefix_max
	for remainder >= 0x80 {
		append(out, u8(remainder & 0x7f) | 0x80)
		remainder >>= 7
	}
	append(out, u8(remainder))
}

/*
Decodes a length-prefixed string, Huffman-coded or literal.

The high bit of the length octet selects the encoding. A literal string borrows
from `data`; a Huffman string must be decoded into `allocator`, since the output
does not exist in the input.

`max_len` bounds the decoded length. Huffman expands, so the limit has to apply
after decoding, not to the wire length.
*/
hpack_decode_string :: proc(
	data: []byte,
	max_len: int,
	allocator := context.temp_allocator,
) -> (s: string, consumed: int, err: Hpack_Error) {
	if len(data) == 0 { return "", 0, .Truncated }

	huffman := data[0] & 0x80 != 0

	length, n := hpack_decode_integer(data, 7) or_return
	if length > u64(max_len) { return "", 0, .Too_Long }

	end := n + int(length)
	if end > len(data) { return "", 0, .Truncated }

	raw := data[n:end]

	if !huffman {
		// Borrowed from the caller's buffer, like the HTTP/1.1 parser's fields.
		return string(raw), end, .None
	}

	decoded := hpack_huffman_decode(raw, max_len, allocator) or_return
	return decoded, end, .None
}

/*
Encodes a string without Huffman coding.

Literal encoding is always legal (RFC 7541 5.2) and costs bytes, not
correctness. A Huffman encoder needs the full code table and buys perhaps 20% on
headers that are already small; the decoder must handle Huffman regardless,
because peers send it, but the encoder does not have to produce it.
*/
hpack_encode_string :: proc(out: ^[dynamic]byte, s: string) {
	hpack_encode_integer(out, u64(len(s)), 7, 0)
	append(out, ..transmute([]byte)s)
}
