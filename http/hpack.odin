package http

import "core:mem"
import "core:strings"

/*
HPACK header compression (RFC 7541).

Fields are addressed by index into the 61-entry static table followed by a
dynamic table the peer mutates as it sends. That makes HPACK stateful: decoding
request N depends on every previous request, so a decoder that drifts from the
encoder corrupts every subsequent header block rather than just one.

The same statefulness is the attack surface, so the table size, header count and
every decoded string are bounded.
*/

/*
The static table (RFC 7541 Appendix A).

Index 0 is unused: HPACK indices are 1-based, and an index of 0 is a decoding
error rather than a reference to the first entry.
*/
@(private, rodata)
hpack_static_table := [62]Header_Entry{
	{},
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""},
}

@(private)
HPACK_STATIC_COUNT :: 61

/*
Per-entry overhead in the dynamic table's size accounting (RFC 7541 4.1).

The 32 octets are notional: they model the memory a real implementation spends
on pointers and lengths, so that a peer sending many tiny headers is charged for
them rather than filling the table for free.
*/
@(private)
HPACK_ENTRY_OVERHEAD :: 32

/*
An HPACK decoder, one per direction per connection.

Holds the dynamic table, which must track the peer's exactly. `strings.clone`
is used for every stored entry because the table outlives the header block it
came from — unlike the HTTP/1.1 parser, borrowing is not an option here.
*/
Hpack_Decoder :: struct {
	// Newest first, which makes index arithmetic direct: dynamic index 1 is the
	// most recent entry (RFC 7541 2.3.3).
	entries:    [dynamic]Header_Entry,
	size:       int,
	// Current limit, which the peer may lower with a dynamic table size update.
	max_size:   int,
	// Ceiling on what the peer may raise `max_size` to, from our own
	// SETTINGS_HEADER_TABLE_SIZE. A peer that ignores it is in error.
	hard_limit: int,
	allocator:  mem.Allocator,
}

hpack_decoder_init :: proc(d: ^Hpack_Decoder, max_size := 4096, allocator := context.allocator) {
	d.allocator  = allocator
	d.entries.allocator = allocator
	d.max_size   = max_size
	d.hard_limit = max_size
}

hpack_decoder_destroy :: proc(d: ^Hpack_Decoder) {
	for e in d.entries {
		delete(e.name, d.allocator)
		delete(e.value, d.allocator)
	}
	delete(d.entries)
	d.entries = nil
	d.size = 0
}

/*
Looks up an index across the static and dynamic tables.

Indices 1..61 are static; anything above indexes the dynamic table newest-first.
An index of 0, or past the end, is a decoding error — silently returning an
empty header would let a peer inject a field this side never validated.
*/
@(private)
hpack_lookup :: proc(d: ^Hpack_Decoder, index: u64) -> (entry: Header_Entry, err: Hpack_Error) {
	if index == 0 { return {}, .Invalid_Index }

	if index <= HPACK_STATIC_COUNT {
		return hpack_static_table[index], .None
	}

	dyn := int(index) - HPACK_STATIC_COUNT - 1
	if dyn >= len(d.entries) { return {}, .Invalid_Index }
	return d.entries[dyn], .None
}

/*
Inserts an entry at the front of the dynamic table, evicting to fit.

An entry larger than the whole table is not an error: RFC 7541 4.4 says the
table is emptied and the entry is simply not stored. Treating that as a failure
would break peers that legitimately send a large header.
*/
@(private)
hpack_insert :: proc(d: ^Hpack_Decoder, name: string, value: string) {
	entry_size := len(name) + len(value) + HPACK_ENTRY_OVERHEAD

	// Evict from the oldest end until the new entry fits.
	for d.size + entry_size > d.max_size && len(d.entries) > 0 {
		last := d.entries[len(d.entries) - 1]
		d.size -= len(last.name) + len(last.value) + HPACK_ENTRY_OVERHEAD
		delete(last.name, d.allocator)
		delete(last.value, d.allocator)
		pop(&d.entries)
	}

	if entry_size > d.max_size {
		// Table is now empty and the entry is dropped, as the RFC requires.
		return
	}

	// Cloned because the dynamic table outlives the block these came from.
	stored := Header_Entry{
		name  = strings.clone(name, d.allocator),
		value = strings.clone(value, d.allocator),
	}

	inject_at(&d.entries, 0, stored)
	d.size += entry_size
}

/*
Applies a dynamic table size update (RFC 7541 6.3).

A peer raising the size above what we advertised is a compression error, not
something to clamp: honouring it would let a peer force unbounded memory by
lying about a value it was told.
*/
@(private)
hpack_set_max_size :: proc(d: ^Hpack_Decoder, new_size: int) -> Hpack_Error {
	if new_size > d.hard_limit { return .Invalid_Index }

	d.max_size = new_size
	for d.size > d.max_size && len(d.entries) > 0 {
		last := d.entries[len(d.entries) - 1]
		d.size -= len(last.name) + len(last.value) + HPACK_ENTRY_OVERHEAD
		delete(last.name, d.allocator)
		delete(last.value, d.allocator)
		pop(&d.entries)
	}
	return .None
}

/*
Limits applied to one decoded header block.

`max_header_list_size` mirrors the h2 setting: without it a peer can send a
small compressed block that expands into an enormous header list, which is the
HPACK bomb.
*/
Hpack_Limits :: struct {
	max_header_count:     int,
	max_string_len:       int,
	max_header_list_size: int,
}

HPACK_DEFAULT_LIMITS :: Hpack_Limits {
	max_header_count     = 100,
	max_string_len       = 8192,
	max_header_list_size = 64 * 1024,
}

/*
Decodes a complete header block into `headers`.

Every field is appended in order, which matters: HPACK preserves ordering, and
pseudo-header ordering is itself validated by the caller.

The block must be complete. A HEADERS frame followed by CONTINUATION frames is
reassembled by the connection layer before reaching here, because a header block
cannot be decoded incrementally without the decoder and encoder drifting.
*/
hpack_decode :: proc(
	d: ^Hpack_Decoder,
	block: []byte,
	headers: ^Headers,
	limits := HPACK_DEFAULT_LIMITS,
) -> Hpack_Error {
	pos := 0
	count := 0
	list_size := 0

	for pos < len(block) {
		b := block[pos]

		switch {
		// 1xxxxxxx: indexed header field, name and value both from the table.
		case b & 0x80 != 0:
			index, n := hpack_decode_integer(block[pos:], 7) or_return
			pos += n

			entry := hpack_lookup(d, index) or_return
			count += 1
			list_size += len(entry.name) + len(entry.value) + HPACK_ENTRY_OVERHEAD
			if count > limits.max_header_count            { return .Too_Long }
			if list_size > limits.max_header_list_size    { return .Too_Long }

			headers_set_parsed(headers, entry.name, entry.value)

		// 01xxxxxx: literal with incremental indexing — adds to the table.
		case b & 0xc0 == 0x40:
			name, value, n := hpack_decode_literal(d, block[pos:], 6, limits, headers.allocator) or_return
			pos += n

			count += 1
			list_size += len(name) + len(value) + HPACK_ENTRY_OVERHEAD
			if count > limits.max_header_count         { return .Too_Long }
			if list_size > limits.max_header_list_size { return .Too_Long }

			hpack_insert(d, name, value)
			headers_set_parsed(headers, name, value)

		// 001xxxxx: dynamic table size update.
		case b & 0xe0 == 0x20:
			size, n := hpack_decode_integer(block[pos:], 5) or_return
			pos += n
			hpack_set_max_size(d, int(size)) or_return

		// 0000xxxx never-indexed, 0001xxxx without indexing: neither is stored.
		case:
			name, value, n := hpack_decode_literal(d, block[pos:], 4, limits, headers.allocator) or_return
			pos += n

			count += 1
			list_size += len(name) + len(value) + HPACK_ENTRY_OVERHEAD
			if count > limits.max_header_count         { return .Too_Long }
			if list_size > limits.max_header_list_size { return .Too_Long }

			headers_set_parsed(headers, name, value)
		}
	}

	return .None
}

/*
Decodes a literal field, whose name is either an index or an inline string.

Returned strings may borrow from `block` (a non-Huffman literal) or be freshly
allocated (Huffman). Huffman output goes into `block_allocator`, which belongs to
the header block being decoded, NOT to the decoder: the decoder's allocator lives
as long as the connection, so decoding into it would accumulate one copy of every
Huffman-coded literal ever received. `hpack_insert` clones what the dynamic table
keeps, so the two lifetimes stay separate.
*/
@(private)
hpack_decode_literal :: proc(
	d: ^Hpack_Decoder,
	data: []byte,
	prefix_bits: uint,
	limits: Hpack_Limits,
	block_allocator: mem.Allocator,
) -> (name: string, value: string, consumed: int, err: Hpack_Error) {
	index, n := hpack_decode_integer(data, prefix_bits) or_return
	pos := n

	if index == 0 {
		// Name is a literal string rather than a table reference.
		name, n = hpack_decode_string(data[pos:], limits.max_string_len, block_allocator) or_return
		pos += n
	} else {
		entry := hpack_lookup(d, index) or_return
		name = entry.name
	}

	value, n = hpack_decode_string(data[pos:], limits.max_string_len, block_allocator) or_return
	pos += n

	return name, value, pos, .None
}

// --- Encoding ---

/*
Encodes a header field without indexing, using literal strings.

Literal-without-indexing is always legal and keeps the encoder stateless: with
no dynamic table on the send side there is nothing to drift out of sync with the
peer's decoder. The cost is bytes on the wire, not correctness, and it can be
replaced with an indexing encoder without changing callers.
*/
hpack_encode_field :: proc(out: ^[dynamic]byte, name: string, value: string) {
	// 0000xxxx with a zero index means "literal name follows".
	append(out, 0x00)
	hpack_encode_string(out, name)
	hpack_encode_string(out, value)
}

/*
Encodes a response status using the static table where possible.

The common statuses are single-byte indexed fields, which is most of what a
stateless encoder can win back.
*/
hpack_encode_status :: proc(out: ^[dynamic]byte, status: Status) {
	index: u64
	#partial switch status {
	case .OK:                    index = 8
	case .No_Content:            index = 9
	case .Partial_Content:       index = 10
	case .Not_Modified:          index = 11
	case .Bad_Request:           index = 12
	case .Not_Found:             index = 13
	case .Internal_Server_Error: index = 14
	}

	if index != 0 {
		hpack_encode_integer(out, index, 7, 0x80)
		return
	}

	// Otherwise a literal value against the :status name at static index 8.
	hpack_encode_integer(out, 8, 4, 0x00)

	buf: [8]byte
	n := 0
	code := int(status)
	for code > 0 {
		buf[n] = u8('0' + code % 10)
		code /= 10
		n += 1
	}
	digits: [8]byte
	for i in 0 ..< n {
		digits[i] = buf[n - 1 - i]
	}
	hpack_encode_string(out, string(digits[:n]))
}

// Number of entries currently in the dynamic table, for tests and diagnostics.
hpack_dynamic_count :: proc(d: ^Hpack_Decoder) -> int {
	return len(d.entries)
}

// Current dynamic table size in HPACK's accounting, including per-entry overhead.
hpack_dynamic_size :: proc(d: ^Hpack_Decoder) -> int {
	return d.size
}
