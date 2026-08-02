package http

import "core:strings"
import "core:mem"

/*
A case-insensitive collection of header fields.

Fields are held in an append-ordered list with a map from lowercased name to
list index. Ordering matters on the wire (RFC 9110 5.3 preserves the order of
fields with the same name), and an ordered list also makes responses
byte-reproducible, which is what lets the tests assert on exact output.

Keys are stored lowercased. Header names arrive lowercase in the overwhelming
majority of real traffic, in which case no copy is made at all; a fold is only
materialized when one is actually needed.

Duplicate fields are joined with ", " per RFC 9110 5.3, which is semantically
equivalent to repeating the field. Set-Cookie is the documented exception and is
appended as a distinct entry, since joining it corrupts the values.
*/
Headers :: struct {
	entries:   [dynamic]Header_Entry,
	_index:    map[string]int,
	allocator: mem.Allocator,
	// Set once a request's headers are parsed, so handler code that tries to
	// mutate the request rather than the response fails loudly.
	readonly:  bool,
}

Header_Entry :: struct {
	name:  string,
	value: string,
}

headers_init :: proc(h: ^Headers, allocator: mem.Allocator) {
	h.allocator = allocator
	h.entries.allocator = allocator
	h._index.allocator = allocator
}

headers_count :: #force_inline proc(h: Headers) -> int {
	return len(h.entries)
}

/*
Looks up a header. `key` must already be lowercase.

This is the hot path: the parser and the response writer both know their keys
are lowercase literals, so folding on every lookup would be wasted work. Use
`headers_get_fold` when the key comes from user code.
*/
headers_get :: proc(h: Headers, key: string) -> (value: string, ok: bool) #optional_ok {
	idx, found := h._index[key]
	if !found { return "", false }
	return h.entries[idx].value, true
}

headers_has :: #force_inline proc(h: Headers, key: string) -> bool {
	return key in h._index
}

// Looks up a header, folding `key` to lowercase first.
headers_get_fold :: proc(h: Headers, key: string) -> (value: string, ok: bool) #optional_ok {
	buf: [64]byte
	folded, alloced := fold_key(key, buf[:], h.allocator)
	defer if alloced { delete(folded, h.allocator) }
	return headers_get(h, folded)
}

/*
Stores a header parsed off the wire.

Both `name` and `value` must point into memory that outlives the headers, which
for the server means the connection arena. Nothing is copied unless a fold or a
duplicate join forces it.
*/
@(private)
headers_set_parsed :: proc(h: ^Headers, name: string, value: string) {
	key := intern_key(h, name)

	// Set-Cookie must never be joined, so it bypasses the duplicate index.
	if key == "set-cookie" {
		append(&h.entries, Header_Entry{key, value})
		return
	}

	if idx, found := h._index[key]; found {
		e := &h.entries[idx]
		e.value = strings.concatenate({e.value, ", ", value}, h.allocator)
		return
	}

	h._index[key] = len(h.entries)
	append(&h.entries, Header_Entry{key, value})
}

/*
Sets a header from user code, replacing any existing value.

The name is validated and folded, and the value is checked for CR/LF. A handler
writing an attacker-controlled string into a header is the response-splitting
path, so this rejects rather than sanitizes: silently stripping the newline
would hide the bug at the call site that introduced it.
*/
headers_set :: proc(h: ^Headers, name: string, value: string, loc := #caller_location) -> bool {
	assert(!h.readonly, "these headers are readonly", loc)

	if !is_token(name)        { return false }
	if !is_field_value(value) { return false }

	key := intern_key(h, name)

	if key == "set-cookie" {
		append(&h.entries, Header_Entry{key, value})
		return true
	}

	if idx, found := h._index[key]; found {
		h.entries[idx].value = value
		return true
	}

	h._index[key] = len(h.entries)
	append(&h.entries, Header_Entry{key, value})
	return true
}

// Appends a header without replacing an existing field of the same name.
headers_add :: proc(h: ^Headers, name: string, value: string, loc := #caller_location) -> bool {
	assert(!h.readonly, "these headers are readonly", loc)

	if !is_token(name)        { return false }
	if !is_field_value(value) { return false }

	headers_set_parsed(h, intern_key(h, name), value)
	return true
}

/*
Removes a header.

The entry is blanked rather than compacted so that previously handed-out indices
stay valid; the writer skips empty names.
*/
headers_delete :: proc(h: ^Headers, key: string, loc := #caller_location) {
	assert(!h.readonly, "these headers are readonly", loc)

	idx, found := h._index[key]
	if !found { return }

	h.entries[idx] = {}
	delete_key(&h._index, key)
}

/*
Folds a name to lowercase and ensures the result outlives the caller's buffer.

Returns the input untouched when it is already lowercase, which is the common
case and costs one scan with no allocation.
*/
@(private)
intern_key :: proc(h: ^Headers, name: string) -> string {
	buf: [64]byte
	key, alloced := fold_key(name, buf[:], h.allocator)
	if alloced {
		// Already owned by the arena.
		return key
	}
	if raw_data(key) == raw_data(name) {
		// Unmodified, so it shares the caller's lifetime, which outlives us.
		return key
	}
	// Folded into the stack buffer; needs a copy that survives this frame.
	return strings.clone(key, h.allocator)
}

@(private)
fold_key :: proc(name: string, buf: []byte, allocator: mem.Allocator) -> (key: string, allocated: bool) {
	needs_fold := false
	for i in 0..<len(name) {
		if name[i] >= 'A' && name[i] <= 'Z' {
			needs_fold = true
			break
		}
	}
	if !needs_fold { return name, false }

	if len(name) <= len(buf) {
		for i in 0..<len(name) {
			buf[i] = to_lower_ascii(name[i])
		}
		return string(buf[:len(name)]), false
	}

	out := make([]byte, len(name), allocator)
	for i in 0..<len(name) {
		out[i] = to_lower_ascii(name[i])
	}
	return string(out), true
}

/*
Replaces a header's value outright, bypassing duplicate joining.

Needed where a protocol defines its own join rule: h2 splits Cookie across
fields and requires "; " between them (RFC 9113 8.2.3), whereas the general
rule for repeated fields is ", ". Using the general rule there corrupts the
cookie string.
*/
@(private)
headers_set_joined :: proc(h: ^Headers, key: string, value: string) {
	if idx, found := h._index[key]; found {
		h.entries[idx].value = value
		return
	}
	h._index[key] = len(h.entries)
	append(&h.entries, Header_Entry{key, value})
}
