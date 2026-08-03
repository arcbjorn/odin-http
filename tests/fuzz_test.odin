package tests

import "core:math/rand"
import "core:strings"
import "core:testing"

import http "../http"

/*
Mutation fuzzing of the pure parsers.

Every procedure driven here takes attacker-controlled bytes and is total: it
must return a verdict for any input, never trap. That property is what the
percent-decode crash violated — `GET /ab% HTTP/1.1` overran a buffer sized on
the assumption that every '%' began a complete escape.

The seeds are *nearly* valid and the mutations are grammar-aware, because that
is what it takes to reach the interesting states. Uniformly random bytes
essentially never place a '%' one byte from the end of a string, so a naive
fuzzer runs millions of cases without touching the bug this one reproduces in
seconds.

The seed is fixed so a failure is reproducible. This is a smoke test rather
than a search: it runs in well under a second and is meant to catch a whole
class of regression, not to prove absence.
*/

@(private)
FUZZ_ITERATIONS :: 40_000

// Inputs that are valid or close to it, so mutations land near real boundaries.
@(private)
fuzz_seeds := []string{
	"/a%20b", "/a/b/c", "/%2e%2e%2f", "/x/../y", "/a.txt", "/",
	"bytes=0-10", "bytes=-5", "bytes=5-", "bytes=*/10",
	"a=1&b=2", "a=hello+world", "flag",
	"GET", "POST", "HTTP/1.1", "HTTP/2.0",
	"text/html", "chunked", "gzip, chunked",
	"100", "7fffffffffffffff", "0",
}

// Fragments spliced in at arbitrary offsets. Truncated escapes and separators
// dominate, since those are where length arithmetic goes wrong.
@(private)
fuzz_fragments := []string{
	"%", "%2", "%zz", "%00", "/", "..", "\x00", "\\", "\r\n", "\t",
	"=", "&", "+", "-", ".", ":", "?", "#", "bytes=", "\"", "\x7f", "\xff",
}

/*
Applies one to three mutations to a seed.

Truncation is included because it is the cheapest way to produce a string whose
prefix is well formed and whose tail is not — exactly the shape that defeats a
length computed from a full-input scan.
*/
@(private)
fuzz_mutate :: proc(input: string, allocator := context.temp_allocator) -> string {
	s := input
	for _ in 0 ..< (1 + rand.int_max(3)) {
		if len(s) == 0 { break }

		switch rand.int_max(3) {
		case 0:
			s = s[:rand.int_max(len(s))]
		case 1:
			at := rand.int_max(len(s) + 1)
			f := fuzz_fragments[rand.int_max(len(fuzz_fragments))]
			s = strings.concatenate({s[:at], f, s[at:]}, allocator)
		case 2:
			at := rand.int_max(len(s))
			s = strings.concatenate({s[:at], s[at + 1:]}, allocator)
		}
	}
	return s
}

/*
No malformed input may trap any pure parser.

Results are deliberately discarded: what is under test is totality, not the
verdict. A parser that rejects everything would pass this and fail the targeted
tests in url_test, token_test and range_test, which is the intended division of
labour.
*/
@(test)
test_fuzz_parsers_never_trap :: proc(t: ^testing.T) {
	r := rand.create(0x5eed)
	context.random_generator = rand.default_random_generator(&r)

	for _ in 0 ..< FUZZ_ITERATIONS {
		s := fuzz_mutate(fuzz_seeds[rand.int_max(len(fuzz_seeds))])

		_, _ = http.percent_decode(s, context.temp_allocator)
		_    = http.url_parse(s, context.temp_allocator)
		_    = http.query_parse(s, context.temp_allocator)
		_    = http.url_path_is_safe(s)
		_    = http.path_clean(s, context.temp_allocator)
		_, _ = http.path_clean_checked(s, context.temp_allocator)
		_, _ = http.file_path_resolve("/srv", s, context.temp_allocator)
		_, _ = http.parse_range_header(s, 100)
		_    = http.is_token(s)
		_    = http.is_field_value(s)
		_, _ = http.parse_decimal(s)
		_, _ = http.parse_hex(s)
		_    = http.trim_ows(s)
		_    = http.mime_by_extension(s)
		_, _ = http.method_parse(s)
		_, _ = http.version_parse(s)
		_    = http.token_list_contains(s, "chunked")
	}

	// Reaching here without a trap is the assertion; `expect` records the pass.
	testing.expect(t, true, "")
}

/*
The same treatment for the header-block parser, which is stateful.

`parser_feed` carries state across calls, so a malformed request must leave it
in a state that either yields an error or asks for more bytes — never one that
traps on the next byte.
*/
@(test)
test_fuzz_request_parser_never_traps :: proc(t: ^testing.T) {
	r := rand.create(0xf0f0)
	context.random_generator = rand.default_random_generator(&r)

	/*
	Several seeds begin with a bare CR or LF on purpose.

	Line scanning looks back one byte to pair a CR with its LF, so a message
	whose very first byte is a terminator is the case where that lookback runs
	off the front of the buffer. Every seed starting with a method name leaves
	that unreachable: mutations insert and delete, but never prepend a
	terminator to an otherwise-valid request.
	*/
	requests := []string{
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc",
		"GET /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"\nGET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"\rGET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"\r\n\r\n",
		"\n",
		"\r",
	}

	for _ in 0 ..< 4_000 {
		raw := fuzz_mutate(requests[rand.int_max(len(requests))])

		req: http.Request
		http.request_init(&req, context.temp_allocator)

		p: http.Parser
		http.parser_init(&p, &req)

		// Feed in slices, so a mutation that lands mid-token is exercised at
		// every buffer boundary rather than only on a whole-message parse.
		off := 0
		for off < len(raw) {
			end := min(len(raw), off + 1 + rand.int_max(8))
			consumed, _ := http.parser_feed(&p, transmute([]byte)raw[off:end])
			if consumed <= 0 { break }
			off += consumed
		}
	}

	testing.expect(t, true, "")
}
