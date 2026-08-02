package http

import "core:mem"
import "core:mem/virtual"

/*
HTTP/2 stream state and flow control (RFC 9113 sections 5.1 and 6.9).

A stream is a state machine plus two counters. Both are pure logic — no sockets,
no allocation beyond the stream map — so the rules that matter can be tested
directly rather than inferred from connection behaviour.

The rules here are not bookkeeping. h2 multiplexes many streams over one socket,
so a peer that can confuse this state machine can make frames land on the wrong
stream, and a peer that can drive a window negative can make the server send
data the peer never agreed to receive. Both are rejected rather than clamped.

Server push is not implemented, so the `reserved` states do not exist: a
PUSH_PROMISE from a client is itself a protocol error (RFC 9113 8.4).
*/

H2_Stream_State :: enum u8 {
	Idle,
	Open,
	// The peer finished sending; we may still respond.
	Half_Closed_Remote,
	// We finished sending; the peer may still be sending its request body.
	Half_Closed_Local,
	Closed,
}

/*
The default connection and stream flow-control window (RFC 9113 6.9.2).

In force from the first byte, before any SETTINGS arrives, so a connection must
be able to operate on this alone.
*/
H2_DEFAULT_WINDOW_SIZE :: 65_535

H2_Stream :: struct {
	id:    u32,
	state: H2_Stream_State,

	// Bytes we may still send on this stream before the peer must extend it.
	// Signed because a SETTINGS change can retroactively push it negative
	// (RFC 9113 6.9.2), which is legal and must not be treated as underflow.
	send_window: i64,
	// Bytes the peer may still send us.
	recv_window: i64,

	// Set once END_STREAM has been seen in each direction, which is what
	// distinguishes a finished stream from one closed by RST_STREAM.
	end_stream_received: bool,
	end_stream_sent:     bool,

	// The request being assembled from HEADERS/CONTINUATION and DATA frames.
	request: Request,
	body:    [dynamic]byte,
	// Owns everything the request borrows. Held per stream rather than per
	// connection because streams finish in any order, so one arena for the
	// connection could not be reset until every stream had ended.
	//
	// A pointer, not a value: `virtual.Arena` holds a block pointer and a
	// mutex, so copying one leaves two owners of the same memory.
	arena:   ^virtual.Arena,
}

/*
Connection-level stream bookkeeping.

`last_peer_stream_id` is the enforcement point for RFC 9113 5.1.1: identifiers
must increase. Without it a peer could reuse an id and have frames for a new
request land on the state of an old one.
*/
H2_Streams :: struct {
	streams:   map[u32]^H2_Stream,
	allocator: mem.Allocator,

	last_peer_stream_id: u32,
	// Counted rather than derived from `len(streams)`, because closed streams
	// linger in the map briefly and must not count against the limit.
	open_count: u32,
	// Closed streams awaiting reaping, oldest first.
	closed_order: [dynamic]u32,

	// Connection-level windows, separate from every stream's.
	send_window: i64,
	recv_window: i64,

	// Our advertised limits, applied to streams as they are created.
	initial_send_window: i64,
	initial_recv_window: i64,
	max_concurrent:      u32,
}

h2_streams_init :: proc(s: ^H2_Streams, allocator := context.allocator) {
	s.allocator = allocator
	s.streams.allocator = allocator
	s.closed_order.allocator = allocator
	s.send_window = H2_DEFAULT_WINDOW_SIZE
	s.recv_window = H2_DEFAULT_WINDOW_SIZE
	s.initial_send_window = H2_DEFAULT_WINDOW_SIZE
	s.initial_recv_window = H2_DEFAULT_WINDOW_SIZE
	s.max_concurrent = 100
}

h2_streams_destroy :: proc(s: ^H2_Streams) {
	for _, stream in s.streams {
		delete(stream.body)
		free(stream, s.allocator)
	}
	delete(s.streams)
	s.streams = nil
	delete(s.closed_order)
	s.closed_order = nil
}

/*
How many closed streams are retained before the oldest are discarded.

Some must linger: `h2_stream_missing_error` needs them to tell a frame for a
finished stream (a race a correct peer can lose) from one for a stream that
never existed. But retaining them all is CVE-2023-44487, Rapid Reset — a peer
opens and immediately resets streams, which never trip `max_concurrent` because
each is short-lived, and memory grows without bound.

Reaping the oldest is safe because `last_peer_stream_id` still records the
high-water mark, so a frame for a reaped stream is classified from that rather
than from the map.
*/
H2_MAX_CLOSED_STREAMS :: 64

/*
Opens a stream for a peer-initiated HEADERS frame.

Enforces the two identifier rules that keep streams from colliding: a
client-initiated stream must be odd, and each must be numerically greater than
every stream the peer has opened before. Violating either is a connection error,
not a stream error, because the connection's stream state can no longer be
trusted.
*/
h2_stream_open :: proc(s: ^H2_Streams, id: u32) -> (stream: ^H2_Stream, err: H2_Error) {
	// Stream 0 is the connection itself and can never carry a request.
	if id == 0 { return nil, .Protocol_Error }

	// RFC 9113 5.1.1: streams initiated by a client use odd identifiers.
	if id % 2 == 0 { return nil, .Protocol_Error }

	// Equal is also an error: reusing an identifier would attach new frames to
	// a previous request's state.
	if id <= s.last_peer_stream_id { return nil, .Protocol_Error }

	if s.open_count >= s.max_concurrent { return nil, .Refused_Stream }

	stream = new(H2_Stream, s.allocator)
	stream.id          = id
	stream.state       = .Open
	stream.send_window = s.initial_send_window
	stream.recv_window = s.initial_recv_window
	stream.body.allocator = s.allocator

	s.streams[id] = stream
	s.last_peer_stream_id = id
	s.open_count += 1

	return stream, .No_Error
}

/*
Looks up an existing stream.

A missing entry is ambiguous on purpose: it may be a stream never opened, or one
already closed and reaped. The caller distinguishes them using
`last_peer_stream_id`, since only frames for streams at or below that have ever
existed.
*/
h2_stream_get :: proc(s: ^H2_Streams, id: u32) -> (stream: ^H2_Stream, found: bool) {
	stream, found = s.streams[id]
	return
}

/*
Classifies a frame arriving for a stream that is not in the map.

RFC 9113 5.1 distinguishes these: a frame for a stream that was never opened is
a PROTOCOL_ERROR, while one for a stream already closed is STREAM_CLOSED. The
difference matters because the second is a race a well-behaved peer can lose,
and the first is not.
*/
h2_stream_missing_error :: proc(s: ^H2_Streams, id: u32) -> H2_Error {
	if id <= s.last_peer_stream_id { return .Stream_Closed }
	return .Protocol_Error
}

/*
Records that END_STREAM was received, advancing the state.

Receiving END_STREAM twice is a protocol error: the peer has already said it
finished, so a second one means its state machine disagrees with ours.
*/
h2_stream_recv_end :: proc(s: ^H2_Streams, stream: ^H2_Stream) -> H2_Error {
	if stream.end_stream_received { return .Stream_Closed }
	stream.end_stream_received = true

	switch stream.state {
	case .Open:
		stream.state = .Half_Closed_Remote
	case .Half_Closed_Local:
		h2_stream_close(s, stream)
	case .Idle, .Half_Closed_Remote, .Closed:
		return .Stream_Closed
	}
	return .No_Error
}

// Records that we sent END_STREAM, advancing the state.
h2_stream_send_end :: proc(s: ^H2_Streams, stream: ^H2_Stream) {
	stream.end_stream_sent = true

	switch stream.state {
	case .Open:
		stream.state = .Half_Closed_Local
	case .Half_Closed_Remote:
		h2_stream_close(s, stream)
	case .Idle, .Half_Closed_Local, .Closed:
		// Already finished in this direction; nothing to advance.
	}
}

/*
Marks a stream closed and releases its concurrency slot.

The entry stays in the map so late frames can be told apart from frames for a
stream that never existed; the connection layer reaps it.
*/
h2_stream_close :: proc(s: ^H2_Streams, stream: ^H2_Stream) {
	if stream.state == .Closed { return }
	stream.state = .Closed
	if s.open_count > 0 { s.open_count -= 1 }

	append(&s.closed_order, stream.id)

	// Discard the oldest closed streams once too many have accumulated.
	for len(s.closed_order) > H2_MAX_CLOSED_STREAMS {
		oldest := s.closed_order[0]
		ordered_remove(&s.closed_order, 0)

		if victim, found := s.streams[oldest]; found {
			delete(victim.body)
			free(victim, s.allocator)
			delete_key(&s.streams, oldest)
		}
	}
}

/*
Validates that a DATA frame may arrive on this stream.

DATA is only legal while the peer still has the send half open. Accepting it
after END_STREAM would let a peer append to a request the handler may already
have acted on.
*/
h2_stream_can_recv_data :: proc(stream: ^H2_Stream) -> H2_Error {
	#partial switch stream.state {
	case .Open:
		return .No_Error
	case .Half_Closed_Remote, .Closed:
		return .Stream_Closed
	case:
		return .Protocol_Error
	}
}

// --- Flow control (RFC 9113 6.9) ---

/*
Accounts for received DATA against both windows.

Both must be debited: a peer could otherwise exhaust memory by spreading a large
body across many streams, each individually within its own window. A negative
result means the peer sent more than it was allowed, which is a connection
error rather than something to absorb.
*/
h2_flow_consume :: proc(s: ^H2_Streams, stream: ^H2_Stream, size: int) -> H2_Error {
	n := i64(size)

	if s.recv_window - n < 0      { return .Flow_Control_Error }
	if stream.recv_window - n < 0 { return .Flow_Control_Error }

	s.recv_window -= n
	stream.recv_window -= n
	return .No_Error
}

/*
Applies a WINDOW_UPDATE to the connection or a stream.

`stream` is nil for a connection-level update (stream 0). Overflowing 2^31-1 is
a flow-control error either way — the check exists because the increment is
peer-supplied and a wrapped window would let a peer authorise unlimited sending.
*/
h2_flow_update :: proc(s: ^H2_Streams, stream: ^H2_Stream, increment: u32) -> H2_Error {
	inc := i64(increment)

	if stream == nil {
		if s.send_window + inc > H2_MAX_WINDOW_SIZE { return .Flow_Control_Error }
		s.send_window += inc
		return .No_Error
	}

	if stream.send_window + inc > H2_MAX_WINDOW_SIZE { return .Flow_Control_Error }
	stream.send_window += inc
	return .No_Error
}

/*
Returns how many bytes may be sent on a stream right now.

The limit is whichever window is smaller: the connection's budget is shared, so
a stream with a generous window still cannot send past it.
*/
h2_flow_sendable :: proc(s: ^H2_Streams, stream: ^H2_Stream) -> int {
	available := min(s.send_window, stream.send_window)
	if available < 0 { return 0 }
	return int(available)
}

// Debits both windows for data we are about to send.
h2_flow_sent :: proc(s: ^H2_Streams, stream: ^H2_Stream, size: int) {
	n := i64(size)
	s.send_window -= n
	stream.send_window -= n
}

/*
Applies a change to SETTINGS_INITIAL_WINDOW_SIZE.

RFC 9113 6.9.2: the delta applies to every existing stream, not just new ones,
and the result may go negative — a peer that lowers the setting after granting a
large window has legitimately over-issued, and the stream must simply stop
sending until an update arrives. Treating that as an error would break a legal
sequence.
*/
h2_flow_initial_window_changed :: proc(s: ^H2_Streams, new_initial: u32) -> H2_Error {
	delta := i64(new_initial) - s.initial_send_window
	s.initial_send_window = i64(new_initial)

	for _, stream in s.streams {
		updated := stream.send_window + delta
		// The window may go negative, but must not exceed the maximum.
		if updated > H2_MAX_WINDOW_SIZE { return .Flow_Control_Error }
		stream.send_window = updated
	}
	return .No_Error
}

// Number of stream records held, closed ones included. For tests and diagnostics.
h2_stream_count :: proc(s: ^H2_Streams) -> int {
	return len(s.streams)
}

// Number of streams currently counting against the concurrency limit.
h2_open_count :: proc(s: ^H2_Streams) -> u32 {
	return s.open_count
}
