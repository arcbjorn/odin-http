package tests

import "core:testing"

import http "../http"

/*
HTTP/2 stream state and flow control.

These are pure logic, so they test the rules directly rather than inferring them
from connection behaviour. The rules are not bookkeeping: h2 multiplexes many
streams over one socket, so a peer that can confuse the state machine makes
frames land on the wrong stream, and one that can drive a window negative makes
the server send data the peer never agreed to receive.
*/

@(private)
new_streams :: proc() -> http.H2_Streams {
	s: http.H2_Streams
	http.h2_streams_init(&s)
	return s
}

// --- Stream identifiers (RFC 9113 5.1.1) ---

@(test)
test_h2_stream_open_assigns_defaults :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, err := http.h2_stream_open(&s, 1)

	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, stream.id, u32(1))
	testing.expect_value(t, stream.state, http.H2_Stream_State.Open)
	// Both windows start at the protocol default, in force before any SETTINGS.
	testing.expect_value(t, stream.send_window, i64(http.H2_DEFAULT_WINDOW_SIZE))
	testing.expect_value(t, stream.recv_window, i64(http.H2_DEFAULT_WINDOW_SIZE))
}

@(test)
test_h2_stream_rejects_even_ids :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	// Even identifiers are reserved for server-initiated streams, so a client
	// using one has either a bug or an intent this server should not honour.
	_, err := http.h2_stream_open(&s, 2)
	testing.expect_value(t, err, http.H2_Error.Protocol_Error)
}

@(test)
test_h2_stream_rejects_stream_zero :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	// Stream 0 is the connection itself and can never carry a request.
	_, err := http.h2_stream_open(&s, 0)
	testing.expect_value(t, err, http.H2_Error.Protocol_Error)
}

@(test)
test_h2_stream_ids_must_increase :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	_, err1 := http.h2_stream_open(&s, 5)
	testing.expect_value(t, err1, http.H2_Error.No_Error)

	// Reusing an identifier would attach new frames to a previous request's
	// state, so equal is an error as well as lower.
	_, same := http.h2_stream_open(&s, 5)
	testing.expect_value(t, same, http.H2_Error.Protocol_Error)

	_, lower := http.h2_stream_open(&s, 3)
	testing.expect_value(t, lower, http.H2_Error.Protocol_Error)

	// Skipping ahead is legal; identifiers need not be contiguous.
	_, higher := http.h2_stream_open(&s, 7)
	testing.expect_value(t, higher, http.H2_Error.No_Error)
}

@(test)
test_h2_stream_enforces_max_concurrent :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)
	s.max_concurrent = 2

	_, a := http.h2_stream_open(&s, 1)
	_, b := http.h2_stream_open(&s, 3)
	testing.expect_value(t, a, http.H2_Error.No_Error)
	testing.expect_value(t, b, http.H2_Error.No_Error)

	// REFUSED_STREAM rather than a connection error: the peer may simply retry
	// this request later, and the connection stays usable.
	_, over := http.h2_stream_open(&s, 5)
	testing.expect_value(t, over, http.H2_Error.Refused_Stream)
}

@(test)
test_h2_closing_frees_a_concurrency_slot :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)
	s.max_concurrent = 1

	stream, _ := http.h2_stream_open(&s, 1)
	http.h2_stream_close(&s, stream)

	// A finished stream must not keep occupying the limit.
	_, err := http.h2_stream_open(&s, 3)
	testing.expect_value(t, err, http.H2_Error.No_Error)
}

// --- State transitions (RFC 9113 5.1) ---

@(test)
test_h2_stream_half_closes_on_end_stream :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)

	err := http.h2_stream_recv_end(&s, stream)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	// The peer has finished, but we may still respond.
	testing.expect_value(t, stream.state, http.H2_Stream_State.Half_Closed_Remote)

	http.h2_stream_send_end(&s, stream)
	testing.expect_value(t, stream.state, http.H2_Stream_State.Closed)
}

@(test)
test_h2_stream_rejects_double_end_stream :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)
	http.h2_stream_recv_end(&s, stream)

	// A second END_STREAM means the peer's state machine disagrees with ours.
	err := http.h2_stream_recv_end(&s, stream)
	testing.expect_value(t, err, http.H2_Error.Stream_Closed)
}

@(test)
test_h2_data_rejected_after_end_stream :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)
	testing.expect_value(t, http.h2_stream_can_recv_data(stream), http.H2_Error.No_Error)

	http.h2_stream_recv_end(&s, stream)

	// Accepting DATA now would let a peer append to a request the handler may
	// already have acted on.
	testing.expect_value(t, http.h2_stream_can_recv_data(stream), http.H2_Error.Stream_Closed)
}

@(test)
test_h2_missing_stream_error_distinguishes_closed :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	http.h2_stream_open(&s, 5)

	// At or below the highest identifier seen: the stream existed and is gone,
	// which is a race a well-behaved peer can lose.
	testing.expect_value(t, http.h2_stream_missing_error(&s, 3), http.H2_Error.Stream_Closed)
	testing.expect_value(t, http.h2_stream_missing_error(&s, 5), http.H2_Error.Stream_Closed)

	// Above it: the stream was never opened, which no correct peer does.
	testing.expect_value(t, http.h2_stream_missing_error(&s, 7), http.H2_Error.Protocol_Error)
}

// --- Flow control (RFC 9113 6.9) ---

@(test)
test_h2_flow_debits_both_windows :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)

	err := http.h2_flow_consume(&s, stream, 1000)
	testing.expect_value(t, err, http.H2_Error.No_Error)

	// Both must be charged: otherwise a peer spreads a large body across many
	// streams, each individually within its own window.
	testing.expect_value(t, stream.recv_window, i64(http.H2_DEFAULT_WINDOW_SIZE - 1000))
	testing.expect_value(t, s.recv_window, i64(http.H2_DEFAULT_WINDOW_SIZE - 1000))
}

@(test)
test_h2_flow_rejects_overrun :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)

	// One byte more than the window allows.
	err := http.h2_flow_consume(&s, stream, http.H2_DEFAULT_WINDOW_SIZE + 1)
	testing.expect_value(t, err, http.H2_Error.Flow_Control_Error)

	// And the windows must be unchanged, not partially debited.
	testing.expect_value(t, stream.recv_window, i64(http.H2_DEFAULT_WINDOW_SIZE))
}

@(test)
test_h2_flow_connection_window_limits_streams :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	a, _ := http.h2_stream_open(&s, 1)
	b, _ := http.h2_stream_open(&s, 3)

	// Drain most of the shared connection window through one stream.
	testing.expect_value(t, http.h2_flow_consume(&s, a, 60_000), http.H2_Error.No_Error)

	// The second stream's own window is untouched, but the connection's is
	// nearly gone, so a large frame must still be refused.
	err := http.h2_flow_consume(&s, b, 10_000)
	testing.expect_value(t, err, http.H2_Error.Flow_Control_Error)
}

@(test)
test_h2_flow_update_extends_window :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)
	before := stream.send_window

	err := http.h2_flow_update(&s, stream, 1024)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, stream.send_window, before + 1024)

	// A nil stream addresses the connection window.
	conn_before := s.send_window
	http.h2_flow_update(&s, nil, 2048)
	testing.expect_value(t, s.send_window, conn_before + 2048)
}

@(test)
test_h2_flow_update_rejects_overflow :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)

	// A wrapped window would let a peer authorise unlimited sending, so the
	// increment is checked against the 2^31-1 ceiling rather than trusted.
	err := http.h2_flow_update(&s, stream, u32(http.H2_MAX_WINDOW_SIZE))
	testing.expect_value(t, err, http.H2_Error.Flow_Control_Error)

	conn := http.h2_flow_update(&s, nil, u32(http.H2_MAX_WINDOW_SIZE))
	testing.expect_value(t, conn, http.H2_Error.Flow_Control_Error)
}

@(test)
test_h2_flow_sendable_takes_the_smaller_window :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)

	// The connection budget is shared, so a generous stream window does not
	// let it send past the connection's.
	s.send_window = 100
	stream.send_window = 5000
	testing.expect_value(t, http.h2_flow_sendable(&s, stream), 100)

	s.send_window = 5000
	stream.send_window = 100
	testing.expect_value(t, http.h2_flow_sendable(&s, stream), 100)
}

@(test)
test_h2_flow_sendable_never_negative :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)
	stream.send_window = -500

	// A negative window means "send nothing", not "send a negative amount".
	testing.expect_value(t, http.h2_flow_sendable(&s, stream), 0)
}

@(test)
test_h2_initial_window_change_applies_retroactively :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)
	testing.expect_value(t, stream.send_window, i64(http.H2_DEFAULT_WINDOW_SIZE))

	// RFC 9113 6.9.2: the delta applies to streams that already exist, not
	// only to new ones.
	err := http.h2_flow_initial_window_changed(&s, http.H2_DEFAULT_WINDOW_SIZE + 1000)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, stream.send_window, i64(http.H2_DEFAULT_WINDOW_SIZE + 1000))
}

@(test)
test_h2_initial_window_may_go_negative :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)
	// Spend most of the window.
	http.h2_flow_sent(&s, stream, 60_000)

	// Now the peer lowers the initial size. It has legitimately over-issued,
	// and the stream must simply stop sending until an update arrives —
	// treating this as an error would reject a legal sequence.
	err := http.h2_flow_initial_window_changed(&s, 1000)

	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect(t, stream.send_window < 0, "window should have gone negative")
	testing.expect_value(t, http.h2_flow_sendable(&s, stream), 0)
}

/*
Rapid Reset (CVE-2023-44487).

A peer opens a stream and immediately resets it, repeatedly. Each stream is
short-lived so `max_concurrent` never trips, but if closed streams are never
reaped the per-stream state accumulates until the process dies. The attack costs
the client almost nothing, which is what made it effective against most h2
implementations in 2023.
*/
@(test)
test_h2_rapid_reset_does_not_leak_streams :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	// Open and immediately close many streams, as a rapid-reset client does.
	id := u32(1)
	for _ in 0 ..< 2000 {
		stream, err := http.h2_stream_open(&s, id)
		testing.expectf(t, err == .No_Error, "open failed at id %d: %v", id, err)
		http.h2_stream_close(&s, stream)
		id += 2
	}

	// Concurrency accounting is correct either way, so it cannot catch this.
	testing.expect_value(t, http.h2_open_count(&s), u32(0))

	// Retained state is what matters. A bounded number of closed streams is
	// fine — some must linger so late frames can be told from frames for a
	// stream that never existed — but 2000 is unbounded growth.
	retained := http.h2_stream_count(&s)
	testing.expectf(t, retained <= 128,
		"%d closed streams retained; rapid reset grows memory without bound", retained)
}

/*
The flow-control ceiling is checked at its exact boundary.

`test_h2_flow_update_rejects_overflow` overshoots by a whole window, so a check
loosened by one still rejects and the test cannot tell the difference. RFC 9113
6.9.1 puts the ceiling at 2^31-1 inclusive: an increment landing exactly there
must be accepted, and one byte more must be a flow-control error. Getting that
edge wrong by one is how a peer wraps the window and authorises unlimited
sending.
*/
@(test)
test_h2_flow_update_boundary_is_exact :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)

	// The window opens at 65535, so this increment lands exactly on the ceiling.
	to_ceiling := u32(http.H2_MAX_WINDOW_SIZE - http.H2_DEFAULT_WINDOW_SIZE)

	err := http.h2_flow_update(&s, stream, to_ceiling)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, stream.send_window, i64(http.H2_MAX_WINDOW_SIZE))

	// One byte past a window already at the ceiling must be refused.
	over := http.h2_flow_update(&s, stream, 1)
	testing.expect_value(t, over, http.H2_Error.Flow_Control_Error)
	testing.expect_value(t, stream.send_window, i64(http.H2_MAX_WINDOW_SIZE))
}

// The connection-level window has its own ceiling and its own check.
@(test)
test_h2_flow_update_connection_boundary_is_exact :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	to_ceiling := u32(http.H2_MAX_WINDOW_SIZE - http.H2_DEFAULT_WINDOW_SIZE)

	err := http.h2_flow_update(&s, nil, to_ceiling)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, s.send_window, i64(http.H2_MAX_WINDOW_SIZE))

	over := http.h2_flow_update(&s, nil, 1)
	testing.expect_value(t, over, http.H2_Error.Flow_Control_Error)
}

/*
Consuming exactly the window is legal; one byte more is not.

`h2_flow_consume` debits the receive window, so an off-by-one here either
rejects a conforming peer's final byte or lets it overrun by one.
*/
@(test)
test_h2_flow_consume_boundary_is_exact :: proc(t: ^testing.T) {
	s := new_streams()
	defer http.h2_streams_destroy(&s)

	stream, _ := http.h2_stream_open(&s, 1)

	// The whole window at once must be accepted.
	err := http.h2_flow_consume(&s, stream, http.H2_DEFAULT_WINDOW_SIZE)
	testing.expect_value(t, err, http.H2_Error.No_Error)
	testing.expect_value(t, stream.recv_window, i64(0))

	// With the window empty, even a single byte is an overrun.
	over := http.h2_flow_consume(&s, stream, 1)
	testing.expect_value(t, over, http.H2_Error.Flow_Control_Error)
	testing.expect_value(t, stream.recv_window, i64(0))
}
