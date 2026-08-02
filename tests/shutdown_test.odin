package tests

import "core:strings"
import "core:testing"
import "core:mem/virtual"
import "core:net"
import "core:thread"
import "core:time"

import http "../http"

/*
Graceful shutdown.

A server that stops accepting is not the same as a server that has stopped. If
`server_serve` returns while connection threads are still running, those threads
go on touching `Server` state that the caller is free to reuse or free, so this
is a use-after-free rather than merely an abrupt disconnect.
*/

@(private)
Slow_Client :: struct {
	endpoint: net.Endpoint,
	// The response is built in an arena the client owns, so the main thread can
	// read it after the join without the builder's buffer having been freed.
	arena:    virtual.Arena,
	response: string,
	done:     bool,
}

@(private)
slow_client_run :: proc(c: ^Slow_Client) {
	resp, _ := http.test_request_raw(c.endpoint,
		"GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
		virtual.arena_allocator(&c.arena))
	c.response = resp
	c.done = true
}

@(test)
test_server_shutdown_waits_for_inflight_requests :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /slow", proc(req: ^http.Request, res: ^http.Response) {
		// Long enough that shutdown is guaranteed to land mid-request.
		time.sleep(300 * time.Millisecond)
		http.respond_plain(res, .OK, "slow done")
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}

	client := Slow_Client{endpoint = ts.endpoint}
	_ = virtual.arena_init_growing(&client.arena)
	defer virtual.arena_destroy(&client.arena)
	client_thread := thread.create_and_start_with_poly_data(&client, slow_client_run)
	defer {
		thread.join(client_thread)
		thread.destroy(client_thread)
	}

	// Let the request reach the handler, then stop while it is still running.
	time.sleep(100 * time.Millisecond)
	http.test_server_stop(&ts)

	// `server_drain` must have run before `server_serve` returned.
	//
	// NOTE: on this platform `accept_tcp` only unblocks when the listening
	// socket is closed, which happens after the handler has usually finished,
	// so this assertion does not by itself prove the drain works — it guards
	// the invariant rather than reproducing the race. The drain matters for the
	// case where accept returns while a long handler is still running.
	testing.expect_value(t, ts.active_at_return, 0)

	thread.join(client_thread)

	testing.expect(t, strings.contains(client.response, "slow done"),
		"an in-flight request must complete before shutdown returns")
}

/*
Directly exercises the drain, without depending on accept-loop timing.

A connection is registered as active and released on a background thread while
`server_drain` is running, which is the situation the drain exists for.
*/
@(test)
test_server_drain_waits_for_active_connections :: proc(t: ^testing.T) {
	s: http.Server
	s.opts = http.DEFAULT_SERVER_OPTS

	// Simulate a connection thread that is mid-request.
	http.server_test_add_active(&s, 1)

	Releaser :: struct { server: ^http.Server }
	rel := Releaser{server = &s}

	releaser := thread.create_and_start_with_poly_data(&rel, proc(r: ^Releaser) {
		time.sleep(150 * time.Millisecond)
		http.server_test_add_active(r.server, -1)
	})
	defer {
		thread.join(releaser)
		thread.destroy(releaser)
	}

	start := time.now()
	http.server_test_drain(&s)
	elapsed := time.since(start)

	// The drain must have blocked until the connection was released.
	testing.expect(t, elapsed >= 100 * time.Millisecond,
		"drain must wait for active connections to finish")
	testing.expect_value(t, http.server_active_connections(&s), 0)
}

@(test)
test_server_drain_gives_up_after_timeout :: proc(t: ^testing.T) {
	s: http.Server
	s.opts = http.DEFAULT_SERVER_OPTS
	// A wedged handler must not hang shutdown forever.
	s.opts.shutdown_timeout = 50 * time.Millisecond

	http.server_test_add_active(&s, 1)
	defer http.server_test_add_active(&s, -1)

	start := time.now()
	http.server_test_drain(&s)
	elapsed := time.since(start)

	testing.expect(t, elapsed >= 40 * time.Millisecond, "must wait for the timeout")
	testing.expect(t, elapsed < 2 * time.Second, "must not wait indefinitely")
}

@(test)
test_server_stops_accepting_after_shutdown :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /hi", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "hi")
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}

	// Works before shutdown.
	before, _ := http.test_request_raw(ts.endpoint,
		"GET /hi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	testing.expect(t, strings.contains(before, "200 OK"), "server should serve before shutdown")

	endpoint := ts.endpoint
	http.test_server_stop(&ts)

	// After shutdown the port is closed, so a new connection must not be served.
	after, _ := http.test_request_raw(endpoint,
		"GET /hi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	testing.expect(t, !strings.contains(after, "200 OK"),
		"server must not serve requests after shutdown")
}
