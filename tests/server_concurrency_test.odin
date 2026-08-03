package tests

import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:testing"
import "core:thread"

import http "../http"

/*
Concurrent load against one server.

The server's shared state — the active-connection count, the closing flag and
the cached Date header — is touched by every connection thread on every request,
but nothing else in the suite drives more than one connection at a time. That
leaves the hottest contended paths in the library unobserved by ThreadSanitizer,
which only reports races on code that actually runs concurrently.

These tests exist mainly to give TSan something to watch. Under a normal build
they also check that concurrent requests do not corrupt each other's responses,
which is the visible symptom a race here would produce.
*/

@(private)
Load_Worker :: struct {
	endpoint:  net.Endpoint,
	requests:  int,
	ok_count:  int,
	bad_count: int,
	// Written by the worker, read by the main thread after the join.
	body_seen: string,
	arena:     virtual.Arena,
}

/*
Issues `requests` sequential requests on its own connections.

Each worker owns its arena so nothing is shared between them but the server
itself; any interference observed therefore comes from the server rather than
from the test.
*/
@(private)
load_worker_run :: proc(w: ^Load_Worker) {
	alloc := virtual.arena_allocator(&w.arena)

	for _ in 0 ..< w.requests {
		resp, _ := http.test_request_raw(w.endpoint,
			"GET /load HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", alloc)

		// A torn or interleaved response is the visible symptom of a race on
		// shared server state, so the whole message is checked rather than the
		// status alone.
		if strings.contains(resp, "200 OK") &&
		   strings.contains(resp, "date: ") &&
		   strings.has_suffix(resp, "payload-body") {
			w.ok_count += 1
		} else {
			w.bad_count += 1
			if len(w.body_seen) == 0 { w.body_seen = resp }
		}
	}
}

/*
Many connections at once, each asking for a response that reads the Date cache.

`server_date` takes a mutex, copies the cached bytes into the caller's buffer
and returns a view of that buffer. Returning a view of the *shared* buffer
instead would be a use-after-unlock: correct in a single-threaded test and torn
under load, which is exactly what this drives.
*/
@(test)
test_server_handles_concurrent_connections :: proc(t: ^testing.T) {
	WORKERS  :: 8
	PER_WORKER :: 12

	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /load", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "payload-body")
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	workers := make([]Load_Worker, WORKERS, context.allocator)
	defer delete(workers)

	threads := make([]^thread.Thread, WORKERS, context.allocator)
	defer delete(threads)

	for i in 0 ..< WORKERS {
		workers[i] = Load_Worker{endpoint = ts.endpoint, requests = PER_WORKER}
		_ = virtual.arena_init_growing(&workers[i].arena)
		threads[i] = thread.create_and_start_with_poly_data(&workers[i], load_worker_run)
	}

	total_ok, total_bad := 0, 0
	for i in 0 ..< WORKERS {
		thread.join(threads[i])
		thread.destroy(threads[i])
		total_ok  += workers[i].ok_count
		total_bad += workers[i].bad_count
	}
	defer for i in 0 ..< WORKERS { virtual.arena_destroy(&workers[i].arena) }

	testing.expect_value(t, total_bad, 0)
	testing.expect_value(t, total_ok, WORKERS * PER_WORKER)
}

/*
Concurrent readers of the Date cache, driven directly.

The server loop reaches `server_date` once per response, so the load test above
exercises it through a socket. This one hammers it from several threads with no
I/O in between, which is what makes a torn read likely enough to catch.
*/
@(private)
Date_Reader :: struct {
	server: ^http.Server,
	rounds: int,
	torn:   int,
}

@(private)
date_reader_run :: proc(d: ^Date_Reader) {
	for _ in 0 ..< d.rounds {
		buf: [64]byte
		got := http.server_test_date(d.server, buf[:])

		// Every well-formed date is the same length and ends in "GMT"; anything
		// else means the copy raced with a refresh.
		if len(got) != http.DATE_LENGTH || !strings.has_suffix(got, "GMT") {
			d.torn += 1
		}
	}
}

@(test)
test_server_date_cache_is_thread_safe :: proc(t: ^testing.T) {
	READERS :: 8
	ROUNDS  :: 500

	s: http.Server
	s.opts = http.DEFAULT_SERVER_OPTS

	readers := make([]Date_Reader, READERS, context.allocator)
	defer delete(readers)

	threads := make([]^thread.Thread, READERS, context.allocator)
	defer delete(threads)

	for i in 0 ..< READERS {
		readers[i] = Date_Reader{server = &s, rounds = ROUNDS}
		threads[i] = thread.create_and_start_with_poly_data(&readers[i], date_reader_run)
	}

	total_torn := 0
	for i in 0 ..< READERS {
		thread.join(threads[i])
		thread.destroy(threads[i])
		total_torn += readers[i].torn
	}

	testing.expect_value(t, total_torn, 0)
}

/*
Shutdown while requests are in flight.

`server_shutdown` flips `closing` under the mutex and the accept loop reads it
on every iteration, so this drives both sides of that flag at once. The
assertion is only that the server stops cleanly: how many of the racing requests
land is timing-dependent and not a property worth pinning.
*/
@(test)
test_server_shutdown_under_load_is_clean :: proc(t: ^testing.T) {
	WORKERS :: 4

	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.router_handle_proc(&r, "GET /load", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "payload-body")
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}

	workers := make([]Load_Worker, WORKERS, context.allocator)
	defer delete(workers)

	threads := make([]^thread.Thread, WORKERS, context.allocator)
	defer delete(threads)

	for i in 0 ..< WORKERS {
		workers[i] = Load_Worker{endpoint = ts.endpoint, requests = 8}
		_ = virtual.arena_init_growing(&workers[i].arena)
		threads[i] = thread.create_and_start_with_poly_data(&workers[i], load_worker_run)
	}

	// Stop while the workers are still issuing requests.
	http.test_server_stop(&ts)

	for i in 0 ..< WORKERS {
		thread.join(threads[i])
		thread.destroy(threads[i])
	}
	defer for i in 0 ..< WORKERS { virtual.arena_destroy(&workers[i].arena) }

	// Every connection the server did accept must have been drained before
	// `server_serve` returned, or a connection thread would still be touching
	// server state the caller is free to reuse.
	testing.expect_value(t, ts.active_at_return, 0)
}
