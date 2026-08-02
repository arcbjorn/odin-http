package tests

import "core:mem/virtual"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

import http "../http"

/*
Concurrent use of a shared connection pool.

`Pool` is documented as safe to share between threads, and the single-threaded
tests pass, so a defect here is invisible until several threads contend for the
same origin. That is exactly the shape of bug that reaches production, because
one client per thread against one service is the normal way a pool gets used.
*/

@(private)
Pool_Worker :: struct {
	pool:      ^http.Pool,
	url:       string,
	requests:  int,
	ok:        int,
	failures:  int,
	first_err: http.Client_Error,
	// Longest a failing request took. Distinguishes a fast rejection from a
	// timeout, which is the difference between a closed socket and a stall.
	slowest:   time.Duration,
	mutex:     ^sync.Mutex,
}

@(private)
pool_worker_run :: proc(w: ^Pool_Worker) {
	c := http.DEFAULT_CLIENT
	c.pool = w.pool

	for _ in 0 ..< w.requests {
		arena: virtual.Arena
		if virtual.arena_init_growing(&arena) != nil { continue }

		t0 := time.now()
		res, err := http.client_get(&c, w.url, virtual.arena_allocator(&arena))
		elapsed := time.since(t0)
		good := err == .None && res.status == .OK && res.body == "pong"

		sync.mutex_lock(w.mutex)
		if good {
			w.ok += 1
		} else {
			w.failures += 1
			if w.first_err == .None { w.first_err = err }
			if w.slowest < elapsed { w.slowest = elapsed }
		}
		sync.mutex_unlock(w.mutex)

		virtual.arena_destroy(&arena)
	}
}

/*
Drives `threads` workers against one pool and reports the totals.

Returns successes, failures, and the first error seen, so a caller can assert on
the outcome rather than on timing.
*/
@(private)
run_pool_workers :: proc(
	t: ^testing.T,
	pool: ^http.Pool,
	threads: int,
	per_thread: int,
) -> (ok: int, failures: int, first_err: http.Client_Error, slowest: time.Duration) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)
	http.router_handle_proc(&r, "GET /ping", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "pong")
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	url := strings.builder_make(context.allocator)
	defer strings.builder_destroy(&url)
	strings.write_string(&url, "http://127.0.0.1:")
	strings.write_int(&url, int(ts.endpoint.port))
	strings.write_string(&url, "/ping")

	mutex: sync.Mutex
	shared := Pool_Worker{
		pool     = pool,
		url      = strings.to_string(url),
		requests = per_thread,
		mutex    = &mutex,
	}

	workers := make([]^thread.Thread, threads, context.allocator)
	defer delete(workers)

	for i in 0 ..< threads {
		workers[i] = thread.create_and_start_with_poly_data(&shared, pool_worker_run)
	}
	for i in 0 ..< threads {
		thread.join(workers[i])
		thread.destroy(workers[i])
	}

	// Release pooled connections while the server is still running. An idle
	// connection left open across shutdown makes `server_drain` wait out its
	// full timeout, which would make every run of this test take 30 seconds for
	// reasons unrelated to what it asserts.
	if pool != nil { http.pool_destroy(pool) }

	return shared.ok, shared.failures, shared.first_err, shared.slowest
}

@(test)
test_pool_survives_concurrent_use :: proc(t: ^testing.T) {
	pool: http.Pool
	http.pool_init(&pool)

	THREADS    :: 8
	PER_THREAD :: 20

	ok, failures, first_err, slowest := run_pool_workers(t, &pool, THREADS, PER_THREAD)


	// The same workload without a pool succeeds completely, so any failure here
	// is the pool's doing rather than the server's.
	testing.expectf(t, failures == 0,
		"%d/%d pooled requests failed (first error: %v, slowest failure: %v)",
		failures, THREADS * PER_THREAD, first_err, slowest)
	testing.expect_value(t, ok, THREADS * PER_THREAD)
}

@(test)
test_pool_per_thread_is_safe :: proc(t: ^testing.T) {
	// One pool per thread removes all sharing. If this passes while the shared
	// pool fails, the defect is in concurrent access rather than in reuse
	// itself.
	ok, failures, first_err, slowest := run_pool_workers_isolated(t, 8, 20)

	testing.expectf(t, failures == 0,
		"%d/160 per-thread-pool requests failed (first: %v, slowest: %v)",
		failures, first_err, slowest)
	testing.expect_value(t, ok, 160)
}

@(test)
test_concurrent_requests_without_pool :: proc(t: ^testing.T) {
	// The control: the same concurrency against the same server with no pool.
	// If this ever fails the problem is the server or the harness, not pooling.
	ok, failures, first_err, _ := run_pool_workers(t, nil, 8, 20)

	testing.expectf(t, failures == 0,
		"%d/160 unpooled requests failed (first error: %v)", failures, first_err)
	testing.expect_value(t, ok, 160)
}

@(private)
Isolated_Worker :: struct {
	url:      string,
	requests: int,
	ok:       int,
	failures: int,
	first_err: http.Client_Error,
	slowest:  time.Duration,
	mutex:    ^sync.Mutex,
}

@(private)
isolated_worker_run :: proc(w: ^Isolated_Worker) {
	// A pool owned entirely by this thread.
	pool: http.Pool
	http.pool_init(&pool)
	defer http.pool_destroy(&pool)

	c := http.DEFAULT_CLIENT
	c.pool = &pool

	for _ in 0 ..< w.requests {
		arena: virtual.Arena
		if virtual.arena_init_growing(&arena) != nil { continue }

		t0 := time.now()
		res, err := http.client_get(&c, w.url, virtual.arena_allocator(&arena))
		elapsed := time.since(t0)
		good := err == .None && res.status == .OK && res.body == "pong"

		sync.mutex_lock(w.mutex)
		if good {
			w.ok += 1
		} else {
			w.failures += 1
			if w.first_err == .None { w.first_err = err }
			if w.slowest < elapsed { w.slowest = elapsed }
		}
		sync.mutex_unlock(w.mutex)

		virtual.arena_destroy(&arena)
	}
}

@(private)
run_pool_workers_isolated :: proc(
	t: ^testing.T,
	threads: int,
	per_thread: int,
) -> (ok: int, failures: int, first_err: http.Client_Error, slowest: time.Duration) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)
	http.router_handle_proc(&r, "GET /ping", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, "pong")
	})

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	url := strings.builder_make(context.allocator)
	defer strings.builder_destroy(&url)
	strings.write_string(&url, "http://127.0.0.1:")
	strings.write_int(&url, int(ts.endpoint.port))
	strings.write_string(&url, "/ping")

	mutex: sync.Mutex
	shared := Isolated_Worker{
		url      = strings.to_string(url),
		requests = per_thread,
		mutex    = &mutex,
	}

	workers := make([]^thread.Thread, threads, context.allocator)
	defer delete(workers)

	for i in 0 ..< threads {
		workers[i] = thread.create_and_start_with_poly_data(&shared, isolated_worker_run)
	}
	for i in 0 ..< threads {
		thread.join(workers[i])
		thread.destroy(workers[i])
	}

	return shared.ok, shared.failures, shared.first_err, shared.slowest
}

/*
Handler state shared across connection threads.

`handler_from_poly` hands the same pointer to every connection, and the server
runs each connection on its own thread, so a handler body runs concurrently with
itself.

This test demonstrates the synchronized pattern end to end: every request is
served and every increment is counted. It deliberately does NOT claim to catch
the unsynchronized version — measured loss is around one update in five thousand,
so at any load small enough to belong in a test suite the plain `+= 1` passes
too. Making the race reliably observable needs far more traffic than a unit test
should generate, so the guarantee here is "the documented pattern works", not
"the undocumented one is caught".
*/
@(private)
Atomic_Counter :: struct {
	hits: int,
}

@(test)
test_handler_state_atomic_is_exact :: proc(t: ^testing.T) {
	counter := new(Atomic_Counter, context.allocator)
	defer free(counter)

	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)
	http.router_handle(&r, "GET /ping", http.handler_from_poly(counter,
		proc(c: ^Atomic_Counter, req: ^http.Request, res: ^http.Response) {
			sync.atomic_add(&c.hits, 1)
			http.respond_plain(res, .OK, "pong")
		}))

	ts: http.Test_Server
	if err := http.test_server_start(&ts, http.router_handler(&r)); err != nil {
		testing.fail_now(t, "could not start test server")
	}
	defer http.test_server_stop(&ts)

	url := strings.builder_make(context.allocator)
	defer strings.builder_destroy(&url)
	strings.write_string(&url, "http://127.0.0.1:")
	strings.write_int(&url, int(ts.endpoint.port))
	strings.write_string(&url, "/ping")

	THREADS    :: 8
	PER_THREAD :: 40

	mutex: sync.Mutex
	shared := Pool_Worker{
		url      = strings.to_string(url),
		requests = PER_THREAD,
		mutex    = &mutex,
	}

	workers := make([]^thread.Thread, THREADS, context.allocator)
	defer delete(workers)
	for i in 0 ..< THREADS {
		workers[i] = thread.create_and_start_with_poly_data(&shared, pool_worker_run)
	}
	for i in 0 ..< THREADS {
		thread.join(workers[i])
		thread.destroy(workers[i])
	}

	// Every request served, and every increment observed.
	testing.expect_value(t, shared.ok, THREADS * PER_THREAD)
	testing.expect_value(t, sync.atomic_load(&counter.hits), THREADS * PER_THREAD)
}
