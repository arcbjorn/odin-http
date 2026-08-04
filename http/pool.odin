package http

import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "core:time"

/*
A pool of idle client connections, keyed by origin.

Opening a connection dominates the cost of a small request. Measured against
example.com over five sequential requests, pooling cut the per-request time from
20-105 ms to 9-17 ms; the spread is the network path, so the ratio is the claim
rather than either figure. Nearly all of the difference is connection setup —
over TLS, mostly the handshake — which a pooled connection pays once instead of
per request.

Keyed by scheme, host and port together — a connection to https://example.com
cannot serve http://example.com or another port.

Safe to share between threads. A plain mutex around a list: contention is
negligible against a network round trip, so a lock-free structure would buy
nothing measurable.
*/
Pool :: struct {
	entries:   [dynamic]Pool_Entry,
	mutex:     sync.Mutex,
	allocator: mem.Allocator,

	// Maximum idle connections kept. Beyond this the oldest is closed, so a
	// client that talks to many hosts cannot accumulate sockets without bound.
	max_idle:  int,
	// How long an idle connection may sit before it is discarded. Servers close
	// idle connections on their own schedule, so holding one indefinitely means
	// eventually handing out a dead socket.
	idle_timeout: time.Duration,
}

// Bounds a TLS handshake against an unresponsive host. Generous enough for a
// slow link, short enough that a mute peer cannot hold a thread indefinitely.
DEFAULT_HANDSHAKE_TIMEOUT :: 15 * time.Second

DEFAULT_POOL_MAX_IDLE     :: 32
DEFAULT_POOL_IDLE_TIMEOUT :: 60 * time.Second

@(private)
Pool_Entry :: struct {
	// Origin this connection belongs to, owned by the pool's allocator.
	origin:    string,
	conn:      ^Pooled_Conn,
	idle_since: time.Time,
}

/*
A connection that outlives a single request.

Heap-allocated because a pooled connection must survive the stack frame that
created it. The transport pointer refers into this struct, so the whole thing
moves together.
*/
Pooled_Conn :: struct {
	transport: ^Transport,
	plain:     Plain_Transport,
	tls:       TLS_Transport,
	is_tls:    bool,
	// Cleared when the peer signals it will close, so the connection is not
	// returned to the pool after the response that said so.
	reusable:  bool,
}

pool_init :: proc(p: ^Pool, allocator := context.allocator) {
	p.allocator    = allocator
	p.entries.allocator = allocator
	p.max_idle     = DEFAULT_POOL_MAX_IDLE
	p.idle_timeout = DEFAULT_POOL_IDLE_TIMEOUT
}

/*
Closes every pooled connection.

Must be called before the pool's allocator goes away, or the sockets leak.
*/
pool_destroy :: proc(p: ^Pool) {
	sync.mutex_lock(&p.mutex)
	defer sync.mutex_unlock(&p.mutex)

	for entry in p.entries {
		pooled_conn_close(entry.conn, p.allocator)
		delete(entry.origin, p.allocator)
	}
	delete(p.entries)
	p.entries = nil
}

/*
Builds the origin key for a URL.

Includes the scheme so a plaintext and a TLS connection to the same host:port
never share a slot.
*/
@(private)
pool_origin_key :: proc(u: Client_URL, allocator: mem.Allocator) -> string {
	b := strings.builder_make(allocator)
	strings.write_string(&b, u.scheme)
	strings.write_string(&b, "://")
	strings.write_string(&b, u.host)
	strings.write_byte(&b, ':')
	strings.write_int(&b, u.port)
	return strings.to_string(b)
}

/*
Takes an idle connection for `origin`, or nil if there is none.

Expired entries encountered along the way are closed rather than returned: a
server that has already hung up would otherwise surface as a failed request the
caller cannot distinguish from a real error.
*/
@(private)
pool_take :: proc(p: ^Pool, origin: string) -> ^Pooled_Conn {
	sync.mutex_lock(&p.mutex)
	defer sync.mutex_unlock(&p.mutex)

	now := time.now()

	// Search from the back: the most recently returned connection is the most
	// likely to still be open.
	for i := len(p.entries) - 1; i >= 0; i -= 1 {
		entry := p.entries[i]

		if time.diff(entry.idle_since, now) > p.idle_timeout {
			pooled_conn_close(entry.conn, p.allocator)
			delete(entry.origin, p.allocator)
			ordered_remove(&p.entries, i)
			continue
		}

		if entry.origin != origin { continue }

		delete(entry.origin, p.allocator)
		ordered_remove(&p.entries, i)
		return entry.conn
	}

	return nil
}

/*
Returns a connection to the pool for reuse.

A connection the peer said it would close, or one whose response was delimited
by connection close, is closed instead: handing it out again would fail the next
request for no reason the caller could act on.
*/
@(private)
pool_put :: proc(p: ^Pool, origin: string, conn: ^Pooled_Conn) {
	if !conn.reusable {
		pooled_conn_close(conn, p.allocator)
		return
	}

	sync.mutex_lock(&p.mutex)
	defer sync.mutex_unlock(&p.mutex)

	// Evict the oldest rather than refusing to cache: the newest connection is
	// the one most likely to be reused next.
	for len(p.entries) >= p.max_idle && len(p.entries) > 0 {
		oldest := p.entries[0]
		pooled_conn_close(oldest.conn, p.allocator)
		delete(oldest.origin, p.allocator)
		ordered_remove(&p.entries, 0)
	}

	append(&p.entries, Pool_Entry{
		origin     = strings.clone(origin, p.allocator),
		conn       = conn,
		idle_since = time.now(),
	})
}

@(private)
pooled_conn_close :: proc(conn: ^Pooled_Conn, allocator: mem.Allocator) {
	if conn == nil { return }
	if conn.transport != nil {
		conn.transport->close()
		conn.transport = nil
	}
	free(conn, allocator)
}

/*
Opens a new connection to `u`, performing the TLS handshake when needed.

Returns nil on failure; the caller maps that to a specific `Client_Error`.
*/
@(private)
pooled_conn_dial :: proc(
	u: Client_URL,
	endpoint: net.Endpoint,
	allocator: mem.Allocator,
	handshake_timeout := DEFAULT_HANDSHAKE_TIMEOUT,
) -> (^Pooled_Conn, Client_Error) {
	socket, dial_err := net.dial_tcp(endpoint)
	if dial_err != nil { return nil, .Connect_Failed }

	conn := new(Pooled_Conn, allocator)
	conn.is_tls   = u.is_tls
	conn.reusable = true

	if u.is_tls {
		// The handshake must be bounded before it starts, for the same reason
		// it is on the server: `SSL_connect` reads from the peer, and a host
		// that accepts TCP and then never sends a ServerHello would otherwise
		// stall this thread forever. The caller's read timeout is only applied
		// after the handshake, so it cannot help here.
		net.set_option(socket, .Receive_Timeout, handshake_timeout)
		net.set_option(socket, .Send_Timeout, handshake_timeout)

		if !tls_client_transport_init(&conn.tls, socket, endpoint, u.host) {
			net.close(socket)
			free(conn, allocator)
			return nil, .TLS_Failed
		}
		conn.transport = &conn.tls.base
	} else {
		plain_transport_init(&conn.plain, socket, endpoint)
		conn.transport = &conn.plain.base
	}

	return conn, .None
}

// Returns the number of idle connections held, for tests and diagnostics.
pool_idle_count :: proc(p: ^Pool) -> int {
	sync.mutex_lock(&p.mutex)
	defer sync.mutex_unlock(&p.mutex)
	return len(p.entries)
}
