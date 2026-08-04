package main

/*
Exercises client-side certificate verification against a local server.

Verification is the one client behaviour whose failure is silent: a client that
accepts any certificate still fetches pages correctly, so no functional test
notices. It cannot be a unit test either — it needs a real handshake against a
real certificate, which means a process, a port and OpenSSL.

Exits non-zero if a self-signed certificate is accepted, which is the regression
worth catching.
*/

import "core:fmt"
import "core:mem/virtual"
import "core:os"
import http "../../http"

main :: proc() {
	// The process exits below, so the arena is left for the OS to reclaim
	// rather than deferred: a defer before a diverging call is unreachable.
	arena: virtual.Arena
	_ = virtual.arena_init_growing(&arena)
	alloc := virtual.arena_allocator(&arena)

	url := "https://127.0.0.1:8443/"
	if len(os.args) > 1 { url = os.args[1] }

	c := http.DEFAULT_CLIENT
	_, err := http.client_get(&c, url, alloc)

	if err == .TLS_Failed {
		fmt.println("ok    self-signed certificate rejected")
		os.exit(0)
	}

	fmt.printfln("FAIL  expected TLS_Failed for a self-signed certificate, got %v", err)
	os.exit(1)
}
