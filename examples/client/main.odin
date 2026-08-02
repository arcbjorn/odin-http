package main

import "core:fmt"
import "core:mem/virtual"
import "core:os"

import http "../../http"

main :: proc() {
	url := "https://example.com/"
	if len(os.args) > 1 { url = os.args[1] }

	// The response borrows from this arena, so one destroy frees everything.
	arena: virtual.Arena
	if virtual.arena_init_growing(&arena) != nil {
		fmt.eprintln("out of memory")
		os.exit(1)
	}
	defer virtual.arena_destroy(&arena)

	c := http.DEFAULT_CLIENT
	res, err := http.client_get(&c, url, virtual.arena_allocator(&arena))
	if err != .None {
		fmt.eprintfln("request failed: %v", err)
		os.exit(1)
	}

	fmt.printfln("%v %s", int(res.status), http.status_text(res.status))

	// Headers are kept in wire order, so iterating the list preserves it.
	for entry in res.headers.entries {
		if len(entry.name) == 0 { continue }
		fmt.printfln("%s: %s", entry.name, entry.value)
	}

	fmt.printfln("\n%d bytes", len(res.body))
}
