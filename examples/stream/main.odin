package main

import "core:fmt"
import "core:log"
import "core:net"

import http "../../http"

/*
Streaming a response whose length is not known up front.

The handler sets a stream callback instead of a body; the server frames each
write as an HTTP chunk and terminates the body when the callback returns. No
part of the response is buffered, so a producer that generates gigabytes uses
the same memory as one that generates a single line.
*/

Feed :: struct {
	rows: int,
}

main :: proc() {
	context.logger = log.create_console_logger(.Info)

	feed := Feed{rows = 10_000}

	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	http.router_handle(&router, "GET /export.csv", http.handler_from_poly(&feed,
		proc(f: ^Feed, req: ^http.Request, res: ^http.Response) {
			http.headers_set(&res.headers, "content-type", "text/csv; charset=utf-8")
			http.response_set_stream(res, f, proc(w: ^http.Stream_Writer, f: ^Feed) {
				http.stream_write_string(w, "id,value\n")

				for i in 0 ..< f.rows {
					// tprintf reuses the temp allocator, so this loop does not
					// grow memory no matter how many rows are produced.
					http.stream_write_string(w, fmt.tprintf("%d,%d\n", i, i * i))

					if i % 1000 == 0 { free_all(context.temp_allocator) }
				}
			})
		},
	))

	http.router_handle_proc(&router, "GET /", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_html(res, .OK, `<a href="/export.csv">download 10k rows</a>`)
	})

	server: http.Server
	endpoint := net.Endpoint{address = net.IP4_Loopback, port = 8083}

	if err := http.server_listen(&server, endpoint); err != nil {
		log.fatalf("listen failed: %v", err)
	}

	log.info("streaming example on http://127.0.0.1:8083")
	http.server_serve(&server, http.router_handler(&router))
}
