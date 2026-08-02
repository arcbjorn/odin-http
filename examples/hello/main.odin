package main

import "core:fmt"
import "core:log"
import "core:net"

import http "../../http"

main :: proc() {
	context.logger = log.create_console_logger(.Info)

	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	http.router_handle_proc(&router, "GET /", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_html(res, .OK, "<h1>Hello from Odin</h1>")
	})

	http.router_handle_proc(&router, "GET /health", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_json(res, .OK, `{"status":"ok"}`)
	})

	// {name} captures one path segment.
	http.router_handle_proc(&router, "GET /greet/{name}", proc(req: ^http.Request, res: ^http.Response) {
		name := http.request_param(req, "name")
		http.respond_plain(res, .OK, fmt.tprintf("Hello, %s", name))
	})

	http.router_handle_proc(&router, "POST /echo", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, .OK, req.body)
	})

	handler := http.router_handler(&router)

	server: http.Server
	endpoint := net.Endpoint{address = net.IP4_Loopback, port = 8080}

	if err := http.server_listen(&server, endpoint); err != nil {
		log.fatalf("listen failed: %v", err)
	}

	log.info("listening on http://127.0.0.1:8080")
	http.server_serve(&server, handler)
}
