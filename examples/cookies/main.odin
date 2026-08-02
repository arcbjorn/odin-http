package main

import "core:log"
import "core:net"

import http "../../http"

main :: proc() {
	context.logger = log.create_console_logger(.Info)

	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	http.router_handle_proc(&router, "GET /login", proc(req: ^http.Request, res: ^http.Response) {
		http.response_set_cookie(res, http.cookie_session("sid", "abc123"))
		http.response_set_cookie(res, http.Cookie{
			name = "theme", value = "dark", path = "/", max_age = 86400,
		})
		http.respond_plain(res, .OK, "logged in")
	})

	http.router_handle_proc(&router, "GET /whoami", proc(req: ^http.Request, res: ^http.Response) {
		sid, ok := http.request_cookie(req, "sid")
		if !ok {
			http.respond_status(res, .Unauthorized)
			return
		}
		http.respond_plain(res, .OK, sid)
	})

	http.router_handle_proc(&router, "GET /logout", proc(req: ^http.Request, res: ^http.Response) {
		http.response_delete_cookie(res, "sid")
		http.respond_plain(res, .OK, "logged out")
	})

	server: http.Server
	if err := http.server_listen(&server, {address = net.IP4_Loopback, port = 8082}); err != nil {
		log.fatalf("listen failed: %v", err)
	}
	log.info("cookies example on http://127.0.0.1:8082")
	http.server_serve(&server, http.router_handler(&router))
}
