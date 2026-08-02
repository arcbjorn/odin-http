package main

import "core:log"
import "core:net"
import "core:os"

import http "../../http"

main :: proc() {
	context.logger = log.create_console_logger(.Info)

	cert := "cert.pem"; key := "key.pem"
	if len(os.args) > 2 { cert = os.args[1]; key = os.args[2] }

	tls: http.TLS_Config
	if err := http.tls_config_init(&tls, cert, key); err != .None {
		log.fatalf("TLS setup failed: %v", err)
	}
	defer http.tls_config_destroy(&tls)

	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	http.router_handle_proc(&router, "GET /", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_html(res, .OK, "<h1>Hello over TLS</h1>")
	})

	opts := http.DEFAULT_SERVER_OPTS
	opts.tls = &tls

	server: http.Server
	if err := http.server_listen(&server, {address = net.IP4_Loopback, port = 8443}, opts); err != nil {
		log.fatalf("listen failed: %v", err)
	}
	log.info("https on https://127.0.0.1:8443")
	http.server_serve(&server, http.router_handler(&router))
}
