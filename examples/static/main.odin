package main

import "core:log"
import "core:net"
import "core:os"

import http "../../http"

main :: proc() {
	context.logger = log.create_console_logger(.Info)

	root := "./public"
	if len(os.args) > 1 { root = os.args[1] }

	fs := http.DEFAULT_FILE_SERVER
	fs.root = root

	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	// The rest wildcard captures everything after the prefix, which the file
	// server uses as the path relative to its root.
	http.router_handle(&router, "GET /static/{path...}", http.file_server_handler(&fs))

	http.router_handle_proc(&router, "GET /", proc(req: ^http.Request, res: ^http.Response) {
		http.respond_html(res, .OK, `<a href="/static/index.html">static</a>`)
	})

	server: http.Server
	endpoint := net.Endpoint{address = net.IP4_Loopback, port = 8081}

	if err := http.server_listen(&server, endpoint); err != nil {
		log.fatalf("listen failed: %v", err)
	}

	log.infof("serving %s on http://127.0.0.1:8081/static/", root)
	http.server_serve(&server, http.router_handler(&router))
}
