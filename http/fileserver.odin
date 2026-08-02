package http

import "core:os"
import "core:strings"
import "core:time"

/*
Static file serving.

The security model is deliberately layered, because path handling is where file
servers get exploited:

 1. The router decodes percent-escapes before matching.
 2. `url_path_is_safe` rejects traversal, NUL, and backslash on the DECODED path.
 3. The path is lexically cleaned, collapsing "." and any surviving "..".
 4. Only then is it joined to the root.

Step 3 exists because step 2 alone is not enough once symlinks and odd inputs
are involved, and step 2 must run on the decoded path because "%2e%2e%2f" only
becomes "../" after decoding. Checking before decoding is the classic bypass.
*/

File_Server :: struct {
	// Directory to serve from. Must not have a trailing slash.
	root:         string,
	// File served for a directory request, e.g. "index.html". Empty disables it.
	index:        string,
	// When set, a request that matches no file falls back to this file rather
	// than 404ing, which is what single-page apps need for client-side routing.
	spa_fallback: string,
	// Value for the Cache-Control header. Empty omits it.
	cache_control: string,
}

DEFAULT_FILE_SERVER :: File_Server {
	index         = "index.html",
	cache_control = "public, max-age=3600",
}

/*
Builds a Handler that serves files below `fs.root`.

Intended to be mounted on a rest-wildcard route, whose captured parameter names
the file:

	fs := http.DEFAULT_FILE_SERVER
	fs.root = "./public"
	http.router_handle(&r, "GET /static/{path...}", http.file_server_handler(&fs))
*/
file_server_handler :: proc(fs: ^File_Server) -> Handler {
	return Handler{
		proc_ = proc(h: ^Handler, req: ^Request, res: ^Response) {
			fs := cast(^File_Server)h.data
			file_server_serve(fs, req, res)
		},
		data = fs,
	}
}

/*
Serves the file named by the request.

Uses the router's rest-wildcard capture when present, otherwise the request
path, so the handler works whether or not it is mounted under a prefix.
*/
file_server_serve :: proc(fs: ^File_Server, req: ^Request, res: ^Response) {
	// Only safe methods make sense for static content.
	if req.method != .Get {
		headers_set(&res.headers, "allow", "GET, HEAD")
		respond_status(res, .Method_Not_Allowed)
		return
	}

	rel := file_server_request_path(req)

	full, ok := file_path_resolve(fs.root, rel, req.headers.allocator)
	if !ok {
		// A traversal attempt is reported as 404 rather than 403: confirming
		// that a path exists outside the root is itself information.
		respond_status(res, .Not_Found)
		return
	}

	info, err := os.stat(full, req.headers.allocator)
	if err != nil {
		file_server_not_found(fs, req, res)
		return
	}

	if info.type == .Directory {
		if len(fs.index) == 0 {
			// Directory listing is not implemented, and defaulting to it would
			// disclose filenames that were never meant to be enumerable.
			respond_status(res, .Not_Found)
			return
		}

		joined := strings.concatenate({rel, "/", fs.index}, req.headers.allocator)
		index_full, index_ok := file_path_resolve(fs.root, joined, req.headers.allocator)
		if !index_ok {
			respond_status(res, .Not_Found)
			return
		}

		index_info, index_err := os.stat(index_full, req.headers.allocator)
		if index_err != nil || index_info.type == .Directory {
			file_server_not_found(fs, req, res)
			return
		}

		full = index_full
		info = index_info
	}

	file_server_send(fs, req, res, full, info)
}

@(private)
file_server_not_found :: proc(fs: ^File_Server, req: ^Request, res: ^Response) {
	if len(fs.spa_fallback) == 0 {
		respond_status(res, .Not_Found)
		return
	}

	full, ok := file_path_resolve(fs.root, fs.spa_fallback, req.headers.allocator)
	if !ok {
		respond_status(res, .Not_Found)
		return
	}

	info, err := os.stat(full, req.headers.allocator)
	if err != nil || info.type == .Directory {
		respond_status(res, .Not_Found)
		return
	}

	file_server_send(fs, req, res, full, info)
}

/*
Sends a file, honouring conditional requests.

ETag and Last-Modified are both emitted so that a client can revalidate with
either. A matching validator produces 304, which by RFC 9110 15.4.5 carries the
validators but no body and no Content-Length; `response_write` enforces that.
*/
@(private)
file_server_send :: proc(fs: ^File_Server, req: ^Request, res: ^Response, path: string, info: os.File_Info) {
	allocator := req.headers.allocator

	etag := file_etag(info, allocator)
	modified := file_modified_time(info, allocator)

	headers_set(&res.headers, "etag", etag)
	headers_set(&res.headers, "last-modified", modified)
	if len(fs.cache_control) > 0 {
		headers_set(&res.headers, "cache-control", fs.cache_control)
	}
	// Prevents a browser from overriding our Content-Type by sniffing, which is
	// what turns an uploaded .txt into executable HTML.
	headers_set(&res.headers, "x-content-type-options", "nosniff")

	if file_not_modified(req, etag, modified) {
		res.status = .Not_Modified
		return
	}

	data, err := os.read_entire_file_from_path(path, allocator)
	if err != nil {
		respond_status(res, .Internal_Server_Error)
		return
	}

	headers_set(&res.headers, "content-type", mime_by_extension(path))
	res.status = .OK
	response_write_bytes(res, data)
}

/*
Evaluates conditional request headers.

If-None-Match takes precedence over If-Modified-Since per RFC 9110 13.1.3, since
an entity tag is a strictly stronger validator than a one-second-resolution
timestamp.
*/
@(private)
file_not_modified :: proc(req: ^Request, etag: string, modified: string) -> bool {
	if inm, ok := headers_get(req.headers, "if-none-match"); ok {
		// "*" matches any existing representation.
		if trim_ows(inm) == "*" { return true }
		return etag_list_matches(inm, etag)
	}

	if ims, ok := headers_get(req.headers, "if-modified-since"); ok {
		// Timestamps have one-second resolution, so equality is the correct
		// test for "not modified since".
		return trim_ows(ims) == modified
	}

	return false
}

/*
Reports whether a comma-separated If-None-Match list contains the tag.

Weak comparison is used (RFC 9110 8.8.3.2), so a "W/" prefix on either side is
ignored: for cache revalidation, semantic equivalence is the right bar.
*/
@(private)
etag_list_matches :: proc(list: string, etag: string) -> bool {
	want := strip_weak_prefix(etag)

	start := 0
	for i := 0; i <= len(list); i += 1 {
		if i != len(list) && list[i] != ',' { continue }

		candidate := strip_weak_prefix(trim_ows(list[start:i]))
		if candidate == want { return true }
		start = i + 1
	}
	return false
}

@(private)
strip_weak_prefix :: proc(etag: string) -> string {
	if strings.has_prefix(etag, "W/") { return etag[2:] }
	return etag
}

/*
Builds an entity tag from the file's size and modification time.

This is a weak validator: it detects a changed file without hashing contents,
which would mean reading every byte on every request. Two writes within the same
nanosecond that preserve size would collide, which does not happen in practice
for served static assets.
*/
@(private)
file_etag :: proc(info: os.File_Info, allocator := context.temp_allocator) -> string {
	b := strings.builder_make(allocator)
	strings.write_string(&b, `W/"`)
	strings.write_int(&b, int(info.size))
	strings.write_byte(&b, '-')
	strings.write_i64(&b, time.to_unix_nanoseconds(info.modification_time), 16)
	strings.write_byte(&b, '"')
	return strings.to_string(b)
}

@(private)
file_modified_time :: proc(info: os.File_Info, allocator := context.temp_allocator) -> string {
	buf := make([]byte, DATE_LENGTH, allocator)
	return date_write(buf, info.modification_time)
}

/*
Returns the path the request names, relative to the server root.

Prefers the router's rest-wildcard capture so that a handler mounted at
"/static/{path...}" strips the prefix automatically.
*/
@(private)
file_server_request_path :: proc(req: ^Request) -> string {
	if rest, ok := params_rest(req.params); ok { return rest }
	return request_path(req)
}

/*
Resolves a request-relative path against a root directory.

Returns false when the path escapes the root. The lexical clean happens before
the join, so ".." can never reach the filesystem.
*/
file_path_resolve :: proc(root: string, rel: string, allocator := context.temp_allocator) -> (full: string, ok: bool) {
	// Normalize to a rooted path so the checks have a single shape to reason
	// about.
	rooted := rel
	if len(rooted) == 0 || rooted[0] != '/' {
		rooted = strings.concatenate({"/", rel}, allocator)
	}

	// Reject bytes that are dangerous regardless of position (NUL, backslash)
	// before doing anything else. Traversal is NOT judged here: "/a/b/../c" is
	// perfectly legitimate and only means something after cleaning.
	if !path_has_safe_bytes(rooted) { return "", false }

	cleaned, escaped := path_clean_checked(rooted, allocator)

	// `path_clean` would clamp an escaping path back inside the root, which is
	// safe but silently serves a different file than the one requested. Refuse
	// instead, so a traversal attempt shows up as a 404 rather than succeeding
	// against something unintended.
	if escaped { return "", false }

	// Defence in depth: a surviving ".." would mean the cleaner failed.
	if !url_path_is_safe(cleaned) { return "", false }

	if cleaned == "/" {
		return root, true
	}
	return strings.concatenate({root, cleaned}, allocator), true
}

/*
Lexically cleans an absolute path.

Removes "." segments, resolves ".." against earlier segments, and collapses
repeated slashes. Purely lexical: the filesystem is never consulted, so this
cannot be raced and cannot follow a symlink.

A ".." that would rise above the root is dropped rather than escaping, matching
how browsers and `path.Clean` in Go behave.
*/
path_clean :: proc(path: string, allocator := context.temp_allocator) -> string {
	cleaned, _ := path_clean_checked(path, allocator)
	return cleaned
}

/*
Like `path_clean`, but also reports whether any ".." segment tried to rise above
the root and was dropped.

Callers resolving a path against a directory need this distinction: clamping is
safe but silently changes which file is named, so a file server should refuse
rather than serve the clamped result.
*/
path_clean_checked :: proc(path: string, allocator := context.temp_allocator) -> (cleaned: string, escaped: bool) {
	if len(path) == 0 { return "/", false }

	// Segment boundaries into a stack of [start, end) ranges, so the result can
	// be built in one pass with no intermediate strings.
	starts := make([dynamic]int, 0, 16, allocator)
	ends   := make([dynamic]int, 0, 16, allocator)

	i := 0
	for i < len(path) {
		for i < len(path) && path[i] == '/' { i += 1 }
		if i >= len(path) { break }

		start := i
		for i < len(path) && path[i] != '/' { i += 1 }
		seg := path[start:i]

		switch seg {
		case ".":
			// No-op segment.
		case "..":
			if len(starts) > 0 {
				pop(&starts)
				pop(&ends)
			} else {
				// Already at the root, so this ".." would escape. Dropping it
				// keeps the result contained, but the caller is told.
				escaped = true
			}
		case:
			append(&starts, start)
			append(&ends, i)
		}
	}

	if len(starts) == 0 { return "/", escaped }

	total := 0
	for idx in 0..<len(starts) {
		total += 1 + (ends[idx] - starts[idx])
	}

	buf := make([]byte, total, allocator)
	w := 0
	for idx in 0..<len(starts) {
		buf[w] = '/'
		w += 1
		copy(buf[w:], path[starts[idx]:ends[idx]])
		w += ends[idx] - starts[idx]
	}
	return string(buf[:w]), escaped
}
