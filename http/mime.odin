package http

/*
Content types by file extension.

Only the types worth serving from a static directory are listed. An unknown
extension deliberately falls back to application/octet-stream rather than
guessing by sniffing content: a wrong guess of text/html on user-uploaded data
is a stored-XSS vector, and "download it" is the safe failure mode.
*/
mime_by_extension :: proc(path: string) -> string {
	ext := path_extension(path)
	if len(ext) == 0 { return DEFAULT_CONTENT_TYPE }

	// Extensions are compared case-insensitively; ".PNG" is still an image.
	switch {
	case equal_fold(ext, "html"), equal_fold(ext, "htm"):
		return "text/html; charset=utf-8"
	case equal_fold(ext, "css"):
		return "text/css; charset=utf-8"
	case equal_fold(ext, "js"), equal_fold(ext, "mjs"):
		return "text/javascript; charset=utf-8"
	case equal_fold(ext, "json"):
		return "application/json"
	case equal_fold(ext, "xml"):
		return "application/xml"
	case equal_fold(ext, "txt"), equal_fold(ext, "md"):
		return "text/plain; charset=utf-8"
	case equal_fold(ext, "csv"):
		return "text/csv; charset=utf-8"

	case equal_fold(ext, "png"):
		return "image/png"
	case equal_fold(ext, "jpg"), equal_fold(ext, "jpeg"):
		return "image/jpeg"
	case equal_fold(ext, "gif"):
		return "image/gif"
	case equal_fold(ext, "webp"):
		return "image/webp"
	case equal_fold(ext, "avif"):
		return "image/avif"
	case equal_fold(ext, "ico"):
		return "image/x-icon"
	// SVG is served as an image but is a script-capable document in browsers.
	// Callers serving untrusted uploads should set a restrictive CSP.
	case equal_fold(ext, "svg"):
		return "image/svg+xml"

	case equal_fold(ext, "woff"):
		return "font/woff"
	case equal_fold(ext, "woff2"):
		return "font/woff2"
	case equal_fold(ext, "ttf"):
		return "font/ttf"
	case equal_fold(ext, "otf"):
		return "font/otf"

	case equal_fold(ext, "mp4"):
		return "video/mp4"
	case equal_fold(ext, "webm"):
		return "video/webm"
	case equal_fold(ext, "mp3"):
		return "audio/mpeg"
	case equal_fold(ext, "ogg"):
		return "audio/ogg"
	case equal_fold(ext, "wav"):
		return "audio/wav"

	case equal_fold(ext, "pdf"):
		return "application/pdf"
	case equal_fold(ext, "zip"):
		return "application/zip"
	case equal_fold(ext, "gz"):
		return "application/gzip"
	case equal_fold(ext, "wasm"):
		return "application/wasm"
	}

	return DEFAULT_CONTENT_TYPE
}

DEFAULT_CONTENT_TYPE :: "application/octet-stream"

/*
Returns the extension without its dot, or "" if there is none.

A dot in a directory component does not count, and a leading dot on the final
component means a dotfile rather than an extension.
*/
@(private)
path_extension :: proc(path: string) -> string {
	last_slash := -1
	for i := len(path) - 1; i >= 0; i -= 1 {
		if path[i] == '/' {
			last_slash = i
			break
		}
	}

	name := path[last_slash + 1:]
	for i := len(name) - 1; i > 0; i -= 1 {
		if name[i] == '.' { return name[i + 1:] }
	}
	return ""
}
