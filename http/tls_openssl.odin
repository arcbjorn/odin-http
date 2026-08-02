//+build darwin, linux
package http

import "core:c"
import "core:log"
import "core:net"
import "core:strings"
import "core:time"

/*
A TLS transport backed by OpenSSL.

This is one backend behind the `Transport` interface, not a commitment to
OpenSSL. Odin has no TLS in core — the maintainers put a native implementation
at "a man year's worth of work to do well", citing constant-time RSA, ASN.1, and
the whole of WebPKI — and their stated near-term plan is a swappable backend
API. Nothing above `Transport` knows this file exists.

Only the server side is implemented. A client would additionally need
certificate verification against a trust store, which is the genuinely hard part
of TLS and is not something to half-do.

Linked against the system OpenSSL 3.x. The `+build` tag keeps Windows builds
from requiring it; a Windows backend would wrap SChannel behind the same
`Transport`.
*/

/*
macOS ships no system libssl — Apple removed it — so the library is named by
path there. Linux resolves `system:ssl` from the default search path.

If OpenSSL lives elsewhere, edit these paths or build with
`-define:ODIN_HTTP_OPENSSL_DIR=...`. This platform coupling is inherent to
depending on a C TLS library, and is precisely what a native Odin TLS stack
would remove.
*/
when ODIN_OS == .Darwin {
	// Apple removed libssl from the system, so it must be named by path. Odin
	// resolves foreign import paths relative to the package directory and has
	// no way to spell an absolute one, hence the leading `../` run: excess
	// segments clamp at the filesystem root, so this reaches /opt regardless of
	// where the project is checked out.
	//
	// This platform coupling is inherent to depending on a C TLS library and is
	// exactly what a native Odin TLS stack would remove. Adjust the tail of the
	// path for a non-Homebrew OpenSSL.
	foreign import ssl    "../../../../../../../../../../../../../../../../opt/homebrew/opt/openssl@3/lib/libssl.dylib"
	foreign import crypto "../../../../../../../../../../../../../../../../opt/homebrew/opt/openssl@3/lib/libcrypto.dylib"
} else {
	foreign import ssl    "system:ssl"
	foreign import crypto "system:crypto"
}

SSL_CTX :: struct {}
SSL     :: struct {}
SSL_METHOD :: struct {}

@(default_calling_convention = "c")
foreign ssl {
	TLS_server_method :: proc() -> ^SSL_METHOD ---

	SSL_CTX_new  :: proc(method: ^SSL_METHOD) -> ^SSL_CTX ---
	SSL_CTX_free :: proc(ctx: ^SSL_CTX) ---
	SSL_CTX_ctrl :: proc(ctx: ^SSL_CTX, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---

	SSL_CTX_use_certificate_chain_file :: proc(ctx: ^SSL_CTX, file: cstring) -> c.int ---
	SSL_CTX_use_PrivateKey_file        :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_CTX_check_private_key          :: proc(ctx: ^SSL_CTX) -> c.int ---
	SSL_CTX_set_cipher_list            :: proc(ctx: ^SSL_CTX, str: cstring) -> c.int ---

	SSL_new       :: proc(ctx: ^SSL_CTX) -> ^SSL ---
	SSL_free      :: proc(s: ^SSL) ---
	SSL_set_fd    :: proc(s: ^SSL, fd: c.int) -> c.int ---
	SSL_accept    :: proc(s: ^SSL) -> c.int ---
	SSL_read      :: proc(s: ^SSL, buf: rawptr, num: c.int) -> c.int ---
	SSL_write     :: proc(s: ^SSL, buf: rawptr, num: c.int) -> c.int ---
	SSL_shutdown  :: proc(s: ^SSL) -> c.int ---
	SSL_get_error :: proc(s: ^SSL, ret: c.int) -> c.int ---
	SSL_get_version :: proc(s: ^SSL) -> cstring ---
}

@(default_calling_convention = "c")
foreign crypto {
	ERR_get_error           :: proc() -> c.ulong ---
	ERR_error_string_n      :: proc(e: c.ulong, buf: [^]byte, len: c.size_t) ---
}

// `SSL_CTX_set_min_proto_version` is a macro over SSL_CTX_ctrl in the headers,
// so it has no exported symbol and the command number is inlined here.
@(private) SSL_CTRL_SET_MIN_PROTO_VERSION :: 123
@(private) TLS1_2_VERSION :: 0x0303
@(private) TLS1_3_VERSION :: 0x0304

@(private) SSL_FILETYPE_PEM :: 1

// SSL_get_error result codes.
@(private) SSL_ERROR_NONE       :: 0
@(private) SSL_ERROR_SSL        :: 1
@(private) SSL_ERROR_WANT_READ  :: 2
@(private) SSL_ERROR_WANT_WRITE :: 3
@(private) SSL_ERROR_ZERO_RETURN :: 6
@(private) SSL_ERROR_SYSCALL    :: 5

/*
A configured TLS server context.

One context is shared by every connection: it holds the certificate chain and
private key, which are immutable after setup and are read concurrently by
OpenSSL without external locking.
*/
TLS_Config :: struct {
	ctx: ^SSL_CTX,
}

TLS_Error :: enum u8 {
	None,
	Context_Failed,
	Certificate_Failed,
	Private_Key_Failed,
	Key_Mismatch,
}

/*
Loads a certificate chain and private key, both PEM.

TLS 1.2 is the enforced minimum: 1.0 and 1.1 are deprecated by RFC 8996 and
their cipher suites are broken in ways that matter. Callers wanting 1.3-only can
pass it explicitly.
*/
tls_config_init :: proc(cfg: ^TLS_Config, cert_path: string, key_path: string, min_version := TLS1_2_VERSION) -> TLS_Error {
	cfg.ctx = SSL_CTX_new(TLS_server_method())
	if cfg.ctx == nil { return .Context_Failed }

	SSL_CTX_ctrl(cfg.ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, c.long(min_version), nil)

	cert_c := strings.clone_to_cstring(cert_path, context.temp_allocator)
	key_c  := strings.clone_to_cstring(key_path, context.temp_allocator)

	if SSL_CTX_use_certificate_chain_file(cfg.ctx, cert_c) != 1 {
		log.errorf("TLS: certificate load failed: %s", tls_last_error())
		tls_config_destroy(cfg)
		return .Certificate_Failed
	}

	if SSL_CTX_use_PrivateKey_file(cfg.ctx, key_c, SSL_FILETYPE_PEM) != 1 {
		log.errorf("TLS: private key load failed: %s", tls_last_error())
		tls_config_destroy(cfg)
		return .Private_Key_Failed
	}

	// Catches a cert and key that were not issued together, which otherwise
	// fails per-connection at handshake time with a confusing error.
	if SSL_CTX_check_private_key(cfg.ctx) != 1 {
		log.errorf("TLS: key does not match certificate: %s", tls_last_error())
		tls_config_destroy(cfg)
		return .Key_Mismatch
	}

	return .None
}

tls_config_destroy :: proc(cfg: ^TLS_Config) {
	if cfg.ctx != nil {
		SSL_CTX_free(cfg.ctx)
		cfg.ctx = nil
	}
}

/*
A TLS-wrapped connection.

Embeds `Transport` so a `^TLS_Transport` is usable anywhere a `^Transport` is,
with the socket kept for timeouts — OpenSSL reads and writes through the fd, so
socket-level deadlines still apply.
*/
TLS_Transport :: struct {
	using base: Transport,
	socket:     net.TCP_Socket,
	ssl:        ^SSL,
}

/*
Performs the server-side handshake and wraps the connection.

Returns false if the handshake fails, which is routine: scanners, clients with
no shared cipher suite, and plain-HTTP requests to a TLS port all land here. The
caller closes the socket.
*/
tls_transport_init :: proc(
	tt: ^TLS_Transport,
	cfg: ^TLS_Config,
	socket: net.TCP_Socket,
	peer: net.Endpoint,
) -> bool {
	tt.socket = socket
	tt.peer   = peer

	tt.ssl = SSL_new(cfg.ctx)
	if tt.ssl == nil {
		log.errorf("TLS: session alloc failed: %s", tls_last_error())
		return false
	}

	if SSL_set_fd(tt.ssl, c.int(socket)) != 1 {
		log.errorf("TLS: could not attach socket: %s", tls_last_error())
		SSL_free(tt.ssl)
		tt.ssl = nil
		return false
	}

	if SSL_accept(tt.ssl) != 1 {
		// Logged at debug: a failed handshake is attacker-triggerable, so it
		// must not be a way to flood the error log.
		log.debugf("TLS: handshake failed: %s", tls_last_error())
		SSL_free(tt.ssl)
		tt.ssl = nil
		return false
	}

	tt.read = proc(t: ^Transport, buf: []byte) -> (n: int, ok: bool) {
		tt := cast(^TLS_Transport)t
		if len(buf) == 0 { return 0, true }

		got := SSL_read(tt.ssl, raw_data(buf), c.int(len(buf)))
		if got > 0 { return int(got), true }

		// A clean TLS close_notify is a normal end of connection, not an error.
		code := SSL_get_error(tt.ssl, got)
		if code != SSL_ERROR_ZERO_RETURN {
			log.debugf("TLS: read error %d", code)
		}
		return 0, false
	}

	tt.write = proc(t: ^Transport, buf: []byte) -> (n: int, ok: bool) {
		tt := cast(^TLS_Transport)t
		if len(buf) == 0 { return 0, true }

		sent := SSL_write(tt.ssl, raw_data(buf), c.int(len(buf)))
		if sent > 0 { return int(sent), true }

		log.debugf("TLS: write error %d", SSL_get_error(tt.ssl, sent))
		return 0, false
	}

	tt.close = proc(t: ^Transport) {
		tt := cast(^TLS_Transport)t
		if tt.ssl != nil {
			// Sends close_notify so the peer can distinguish a clean shutdown
			// from a truncation attack. One attempt only: a peer that has
			// already vanished must not stall the connection thread.
			SSL_shutdown(tt.ssl)
			SSL_free(tt.ssl)
			tt.ssl = nil
		}
		net.close(tt.socket)
	}

	tt.set_timeout = proc(t: ^Transport, recv: bool, d: time.Duration) {
		tt := cast(^TLS_Transport)t
		// OpenSSL reads and writes through the fd, so socket deadlines still
		// bound a slow peer.
		net.set_option(tt.socket, .Receive_Timeout if recv else .Send_Timeout, d)
	}

	return true
}

// Returns the negotiated protocol version, e.g. "TLSv1.3".
tls_version :: proc(tt: ^TLS_Transport) -> string {
	if tt.ssl == nil { return "" }
	return string(SSL_get_version(tt.ssl))
}

/*
Drains and formats the most recent OpenSSL error.

The error queue is per-thread and must be emptied, or a later unrelated failure
reports this one instead.
*/
@(private)
tls_last_error :: proc() -> string {
	code := ERR_get_error()
	if code == 0 { return "unknown error" }

	buf: [256]byte
	ERR_error_string_n(code, raw_data(buf[:]), len(buf))

	// Drain the rest of the queue so it cannot leak into a later report.
	for ERR_get_error() != 0 {}

	return strings.clone_from_cstring(cstring(raw_data(buf[:])), context.temp_allocator)
}
