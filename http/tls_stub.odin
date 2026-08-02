#+build windows, freebsd, openbsd, netbsd, wasi, js, freestanding
package http

import "core:net"

/*
TLS placeholder for platforms with no backend.

The OpenSSL backend builds on Darwin and Linux only. Everywhere else the types
exist here so the server, client and pool compile unchanged, and every entry
point fails immediately with `.Context_Failed`.

The platform list is explicit rather than a negation because a build tag's
commas mean OR: `!darwin, !linux` is true on every platform, which would
redeclare the real backend rather than replace it.

That is the honest failure: a caller that configures TLS learns at setup that it
is unavailable, instead of getting a server that listens and then rejects every
handshake. Plaintext HTTP is fully supported.

A Windows backend would wrap SChannel behind the same `Transport` interface,
which is what makes this a stub rather than a fork.
*/

SSL     :: struct {}
SSL_CTX :: struct {}

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

TLS_Transport :: struct {
	using base: Transport,
	socket:     net.TCP_Socket,
	ssl:        ^SSL,
}

tls_config_init :: proc(
	cfg: ^TLS_Config,
	cert_path: string,
	key_path: string,
	min_version := 0,
) -> TLS_Error {
	return .Context_Failed
}

tls_config_destroy      :: proc(cfg: ^TLS_Config) {}
tls_config_enable_alpn  :: proc(cfg: ^TLS_Config) {}

tls_transport_init :: proc(
	tt: ^TLS_Transport,
	cfg: ^TLS_Config,
	socket: net.TCP_Socket,
	peer: net.Endpoint,
) -> bool {
	return false
}

tls_client_transport_init :: proc(
	tt: ^TLS_Transport,
	socket: net.TCP_Socket,
	peer: net.Endpoint,
	hostname: string,
) -> bool {
	return false
}

// Without TLS there is no ALPN, so h2 is never negotiated.
tls_negotiated_h2 :: proc(tt: ^TLS_Transport) -> bool { return false }

tls_version :: proc(tt: ^TLS_Transport) -> string { return "" }
