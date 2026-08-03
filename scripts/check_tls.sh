#!/bin/sh
# Verifies the TLS example serves HTTPS and negotiates h2 over ALPN.
#
# The TLS and h2-over-TLS paths have no unit coverage: OpenSSL is linked at
# build time and there is no FFI for generating a certificate, so a self
# contained Odin test cannot stand one up. Driving the real example with curl
# covers what matters — that a handshake completes, that ALPN offers h2 without
# the caller configuring anything, and that a client preferring HTTP/1.1 still
# gets served on the same port.
set -e
set +m

command -v openssl >/dev/null 2>&1 || { echo "openssl not found; skipping" >&2; exit 0; }

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"

work=".tls-check"
rm -rf "$work"
mkdir -p "$work"

pid=""
cleanup() {
	[ -n "$pid" ] && kill "$pid" 2>/dev/null
	wait 2>/dev/null || true
	rm -rf "$repo/$work"
}
trap cleanup EXIT

if curl -sk -o /dev/null --max-time 1 https://127.0.0.1:8443/ 2>/dev/null; then
	echo "FAIL  port 8443 is already in use" >&2
	exit 1
fi

openssl req -x509 -newkey rsa:2048 -keyout "$work/key.pem" -out "$work/cert.pem" \
	-days 1 -nodes -subj "/CN=127.0.0.1" >/dev/null 2>&1

odin build examples/tls -out:"$work/tls-example"
(cd "$work" && exec ./tls-example > tls.log 2>&1) &
pid=$!

ready=0
i=0
while [ $i -lt 40 ]; do
	if curl -sk -o /dev/null --max-time 2 https://127.0.0.1:8443/ 2>/dev/null; then
		ready=1
		break
	fi
	i=$((i + 1))
	sleep 0.25
done

if [ "$ready" != "1" ]; then
	echo "FAIL  TLS example did not start" >&2
	cat "$work/tls.log" >&2 || true
	exit 1
fi

fail=0

# ALPN must offer h2 with no extra configuration: tls_config_init enables it.
ver=$(curl -sk -o /dev/null -w "%{http_version}" --http2 https://127.0.0.1:8443/ --max-time 5)
if [ "$ver" = "2" ]; then
	echo "ok    ALPN negotiates h2"
else
	echo "FAIL  expected HTTP/2 over ALPN, got version $ver" >&2
	fail=1
fi

# A client that does not want h2 is served HTTP/1.1 on the same port.
ver11=$(curl -sk -o /dev/null -w "%{http_version}" --http1.1 https://127.0.0.1:8443/ --max-time 5)
if [ "$ver11" = "1.1" ]; then
	echo "ok    HTTP/1.1 falls back on the same port"
else
	echo "FAIL  expected HTTP/1.1 fallback, got version $ver11" >&2
	fail=1
fi

# The response itself must be intact over both.
body=$(curl -sk --http2 https://127.0.0.1:8443/ --max-time 5)
case "$body" in
	*"Hello over TLS"*) echo "ok    body intact over h2" ;;
	*) echo "FAIL  unexpected body over h2: $body" >&2; fail=1 ;;
esac

[ "$fail" = "0" ] || exit 1
echo "TLS and ALPN verified"
