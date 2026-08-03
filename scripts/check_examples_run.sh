#!/bin/sh
# Starts each network example and checks it actually serves a request.
#
# `odin build` only proves an example compiles. An example that binds the wrong
# port, registers a route it does not serve, or dies on startup still builds
# cleanly — and it is the first thing a user runs, so a silent break there costs
# more than a failing unit test.
set -e
set +m

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"

work=".example-check"
rm -rf "$work"
mkdir -p "$work"

pids=""
cleanup() {
	for p in $pids; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	rm -rf "$repo/$work"
}
trap cleanup EXIT

fail=0

# name:port:path:expected-status. The client example is excluded: it reaches the
# public internet rather than listening, so it is not a hermetic check.
#
# `static` is checked on a path served from disk rather than on "/", which is an
# inline handler: requesting "/" passes even when the served directory is
# missing entirely, which is exactly how examples/static/public went unnoticed.
for spec in "hello:8080:/:200" "static:8081:/static/index.html:200" "cookies:8082:/login:200" "stream:8083:/export.csv:200"; do
	name=${spec%%:*}; rest=${spec#*:}
	port=${rest%%:*}; rest=${rest#*:}
	path=${rest%%:*}; want=${rest#*:}

	# A listener left over from an earlier run would answer on this port and
	# make the check pass without ever starting the example under test.
	if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/" 2>/dev/null; then
		echo "FAIL  $name: port $port is already in use" >&2
		exit 1
	fi

	odin build "examples/$name" -out:"$work/$name"

	# `static` serves from a directory relative to its working directory. `exec`
	# replaces the subshell so $! is the server itself and cleanup can kill it.
	(cd "examples/$name" && exec "$repo/$work/$name" > "$repo/$work/$name.log" 2>&1) &
	pids="$pids $!"

	ready=0
	i=0
	while [ $i -lt 40 ]; do
		code=$(curl -s -o /dev/null -w "%{http_code}" \
			"http://127.0.0.1:$port$path" --max-time 2 2>/dev/null) || code=000
		[ -n "$code" ] || code=000
		if [ "$code" = "$want" ]; then ready=1; break; fi
		i=$((i + 1))
		sleep 0.25
	done

	if [ "$ready" = "1" ]; then
		echo "ok    $name: $path -> $want"
	else
		echo "FAIL  $name: $path expected $want, got ${code:-none}" >&2
		cat "$work/$name.log" >&2 || true
		fail=1
	fi
done

[ "$fail" = "0" ] || exit 1
echo "all network examples serve"
