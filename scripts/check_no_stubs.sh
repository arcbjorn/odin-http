#!/bin/sh
# Fails when library source contains a disabled guard.
#
# Mutation testing works by rewriting a check to `if false { ... }` and running
# the suite. A run interrupted between the rewrite and the restore leaves the
# library with a security check switched off, which then looks like ordinary
# source. This caught exactly that: an `if false` left in h2_conn.odin after an
# interrupted sweep.
set -e

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"

# `if false` has no legitimate use here; a deliberate one would be written as a
# constant with a name explaining it.
if grep -rn "if false" http/ 2>/dev/null; then
	echo "" >&2
	echo "a disabled guard is present in http/ — likely a leftover mutation" >&2
	exit 1
fi

echo "no disabled guards in http/"
