#!/bin/sh
# Compiles the README's quickstart against the real package.
#
# Documentation that no longer compiles is a defect: it is the first code a user
# runs. Extracting the block keeps the README itself the single source, rather
# than a copy under examples/ that can drift the other way.
set -e

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"

# Odin resolves import paths relative to the importing file, so the scratch
# package has to live inside the checkout rather than in /tmp.
work=".readme-check"
rm -rf "$work"
mkdir -p "$work"
trap 'rm -rf "$repo/$work"' EXIT

awk '/^```odin$/{n++; if (n==1) {inblock=1; next}} /^```$/{inblock=0} inblock' README.md \
	> "$work/main.odin"

if [ ! -s "$work/main.odin" ]; then
	echo "could not extract the quickstart from README.md" >&2
	exit 1
fi

# The README shows an illustrative import path; point it at this checkout.
sed -i.bak 's|"path/to/http"|"../http"|' "$work/main.odin"
rm -f "$work/main.odin.bak"

odin build "$work" -out:"$work/bin"
echo "README quickstart compiles"
