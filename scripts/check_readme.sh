#!/bin/sh
# Fails when the README's test count no longer matches the suite.
#
# A number in prose drifts silently on every commit that adds a test, and a
# README that overstates coverage is worse than one that omits it. This is the
# cheapest way to keep the claim honest.
set -e

actual=$(odin test tests 2>&1 | sed -n 's/^Finished \([0-9][0-9]*\) tests.*/\1/p')
claimed=$(sed -n 's/^\*\*Status:\*\* \([0-9][0-9]*\) tests.*/\1/p' README.md)

if [ -z "$actual" ]; then
	echo "could not determine the suite's test count" >&2
	exit 1
fi
if [ -z "$claimed" ]; then
	echo "could not find the test count in README.md" >&2
	exit 1
fi
if [ "$actual" != "$claimed" ]; then
	echo "README claims $claimed tests; the suite has $actual" >&2
	exit 1
fi
echo "README test count matches the suite ($actual)"
