#!/usr/bin/env bash
# Prints a sorted "METHOD /path" list of every route registered across server.ts and the
# extracted route modules (src/routes/). Run before and after an extraction; the two outputs
# must be byte-identical — routes only move between files, they never appear or disappear.
set -euo pipefail
src="$(dirname "$0")/../src"
grep -rhaoE '\.(get|post|put|delete|patch)\("[^"]+"' "$src/server.ts" "$src/routes" \
  | sed -E 's/^\.//; s/\("/ /; s/"$//' \
  | sort || true
