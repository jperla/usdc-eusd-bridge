#!/usr/bin/env bash
# Make contracts/node_modules exist and match contracts/package-lock.json.
#
# The Solidity suite compiles real bytecode and reports gas, so the compiler
# and the EVM are part of every result it prints. Installing from the lockfile
# rather than the ranges is what makes two machines print the same numbers.
set -euo pipefail
cd "$(dirname "$0")/../contracts"

if ! command -v npm >/dev/null 2>&1; then
  echo "scripts/node-deps.sh: npm is not on PATH; the Solidity suite needs it" >&2
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "=== installing contract dependencies (npm ci) ==="
  npm ci --no-audit --no-fund
  exit 0
fi

# node_modules already exists. It may predate the lockfile -- this repo was
# developed against a hand-assembled tree whose versions did not satisfy
# package.json -- so check rather than assume, and repair in place.
if ! npm ls --depth=0 >/dev/null 2>&1; then
  echo "=== contracts/node_modules does not match the lockfile; reinstalling ==="
  npm ci --no-audit --no-fund
fi
