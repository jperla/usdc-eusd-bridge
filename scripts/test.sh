#!/usr/bin/env bash
# Run every test in the repo: Rust workspace and Solidity contracts.
set -euo pipefail
cd "$(dirname "$0")/.."

# rustup may not be on PATH; rust-toolchain.toml is then not honoured, so
# resolve the pinned toolchain directly. The directory name carries the host
# triple, so glob rather than naming one -- a checkout on a different host
# still finds it.
for TC in "$HOME"/.rustup/toolchains/nightly-2024-10-11-*/bin; do
  if [ -d "$TC" ]; then
    export PATH="$TC:$PATH"
    break
  fi
done

# The workspace path-depends on vendor/mobilecoin. Without it cargo fails four
# `Caused by:` levels deep in a message that never names the fix, so say it.
if [ ! -d vendor/mobilecoin/crypto/hashes ]; then
  echo "vendor/mobilecoin is missing -- run ./scripts/setup.sh first." >&2
  echo "The Rust workspace path-depends on it at a pinned revision." >&2
  exit 1
fi

echo "=== rust ==="
cargo test --offline "$@"

echo
echo "=== contracts ==="
# The Solidity suite is a Node program with real dependencies. Install them
# from the lockfile if they are missing, so a fresh clone can run this script
# without a separate documented step that someone has to remember.
./scripts/node-deps.sh
cd contracts && node test/run.mjs
