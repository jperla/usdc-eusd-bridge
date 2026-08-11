#!/usr/bin/env bash
# Run every test in the repo: Rust workspace and Solidity contracts.
set -euo pipefail
cd "$(dirname "$0")/.."

# rustup may not be on PATH; rust-toolchain.toml is then not honoured, so
# resolve the pinned toolchain directly.
TC="$HOME/.rustup/toolchains/nightly-2024-10-11-aarch64-apple-darwin/bin"
if [ -d "$TC" ]; then export PATH="$TC:$PATH"; fi

echo "=== rust ==="
cargo test --offline "$@"

echo
echo "=== contracts ==="
cd contracts && node test/run.mjs
