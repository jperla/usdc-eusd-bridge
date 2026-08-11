#!/usr/bin/env bash
#
# Runs this crate's tests. The straightforward command is
#
#     cargo test --offline -p mc-return
#
# and it is what you should use as soon as the workspace root manifest carries
#
#     [workspace]
#     exclude = ["vendor"]
#
# Without that line the workspace does not load AT ALL -- not this crate, not
# any crate that touches a vendored MobileCoin dependency:
#
#   error inheriting `rust-version` from workspace root manifest's
#   `workspace.package.rust-version`
#
# Cause: `vendor/mobilecoin` sits inside the bridge workspace's own directory,
# and a nested workspace does NOT shield its packages from the outer one.
# Cargo's workspace-root search for e.g. vendor/mobilecoin/crypto/hashes lands
# on bridge/Cargo.toml, which has no `workspace.package.rust-version`, so the
# vendored manifest's `rust-version = { workspace = true }` has nothing to
# inherit from. It is a property of the layout, not of the symlink: a real
# `git clone` into vendor/ (which scripts/setup.sh does) reproduces it exactly.
#
# The root manifest is not this component's to edit, so until it is fixed this
# script builds the same crate from a workspace root placed OUTSIDE the vendor
# tree. It mirrors the root manifest's [workspace.package] and
# [workspace.dependencies] verbatim; nothing about the crate changes.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="$(dirname "$HERE")"
REPO="$(cd "$CRATE/../.." && pwd)"

SHADOW="${MC_RETURN_SHADOW:-${TMPDIR:-/tmp}/mc-return-shadow}"
# `vendor` must be a SIBLING of the workspace root, not a child, or the outer
# workspace reclaims the vendored manifests all over again.
mkdir -p "$SHADOW/ws"
ln -sfn "$REPO/vendor" "$SHADOW/vendor"

rm -rf "$SHADOW/ws/mc-return"
mkdir -p "$SHADOW/ws/mc-return"
cp -R "$CRATE/Cargo.toml" "$CRATE/src" "$CRATE/tests" "$SHADOW/ws/mc-return/"
mkdir -p "$SHADOW/ws/mc-return/fixtures"

cat > "$SHADOW/ws/Cargo.toml" <<'EOF'
# Mirror of bridge/Cargo.toml. See scripts/test.sh for why this exists.
[workspace]
resolver = "2"
members = ["mc-return"]

[workspace.package]
version = "0.1.0"
edition = "2021"
publish = false

[workspace.dependencies]
mc-crypto-ring-signature = { path = "../vendor/mobilecoin/crypto/ring-signature", default-features = false, features = ["alloc"] }
mc-crypto-keys = { path = "../vendor/mobilecoin/crypto/keys", default-features = false, features = ["alloc"] }
mc-core-types = { path = "../vendor/mobilecoin/core/types", default-features = false }
mc-crypto-hashes = { path = "../vendor/mobilecoin/crypto/hashes", default-features = false }
mc-crypto-digestible = { path = "../vendor/mobilecoin/crypto/digestible", default-features = false }
mc-blockchain-types = { path = "../vendor/mobilecoin/blockchain/types", default-features = false }
mc-transaction-core = { path = "../vendor/mobilecoin/transaction/core", default-features = false }

curve25519-dalek = { version = "4", default-features = false, features = ["alloc", "rand_core"] }
rand_core = { version = "0.6", features = ["std", "getrandom"] }
rand_chacha = "0.3"
zeroize = { version = "1.8", features = ["zeroize_derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = "0.4"
thiserror = "1"

[patch.crates-io]
schnorrkel-og = { git = "https://github.com/mobilecoinfoundation/schnorrkel.git", rev = "049bf9d30f3bbe072e2ad1b5eefdf0f3c851215e" }
EOF

cd "$SHADOW/ws"
cargo test --offline -p mc-return "$@"

# The fixture is a build product of the test run; put it back where the
# Solidity suite expects to find it.
if [ -f "$SHADOW/ws/mc-return/fixtures/return.json" ]; then
  cp "$SHADOW/ws/mc-return/fixtures/return.json" "$CRATE/fixtures/return.json"
  echo "fixture -> $CRATE/fixtures/return.json"
fi
