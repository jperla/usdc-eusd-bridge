#!/usr/bin/env bash
#
# Runs this crate's tests.
#
# The command you want is
#
#     cargo test --offline -p mc-return
#
# and it will be, as soon as the workspace root manifest is repaired. Three
# things stop it today, none of them in this crate, all of them in files this
# component does not own. This script is the smallest thing that works around
# them without touching those files, and it is the ONLY reason it exists.
#
#  1. The workspace does not load at all -- not this crate, not any crate that
#     touches a vendored MobileCoin dependency:
#
#       error inheriting `rust-version` from workspace root manifest's
#       `workspace.package.rust-version`
#
#     `vendor/mobilecoin` sits inside the bridge workspace's own directory, and
#     a nested workspace does NOT shield its packages from the outer one:
#     cargo's workspace-root search for vendor/mobilecoin/crypto/hashes lands on
#     bridge/Cargo.toml, which has no `workspace.package.rust-version`, so the
#     vendored `rust-version = { workspace = true }` has nothing to inherit.
#     It is a property of the layout, not of the symlink -- a real `git clone`
#     into vendor/, which scripts/setup.sh does, reproduces it exactly.
#     FIX: add `exclude = ["vendor"]` to the root `[workspace]`.
#
#  2. The root `[patch.crates-io]` carries only `schnorrkel-og`. MobileCoin's
#     own root patches five more, and patches do not compose across workspaces
#     -- they only take effect from the workspace being built. Without
#     `bulletproofs-og` and `serde_cbor`, mc-transaction-core does not resolve.
#     FIX: copy MobileCoin's `bulletproofs-og` and `serde_cbor` patch entries
#     into the root [patch.crates-io].
#
#  3. MobileCoin pins `nightly-2024-10-11` (vendor/mobilecoin/rust-toolchain.toml)
#     and means it: mc-common enables `hashbrown/nightly`, which needs
#     `min_specialization`. On the stable toolchain first on PATH here (1.97.1)
#     hashbrown 0.14.x fails to compile -- with RUSTC_BOOTSTRAP=1 it gets past
#     the feature gate only to hit "cannot specialize on trait `Copy`", which
#     modern rustc rejects outright. The pinned toolchain IS installed under
#     ~/.rustup/toolchains, so this script uses it directly. There is no rustup
#     shim on PATH, so RUSTC has to be pointed at it by hand or cargo picks up
#     the stable rustc next door.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="$(dirname "$HERE")"
REPO="$(cd "$CRATE/../.." && pwd)"

TOOLCHAIN="${MC_RETURN_TOOLCHAIN:-$HOME/.rustup/toolchains/nightly-2024-10-11-aarch64-apple-darwin}"
if [ ! -x "$TOOLCHAIN/bin/cargo" ]; then
  echo "toolchain not found: $TOOLCHAIN" >&2
  echo "MobileCoin pins $(cat "$REPO/vendor/mobilecoin/rust-toolchain.toml" | tr -d '\n')" >&2
  exit 1
fi

SHADOW="${MC_RETURN_SHADOW:-${TMPDIR:-/tmp}/mc-return-shadow}"
# `vendor` must be a SIBLING of the workspace root, not a child, or reason (1)
# above reclaims the vendored manifests all over again.
mkdir -p "$SHADOW/ws"
ln -sfn "$REPO/vendor" "$SHADOW/vendor"

rm -rf "$SHADOW/ws/mc-return"
mkdir -p "$SHADOW/ws/mc-return/fixtures"
cp -R "$CRATE/Cargo.toml" "$CRATE/src" "$CRATE/tests" "$SHADOW/ws/mc-return/"

cat > "$SHADOW/ws/Cargo.toml" <<'EOF'
# Mirror of bridge/Cargo.toml, plus the [patch.crates-io] entries the root is
# missing. See scripts/test.sh for why this file exists.
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
bulletproofs-og = { git = "https://github.com/mobilecoinfoundation/bulletproofs.git", rev = "9abfdc054d9ba65f1e185ea1e6eff3947ce879dc" }
serde_cbor = { git = "https://github.com/mobilecoinofficial/cbor", rev = "4c886a7c1d523aae1ec4aa7386f402cb2f4341b5" }
EOF

# Seed from MobileCoin's own lockfile. Resolving from scratch offline picks a
# yanked `elliptic-curve 0.13.5` for mc-sgx-dcap-types and dies; upstream's
# pins are the ones this rev is known to build under anyway.
[ -f "$SHADOW/ws/Cargo.lock" ] || cp "$REPO/vendor/mobilecoin/Cargo.lock" "$SHADOW/ws/Cargo.lock"

cd "$SHADOW/ws"
RUSTC="$TOOLCHAIN/bin/rustc" RUSTDOC="$TOOLCHAIN/bin/rustdoc" \
  "$TOOLCHAIN/bin/cargo" test --offline -p mc-return "$@"

# The fixture is a product of the test run; put it where the Solidity suite
# looks for it.
for f in return.json return-block-metadata.json; do
  if [ -f "$SHADOW/ws/mc-return/fixtures/$f" ]; then
    cp "$SHADOW/ws/mc-return/fixtures/$f" "$CRATE/fixtures/$f"
    echo "fixture -> $CRATE/fixtures/$f"
  fi
done
