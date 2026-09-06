#!/usr/bin/env bash
# Component acceptance for docs/FINAL-PLAN.md, in one command.
#
#   1. handle a USDC deposit into an Ethereum escrow account
#   2. upon verified USDC deposit, release eUSD from the eUSD escrow wallet
#   3. when eUSD is returned, release USDC from the Ethereum escrow account
#
# Leg 2 is on MobileCoin and can only be established against MobileCoin's own
# code, so its signing checks run first, in Rust. Legs 1 and 3 then run against
# a real EVM using a proof Rust produced from MobileCoin types. This does not
# run a live deposit observer, distributed signer, or MobileCoin submission.
set -euo pipefail
cd "$(dirname "$0")/.."

# The workspace needs the pinned nightly (mc-common hardcodes hashbrown's
# nightly feature). Match setup.sh's cargo selection for the m2d spike's
# separate lockfile/cache; rustc and rustdoc still come from the pinned PATH.
DEFAULT_CARGO="$(command -v cargo || true)"
for TC in "$HOME"/.rustup/toolchains/nightly-2024-10-11-*/bin; do
  if [ -d "$TC" ]; then
    export PATH="$TC:$PATH"
    break
  fi
done
# Explicit executable overrides also let the runner's failure paths be tested
# without compiling Rust or executing the Solidity suite.
BRIDGE_CARGO="${BRIDGE_CARGO:-cargo}"
BRIDGE_SPIKE_CARGO="${BRIDGE_SPIKE_CARGO:-${DEFAULT_CARGO:-cargo}}"

rule() { printf '%.0s=' {1..72}; echo; }

rule
echo "LEG 2 — the composite spend key, against MobileCoin's own verifier"
rule
echo
echo "\$ cargo test --offline -p two-cohort"
"$BRIDGE_CARGO" test --offline --locked -p two-cohort
echo
echo "\$ cargo test --offline   # in proofs/executable/m2d-two-cohort"
( cd proofs/executable/m2d-two-cohort \
    && "$BRIDGE_SPIKE_CARGO" test --offline --locked )
echo
echo "The load-bearing case is an_owner_only_scalar_is_rejected_by_the_stock_verifier:"
echo "signing SUCCEEDS with a scalar missing the gate cohort's share, and"
echo "MobileCoin's unmodified RingMLSAG::verify returns exactly InvalidSignature."
echo

rule
echo "THE RETURN PROOF — built by MobileCoin's own crates"
rule
echo
echo "\$ cargo test --offline -p mc-return"
"$BRIDGE_CARGO" test --offline --locked -p mc-return
echo
python3 - <<'PY'
import json
d = json.load(open('crates/mc-return/fixtures/return.json'))
q = d['quorum']
print(f"  block index      {d['anchor_block_index']}")
print(f"  block id         {d['chain'][-1]['id']}")
print(f"  quorum route     {q['route']}  ({len(q['signatures'])} signers, "
      f"threshold {q['threshold']})")
print(f"  transcripts      {d['quorum_cost']['transcripts']} "
      f"(constant in quorum size for this route)")
print(f"  TxOut public key {d['tx_out']['public_key']}")
print(f"  membership path  {len(d['membership_proof']['elements'])} elements "
      f"against root {d['merkle']['known_root']['hash'][:18]}...")
PY
echo

rule
echo "LEGS 1 AND 3 — real EVM, real verifier, real proof"
rule
BRIDGE_RETURN_FIXTURE_BIN="$(node scripts/rust-artifact.mjs mc-return --example return-fixture)"
export BRIDGE_RETURN_FIXTURE_BIN
BRIDGE_LOCAL_RELEASE_BIN="$(node scripts/rust-artifact.mjs e2e --bin local-release)"
export BRIDGE_LOCAL_RELEASE_BIN
./scripts/node-deps.sh
node scripts/auditor-handoff.mjs
cd contracts && node test/acceptance.mjs
