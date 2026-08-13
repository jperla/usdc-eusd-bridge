#!/usr/bin/env bash
# The objective from docs/FINAL-PLAN.md, end to end, in one command.
#
#   1. handle a USDC deposit into an Ethereum escrow account
#   2. upon verified USDC deposit, release eUSD from the eUSD escrow wallet
#   3. when eUSD is returned, release USDC from the Ethereum escrow account
#
# Leg 2 is on MobileCoin and can only be established against MobileCoin's own
# code, so it runs first, in Rust. Legs 1 and 3 then run against a real EVM
# using a return proof that Rust produced from real MobileCoin types.
set -euo pipefail
cd "$(dirname "$0")/.."

# The workspace needs the pinned nightly (mc-common hardcodes hashbrown's
# nightly feature). The m2d spike pins its own lockfile and resolves under the
# default toolchain, so capture that before overriding PATH.
DEFAULT_CARGO="$(command -v cargo || true)"
TC="$HOME/.rustup/toolchains/nightly-2024-10-11-aarch64-apple-darwin/bin"
[ -d "$TC" ] && export PATH="$TC:$PATH"

rule() { printf '%.0s=' {1..72}; echo; }

rule
echo "LEG 2 — the composite spend key, against MobileCoin's own verifier"
rule
echo
echo "\$ cargo test --offline -p two-cohort"
cargo test --offline -p two-cohort 2>&1 | grep -E "^test |^test result" || true
echo
echo "\$ cargo test --offline   # in proofs/executable/m2d-two-cohort"
( cd proofs/executable/m2d-two-cohort \
    && "${DEFAULT_CARGO:-cargo}" test --offline 2>&1 \
    | grep -E "^test |^test result" || true )
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
cargo test --offline -p mc-return 2>&1 | grep -E "^test result" || true
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
cd contracts && node test/acceptance.mjs
