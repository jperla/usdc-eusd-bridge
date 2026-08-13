# USDC ↔ eUSD bridge

A bridge between USDC on Ethereum and eUSD on MobileCoin, built to a design
that has been through sustained adversarial review. This repo is the
implementation; `docs/FINAL-PLAN.md` is the plan it implements and
`proofs/` is the evidence behind the design decisions.

---

## The one thing that shapes everything

**Ethereum can verify MobileCoin. MobileCoin cannot verify Ethereum.**

Ethereum contracts can run the arithmetic needed to check a MobileCoin block
signature. Nothing on MobileCoin can check what happened on Ethereum. The two
legs of the bridge are therefore *not* mirror images, and any description that
makes them sound symmetric is wrong:

| | how it is secured |
|---|---|
| **Deposit leg** (USDC in → eUSD out) | **Attested.** Operators each watch Ethereum through their own node and jointly release eUSD. Capped and audited. Not trustless, and this repo does not claim otherwise. |
| **Return leg** (eUSD back → USDC out) | **Verified.** The proof is checked cryptographically on Ethereum. Anyone may relay it. |

---

## The three legs, which are the acceptance test

1. A user deposits USDC into an Ethereum escrow contract.
2. On a verified deposit, eUSD is released from the eUSD escrow wallet.
3. When eUSD is returned, USDC is released from the Ethereum escrow.

---

## How releases are authorised

Releasing eUSD needs **two separate groups to agree**:

```
k of n  OPERATORS     AND     g of m  GATES
```

This is not a policy check that a coordinator could skip. The two groups'
shares are added together into a single spend key, and the gate's contribution
lands inside the **key image** — the value MobileCoin's consensus uses to
detect double spends. A release without the gate's share produces a key image
the network does not accept. There is nothing to bypass.

**Recommended shape: 3 operators (2-of-3) plus 1 independent gate.** Four
entities, and an attacker needs three of them. `proofs/tla/AccessStructure.tla`
machine-checks the general rule, `T = max(k, g, k+g−r)` where `r` is how much
the two groups overlap, and shows it tight across configurations.

**The catch, stated up front:** if the two groups are the same people, the
whole structure collapses to an ordinary `max(k,g)`-of-n multisig wearing a
costume. And there is deliberately **no recovery path** — any way for operators
to move funds without the gates would be the exact hole the gates exist to
close. If the keys are lost, the money is gone.

---

## What is in here

### Ethereum (`contracts/`)

| file | what it does |
|---|---|
| `Escrow.sol` | USDC custody. Deposits with a cap; permissionless redemption that pays **the beneficiary named in the proof, never `msg.sender`**. |
| `ValidatorRegistry.sol` | The MobileCoin validator key set and the quorum rule, with timelocked rotation. |
| `IMobileCoinVerifier.sol` | The boundary the return-leg proof crosses. |
| `TestMocks.sol` | Test-only. Never deploy. |

Tests run against a **real EVM** (ethereumjs) executing real compiled bytecode —
no mocked chain — via `contracts/test/harness.mjs`.

### MobileCoin side (`crates/`)

| crate | what it does |
|---|---|
| `two-cohort` | The composite spend key: two independent groups, each with its own roster and threshold, over one root. |
| `ceremony` | The signing state machine: one-time values keyed on the full signing context and committed before anything observable happens. |
| `auditor` | Matches every release to exactly one deposit and produces an enforceable freeze, not a warning. |
| `mc-return` | Builds the return-leg proof the Ethereum contract consumes. |

---

## Two ways to prove a block — still "prototype and measure"

MobileCoin offers two routes. One is genuinely cheaper, but it is **not
selected**, because review found the cost comparison overstated and the cheap
route incomplete in a way that matters.

- **Via block metadata** — each validator's signature covers its own hardware
  attestation evidence, which differs per validator.
- **Via the block signature** — every validator signs the *same* 164-byte block
  summary, so that hashing happens **once** for the whole quorum. Measured
  exactly: **6 Keccak permutations** (5 if the fixed setup is precomputed).

**What is established:** the shared digest is real, and 6 is a measurement
rather than an estimate.

**What is not:** the metadata route's cost was an *estimate over an assumed
evidence size*, so the "25×" that appeared in an earlier draft compared a
measurement against a guess and has been withdrawn. Real DCAP evidence has no
established size bound, and part of it amortises across validators, so "nothing
amortises" was too strong. The current native route also needs a separate block
ID transcript — another 5 permutations — before any inclusion or bridge checks.

**The catch that actually blocks the cheap route.** Its signature is made with
a **per-enclave identity key**, not the node's message key that defines its
identity in the network — and that key is created randomly by default. So *N
block signatures are not N validators*. Taking this route requires an
authenticated, height-scoped mapping from enclave key to validator entity, with
entity-level deduplication so a rotation cannot count twice. `ValidatorRegistry`
implements exactly that mapping; the enrollment that fills it is off-chain.
Availability is also weaker: the signature is optional in the block record, and
a node that caught up rather than forming the block discards it.

Attestation is what natively authenticates that enclave key — the enclave places
its block-signing key inside the attested identity — so it is **not** true that
the expensive route's binding buys nothing. It buys nothing *in the current
acceptance decision*, which is a narrower statement.

---

## What is proven, and what is not

`proofs/` holds 17 TLA+ models. They are **not** all established the same way,
and an earlier version of this section said they were. What is actually there:

| | models | how |
|---|---|---|
| Guard-mutation studies under TLC | 6 | `BridgeA`, `FreezeBound`, `CatalogIntegrity`, `ClaimAcceptance`, `NonceSlot`, `PackageProjection` |
| Other TLC runs — scenario tables, an observability search, a bounded lifecycle | 5 | `AccessStructure`, `CompositeGate`, `AuditObservability`, `SubsetRetry`, `BridgeEscrowV3` |
| Handwritten Python mirrors, **not** TLC | 6 | `BridgeEscrow`, `BridgeEscrowV2`, `BridgeCapacityV2`, `M5SealedResponse`, `ReserveRecovery`, `ReserveRecoveryV2` |

So "each mutation-tested" was wrong twice over: only six of the seventeen are
guard-mutation studies, and six are not checked by TLC at all. The mirrors are
handwritten from the design documents; `proofs/tla/check.py` says in its own
header that it is "NOT a substitute for TLC".

Two further corrections, both of which the runners had already made before this
file caught up with them:

- **Not "exactly the invariant it protects".** A mutation must break the
  invariant it is paired with; it may break others, and the runners report the
  full set. The "exactly one" wording dates from a harness that only ever
  inspected TLC's *first* reported violation, which could not have established
  it — see the header of `proofs/tla/tlc_harness.py` and of `run_bridge_a.py`.
- **Not "every guard".** Two are deliberately excluded and named as such.
  `run_claim_acceptance.py` prints "THREE guards are established here, not
  four" — `GuardRevertOnFailure` is not in the established set.
  `run_catalog.py` holds `GuardNoOverwrite` out of the mutation matrix because
  it is subsumed once `Prove` binds the (output, key image) pair, and switched
  off alone it breaks nothing.

Those two runners also print a `KNOWN UNPROVED` block for checks found not to
establish what they appeared to: `INV_NoStrandedClaims` is a synthetic oracle
where the same guard introduces the bug and sets the flag that detects it, and
`COV_CanRevert` never reaches the failure it claims to cover.

What holds without qualification: the negative coverage assertions are real —
each is written to fail, and a model too dead to reach one is a runner failure
— and `tlc_harness.py` fails closed, so a TLC tool error is `ERROR` and never a
pass. Alongside the models: threshold algebra executed in real Ed25519, a DDH
privacy reduction, composite-root algebra accepted by MobileCoin's
**unmodified** verifier, and EVM gas measured rather than estimated.

**None of the TLA+ work reproduces from a clean clone.** `tlc_harness.py`
expects `proofs/tla/tla2tools.jar`, which is neither committed nor fetched by
`scripts/setup.sh`; `run_bridge_v3_tla.py` defaults to an absolute path outside
the repository. These results are archived evidence, re-runnable only if you
supply TLC yourself. `scripts/test.sh` does not run them, and CI does not
either — so nothing on this page about `proofs/` is continuously checked.

**Limits, stated as limits and not gaps:**

- The deposit leg is attested, not trustless. That is structural.
- Pausing the Ethereum contract bounds only USDC leaving *it*. It cannot stop a
  compromised operator quorum on MobileCoin — that is what the gate is for.
- An unbacked release cannot be caught downstream: ordinary MobileCoin spends
  erase provenance, so no later check finds an earlier bad release. Detection is
  the auditor's job and needs an enforceable response.

**Of 326 recorded claims during design, 74 were refuted and 26 disputed** —
about a third of what was written down got overturned, including defects in the
checking apparatus itself rather than the design. What survived, survived that.

---

## Status

**377 tests, 0 failures** — 177 Rust, 200 Solidity against a real EVM.

The Solidity half is re-run by CI on every push, from the lockfile, so that
number is checked rather than asserted. The Rust half is not in CI (see
`.github/workflows/ci.yml` for why) — reproduce it with `./scripts/test.sh`.
The `proofs/` results are in neither.

| | | |
|---|---|---|
| Escrow, custody and replay set | Solidity | 22 tests |
| Validator registry and quorum rule | Solidity | 21 tests |
| Ed25519 (RFC 8032 vectors) | Solidity | 25 tests, **550,321 gas/verify** |
| Ristretto255 (vs dalek vectors) | Solidity | 26 tests |
| Blake2b-256 (vs hashlib) | Solidity | 10 tests |
| Merlin — MobileCoin block IDs byte-identical | Solidity | 72 tests |
| Return-leg verifier | Solidity | 17 tests |
| Acceptance: the three legs | Solidity | 7 tests |
| Two-cohort composite spend key | Rust | 34 tests |
| Signing ceremony state machine | Rust | 48 tests |
| Deposit auditor and freeze bound | Rust | 50 tests |
| Return-proof builder | Rust | 45 tests |

## Status

**383 tests, 0 failures** — 179 Rust, 204 Solidity against a real EVM.
`./scripts/acceptance.sh` runs the whole objective in one command.

**It fits.** A real return-leg transaction costs **6,498,577 gas** — 21.7% of a
30M block, including the 21,000 intrinsic and 1,694 bytes of calldata. It was
31M, over the limit and unlandable at any price, until Keccak-f1600 was
rewritten in Yul: 1,281,221 → 135,629 gas per permutation, and `verifyReturn`
runs about eighteen of them.

**The bridge is still not ready to hold funds.** Two things are open, and the
acceptance run prints them itself rather than letting a green result imply more
than it shows:

1. **The payout amount is asserted by whoever relays the proof.** The TxOut
   digest binds the *masked* value, so the figure is not derived from the
   output. The fix is for the recipient check to return `(payable, amount)`
   rather than a bool — it already computes the shared secret that unmasking
   needs.
2. **No non-reconstructing two-cohort signing protocol.** The artifacts
   reconstruct the composite scalar in one process, so what is established is
   the algebra plus stock-verifier compatibility, not a live threshold
   ceremony. **A composite address must not be funded on this evidence.**

Also absent: a live signing ceremony, DKG with proof-of-possession, and any
deployment.

## Building

You need Rust (the toolchain is pinned, see below), Node 18 or later, and
`npm`. From a fresh clone:

```bash
./scripts/setup.sh    # clone the pinned MobileCoin and Serai checkouts
./scripts/test.sh     # everything: Rust workspace, then Solidity
```

`setup.sh` is not optional — the Rust workspace path-depends on
`vendor/mobilecoin`, and `test.sh` stops with that message if it is missing.

The Solidity suite is a Node program. `test.sh` installs its dependencies from
`contracts/package-lock.json` when `contracts/node_modules` is absent, and
reinstalls if what is there does not match the lockfile, so there is no
separate step to remember. To run just that half:

```bash
./scripts/node-deps.sh
cd contracts && node test/run.mjs
```

The versions are pinned exactly rather than by range. The suite compiles real
bytecode and reports gas, so the compiler and the EVM are part of every number
it prints; a caret would let a later `solc` change what those numbers refer to
without anything looking different.

The pinned toolchain is not a preference. MobileCoin's `mc-common` hardcodes
hashbrown's `nightly` feature, and feature flags are additive, so a dependent
workspace cannot turn it off. Using that toolchain is what lets `mc-return`
link **MobileCoin's own light-client verifier** rather than reimplementing it.

## Review

Every artifact here is reviewed by a second model before being relied on:

```bash
./scripts/sol-review.sh <dir> <prompt-file> <out-file>
```
