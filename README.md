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

`proofs/` holds 17 TLA+ models, each mutation-tested — every guard is switched
off in turn and must break exactly the invariant it protects — plus negative
coverage assertions that catch a model too dead to move, and a harness that
fails closed on tool errors. Alongside them: threshold algebra executed in real
Ed25519, a DDH privacy reduction, composite-root algebra accepted by
MobileCoin's **unmodified** verifier, and EVM gas measured rather than
estimated.

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

## Building

The workspace builds against pinned MobileCoin and Serai checkouts:

```bash
./scripts/setup.sh
```

Then:

```bash
cargo test --offline
```

```bash
cd contracts && npm install && npm test
```

## Review

Every artifact here is reviewed by a second model before being relied on:

```bash
./scripts/sol-review.sh <dir> <prompt-file> <out-file>
```
