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

## Two ways to prove a block, and why the cheap one is used

MobileCoin offers two routes, and they are in very different cost classes:

- **Via block metadata** — each validator's signature covers its own hardware
  attestation evidence. Different for every validator, so nothing is shared:
  about **203 hash permutations** for seven validators.
- **Via the block signature** — every validator signs the *same* 164-byte block
  summary, so the hashing happens **once** for the whole quorum: at most **8**.

That is **~25× less work**, and since it is a count of operations rather than a
gas figure, it holds however well the code is optimised.

**Why the expensive route buys nothing:** a contract cannot *validate*
attestation evidence — that needs certificate-chain verification far beyond any
gas budget — it can only hash bytes it has no way to interpret. Both routes end
up trusting `ValidatorRegistry`. So the expensive one pays 25× for a binding it
cannot check.

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
