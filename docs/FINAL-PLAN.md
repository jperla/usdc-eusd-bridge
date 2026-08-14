# USDC ↔ eUSD Bridge — Final Plan

**Status.** The strategy and design are settled and have been through sustained adversarial
review. Four of six components can start now. Two are behind a single architecture gate,
which is a decision about *who holds a second key* rather than a cryptography problem. One
recommendation is out for review and is marked as such.

---

## 1. Decided

| | |
|---|---|
| **Approach** | Escrow now: pre-fund an eUSD wallet and release from it. Mint/burn later if MobileCoin governance allows. |
| **Why** | Escrow needs nobody's permission, so work starts immediately, and it matches the original acceptance test. |
| **Two addresses** | `R` receives returns with a **published** view key so Ethereum can verify them. `F` funds releases with a **private** view key so release rings stay private. The sweep is one-way, `R → F`. |
| **Composite spend key** | Releases need *k of n operators* **AND** *g of m gates*. The gate's share is inside the key image, so consensus rejects a release without it. |
| **Gate holders** | Testing: one party. Production: independent parties — *structure pending, see §2*. |
| **Recovery** | **None.** If the operators lose their keys, the money is gone. This is required: any operator-only recovery path nullifies the gate. |
| **Float** | Unfixed. Someone provides liquidity day one; capacity and the theft ceiling scale with it. |

**The asymmetry everything rests on:** Ethereum can verify MobileCoin; MobileCoin cannot
verify Ethereum. So the return leg is cryptographically verified and the deposit leg is
*attested* by operators, capped, and audited. We do not describe it as trustless.

---

## 2. The access structure — DECIDED

**Decided: 3 operators (2-of-3) AND 1 independent gate. Four entities, and an
attacker must compromise three of them.**

Machine-checked in `proofs/tla/AccessStructure.tla`, which proves
`T = max(k, g, k+g−r)` is both a lower bound and achievable, where `r` is the
operator/gate overlap. Every row below has been model-checked for bound,
tightness, and that some coalition can actually authorize:

| configuration | entities | T | survives one lost operator key |
|---|---|---|---|
| 3 principals holding **both** roles, 2-of-3 | 3 | **2** | yes |
| 3 principals holding **both** roles (owners 2-of-3, gates 3-of-3) | 3 | 3 | no — *collapses to plain 3-of-3 at entity level* |
| 2-of-2 operators + 1 gate | 3 | 3 | **no** |
| any-one-principal loss, nonredundant split | 5 | 3 | yes |
| **2-of-3 operators + 1 gate** ← **decided** | **4** | **3** | one **operator**; never the gate |

**Why the fourth entity, stated correctly.** Three entities *can* reach
`T = 3` — as 2-of-2 operators plus a gate — so "three parties" was never in
conflict with the security target. The fourth entity buys tolerance of one lost
**operator** key, and that is the whole of what it buys.

It is not free. Both shapes have `T = 3`, but they differ in how *many*
coalitions of that size work: `2-of-2 + gate` has exactly one, `{O1,O2,G}`;
`2-of-3 + gate` has three. The extra operator does not raise the cheapest
targeted attack cost at all — it adds attack paths. Under independent
compromise at probability `p`: `p³` against `3p³ − 2p⁴`.

**Neither shape tolerates losing the gate.** It is indispensable in both and
there is no recovery, so losing it freezes the funds permanently. Tolerating
the loss of *any* one principal is impossible at four entities without
collapsing to a plain `3-of-4`; a nonredundant role split with that property
needs **five**.

`T` is minimum coalition *size* and nothing else — not how many such coalitions
exist, not correlation between principals, not availability. Read as a general
key-theft threshold it overstates itself.

**The 3-of-3 row is a trap.** It reaches `T = 3` on paper, but when the same
parties hold both roles the structure reduces to an ordinary `max(k,g)`-of-n
multisig — the split contributes nothing at the entity level. It is 3-of-3
multisig with extra steps.

**Entity count is about compromise domains, not machines.** The gate entity can
hold its key with internal redundancy — several HSMs, several people — without
becoming multiple principals. That buys availability without buying entities.

**What does not work:** an HSM that an operator organization administers, or can
recover from, is not an independent gate. It is the same compromise domain in
different hardware.

**Still open, and it is not a parameter.** *Who* the gate is. Model-checking
shows gates under operator control sign straight through a pause and the
arrangement buys nothing, so this is an organizational fact about real
administrative boundaries — no model can see it and no code review can verify
it.

**The gate co-signs every release.** It is not an emergency key: its share is in
the key image, so nothing moves without it. Gates therefore need routine
availability, and the gate threshold trades against liveness exactly as the
operator threshold does.

**Consequence worth stating before it is discovered:** under *(operators AND
gates)* there are two independent ways to lose the funds — losing either
cohort's threshold is terminal. It does **not** follow that the probability
doubles: a 1-of-1 gate held with internal redundancy is far harder to lose than
a 2-of-3 operator set. The operational point stands regardless: gate key
management needs the same rigor as operator key management.

**This blocks funding, not building.** The address derives from `B = B_owner + B_gate`, so a
production address cannot be funded before the holders are known. Everything in §5 proceeds
regardless.

---

## 3. How it works

**Deposit leg.** A user deposits USDC into an Ethereum contract. Each operator confirms the
deposit **through its own node** — operators sharing a feed are one operator wearing k hats,
and the security argument collapses silently. They jointly release eUSD from `F`.

**Return leg.** The user sends eUSD to `R`. An untrusted relayer brings the block and
validator signatures to Ethereum, where the contract verifies: the output is genuinely payable
to `R` (the `target_key` check, not a view-key match); the token is eUSD with exact conversion;
the claim has not been redeemed, keyed on the output public key across every epoch and mode;
the memo parses under a domain-bound schema; a real validator quorum signed; and the proof
targets the right block for the chosen proof route.

**Beneficiary.** Derived from the finalized output, **never** from the proof submitter. The
return leg is permissionless *because* a relayer only carries bytes — which is exactly why
paying `msg.sender` would let a watcher take someone else's redemption.

---

## 4. What is proven, and what cannot be

**Machine-checked.** Ten TLA+ models, each mutation-tested — every guard switched off in turn
must break exactly the invariant it protects — with negative coverage assertions that catch a
model too dead to move, and a harness that fails closed on tool errors.

**Executed rather than argued.** Three threshold-algebra results in real Ed25519; the DDH
privacy reduction, now covering the **shared-root** construction the design actually
specifies; the composite-root algebra accepted by MobileCoin's **unmodified** verifier; and
the Ethereum gas measurement below.

**Gas, measured on a real EVM.** A 7-validator Ed25519 quorum costs **3.48M gas** measured in
one call, against **27K** for the same loop shape via `ecrecover` — a **128× ratio**. Since the
protocol is ours to change, auxiliary secp256k1 block signatures remove the dominant *signature*
cost.

**The hashing term is now partly measured, and review cut the conclusion back.** MobileCoin has
**two** ways to prove a block was signed:

- **Via block metadata** — what MobileCoin's own light client does. Each validator's signature
  covers its own hardware-attestation evidence, which differs per validator.
- **Via the block signature** — every validator signs the **identical** 164-byte block summary,
  so that hashing is done **once** for the whole quorum. Now measured exactly: **6 permutations**
  (5 with the fixed setup precomputed), by replaying the real encoding rather than estimating.

**A "25× reduction" appeared in the previous draft and has been withdrawn.** The metadata figure
was an *estimate over an assumed 4KB evidence size*, so the ratio compared a measurement against a
guess. Real attestation evidence has no established size bound, and some of it amortizes across
validators, so "nothing amortizes" was also too strong.

**And the cheap route is not simply available.** Its signature is made with a **per-enclave
identity key** — created randomly by default — not the node's configured message key that defines
its identity in the network. So **N block signatures are not N validators**. Using it requires an
authenticated, height-scoped mapping from enclave key to validator entity, with entity-level
deduplication so a rotation cannot be counted twice. Availability is weaker too: the signature is
optional in the block record, and a node that caught up rather than forming the block discards it.

**Attestation is what natively authenticates that enclave key**, so the earlier claim that the
expensive route's binding "buys nothing" was wrong as stated. It buys nothing *in the current
acceptance decision* — a much narrower claim.

**Decision state: still "prototype and measure".** The cheap route stays the leading prototype
candidate, conditional on key enrollment, historical quorum mapping, entity deduplication and
archive coverage. Since the protocol is ours to change, the cleaner production candidate remains a
compact domain-separated signature under an **already authenticated** validator key — the existing
message key, or an auxiliary secp256k1 key verified with `ecrecover`.

**Still a line item, not a verifier total** — it excludes point decompression, SHA-512 challenge
derivation, small-order checks, the Merkle path, and calldata. Every figure is naive Solidity and
therefore an **upper bound**; optimized assembly is roughly 10× cheaper, which *reverses* which
term dominates. The verifier strategy therefore stays **"prototype and measure"**.

**Structural limits, stated as limits and not gaps:**

- MobileCoin cannot verify Ethereum, so the deposit leg is attested rather than trustless.
- An Ethereum pause bounds only escrow-contract USDC outflow. Without an indispensable
  MobileCoin-side factor it cannot stop a compromised operator quorum from spending — which is
  precisely what the composite gate exists to fix.
- Unbacked releases cannot be caught downstream: ordinary spends erase provenance, so no
  validation of a later return detects an earlier bad release. Detection is the auditor's job
  and it needs an enforceable response, not a dashboard.

**One finding to act on regardless of this project:** MobileCoin's own light-client relayer
classifies burns with a check that never reads the field determining who can spend. Latent
today because payouts are manual; live the moment they are automated.

---

## 5. Build plan

**Start now — four components, none gated:**

1. **Ethereum escrow contract** — deposit custody, events, release interface.
2. **MobileCoin block and inclusion verifier** — quorum signatures and membership proof.
3. **Deposit auditor** — matches every release to exactly one deposit, freezes on mismatch.
4. **Signing ceremony state machine** — against an abstract authorization backend, with the
   one-time value store keyed on the full signing context and anchored before each externally
   observable step.

**Critical path — the two-cohort signing spike.** The existing threshold spike has a
**one-cohort shape** (a single roster and threshold shared by the spend and mask keys) and
cannot express operators-plus-gates at all. This is the thing standing between the project and
a fundable architecture.

**Also gated:** anything that funds a composite address, pending §2.

**Baseline hardening that is useful either way:** identity-signed round messages, durable
one-time value storage, typed errors, canonical wire encoding.

---

## 6. What I would watch

**The operational failure is more likely than the cryptographic one.** Operators sharing an
Ethereum feed defeats the entire security argument and looks completely normal from outside.

**Gate independence is the whole ballgame.** Model-checking shows gates under operator control
sign straight through a pause and the composite key buys nothing. This is an organizational
property, not a technical one, and it cannot be verified by review.

**Snapshot-restoring a signer is key compromise** unless the one-time value store sits on
storage excluded from snapshots with an external monotonic anchor. This is the kind of thing an
ops team does routinely and correctly, and it would be catastrophic here.

---

## 7. Confidence

The design has been reviewed adversarially throughout. **Of 231 recorded claims, 74 were
refuted and 26 disputed** — a third of what was written down got overturned, including several
defects in the *checking apparatus* rather than the design itself. What survived, survived that.

Two things are not yet confirmed and are marked accordingly: the gate structure recommendation
in §2, and the reviewer's standing position that the project **has not crossed the production
threshold-composition boundary** — which is agreement about the gap in §5, not disagreement
about the plan.
