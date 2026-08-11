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

## 2. The one open item

**Recommendation, revised after Josh said six entities is too many:** 3 operators (2-of-3)
**AND** 1 independent gate — **four entities**, and an attacker must compromise **three** of
them. Going from six entities to four costs T=4 → T=3.

Machine-checked in `spec/AccessStructure.tla`, which proves `T = max(k, g, k+g−r)` tight
across configurations, where `r` is the operator/gate overlap:

| configuration | entities | T |
|---|---|---|
| 3 principals holding **both** roles | 3 | **2** — no benefit at all |
| 2-of-3 operators + 1 gate | **4** | **3** |
| 2-of-3 operators + 2-of-3 gates | 6 | 4 |

**Entity count is about compromise domains, not machines.** One gate entity can hold its key
with internal redundancy — several HSMs, several people — without becoming multiple
principals. That buys availability without buying entities.

**What does not work:** an HSM that an operator organization administers or can recover from
is *not* an independent gate. It is the same compromise domain in different hardware.

Two things make this sharper than it looks:

**The gate co-signs every release.** It is not an emergency key — its share is in the key
image, so nothing moves without it. Gates therefore need routine availability, and the gate
threshold trades against liveness exactly as the operator threshold does.

**Shared parties collapse the structure entirely.** If the same parties hold both roles, a
coalition spends iff it reaches `max(k,g)` — so the access structure is *exactly* a
`max(k,g)`-of-n multisig, and the split provides no **entity-level compromise-threshold**
benefit. That rules out every threshold assignment over three shared parties: operators 2-of-3
with gates 3-of-3 over the same three is 3-of-3 multisig wearing a costume. *(Narrower than
"no benefit at all" — a separately administered, non-bypassable system may still resist a
compromise limited to one role's credentials.)*

**Consequence worth stating before it is discovered:** under *(operators AND gates)* there
are now **two independent ways to lose the funds** — losing either cohort's threshold is
terminal. It does **not** follow that the probability doubles: the two cohorts have different
loss profiles, and a 1-of-2 gate is far harder to lose than a 2-of-3 operator set. The
operational point stands regardless — gate key management needs the same rigor as operator key
management, and `m` should be sized for availability rather than treated as a formality.

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
