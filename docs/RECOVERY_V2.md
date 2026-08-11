# Reserve recovery v2 — archived bounded decision analysis

> **ARCHIVED 2026-08-08:** Josh subsequently removed key recovery and
> escrow-key-compromise recovery from the current product scope. This checked
> model is retained as decision evidence and a regression artifact; it is not
> an implementation requirement or the active product specification.
> `BridgeEscrowV2` is the active formal target. See shared-channel messages
> #53–#54.

`ReserveRecoveryV2.tla` is the final bounded analysis of the earlier
MobileCoin reserve-recovery and successor-generation decision. It supersedes the
exploratory `ReserveRecovery.tla` model, whose original catastrophic-loss
witnesses were false positives.

## Result and current run status

On 2026-08-07, TLC 2.19 on OpenJDK 26 completed the repaired broad safety
exploration with **1,670,448 distinct states** and no violation of any of the
31 safety invariants.

The repaired acceptance inventory is:

| Check | Repaired contract | Current published status |
|---|---:|---|
| Broad TLC safety exploration | 31 invariants | **1,670,448 distinct states, clean** |
| Independent Python broad exploration | reachable-state cardinality comparison | **1,670,448 distinct states, exact cardinality match** |
| Disjoint feature/scope profiles | 16 | **16/16 exact TLC/Python cardinality matches; sum 1,670,448** |
| Conditional temporal scenarios | 9 | **9/9 pass** |
| Non-`NONE` one-defect configurations | 36 | **36/36 hit the designated invariant in both TLC and Python** |
| Required Python outcome witnesses | 14 | **14/14 reached** |
| Explicitly forbidden Python outcomes | none permitted | **0 reached** |

The 16 profiles are the eight subsets of the independent `RESHARE`, `RECOVERY`,
and `SUCCESSOR` capabilities, each under both `GLOBAL` and `SEGREGATED`
accounting. They are disjoint because the selected capability set and scope are
part of every state. Their confirmed reachable-state cardinalities are:

| Capabilities | `GLOBAL` | `SEGREGATED` | Combined |
|---|---:|---:|---:|
| none | 340 | 340 | 680 |
| `RESHARE` | 5,626 | 5,626 | 11,252 |
| `RECOVERY` | 866 | 866 | 1,732 |
| `SUCCESSOR` | 10,920 | 10,312 | 21,232 |
| `RESHARE + RECOVERY` | 11,740 | 11,740 | 23,480 |
| `RESHARE + SUCCESSOR` | 280,918 | 205,302 | 486,220 |
| `RECOVERY + SUCCESSOR` | 34,626 | 34,754 | 69,380 |
| all three | 563,212 | 493,260 | 1,056,472 |
| **Total** | **908,248** | **762,200** | **1,670,448** |

The nine named temporal scenarios passed with these TLC counts:

| Scenario | States | Checked temporal outcome |
|---|---:|---|
| false incident, keep owner | 70 | fresh legacy gate and `K0` reactivation |
| partial loss, reshare response | 310 | same-key epoch-1 repair and reactivation |
| catastrophic loss, reshare only | 480 | legacy becomes derived `Stranded` |
| catastrophic loss, no recovery | 40 | legacy becomes derived `Stranded` |
| catastrophic loss, delayed recovery | 158 | bound full `K0 -> KR` migration and reactivation |
| threshold compromise, migration | 94 | owner-authorized full `K0 -> KR` migration |
| mixed-epoch compromise | 772 | mixed-epoch triples do not form a threshold |
| successor, global accounting | 420 | successor activates with no new liability capacity |
| successor, segregated accounting | 1,028 | one successor liability is eventually admitted |

Run the contract with:

```bash
cd /Users/jperla/josh/spec
./run_recovery_v2.sh
```

The runner parses every config rather than grepping comments, verifies exact
config specifications and `Bug` assignments, compares reachable-state
cardinalities between independently implemented transition systems, checks the
temporal scenarios, and requires each negative configuration to fail its
designated invariant.

Equal reachable-state counts are useful **cardinality-parity evidence and a
regression oracle**. They do not show that state labels or successor edges are
equal, and do not establish graph identity or isomorphism. Semantic confidence
also depends on reviewing the two implementations' actions, state projections,
and invariant meanings.

## What the model establishes

Within its finite constants and one-incident/one-rotation boundary, the clean
broad TLC run supports these safety conclusions:

1. **Resharing is repair and preventive maintenance, not catastrophic
   recovery or revocation.** A reshare event records exact
   `(custodian, ownerKey, shareEpoch)` contributor triples and requires at least
   `KOwn` usable, issued shares from one old epoch. Shares from different epochs
   do not combine. A threshold learned by the adversary in any historical epoch
   remains a capability while the public owner key remains `K0`.

2. **Share-package loss is not actor outage.** Losing a
   `(custodian, K0, epoch)` package does not prevent that healthy actor from
   joining a fresh `KR` or `KS` ceremony. Conflating those facts was the defect
   that invalidated the v1 catastrophic-loss witnesses.

3. **A below-threshold legacy owner is recoverable only through a branch
   committed when the old outputs were created.** Recovery requires an exact
   request, a recovery quorum, the configured delay, recorded fresh owner and
   gate ceremonies, and consume-and-create migration of the complete inventory.
   MobileCoin outputs are immutable; the owner key and recovery branch cannot be
   rewritten in place.

4. **The recovery-policy atom is an abstraction, not the whole policy.**
   `RECOVERY_V1` represents an immutable, versioned output policy committing to
   the recovery roster/key, threshold, delay, domain separator, and canonical
   request/authorization schema. The bounded model fixes those fields as
   constants and records; it does not model byte encoding, hashing, signatures,
   or policy-parser correctness.

5. **A compromised owner threshold and a stranded owner are exclusive
   classifications.** An output is `Unsafe` when the adversary has a same-epoch
   threshold for its owner key. `DerivedStrandedOutputs` explicitly excludes
   unsafe outputs, so `Unsafe` has priority. An output is stranded only when it
   is not unsafe, lacks a durable legitimate threshold, and lacks a structurally
   viable bound recovery capability. Neither unsafe nor stranded value is
   eligible to back liability admission.

6. **Stranding is per output and based on durable/eventual authority.** The
   durable-holder calculation counts issued shares after permanent loss and
   expulsion but deliberately ignores transient `offline` status. A temporary
   outage can block current operation without making an output stranded.
   `StrandingSound` classifies authority; it does not prove that a viable
   recovery branch will make progress in deployment.

7. **Ceremonies and authorizations are explicit abstract records.** Gate and
   owner DKG events bind modeled key, epoch, roster/policy, signer set, and
   availability snapshot. Recovery requests bind the exact recorded owner and
   gate events, domain, recovery policy, output sets, replacement owner and
   policy, gate key, and maturity. These records let the model check ordering
   and binding; they are not cryptographic DKG transcripts or proofs that a
   secure DKG/FROST protocol completed.

8. **A successor generation is continuity, not recovery.** It requires a
   recorded `KS` owner ceremony before funding, an external capital allocation,
   a distinct successor gate ceremony, activation, and explicit liability
   treatment. It neither repairs nor erases the legacy deficit. Under `GLOBAL`
   accounting, new capital creates no new capacity until all obligations are
   covered. Under `SEGREGATED` accounting, successor liability admission is
   checked only under an assumed enforceable entitlement boundary; the model
   does not create or prove that legal segregation.

9. **Recovery, reshare, and successor are composable capabilities.** They are
   not mutually exclusive modes. The broad model explores every feature subset
   and both accounting scopes.

The 36 one-defect configurations are designed to falsify the corresponding
properties for: sub-threshold, non-holder, or mixed-epoch reshare; erased issued,
lost, or adversary-known history; under-quorum or reused ceremonies; missing or
under-bound owner authorization; retroactive, premature, sub-quorum, unbound, or
unlogged recovery authorization; non-consuming, external, wrong-owner,
wrong-policy, or wrong-value migration; in-place mutation; partial or unsafe
activation; successor DKG/funding errors; ineligible backing; erased liability,
reservation, or nullifier history; and stale-gate authorization. Their final
post-repair executions each hit the designated invariant in both TLC and Python.

## What the accounting and history checks mean

- Issued shares are the append-only union of initial issuance and logged reshare
  and owner-ceremony issuance. Permanent loss and adversary knowledge each have
  an append-only history as well as a current set; the clear-current-and-history
  defects are intended to show that clearing both views is still detected.
- A migration event must attach exactly the canonical recovery-authorization or
  owner-authorization log for this single incident. This detects altered or
  unlogged attached authorization and an owner authorization bound to the wrong
  old key. It is not a proof against cross-incident replay.
- Liability, reservation, and nullifier checks ensure that already-recorded
  accounting facts survive the modeled successor-generation transition.
  Reservation and nullifier preservation do **not** prove source-event
  idempotency, nullifier completeness, or binding between a source event,
  admission decision, authorization, and release.

## What this result does not establish

This is decision support for reserve authority and accounting, not a proof of
the complete bridge or its cryptography.

Not modeled or proved here:

- FROST, MLSAG, or DKG cryptographic security, including unforgeability, nonce
  safety, transcript validation, proof of possession, or ring unlinkability;
- Ethereum-to-MobileCoin or MobileCoin-to-Ethereum bridge-leg correctness,
  finality, deposit observation, return receipts, or release authorization;
- source-event admission, authorization binding, idempotency, or a complete
  consensus-nullifier construction;
- evidence admission, blame, bonds, slashing, or restitution;
- prices, exchange rates, fees, denomination fragmentation, or arbitrary values;
- legal enforceability of the `SEGREGATED` accounting boundary;
- repeated incidents, a second recovery generation, cross-incident replay, or
  compromise of `KR` or `KS`.

Named-scenario progress is conditional on modeled weak fairness, stable required
quorums, and fair time advance. Successor progress additionally assumes that an
external actor allocates the modeled capital. Fairness cannot create operators,
secrets, money, or a legal entitlement boundary in a deployed system.

## Protocol implication

This model does not replace the bridge design. Its result should be composed
with that design as follows:

- protocol-enforced threshold MLSAG/FROST supplies MobileCoin ownership
  authorization;
- a distinct, current-epoch, on-chain warden/gate authorization supplies
  cross-chain attestation and attributable signers;
- a consensus source-event nullifier must separately enforce one authorized
  release per source event;
- a compromised historical ownership threshold is contained only while it
  lacks the current gate;
- expulsion requires a fresh DKG and retired-gate rejection, because deleting
  names cannot revoke shares already issued;
- if catastrophic key-loss recovery is desired, the immutable, versioned,
  narrowly confined delayed migration policy must be part of the transaction
  format at output creation. Otherwise catastrophic loss is intentionally
  fail-closed and stranded.

The exact profile, scenario, invariant, witness, and falsifier contract is in
`RECOVERY_V2_TEST_PLAN.md`.
