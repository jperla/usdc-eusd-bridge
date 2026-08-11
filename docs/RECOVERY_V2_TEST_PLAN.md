# Reserve recovery v2 acceptance contract (archived scope)

> **ARCHIVED 2026-08-08:** This remains the reproducible acceptance contract
> for the checked recovery model, but recovery is no longer a current product
> deliverable. Do not infer a requirement to implement any recovery branch,
> successor-continuity mechanism, or migration path from this document.
> `BridgeEscrowV2` is the active normal-operation model.

This document is the acceptance contract for `ReserveRecoveryV2.tla` and its
independent Python mirror. It exists because the v1 checker accidentally used
benign `FALSE_1` traces as witnesses for catastrophic recovery.

## Repaired verification inventory

The broad `ReserveRecoveryV2.cfg` run explores all feature subsets, both
accounting scopes, and all modeled incident branches under `Spec`, without
fairness. Its 31 separately named safety invariants are clean across
**1,670,448 distinct TLC states** on the repaired snapshot.

The complete acceptance inventory is:

- 16 disjoint profiles: all eight subsets of `RESHARE`, `RECOVERY`, and
  `SUCCESSOR`, crossed with `GLOBAL` and `SEGREGATED` accounting;
- nine named temporal scenarios;
- 36 non-`NONE` one-defect configurations, each mapped to one required named
  invariant failure in both TLA+ and Python; and
- 14 required Python outcome witnesses plus an explicit forbidden-outcome set.

All 16 profile cardinalities now match exactly between TLC and Python, and
their disjoint partition sums to **1,670,448**. All nine temporal scenarios
also pass. Exact profile and scenario counts are published in `RECOVERY_V2.md`.

The independent Python broad exploration also reaches **1,670,448** states.
All 36 one-defect configurations hit their designated named invariant in both
TLA+ and Python, all 14 required Python witnesses are reached, and the Python
forbidden-outcome set remains empty.

For the broad model and each profile, equal TLC/Python reachable-state counts
are cardinality-parity evidence and a regression check. Equal counts alone do
not establish state correspondence, edge correspondence, graph identity, or
isomorphism.

## Verification discipline

- The broad model checks safety only. It makes no fairness or unconditional
  progress claim.
- A profile uses a state `CONSTRAINT` to fix one capability set and one scope.
  The 16 profiles are disjoint, and the runner requires their TLC state-count
  sum to equal the broad TLC count as well as comparing each profile's TLC and
  Python cardinalities.
- A named scenario uses a state `CONSTRAINT` to select its feature set, scope,
  and incident family, then checks a temporal property under `ScenarioFairSpec`.
  Weak fairness applies only to the explicitly listed modeled actions; it
  cannot supply a missing quorum, secret, capital allocation, or legal rule.
- `PARTIAL_RESHARE` additionally declares the config directive
  `ACTION_CONSTRAINT PartialReshareResponsePolicy`. Once the partial-loss
  incident has occurred, that policy disallows the `KeepOwner` response
  transition. It does **not**
  prune states because they lack the desired epoch, assert the conclusion, or
  retain only states in which resharing succeeded. The independently stated
  temporal property must still reach epoch-1 reactivation.
- Positive reachability witnesses are accompanied by safety invariants and an
  explicit Python forbidden-outcome matrix. A successful trace by itself is
  insufficient.
- The runner parses config directives and assignments, ignoring comments. It
  checks the exact `SPECIFICATION`, state and action constraints, invariants,
  temporal property, and `Bug` selector before running TLC.

## Interpretation of the abstraction

### Share authority and history

Custody packages, reshare contributors, and adversary knowledge are exact
`(holder, ownerKey, shareEpoch)` triples. A valid reshare contributor set must
contain at least `KOwn` distinct holders whose same-key, same-source-epoch
triples were issued and were usable in the event snapshot. The
`RESHARE_WITH_MIXED_EPOCH` falsifier deliberately supplies one epoch-0 and one
epoch-1 contributor triple; two holder identities do not make those triples a
threshold.

Issuance is append-only and equals initial issuance plus shares recorded in
reshare and owner-ceremony logs. Permanent loss and adversary knowledge each
have both a current set and an append-only history. The loss-erasure defect
clears both `lost` and `lostHistory`, and the knowledge-erasure defect clears
both `adversaryKnown` and `adversaryHistory`; `ShareHistoryMonotonic` must catch
both attempts. A later compromise reveals only the then-current share triple,
not every share the actor held in every historical epoch.

### Policy, DKG, and authorization records

`RECOVERY_V1` is an atom standing for an immutable, versioned output policy
that commits to a recovery roster/key, threshold, delay, domain separator, and
canonical request/authorization schema. The model fixes those commitments with
constants and exact record fields; it does not model policy bytes or a parser.

Owner and gate DKG events are abstract records of key, epoch, roster or policy,
signers, availability snapshot, and issued shares where applicable. They let
the invariants check quorum, roster, freshness, ordering, and exact binding.
They are not DKG transcripts, cryptographic proofs, or evidence that a secure
FROST/DKG implementation completed.

The successor owner-DKG record must exist before successor funding creates
fresh outputs. A recovery owner-DKG record must exist before recovery
authorization. The canonical recovery request binds the exact recorded owner
and gate DKG events, bridge domain, recovery-policy version, old and new output
sets, replacement owner, output policy, gate key, arming time, and maturity.
Owner-authorized migration similarly binds the old and new keys and outputs,
share epoch, exact owner/gate DKG records, and gate key.

Each migration event must attach a nonempty authorization set exactly equal to
the corresponding canonical log (`recovery.authLog` or
`recovery.ownerAuthLog`). The unlogged-authorization falsifiers attach altered
records that are not equal to those logs. The under-bound owner-authorization
falsifier substitutes the wrong old owner key. These are exact-attachment and
binding checks within one incident, not a cross-incident replay proof.

### Unsafe, stranded, and eligible backing

`UnsafeOutputs` contains outputs whose owner key is known to an adversarial
same-epoch threshold. `DerivedStrandedOutputs` explicitly excludes those
outputs, so `Unsafe` has priority and the two classifications are exclusive.
Stranding is derived per live legacy output: the output is not unsafe, has no
durable legitimate owner threshold after package loss and expulsion, and has
no structurally viable bound recovery capability. Both classes are excluded
from backing used for liability admission.

Durable/eventual authority deliberately ignores transient actor `offline`
status. Offline actors can block `CanOperate` now without making an output
durably stranded. Conversely, recognizing a structurally viable recovery
capability is not a liveness proof that its operators will participate or that
recovery will finish.

### Accounting scope and history preservation

`GLOBAL` accounting pools active eligible backing against all obligations.
`SEGREGATED` accounting admits liability against eligible backing in the named
pool only. The latter assumes an enforceable legal/entitlement boundary; the
model neither implements nor proves segregation.

The successor-capital action records an external allocation. Temporal progress
to a successor relies on that modeled allocation and weak fairness for the
capital action; capital is an environmental assumption, not something fairness
or key ceremonies create.

`LiabilitiesAccounted`, `ReservationsAccounted`, and
`NullifierHistoryPreserved` check that already-recorded facts are not cleared
during the modeled generation transition. The reservation and nullifier checks
do not prove source-event idempotency, nullifier completeness, source-event
admission, or binding among a source event, an authorization, and a release.

## Decision scenarios

All nine scenario configs pass. `States` is the TLC distinct-state count.

| Scenario | States | Capabilities and incident | Required outcome under stated assumptions | Forbidden outcome |
|---|---:|---|---|---|
| `FALSE_KEEP` | 70 | no recovery capabilities required; false incident | fresh legacy gate record, then `K0` legacy reactivation | activation under the retired gate or without a valid recorded gate ceremony |
| `PARTIAL_RESHARE` | 310 | `RESHARE`; enough usable old shares remain; action response policy disallows `KeepOwner` after the incident | same-key epoch-1 reshare and legacy reactivation | reshare from fewer than `KOwn` same-epoch usable issued contributor triples |
| `CATASTROPHIC_RESHARE` | 480 | `RESHARE`; fewer than `KOwn` old shares remain | derived legacy stranding | legacy `K0` reactivation or a completed reshare below threshold |
| `CATASTROPHIC_NO_RECOVERY` | 40 | identical loss; no recovery branch committed at output creation | derived legacy stranding | arming recovery, creating `KR` replacements, or legacy reactivation |
| `CATASTROPHIC_DELAYED` | 158 | immutable `RECOVERY` policy; old quorum below threshold | after exact owner/gate records, recovery quorum, bound request, delay, and full consume-and-create migration: active legacy under `KR` | early, sub-quorum, under-bound, unlogged, external, non-conservative, or partial recovery within the modeled incident |
| `THRESHOLD_MIGRATION` | 94 | historical `K0` threshold compromised while an honest same-epoch `K0` quorum remains | fresh gate and `KR` owner records plus owner-authorized full migration; historical `K0` exposure remains permanent | same-key reshare clearing exposure, under-bound owner authorization, in-place owner rewrite, or active unsafe backing |
| `MIXED_EPOCH` | 772 | proactive reshare; adversary learns one epoch-0 and one epoch-1 `K0` triple | the triples do not form a threshold; honest current-epoch response remains possible | combining mixed-epoch triples into an adversarial threshold |
| `SUCCESSOR_GLOBAL` | 420 | `SUCCESSOR`; external capital 3; legacy obligations 3 | recorded `KS` owner DKG before capital, distinct successor gate, and successor activation; zero capacity for a new successor liability | counting quarantined, unsafe, or stranded legacy value, or accepting a new liability without total recapitalization |
| `SUCCESSOR_SEGREGATED` | 1,028 | same physical state under an assumed segregated-entitlement boundary | successor activation **and eventual admission of one successor liability** within successor capacity; legacy obligations remain recorded | erasing/transferring legacy liability or reservation, clearing global nullifier history, or using ineligible legacy outputs as successor backing |

Scenario progress is conditional on stable gate and required
ownership/recovery quorums, fair time advance where needed, and weak fairness
for the relevant modeled actions. Successor scenarios additionally assume the
external capital allocation. The contract never asserts unconditional
`Frozen ~> Active`.

## The 31 safety invariants

| Area | Named invariants | Count |
|---|---|---:|
| State, immutability, conservation | `TypeOK`, `OutputMetadataImmutable`, `RecoveryPolicyImmutable`, `OutputConservation` | 4 |
| Share history and reshare | `ShareIssuanceAccounted`, `ShareHistoryMonotonic`, `MixedEpochIsNotThreshold`, `ReshareSound` | 4 |
| Ceremonies and authorization | `GateCeremonySound`, `FreshGateCeremonies`, `OwnerCeremonySound`, `RecoveryAuthorizationSound`, `RecoveryDelayHonored`, `RecoveryBranchConfinement`, `RecoveryMigrationBound`, `OwnerMigrationSound`, `NoStaleAuthorization` | 9 |
| Migration, activation, authority | `MigrationConsumesOld`, `MigrationConservative`, `FreshOwnerRequiresFullMigration`, `ActiveGateSound`, `ActiveOwnershipSound`, `StrandingSound`, `NoRecoveryWithoutBranch` | 7 |
| Accounting and successor | `LiabilityAdmissionSound`, `LiabilitiesAccounted`, `ReservationsAccounted`, `CapitalizationSound`, `NullifierHistoryPreserved`, `ActiveSolvency`, `SuccessorSound` | 7 |
| **Total** |  | **31** |

## Required Python witnesses

The broad Python exploration must reach all 14 named outcomes:

1. `preincident_reshare`
2. `false_incident_keep_owner`
3. `partial_loss_incident_reshare_active`
4. `catastrophic_reshare_stranded`
5. `mixed_epoch_not_unsafe`
6. `epoch1_partial_loss_exact`
7. `epoch1_catastrophic_loss_exact`
8. `epoch1_threshold_compromise_exact`
9. `threshold_compromise_unsafe`
10. `threshold_honest_owner_migration_active`
11. `catastrophic_recovery_active`
12. `catastrophic_successor_active`
13. `segregated_successor_liability_accepted`
14. `recovery_and_successor_compose`

The repaired Python run reached all 14 witnesses and no forbidden outcome.

## The 36 one-defect falsifiers

| Injected defect group | Configs | Required named failure |
|---|---:|---|
| reshare below threshold, with non-holder claims, or with mixed-epoch contributor triples | 3 | `ReshareSound` |
| erase previously issued shares while retaining only new issuance | 1 | `ShareIssuanceAccounted` |
| clear both current loss and append-only loss history | 1 | `ShareHistoryMonotonic` |
| clear both current adversary knowledge and append-only knowledge history | 1 | `ShareHistoryMonotonic` |
| complete a gate ceremony without quorum | 1 | `GateCeremonySound` |
| reuse `G0` for the replacement legacy gate | 1 | `FreshGateCeremonies` |
| reactivate legacy before replacement gate DKG | 1 | `ActiveGateSound` |
| owner DKG without quorum or with the wrong roster | 2 | `OwnerCeremonySound` |
| owner authorization bound to the wrong old key or an altered/unlogged attached owner authorization | 2 | `OwnerMigrationSound` |
| add a recovery branch retroactively | 1 | `RecoveryPolicyImmutable` |
| authorize recovery before the `KR` owner-DKG event is in the canonical log | 1 | `RecoveryAuthorizationSound` |
| attach altered/unlogged recovery authorization to migration | 1 | `RecoveryMigrationBound` |
| recovery authorization without quorum or with a signed request unequal to the canonical request | 2 | `RecoveryAuthorizationSound` |
| recover before maturity | 1 | `RecoveryDelayHonored` |
| create a replacement without consuming its old output | 1 | `MigrationConsumesOld` |
| create an external, wrong-owner, wrong-policy, or wrong-value replacement | 4 | `MigrationConservative` |
| mutate an existing output owner in place | 1 | `OutputMetadataImmutable` |
| activate `KR` after only partial inventory migration | 1 | `FreshOwnerRequiresFullMigration` |
| activate an adversary-controllable owner key | 1 | `ActiveOwnershipSound` |
| activate successor without its required DKG facts | 1 | `SuccessorSound` |
| reuse a legacy gate key for the successor | 1 | `FreshGateCeremonies` |
| create/fund successor outputs before owner DKG | 1 | `CapitalizationSound` |
| create successor inventory without logged external capital | 1 | `CapitalizationSound` |
| count ineligible output value when admitting liability | 1 | `LiabilityAdmissionSound` |
| erase legacy liability | 1 | `LiabilitiesAccounted` |
| clear the legacy reservation during successor creation | 1 | `ReservationsAccounted` |
| clear already-recorded nullifiers during successor creation | 1 | `NullifierHistoryPreserved` |
| accept authorization under the retired legacy gate | 1 | `NoStaleAuthorization` |
| **Total** | **36** |  |

Each config must enable exactly one non-`NONE` `Bug` selector. TLC and Python
must both reach the designated named failure; incidental additional failures do
not substitute for it. The repaired full run passed all 36 configs in both
engines against those designated failures.

## Explicit boundary and nonclaims

V2 models one incident and one owner/gate rotation over epochs 0 and 1. It does
not model a second incident identifier, repeated recovery generation, or
cross-incident authorization replay. Fresh-gate rejection and exact attached-log
equality therefore support only bounded, current-incident key/authorization
binding claims; they must not be described as general replay safety.

V2 also does not establish:

- FROST, MLSAG, or DKG cryptographic correctness, unforgeability, nonce safety,
  transcript soundness, or ring unlinkability;
- correctness or liveness of either bridge leg, finality, receipts, or
  source-event admission and authorization;
- evidence admission, adjudication, blame, bonds, slashing, or restitution;
- price, exchange-rate, denomination, or fee correctness;
- legal enforceability of segregated claims; or
- safety or liveness across repeated incidents and rotations.
