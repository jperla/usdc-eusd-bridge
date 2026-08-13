# Standalone reserve-recovery model — v1 exploratory artifact

> **Do not use this file to freeze the product decision.** Adversarial review found that its
> delayed-recovery and successor witnesses succeed after a benign false incident but are
> unreachable after the modeled catastrophic loss. The cause is a conflation of lost old-key
> share packages with permanent actor outage. It also encodes composable policy controls as
> exclusive modes and constructs several authorization facts as trusted fields. The replacement
> acceptance contract is [`RECOVERY_V2_TEST_PLAN.md`](RECOVERY_V2_TEST_PLAN.md); v2 is not accepted
> until the catastrophic scenarios themselves pass TLC and the independent mirror.

`ReserveRecovery.tla` is a first executable exploration of `DESIGN.md` §7.1. It is a new,
separate state machine, not a patch to `BridgeEscrow.tla`. The older bridge model remains marked
**DO NOT GATE** because it assumes source validity in a release guard and does not model sound
adjudication.

## Verified result

Run:

```bash
./run_recovery.sh
```

Verified with TLC 2.19 and the independent Python mirror on 2026-08-07:

```text
baseline: 100,078 distinct states, all invariants clean
Python:   100,078 distinct states, exact match
bugs:     all 13 injected defects violate their named invariant
```

The Python checker also finds witnesses for all six required outcomes:

1. partial key loss followed by a same-key reshare and successful legacy reactivation;
2. below-threshold loss followed by explicit legacy stranding;
3. a historical ownership threshold remaining exposed after resharing;
4. delayed recovery consuming every old output before activation under a new key;
5. intentional strand mode reaching its terminal state; and
6. a separately funded successor generation becoming active while legacy liability remains.

The matching state count shows that TLC and `check_recovery.py` implement the same transition
system. It does **not** prove that the abstraction is complete or that MobileCoin cryptography is
secure.

## Scope boundary

`RaiseIncident` is arbitrary environment input. It does not require a fraud proof, verdict, or
objective fault. The model explores false, loss, compromise, and repeated incident inputs.

This module proves only the safety of the response:

- an incident cannot erase liabilities or source-event history;
- a new gate must be ready before legacy reactivation;
- old gate authorizations are rejected;
- output ownership metadata is immutable;
- retained share knowledge and historical threshold exposure are monotonic;
- resharing requires a live old threshold and preserves the group key;
- delayed recovery waits, is recovery-quorum authorized, consumes the old output, preserves value
  and policy, and remains internal to escrow;
- partial migration cannot activate a fresh ownership key;
- stranded, quarantined, or historically exposed outputs do not create new liability capacity; and
- a successor generation cannot silently inherit or erase the legacy generation.

It deliberately makes no claim about:

- whether raising the incident was justified;
- evidence admission, adjudication, slashing, or restitution;
- MLSAG/FROST unforgeability or nonce safety;
- cryptographic ring privacy;
- cross-chain finality or either bridge transfer leg; or
- unconditional liveness.

The later integrated bridge model must refine `RaiseIncident` with observable evidence and
`VerdictSound`; it must not add an `ObjectiveFault` guard to this module.

## State model

The finite instance uses four ownership custodians with `K_OWN = 2`, two share epochs, two gate
epochs, two recovery operators, two reserve units valued at 1 and 2, and two custody generations.
The asymmetry is intentional: it exposes which historical share epoch an adversary knows.

Outputs have fixed identities:

```text
Old(u)   = legacy output under K0
Moved(u) = consumed-and-recreated legacy output under KR
Fresh(u) = separately funded successor output under KS
```

`ownerKey` is initialized from those identities and cannot change. Recovery creates `Moved(u)`; it
never rewrites `Old(u)`. This mirrors MobileCoin's immutable `TxOut.target_key`.

The model separates:

- `issued`: every ownership share ever issued;
- `compromised`: adversarially retained share knowledge;
- `exposed`: ownership keys for which some single historical epoch reached threshold;
- `unavailable`: shares the authorized side can no longer use;
- `stranded`: legacy outputs explicitly classified as unavailable to the authorized roster; and
- `quarantined`: legacy outputs excluded when a successor generation starts.

`UnsafeOutputs` is derived from historical exposure. Unsafe and stranded are independent risk
dimensions and can overlap: an authorized quorum may be gone while an adversarial historical
quorum remains. Neither receives backing credit for new liabilities.

Operational authority excludes both unavailable shares and shares marked compromised in that
sharing epoch. Compromised knowledge remains recorded forever, but it is never counted toward the
honest roster's recovery/liveness threshold.

## Recovery mechanisms and checked outcomes

### Long-lived custody

If an authorized old threshold survives, it can resume behind the newly generated gate. If `K0`
was historically exposed, the pool cannot create new liability capacity until the honest threshold
uses the current gate to consume the old outputs into `KR` outputs. If fewer than `K_OWN` old shares
remain, the legacy pool reaches `Stranded`.

### Same-key reshare

A reshare requires at least `K_OWN` contributors from one authorized, available old share epoch.
It can repair partial loss and restore honest operational liveness. It cannot:

- run below threshold;
- combine sub-threshold shares from different epochs; or
- clear a historical threshold exposure.

If the old ownership threshold is exposed but an honest threshold remains, the fresh gate contains
the old coalition while the honest side migrates outputs. Resharing itself is maintenance, not
revocation.

### Delayed recovery branch

This is the only modeled path that moves legacy outputs without the old ownership threshold. It is
available only because the transaction format is assumed to contain an independently authorized
recovery branch from output creation.

After the delay and recovery quorum authorization, each `Old(u)` is consumed and exactly one
same-value, same-policy `Moved(u)` is created. Activation under `KR` requires every unit to have
migrated. The model treats recovery as an internal escrow migration; it does not permit a customer
withdrawal.

### Strand

The legacy generation becomes terminal and all live legacy outputs are explicitly marked stranded.
Their liabilities remain present.

### Successor-generation continuity

The successor overlay may compose with any recovery mode. It creates separately funded outputs
under `KS` and a fresh gate, retires or leaves stranded the legacy generation, quarantines all
legacy outputs, and preserves legacy liability and nullifier history.

The model explores two accounting policies:

- `GLOBAL`: fresh successor capital must first cover the bridge-wide legacy deficit;
- `SEGREGATED`: the successor has its own liability allocation while the legacy default remains
  explicit.

`SEGREGATED` is an assumption, not a solved protocol feature. eUSD is fungible and private, so a
real deployment needs an enforceable generation-specific entitlement or legal allocation. Without
one, `GLOBAL` is the conservative interpretation: new liquidity can be drained by old redemption
claims and must recapitalize the old deficit before supporting new liabilities.

## Invariants

| Invariant | Checked claim |
|---|---|
| `OutputMetadataImmutable` | an existing output's owner key cannot be rewritten |
| `OutputVersionExclusive` | old and replacement versions cannot both be live |
| `ShareIssuanceAccounted` | issued-share knowledge equals initial shares plus append-only issuance records |
| `CompromiseKnowledgePreserved` | incident response cannot erase adversarially retained shares |
| `HistoricalExposurePreserved` | same-key maintenance cannot clear a historical threshold exposure |
| `ReshareSound` | reshare uses one live old threshold and preserves `K0` |
| `RecoveryDelayHonored` | no recovery migration occurs before maturity |
| `RecoveryAuthorized` | every delayed migration has a recovery quorum |
| `MigrationConsumesOld` | replacement creation consumes the immutable old output exactly once |
| `MigrationConservative` | migration preserves unit/value/policy and remains internal |
| `ActiveGateReady` | post-incident activation uses a completed fresh gate |
| `NoStaleAuthorization` | no accepted authorization uses the retired gate epoch |
| `FreshKeyRequiresFullMigration` | `KR` cannot activate while any old reserve unit remains unmigrated |
| `ActiveOwnershipOperable` | every active generation has a derived operational ownership quorum |
| `StrandingSound` | a stranded legacy generation explicitly classifies every live legacy output |
| `NewLiabilitySound` | every accepted new liability had true eligible capacity at acceptance |
| `LiabilitiesAccounted` | generations cannot erase obligations during restart |
| `NullifierHistoryPreserved` | a generation restart cannot reset consumed source-event history |
| `ActiveSolvency` | an active generation satisfies its configured global or segregated accounting rule |
| `SuccessorIsolation` | successor activation uses fresh inventory and leaves legacy retired/stranded |

## Falsifiers

The model uses one typed `Bug` enum. Unlike independent Boolean switches, it is impossible for a
configuration to enable multiple defects accidentally. `run_recovery.sh` strips TLA+ comments,
parses the assignment, and verifies each config contains exactly its documented value before TLC
runs.

| Injected defect | Must violate |
|---|---|
| reshare with one old contributor | `ReshareSound` |
| erase initial shares during refresh | `ShareIssuanceAccounted` |
| declare a historical threshold healed | `HistoricalExposurePreserved` |
| resume directly from frozen state | `ActiveGateReady` |
| accept an authorization under gate epoch 0 after rotation | `NoStaleAuthorization` |
| rewrite an existing output to `KR` | `OutputMetadataImmutable` |
| migrate before the recovery deadline | `RecoveryDelayHonored` |
| create a replacement without consuming the old output | `MigrationConsumesOld` |
| send recovery to an external recipient | `MigrationConservative` |
| activate `KR` after migrating only one reserve unit | `FreshKeyRequiresFullMigration` |
| count unsafe/quarantined/inactive outputs as capacity | `NewLiabilitySound` |
| zero legacy liability during successor preparation | `LiabilitiesAccounted` |
| clear consumed source-event history on restart | `NullifierHistoryPreserved` |

## Liveness status

The six outcomes above are finite-state reachability/non-reachability checks, not temporal liveness
proofs. A later pass may add weak fairness, but only under explicit environmental assumptions:

- a gate DKG quorum eventually remains online;
- an old ownership threshold exists for long-lived/reshare paths;
- the recovery quorum remains available for delayed recovery;
- time advances; and
- successor capital is actually supplied.

No scheduler fairness assumption can manufacture missing key shares or capital. Therefore the model
must never assert unconditional `Frozen ~> Active`.

## Files

| File | Purpose |
|---|---|
| `ReserveRecovery.tla` | authoritative standalone state machine |
| `ReserveRecovery.cfg` | full clean baseline |
| `ReserveRecovery-bug-*.cfg` | one typed defect and one required counterexample each |
| `check_recovery.py` | independent Python transition mirror and reachability checker |
| `run_recovery.sh` | config validation, TLC runs, baseline parity, Python falsifiers |
