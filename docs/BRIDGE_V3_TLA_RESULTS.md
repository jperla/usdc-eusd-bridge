# BridgeEscrowV3 focused TLA+ checkpoint

Status: **FOCUSED TLA+ BOUNDED CHECK: PASS**

This does **not** claim the decision register's reserved full-contract
`BOUNDED MODEL PASS` or `DEFECT WITNESS PASS` labels. The module is a reduced
lifecycle-composition model, not the complete 28-event, 100-property,
56-scenario, or 176-selector acceptance run.

## Frozen inputs and artifacts

- `BRIDGE_V2_TEST_PLAN.md`:
  `bbbd520350d133124ca77f2827f563cd64692b1495e4949cce65bdf28e2d0f14`
- `BRIDGE_V2_CAPACITY_INTERFACE.md`:
  `71114628df1b10a5eba70f787e160f86d22b2ea81a3398cd0f0825f5a05884dd`
- `BRIDGE_V3_DECISION_REGISTER.md`:
  `5f5719eb3393babff3f11e835e397d0b27f27b790be32f177329e4b98f8f7a1d`
- `BridgeEscrowV3.tla`:
  `afc87b6fa2982f7daf17f44b057113dbae64da0f0af67ccdf6cd3d9e2be7569b`
- baseline `BridgeEscrowV3.cfg`:
  `63dcf13c1443af55e94a9a953e67b84b25783988cac69cbe40494b921e08ef8c`
- honest-cycle `BridgeEscrowV3_honest.cfg`:
  `32dbbb1e3dd4cf205ec955d99f2e20013d777c8201c5b40756edb6613344be50`
- `run_bridge_v3_tla.py`:
  `61a0e64427c8fe474e1e9f96b9cdd9da911218494e541bf5036a20056042a5b3`
- TLA+ Tools jar:
  `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`

## Semantic corrections made before execution

Independent review found two P1 defects in the first draft. Both were fixed
before any model-checking result was accepted:

1. Source inventory and its promoted CapacityLot had been conflated. The
   corrected model keeps source state in `Absent/Encumbered/Available`; reverse
   reservation, finalization, and cancellation mutate only the separately
   promoted lot. `SourceLotProjection` checks the explicit projection.
2. `FullCycleConservation` was vacuous under baseline `Spec`, whose
   `honestStep` remains zero. Baseline now checks eleven invariants without
   counting that implication. A separate deterministic `HonestSpec` reaches
   step 18 and checks the terminal predicate non-vacuously.

## Reproduction

- OpenJDK `21.0.12` (Homebrew)
- TLC `2.19`, 08 August 2024
- one worker, deterministic runner seed/fingerprint selection

From `spec/`:

```sh
JAVA_BIN=/opt/homebrew/opt/openjdk@21/bin/java \
  python3 run_bridge_v3_tla.py
```

The runner first requires a clean SANY semantic pass, then executes the clean
baseline, the separate honest cycle, two reachability witnesses, and eight
named mutants. It exits nonzero if a clean run fails or a mutant/witness does
not violate its designated predicate.

## Exact TLC results

SANY: **PASS**.

Clean configurations:

| Configuration | Generated | Distinct | Depth | Result |
|---|---:|---:|---:|---|
| baseline `Spec`, 11 invariants | 15,860 | 6,564 | 28 | PASS, no error |
| deterministic `HonestSpec`, 12 invariants | 20 | 19 | 19 | PASS, no error |

Required reachability witnesses:

| Witness | Named deliberately false predicate | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| fully authorized false-source release | `NoFalseSourceRelease` | 112 | 68 | 5 |
| complete honest round trip | `NoHonestRoundTrip` | 19 | 19 | 19 |

Named mutant witnesses:

| Mutant specification | Expected oracle | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| `SpecEarlyFinalize` | `PriorBlockReservation` | 54 | 40 | 4 |
| `SpecUnsafeCancel` | `SafeCancellation` | 114 | 70 | 5 |
| `SpecDropFinalExposure` | `FinalizedUnclearedRetained` | 114 | 70 | 5 |
| `SpecEarlyClear` | `FinalizedUnclearedRetained` | 200 | 113 | 6 |
| `SpecExtraCulprit` | `ExactCulpritPenalty` | 200 | 113 | 6 |
| `SpecGlobalPause` | `ChainLocalPauseSound` | 340 | 186 | 7 |
| `SpecReplayPromotion` | `HistoryAndReplaySound` | 1,161 | 581 | 9 |
| `SpecReplayFinal` | `HistoryAndReplaySound` | 200 | 113 | 6 |

The replay-final mutant is diagnostic and may violate more than one full
contract property; this focused runner checks its designated oracle only.

## Model boundary

The executable state includes both chains/directions and represents:

- `Open -> CapacityReserved -> Settled`, with objective cancellation back to
  `Open` while retaining the stable claim lock;
- distinct source inventory and promoted CapacityLots;
- CapacityLot `Available -> ReservedIntent -> Spent`, or cancel to `Available`;
- nullifier `Free -> Reserved -> Consumed`, or cancel to `Free`;
- MobileCoin lease `Free -> Live -> Consumed`, or cancel to `Free`;
- `CapacityReserved -> FinalizedUncleared -> Cleared` risk;
- prior-block reservation and append-only reserve/cancel history;
- chain-local pause bits;
- one unique WARDEN/ACCOUNT culprit-set fixture with cross-role overlap; and
- an 18-transition USDC deposit -> eUSD release -> typed eUSD return -> USDC
  release lifecycle.

OPEN, RESERVE, and FINAL do not inspect `objectiveSource`; therefore a fully
authorized false source remains reachable. The environment action that records
a real source and the post-release fault fixture may inspect ghost truth.

## Explicit limitations

- **No truth-noninterference hyperproperty was model-checked.** Static action
  inspection establishes zero objective-truth reads on the release path, and
  the false-release witness establishes reachability; paired-state successor
  equivalence is checked only in the independent Python model.
- The fault proof is a ghost-truth lookup, not an authenticated evidence
  verifier.
- Penalty semantics cover exact identity-set freeze/distribution only. Bond
  quantities, collectability, loss evidence, full debit, and the ordered
  restitution -> proof cost -> bounty -> insurance arithmetic are absent.
- Cancellation is an abstract validated action with a prior-block guard. The
  cryptographic/finality proof of exact nonexecution is not represented; the
  mutant checks resource unwinding only.
- Pause causality uses a local self-marker. It does not bind an authenticated
  typed fault reference, cross-chain propagation proof, expelled roster, or
  fresh-gate activation.
- Risk maturity is a Boolean transition with no real time/finality bound.
- `FullCycleConservation` checks the terminal lifecycle shape of the honest
  harness. It does not prove amount-vector, fee, valuation, haircut, or
  production solvency arithmetic.
- The model omits generation/roster rotation, multiple liabilities per
  direction, common-risk arithmetic, accounting backend choice, digest/event
  composition, equivocation intersections, challenger penalties, and
  overlapping incidents.
- Cryptographic validity is an atomic transition boundary. No MLSAG, FROST,
  DKG, reserve proof, range proof, ZK circuit, or SGX attestation is proved.

The result is useful bounded evidence for the reduced lifecycle relation and
for the sensitivity of its named mutant oracles. It is not authorization to
activate the network upgrade.
