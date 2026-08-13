# Independent Python bridge-v3 focused-model result

Status: **FOCUSED BOUNDED EXPLORATION: PASS**

This deliberately does **not** claim the decision register's reserved
`BOUNDED MODEL PASS` label. The executable relation is a reduced lifecycle,
accountability, and conservation model; it does not enumerate the complete B0
profile or the amended contract's 28 events, 100 properties, 56 scenarios, and
176 selectors.

This is finite-state evidence, not an inductive theorem, cryptographic proof,
implementation result, network-upgrade result, or production-risk
calculation.

## Reproduction manifest

- Runtime used: Python `3.14.6`.
- Model: `spec/bridge_v3_model.py`.
- Model SHA-256:
  `aad8ff61e7591f80e057807b0a7420385629734481630209d170c11f03f39ea3`.
- Model size/mode: `76,951` bytes, executable.
- Compile:

  ```sh
  PYTHONPYCACHEPREFIX=/tmp/bridge-v3-pycache \
    python3 -m py_compile spec/bridge_v3_model.py
  ```

- Full suite:

  ```sh
  PYTHONHASHSEED=0 \
    python3 spec/bridge_v3_model.py all --max-states 500000
  ```

- Determinism probes repeated the full command with
  `PYTHONHASHSEED=8675309` and `PYTHONHASHSEED=314159`.

All three seeds produced identical exploration counts. A deliberately low
`--max-states 20000` run exits nonzero rather than labeling a truncated search
complete.

## Exhaustive focused exploration

The breadth-first queue exhausted naturally:

| Measure | Result |
|---|---:|
| Distinct states | 22,288 |
| Accepted transition edges | 96,976 |
| Maximum BFS depth | 25 |
| Maximum charged common exposure | 2 normalized units |
| False-source release witness depth | 3 |
| Complete bidirectional round-trip witness depth | 12 |
| Truncated at state limit | no |

The common cap is specifically a **cross-chain charged release-risk cap in
normalized 1:1 model units**. It is not a production valuation, inventory cap,
haircut, price-oracle proof, or permission to add native USDC and eUSD amounts
without an approved conversion policy.

All 16 focused predicates held at every visited state:

`ProjectionAtomic`, `ClaimLockInjective`, `LiveReservationInjective`,
`ReservePrecedesFinal`, `SafeCancellation`, `NullifierExactlyOnce`,
`LeaseExactlyOnce`, `ExposureBound`, `SourcePromotionSound`,
`SourceAuthenticity`, `LotConservation`, `PerAssetConservation`,
`FalseSourceAccountable`, `PenaltyExact`, `ChallengerIsolation`, and
`ChainLocalPause`.

The release-path paired-state test also found identical enabledness and
observable successors through OPEN, RESERVE, and FINAL when only ghost
objective-source history differed. Objective truth is read by environment and
post-release adjudication fixtures, never by a release guard.

## Eight deterministic scenarios

1. Finalized USDC deposit -> MobileCoin eUSD release -> typed eUSD return ->
   Ethereum USDC release, including source promotion and risk clearing.
2. A fully authorized false-source release, unique culprit-bond freeze,
   delayed loss resolution, and ordered distribution.
3. Cross-chain common-risk admission: two charged MobileCoin units block a
   third Ethereum unit even though its local Ethereum allocation remains free.
4. Two false releases sharing one physical culprit-bond set aggregate into one
   incident; distribution rejects until both releases are attached, both risks
   are cleared, and cumulative loss is fixed.
5. A liability opened before a fault freeze cannot reserve afterward because
   RESERVE revalidates the approver bonds.
6. Safe cancellation rejects without objective nonexecution evidence and
   preserves the stable claim lock while returning lot, nullifier, and lease.
7. Chain-local pause preserves an existing reservation and charged risk,
   rejects later finalization on that chain, and leaves objective cancellation
   available.
8. Paired-state objective-truth noninterference.

The accountable-quorum fixture uses 2-of-3 WARDEN and 2-of-3 ACCOUNT rosters.
One identity appears in both selected role quorums but supplies distinct typed
approvals; its physical bond is frozen once. The false-source culprit union is
three unique identities holding 30 units, not four role slots holding 40.

## Focused defect witnesses

Each enabled selector reached its named oracle:

| Selector | Named oracle reached | Other focused predicates reached |
|---|---|---|
| `DOUBLE_RESERVATION` | `LiveReservationInjective` | `LotConservation`, `ProjectionAtomic` |
| `RESERVE_BYPASS` | `ReservePrecedesFinal` | none |
| `UNSAFE_CANCELLATION` | `SafeCancellation` | none |
| `NULLIFIER_REPLAY` | `NullifierExactlyOnce` | none |
| `LEASE_REPLAY` | `LeaseExactlyOnce` | none |
| `SERIAL_DRAIN` | `ExposureBound` | none |
| `FALSE_SOURCE_TRUTH_GUARD` | false-source reachability and truth noninterference | paired-state witness |
| `UNDER_SLASH` | `PenaltyExact` | none |
| `CHALLENGER_MISPUNISH` | `ChallengerIsolation` | none |
| `GLOBAL_PAUSE_COUPLING` | `ChainLocalPause` | none |

`DOUBLE_RESERVATION` is deliberately a compound corruption of the live
reservation, lot, and atomic projection. It is diagnostically useful but does
not satisfy the full acceptance contract's stronger single-target/no-
forbidden-secondary discipline. None of these ten fixtures claims that all
176 contract selectors ran.

## Independent adversarial audit and repaired counterexamples

An independent audit falsified the first draft despite its clean 24,192-state
run:

- it enforced only separate per-chain allocations and admitted three units
  against the declared two-unit common cap; and
- it could distribute one shared culprit-bond set after clearing one false
  release while another false release by the same culprits remained
  `FinalizedUncleared` and uncollectible.

The result was withdrawn, repaired, and re-explored. The post-repair audit of
the exact model hash above independently scanned the full state graph and
reported:

- 2,224 observations of states containing a distribution;
- 6,560 trials of RESERVE from an OPEN liability with non-LOCKED approver
  bonds;
- zero common exposure above two;
- zero distributions omitting a same-culprit false release;
- zero distributions with an uncleared risk or unfixed loss; and
- exact aggregate restitution in every distribution-bearing state.

The old traces now reject respectively with `common-risk exposure cap
exceeded`, `related false release is outside the incident` followed by
`implicated risk/loss is unresolved`, and `approver bond changed after OPEN`.
No P0 or P1 model-logic defect remained in that post-repair audit.

## Explicit deviations from full B0 and production semantics

- Generation and epoch rotation are not enumerated; only chain-local pause is
  modeled.
- Owner/MLSAG, FROST-gate, and Ethereum execution quorums are typed validity
  tokens, not roster-state variables.
- Principal transitions use one unit; zero and two are boundary/cap values.
- Lots are not indexed by generation.
- Prior-block ordering is a committed-predecessor marker rather than explicit
  heights 0 through 3.
- Risk maturity and admissible loss evidence are typed tokens rather than
  enumerated time/finality schedules.
- Accounting backends and V1/V2 adapters are closed validity-token boundaries.
- Equivocation and cross-manifest culprit intersections are outside this
  focused relation.
- False releases sharing the one modeled physical culprit set aggregate into
  one incident; partially overlapping culprit sets and multi-incident
  collateral apportionment are not modeled.
- Common risk uses normalized one-unit equivalents; production valuation,
  haircut, and oracle arithmetic are not modeled.
- Only ten focused selectors run, not the full acceptance inventory.

These limitations are why the result remains a focused bounded checkpoint.
