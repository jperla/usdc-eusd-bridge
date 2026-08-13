# Bridge v3 decision register and proof boundary

Status: **PROSPECTIVE / MODEL INPUT — NOT A PRODUCTION CONFIGURATION**

This register separates three things that must not be conflated:

1. protocol semantics that are already fixed by Josh's product outcome;
2. finite constants selected only so exhaustive model checking can run; and
3. production choices or cryptographic constructions that remain unresolved.

Passing a bounded model under the constants below is evidence that the state
machine enforces its stated invariants for that finite domain. It is not a
claim that the constants are economically adequate, that the cryptography is
secure, or that a MobileCoin network upgrade has been implemented.

## A. Frozen semantic decisions

The following are no longer open design questions for the prospective model:

- The product cycle is finalized USDC inflow on Ethereum, eUSD release on
  MobileCoin, finalized typed eUSD return, and USDC release on Ethereum.
- MobileCoin receives a new transaction format and network/block-version
  upgrade. The threshold custody mechanism is protocol-level, not merely a
  wallet convention.
- A threshold spend authorization does not provide signer attribution.
  Individually signed, bond-bound WARDEN and ACCOUNT receipts therefore wrap
  the same base execution digest under distinct role domains.
- Objective source truth is not a release guard. A threshold-valid false
  assertion remains reachable in the baseline model so accountability and
  loss containment are tested rather than assumed away.
- `OPEN_LIABILITY` acquires the stable claim lock but reserves no backing.
  `RESERVE_RELEASE_INTENT` is the first capacity mutation and must precede
  executable authorization. `FINALIZE_RELEASE` consumes the exact prior-block
  reservation atomically.
- Capacity lots follow `Available -> ReservedIntent -> Spent`, or safe cancel
  back to `Available`. Liabilities follow
  `Open -> CapacityReserved -> Settled`, or safe cancel back to `Open` while
  retaining their claim lock and history.
- Source nullifiers follow `Free -> Reserved -> Consumed`; MobileCoin input
  leases follow `Free -> Live -> Consumed`. Safe cancellation may return a
  reserved value to `Free`; settlement never does.
- Finalized outflow remains `FinalizedUncleared` and charged to risk until an
  exact clearance or audit-resolution event fixes its outcome.
- False-source culprits are the unique union of valid WARDEN and ACCOUNT
  approvers. Equivocation culprits are the unique union of the two per-role
  quorum intersections. Operator-fault bonds are frozen/slashed in full;
  distribution is restitution, capped proof cost, capped bounty, then
  insurance. Challenger fault moves only the challenge bond.
- Ethereum and MobileCoin have independent append-only event sequences,
  allocation state, and pause state. Cross-chain causality is represented by
  authenticated references; there is no atomic global counter, hash, pause,
  or transaction.
- MobileCoin policy outputs use an immutable consensus field. Ordinary rings
  contain only untagged outputs; bridge rings contain one exact policy ID.
  This partitions the anonymity set and is an explicit privacy degradation.
- A reserve ownership proof and a reserve accounting proof are separate.
  Ownership row 0 is threshold-held. Row 1 has an explicit profile:
  `CoreCustodyKnownZ` permits a signed authority to know the mask difference,
  while optional `PrivateThresholdZ` distributes it. The second profile is
  privacy hardening, not a prerequisite for k-of-n spend custody. The reserve
  accounting proof still needs a pinned ZK or attested-SGX backend, and
  ordinary RingCT range-proof verification remains independent and mandatory.

## B. Bounded profile B0 for executable state models

These constants exist only to make exhaustive exploration finite. An engine
may use symmetry reduction but must emit these values in its result manifest.

| Dimension | B0 value | Coverage purpose |
|---|---:|---|
| Chains | `{ETH, MOB}` | both local event sequences and causal directions |
| Directions | `{ETH_TO_MOB, MOB_TO_ETH}` | full customer round trip |
| Assets | `{USDC, eUSD}` | typed native vectors; no raw cross-asset sum |
| Generations | `{g0, g1}` | predecessor/successor overlap and drain guards |
| Policy epochs per chain | `2` | pause, rotate, and reopen ordering |
| WARDEN roster | `3`, threshold `2` | majority intersection and one offline signer |
| ACCOUNT roster | `3`, threshold `2` | independent accountable quorum |
| Owner/MLSAG roster | `3`, threshold `2` | sub-threshold rejection and liveness |
| FROST gate roster | `3`, threshold `2` | gate separation and rotation |
| Ethereum execution roster | `3`, threshold `2` | native multisig abstraction |
| Source events | at most `2` per direction | replay and second-liability attacks |
| Liabilities | at most `2` per direction | concurrent reservation and cap boundary |
| Capacity lots | `2` per asset/generation | alias, split, and double-reserve attacks |
| Abstract principal units | `{0,1,2}` | exact-boundary accept/reject witnesses |
| Local allocation per direction | `2` units | one legal release and one over-cap attempt |
| Common-risk cap | `2` normalized units | serial-drain and cross-direction boundary |
| Input lease tags | `2` | same-input collision and retry lifecycle |
| Local block heights | `{0,1,2,3}` | prior-block reservation and safe cancel |
| Accounting backends | `{ZK_V1, SGX_V1}` | backend partition and fail-closed absence |
| Source adapter profiles | `{V2_AUTO, V1_CONTRACTUAL}` | automatic/non-automatic claim separation |
| Fault classes | `{FALSE_SOURCE, EQUIVOCATION}` | exact culprit-set formulas |
| Verdict classes | `{OPERATOR_FAULT, CHALLENGER_FAULT}` | consequence separation |

For B0, all roster identities and role keys are distinct within a role. One
fixture deliberately overlaps an identity across WARDEN and ACCOUNT while
requiring distinct role-domain signatures and counting its physical bond once.
The baseline uses one active manifest per role; a dedicated rollover fixture
introduces old/new manifests whose permitted quorum pairs have a nonempty
bonded intersection. No B0 threshold is a production recommendation.

Cryptographic validity is represented by typed, immutable tokens whose only
constructors are the corresponding verified protocol actions. Defect runs may
mutate one constructor or verifier rule. This abstraction can prove state
machine consequences of accepting a valid artifact; it cannot prove the
artifact's computational soundness.

## C. Proof claims that can be attempted now

### C1. State-machine safety

The TLA+ and Python engines can independently check:

- no finalization without an exact prior reservation;
- lot, liability, nullifier, input-lease, and risk lifecycle partitions;
- no double reservation, replayed settlement, or serial reuse of uncleared
  collateral;
- source-inventory authenticity and no capital creation from an assertion;
- typed per-asset conservation across a complete bidirectional round trip;
- safe cancellation only after objective non-executability;
- chain-local pause and allocation semantics;
- exact culprit selection, full slash, delayed distribution, and challenger
  isolation; and
- equality of the two engines' accepted/rejected transition projections for
  the shared bounded action set.

These are bounded proofs unless a separately reviewed inductive proof is
provided.

### C2. Structural specification integrity

The contract auditor can check exact document hashes, ID/name uniqueness,
declared counts and layers, selector target/oracle references, event vocabulary,
and byte-order equality for shared schemas. This proves internal consistency of
the acceptance boundary, not behavioral correctness.

### C3. Arithmetic identities

The sizing audit can check mutually exclusive competing-risk probabilities,
the strict-majority survivor identity, regime-mixture arithmetic, cap-ratio
algebra, bond-factor algebra, and input validation. It cannot select a roster,
cap, haircut, enforcement probability, or risk appetite.

## D. Release-blocking unresolved constructions

The following cannot be discharged by a state model and must remain explicit
implementation gates:

1. Per-output verifiable shares of the one-time spend witness and confidential
   amount blinding, including nonlinear `MaskedAmountV2` derivation, typed
   external returns, change, refresh, loss, backup, and recovery.
2. A reviewed two-witness threshold MLSAG reserve ceremony with dedicated
   pre-intent key-image/DLEQ and post-digest nonce rounds, durable nonce burning,
   blame semantics, and a security reduction.
3. One pinned reserve-accounting backend: either a concrete ZK circuit and
   verifier or an exact SGX measurement/attestation profile. MLSAG row 1 alone
   does not prove CapacityLot identity, output classification, fees, gross
   depletion, range validity, or change provenance.
4. MobileCoin wire encodings, consensus validation, block-version activation,
   historical spent-key-image backfill, authenticated receipt dictionary, and
   enclave measurement rollout.
5. Ethereum contract encodings, nonce invalidation/nonexecution proof, finality
   profile, and authenticated MobileCoin receipt verification.
6. Production rosters, allocations, C_loss, valuation/haircut manifests,
   challenge economics, propagation windows, legal collectability, and static
   cross-chain allocation governance.

If any release-blocking construction is absent, unknown, stale, below
threshold, or bound to a different manifest/digest, the only valid transition
is rejection with no reservation or release mutation.

## E. Evidence labels

Use exactly these labels in reports:

- **STRUCTURAL PASS** — document/parser consistency only.
- **BOUNDED MODEL PASS** — all states within the published finite profile were
  explored by the named engine.
- **DEFECT WITNESS PASS** — the single injected defect reached its required
  earliest oracle and no forbidden secondary.
- **CRYPTOGRAPHICALLY REVIEWED** — only after an external cryptographic review
  identifies the construction, assumptions, and proof or accepted reduction.
- **IMPLEMENTED** — code compiles and unit/integration tests pass.
- **NETWORK-UPGRADE VERIFIED** — mixed-version, activation, migration, enclave,
  and end-to-end tests pass on a network matching the published manifest.

No lower label implies a higher one.
