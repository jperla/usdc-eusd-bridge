# Design record

**Read [`FINAL-PLAN.md`](FINAL-PLAN.md) first. It is the authoritative design;
this directory is the record of how it was reached, and parts of it are
superseded.**

Everything below the line is kept because the reasoning and the counterexamples
are worth having, not because it is current. Where they disagree with
`FINAL-PLAN.md`, `FINAL-PLAN.md` wins. Specifically:

| superseded here | current |
|---|---|
| an 8-of-11 signer policy | 3 operators (2-of-3) **and** 1 independent gate — four entities, `T = 3` |
| "bridge-v3 acceptance contract" as the target | the plan in `FINAL-PLAN.md`, implemented in `contracts/` and `crates/` |
| a ~25× cheaper block-signature route | **withdrawn** — it compared an exact count against an estimate over an assumed evidence size |

The machine-checked artifacts these documents refer to are in
[`../proofs/`](../proofs/), and they are current: the TLA+ models and their
runners, the executable spikes, and the gas measurement.

---

# Bridge escrow formal evidence

> **The bridge-v3 acceptance contract is an active prospective draft pending
> the M4 custody-profile refreeze; it has not earned the reserved
> `BOUNDED MODEL PASS` label.**
> [`BRIDGE_V2_TEST_PLAN.md`](BRIDGE_V2_TEST_PLAN.md),
> [`BRIDGE_V2_CAPACITY_INTERFACE.md`](BRIDGE_V2_CAPACITY_INTERFACE.md), and
> [`BRIDGE_V3_DECISION_REGISTER.md`](BRIDGE_V3_DECISION_REGISTER.md) define
> the active prospective target. The retained V2 filenames identify the
> amended contract documents.
>
> Two independently reviewed **focused** checkpoints now pass. The Python
> model exhausts 22,288 states / 96,976 edges, reaches the complete customer
> round trip, and passes eight deterministic scenarios plus ten defect
> fixtures. The TLA+ baseline is invariant-clean over 6,564 distinct states;
> its separate 19-state honest harness makes the full-cycle terminal predicate
> non-vacuous, and ten named witnesses fire. These engines intentionally model
> different reduced relations, so no state-count parity or graph-isomorphism
> claim is made. Read
> [`BRIDGE_V3_PYTHON_RESULTS.md`](BRIDGE_V3_PYTHON_RESULTS.md) and
> [`BRIDGE_V3_TLA_RESULTS.md`](BRIDGE_V3_TLA_RESULTS.md) for exact limits.
>
> The first cryptographic feasibility gate now also passes. The audited M2
> spike constructs 298 verifier-accepted ordinary MobileCoin MLSAG artifacts,
> including every signer set satisfying the provisional 8-of-11 policy at one
> ring position. Read
> [`MOBILECOIN_THRESHOLD_MLSAG_RESULTS.md`](MOBILECOIN_THRESHOLD_MLSAG_RESULTS.md).
> This proves the two-row threshold algebra, not real masked-amount custody,
> authenticated slashing evidence, a full transaction, or the network upgrade.
>
> The next focused integration gate also passes. M3 places M2b behind a real
> MobileCoin v4 `RingSigner` path for two `MaskedAmountV2` inputs and constructs
> six verifier-accepted MLSAGs across all three exact 2-of-3 subsets. Three
> complete signature/RingCT objects pass stock `validate_signature`, including
> v4 range proofs and commitment conservation; the negative mutation matrix
> also rejects as required. Read
> [`MOBILECOIN_M3_TRANSACTION_RESULTS.md`](MOBILECOIN_M3_TRANSACTION_RESULTS.md).
> The membership proofs are synthetic and the deliberately insecure fixture
> reconstructs spend and mask scalars, so this is not full-ledger acceptance,
> strict distributed custody, on-chain policy, or a network-upgrade pass.
>
> M4a now closes the narrow spend-scalar custody gap. The offset spike derives
> the exact MobileCoin one-time-key offset from `(R,a,i)` without accepting the
> root spend scalar or returning the one-time scalar. The core-custody spike
> then runs real Serai PedPoP 2-of-3 key generation, applies the validated
> offset, and reproduces M3's two-input result for every qualifying subset:
> six MLSAGs and three complete signature/RingCT objects pass stock validation,
> while the frozen source constructs no complete root, subaddress, or one-time
> spend scalar. Read [`MOBILECOIN_M4_ONETIME_OFFSET_RESULTS.md`](MOBILECOIN_M4_ONETIME_OFFSET_RESULTS.md)
> and [`MOBILECOIN_M4_CORE_CUSTODY_RESULTS.md`](MOBILECOIN_M4_CORE_CUSTODY_RESULTS.md).
> This remains a same-process fixture with complete view/mask material,
> synthetic membership, and no consensus-visible authorization.
>
> M4b separately proves balanced threshold pseudo-mask algebra. That is optional
> `PrivateThresholdZ` privacy hardening, not a prerequisite for k-of-n spend
> custody. A complete private-Z v4 transaction remains open because the stock
> range prover consumes complete blinding witnesses. The authenticated ceremony
> document is a reviewed design/test plan, not executed code; durable restart
> safety, identity-authenticated blame, process isolation, the new transaction
> format, and network activation are still gates.
>
> One focused M5 implementation slice now passes. The single-host SQLite
> operation-journal oracle survived 53 deterministic crash, race, alias,
> rollback, expiry, replay, and semantic-corruption tests across three
> Python/SQLite versions. It atomically binds an authenticated source and its
> complete real-UTXO/input set, requires exact operation-wide authorization
> before modeled response persistence/transmission, and detects coherent
> cross-operation authorization/retry reassignment. Read
> [`MOBILECOIN_M5_OPERATION_JOURNAL_RESULTS.md`](MOBILECOIN_M5_OPERATION_JOURNAL_RESULTS.md).
> This is not full M5: fixture proof/liveness boundaries, an ordinary-file
> anchor, and same-process SQLite do not establish authenticated networking,
> sealed nonce custody, isolated signers, replicated monotonicity, or the
> PedPoP/share/catalog lifecycle. It proves no on-chain FROST/warden rule,
> MobileCoin upgrade, or bridge cycle.
>
> A second narrow M5 checkpoint independently ports the candidate codec and ID
> derivations to Rust. All 110 frozen Python vectors match; validated newtypes
> and whole-history checks close a caller-supplied input-count bypass found in
> review. Twenty-nine Rust tests pass, including 9,309 exhaustive
> prefix/trailing boundary falsifiers. Read
> [`MOBILECOIN_M5_RUST_CODEC_RESULTS.md`](MOBILECOIN_M5_RUST_CODEC_RESULTS.md).
> It did not itself prove a durable/replicated journal, real proof boundary,
> nonce custody, ceremony, consensus rule, warden penalty, or bridge cycle.
>
> A third focused M5 checkpoint ports the representative monotone journal
> control plane to Rust. Twenty-eight tests pass on Rust 1.97.1 and exact Rust
> 1.83.0, covering atomic complete reservation, operation-wide authorization,
> anchored persist-before-observe recovery, rollback/integrity checks, and
> adversarial races. Read
> [`MOBILECOIN_M5_RUST_JOURNAL_RESULTS.md`](MOBILECOIN_M5_RUST_JOURNAL_RESULTS.md).
> This is not a production signer: the fixture still accepts caller-supplied
> response bytes and its nonce states are symbolic. An isolated produce-once
> signer/HSM with globally unique durable nonce custody is the next P0.
> The concrete sealed-receipt/release-certificate protocol, state machines,
> success/failure conditions, and adversarial matrix are specified in
> [`MOBILECOIN_M5_PRODUCE_ONCE_SIGNER_TEST_PLAN.md`](MOBILECOIN_M5_PRODUCE_ONCE_SIGNER_TEST_PLAN.md).
> Its nonce-reuse claims have an executable scalar-algebra witness in
> [`frost_nonce_reuse_witness.py`](frost_nonce_reuse_witness.py).
>
> A fourth focused M5 checkpoint now makes that sealed-receipt ordering
> executable. The bounded Rust nonce-vault passes 17 tests on Rust 1.97.1 and
> exact Rust 1.83.0; a separate TLA+ model passes over 18 distinct states,
> while two deliberately defective variants violate the intended anchor and
> single-binding invariants. The implementation commits opaque round-one
> context digest values before exposing a commitment, rejects changed values
> and later request mismatch, computes one modeled response, and returns only
> an opaque receipt. It does not yet authenticate or recompute the complete
> context preimages at commit time. Its in-memory authority fixture must retain
> the exact certificate before release; the separate TLA+ model, not the Rust
> crate, represents receipt persistence and anchoring as distinct steps. Read
> [`MOBILECOIN_M5_RUST_SIGNER_VAULT_RESULTS.md`](MOBILECOIN_M5_RUST_SIGNER_VAULT_RESULTS.md)
> and
> [`MOBILECOIN_M5_SEALED_RESPONSE_TLA_RESULTS.md`](MOBILECOIN_M5_SEALED_RESPONSE_TLA_RESULTS.md).
> This remains an in-memory deterministic-hash fixture: real FROST/MLSAG,
> persistent/HSM nonce custody, journal-vault integration, abrupt-death and
> rollback evidence, consensus rules, and the bridge cycle remain open.
>
> The next journal/vault ordering has a separate executable reference model.
> Its honest one-child search is invariant-clean across 128 states / 192 labeled
> edges and reaches four safe delivered-state variants; thirteen isolated
> defects produce shortest named witnesses from 1 to 18 edges. Release
> persistence, opaque response return, and publisher observation are separate,
> including the crash window after release and before return. Read
> [`MOBILECOIN_M5_JOURNAL_VAULT_MODEL_RESULTS.md`](MOBILECOIN_M5_JOURNAL_VAULT_MODEL_RESULTS.md)
> and the prospective implementation contract in
> [`MOBILECOIN_M5_JOURNAL_VAULT_INTEGRATION_PLAN.md`](MOBILECOIN_M5_JOURNAL_VAULT_INTEGRATION_PLAN.md).
> The Python state checks symbolic retained identities and projections only.
> It collapses durable-vault/checkpoint internals into symbolic transitions;
> its explicit anchor-ahead flag is an injected oracle, not a verified root
> mismatch. The expanded Rust/SQLite/vault-v2 gate, cold-restart evidence,
> exact proof codecs, and real cryptography remain unexecuted.
>
> A privacy-model correction is also executable. The earlier hypergeometric
> calculation is retained only as a conditional known-spent-set-oracle
> sensitivity analysis: public MobileCoin key images do not identify which
> ring output was spent. A separate trace checker proves that selecting only
> internally known-unspent decoys can instead leak an earlier real member via
> later ring appearances to a ring-observing adversary. No quantitative bridge
> anonymity claim or unspent-only selector is accepted. Read
> [`PRIVACY_SELECTOR_COUNTEREXAMPLE.md`](PRIVACY_SELECTOR_COUNTEREXAMPLE.md).
>
> **Recovery v2 is archived, verified decision analysis—not current product scope.**
> Josh removed key recovery and escrow-key-compromise recovery from scope on
> 2026-08-08 (shared-channel #53). The artifacts and results below remain
> reproducible evidence, but they are not implementation requirements;
> The amended bridge-v3 contract is the active formal target.
> The repaired broad TLC run is safety-clean across 1,670,448 distinct states and 31 named
> invariants. All 16 disjoint feature/scope profiles match exactly between TLC and Python and sum
> to 1,670,448; all nine temporal scenarios pass. The acceptance inventory also contains 36
> non-`NONE` defect configurations and 14 required Python witnesses. The independent Python broad
> exploration matches TLC's 1,670,448-state cardinality; all 36 defects hit their designated
> invariant in both engines, all 14 witnesses are reached, and zero forbidden outcomes are reached.
> Equal reachable-state counts are cardinality-parity evidence—not graph identity or isomorphism.
> Read [`RECOVERY_V2.md`](RECOVERY_V2.md) for the
> result and limits, and
> [`RECOVERY_V2_TEST_PLAN.md`](RECOVERY_V2_TEST_PLAN.md) for the acceptance contract.
> `ReserveRecovery.tla` remains a v1 exploratory artifact and must not be used for a decision.
> Recovery v2 documents the now-descoped bounded reserve-authority/continuity fork; it is not a
> product gate for the cryptography or the bidirectional bridge.

Recovery v2 interprets `RECOVERY_V1` as an immutable, versioned policy commitment to a recovery
roster/key, threshold, delay, domain, and request schema. Its DKG and authorization events are
abstract records, not cryptographic proofs. `Unsafe` takes priority over, and is exclusive with,
per-output durable `Stranded`; neither class backs liabilities. Successor progress assumes external
capital, and `SEGREGATED` accounting assumes a legal entitlement boundary. The model covers one
incident/rotation and does not prove bridge legs, FROST/MLSAG/DKG cryptography, source-event
idempotency, evidence/slashing, price/fees, legal segregation, or repeated-incident replay safety.

Models the two-gate escrow release, the source-event nullifier, epoch rotation on fault, and the
blame adjudicator. Corresponds to `DESIGN.md` §2 (design), §3 (why each gate), §4 (penalty).

## Files

| File | Purpose |
|---|---|
| `BridgeEscrow.tla` | v1 exploratory bridge model; known semantic gaps 1–3 |
| `BridgeEscrow.cfg` | v1 baseline config |
| `bug-*.cfg` | v1 injected-defect configs |
| `BRIDGE_V2_TEST_PLAN.md` | active prospective acceptance contract; custody-profile tables require M4 refreeze before its counts/labels are authoritative |
| `BRIDGE_V2_CAPACITY_INTERFACE.md` | frozen typed core-to-capacity boundary; 75 invariants and 119 interface selectors |
| `BRIDGE_V3_DECISION_REGISTER.md` | frozen semantics, finite-profile boundary, and 19 production/release blockers |
| `bridge_v3_model.py` | independently audited focused Python state model |
| `BRIDGE_V3_PYTHON_RESULTS.md` | exact Python counts, repaired counterexamples, and scope |
| `BridgeEscrowV3.tla` | reduced TLA+ lifecycle-composition model |
| `BridgeEscrowV3.cfg` / `BridgeEscrowV3_honest.cfg` | baseline and non-vacuous honest-cycle configurations |
| `run_bridge_v3_tla.py` | reproducible SANY/TLC baseline, scenario, and mutant suite |
| `BRIDGE_V3_TLA_RESULTS.md` | exact TLA+ counts and explicit abstraction limits |
| `audit_bridge_v3_tla.py` | hash-bound static companion audit; not a substitute for TLC |
| `MOBILECOIN_PROTOCOL_PATCH_MAP.md` | source-anchored MobileCoin v5 implementation lanes and release gates |
| `MOBILECOIN_THRESHOLD_MLSAG_RESULTS.md` | audited M2a/M2b verifier-acceptance evidence and exact limitations |
| `MOBILECOIN_M3_TRANSACTION_INTEGRATION_PLAN.md` | source-anchored real `MaskedAmountV2`/SigningData/range-proof integration test plan |
| `MOBILECOIN_M3_TRANSACTION_RESULTS.md` | executed two-input v4 threshold-MLSAG/signature/RingCT integration result and production blockers |
| `MOBILECOIN_M4_ONETIME_OFFSET_RESULTS.md` | executed canonical `(R,a,i)->delta` derivation/equivalence result and privacy boundary |
| `MOBILECOIN_M4_CORE_CUSTODY_RESULTS.md` | executed real-PedPoP root-spend custody result over the M3 transaction path and exact limitations |
| `MOBILECOIN_M4_MASK_PROTOCOL_DESIGN.md` | executed threshold pseudo-mask algebra plus private-Z range-proof boundary |
| `MOBILECOIN_M4_CEREMONY_INTERFACE_TEST_PLAN.md` | authenticated operation/ceremony protocol and adversarial test plan; design-only until implemented |
| `MOBILECOIN_M5_OPERATION_JOURNAL_RESULTS.md` | executed 53-test single-host operation-journal checkpoint, counterexamples, exact claims, and remaining M5/M6 gates |
| `MOBILECOIN_M5_RUST_CODEC_RESULTS.md` | executed independent Rust codec/ID portability and validated-history checkpoint, including the caller-count counterexample and exact boundary |
| `MOBILECOIN_M5_RUST_JOURNAL_RESULTS.md` | executed 28-test Rust monotone journal control-plane checkpoint, raw-response/nonce P0s, and next signer/HSM gate |
| `MOBILECOIN_M5_PRODUCE_ONCE_SIGNER_TEST_PLAN.md` | sealed produce-once signer/HSM protocol, canonical objects, crash handshake, exact acceptance/failure conditions, and adversarial implementation matrix |
| `MOBILECOIN_M5_RUST_SIGNER_VAULT_RESULTS.md` | executed 17-test bounded Rust sealed-receipt vault checkpoint, repaired counterexamples, exact nonclaims, and next journal-integration gate |
| `MOBILECOIN_M5_JOURNAL_VAULT_INTEGRATION_PLAN.md` | journal-v2/vault-v2/API/happens-before design and 22-test-plus-mutants contract for removing caller response bytes from the journal path |
| `m5_journal_vault_model.py` | exhaustive symbolic one-child model of Jc/C/J0/J1/J2/J3/release/outbox/delivery ordering |
| `test_m5_journal_vault_model.py` | frozen honest counts, release-boundary/retry/restart cases, and thirteen shortest mutant traces with exact violation sets |
| `MOBILECOIN_M5_JOURNAL_VAULT_MODEL_RESULTS.md` | exact 128-state/192-edge bounded symbolic-projection result, hashes, witnesses, and nonclaims |
| `M5SealedResponse.tla` / `M5SealedResponse.cfg` | bounded sealed-response ordering model and honest configuration |
| `M5SealedResponse-bug-cert-without-anchor.cfg` / `M5SealedResponse-bug-rebind-changed-request.cfg` | one-defect configurations that must violate their designated invariants |
| `MOBILECOIN_M5_SEALED_RESPONSE_TLA_RESULTS.md` | exact TLC state counts, named counterexamples, hashes, and abstraction boundary |
| `frost_nonce_reuse_witness.py` | executable two-effective-nonce/three-pair-reuse scalar extraction witnesses and precise two-generic-response limitation |
| `anonymity.py` | conditional single-ring sensitivity arithmetic under an explicit perfect known-spent-set oracle; not a MobileCoin privacy measurement |
| `privacy_selector_trace.py` | exhaustive small / constructive size-11 temporal-elimination counterexample for unspent-only selection |
| `PRIVACY_SELECTOR_COUNTEREXAMPLE.md` | observer-model correction, executable result, capacity correction, and privacy-claim boundary |
| `ReserveRecoveryV2.tla` | archived, checked recovery/continuity decision model |
| `check_recovery_v2.py` | independent exhaustive mirror and witness/forbidden-outcome checks |
| `ReserveRecoveryV2-*.cfg` | profiles, conditional scenarios, and one-defect falsifiers |
| `run_recovery_v2.sh` | complete reproducible TLC/Python verification suite |
| `RECOVERY_V2.md` | verified result, interpretation, and explicit scope boundary |
| `RECOVERY_V2_TEST_PLAN.md` | acceptance contract used to build and judge v2 |

## Running the focused bridge-v3 checkpoints

```bash
PYTHONHASHSEED=0 python3 bridge_v3_model.py all --max-states 500000
python3 audit_bridge_v3_tla.py
JAVA_BIN=/opt/homebrew/opt/openjdk@21/bin/java python3 run_bridge_v3_tla.py
```

The Python command fails closed if the BFS state ceiling truncates the search.
The TLA+ runner requires SANY success, two clean configurations, and the exact
named predicate from each reachability/mutant case. The static auditor checks
hashes and structural relationships only; its output is explicitly not TLC.

## Running the threshold-MLSAG feasibility spike

```bash
cd /Users/jperla/josh/m2-threshold-mlsag-spike
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline \
  strict::tests::target_eight_of_eleven_accepts_every_qualifying_subset \
  -- --ignored --exact
```

The fast suite passes 10 tests and intentionally ignores the roughly
two-minute deployment-candidate enumeration. The explicit test covers all 232
signer sets of sizes 8 through 11. Both runs ultimately call MobileCoin's
unmodified `RingMLSAG::verify`; they do not invoke full transaction validation.

## Running the M3 transaction-integration spike

The exact compiler, Clippy, `protoc`, offline-build commands, and frozen hashes
are recorded in `MOBILECOIN_M3_TRANSACTION_RESULTS.md`. In the recorded local
environment:

```bash
cd /Users/jperla/josh/m3-mobilecoin-tx-spike
PATH=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin:$PATH \
RUSTC=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin/rustc \
RUSTDOC=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin/rustdoc \
PROTOC=/tmp/m3-protoc/bin/protoc \
cargo test --locked --offline
```

The test proves stock signature/RingCT integration only. Its placeholder
membership proofs are not suitable for ledger validation, and its adapter is
intentionally named `InsecureFixtureThresholdRingSigner` because it
materializes complete custody secrets.

## Running the M4 custody checkpoints

Use the exact nightly/compiler environment recorded in the M4 result files:

```bash
cd /Users/jperla/josh/m4-onetime-offset-spike
cargo test --locked --offline --all-targets

cd /Users/jperla/josh/m4-core-custody-spike
cargo test --locked --offline -- --nocapture

cd /Users/jperla/josh/m4-mask-algebra
cargo test --locked --offline --all-targets
```

The first command proves the offset API/equivalence only. The second executes
real PedPoP root-share generation and the stock-v4 two-input core-custody path.
The third proves private-mask linear algebra with a test dealer; it does not
implement the authenticated mask-slot ceremony, proof-worker boundary, or a
complete private-Z transaction. Read each frozen result/design document for
the required toolchain variables, source hashes, and nonclaims.

## Running the M5 operation-journal checkpoint

```bash
cd /Users/jperla/josh/m5-operation-journal-spike
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -q test_m5_journal.py
ruff check --no-cache m5_journal.py test_m5_journal.py
ruff format --check --no-cache m5_journal.py test_m5_journal.py
```

The final suite has 53 tests and no third-party Python runtime dependency. It
proves only the reference state machine's single-host safety claims. The exact
multi-version run, frozen hashes, repaired counterexamples, and nonclaims are
recorded in `MOBILECOIN_M5_OPERATION_JOURNAL_RESULTS.md`.

## Running the M5 Rust codec checkpoint

```bash
cd /Users/jperla/josh/m5-rust-codec-spike
cargo test --frozen --all-targets
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt --all -- --check
python3 -B -m unittest -v reference/test_reference_vectors.py
```

The Rust tests consume only the committed static corpus; the Python command
separately proves that the frozen oracle still regenerates those exact bytes.
This checkpoint validates codec portability and local operation-history shape,
not durable journal semantics or MobileCoin consensus.

## Running the M5 durable Rust journal checkpoint

```bash
cd /Users/jperla/josh/m5-rust-journal-spike
env CARGO_TARGET_DIR=/tmp/m5-rust-journal-target cargo test --locked --offline --all-targets
env CARGO_TARGET_DIR=/tmp/m5-rust-journal-target cargo clippy --locked --offline --all-targets -- -D warnings
python3 -B -m unittest -v reference/test_reference_vectors.py
```

The suite exercises the representative local journal kernel and ordinary-file
fixtures. It does not prove signer/HSM nonce custody, cross-process or
distributed monotonicity, production proof adapters, or MobileCoin consensus.
The exact Rust 1.83 command and failure contract are in
`MOBILECOIN_M5_RUST_JOURNAL_RESULTS.md` and the crate's `RESULTS.md`.

## Running the signer-vault nonce-reuse witness

```bash
python3 -B frost_nonce_reuse_witness.py --selftest
ruff check --no-cache frost_nonce_reuse_witness.py
ruff format --check --no-cache frost_nonce_reuse_witness.py
```

These four algebraic tests prove the concrete extraction failures used by the
produce-once test plan. They do not implement FROST or prove HSM durability.

## Running the bounded M5 sealed signer/vault checkpoint

```bash
cd /Users/jperla/josh/m5-rust-signer-vault-spike
env CARGO_TARGET_DIR=/tmp/m5-signer-vault-target \
    CARGO_NET_OFFLINE=true \
    /opt/homebrew/bin/cargo test --locked --offline --all-targets
env CARGO_TARGET_DIR=/tmp/m5-signer-vault-target \
    CARGO_NET_OFFLINE=true \
    /opt/homebrew/bin/cargo-clippy clippy --locked --offline \
    --all-targets -- -D warnings
/opt/homebrew/bin/rustfmt --check src/lib.rs src/codec.rs src/vault.rs src/tests.rs
```

The exact Rust 1.83.0 command and hashes are recorded in
`MOBILECOIN_M5_RUST_SIGNER_VAULT_RESULTS.md`. The crate uses in-memory state and
deterministic tagged-hash fixtures; it is not a durable or cryptographic signer.

Run the associated bounded formal model from `/Users/jperla/josh/spec`:

```bash
/opt/homebrew/opt/openjdk/bin/java -XX:+UseParallelGC -cp tla2tools.jar \
  tlc2.TLC -nowarning -workers 1 -seed 1 -fp 0 \
  -metadir /tmp/m5-sealed-response-tlc-honest \
  -config M5SealedResponse.cfg M5SealedResponse.tla
```

The two expected-failure mutant commands and their named invariant violations
are frozen in `MOBILECOIN_M5_SEALED_RESPONSE_TLA_RESULTS.md`.

## Running the bounded journal/vault integration-order model

```bash
cd /Users/jperla/josh/spec
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
  test_m5_journal_vault_model.py
/opt/homebrew/anaconda3/bin/ruff check --no-cache \
  m5_journal_vault_model.py test_m5_journal_vault_model.py
/opt/homebrew/anaconda3/bin/ruff format --check --no-cache \
  m5_journal_vault_model.py test_m5_journal_vault_model.py
```

The honest symbolic search reaches 128 states / 192 labeled edges; thirteen
isolated defects have frozen shortest traces and exact violation sets. This
model does not execute SQLite, canonical row/proof codecs, filesystem/anchor
failures, a durable vault, an HSM, or cryptography. “Exact” means one retained
symbolic identity, not byte equality. Its exact scope and hashes are in
`MOBILECOIN_M5_JOURNAL_VAULT_MODEL_RESULTS.md`.

## Running the privacy-model corrections

```bash
python3 anonymity.py selftest
python3 privacy_selector_trace.py --selftest
python3 privacy_selector_trace.py
```

The first command checks only hypergeometric arithmetic and prints that its
adversary premise is untested. The latter commands exhaustively check the
three-member inference and construct the size-11 temporal-elimination witness.
They deliberately distinguish chain-only from ring-observing adversaries.

## Running recovery v2

```bash
./run_recovery_v2.sh
```

The v2 runner validates every config, checks the broad model and 16-profile
partition, compares TLC/Python reachable-state cardinalities, checks all nine
temporal scenarios, and exercises all 36 named falsifiers and 14 required
Python witnesses. The published repaired results above come from a complete
successful run of this contract.

## Running the historical v1 BridgeEscrow model

```bash
./run.sh
```

That runs TLC on the baseline and all five bug configs, checks each violates its **named**
expected invariant, then runs the Python mirror for cross-comparison. It fetches `tla2tools.jar`
if missing and exits non-zero on any mismatch.

Prerequisite: a real JVM. **The system `/usr/bin/java` on macOS is a stub** that prints "Unable to
locate a Java Runtime" — `brew install openjdk` and note it is keg-only, so the binary lives at
`/opt/homebrew/opt/openjdk/bin/java` (which `run.sh` uses by default; override with `JAVA=`).

State space is small by design (5 operators, 2 events, 3 outputs); every run finishes in seconds.
Widen the constants only after all five configs behave as documented.

## Historical v1 verified results

TLC 2.19 on OpenJDK 26, 2026-08-07:

```
  BridgeEscrow      13894 states  PASS   clean
  bug-legacy            4 states  PASS   violates NoBypass
  bug-cert           1263 states  PASS   violates NoBypass
  bug-nullifier       161 states  PASS   violates NoDoubleRelease
  bug-rotate            9 states  PASS   violates RotationSound
  bug-epoch          1263 states  PASS   violates NoStaleAuthorization
```

**The baseline distinct-state count matches the Python mirror exactly (13894 = 13894)**, from two
independently written implementations. That is useful cardinality-parity and regression evidence,
not evidence of graph identity or isomorphism. Bug-config counts differ because TLC halts at the
first violation while the mirror explores the whole space and collects every violation — so a
*baseline* mismatch would indicate a real problem; bug-config mismatches would not.

Each config's invariants are declared individually rather than as a single `Safety` conjunction,
so TLC names the specific failing invariant. Declaring only the conjunction tells you *something*
broke but not *what*, which is not enough to know a switch broke the thing it was aimed at.

## What is deliberately *not* modelled

The cryptography. There is no MLSAG, no FROST, no signature. The spec models **whether the
required authorization artifact was produced by a party able to produce it**, which is the right
abstraction for reachability questions and the wrong one for unforgeability.

The other layers get their own tools, per `DESIGN.md` §9 and the verification plan:

| Layer | Tool | Why not here |
|---|---|---|
| Nonce single-use across restarts | Verus / Kani | a linearity property over Rust state, not a protocol reachability question |
| Ceremony replay / cross-epoch confusion | Tamarin | needs a symbolic attacker model |
| Threshold MLSAG unforgeability | (paper proof first) | no written reduction exists yet; formalizing before that is backwards |
| Bond arithmetic, slashing contract | Certora | lives in Solidity |
| Decoy exchangeability | statistical testing | not expressible as an invariant |

Mixing any of those in here would explode the state space and verify nothing well.

## The bug switches, and why they exist

**A specification that cannot reproduce a known bug is not validating anything.** Each switch
injects a defect we argued about during design. Each *must* break a specific invariant. If a
switch is flipped and everything still passes, the spec is too weak — fix the spec.

| Switch | Injects | MUST violate | The argument it encodes |
|---|---|---|---|
| `BUG_LegacyPathOpen` | escrow outputs stay spendable via the ordinary MLSAG path | `NoBypass` | Sol's §15.2: if a legacy path survives, a corrupt quorum omits the certificate and the second gate is decorative |
| `BUG_OptionalCertificate` | the warden certificate becomes spend-time optional | `NoBypass` | "optional attribution" must mean per-escrow at creation, never per-transaction |
| `BUG_NoNullifier` | source events are not consumed | `NoDoubleRelease`, `Solvency` | key images stop double-*spending* but not double-*releasing* against one deposit — two valid txs, different key images |
| `BUG_RotateOwnership` | rotation mints a fresh ownership key instead of rotating the gate | `RotationSound` | MobileCoin's one-time key derives from the account spend secret (`onetime_keys.rs:169-184`), so a fresh ownership key cannot generate old outputs' key images — the constraint that forced the two-key split |
| `BUG_NoEpochCheck` | consensus does not require the authorization's epoch to be current | `NoStaleAuthorization` | rotation only contains a compromised quorum if consensus *rejects* authorizations under the retired gate key — otherwise the expelled coalition keeps authorizing with the key it still holds |

### The switches already caught two bugs — in this spec

Both were found before any human or TLC looked at the file, which is the whole argument for having
the switches.

**1. `NoBypass` inferred certification instead of tracking it.** The first draft derived "went
through the gated path" from whether a source event cited the output. But an *uncertified* release
still cites an event, so `BUG_OptionalCertificate` produced **no violation at all** — the invariant
was blind to the precise defect it existed to catch. Fixed by making `releases` a set of
`[event, output, certified]` records and having `NoBypass` require membership in `CertifiedOutputs`.

**2. `RotationSound` was vacuous after any expulsion.** The first draft conjoined all three
thresholds in its guard. Since rotation only happens via `BlameOperator`, which always expels
someone, the roster always fell below `K_W` and the implication was trivially true —
`BUG_RotateOwnership` also produced no violation. Fixed to state the property precisely:
`(Cardinality(Active) >= K_OWN) => CanOwn`. Rotating the *gate* must not destroy *ownership*.

### A design finding from making the config non-degenerate

The original config used `K_W = K_F = K_OWN = 3` over 4 operators, which is **degenerate**: the
certificate threshold is never the binding gate, so the certificate could be deleted with no
observable effect. Fixing it surfaced a real operational constraint:

> **The warden threshold must leave headroom for expulsions.** With `K_W = n`, a single
> operator-fault expulsion drops the roster below the certificate threshold and the bridge can
> **never release again** — bricked by its own enforcement mechanism.

Now 5 operators with `K_W = 3`, `K_F = 2`, `K_OWN = 2`: expelling up to two leaves the bridge
functional, and expelling three makes the certificate the binding gate, which is the state
`BUG_OptionalCertificate` needs to be reachable. **Sizing `K_W` against expected expulsions belongs
in `DESIGN.md` §7.2.**

### The config bug: the two checkers disagreed, and the mirror was right

On the first TLC run, **three of four bug configs reported no error and produced exactly 9582
distinct states — byte-identical to baseline.** The Python mirror reported all four violating. TLC
was running baseline four times. Three cascading mistakes:

1. **The `sed` generating the configs matched nothing.** The baseline `.cfg` aligns its assignments
   (`BUG_NoNullifier         = FALSE`) but the pattern assumed a single space around `=`. Only
   `BUG_OptionalCertificate` — longest name, hence exactly one space — matched.
2. **The verifying `grep` was satisfied by a comment.** A header comment containing the literal text
   `BUG_LegacyPathOpen = TRUE` was written, then the file grepped for that string. It found the
   comment. **A check that validates against text you just wrote validates nothing.**
3. **The checkers were not testing the same configurations.** `check.py` reads switches from Python
   objects, not the `.cfg` files, so it exercised the real defects while TLC exercised baseline.

Fixed with a padding-tolerant regex and verification that **parses constant assignments and ignores
comments**, asserting exactly one switch is TRUE per config. The tell was the identical state
count — three configs producing byte-identical state spaces to baseline is not plausible if the
switches do anything. Watch that number, not the pass/fail.

## Invariants

| Invariant | Claim |
|---|---|
| `NoBypass` | every consumed escrow output went through the gated path |
| `NoDoubleRelease` | one source event funds at most one release |
| `NoDoubleSpend` | an output is never both unspent and consumed |
| `RotationSound` | containing a compromised quorum does not strand the reserve |
| `BlameExclusive` | no claim resolves to both operator and challenger fault |
| `ContainmentOK` | only an operator-fault verdict pauses the bridge |
| `NoSlashUnproven` | nobody is slashed without an admitted verdict |
| `Solvency` | releases never exceed finalized deposits |
| `CitesOnlyFinalized` | the reorg guard — only finalized events may be cited |

## Known gaps, prioritized (from Sol's review #41)

These must be closed before the spec can gate M6. Ordered by how badly the current model misleads.

**Priority changed 2026-08-08:** gap 6 (§7.1 recovery) is descoped, so the next artifact is the
`BridgeEscrowV2` rewrite covering gaps 1–3 — validity-in-the-guard, blame soundness, and
artifacts-rather-than-capabilities. Those are all about *normal operation* and remain fully in scope.

| # | Gap | Fix |
|---|---|---|
| 1 | **Validity is in the guard.** Corrupt wardens cannot lie about Ethereum. | Split `claimedSourceState` from `objectiveSourceState`; add an action accepting a false attestation. **Do not simply "replace" `CitesOnlyFinalized`** (Sol's correction) — keep source correctness as a property/config for the case where a light client makes it enforceable, and *add* the trusted-attestation properties: `UnmatchedReleaseHasAccountability` (mismatch ⇒ attributable bonded signer set, both directions) and `UnmatchedReleaseHasAutomaticProof` (mismatch ∧ `AutoVerifiable` ⇒ admissible objective proof, direction- and version-dependent). Under trusted attestation the adversarial property is *"false releases remain reachable but necessarily attributable, and automatically remediable only for supported proof classes."* |
| 2 | **Blame is arbitrary; slashing unsound.** Any subset of `Active` can be expelled with no claim, release, or evidence. | Model `Claims` and `Challengers` as first-class; make adjudication a pure function of authenticated evidence; add `VerdictSound`, `SlashSound`, `NoRejectedClaimEffect`. |
| 3 | **Gates are capabilities, not artifacts.** No digest binding, no distinct signer sets. | Record actual artifacts and signer subsets per release; require `frostEpoch = policyEpoch`, `frostDigest = wardenDigest = txDigest`, distinct signers from per-epoch rosters. Then add switches for missing MLSAG, missing FROST, digest mismatch, duplicate signers, missing receipt. |
| 4 | **One `Operators` set** collapses the gates to `\|Active\| >= max(K_W,K_F,K_OWN)`. | Separate (possibly overlapping) warden / gate / accountability / ownership rosters, so independent authorization is demonstrable. |
| 5 | **`Resume` is not recovery.** | Split into `FreezeEpoch → StartDKG → CompleteDKG → ActivateEpoch → Resume`; `Resume` must require fresh DKG activation and per-role capacity. Pause must stop value movement but not source observation or later fraud claims. |
| ~~6~~ | ~~**§7.1 unmodelled.**~~ **DESCOPED 2026-08-08** — Josh: "key recovery and escrow key compromise are outside of scope for now." `ReserveRecovery.tla` is not being written; effort redirects to gaps 1–3. Retained below for the reasoning, and because the Stranded/Unsafe *accounting* rule survives descoping. | ~~Standalone module first (`ReserveRecovery.tla`). Trigger must be a nondeterministic *environment* action `RaiseIncident(pool, affectedRoles, unavailableHolders, compromisedHolders)` — **not** `FreezeOnProvenFault`, and carrying no adjudication claim, so this is assume/guarantee decomposition rather than the guard error. Safety must hold even for a **false or repeated** trigger: no external release, no liability erasure, no nullifier reset, no premature recovery, no slash. One `RecoveryMode` per config; `secretExposed` monotonic; distinguish `Stranded` from `Unsafe`. **This is what would let Josh choose §7.1 from checked outcomes.**~~ |
| 7 | **`Solvency` counts releases, not value.** | Add abstract amounts, fees, change conservation, `liabilities <= reserve assets`. Until then it is honestly named `NoUnbackedReleaseCount`. |
| 8 | **Nullifier uniqueness without completeness.** | Require the bijection `nullifiers = {r.event : r \in finalizedReleases}` plus `unspent \cup keyImages = AllOutputs`; add `BUG_NullifierPoison` for a pre-consumed nullifier that bricks an event without releasing value. |
| 9 | **Single-input releases only.** | Model releases by `ReleaseId` with `inputs \subseteq EscrowOutputs` — real releases consume up to 16. |
| 10 | **Reverse leg absent.** | Add `direction`/`proofKind` and an `AutoVerifiable(direction, proofKind)` capability predicate, FALSE for `MobToEth`/`falseSource` in v1 and TRUE in v2. **Do not omit the reverse leg from v1** — omitting it makes the v1 model look stronger than the deployed protocol. Include an *expected* reachability scenario in which a captured reverse threshold authorizes a false return and drains within the exposure cap: attribution names the signers, it does not restore the USDC. If v1's contractual adjudication permits a human to slash, model a separate `TrustedAdjudicator` path — never as automatic objective proof. |
| 11 | Finality assumed; `MaxEpoch` hides repeated-rotation failures; `ClaimIds == SourceEvents` prevents multiple incidents per event; `ContainmentOK` is historical not causal. | Document finality as an environmental assumption or model reorg states; track `pauseCause`. |

Sol's verdict on the mirror: transition-faithful for present reachability, and the matching baseline
cardinality is useful parity evidence — **but both share every semantic error above.** Agreement
between two implementations of the wrong model is not evidence about the design.

## Earlier limitations (superseded by the table above, kept for the reasoning)

1. **Admission is not modelled at all.** An earlier draft had a `RejectInadmissible` action, but
   TLC proved it was dead code — the state count was identical with and without it, because its body
   was `UNCHANGED vars` and a step that changes nothing is already permitted by stuttering. It has
   been removed with a note. So "inadmissible claims are rejected without punishing anyone" is
   **not verified**; it is simply absent. Making it observable needs a rejection counter. This is
   the first extension worth making.
2. **`BlameOperator` is not tied to an actual safety violation.** It fires on any admitted claim,
   so the spec checks *containment* and *exclusivity* but not *soundness* of the fault predicate
   (whether a real fault occurred). Modelling that needs the fraud predicates from `DESIGN.md` §4
   and would be the second extension.
3. **No bond arithmetic.** `B* ≥ 2L` is a Certora property over Solidity, not a TLA+ one.
4. **No liveness.** Everything here is safety. Liveness under `n − k` operators offline is worth a
   temporal property later, but safety first.
5. **Ownership capability is coarse, and the adversary's retained shares are not modelled.**
   `CanOwn` uses `Cardinality(Active)`, which represents the *honest* roster's capability. But
   expelled operators retain their `K_own` shares, and the model never represents that retained
   adversarial capability. Consequence: **`DESIGN.md` §7.1's residual risk is invisible here** —
   "if `K_own` was also compromised, the replacement roster may be unable to sign at all" cannot be
   expressed or checked. Since §7.1 is the one decision still open, modelling it is arguably the
   highest-value extension. Contrast the *gate*, which now does carry per-epoch identity precisely
   so that stale-epoch replay is expressible.

6. **`NoStaleAuthorization` was added after review found the spec could not verify its own
   central claim.** The first draft defined gate capability as `Cardinality(Active) >= K_F`, with no
   epoch identity — so "expelled colluders keep the MLSAG half but cannot satisfy the new gate", the
   containment property that *justifies the two-key design*, was inexpressible. The gate now has
   per-epoch holder sets, rotation issues the new key only to survivors, and consensus must check
   the authorization epoch is current. That check is what `BUG_NoEpochCheck` removes.

## Review status

> ## ⚠️ DO NOT GATE ANY DECISION ON THIS SPEC YET
>
> Sol's adversarial review (`convo.sqlite` topic `tla-spec`, message #41) established that the
> green TLC run **does not mean what it looks like it means**. The headline problem:
>
> **The spec proves validity by putting validity in the release guard.** `EscrowRelease` requires
> `e \in finalized`, so a threshold of corrupt wardens *cannot* cause a false claim about Ethereum
> to be accepted — the action is disabled by construction. The model conflates what wardens
> **attest**, what MobileCoin consensus can **verify**, and Ethereum's **objective** state. Absent
> an Ethereum light client, consensus learns only the attestation. So `CitesOnlyFinalized` is
> trivially true, and *the central bridge threat is unrepresentable.*
>
> Confirmed by counterexample: TLC finds a 4-state trace — `FinalizeDeposit`,
> `BlameOperator(all five operators)`, `Resume` — leaving the bridge **live with no custodian and
> stranded inventory**, with every baseline invariant passing.
>
> Also confirmed: `BUG_OptionalCertificate` does not model the real bug. Because releases record
> `certified |-> CanCertify`, omission only occurs once blame has already reduced the roster below
> `K_W`. A coordinator omitting an *available* certificate — the actual implementation defect — is
> unrepresentable. The earlier "track rather than infer" fix tracked whether certification was
> **possible**, not whether it was **presented**: the same error one level down.
>
> See "Known gaps" below for the prioritized list. The machine-checked facts in the next section
> remain true; they are just much weaker claims than they appear.

**Machine-checked:** TLC 2.19 on OpenJDK 26, 2026-08-07 — see Verified results above. The TLA+
parses and semantically processes cleanly, the baseline is invariant-clean across the full reachable
state space, and every bug switch violates its expected named invariant. Reproduce with `./run.sh`,
which exits non-zero on any mismatch.

**Not yet independently reviewed.** TLC establishes that the spec is well-formed and that the
switches bite. It says nothing about whether the spec models the *right* system — that needs a
human or a second agent reading it against `DESIGN.md`. Sol was sent it (`convo.sqlite`, topic
`tla-spec`) but its review task was orphaned before completing. **Treat the limitations below as
the current known gaps, not as an exhaustive list.**
