# M3 result: threshold MLSAG inside a real MobileCoin transaction path

Date: 2026-08-08 (America/Los_Angeles)

Status: **focused integration pass with explicit production blockers**

Pinned inputs:

- MobileCoin `05cb699f8f4cc1bc21186392545820c5b38408db`
- Serai `4b89cf0206184886e96d0663861596312e5b47d2`
- M2b `src/strict.rs`
  `76092f20bc1c5d706add15e3151b016d80f5a1857572d0dd5e0f01350d0a2ab8`

The authoritative result label is:

> **REAL MOBILECOIN V4 TWO-INPUT SIGNATURE AND RANGE-PROOF INTEGRATION PASS,
> WITH SYNTHETIC MEMBERSHIP PROOFS AND CENTRALIZED FIXTURE-TIME SPEND/MASK
> SCALAR EXPOSURE. FULL-LEDGER VALIDATION, STRICT DISTRIBUTED CUSTODY,
> END-TO-END ATTRIBUTABLE CEREMONY ERRORS, ON-CHAIN POLICY, WARDENS, AND THE
> NETWORK UPGRADE REMAIN UNPROVED.**

## Question answered

M2 showed that a threshold ceremony can produce an ordinary two-row MobileCoin
MLSAG accepted by the existing MLSAG verifier. M3 answers the next narrower
integration question:

> Can that signer be placed behind MobileCoin's existing `RingSigner`
> interface in a real v4 two-input construction while retaining stock
> `MaskedAmountV2` opening, the exact MobileCoin signing digest,
> pseudo-output/value conservation, v4 range proofs, and unmodified
> signature/RingCT validation?

For the executed fixture, **yes**.

This does not answer whether consensus can recognize or require a threshold
ceremony. The produced object is still an ordinary MLSAG. It also does not
prove that no machine ever reconstructs the spend or mask secrets; this test
deliberately reconstructs them at its adapter boundary.

## Executed construction

The test creates two real eUSD inputs (`TokenId = 8192`) for subaddresses 7 and
19 under one `ViewAccountKey` whose root spend public key is the threshold
group point. Each input has a sorted 11-member ring. All 22 ring members are
globally distinct, and every input and output uses `MaskedAmountV2`.

The stock `TransactionBuilder` constructs a v4 transaction with:

- input values 1,000 and 1,200 eUSD;
- recipient value 1,500 eUSD;
- change value 600 eUSD;
- fee 100 eUSD;
- two independent input rings and one v4 range proof.

`UnsignedTx::get_signing_data` computes the real pseudo-output blindings,
commitments, range proof, and MLSAG digest. The
`InsecureFixtureThresholdRingSigner` invokes the frozen M2b
`reserve -> sign -> aggregate` path for both response rows. Every exact 2-of-3
subset—`{1,2}`, `{1,3}`, and `{2,3}`—signs both inputs. Therefore the run
constructs six threshold-created MLSAGs and three complete
`SignatureRctBulletproofs` objects.

## Success conditions

| Required assertion | Result |
|---|---|
| Real inputs and all constructed outputs use `MaskedAmountV2` | PASS |
| Stock unmasking recovers exact value, token, and blinding for both real inputs | PASS |
| Threshold root group equals the `ViewAccountKey` root spend public key | PASS |
| Two real inputs use distinct subaddresses and distinct additive one-time-key offsets | PASS |
| Threshold key images equal MobileCoin's canonical local key images byte-for-byte | PASS |
| Key images remain identical across all three signer subsets, while fresh ceremonies produce different signatures | PASS |
| For both inputs, `zG = C_pseudo - C_input` | PASS |
| Sum of pseudo-output blindings equals sum of output blindings | PASS |
| Full output + fee - pseudo-output commitment difference is the identity | PASS |
| v4 `range_proofs` is nonempty and legacy `range_proof_bytes` is empty | PASS |
| All six ordinary MLSAGs pass unmodified `RingMLSAG::verify` | PASS |
| All three complete signatures pass stock `validate_signature` | PASS |
| Rings have size 11, are sorted, are globally unique, and inputs are sorted | PASS |

Here “complete signatures” means MobileCoin's signature/RingCT object and
validation path. It does **not** mean complete ledger/consensus acceptance.

## Failure conditions

| Fault or mutation | Executed result | Interpretation |
|---|---|---|
| Wrong subaddress / one-time-key offset | rejected; no post-success evidence | M2b's source-checked reservation ordering performs the group check before nonce sampling; M3 does not independently instrument that phase |
| Wrong mask-difference sharing group | rejected; no post-success evidence | group point does not open `C_pseudo - C_input`; the pre-nonce ordering is inherited from M2b |
| Fewer than threshold participants | rejected; no post-success evidence | threshold view cannot be constructed; pre-nonce ordering is inherited from M2b |
| Participant outside registered DKG roster | rejected without panic | hardened after independent review |
| Tombstone/prefix changed after signing | `validate_signature` rejects | exact prefix digest is bound |
| Masked output changed after signing | `validate_signature` rejects | output digest/range/balance binding survives integration |
| Fee changed after signing | `validate_signature` rejects | fee is bound |
| Fee token changed after signing | `validate_signature` rejects | fee token is bound |
| Pseudo-output commitment changed | `validate_signature` rejects | MLSAG/range/balance verification detects the mutation |
| Range-proof byte changed | `validate_signature` rejects | range-proof verification detects the mutation |
| Input/output value imbalance | exact `RingCtError::ValueNotConserved` | rejected while deriving `SigningData`, before `RingSigner` invocation |
| Corrupt row-0 response share | exact participant identified in frozen M2b tests only | **not preserved end-to-end** by the stock `RingSignerError` type |
| Corrupt row-1 response share | exact participant identified in frozen M2b tests only | **not preserved end-to-end** by the stock `RingSignerError` type |

The last two rows are an integration requirement still open, not an M3 pass.
The M3 adapter maps structured M2b errors—including
`InvalidShare(participant)`—to `RingSignerError::Unknown`, because the current
MobileCoin trait has no participant-bearing variant. A production ceremony
needs a parallel authenticated result/evidence channel or an extended signer
API. Protocol-local identification is not yet slashable evidence: round
messages still need registered identity signatures and an on-chain adjudication
rule.

## Independent audit and repairs

An independent code review reproduced the pre-hardening test and found no P0
or P1 defect in the stated integration claim. Before publication, its P2
findings produced four additional hardening changes:

1. The adapter was renamed `InsecureFixtureThresholdRingSigner` so the scalar
   exposure is visible at the call site.
2. The test now asserts distinct per-output offsets and equality between the
   root threshold point and the view account spend public key.
3. An unregistered participant returns an error rather than panicking through
   `HashMap` indexing.
4. Signatures from independent subset ceremonies must differ while their key
   images remain identical, regression-testing nonce freshness at this layer.

The audit also confirmed that exact bad-share attribution is erased by the
stock adapter error type and that the locally duplicated M2 transcript/key-ID
constructor must become a single canonical API before production.

## Deliberate claim exclusions

### Synthetic membership proofs

The fixture creates placeholder `TxOutMembershipProof` objects. It calls ring
size, sorting, global uniqueness, MLSAG, range-proof, and commitment-balance
validators, but it does not call the ledger-backed full transaction validation
path. It proves no Merkle membership, key-image absence, tombstone freshness,
fee-map policy, enclave acceptance, consensus propagation, or block inclusion.

### Centralized fixture scalars

The adapter retains the complete root spend scalar and `AccountKey`, invokes
MobileCoin's private recovery helper to materialize the complete one-time
scalar, receives complete input and pseudo-output blindings, reconstructs
`z = b_pseudo - b_input`, and dealer-shares `z` anew for each signature. This
is useful wiring evidence and is **not** strict distributed custody.

Production needs at least:

- a reviewed canonical MobileCoin helper for the additive one-time-key offset,
  without reconstructing `x` or copying private hash/domain logic;
- distributed construction of input/pseudo-output mask-difference shares and
  balanced multi-input pseudo outputs;
- an authenticated DKG and durable, crash-safe nonce reservation state;
- a structured, signed ceremony transcript preserving bad-participant
  attribution across the wallet/`RingSigner` boundary; and
- the v5 on-chain policy/warden transaction format and coordinated activation.

### Not a privacy result

The test exposes real ring indices to the fixture signers, consistent with
Josh's stated requirement. It makes no claim about decoy selection,
history-conditioned anonymity, ring confidentiality from infrastructure, or
the policy pool's observer model.

## Reproduction

The combined dependency graph resolves one `curve25519-dalek` instance,
version 4.1.3. It requires a compiler new enough for Serai's resolved graph and
nightly support required by the pinned MobileCoin build. The recorded toolchain
was:

```text
rustc 1.87.0-nightly (287487624 2025-02-28)
cargo 1.87.0-nightly (2622e844b 2025-02-28)
clippy 0.1.86 (2874876243 2025-02-28)
libprotoc 25.3
```

`RUSTC_BOOTSTRAP` was not used. The initial warm-up fetched crates.io
dependencies and the pinned MobileCoin Bulletproofs/Schnorrkel revisions.
The evidence run then rebuilt into a fresh target directory with
`--locked --offline`.

```bash
cd /Users/jperla/josh/m3-mobilecoin-tx-spike

PATH=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin:$PATH \
RUSTC=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin/rustc \
RUSTDOC=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin/rustdoc \
PROTOC=/tmp/m3-protoc/bin/protoc \
CARGO_TARGET_DIR=/tmp/m3-independent-target \
cargo test --locked --offline

PATH=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin:$PATH \
RUSTC=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin/rustc \
RUSTDOC=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin/rustdoc \
PROTOC=/tmp/m3-protoc/bin/protoc \
CARGO_TARGET_DIR=/tmp/m3-independent-clippy-target \
cargo clippy --locked --offline --no-deps --all-targets -- -D warnings
```

The fresh-target test compiled successfully, then reported one test passed,
zero failed; the test body completed in approximately 2.39 seconds. The
same-toolchain Clippy run passed with `-D warnings` for the M3 crate. Upstream
Serai dependencies emit an unknown-lint warning under this historical
toolchain, so `--no-deps` is intentional and the dependency warning is not
represented as a clean whole-graph lint result.

Using Homebrew's 2026 `cargo-clippy` with the 2025 `RUSTC` incorrectly mixes
compiler metadata and fails with `E0514`; placing the matching toolchain first
on `PATH` is required. This is a reproduction-command constraint, not a source
failure.

## Frozen artifact hashes

```text
ebcfa1edd1821d0aff6d2dade7f9d18f5c1ed297c0df03eaa1a758ad974591c4  Cargo.toml
45100bfaa1a8572bbba742b75b618fbee6ff3159d6931a1079ba3add946611e7  Cargo.lock
1de79ba0eeb3abdbef556eba90a1115be0f371f17baecffc67b247177bdd5c61  README.md
acf2f64ac31b8adeb0bd940b5a925b6609a2167cea182af371f90471f602a186  src/lib.rs
```

The pinned MobileCoin and Serai worktrees remained clean at their recorded
commits after the run.

## Next executable gate

M4 should not add the v5 consensus policy yet. First it should replace the
insecure fixture boundary with a share-native transaction-construction API:
derive the one-time spend-key offset without `x`, jointly construct balanced
pseudo-output mask shares across multiple inputs, preserve typed authenticated
ceremony failures, and verify that no complete spend or mask witness exists in
one process. Only after that gate passes should M5 place the threshold artifact
and independent warden/source-event certificate into the new transaction
format and consensus validator.
