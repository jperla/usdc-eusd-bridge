# M5 sealed signer / nonce-vault checkpoint

## Verdict

**Focused in-memory orchestration pass; not the production M5 signer gate.**

The Rust spike in `/Users/jperla/josh/m5-rust-signer-vault-spike` makes one
critical ordering rule executable:

```text
opaque round-one context digests committed
    -> nonce slot committed
    -> one exact round-two request bound
    -> response computed and self-checked once
    -> response sealed; opaque receipt returned
    -> receipt/certificate retained by one in-memory authority fixture
    -> retained raw response released
```

An untrusted coordinator cannot provide response bytes to this API. The vault
does not return its modeled raw response before a certificate retained by its
configured authority fixture. This proves token/order gating only: anyone
holding the public fixture-authority handle can request that certificate, so no
independent approval boundary is proved. Exact produce/release retries return
the retained identity or bytes through the configured retention height; a
changed request conflicts; failed self-verification retires the nonce identity
for the lifetime of the volatile process state.

The result does **not** prove durable nonce custody, a real HSM boundary, or
FROST/MLSAG cryptography. The state is an in-memory `Mutex<HashMap<...>>`, and
nonce identities, commitments, responses, authorization proofs, and
attestations are deterministic tagged-hash fixtures. There is no entropy-grown
secret nonce or nonce-ID/response-handle collision adversary.

## Executed evidence

| Check | Result |
|---|---|
| Rust 1.97.1 test suite | 17 passed; 0 failed |
| Exact Rust 1.83.0 test suite | 17 passed; 0 failed |
| Clippy, all targets, warnings denied | PASS |
| Direct rustfmt check | PASS |
| Exact-call race | 16 callers collapse to one receipt and one computation |
| Honest TLA+ configuration | PASS; 140 generated, 18 distinct, depth 10, zero queued |
| Certificate-without-anchor mutant | expected `CertificateRequiresExactAnchor` violation; 40/12/depth 7 |
| Changed-request-rebinding mutant | expected `SingleRequestBinding` violation; 7/5/depth 4 |

The separate TLA+ result is recorded in
`MOBILECOIN_M5_SEALED_RESPONSE_TLA_RESULTS.md`. Its state transitions are
abstract atomic steps, so the model is an ordering proof, not a filesystem or
power-cut durability test.

## Safety properties exercised

1. The stable nonce-slot identity uses semantic coordinates rather than the
   complete plan. A changed algorithm, epoch, component plan, registry root,
   participant roster, manifest, or round-one request therefore reaches the
   existing slot and conflicts instead of allocating a second nonce.
2. Nonzero registry, participant-set, manifest, and round-one-request **digest
   values** enter the caller-supplied plan before the modeled public commitment
   is returned. The crate does not authenticate or recompute their complete
   preimages at commit time.
3. The participant-set digest is recomputed later from the request's canonical
   sorted roster. Other opaque context digest mismatches fail before response
   computation or request-state mutation, but their preimages remain unproved.
4. Row 0 and row 1 use separate nonce domains and receive distinct modeled
   nonce identities.
5. `produce_once` accepts no caller-supplied response and returns only a
   `SealedResponseReceiptV1`. The response producer and raw constructor are
   crate-private.
6. Exact sealed retry returns the stored receipt without recomputation. A
   changed request conflicts; an internally invalid response returns no
   receipt and retires the slot.
7. A mutated certificate or one not retained by the in-memory fixture authority
   cannot release the response. An exact retained certificate moves the modeled
   state to `Released` before bytes are returned.
8. Archived and retired states retain typed, digest-only terminal evidence;
   neither path regenerates a response.
9. Canonical decoders reject trailing bytes, unknown domains, and nonzero
   fixed-capacity padding; accepted objects re-encode byte-identically.

These are semantic/in-memory properties. Terms such as “commit,” “anchor,” and
“release” name modeled transitions and do not imply `fsync`, monotonic hardware,
rollback resistance, remote attestation, or distributed linearizability.

## Counterexamples repaired during the slice

### Opaque round-one digest binding was added; full binding remains open

The first implementation could expose a commitment before even opaque registry,
roster, manifest, and round-one-request digests entered the nonce plan. Those
digest values are now part of the plan before commitment exposure, while
remaining outside the stable slot key so a changed value conflicts rather than
opening another slot. This is only a partial repair: `commit_nonce(plan)` still
accepts caller-supplied digests, does not accept/authenticate the corresponding
content envelopes, and does not recompute the registry, manifest, or round-one
request digest. Complete authenticated preimage binding remains a P0.

### Full-plan slot keys would have enabled nonce aliasing

If the slot key hashed every plan field, changing an algorithm revision or DKG
epoch would select a new record instead of finding and rejecting the existing
semantic nonce slot. The implementation therefore derives a separate stable
slot key from selected `NoncePlanV1` coordinates rather than hashing the full
plan. (`NonceSlotIdentityV1` is the explicit object required by the production
test plan, not a concrete type in this bounded crate.)

### Terminal states initially erased forensic identity

Early archive/retirement transitions discarded the evidence needed to explain
why a nonce could never be used again. The final model retains typed retirement
causes and exact plan/request/response/receipt/certificate evidence digests.

### Public raw-response extension points were unsafe

Early public producer/authority traits could have let callers inject arbitrary
bytes or an always-true verifier. Those traits and raw constructors are now
crate-private; the public bounded constructors pin the deterministic fixture.

## Relationship to the 38-test contract

The 17 tests implement only a bounded subset of
`MOBILECOIN_M5_PRODUCE_ONCE_SIGNER_TEST_PLAN.md` section 8.7. Still absent are:

- frozen cross-language vectors and the full mutation/size matrix;
- authenticated context envelopes and pre-commit preimage recomputation;
- entropy and nonce-ID/response-handle collision tests;
- durable reopen, abrupt-death, torn-write, rollback, and multi-process tests;
- independent Rust-journal receipt validation and cross-store recovery;
- publisher append-once and delivery recovery;
- a Byzantine-vault evidence path;
- all changed-request/retire/seal concurrency matrices; and
- real Ristretto/FROST/MLSAG commitments, shares, and verification equations.

Passing this checkpoint cannot authorize a MobileCoin transaction.

## Next falsifiable integration gate

The next bounded slice should connect the existing durable Rust journal to one
single-input, Row-0, deterministic-crypto vault without permitting raw response
bytes through the journal API:

1. the journal exports one exact authenticated operation/child authorization
   checkpoint;
2. the registered vault commits and seals against that checkpoint;
3. the journal validates and persists the exact attested receipt while
   consuming the child;
4. the journal anchors an exact release certificate;
5. only then does the vault release the retained response to an append-once
   publisher; and
6. crash/restart tests cover commit, bind, seal, receipt persistence, anchor,
   release, and delivery boundaries.

The gate fails if caller bytes can consume a child, if any commitment predates
complete round-one binding, if journal/vault checkpoints disagree without a
fail-closed result, if restart regenerates a response, or if raw bytes become
observable before the exact authority anchor.

After that control-plane slice passes, the deterministic producer must be
replaced by the pinned Serai `modular-frost` adapter and checked against stock
MobileCoin MLSAG equations.

## Frozen artifact hashes

```text
MOBILECOIN_M5_PRODUCE_ONCE_SIGNER_TEST_PLAN.md
  e958fe8160e2fc79d71f93a0c392779b1d7f7969da09081be1f2df21302da7c6

m5-rust-signer-vault-spike/Cargo.toml
  946647f590d077bc19e6b453d62d9e600db615562f86867da2fdb98523c06e58
m5-rust-signer-vault-spike/Cargo.lock
  d96e1a9644830d7926dd26f69aef2c96ac80884fcc5e3f93f710f405af80f92d
m5-rust-signer-vault-spike/README.md
  d5030ff74e5cfb8fd134b20c2848c0994453bf1a09d9ea0e59efaf2756005fe6
m5-rust-signer-vault-spike/RESULTS.md
  51137799cbc9121a35ae1af4477ef0c4a8879416ea568ef118ec538ffe7af021
m5-rust-signer-vault-spike/src/lib.rs
  dfdb66b977caf56b33d0643b1aa36baea55555c37f5ce01482b146f9d7696739
m5-rust-signer-vault-spike/src/codec.rs
  57c67b43bffbf6b0a613d150458377daa86a38b67b0717f66b6dcad0c1304ce5
m5-rust-signer-vault-spike/src/vault.rs
  a80ab079043ccf59a2433572144a35cf6b1195a59c3b62afd0971918bf42619d
m5-rust-signer-vault-spike/src/tests.rs
  95d63765af90c45a756a62148f6b6ca69302baa7fec04bb7f6b78de93325f514

M5SealedResponse.tla
  80e518caaac30d5fac5fc82e0def6834e244109b654af4603c865802b25f0a40
M5SealedResponse.cfg
  8aa19a2f5fa5633bb04af222cb9b319e4fa6fbba16128cd561afd035175cfb2c
M5SealedResponse-bug-cert-without-anchor.cfg
  3f1b6953b884660a6078f13268a7004d8c50da350da02e2c781d0cd8ede42565
M5SealedResponse-bug-rebind-changed-request.cfg
  c629feafa4a63e2c0af8eba83903242b3b31c1ea31801db161b9c33181b615e8
MOBILECOIN_M5_SEALED_RESPONSE_TLA_RESULTS.md
  046f3fdb1c8fe14fb693590eda5611e3ac036ca95a13bd261d05afc8a3c26b14
```

The hash of this shared result is recorded in `HANDOFF.md` after the file is
frozen.
