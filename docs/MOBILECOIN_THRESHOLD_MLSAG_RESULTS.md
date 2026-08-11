# MobileCoin threshold-MLSAG M2 result

Date: 2026-08-08

Result label:

> **RESERVATION-BOUND TWO-ROW THRESHOLD-MLSAG ALGEBRA PASS; REAL
> MASKED-AMOUNT CUSTODY, AUTHENTICATED ACCOUNTABILITY, COMPLETE TRANSACTION,
> ON-CHAIN POLICY, AND NETWORK UPGRADE NOT YET PROVED.**

## Why M1 was insufficient

The earlier `m1-spike` is a valid Dalek dependency/adapter interoperability
test, but its threshold tests reconstruct a complete scalar before signing.
It contains neither a real Serai FROST signing machine nor threshold MLSAG.
Its correct verdict is therefore:

> `Dalek dependency/adapter interop PASS; account-level DKG and threshold
> MLSAG UNVERIFIED.`

M2 was created to test the missing cryptographic proposition against the
actual MobileCoin verifier.

## Frozen source basis

- MobileCoin commit:
  `05cb699f8f4cc1bc21186392545820c5b38408db`
- Serai commit:
  `4b89cf0206184886e96d0663861596312e5b47d2`
- both repositories clean during the recorded runs
- dependency graph: exactly one `curve25519-dalek`, version `4.1.3`

M2 source hashes:

| File | SHA-256 |
|---|---|
| `Cargo.toml` | `56a162f569ff0cbf170e79ac9deafbd4b711aa11f3590ed7b9d9cdc7a74b367c` |
| `Cargo.lock` | `63022870d7ed06b9977cac911ccab3ad980868befafc66015118ebe62313bed1` |
| `src/lib.rs` | `2f51234386f5e23e9b43e375c6e1eb75352a062ba380fea4338f664a052a353d` |
| `src/strict.rs` | `76092f20bc1c5d706add15e3151b016d80f5a1857572d0dd5e0f01350d0a2ab8` |
| `README.md` | `c335acab71498b7d4c48e7ad12db353d423bd9f97f59fa92d57ea3a52de3462c` |

The README hash covers the initial result text and may be superseded only if
the published copy records a new hash explicitly.

## Construction tested

For a real ring member at index `pi`, MobileCoin's MLSAG has two witnesses:

- `x`, the one-time private spend scalar, with public key `P = xG` and key
  image `I = x H_p(P)`;
- `z = b_pseudo - b_input`, whose public relation is
  `Z = C_pseudo - C_input = zG`.

M2b keeps independently shared `x` and `z` values in Serai
`ThresholdKeys`. Every participant uses a Lagrange-weighted threshold view and
two bound nonce pairs. The aggregator accepts a participant only if all three
relations hold:

```text
s0_i G      + c X_i = R0_i,G
s0_i H_p(P) + c I_i = R0_i,H
s1_i G      + c Z_i = R1_i,G
```

The first two equations force the same row-0 response to be valid under both
bases, binding the spend share to the key-image share. Summing valid shares
produces the ordinary MLSAG real responses; decoy responses and the challenge
cycle retain MobileCoin's existing encoding and domain separation. The final
artifact is passed directly to the public, unmodified
`RingMLSAG::verify` implementation.

M2a separately proves that Serai's stock `modular_frost::AlgorithmMachine`
can threshold row 0. M2b proves the two-row algebra with a custom vector state
machine; it does not mislabel that custom protocol as stock Serai FROST.

## Authorization and substitution boundary

Before nonce commitments are exposed, M2b commits to a canonical reservation
statement containing:

- protocol version, network, DKG epoch, derived spend/mask key IDs;
- ordered bonded-roster digest and `t/n` policy;
- unique session ID and exact MobileCoin signing message;
- real index, pseudo-output commitment, full ordered ring, and decoy responses;
- canonical included signer set.

Every tag and value is length-framed. Ring/response/roster counts and entry
indices are explicit. Binding factors extend that transcript with every
participant's registered spend/mask verification shares, key-image share, and
six row-specific nonce commitment points.

A signer-local `KeyContext` derives key IDs from the actual group points and
derives the roster ID from the ordered participant-to-bonded-identity map. The
mapping must contain exactly threshold-share participants `1..=n`, with a
unique nonzero bonded identity key for each participant. It
must be loaded from the local DKG/accountability registry; it is deliberately
not accepted from the transaction coordinator. `reserve` compares the
statement and supplied threshold keys with this context before generating any
nonce. `sign` consumes its in-memory nonce package and rechecks the reservation
digest before computing a response.

This closes coordinator substitution inside the demonstrated API. It does not
replace authenticated persistent registry storage or identity signatures on
round messages.

## Executed evidence

Fast suite:

```text
cargo test --locked --offline
10 passed; 0 failed; 1 ignored
```

The ignored test is intentionally separated because it enumerates all
8-of-11 subsets. It was run explicitly and passed:

```text
cargo test --locked --offline \
  strict::tests::target_eight_of_eleven_accepts_every_qualifying_subset \
  -- --ignored --exact
1 passed; 0 failed
finished in 111.12s
```

Static lint gate:

```text
cargo clippy --locked --offline --all-targets -- -D warnings
PASS
```

Accepted verifier artifacts:

- M2a: 33 = 11 ring positions x 3 qualifying 2-of-3 subsets;
- M2b: 33 = 11 ring positions x 3 qualifying 2-of-3 subsets;
- target policy: 232 = every signer set of size 8, 9, 10, or 11 at one ring
  position;
- total across recorded runs: 298 ordinary MLSAG artifacts accepted by the
  pinned MobileCoin verifier.

For a fixed input, every qualifying subset produced the same key image.

The fast suite also executes rejection paths for wrong message, wrong ring,
wrong pseudo-output, corrupted row 0, corrupted row 1, post-reservation
message/roster substitution, initial network/epoch/key/roster/threshold
mislabeling, a different group key, a bonded roster inconsistent with the
threshold registry, duplicate bonded identity keys, unregistered
per-participant verification shares, malformed ring size/public key,
noncanonical real response slots,
spend/mask policy mismatch, statement/key policy mismatch, and `t-1` signing.
It separately mutates every reserved statement field and every round-1 point
to demonstrate transcript coverage.

## Independent review

Two independent code reviews found no error in the MLSAG sign convention,
dual-base row-0 relation, row-1 commitment orientation, challenge traversal,
`c_zero` selection, threshold offset treatment, or verifier acceptance.

The reviews found four material omissions: reservation was not bound to
the complete statement, policy labels were not checked against local key
state, supplied spend/mask verification shares were checked only in the
aggregate, and the bonded identity roster was not tied to the threshold-share
registry. The published source repairs all four and adds mutation tests.

A later audit also found an M2a nonce-reuse error: the original example cloned
one complete row-1 nonce across multiple subset ceremonies. Two different
challenges with that nonce reveal the row-1 secret, and the reused decoy
response vector can reveal the real ring index. The published M2a session and
algorithm are no longer cloneable; its consuming test-only ceremony factory
duplicates state only across participant machines producing one signature,
and every new subset attempt asserts a fresh session ID, row-1 nonce
commitment, and decoy-response vector. M2b was never affected because its
nonce scalars are independently generated and consumed per signer ceremony.

The reviews still require the following limitations to remain explicit:

1. Round-1 and round-2 messages are not identity-signed. A bad map entry can be
   located, but it is not yet admissible evidence that the named bonded party
   authored it.
2. Nonce one-shot behavior is enforced only by Rust ownership in memory. A
   crash-safe persistent `AVAILABLE -> RESERVED -> BURNED` journal and session
   replay filter are not implemented.
3. M2a gives each participant the complete row-1 witness and same-ceremony
   nonce. Its non-cloneable example prevents the reproduced reuse defect, but
   it remains an intentionally weaker construction; production work should
   proceed from M2b and durable nonce state.
4. M2a's Serai `Algorithm` adapter still asserts on a substituted machine
   message or mismatched group key, so hostile API misuse can panic rather
   than returning a typed error. This P2 hardening defect does not affect
   M2b's fallible reservation/signing path.
5. Dealer fixtures materialize master polynomial coefficients during setup.
   They are not a PedPoP DKG, refresh, or proof that no production machine ever
   learns an aggregate scalar.
6. This is an implementation feasibility result, not a security reduction or
   third-party cryptographic audit.

## The decisive remaining blocker

M2 constructs the pseudo-output commitment backward from an independently
dealer-shared mask-difference group. It therefore proves this conditional:

> **Given valid threshold shares of `z = b_pseudo - b_input`, both MobileCoin
> MLSAG rows can be threshold-signed.**

It does not yet explain how a strict-custody implementation obtains those
shares from MobileCoin's nonlinear `MaskedAmountV2` KDF without first exposing
the complete input and pseudo-output blindings. It also does not jointly build
balanced multi-input pseudo outputs, masked outputs, or range proofs.

The minimum M3 test is now source-mapped: use two real v4 MobileCoin inputs,
stock `TransactionBuilder` and `UnsignedTx::get_signing_data`, hand the exact
digest/rings/pseudo blindings to a custom `RingSigner`, use M2b for each input,
retain stock Bulletproof range proofs, construct the transaction, and require
stock `validate_signature` to pass. Mandatory negatives mutate the key offset,
mask difference, prefix/output/fee, pseudo commitment, proof, each response
row, conservation equation, and signer cardinality.

M3 will be an integration proof, not strict mask custody, because current
MobileCoin builder interfaces expose complete blindings. Production M4 must
either redesign distributed masked-amount/pseudo-output generation or
explicitly weaken the custody requirement.

## Effect on Josh's final goal

This result answers the primitive feasibility question positively: MobileCoin
MLSAG is compatible with threshold/FROST-style signing on Ristretto, including
both response rows and the proposed 8-of-11 quorum.

It does **not** yet satisfy Josh's protocol-level requirement. An ordinary
MLSAG carries no on-chain threshold policy and no warden certificate; consensus
cannot distinguish this artifact from a single-holder signature. The final
system still requires a versioned MobileCoin transaction/certificate format,
consensus and enclave enforcement, warden authorization bound to the same base
transaction digest, durable accountability evidence, bridge accounting, and a
coordinated network upgrade.
