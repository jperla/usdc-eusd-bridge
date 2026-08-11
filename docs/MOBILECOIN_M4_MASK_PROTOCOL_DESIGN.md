# M4 share-native amount-mask protocol: source audit and decision

Pinned sources: MobileCoin `05cb699f8f4cc1bc21186392545820c5b38408db` and
Serai `4b89cf0206184886e96d0663861596312e5b47d2`.

## Verdict

There are two materially different requirements and they must not be conflated.

1. **`CoreCustodyKnownZ` is sufficient for Josh's stated custody goal.** Keep the one-time spend
   scalar `x` threshold-held. Wardens may know the real ring member, the input opening, the
   pseudo-output blinding, and therefore `z = b_pseudo - b_input`. Knowledge of `z` does not let
   fewer than `k` wardens produce MLSAG row 0, so it does not weaken `k`-of-`n` spend custody.
2. **`PrivateThresholdZ` is a stronger operator/privacy goal.** It prevents any single honest
   process from materializing `z`, improves row-1 sabotage attribution, and reduces the chance that
   a leaked mask identifies the real ring member. It is not required to prove `k`-of-`n` spend
   authorization, and it cannot punish a `k`-party coalition for reconstructing `z`: ordinary
   Shamir shares intentionally permit that coalition to interpolate the secret, with no public
   evidence that interpolation happened.

For the current v4 format, strict end-to-end `PrivateThresholdZ` is blocked by range-proof witness
handling. MobileCoin's prover is called with complete `(value, blinding)` pairs for every pseudo
output and output. Three choices exist:

- reconstruct each `b_pseudo` only inside a separately administered range-proof process which has
  no view key/input opening (stock-format compatible, but depends on non-collusion/role isolation);
- implement a threshold/MPC Bulletproof for a single additively shared witness (not provided by the
  pinned MobileCoin or Serai code); or
- in vNext, omit pseudo outputs from the range proof and rely on the same-index MLSAG row-1 proof
  plus ledger membership in previously validated outputs (a protocol change requiring a formal
  soundness argument and independent review).

The recommended implementation order is therefore: ship/prove `CoreCustodyKnownZ` for the custody
goal; treat `PrivateThresholdZ` as an explicit optional hardening milestone, not a hidden launch
dependency.

## What the pinned code actually does

For real input `j`, `InputCredentials::new` takes the TxOut public key `R_j`, computes the DH point

```text
S_j = a R_j
```

with the account view private key `a`, then calls `MaskedAmountV2::get_value`. V2 computes

```text
amount_secret_j = Blake2b512("mc_amount_shared_secret" || encode(S_j))[0..32]
b_input_j       = ScalarReduce64(HKDF-SHA512(
                      salt = "mc_amount_blinding_factors",
                      ikm  = amount_secret_j,
                      info = "mc_amount_blinding"))
```

and similarly derives XOR masks for value and token ID. It recomputes

```text
C_input_j = v_j H_token_j + b_input_j G
```

and rejects an inconsistent opening. Therefore the input blinding depends on the view DH secret,
not the spend secret. Replicating `a` among wardens, or reconstructing `aR_j` from threshold-DH
shares, reveals the complete `b_input_j`. Keeping `a` threshold-shared does not by itself keep
`b_input_j` shared because Blake2b/HKDF is nonlinear; hiding that output requires generic MPC for
the hash/KDF.

For `m` signable inputs, stock MobileCoin chooses random pseudo-output blindings for the first
`m-1` inputs and fixes the last so

```text
sum_j b_pseudo_j = sum_l b_output_l.
```

It generates range proofs over pseudo outputs and transaction outputs, then supplies every complete
`b_pseudo_j` to `RingSigner`. MLSAG row 1 uses

```text
z_j  = b_pseudo_j - b_input_j
s1_j = alpha1_j - c_real_j z_j
Z_j  = z_j G = C_pseudo_j - C_input_j.
```

This exact interface is why M3 necessarily materialized `z`.

## Profile 1: `CoreCustodyKnownZ`

Persistent secrets:

- root spend key `b`: PedPoP/FROST `k`-of-`n` shares;
- view key `a`: deliberately replicated among scanners/wardens, or held in a designated scanning
  component; it is privacy-sensitive but is not a spend key.

Per input, each approving signer independently derives `(value, token_id, b_input)` from V2 and
verifies the commitment. The stock builder chooses `b_pseudo`, output blindings, commitment balance,
and range proofs. A threshold `RingSigner` offsets the root spend shares to the one-time key and
produces row 0. Row 1 may be produced by a designated signed authority that knows `z`, or `z` may be
dealer-shared into M2b solely to retain a uniform two-row blame equation. The latter does not make
`z` unknown to the dealer and must not be advertised as strict mask custody.

Security statement:

> Fewer than `k` spend-share holders cannot authorize a MobileCoin input, even if they know every
> input/pseudo-output opening and the real ring index. The profile does not hide reserve activity or
> the real member from wardens, and a warden can disclose that information without producing
> objectively slashable cryptographic evidence.

## Profile 2: `PrivateThresholdZ`

### Algebra and one-shot mask slots

Generate a pool of one-shot random scalar sharings with Serai PedPoP while the full roster is
available. Each slot `q` contains, for participant `i`, a Shamir share `r_q(i)` and the complete
public verification-share registry `R_q(i)=r_q(i)G`; the group point is `R_q=r_qG`. PedPoP provides
coefficient commitments, proofs of possession, encrypted shares, invalid-share blame, and an
explicit completion barrier. The surrounding state machine must obtain the same signed completion
certificate from all participants before marking a slot available.

For an all-signable transaction with `m >= 2` inputs, atomically reserve `m-1` independent slots. Let

```text
B_out = sum_l b_output_l.
```

Define pseudo-mask sharings:

```text
p_j = r_j                                      for 1 <= j < m
p_m = B_out - sum_{j=1}^{m-1} r_j.
```

Participant `i` locally derives the final base share and every public verification share:

```text
u_m(i) = -sum_{j=1}^{m-1} r_j(i)
U_m(l) = -sum_{j=1}^{m-1} R_j(l)               for every roster member l,
```

constructs `ThresholdKeys(u_m,U_m)`, and applies Serai's public offset `+B_out`. This yields a
threshold key for `p_m`. The public check is

```text
sum_j P_j = B_out G, where P_j = p_j G.
```

No participant reconstructs any `p_j`. Each input's MLSAG row-1 key is obtained without a new DKG:

```text
z_keys_j = p_keys_j.offset(-b_input_j).
```

For signer set `S`, `ThresholdKeys::view(S)` applies the public offset exactly once, to the lowest
participant ID after Lagrange interpolation. Consequently

```text
sum_{i in S} z_share_j(i) = p_j - b_input_j
sum_{i in S} Z_share_j(i) = P_j - b_input_j G
                           = C_pseudo_j - C_input_j.
```

The M2b row-1 equation remains unchanged:

```text
G s1_i + c_real Z_i = R1_i.
```

Important persistence rule: Serai serialization explicitly omits `scale` and `offset`. Persist the
base slot IDs, the signed derivation recipe, `B_out`, input-opening hashes, and the transaction
binding; reconstruct and revalidate offsets after restart. Never serialize an offset key and assume
the offset survived.

Slot state is durable and monotonic:

```text
AVAILABLE -> RESERVED(mask_share_context_id) -> CONSUMED
                                           \-> BURNED_ON_ABORT
```

Do not reuse a slot for a different prefix, output set, range proof, input order, or signer set.

### Context binding

The signed `mask_share_context_id` must commit to at least:

- protocol/suite version, network/genesis, MobileCoin block version, custody epoch;
- ordered bonded roster, threshold, mask-registry root, and ordered consumed slot IDs;
- bridge-intent/transaction-approval digest and unique session ID;
- exact final input order; for each input, ordinal, ring hash, real index (private distribution is
  acceptable), real TxOut target/commitment, amount/token opening hash, and `b_input G`;
- exact output order/opening hashes, fee, `B_out G`, every `P_j`, `Z_j`, and `C_pseudo_j`;
- range-proof mode and final range-proof bytes/hash; and
- exact MLSAG signing digest before any MLSAG nonce is released.

This is a **confidential ceremony manifest**, not automatically a public transaction field. Publishing
`Z_j` together with the ordered ring and `C_pseudo_j` lets anyone test
`Z_j == C_pseudo_j-C_i` and identify the real member. The same warning applies to `b_input G` and
the real index. If a dispute publishes those fields for slashing, the protocol must explicitly
accept privacy loss for that transaction as the cost of adjudication; hash commitments can keep
them hidden during the honest path.

`P_j=p_jG`, the mask-slot group keys/verification registry, and the slot-to-transaction mapping are
also roster-confidential. MobileCoin v4 publishes pseudo-output token IDs; an observer who learns
both `P_j` and public `C_pseudo_j` obtains `v_j H_token = C_pseudo_j-P_j` and can dictionary-search
plausible eUSD amounts. This leaks the amount even without opening the real ring member.

### Range-proof choices

#### A. v4 role-separated prover (implementable, weaker assumption)

After `k` wardens approve the frozen transaction, they send Lagrange-weighted `p_j` shares over an
authenticated confidential channel to a registered proof worker. Its typed `ProofJobView` contains
only an opaque parent-context hash; block/proof version; canonical per-token ordered pseudo
witnesses `(ordinal, token_id, value, p_j, C_pseudo_j)`; ordered output witnesses; and the minimum
transcript/order data required by the prover. The worker generates the per-token v4 range proofs,
signs the opaque context digest plus result, and erases the witnesses. Wardens verify the proof
against the exact expected commitment order before reserving MLSAG nonces.

`ProofJobView` must not contain or resolve to the ordered input rings, real indices/TxOut targets,
`Z_j`, `b_input_j`/`b_input_j G`, the view key/amount shared secret, or the full confidential
ceremony manifest. `Z_j` together with a ring and `C_pseudo_j` directly selects the real member.
Do not send the ring at job time, but assume the worker can link its commitments/proof to the
finalized public ring later. The reconstructed `p_j` and its value/token witness are themselves
sensitive transaction-linkage and amount-enumeration material, so this option cannot hide the
transaction from the proof worker; it is a narrowly scoped confidential role, not a public service.

The pinned Bulletproof fork also exposes an online multi-party aggregation API with `Party` and
`Dealer`; `Dealer::receive_shares` audits malformed proof shares and returns bad party indices.
However, each `Party::new` still receives one complete `(value, blinding)` witness. It can separate
different witnesses among no-view proof workers; it does **not** threshold one pseudo-output
blinding. Add canonical message encodings/accessors, identity signatures, independent challenge
recomputation, an expected-`V_j` check, MobileCoin's exact power-of-two witness padding, and the
exact pseudo-then-output per-token ordering before treating its party index as slashable evidence.

This option ensures no honest process has both `p_j` and `b_input_j`, but it is not secure against a
proof worker colluding with any view-key warden. Process separation is an operational assumption,
not a cryptographic theorem.

#### B. threshold/MPC Bulletproof (strong, currently absent)

Evaluate the Bulletproof prover with additively/Shamir-shared `p_j`, including shared bit
decomposition and nonlinear transcript products. Neither Serai FROST/PedPoP nor MobileCoin's wrapper
implements this. This is new cryptographic engineering and audit scope.

#### C. vNext output-only range proof (promising protocol change)

Range-prove only newly created outputs. The same-index two-row MLSAG proves that each pseudo-output
has the same value as one ledger-member commitment, and membership/full-ledger validation establishes
that ledger commitment came from a previously valid transaction or mint path. This keeps `p_j`
shared. It changes standalone signature-validation semantics and requires a proof covering every
TxOut creation path, validator ordering, SCI/presigned inputs, and mint outputs before adoption.

### Single-input impossibility

When `m=1`, conservation fixes

```text
p_1 = B_out.
```

If a warden knows both `B_out` (as current output construction exposes) and `b_input_1` (from the
view key), it necessarily knows `z_1=B_out-b_input_1`; no random-share protocol can hide a scalar
that is already algebraically determined by that process's inputs. `PrivateThresholdZ` must choose
one of:

- require at least two inputs per transaction;
- threshold-hide output blindings and use a distributed output/range-proof construction;
- place output-mask construction in a non-view role and accept that role-separation assumption; or
- fall back explicitly to `CoreCustodyKnownZ` for one-input spends.

Likewise, any `k` colluding share holders can interpolate `p_j`/`z_j` by design. No protocol can both
use ordinary `k`-of-`n` Shamir shares and make that coalition unable to reconstruct them.

Stock v4 also supports SCI/presigned inputs whose pseudo masks are already fixed. The simple
`m-1`-slot formula above intentionally excludes them. A later extension must partition fixed inputs
`F` from signable inputs `U` and derive the last signable mask as
`p_last = B_out - sum_{f in F} p_f - sum_{u in U, u != last} r_u`. Strict private mode needs at
least two signable pseudo masks, not merely two total inputs; the first implementation should reject
SCI/presigned inputs rather than silently applying the all-signable construction.

## Objective checks and accountability

Reject before any MLSAG nonce commitment is released unless every signer verifies:

1. V2 unmasking succeeds and recomputes every real commitment exactly.
2. The one-time spend group plus canonical offset equals the real target key.
3. Every mask slot is `AVAILABLE`, belongs to the local signed registry root/epoch, has the exact
   roster/threshold, and is atomically reserved once.
4. All PedPoP PoPs, encrypted shares, coefficient commitments, completion certificates, and identity
   signatures verify; equivocated signed broadcasts are permanent evidence.
5. Derived raw and public shares agree; all signers independently derive the last pseudo key.
6. `sum P_j = B_out G` and `Z_j = P_j-b_input_jG = C_pseudo_j-C_input_j` for every input.
7. Integer value conservation holds per token with checked arithmetic, and the aggregate commitment
   conservation equation is the identity.
8. Pseudo/token/output order is canonical, all range proofs verify over the final commitments, and
   the final signing digest/context ID matches signer-local recomputation.
9. M2b round-1 verification shares exactly match each signer's local `z_keys_j.view(S)`; each
   round-2 share satisfies the row-0 and row-1 blame equations.

Invalid signed DKG, range-proof, round-1, or round-2 messages can identify a bonded participant or
proof worker. Silence/withholding is only a liveness fault unless an adjudicator has a canonical
deadline and authenticated availability log. Off-protocol reconstruction or disclosure of `z` is
not publicly detectable and cannot be made objectively slashable merely by writing a penalty rule.

## Executable acceptance tests

Success suite:

- exact V2 derivation vectors for multiple inputs/subaddresses and wrong-secret rejection;
- two, three, and maximum-input transactions, including mixed-token v4 ordering;
- `m-1` independent PedPoP slots, derived last key, and `sum P=B_out G`;
- every exact `k`-subset for a small roster and sampled/exhaustive 8-of-11 subsets: invariant
  `P_j`, `Z_j`, key image, successful M2b shares, and stock MLSAG verification;
- stock range-proof and complete `SignatureRctBulletproofs::verify` pass in the chosen range-proof
  mode;
- crash/restart reconstructs offsets from the signed recipe and never revives consumed slots;
- capability/data-flow test proves no configured process role or message schema combines
  `PSEUDO_MASK_RECONSTRUCT` with any of `VIEW_INPUT_OPEN`, `ROW1_KEY_Z`,
  `INPUT_BLINDING_POINT`, or `REAL_INDEX`; verifies the exact `ProofJobView` field allowlist; and
  proves the proof worker never receives `Z_j`, `b_input_j G`, real indices, TxOut targets, or
  ordered rings in the role-separated profile.

Failure suite:

- corrupt V2 masked value/token/commitment or wrong DH secret;
- corrupt/equivocated PedPoP commitment, PoP, encrypted share, completion certificate, registry
  root, slot epoch, or slot ID;
- reuse/reserve one slot under two contexts, restore pre-reservation snapshot, or change the signer
  set/transaction after reservation;
- corrupt any raw/verification share, derived last share, public offset, `B_out`, `P_j`, `Z_j`,
  pseudo commitment, token ID, output opening, fee, or input/output order;
- fewer than `k` reconstruction/signing shares;
- proof worker uses wrong `(value,p)`, wrong commitment slot, challenge, proof share, proof order, or
  final proof; require signed identity attribution where the API supports it;
- submit any SCI/presigned input to the initial all-signable private profile, or configure fewer
  than two signable inputs; require explicit rejection rather than silently reusing the slot formula;
- corrupt M2b row 0/row 1 share and require exact participant blame;
- attempt one-input `PrivateThresholdZ` while both `B_out` and `b_input` are locally visible; require
  explicit `INSUFFICIENT_MASK_ENTROPY`, not silent downgrade.

The algebra-only spike at `/Users/jperla/josh/m4-mask-algebra` passed `cargo test --offline` and
`cargo clippy --offline --all-targets -- -D warnings`. It constructs three balanced pseudo-mask
keys from two independent 2-of-3 threshold slots, derives every `z` by public offset, and checks all
three exact 2-of-3 subsets. It intentionally uses Serai's trusted test dealer only to isolate the
linear-combination claim; production slot generation must use PedPoP and the completion protocol.

## Source anchors

- MobileCoin `transaction/builder/src/input_credentials.rs:55-91`
- MobileCoin `transaction/types/src/masked_amount/v2.rs:59-157,210-272`
- MobileCoin `transaction/core/src/ring_ct/rct_bulletproofs.rs:304-425,878-945`
- MobileCoin `transaction/core/src/range_proofs/mod.rs:35-67`
- MobileCoin `crypto/ring-signature/src/ring_signature/mlsag_sign.rs:309-325`
- MobileCoin `crypto/ring-signature/signer/src/traits.rs:78-109`
- Serai `crypto/dkg/src/lib.rs:409-447,461-532,535-570`
- Serai `crypto/dkg/pedpop/src/lib.rs:145-201,465-571`
- pinned Bulletproof fork `src/range_proof/{mod.rs:53-58,party.rs:32-71,dealer.rs:300-353}`
