# MobileCoin BridgeEscrowV3 on-chain threshold-custody protocol patch map

**Source snapshot:** `/Users/jperla/josh/repos/mobilecoin` at
`05cb699f8f4cc1bc21186392545820c5b38408db` (working tree observed clean).

**Normative contract (durable live copy):**
`/Users/jperla/josh/spec/BRIDGE_V2_TEST_PLAN.md` at SHA-256
`bbbd520350d133124ca77f2827f563cd64692b1495e4949cce65bdf28e2d0f14`,
especially the digest DAG at lines 350-746, role separation at 748-790,
reservation lifecycle at 792-920, MobileCoin policy/lease/proof rules at
924-1295, and safe cancellation at 1297-1318. Companion live contracts are
`/Users/jperla/josh/spec/BRIDGE_V2_CAPACITY_INTERFACE.md` at SHA-256
`71114628df1b10a5eba70f787e160f86d22b2ea81a3398cd0f0825f5a05884dd`
and `/Users/jperla/josh/spec/BRIDGE_V3_DECISION_REGISTER.md` at SHA-256
`5f5719eb3393babff3f11e835e397d0b27f27b790be32f177329e4b98f8f7a1d`.
The retained V2 filenames identify the frozen acceptance contracts; this is
the v3 implementation map. The capacity interface is a companion, not a
substitute for the test-plan contract.

This is an implementation map, not a claim that the named bridge types or
functions already exist. Existing identifiers below are quoted exactly. A row
marked **NEW** is a required protocol surface whose final Rust name, protobuf
tag, and crate placement must be frozen in the MCIP/design review before code
lands.

## 1. Executive conclusion

The requested result is feasible only as a coordinated MobileCoin network
upgrade. It is not “port Serai CLSAG into `RingSigner`.” The current repository
has:

- a fixed two-row ordinary MLSAG spend proof;
- a synchronous one-call signer which receives the real ring index, complete
  one-time spend secret, complete input blinding, and complete pseudo-output
  blinding;
- no FROST, DKG, Shamir, VSS, threshold-MLSAG, or durable signing-round state;
- no consensus value for a reservation or bridge event;
- no bridge state commitment or ledger indices; and
- blocks which retain only outputs, key images, and mint records after the
  enclave redacts ordinary transactions.

Consequently, the implementation touches transaction wire formats and hashes,
RingCT signing, a new reserve-only verifier, consensus proposal/value handling,
the consensus enclave ABI and measurement, block contents, LedgerDB and its
migration tool, Fog/mobilecoind/wallet data paths, light-client verification,
and network activation.

Four items are research/review gates, not normal engineering tasks:

1. a VSS/MPC provisioning path which creates and rotates shares of each policy
   output's one-time key and amount blinding without any participant,
   coordinator, or host reconstructing `x`, `b_input`, `b_pseudo`, or `z`,
   including a reviewed distributed derivation of MobileCoin
   `MaskedAmountV2`'s nonlinear amount-shared-secret/HKDF result rather than
   applying that KDF independently to Shamir/FROST shares;
2. security reductions and reviewed protocols for all three: the threshold
   two-row reserve proof, the separate threshold ordinary-MLSAG spend, and
   distributed generation of the ordinary RingCT range proof before `D`;
3. one concrete accounting backend: a pinned ZK circuit/verifying key or a
   pinned SGX accounting measurement, attestation/freshness, and anti-rollback
   profile; and
4. an authenticated bridge-state/checkpoint proof which makes “expired and
   exactly not executed” objectively provable for safe cancellation.

Until all four are frozen, the only safe implementation is a non-activatable
v5 skeleton. A feature flag or operator assertion must not bypass a gate.

## 2. Existing protocol topology and exact seams

| Concern | Existing source boundary | What exists now |
|---|---|---|
| Block-version ceiling | `transaction/types/src/block_version.rs:33-47,59-77,85-156` | `BlockVersion::MAX` is `FOUR`; `FOUR` has no new feature gate. |
| Block/header identity | `blockchain/types/src/block.rs:16-48,50-171,174-199` | Header tags 1-7; block ID is a manual Merlin transcript over the existing fields. |
| Transaction wire | `transaction/core/src/tx.rs:104-139,157-213,245-297,300-425` | `Tx`, `TxPrefix`, `TxIn`, and `TxOut` are prost messages and `Digestible`. `TxOut` has tags 1-6; `TxPrefix` has tags 1-5. |
| Public transaction proto | `api/proto/external.proto:208-233,235-312,314-368` | Mirrors the existing transaction structs. |
| Public converters | `api/src/convert/tx_out.rs:9-87`, `api/src/convert/tx_prefix.rs:8-45`, `api/src/convert/tx.rs:8-39` | Explicit conversions; new fields will not propagate automatically. |
| Signing digest | `transaction/core/src/ring_ct/signing_digest.rs:31-101,124-171` | Hashes `tx_prefix.hash()`, then pseudo outputs/range proofs; derives `TxSummary` internally. No network/genesis parameter. |
| Signing-data creation | `transaction/core/src/ring_ct/rct_bulletproofs.rs:125-166,186-475` | Generates complete pseudo blindings, commitments, range proofs, digest, and summary in one process. |
| RingCT assembly | `transaction/core/src/ring_ct/rct_bulletproofs.rs:478-525,528-620` | `SigningData::sign` calls a one-shot `RingSigner` and directly builds `SignatureRctBulletproofs`. |
| Ordinary verification | `transaction/core/src/ring_ct/rct_bulletproofs.rs:606-867` | Verifies range proofs, value balance, recomputes signing digest, then calls ordinary `RingMLSAG::verify`. |
| Ordinary MLSAG | `crypto/ring-signature/src/ring_signature/mlsag.rs:25-44,64-205`; `mlsag_verify.rs:14-103`; `mlsag_sign.rs:147-177,214-250,311-325` | Two rows: ownership/key image and commitment-difference equality. Challenge is hard-coded to the ordinary domain. |
| MLSAG domains | `crypto/ring-signature/src/ring_signature/mod.rs:124-139`; `crypto/ring-signature/src/domain_separators.rs:18-25` | Ordinary challenge domain is `mc_ring_mlsag_challenge`. |
| Signer custody API | `crypto/ring-signature/signer/src/traits.rs:13-42,72-110`; `local_signer.rs:20-68` | The signer receives `real_input_index`, full key derivation data, full amount/blinding, and full pseudo blinding. |
| MaskedAmountV2 derivation | `transaction/types/src/masked_amount/v2.rs:59-87,239-272` | Output construction derives value mask, token mask, and commitment blinding through one nonlinear amount-shared-secret/HKDF path; evaluating it independently on additive key shares does not produce valid blinding shares. |
| Ordinary range-proof generation | `transaction/core/src/ring_ct/rct_bulletproofs.rs:304-382,878-945`; `transaction/core/src/range_proofs/mod.rs:36-66` | The current one-process path selects complete pseudo-output blindings and passes complete value/blinding arrays to the Bulletproof prover before computing the MLSAG digest. |
| Unsigned/offline API | `transaction/extra/src/unsigned_tx.rs:18-147`; `api/proto/external.proto:682-790`; `api/src/convert/signing_data.rs:8-49` | Serializes full `InputRing`/`InputSecret` and full `SigningData`; unsafe for the bridge custody profile. |
| Pure tx validation | `transaction/core/src/validation/validate.rs:31-93,95-121,300-331,333-477`; errors at `transaction/core/src/validation/error.rs:9-175` | Structural/signature/fee/tombstone rules only; no bridge state. |
| Enclave admission | `consensus/enclave/impl/src/lib.rs:591-730` | Decrypts directly into `Tx`, checks fee map, validates membership/signature, and emits a small context. |
| Untrusted state checks | `consensus/service/src/validators.rs:73-163` | Checks tombstone, historical KIs, output keys, and in-block KI/output-key collisions. |
| Enclave API/ABI | `consensus/enclave/api/src/lib.rs:59-142,180-198,215-331`; `messages.rs:22-137` | `WellFormedTxContext`, `FormBlockInputs`, and serialized `EnclaveCall` know only ordinary/mint transactions. |
| Consensus values | `peers/src/consensus_msg.rs:19-32`; `consensus/service/src/byzantine_ledger/pending_values.rs:69-112,145-157`; `byzantine_ledger/mod.rs:142-190` | Values are only `TxHash`, `MintConfigTx`, and `MintTx`. |
| Block formation/redaction | `consensus/enclave/impl/src/lib.rs:765-953` | Enclave emits only key images, outputs, validated mint configs, and mint txs. |
| Block contents | `blockchain/types/src/block_contents.rs:19-43`; `api/proto/blockchain.proto:48-60`; `api/src/convert/block_contents.rs:13-75` | Four fields only. `contents_hash` commits their `Digestible` representation. |
| Ledger append | `ledger/db/src/ledger_db.rs:35-74,97-223,432-523,588-617,665-809,834-873,917-933` | One LMDB transaction writes KIs, outputs, mint data, and block. No bridge state. |
| Ledger trait | `ledger/db/src/ledger_trait.rs:17-143` | Exposes block/output/KI/mint queries only. |
| Ledger migration | `ledger/migration/src/lib.rs:24-142,144-245` | Explicit metadata-version ladder and existing deterministic backfill patterns. |
| Merkle leaves | `transaction/core/src/membership_proofs/mod.rs:31-52`; `ledger/db/src/tx_out_store.rs:108-147,242-296` | Leaf hash includes `TxOut::hash()`; changing legacy TxOut hashing would corrupt the whole historical tree. |
| Role multisig primitive | `crypto/multisig/src/lib.rs:23-72,74-157,159-244` | At most ten generic signatures; verifies a signer set but has no role/identity/bond/epoch receipt schema. |
| Node/enclave config | `consensus/service/config/src/lib.rs:34-118`; `consensus/service/src/bin/main.rs:67-97`; `consensus/enclave/api/src/config.rs:15-95` | Host has a string `chain_id` and origin path; enclave config has fees/governors/block version only. |
| SGX identity build | `consensus/enclave/measurement/build.rs:11-88`; `consensus/enclave/measurement/src/lib.rs:10-39` | Any trusted-code change produces a new signed enclave and measurement. |

## 3. Required v5 wire and hash patch

### 3.1 BlockVersion and activation

Patch `transaction/types/src/block_version.rs:59-77` to add a distinct value
after `FOUR` and make it the maximum supported version. Do not repurpose
`FOUR`; released software already interprets it. Add v5 feature predicates for
the canonical network-bound signing digest, policy-tagged outputs, bridge
extensions, and bridge-state contents. Every predicate must remain false for
versions 0-4.

The code currently accepts any nondecreasing block version up to the compiled
maximum (`ledger/db/src/ledger_db.rs:693-698`) and a node publishes one configured
version (`consensus/enclave/impl/src/lib.rs:780-792`). That is not an activation
schedule. **NEW:** freeze an activation height/checkpoint in signed network
configuration and require the exact expected version at each height. Wire this
through `consensus/service/config/src/lib.rs:34-118`, construction at
`consensus/service/src/bin/main.rs:67-83`, and
`consensus/enclave/api/src/config.rs:15-72`. Early v5 and late v4 blocks must
both reject.

`chain_id: String` is not a cryptographic network identity. Before enclave
initialization, load block zero from the configured ledger/origin, derive its
actual `BlockID`, compare it with the signed network manifest, then pass that
fixed 32-byte genesis ID into `BlockchainConfig`. The enclave must compare all
v5 transaction/receipt/proof network IDs to this immutable value. Never use the
operator-supplied chain-id string in `InputLeaseTag` or signing domains.

Success gate:

- every v0-v4 block/digest fixture remains byte-identical;
- old binaries reject v5 and v5 binaries reject an incorrect activation
  height or genesis ID;
- two validators with different genesis/backend/manifest config cannot peer as
  if their configurations were equal (the config digest at
  `consensus/enclave/api/src/config.rs:86-95` must cover all additions).

### 3.2 TxOut policy and provenance fields

At `transaction/core/src/tx.rs:300-323`, add the contract's three immutable
optional values to `TxOut`:

- `spend_policy_id`;
- `bridge_lot_commitment`; and
- `threshold_witness_package_commitment`.

These are **NEW wire fields**. Tags 7, 8, and 9 are presently free in the Rust
and external proto, but those numbers are only candidates until the MCIP
reserves them. Use fixed-length typed wrappers and explicit absence, not an
arbitrary string or an unchecked `Vec<u8>`. Absence is the one canonical
`UNTAGGED` representation; zero bytes must not become a second spelling.

Mirror the fields in `api/proto/external.proto:208-233`, both directions of
`api/src/convert/tx_out.rs:9-87`, JSON representations, archive/fog APIs, and
all explicit struct constructors. `TxOut::new` and `TxOut::new_with_memo` at
`transaction/core/src/tx.rs:348-420` must remain ordinary constructors and
always return UNTAGGED outputs. The generic builder path
`transaction/builder/src/tx_blueprint.rs:23-64,95-240` and helper
`transaction/builder/src/transaction_builder.rs:877-895` must also remain
UNTAGGED.

Consensus, not Rust visibility, closes output creation. Callers can always
construct protobuf messages directly. Add authoritative v5 validation so that
non-absent policy fields are accepted only when the block transition contains
one of the four frozen provenance paths:

1. `CAPITALIZE_EXTERNAL_EUSD` with the exact supply/owner/policy/generation
   authorization;
2. `CAPITALIZE_PREDECESSOR_TRANSFER` consuming the cited predecessor lot;
3. a typed `BridgeReturn`/`RECORD_ESCROW_SOURCE_INFLOW` whose escrow recipient,
   policy, lot, provenance, and witness-package commitment are derived rather
   than caller labels; or
4. same-lot bridge change produced atomically by the matching final release.

The deterministic fee and mint output path at
`consensus/enclave/impl/src/lib.rs:813-875,890-915,984-1029` must always create
UNTAGGED outputs. If external capitalization creates new eUSD supply, its
relationship to existing `MintTx` governor authorization and mint limits must
be frozen; a bridge event must not silently become a second mint authority.

`TxOut::eq_ignoring_amount` at `transaction/core/src/tx.rs:496-505` should
continue comparing all new policy/provenance fields. `ReducedTxOut` at
`transaction/core/src/tx.rs:508-515` may remain the cryptographic
key/commitment reduction, but validation must inspect full ring members before
that reduction.

Historical-hash gate: adding fields to a `Digestible` struct naively changes
`TxOut::hash()` for every old output, and therefore every leaf at
`membership_proofs/mod.rs:31-36`. Implement an explicit compatibility path:

- a TxOut with all v5 policy/provenance fields absent hashes with the exact
  legacy transcript and produces the exact old leaf;
- a policy/provenance-bearing TxOut hashes in a new frozen v5 domain over the
  complete canonical object; and
- golden tests load real pre-v5 TxOut bytes and assert the old TxOut hash,
  global hash index, leaf, and Merkle root bit-for-bit.

Do not rely on a new derive with omitted/default fields without proving its AST
is byte-identical to the old derive.

### 3.3 TxPrefix bridge extension and top-level final artifact

At `transaction/core/src/tx.rs:157-184`, add one optional typed bridge extension
containing exactly the frozen fields: network genesis, bridge/direction,
policy/epoch/generation, liability, source nullifier, allocation manifest, and
typed reservation ID. Tag 6 is presently free but must be reserved in the
MCIP. The pre-reservation object contains the unique typed zero reservation;
the final object differs only by replacing that value once.

The ordinary `TxPrefix::new` at lines 186-208 remains non-bridge. Add a separate
closed bridge construction path rather than optional arguments on the ordinary
constructor. `TxBlueprint`/`UnsignedTx` conversion at
`transaction/builder/src/tx_blueprint.rs:75-132` currently always calls the
ordinary constructor and therefore needs a distinct bridge blueprint path.

The final FROST gate artifact is a signature over `M_GATE`, so it cannot be a
field inside the prefix from which `D` is derived. **NEW:** carry the typed gate
artifact in a non-prefix bridge-final authorization field on `Tx` (current top
level tags are 1-3 at `transaction/core/src/tx.rs:104-122`) or reference an
already committed artifact by an unambiguous on-chain ID. Freeze this choice.
The ordinary threshold MLSAG aggregate remains in
`SignatureRctBulletproofs.ring_signatures`; WARDEN/ACCOUNT receipts and reserve
proofs are stored by the prior reservation, not smuggled into the ordinary
MLSAG.

Update `api/proto/external.proto:296-368`, converters, external unsigned/signing
types, `mobilecoind-json/src/data_types.rs:920-965`, and all explicit
`TxPrefix`/`Tx` construction. Add strict length, enum, canonical-order, and
unknown-profile validation.

### 3.4 Canonical vNext MLSAG digest

The only current function is
`transaction/core/src/ring_ct/signing_digest.rs::compute_mlsag_signing_digest`
at lines 54-101; its only production call sites are
`transaction/core/src/ring_ct/rct_bulletproofs.rs:438-444,841-847`.

Keep the existing algorithm byte-for-byte for versions 0-4. For v5 dispatch to
the frozen algorithm which takes:

- the immutable genesis `BlockID` bytes;
- block version;
- the decoded, closed `FinalTxPrefix` re-encoded using the one canonical v5
  encoding;
- exact ordered pseudo-output commitments; and
- exactly one of legacy single-range-proof bytes or ordered multi-range-proof
  bytes according to the block-version rule.

Use a new domain separator in `transaction/types/src/domain_separators.rs:44-48`.
Do not call `tx_prefix.hash()` at line 62 in the v5 branch and do not substitute
`IntentBindingCore` or a compact prefix commitment. The verifier must derive
`TxSummary` internally as it does at line 73. Define “canonical wire” as the
deterministic encoding of the fully decoded closed Rust/prost object; either
reject a noncanonical inbound encoding or explicitly specify that alternate
protobuf field order/duplicate singular spellings normalize to that one object.
Unknown fields must never become unsigned semantics.

The signature also contains `pseudo_output_token_ids` and `output_token_ids`
(`rct_bulletproofs.rs:557-565`). They are verifier-consumed fields but are not
parameters of the frozen draft's vNext function. Before implementation, the
MCIP must either bind them explicitly or document and prove why the range-proof
and balance checks make them cryptographically redundant. This cannot remain
an accidental exclusion.

`TxSummary` currently omits policy and bridge fields
(`transaction/types/src/tx_summary.rs:19-73`; construction at
`transaction/core/src/tx_summary.rs:108-159`). A v5 signer/hardware wallet must
see policy, lot, reservation, destination, and network context. Add a v5 summary
representation or a versioned digest path. Naively adding fields to the current
`Digestible` summary would change v3/v4 MLSAG digests. Preserve all old vectors.

Plumb genesis/network context through `TransactionBuilder`, `TxBlueprint`,
`UnsignedTx`, `SigningData`, transaction-signer/hardware-wallet APIs, and the
consensus enclave verifier. A threshold participant must recompute `D` from the
full canonical object; accepting a coordinator-supplied 32-byte digest alone is
not sufficient.

Mutation gate: for a valid v5 vector, flipping every individual prefix field,
ring member/proof/input rule, output field, policy/lot/witness commitment,
genesis ID, block version, pseudo output, or range-proof byte must change `D`
or fail canonical validation. The typed zero-to-final reservation replacement
must have exactly one valid location.

## 4. Policy-homogeneous rings and global input leases

### 4.1 Ring validation and selection

Add the pure homogeneity check to
`transaction/core/src/validation/validate.rs:31-93` before conversion to
`SignedInputRing` and ordinary signature verification:

- a standard/ordinary input ring is entirely UNTAGGED;
- a final bridge escrow-spend ring is entirely the one exact
  `spend_policy_id` cited by its bridge manifest;
- a typed customer BridgeReturn uses the exact rule frozen for that action
  (normally ordinary UNTAGGED input rings and one authorized tagged escrow
  output); and
- legacy/tagged or mixed-policy rings fail. There is no “real member has the
  right label” exception.

Add typed errors in `transaction/core/src/validation/error.rs:14-156`, map them
through `consensus/api/src/conversions.rs:22-67`, and reserve public enum values
after `FeeMapDigestMismatch = 55` in
`consensus/api/proto/consensus_common.proto:53-102`.

Builder checks are useful diagnostics but not security boundaries. The
authoritative full-ring check occurs before `TxIn -> SignedInputRing` discards
the fields (`transaction/core/src/tx.rs:286-297`).

Existing decoy selection samples the whole global output space:

- `mobilecoind/src/payments.rs:1026-1082`;
- `mobilecoind/src/service.rs:904-952`; and
- `fog/sample-paykit/src/client.rs:811-875`.

Bridge ring selection must query/sample only the exact eligible policy pool and
verify every returned member/proof locally. Ordinary selection must exclude all
tagged outputs. Do not download global outputs and let a coordinator choose an
operator-labelled subset. The fixed limits are ring size 11, at most 16 inputs
and 16 outputs (`transaction/types/src/constants.rs:7-17`); activation must
require at least 11 eligible outputs per policy pool and declare the intended
anonymity/capacity threshold.

### 4.2 Fog and wallet propagation

`FogTxOut` drops all data other than keys, amount fragments, and memo
(`fog/types/src/view.rs:484-530`) and reconstructs a `TxOut` at lines 549-590.
Extend `FogTxOut`, flattened `TxOutRecord` at lines 337-445, and
`fog/api/proto/view.proto:322-380+` so a wallet can identify policy/lot/witness
metadata and retrieve the exact ledger TxOut for membership proofs. Update
ingest conversion at `fog/ingest/enclave/impl/src/lib.rs:293-305,393-437`, Fog
record size/ORAM assumptions, and round-trip vectors. This changes Fog ingest
trusted code and therefore its measurement as well as the consensus enclave's.

Bridge custody must not use ordinary `InputCredentials::new` at
`transaction/builder/src/input_credentials.rs:42-98`: it reconstructs the full
input blinding and stores a complete `InputSecret`. Add a distinct share-based
wallet/custody path. Ordinary wallet/mobilecoind behavior remains unchanged
except that it excludes tagged outputs from ordinary spends and decoys.

### 4.3 InputLeaseTag and permanent ring binding

Implement the exact global derivation:

```text
H("MC_INPUT_LEASE_TAG_V1", network_genesis_id,
  canonical_key_image_bytes)
```

No bridge, epoch, generation, retry, reservation, salt, ring, or protocol
version enters this hash. Canonical key images come from the pre-intent
threshold KI/DLEQ ceremony; consensus recomputes every tag at reserve and
finalization.

**NEW ledger state** is required for:

- lease tag -> `Live(reservation_id, ring_binding)` or `Consumed`; absence is
  the only `Free` state;
- key image -> permanent salted canonical ring-member-set binding;
- append-only reserve/cancel/consume history.

Every ordinary spend also transitions its derived tag to `Consumed`, not only
bridge spends. A standard transaction whose key image is currently `Live` is
invalid. A matching bridge final may consume it; cancellation returns `Live`
to absent/Free but retains the permanent ring binding. Retry must open the same
salt and canonical member set.

Extend `WellFormedTxContext` (`consensus/enclave/api/src/lib.rs:59-142`) with
enclave-derived bridge conflict identifiers, and extend the combine logic at
`consensus/service/src/validators.rs:112-163` to reject every same-block
reserve/spend, reserve/cancel, cancel/retry, cancel/final, double reserve, KI,
lease-tag, source-nullifier, liability, or capacity-lot conflict. These host
fields are hints for deterministic combination; block formation/state replay
must revalidate them against the committed payload.

### 4.4 Historical migration

At activation, every historical key image must already have a consumed lease
tag. Source data exists in `KEY_IMAGES_DB_NAME` and per-block
`KEY_IMAGES_BY_BLOCK_DB_NAME` (`ledger/db/src/ledger_db.rs:40-49,588-617`), and
the public trait exposes `get_key_images_by_block` at
`ledger/db/src/ledger_trait.rs:88-100`.

Add a new metadata version after `2022_09_21`
(`ledger/db/src/ledger_db.rs:58-74`) and an explicit ladder step in
`ledger/migration/src/lib.rs:36-140`. The offline/idempotent migration must:

1. bind itself to the exact genesis ID and a pinned pre-activation tip block ID;
2. create the bridge state/tag/history databases and raise
   `MAX_LMDB_DATABASES` from 19 (`ledger_db.rs:35-49`);
3. iterate every historical key image, canonicalize it, derive its tag, and
   write `Consumed` with the first spent height;
4. independently count/cursor the global KI database and the concatenated
   per-block lists, rejecting any mismatch, duplicate, corrupt key, or missing
   block; and
5. commit a migration checkpoint containing genesis, tip, counts, and a
   deterministic digest. The node refuses v5 activation until that checkpoint
   verifies and then updates tags atomically with every appended block.

Test crash/restart at every batch boundary, a wrong genesis, a partial DB, a
duplicate, and a ledger which advances after the pinned tip. “Missing means
Free” is forbidden before the completeness marker is verified.

## 5. Reserve proof and accounting verifier

### 5.1 Structurally distinct two-row reserve verifier

Ordinary MobileCoin MLSAG is already two-row algebra, but its wire type and
challenge are spend-authorizing. The reserve proof must be a distinct **NEW**
wire type and verifier adjacent to `crypto/ring-signature/src/ring_signature/`,
with a domain in `crypto/ring-signature/src/domain_separators.rs` matching
`BRIDGE_THRESHOLD_MLSAG_OWNERSHIP_EQUALITY_CHALLENGE_V2`.

Do not implement it as `RingMLSAG::verify(different_message, ...)`. The new
envelope/type discriminator and protobuf layout must be incompatible with the
ordinary `RingMLSAG` at `mlsag.rs:25-44`, and each verifier must reject the
other type before parsing response scalars. Low-level point/scalar operations
may be refactored and shared after review, but the challenge function at
`ring_signature/mod.rs:124-139` is currently hard-coded and must not be
silently parameterized without cross-domain tests.

For each input the reserve verifier checks, against the complete frozen
statement and ring:

- row 0 ownership and the canonical ordinary key image;
- row 1 `C_pseudo - C_input = zG` for the same hidden member;
- exact ring order/set binding, input ordinal, policy, owner manifest,
  reservation, `D`, pseudo output, KI/tag, and permanent ring binding;
- canonical, non-identity Ristretto points/scalars and exact response count;
- proof-byte and bundle commitments; and
- no claim about lot provenance/accounting beyond those two rows.

The final ordinary spend continues to call `RingMLSAG::verify` at
`rct_bulletproofs.rs:849-863`; the reserve path never marks the key image spent.

Required crypto tests include ordinary-as-reserve and reserve-as-ordinary
rejection, domain/role/network/input/ring swaps, identity/noncanonical points,
bad KI/DLEQ shares, bad z shares, signer-set and cross-input swaps, nonce reuse,
response-before-`D`, altered pseudo commitments, and batch-versus-single
verification equivalence. Add fuzz targets for both decoders and verifiers and
obtain an external cryptography review/security reduction before activation.

### 5.2 Accounting backend hook

The two rows do not prove lot provenance, asset/token classification, full
input/output relations, fee, gross depletion, or same-lot change. Add one
closed backend dispatcher to bridge reservation validation; it accepts only
the manifest-selected enum:

- `ZK_ACCOUNTING_CIRCUIT_V1`: deterministic verification under the exact pinned
  circuit and verifying-key hash; or
- `SGX_ATTESTED_ACCOUNTING_V1`: deterministic verification of an artifact whose
  attested report data binds the full `ReserveAccountingProofDigest`, backend
  manifest, measurement, freshness checkpoint, and result.

There is no default/NONE/MLSAG-only/coordinator-boolean branch. The public
ordinary range proofs are still independently verified by
`SignatureRctBulletproofs::verify` (`rct_bulletproofs.rs:708-837`).

For the SGX profile, the repository has reusable DCAP verification and report
data binding at `attest/verifier/src/dcap.rs:42-62,107-131`, but it does not have
the accounting prover, statement schema, anti-rollback store, or freshness
protocol. Pin trusted identities/roots/advisories and ensure report data commits
to the exact statement, not an opaque “valid” bit. Consensus-critical
verification belongs in deterministic trusted/shared code, never solely in an
untrusted host callback.

For either backend, benchmark and cap proof/attestation bytes, verifier time,
memory, and batch size inside the consensus-enclave limits. A stale/unknown
measurement or VK, omitted relation, mismatched public range proof, wrong lot,
wrong fee, wrong output class, or change leaving the lot fails closed.

### 5.3 Threshold generation is a research gate

The stock signer API cannot generate either threshold proof. More importantly,
`SigningData::new_with_summary` centrally constructs and returns complete
`pseudo_output_blindings` (`rct_bulletproofs.rs:125-164,430-475`). The external
`SigningData` converter serializes them (`api/src/convert/signing_data.rs:8-49`).
Neither path satisfies the frozen custody rule.

The same boundary begins earlier for every policy output. `MaskedAmountV2`
derives its value mask, token-id mask, and amount-commitment blinding from a
nonlinear amount-shared-secret/HKDF computation
(`transaction/types/src/masked_amount/v2.rs:59-87,239-272`). Applying this KDF
independently to additive Shamir/FROST shares is not a distributed evaluation
of the function and does not yield valid shares of the resulting blinding.
Every authorized policy-output creation path—external capitalization,
predecessor transfer, typed BridgeReturn, and same-lot change—therefore needs a
reviewed distributed-generation or MPC derivation which emits verifiable VSS
commitments and authenticated per-participant shares without reconstructing
the shared secret or final blinding. An output is ineligible until that witness
package exists under the exact historical owner roster.

Ordinary MobileCoin range-proof creation is a second, independent threshold
requirement. The current path chooses complete pseudo-output blindings and
passes complete value/blinding arrays to the Bulletproof prover
(`transaction/core/src/ring_ct/rct_bulletproofs.rs:304-382,878-945` and
`transaction/core/src/range_proofs/mod.rs:36-66`). Those public range-proof
bytes are an input to `D`, so a strict-custody bridge must finish a reviewed
distributed ordinary range-proof ceremony before any participant signs `D`.
The separate reserve-accounting proof does not replace this ordinary RingCT
proof. No coordinator, host, accounting prover outside its declared profile,
or individual owner may reconstruct the complete input, pseudo-output, or
output blinding merely to call the stock prover.

Build a separate durable, DKG-style state machine for:

- historical VSS/MPC witness provisioning, including distributed
  `MaskedAmountV2` derivation for all four authorized policy-output creation
  paths;
- pre-`D` pseudo-output balance selection and distributed ordinary range-proof
  generation with transcript-bound, one-use prover nonce state;
- pre-intent key-image nonce/DLEQ aggregation;
- post-`D` reserve nonce/ownership/z-share rounds; and
- a wholly separate final ordinary-MLSAG signing ceremony.

Split public RingCT material from distributed secret shares; never hand the
existing full `InputSecret`, `SignableInputRing`, or complete pseudo blinding to
a bridge coordinator. The final assembly seam is
`SignatureRctBulletproofs` at `rct_bulletproofs.rs:528-566`, but add a checked
assembly path which accepts aggregate ordinary `RingMLSAG`s and immutable
public commitments/range proofs, then runs the ordinary verifier before
release. Do not put async networking or multi-round state into the synchronous
`RingSigner` trait.

No FROST dependency exists in this checkout. A Zcash FROST library may help
with the separate gate signature or scalar-share mechanics, but it does not by
itself implement MobileCoin's cyclic two-row MLSAG, shared pseudo masks,
distributed Bulletproof preparation, or the required share provisioning.

## 6. WARDEN/ACCOUNT receipts and role manifests

Define **NEW** closed, on-chain role-manifest and receipt types matching the
frozen fields. Every receipt carries role, manifest ID, identity ID, role-key
ID, base `D`, exact role digest, and signature. WARDEN signatures verify only
`M_WARDEN`; ACCOUNT signatures verify only `M_ACCOUNT`; FROST gate signatures
verify only `M_GATE`. Store the ordered approving identity/key slots and
historical bond references in the reservation event so later adjudication does
not reconstruct a roster from current configuration.

`mc_crypto_multisig::{MultiSig, SignerSet}` may supply Ed25519 verification
mechanics (`crypto/multisig/src/lib.rs:23-244`), subject to its ten-signature
limit, but it is not the manifest/receipt protocol. Its verifier sorts and
deduplicates signatures and returns matched public keys; the bridge layer must
still enforce fixed-width slots, exact identity-role-key bindings, no duplicate
identity/key within a role, correct epoch/bond, exact digest, and `2k > n`
including every concurrently valid cross-manifest quorum pair.

Do not reuse mint governors as the role registry. `GovernorsMap` is keyed by
token ID and has different semantics (`consensus/enclave/api/src/governors_map.rs:14-99`).
Role/bond/allocation/valuation manifests are bridge-state objects activated by
committed events, with only their genesis trust anchor/config pinned in
`BlockchainConfig`.

Tests must cover duplicate slots, padding, wrong role/key/epoch/manifest/bond,
cross-role replay even for the same key, overlapping roles requiring fresh
signatures, n > 10 behavior, and the exact WARDEN/ACCOUNT approver set retained
after manifest rotation.

### 6.1 Authenticated fault evidence and MobileCoin containment

The frozen penalty contract places bond freeze, slash, and collateral
distribution on the Ethereum bond registry; MobileCoin must not invent a
remote slash or treat cross-chain state as synchronously atomic. MobileCoin
nevertheless owns the local containment half of accountability. Add three
**NEW** committed bridge actions and reducer transitions:

1. `PAUSE_POLICY_EPOCH` accepts only a finalized, authenticated causal proof of
   the exact Ethereum `FAULT_BOND_FREEZE`/operator-fault record under the pinned
   Ethereum source-finality profile. It records the remote chain/event/block
   reference, incident/verdict, exact historical culprit identities and bond
   references, affected policy/generation/epoch, and proof profile. A warden,
   host, coordinator, RPC response, or local database Boolean is not fault
   evidence. The transition locally rejects new OPEN, RESERVE, and FINAL
   actions under the retired epoch while retaining all live reservations,
   uncleared risk, cancellation rights, and append-only history.
2. `REGISTER_FRESH_GATE_EPOCH` installs fresh owner, FROST-gate, WARDEN, and
   ACCOUNT manifests through the authorized rotation path. Every identity in
   the incident's exact expelled/slashed set is permanently ineligible in
   every bridge role; role overlap, a new role key, or a new manifest cannot
   re-admit it. Historical artifacts continue to verify under their cited
   manifests.
3. `REOPEN_POLICY_EPOCH` is a separate local transition enabled only after the
   pause, fresh threshold-capable manifests, active bond/allocation/valuation
   prerequisites, selected verifier/backend, and all generation activation
   gates pass. It never revives an old-epoch pending final or releases its
   reservation; that artifact must finalize according to its valid historical
   ordering or satisfy exact safe cancellation.

Commit paused epochs, authenticated fault-evidence references, incident-to-
culprit bindings, expelled identities, and fresh manifest history in
`bridge_events` and the bridge state root. The deterministic reducer derives
the culprit set from the immutable verdict plus the stored WARDEN/ACCOUNT
approver slots (or the frozen per-role intersections for equivocation); it
never accepts a caller-supplied extra or omitted culprit. The Ethereum adapter
owns bond debit and the restitution/proof-cost/bounty/insurance waterfall;
MobileCoin owns evidence preservation, local pause, exclusion, and safe reopen.

Tests must reject nonfinal Ethereum evidence, the wrong chain/contract/event,
unsupported verdicts, altered culprit sets, replay to another policy or epoch,
pause after a purported new-epoch final, reuse of an expelled identity in any
role, reopen without every prerequisite, and any attempt to erase or free
pre-pause reservations or uncleared risk.

## 7. Consensus reservation and state-commitment patch

### 7.1 New action family and cache path

`ConsensusValue` currently cannot represent OPEN, RESERVE, CANCEL, manifest,
capitalization, BridgeReturn, finalization, `PAUSE_POLICY_EPOCH`,
`REGISTER_FRESH_GATE_EPOCH`, or `REOPEN_POLICY_EPOCH` events. Add a **NEW**
typed bridge action hash/envelope variant at
`peers/src/consensus_msg.rs:19-32` and update
every exhaustive match in:

- `consensus/service/src/byzantine_ledger/pending_values.rs:69-112,145-157`;
- `consensus/service/src/byzantine_ledger/mod.rs:142-190`; and
- `consensus/service/src/byzantine_ledger/worker.rs:815-873`.

Prefer the existing confidentiality pattern: consensus agrees on the hash of a
well-formed encrypted action held in a manager/cache, and the enclave emits the
redacted committed event. Do not put a coordinator's unvalidated state result
directly into SCP. Generalizing the existing transaction envelope is acceptable
only if ordinary `Tx` wire bytes and hashes remain unambiguous.

Extend the client/peer proposal APIs (`consensus/api/proto/consensus_client.proto:71-83`,
`consensus/service/src/api/client_api_service.rs:122-219`) with typed proposal
and result surfaces. Add per-action count/byte/proof limits. The existing
ordinary-transaction cap is 5,000 transaction hashes per block
(`transaction/types/src/constants.rs:7-8`); mint and mint-config families have
their own limits of ten (`transaction/core/src/mint/constants.rs:7-12`). None
of those limits bounds a new bridge-action family.

### 7.2 Enclave validation and ABI

Extend or add the bridge equivalents of `TxContext`, `WellFormedTxContext`, and
`FormBlockInputs` at `consensus/enclave/api/src/lib.rs:59-227`. Admission must
return only identifiers derived inside trusted validation: action hash,
reservation/liability/source IDs, canonical KIs/tags, lots, event kind,
tombstone, and conflict keys. The host must not supply a trusted “proof valid”
Boolean.

Add serialized call variants/fields in `consensus/enclave/api/src/messages.rs:22-137`,
dispatcher arms in `consensus/enclave/trusted/src/lib.rs:35-80`, untrusted proxy,
mock enclave (`consensus/enclave/mock/src/lib.rs:263-358`), and enclave impl.
At block formation, decrypt and revalidate every action against the parent
bridge state and whole candidate set; evaluate finals only against the parent
snapshot so a same-block reserve can never authorize a final.

The block transition must atomically produce:

- OPEN claim lock and immutable WARDEN/ACCOUNT receipt references;
- live reservation, capacity decision, liability/risk/lot/source-nullifier
  transitions, KI/lease/ring binding, and proof commitments;
- final consumption, output classification/change, liability settlement, and
  uncleared risk; or
- exact safe cancellation/incident transitions; or
- authenticated policy-epoch pause, culprit exclusion/fresh-manifest
  registration, and safe reopen without changing remote bond state.

Any failure produces no partial event or state write.

### 7.3 Committed events and state root

Current block formation discards transaction prefixes and retains only four
vectors (`consensus/enclave/impl/src/lib.rs:881-938`). Therefore reservations,
receipts, proofs, and final/cancel history must be added to `BlockContents`, not
only to an auxiliary host database.

Recommended compatibility-preserving layout:

- **NEW** `bridge_events` on `BlockContents` (tag 5 is currently free); and
- **NEW** mandatory-for-v5 `bridge_state_commitment` (tag 6), containing the
  post-block root and event-chain/checkpoint information.

The tags and state-tree/hash algorithm must be frozen. Every v5 block carries
the commitment even with zero bridge events. `contents_hash` then commits the
events and state root without modifying the `Block` header or historical block
signature representation.

Adding fields to the derived `BlockContents` hash naively changes every old
contents hash. Introduce a version-aware contents-hash path:

- v0-v4 uses the exact current transcript;
- v5 requires the checkpoint and hashes the exact new schema/domain.

Update all current call sites: `blockchain/types/src/block.rs:62-76,126-152`,
`ledger/db/src/ledger_db.rs:735-738`, `light-client/verifier/src/verifier.rs:76-90`,
`api/src/convert/archive_block.rs:62`, `ledger/sync/src/ledger_sync/ledger_sync_service.rs:837`,
and `watcher/src/block_data_store.rs:263`. Preserve historical BlockID and
`BlockSignature` verification with golden archive blocks. Avoid adding a
header field unless there is a reviewed reason; `BlockSignature` currently
digests the entire derived `Block` at
`blockchain/types/src/block_signature.rs:51-56,87-91`, so a naïve header-field
addition would also invalidate old signatures.

The bridge state commitment needs a deterministic authenticated map with
canonical typed keys/values, default hashes, update ordering, and inclusion/
non-inclusion proofs. Freeze these bytes before implementation. The same pure
state reducer should be shared by admission/block formation, LedgerDB replay,
sync, and light-client proof verification. Host storage may cache nodes, but
all honest validators recompute the post-root from the parent root and exact
ordered events.

Safe cancellation can then use a finalized authenticated proof that the exact
reservation remains Live/non-consumed after its committed tombstone and that
every permitted replacement maps to the same exclusive reservation/action
state. A timeout, mempool absence, or local DB miss is not a proof.

### 7.4 Ledger atomicity and replay

Add LMDB stores for committed bridge events by block, authenticated state-tree
nodes/current records, reservations, source-nullifier/liability reverse
indices, capacity lots, leases, permanent KI-ring bindings, role/manifest
history, authenticated Ethereum fault-evidence references, paused policy
epochs, incident/culprit and expelled-identity records, and migration
checkpoints. These are **NEW stores**, not existing APIs.

Open/create them at `ledger/db/src/ledger_db.rs:432-523`, include them in the
`LedgerDB` struct at lines 97-142, and update them inside the one existing RW
transaction at lines 171-204. In `validate_append_block` (`665-809`), before
any write:

- validate v5 contents schema and versioned contents hash;
- replay ordered bridge events from prior committed state;
- recheck all injectivity/conflict rules and prior-block reservation rule;
- compare recomputed post-root/checkpoint with the block; and
- validate every tagged output has exactly one authorized creating event and
  every consumed KI updates the global tag state.

`get_block_contents_impl` at lines 834-873 must reconstruct the exact bridge
event/checkpoint fields. Extend `Ledger` at `ledger_trait.rs:17-143` with the
minimal typed event/state/proof queries needed by consensus, Fog/wallets, and
light clients; keep mutation confined to append/migration.

Blocks containing only bridge events must become valid under v5. Current
checks reject no-output/no-KI blocks except mint configuration
(`ledger_db.rs:710-733`); version-gate the new bridge-event exception without
weakening v0-v4.

Replay gate: delete all derived bridge-state databases, replay committed blocks,
and obtain the identical root and query results at every height. A modified,
reordered, omitted, or duplicated event must fail the block contents hash or
state transition.

## 8. Fees, tombstones, and prior-block semantics

The final MobileCoin execution remains an ordinary fee-bearing RingCT
transaction. Existing checks are `validate_transaction_fee` at
`transaction/core/src/validation/validate.rs:324-331` and `validate_tombstone`
at lines 444-464; maximum lifetime is 20,160 blocks at
`transaction/types/src/constants.rs:19-35`. `D`, the reservation, and accounting
statement must bind exact fee value/token, tombstone, public range-proof bytes,
gross lot depletion, and output classification.

At reservation admission:

- validate the final prefix's fee map/token and tombstone against the current
  v5 rules;
- require enough lead time for one strictly later final block and the selected
  signing protocol (freeze the minimum lead-time constant);
- reject a final when `current_height >= tombstone`; and
- keep the reservation charged until exact finalized cancellation, not merely
  until tombstone.

The separate OPEN/RESERVE action currently has no MobileCoin fee mechanism.
Before activation, freeze either a protocol action fee with conservation rules
or an explicitly bounded/authenticated no-fee policy with strict per-block and
per-manifest quotas. It must not inherit the final transaction's fee as if the
reservation itself paid it.

Final block formation looks only at reservations committed at height less than
the candidate block height. Whole-block combining rejects every conflict
independent of action ordering. Cancelled inputs may be retried only in a later
block and only with the permanent ring binding.

Boundary tests cover tombstone equal to current height, +1, maximum, maximum+1,
reserve at last usable height, final in same block, final one block later,
cancel before finality, expired-but-executed, expired-and-live authenticated
state, and all cancel/final races.

## 9. Enclave and network compatibility consequences

Consensus changes in `consensus/enclave/impl`, any new verifier compiled into
trusted code, config/ECALL layout changes, or bridge block formation require:

- rebuild and sign the consensus enclave;
- publish the new `MRENCLAVE`/`MRSIGNER`/ISVSVN policy and attestation roots;
- update `consensus/enclave/measurement/build.rs:11-88` artifacts and all
  verifier configurations/clients;
- update mock/simulation/hardware enclave tests; and
- coordinate validator deployment before activation.

Adding only immutable runtime data changes `BlockchainConfig` and its responder
digest; adding code changes the enclave measurement. Fog ingest changes for the
new TxOut metadata similarly require a Fog enclave rebuild/measurement update.

Peer consensus serialization changes when a `ConsensusValue` enum variant is
added. Old and new validators are not wire/consensus compatible for v5 values.
The safe rollout is:

1. release software which understands but cannot yet activate v5;
2. freeze MCIP schemas/vectors and complete crypto/security reviews;
3. migrate every ledger at the pinned checkpoint and verify the KI-tag marker;
4. distribute signed enclaves, measurements, manifests, wallets, Fog,
   mobilecoind, archive/sync, watcher, and light-client support;
5. require a readiness quorum and activate at the precommitted height; and
6. treat the first v5 block as irreversible for rollback purposes.

A node missing any verifier, manifest, migration marker, genesis match, or
trusted measurement fails startup/activation. It does not run v5 with bridge
actions ignored.

## 10. Phased patch series and hard gates

The patch series has five distinct lanes. They must not be collapsed into one
"multisig" implementation:

| Lane | Concrete repository scope | Activation responsibility |
|---|---|---|
| Consensus/wire/ledger | `transaction/{types,core}`, `blockchain/types`, `peers`, `consensus/service`, `ledger/{db,migration,sync}`, public protos/converters, archive/watcher/light-client | Defines v5 bytes, hashes, deterministic transition rules, committed events/state, migration, and node compatibility. |
| Trusted enclave | `consensus/enclave/{api,impl,trusted,mock,measurement}` plus any verifier linked into the enclave; Fog ingest enclave for policy metadata | Revalidates proofs and whole-block state against the parent snapshot; requires ABI changes, new signed binaries/measurements, attestation-policy rollout, and SGX resource testing. |
| Wallet/client integration | `transaction/builder`, `mobilecoind`, Fog view/ingest/client, JSON/API surfaces, hardware/display summaries | Constructs only closed bridge forms, selects policy-homogeneous rings, preserves metadata, recomputes/displays the full v5 digest, and keeps ordinary spends away from tagged outputs. |
| Threshold signer/custody | A **NEW**, separate durable DKG-style service/protocol plus checked RingCT assembly; not the current one-shot `RingSigner`/`UnsignedTx` path | Provisions one-time-key and nonlinear MaskedAmountV2 blinding shares, generates the ordinary range proof without reconstructing masks, creates pre-intent KI/DLEQ material, performs post-`D` reserve and final-spend rounds, burns nonces durably, emits blame evidence, and never reconstructs prohibited secrets. |
| Cryptographic research/review | Protocol specifications, reference vectors, security reductions, independent implementations/reviews, ZK circuit or SGX accounting profile | Blocks activation until nonlinear share provisioning, distributed ordinary range-proof generation, the threshold reserve proof, threshold ordinary MLSAG, accounting relation, and exact-nonexecution proof are frozen and independently validated. |

Consensus code can be developed against test-only proof fixtures, but that does
not satisfy the signer or cryptographic-research gates. Conversely, a working
threshold signing demo does not authorize activation without the deterministic
consensus/state/enclave and compatibility work.

### Phase 0 — Protocol/crypto freeze (no activation code)

Freeze the exact Rust/protobuf schemas and tags, canonical encoding, hash
domains, v5 activation schedule, role/manifest limits, state-tree commitment,
safe-cancel proof, authenticated Ethereum-fault evidence and local containment,
per-action fees/limits, nonlinear `MaskedAmountV2` VSS/MPC provisioning,
distributed ordinary range-proof generation, threshold reserve/spend protocols,
gate signature, and exactly one accounting backend.
Publish golden vectors and external cryptographic/security review plans.

**Gate:** every field in the frozen digest DAG has one canonical byte encoding
and one owner/verifier; there is no `TBD`, fallback backend, full-secret
coordinator, or operator truth oracle. Otherwise stop.

### Phase 1 — Compatibility-preserving v5 wire skeleton

Patch BlockVersion/config/genesis plumbing; add dormant transaction/proto/API
fields; implement legacy TxOut/content-hash compatibility and v5 canonical
digest scaffolding; update summaries/converters/JSON/Fog types. Bridge actions
still reject because no active backend/manifests exist.

**Gate:** all v0-v4 transaction, TxOut leaf/Merkle, block contents, BlockID,
block signature, archive, and signing vectors remain identical; v5 round trips
and rejects malformed/ambiguous encodings.

### Phase 2 — Deterministic bridge event/state engine and migration

Implement typed events/manifests/state reducer/state commitment, BlockContents
extensions, LedgerDB stores/atomic append/replay, state proofs, historical KI
tag migration, authenticated fault-evidence references, paused policy epochs,
expelled-identity and fresh-manifest history, and sync/archive/watcher/light-
client support.

**Gate:** clean replay and migrated replay produce identical roots at every
height; crash/restart is idempotent; partial backfill and every state conflict
fail closed; old blocks still verify.

### Phase 3 — Policy-tagged outputs and client selection

Implement consensus closed creation paths, policy ring rules, global lease
updates, builder diagnostics, typed BridgeReturn/capitalization/predecessor/
change flows, policy-pool sampling, ordinary exclusion, Fog/mobilecoind/wallet
propagation, and supply-authority integration.

**Gate:** no caller-labelled tagged output or mixed/legacy ring enters a block;
every accepted tagged output has one committed provenance event and witness
package; fee/mint/ordinary outputs are untagged; policy pool has the required
11-member minimum.

### Phase 4 — vNext signing digest and ordinary final verifier

Finish network-bound digest, summary/hardware display, final bridge prefix and
gate-artifact validation, mutation vectors, and checked RingCT assembly.

**Gate:** independent implementations produce identical `D`; every exact-wire
mutation changes/rejects; old versions are unchanged; final without a matching
prior reservation or with a substituted KI/tag/lot/tombstone fails.

### Phase 5 — Reserve ownership and accounting proofs

Implement the distinct reserve verifier, the selected ZK/SGX accounting
verifier, proof limits, enclave integration, fuzzing, benchmarks, and external
review. Proof generation may initially be a test harness only.

**Gate:** all cross-domain/malformed/omitted-relation tests fail; verifier is
deterministic and within block/enclave budgets; external review has no open
critical/high findings; no untrusted Boolean is consensus-authoritative.

### Phase 6 — Consensus OPEN/RESERVE/FINAL/CANCEL/CONTAINMENT pipeline

Implement encrypted bridge action proposals/cache, SCP value, admission and
whole-block combination, enclave revalidation, prior-block ordering, committed
events, atomic LedgerDB transitions, public result codes, and safe-cancel state
proofs. Add authenticated `PAUSE_POLICY_EPOCH`,
`REGISTER_FRESH_GATE_EPOCH`, and `REOPEN_POLICY_EPOCH` admission, conflict,
replay, and state-transition paths without pretending to mutate Ethereum bond
state.

**Gate:** exhaustive conflict/race tests show one atomic successor or no state
change; same-block reserve/final never passes; restart/sync/replay preserve
receipts, bonds, leases, lots, liabilities, fault evidence, paused epochs,
expelled identities, fresh manifests, and roots.

### Phase 7 — Production threshold custody/signers

Implement VSS/MPC output provisioning and rotation for all four policy-output
creation paths, including reviewed distributed `MaskedAmountV2` nonlinear-KDF
evaluation and verifiable historical-roster witness packages. Implement the
pre-`D` distributed pseudo-output/blinding-balance and ordinary range-proof
ceremony, durable pre-intent KI/DLEQ, post-`D` reserve rounds, independent final
spend rounds, gate FROST, authenticated participant messages, blame/abort
receipts, nonce burn ledger, recovery, and checked aggregate assembly.

**Gate:** fault-injection tests for crash, retry, equivocation, reordered/
duplicated messages, signer loss, bad shares, and roster rotation pass; audit
instrumentation demonstrates no participant/coordinator/host receives complete
`x`, amount shared secret, output blinding, `b_input`, `b_pseudo`, or `z`;
ordinary range-proof bytes verify under the stock verifier; and independent
crypto review approves every custody protocol.

### Phase 8 — Cross-chain system test and activation

Run the real Ethereum escrow/USDC adapter and MobileCoin eUSD policy pool on a
multi-validator v5 testnet, with production-like enclaves and warden/account
roles.

**Gate:** the three user outcomes are proven end to end:

1. finalized USDC deposit -> accountable OPEN/RESERVE -> prior-block threshold
   MobileCoin final -> exact eUSD release;
2. finalized typed eUSD return -> accountable Ethereum reserve/final -> exact
   USDC release; and
3. duplicate/false source, mixed rings, forged reserve/accounting proof,
   substituted final, double reservation, signer abort/retry, and cancel/final
   races cannot release value and leave exact attributable evidence/charged
   risk required by the frozen failure contract; finalized authenticated
   Ethereum fault evidence produces the exact MobileCoin pause, culprit
   exclusion/fresh manifests, and safe reopen without reusing an expelled
   identity or freeing historical risk.

Only after this gate should the activation height be armed.

## 11. Concrete test and benchmark inventory

Add/extend tests at these existing natural homes:

- `transaction/core/tests/validation.rs`: v5 structural, policy-ring,
  fee/tombstone, creation-path, and exact error tests;
- `crypto/ring-signature/src/ring_signature/mlsag.rs` tests plus new reserve
  proof tests/fuzz targets: algebra, cross-domain, malformed points/scalars;
- `transaction/types/src/masked_amount/v2.rs` tests plus independent threshold
  vectors: all four authorized output-creation paths produce the exact stock
  bytes/commitment and verified share package; missing delivery, wrong roster,
  refresh failure, and per-share nonlinear-KDF evaluation remain ineligible;
- `transaction/core/src/ring_ct/rct_bulletproofs.rs` and
  `transaction/core/src/range_proofs/mod.rs`: distributed ordinary range-proof
  vectors, corrupt/missing/share-swap and nonce-reuse failures, stock-verifier
  equivalence, and coordinator/sub-threshold knowledge projections;
- `transaction/extra/tests/verifier.rs:109-149,194-230`: canonical wire sizes,
  summary recomputation, and signer-display fields (current maximum tx is
  asserted as 309,238 bytes at line 131);
- `blockchain/types/tests/digest.rs` and block tests: old/new content hashes,
  IDs, signatures, state checkpoint;
- `ledger/db/src/ledger_db.rs` test module and `ledger/migration`: atomic state,
  replay, migration completeness/crash recovery;
- `consensus/service/src/validators.rs` tests: full same-block conflict matrix,
  authenticated pause/register/reopen ordering, and expelled-identity rejection
  in every role;
- `consensus/enclave/impl/src/lib.rs` tests and
  `consensus/enclave/tests/enclave_api_tests.rs`: trusted revalidation, ECALL
  compatibility, backend/config/genesis failures, deterministic block output;
- `api`/Fog conformance tests and real pre-v5 serialized fixtures;
- `light-client/verifier/src/verifier.rs`: event/root/state proof and legacy
  archive verification; and
- a new multi-node integration harness covering proposal relay, externalize,
  sync, restart, and the complete Ethereum/MobileCoin cycle.

Required property/fuzz tests include:

- canonical encoding injectivity and decode/re-encode behavior;
- every digest-DAG mutation and role/scheme replay;
- reservation/liability/source/lot/tag injectivity;
- state conservation and gross depletion arithmetic at 0/u64 boundaries;
- quorum intersection across concurrently valid manifests;
- state-root determinism under candidate input permutations;
- no same-block ordering makes a forbidden pair valid;
- cancel requires finalized exact nonexecution;
- historical tags never become Free after migration;
- threshold nonce records are monotone and never return to unused;
- no coordinator, participant, or sub-threshold view reconstructs an amount
  shared secret or complete input/pseudo/output blinding during output
  provisioning or ordinary range-proof generation; and
- only exact finalized Ethereum fault evidence pauses the cited MobileCoin
  policy epoch, exact culprits are excluded from every fresh role, and reopen
  neither revives nor frees any old-epoch executable artifact.

Benchmark at minimum:

- ordinary v4 versus ordinary v5 signing/verification regression;
- 1 and 16 inputs, ring size 11, for reserve proof and threshold final spend;
- distributed `MaskedAmountV2` provisioning and distributed ordinary
  range-proof generation for 1 and 16 inputs/outputs, including network,
  communication, durable-round-state, and prover-memory bounds;
- selected accounting verifier worst-case proof/attestation;
- canonical encoding/digest and state-proof verification;
- migration over production-scale historical KI count;
- block formation/replay at maximum ordinary and maximum bridge action counts;
- enclave stack/heap/ECALL payload and latency; and
- Fog encrypted-record/ORAM capacity after metadata expansion.

Freeze hard maximum byte/count/time budgets from those measurements. A proof
which is valid but can exhaust enclave or block resources is a failed design.

## 12. Release blockers and “do not implement this shortcut” list

- Do not claim Serai CLSAG or a Zcash FROST crate is a drop-in replacement for
  MobileCoin MLSAG.
- Do not route threshold bridge inputs through `InputCredentials`,
  `SignableInputRing`, the external `UnsignedTx`, or serialized full
  `SigningData`.
- Do not mark a policy output eligible without its exact historical-roster
  one-time-key and amount-blinding VSS package, and do not apply
  `MaskedAmountV2`'s nonlinear KDF independently to Shamir/FROST shares.
- Do not call the stock ordinary range-proof prover with reconstructed complete
  blindings; use a reviewed distributed protocol whose output passes the stock
  verifier. The reserve-accounting proof is not a substitute for this RingCT
  proof.
- Do not accept a reserve proof in `RingMLSAG::verify`, or an ordinary spend
  proof in the reserve verifier.
- Do not infer output provenance from `spend_policy_id`; validate one closed
  creating event and witness package.
- Do not use the host `chain_id` string instead of the actual genesis BlockID.
- Do not put receipts/reservations only in a warden DB; commit them in block
  contents/state.
- Do not treat tombstone expiry, mempool absence, or local DB absence as exact
  nonexecution.
- Do not add fields to `Digestible` TxOut/TxSummary/BlockContents/Block and
  assume old hashes remain stable.
- Do not trust untrusted state/proof booleans or permit an accounting `NONE`
  backend.
- Do not activate with an incomplete historical KI-tag backfill.
- Do not permit same-block reserve/final or action-order-dependent validity.
- Do not pause or rotate a MobileCoin policy epoch from an unfinalized Ethereum
  assertion, and do not allow an expelled/slashed identity back through a new
  key, role, roster, or manifest.
- Do not ship new trusted validation code without rebuilding/signing enclaves,
  publishing measurements, updating attestation policy, and repeating SGX
  performance/security review.

## 13. Definition of implementation success

The MobileCoin side is implemented only when a v5 block independently proves
and commits all of the following: the exact network-bound destination digest;
policy-homogeneous rings and closed tagged-output provenance; a prior-block
exclusive reservation over public CapacityLots, source nullifier, canonical
KIs/global lease tags, and permanent ring bindings; individually attributable
WARDEN and ACCOUNT receipts; the distinct threshold ownership/equality proof;
verifiable nonlinear `MaskedAmountV2` witness-share provisioning; a distributed
ordinary RingCT range proof made without reconstructing complete blindings; the
selected full accounting proof; a valid ordinary MLSAG aggregate and FROST
gate; atomic final state/output/fee/change; replayable events/state root; and
authenticated fault evidence producing the exact local pause, permanent
culprit exclusion/fresh manifests, and prerequisite-complete safe reopen.

It fails if any one can be omitted, substituted, replayed across network/role/
scheme/input, produced by reconstructing prohibited complete secrets, accepted
from an untrusted Boolean, lost during redaction/restart/sync, or canceled
without finalized exact nonexecution. It also fails if a remote fault assertion
can pause MobileCoin without the pinned finalized proof, if an expelled identity
can re-enter any bridge role, or if reopen revives an old-epoch executable
artifact or frees its charged risk.
