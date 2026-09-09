# PR 2: v2 hardening and local integration

This follow-up builds on review commit `5a3e57a`. The earlier hardening review
is a historical snapshot. This implementation improves the prototype; it is
not a production security certificate or a claim that real funds were bridged.
No network endpoints, test funds or independent operators were available.

## Changes

### Authenticated return destination

The v1 relayer-supplied `memoDomainTag` is removed from the proof ABI. A v2
memo (`0x8002`) contains `beneficiary20 || domain32 || reserved12`, with reserved
bytes required to be zero. The domain is

```
keccak256(abi.encode(bytes32("mc-bridge-return-v2"), chainid, escrow, namespace))
```

`escrow` is the calling address at the real verifier boundary. The MobileCoin
output digest authenticates the encrypted memo, the membership proof binds it
to a block, and the validator quorum authenticates that block. Merely supplying
a new proof tag cannot alter the destination. Escrows sharing a return address,
even the same verifier, cannot redeem one another's outputs. Tests also change
the EVM chain ID and confirm refusal before restoring the original chain and
successfully paying the same proof.

The Rust builder creates the memo using MobileCoin's own encryption/TxOut API;
proof construction requires an expected domain and checks it. Isolated opener
controls cover legacy type, wrong domain, both ends of the reserved region,
zero beneficiary and malformed length. Original upstream v1 oracle memos still
exercise raw decryption, but cannot authorize v2 payouts.

This is a breaking wire-format change. Query `redemptionDomain(escrow)` before
creating a return. Already-signed v1 outputs cannot be relayer-migrated. Plan
any deployment migration before funding; preserving a namespace during a
verifier upgrade also requires preserving the existing escrow replay mapping.
Token IDs, unit conversions, return address and enrollment must agree across
the deployment. The local test token is ID 1, not a production token assertion.

### MLSAG nonce binding

Each spend seat publishes hiding and binding nonce commitments on both G and
Hp(P); the mask seat publishes both on G. Independent secret-keyed hash domains
derive the two nonces. A canonical, seat-sorted transcript hashes the complete
session, every share/image/nonce commitment, mask commitments and decoy
responses. Each seat uses `alpha_i + rho_i * beta_i` in its response. The
coordinator checks these effective commitments on both bases; the stock
MobileCoin MLSAG verifier accepts the result.

The design follows the two-commitment binding-factor structure in
[RFC 9591 sections 4.4–4.5](https://www.rfc-editor.org/rfc/rfc9591.html#section-4.4).
This is an adaptation to a custom two-cohort MLSAG protocol, not an RFC 9591
ciphersuite or a concurrent-security theorem. Deterministic nonce derivation,
the two-base composition, authenticated roster policy and independent DKG still
need external cryptographic review. A public artifact cannot establish that
three independent humans are necessary to spend.

Regressions require both commitments in the participant's own transcript,
cover each binding-factor input, check canonical ordering, and demonstrate that
changing a peer's binding commitment changes another participant's effective
nonce. Replacing the actual binding-factor function with constant 1 compiles
but fails the targeted transcript-coverage test; the original source is restored
and the honest protocol suite is rerun afterward.

### Durable binding journal and authenticated packets

`ceremony::store::FileStore` provides an explicit-create/open Unix backend.
An exclusive OS writer lock spans append, fsync and whole-journal read-back.
Records have fixed encoding and a hash chain. The backend refuses missing,
symlinked, corrupt, torn or oversized journals and poisons a live handle after
an uncertain write. The file is created mode 0600 in an existing private
directory; the directory entry is synced on creation. It stores binding state,
not secret nonce material.

`DurableNonceGuard` checks a separately supplied Anchor against the journal
head and sequence, then durably records the full session/seat context before
MLSAG commitments can be emitted. Existing reservations fail across reopen.
A journal cannot detect its own valid snapshot rollback: an independent,
rollback-resistant anchor is mandatory. The simulation uses MemoryAnchor.
Journal/anchor disagreement stops signing. Explicit `FileStore::reconcile`
can acknowledge exactly one durable write beyond the independent anchor, after
replaying and validating storage and checking the exact predecessor hash and
sequence. It never reconstructs an anchor or skips history. A failed recovery
poisons the handle until reopen; an uncertain anchor acknowledgement is safely
retryable after reopen, whether the anchor advanced or stayed unchanged. The backend revalidates the whole log per write and caps it at
128 MiB; high-throughput operation and log maintenance remain future work.

Tests cover a subprocess exiting without Rust destructors, lock release on
exit, exclusive writers, restart conflicts, every single-byte corruption and
partial final frame, missing files, symlinks, live-handle poisoning, duplicate
MLSAG reservations and old snapshots against an independent anchor. These are
process/crash simulations, not physical power-loss tests of storage hardware.

`mlsag::wire` encodes bounded, signed round-one and round-two packets. Decoding
requires a caller-provisioned identity key, expected seat, phase and session or
full transcript context. Exact length and canonical point/scalar encodings are
mandatory. Tests alter every packet byte, vary each expected context, truncate
and append, and authenticate malformed point/scalar bodies with the real key
to exercise validation beyond the signature check. This is a transport codec;
there is no deployed peer service, key-rotation service or automatic blame log.

### Connected local flow

`./scripts/test.sh` and `./scripts/acceptance.sh` build the binaries they invoke
using Cargo's reported executable paths, including custom target directories.
The acceptance run:

1. Executes an ERC20 deposit in real Escrow bytecode and obtains its log.
2. Sends that exact log to a Rust subprocess, which validates the event shape
   and numeric bounds and constructs a structured release intent binding chain,
   escrow, deposit ID, sender, destination, amount, token and return association.
3. Drives both signing rounds with a 2-of-3 owner cohort plus 1 gate, the durable
   journal and identity-signed packets. The intent digest is included in the
   release memo; signers sign the upstream transaction signing digest. Stock
   MLSAG and RCT verification check the signature, fee balance and Bulletproofs.
   Six negative controls alter fee, expiry, recipient, range proof, token and
   memo independently. Repeating the process cannot
   silently recreate its existing journal.
4. Builds deployment-specific synthetic return blocks using MobileCoin's own
   types, then verifies their proof and pays the beneficiary through the real
   Solidity verifier and escrow. Replay, bad signature, wrong membership,
   altered beneficiary layout and deployment mismatches are refused.

This connects components over actual process and EVM boundaries and constructs
a TxPrefix and RCT signature. **It does not demonstrate ledger admission.**
The synthetic funding ring lacks ledger membership proofs; the recipient view
key is an explicit test fixture because the deposit event only supplies a spend
key. The fee (one unit) and tombstone (100) are local fixtures. Independent signer
hosts, production DKG, authenticated full-address discovery, ledger submission/
confirmation and a live Ethereum observer remain unestablished. Shares, return
ledger and token are synthetic. Do not describe this as a live three-leg bridge.

Solidity-only CI reads committed upstream-generated per-domain fixtures. Full
local acceptance regenerates them with a freshly built Rust example; an
explicitly configured missing generator fails. A native Linux CI job is added
to build/run the full integration and check fixture reproducibility. Its remote
result must be observed separately from local success.

## Executable proof scope

`DeploymentReplay.tla` checks intended destination, bound memo version and at
most one payout. Its baseline generates 3,328 states. Six guard-removal matrices
produce exactly the expected invariant failures. A source mutation substitutes
editable relay metadata into the actual domain comparison and violates the
intended-deployment invariant. Successful payment and distinct destination
coverage prevent a reject-everything baseline.

The model assumes authenticated memos, hash collision resistance and persistent
replay state for each chain/escrow. It is independent finite design evidence,
not a refinement proof of the Solidity implementation. The complete proof
command discovers 16 runners, including the earlier rollback, provenance,
threshold counterexamples and failure-propagation controls.

`JournalReconcile.tla` separately enumerates histories of length zero through
three over two abstract records (464 baseline states). It checks exact history
continuation and poisoned-state refusal. Reachability and guard-removal controls
must produce the named counterexamples. Full-history equality makes the model's
sequence check redundant; the implementation checks both sequence and hash.
This model assumes durable, validated storage and does not model hardware faults.

## Verification

Locally verified with the pinned Rust nightly and locked Solidity dependencies:

| Check | Result |
|---|---|
| `./scripts/test.sh` | 395 Rust tests, 350 Solidity tests, 12 runner controls and 3 auditor handoff checks; exit 0 |
| `./scripts/proofs.sh` | 16 runners passed, 0 failed; exit 0 |
| Actual constant-rho source mutation | Compiled; the targeted binding-factor regression failed as expected |
| Restored MLSAG protocol and wire tests | Passed; final additional authenticated-malformed-payload coverage is included in acceptance |

These totals overlap the separate acceptance command; do not add them as
independent tests. The return fixture costs 10,679,423 execution gas and
10,716,299 including intrinsic calldata gas, below the asserted 30M budget.
The final acceptance command and remote CI status are recorded in the PR
update. A Linux workflow being configured is not evidence that it has passed.
The funding gates remain independent DKG/operators, an external anchor and
production recovery integration, independently enforced transaction authorization, live-chain integration,
authenticated enrollment/finality policy, operational freeze drills and
independent cryptographic/smart-contract review.
