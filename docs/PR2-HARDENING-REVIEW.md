# PR 2 hardening review

Reviewed PR 2 at `95d6d16c3a0469dc6859b78f34ea062d3e384700`; changes are on
local branch `codex/pr2-hardening`. This is code review, executable testing,
and finite-state model checking, not a certification of absence of bugs.

## Bottom line

No production Ristretto arithmetic defect was found. The current return
verifier derives amount, token ID, and beneficiary from the authenticated
output, closing the earlier relayer-chosen-payout defect. The new tests catch
the particular codec mutations that previously escaped the fixtures.

The bridge is **not ready to fund**. Cross-deployment replay remains possible
when return addresses are reused; artifact audit cannot certify minimum
coalition size; and the live distributed signing/observation/submission and
operational recovery paths have not been demonstrated end to end.

## Findings and fixes

### P1 — deployment domain is not authenticated (remaining)

`contracts/src/MobileCoinVerifier.sol:352` compares a relayer-supplied tag to a
public deployment constant. That tag is not part of the signed TxOut or its
encrypted memo. `contracts/src/Escrow.sol:249` protects only that escrow's
replay mapping.

Reproducer: `contracts/test/acceptance.mjs:544` first uses a return already paid
by one funded escrow. A second escrow uses the same MobileCoin return address
but a different domain. The unchanged proof fails with `WrongMemoDomain`;
changing only the tag pays the same beneficiary the same amount again. A
verifier-level control is also in `contracts/test/verifier.mjs:799`.

This does not let a relayer change the beneficiary or amount within one
correctly configured escrow. It does let duplicate funded deployments pay
twice, including migrations that reuse an address without migrating replay
state. Require distinct return addresses, an authenticated deployment/chain
domain in a versioned memo, or shared/migrated replay state before that
deployment shape is funded. No memo wire-format migration was silently made
in this hardening pass.

### P1 — audited threshold is not proved minimum coalition size (remaining premise)

`crates/two-cohort/src/ceremony.rs:1548` checks reconstruction by smaller
subsets using their usual Lagrange coefficients. That is not a test of every
way a share holder could recover the secret.

`crates/two-cohort/tests/correlated_shares.rs:33` constructs the exact-degree-one
polynomial `p(x) = b*(1+x)`. Every pair reconstructs `b`, but a single owner
also recovers it as `share_i/(1+i)`. Genuine organisation/seat endorsements,
composition audit, and production funding authorization all pass (`:92`).
One owner plus the genuine gate then produces an MLSAG accepted by MobileCoin's
stock verifier (`:100`).

This is not an attack on honest independently randomized DKG, nor a bypass of
the checked holder APIs. It disproves the stronger claim that public artifact
acceptance establishes the advertised minimum coalition. Honest DKG execution,
independent coefficient randomness, absence of retained copies, and actual
principal independence remain premises. Rejecting just this recognizable
polynomial would not establish the general property. Documentation and the
attribution model now say so explicitly.

### P2 — invalid local identity and ambiguous rosters (fixed)

`crates/ceremony/src/machine.rs:44` now rejects zero participant IDs, repeated
IDs, and duplicate identity keys. Repeated IDs previously silently overwrote
the configured key; repeated identity keys made seat attribution ambiguous.

`crates/ceremony/src/machine.rs:348` now checks the local signing identity
against the roster **before nonce allocation**. Previously a one-seat
ceremony could finish even though its identity signatures did not verify
against the configured roster.

Four new regressions are in `crates/ceremony/tests/roster_identity.rs`.
Each individual guard deletion fails precisely its corresponding test;
moving the identity check after nonce allocation also fails. The latter uses
an instrumented real signer and a positive control, not a constant flag.

### P2 — JSON bypasses a numeric constructor invariant (fixed)

`crates/auditor/src/bound.rs:61` now deserializes `ReleaseRate` through its
validated constructor. Previously derived deserialization accepted a zero
window even though `new` rejects it. Auditing that configuration reached
division by zero at `:119` and panicked. Existing JSON shape is preserved;
invalid rates now produce an input error. Regression tests are in
`crates/auditor/tests/rate_json.rs` and the new handoff adapter tests.

### P2 — green test output could hide failure (fixed)

`scripts/acceptance.sh:37` previously piped Cargo output through `grep` and
ended the pipelines with `|| true`. Rust failures therefore did not stop
the command. Once removed, the real archived spike failed: developer-specific
absolute dependency paths and incompatible locked zeroize versions had been
hidden by the runner. Paths now use the pinned vendor checkouts; only
`zeroize` and `zeroize_derive` were downgraded to the compatible versions
already used by the workspace. All nine archived tests actually execute.

`contracts/test/run.mjs:28` now requires a successful child exit and exactly
one nonempty summary. An exception, signal, output error, duplicate summary,
or empty suite cannot turn into success merely by printing a passing count.
`scripts/test-runners.mjs` executes 12 failure/positive controls against the
real entrypoint scripts.

The former JavaScript leg-2 assertion only searched Rust source for test names;
it did not execute the asserted tests. It was removed. Forged-signature and
swapped-output acceptance tests now use fresh funded escrows, require the
specific cryptographic refusal, then successfully retry the honest proof in
that same escrow. They cannot pass merely because an already-redeemed output
triggers the replay guard.

## Ristretto answer

Reviewed `contracts/src/Ristretto255.sol:157` and `:207` against
[RFC 9496 sections 4.3.1–4.3.2](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.1).
The decoder performs all five required checks, not a blacklist of fixture
values: canonical integer range, nonnegative `s`, square ratio, nonnegative
`t`, and nonzero `y`. The encoder follows the specified rotation/sign rules.

The RFC defines a unique encoding for each abstract group element. The
implementation review supports conformance; finite tests are not a formal
proof over the entire group. Different valid Edwards/projective
representatives need not have identical coordinates, but must encode equally.
That distinction is now tested directly, not inferred from decoder round trips.

Added `contracts/test/ristretto-codec.mjs`:

- All 29 official RFC A.2 invalid encodings, including separate negative-s and
  negative-t categories.
- 352 deterministic independent decoder cases from noble, including arbitrary
  bytes, field boundaries, and valid encodings.
- 160 encodings across 10 points, four order-four-torsion representatives and
  four nonzero projective rescalings; curve identities are checked first.
- 36 independent algebra comparisons. The committed oracle regenerates
  byte-for-byte with the locked noble implementation.

The new suite passes 8/8. Disabling rotation, negative-s rejection, or
negative-t rejection independently gives **6 passed, 2 failed** each.
Rotation-free canonical decode/reencode cases still pass, demonstrating why
the representative tests are necessary. Official negative witnesses include
`c34c4e…04562` and `3eb858…79630e`.

No production curve formulas were changed. A test-only coordinate probe and
incorrect comments were corrected: the relevant quotient representatives are
order-four torsion, and identity encoding calls `_sqrtRatio(1,0)`, not `(0,0)`.

## Shared-secret/API design

The current `(recognized, sharedSecret)` boundary is a sensible implementation
of the original proposed shared-work fix. The verifier reuses the same `[a]R`
for amount/token recovery, Pedersen commitment verification, and memo
decryption. It neither repeats scalar multiplication nor trusts a relayer
amount. Keeping these validation stages modular does not require recomputing
the shared secret. Recognition alone, or unmasking without commitment
verification, would still be insufficient.

## Stronger executable proofs

All 14 `scripts/proofs.sh` runners passed with the exact official TLC 2.19 jar
distributed as v1.7.4 (SHA-256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`).
`scripts/setup-proofs.sh` now verifies that checksum. CI is wired to run the
proof suite; this review did not dispatch a GitHub Actions run.

| Model/check | Executed evidence |
|---|---|
| ClaimAcceptance | Clean baseline: 1,348 generated states. Actual failure: witness at 22. Same-key successful retry: 181. Two outputs to one payee: 173. |
| Independent rollback counter-mutation | Corrupt only the rollback assignment with every guard TRUE: state-restoration violation at 22 states. Retry success becomes unreachable over 676 states. |
| PayoutProvenance | Clean baseline: 576 states. Each disabled amount/token/payee derivation breaks exactly its expected invariant set. |
| AttributionCoverage | Baseline: 1,200 states. Correlated shares violate the three-principal guarantee at 121 states; the two-principal bound holds over 1,920 states and is tight. |

The rollback oracle now compares observed pre-call/post-failure state instead
of letting the same switch introduce and announce the bug. Payout choice
independence is separate from within-run replay uniqueness. The model of
attribution no longer claims a joint knowledge proof establishes exclusive
co-location of the two secrets in one person.

Generated TLC/config state is isolated; Java/JAR selection is portable; the
harness reports the final state count rather than an intermediate progress
count. Tool failures are not invariant violations or successful model checks.
These remain finite models with assumptions, not proofs that the Rust/Solidity
implementation refines them. Reachable retry success is not eventual liveness.

## End-to-end boundary and next funding gates

The new `scripts/auditor-handoff.mjs` decodes an actual EVM deposit event,
passes it to the real Rust auditor, distinguishes a matching release from
double/unbacked issuance, submits the exact returned reason to `Escrow.freeze`,
and checks that balances/replay state remain unchanged until governance
unfreezes. This handoff uses a mock token and mock return verifier; the separate
return acceptance test uses the real verifier and synthetic signed MobileCoin
data. Neither test is described as a live bridge.

The real return path measured **10,678,964 execution gas**, or **10,716,220**
including intrinsic calldata cost for this fixture. A 30M transaction-budget
assertion now fails the suite instead of merely printing a warning. This is
not an estimate for every quorum/path or a claim about every Ethereum fork's
limits. The fixture's token ID is 1, not a deployed production eUSD ledger.

Before funding:

1. Choose and enforce the cross-deployment replay strategy above.
2. Run independent honest DKG and verify actual principal/seat control;
   artifact acceptance cannot replace that ceremony.
3. Harden the MLSAG signing service for concurrency and authenticated
   transport. `crates/two-cohort/src/mlsag.rs:199` explicitly lacks the standard
   concurrency defence; `:209` lacks authenticated round transport. This review
   does not claim an executable concurrency forgery, only the missing defence.
4. Implement and exercise crash-safe persistent nonce storage, restart/retry
   handling, and signer authorization over decoded transaction contents rather
   than opaque message bytes.
5. Demonstrate the connected observer → authorized spend → actual MobileCoin
   submission/confirmation → return proof → real USDC payout flow, including
   reorg/finality policy, production token/units, deployment parameter agreement,
   validator enrollment and effective freeze latency.
6. Obtain independent cryptographic and smart-contract review. Passing this
   suite must not be marketed as proving the entire system bug-free.

## Final verification

Executed locally with Node 18.18.1, Rust 1.83.0-nightly
(`nightly-2024-10-11`), locked Solidity dependencies, and the TLC jar above:

| Command | Result |
|---|---|
| `./scripts/setup.sh` | Exit 0; both pinned vendors and both locked Rust dependency caches resolved. |
| `./scripts/test.sh` | Exit 0: 12 runner controls, **376 Rust tests including doctests**, 3 auditor handoff checks, **349 Solidity tests**; no failures or ignored Rust tests. |
| `./scripts/acceptance.sh` | Exit 0: two-cohort and mc-return tests executed, all 9 archived stock-verifier tests passed, 3 handoff checks and 11 EVM acceptance tests passed. |
| `./scripts/setup-proofs.sh` | Exact checksum-pinned official artifact verified; fresh-download and bad-cache controls also checked. |
| `./scripts/proofs.sh` | **14 runners passed, 0 failed**, including harness controls and strengthened mutation matrices. |
| `git diff --check` and shell syntax checks | Clean. |

The 11 acceptance tests are part of the 349 Solidity total; the Rust acceptance
subsets overlap the workspace suite. These numbers must not be added together
as if all commands exercised disjoint cases. The complete acceptance command
passed after its formerly suppressed Rust failure was corrected. A prior setup
retry was interrupted during unnecessary vendor checkout; setup now avoids
rechecking an already-pinned HEAD and the final setup run completed.

The added checks validate their stated component boundaries. No live-chain
deployment, clean-machine Linux Rust build, or GitHub Actions run was performed.
These are the results of the first hardening review. Subsequent implementation
and publication are recorded in git history; the findings above describe this
reviewed snapshot rather than a permanent deployment status.
