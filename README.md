# USDC ↔ eUSD bridge

An experimental bridge between USDC on Ethereum and eUSD on MobileCoin.
**Not ready to hold funds.** Passing component tests and bounded models are
not a production security certificate.

See [the PR 2 hardening review](docs/PR2-HARDENING-REVIEW.md) for the current
findings, executable counterexamples, verification results, and remaining
funding blockers. Older design documents and review transcripts are historical
evidence; their claims and test counts may predate the implementation.

## Security model

Ethereum can verify MobileCoin signatures and output proofs. MobileCoin does
not verify an Ethereum deposit in this design, so the two directions differ:

| Direction | Authorization |
|---|---|
| USDC deposit → eUSD release | Operators attest to Ethereum deposits; two signing cohorts authorize the MobileCoin spend. |
| eUSD return → USDC payout | Ethereum verifies a validator quorum, block header, output membership, recipient, committed amount/token, and encrypted beneficiary. |

The intended access structure is **2-of-3 operators AND 1 independent gate**.
Its three-principal threshold assumes honestly generated independent shares,
secure protocol execution, and genuinely independent control/possession.
Public endorsements do not prove these premises: a correlated 2-of-3 dealing
can pass artifact audit while one owner recovers the operator secret.
There is deliberately no operator-only recovery path.

Governance can replace the Ethereum verifier after a timelock. Validator
enrollment depends on an authenticated, height-scoped mapping from enclave
signing keys to validator entities. The auditor depends on trustworthy feeds
and an effective freeze transaction. These are explicit trust boundaries.

## Implementation

| Component | Current scope |
|---|---|
| `contracts/src/Escrow.sol` | ERC20 custody, caps, permissionless payout, per-escrow replay protection, freeze and governance controls. |
| `MobileCoinVerifier.sol` | Quorum/header/membership checks; recipient recognition; amount/token and beneficiary recovery from the authenticated output. |
| `Ristretto255.sol` | Ristretto decoding, encoding, arithmetic and uniform-byte mapping; independently cross-checked against RFC 9496 and noble/dalek vectors. |
| `crates/two-cohort` | DKG/composition and non-reconstructing MLSAG primitives accepted by MobileCoin's stock verifier. Not a deployed distributed signer. |
| `crates/ceremony` | Signing state machine, contextual nonce binding, authorization hooks and attributable messages. |
| `crates/auditor` | Deposit/release reconciliation, exposure calculation and structured freeze decisions. |
| `crates/mc-return` | Return-proof construction using MobileCoin's own types and verifier. |
| `crates/e2e` | A scoped auditor-to-EVM handoff adapter/test, not a live three-leg bridge. |

`Proof` no longer contains relayer-chosen amount, token ID, or beneficiary.
Recipient checking returns the already computed shared secret; the verifier
reuses it to open the amount, verify its Pedersen commitment, and decrypt the
memo. A second scalar multiplication is unnecessary.

**Replay protection is local to an escrow.** `memoDomainTag` is not authenticated
by the MobileCoin output. Independently funded deployments must use distinct
return addresses, a cryptographically memo-bound deployment domain, or shared
replay state. A passing test explicitly demonstrates duplicate payouts when
two escrows share an address; it is a counterexample, not a safety guarantee.

## Reproduce

Prerequisites: Git, Node 18+, npm, Python 3, a native Rust build toolchain and
the pinned `nightly-2024-10-11` Rust toolchain. The vendored MobileCoin graph
requires that nightly; a newer stable compiler is not an equivalent substitute.
Install it with `rustup toolchain install nightly-2024-10-11` if needed.

```sh
./scripts/setup.sh       # pinned vendor checkouts and both locked Rust caches
./scripts/test.sh        # runner controls, Rust workspace, Solidity EVM suites
./scripts/acceptance.sh  # stock-verifier checks, Rust proof tests, EVM acceptance
```

The test commands use offline, locked Cargo resolution. Setup requires network
access. Solidity dependencies are installed from `contracts/package-lock.json`
by `scripts/node-deps.sh`.

For the proof suite, install Java 21, then:

```sh
./scripts/setup-proofs.sh  # official TLC release, pinned SHA-256
./scripts/proofs.sh        # all 14 discovered proof runners
```

See [proofs/README.md](proofs/README.md) for tool overrides and model scope.
CI runs Solidity, runner failure controls, and the proof runners. The native
Rust build is still locally verified, not claimed to have passed Linux CI.

## What the evidence establishes

The EVM suites execute compiled Solidity bytecode. They include the complete
synthetic return-proof-to-ERC20-payout path, precise failure selectors, retry
after refusal, and a transaction gas budget. Ristretto tests include all 29
official invalid encodings and equivalent internal representatives; disabled
rotation and negative-s/negative-t guards are caught by independent controls.

The TLA+ work establishes selected finite-state properties under explicit
premises. Rollback now has an independent state-restoration invariant, genuine
failure/retry coverage, and a source-level counter-mutation. Payout provenance
separates replay uniqueness from relayer choice. Attribution models explicitly
exhibit the correlated-share threshold failure.

**Not established:** a connected live Ethereum deposit observer → authorized
distributed signing → MobileCoin submission → confirmed return → real USDC
payout. No live ceremony, durable nonce backend, authenticated signer transport,
concurrency-safe production signing service, deployed validator enrollment,
or operational freeze-latency guarantee has been demonstrated here. The
acceptance command runs related component integrations; it does not erase
those boundaries.
