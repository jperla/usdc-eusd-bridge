# USDC ↔ eUSD bridge

An experimental bridge between USDC on Ethereum and eUSD on MobileCoin.
**Not ready to hold funds.** Passing component tests and bounded models are
not a production security certificate.

See [the v2 implementation results](docs/PR2-V2-HARDENING.md) for the latest
changes and remaining deployment gates. See [the PR 2 hardening review](docs/PR2-HARDENING-REVIEW.md) for the current
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
| `contracts/src/Escrow.sol` | ERC20 custody, caps, permissionless payout, authenticated chain/escrow domains and replay protection, freeze and governance controls. |
| `MobileCoinVerifier.sol` | Quorum/header/membership checks; recipient recognition; amount/token and beneficiary recovery from the authenticated output. |
| `Ristretto255.sol` | Ristretto decoding, encoding, arithmetic and uniform-byte mapping; independently cross-checked against RFC 9496 and noble/dalek vectors. |
| `crates/two-cohort` | DKG/composition and non-reconstructing MLSAG primitives accepted by MobileCoin's stock verifier. Not a deployed distributed signer. |
| `crates/ceremony` | Signing state machine, fsynced single-writer binding journal, independent-anchor adapter, authorization hooks and attributable messages. |
| `crates/auditor` | Deposit/release reconciliation, exposure calculation and structured freeze decisions. |
| `crates/mc-return` | Return-proof construction using MobileCoin's own types and verifier. |
| `crates/e2e` | Auditor handoff and connected EVM-deposit → authenticated Rust release-intent signing → synthetic return → EVM payout simulation. |

`Proof` no longer contains relayer-chosen amount, token ID, or beneficiary.
Recipient checking returns the already computed shared secret; the verifier
reuses it to open the amount, verify its Pedersen commitment, and decrypt the
memo. A second scalar multiplication is unnecessary.

**Return memos are deployment-bound.** Version `0x8002` carries
`beneficiary20 || domain32 || reserved12` inside the authenticated encrypted
memo. The sender obtains the domain from `redemptionDomain(escrow)` on the
intended chain before creating the output. The verifier hashes the protocol
version, chain ID, calling escrow, and configured namespace. Legacy `0x8001`
memos are rejected; relayers cannot migrate or retag already-signed returns.
Verifier upgrades retaining a namespace must retain that escrow's replay state.

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
./scripts/proofs.sh        # all 15 discovered proof runners
```

See [proofs/README.md](proofs/README.md) for tool overrides and model scope.
CI is configured for Solidity, runner failure controls, proof runners, and a
native Linux Rust/integration job. Configuration is not a claim that the
remote native job has passed; see the PR checks for its result.

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

**Not established:** a live Ethereum observer, independent cross-host signing,
MobileCoin full-transaction submission/confirmation, or real USDC payout. The
local flow signs a structured release intent derived from an executed deposit;
it does not construct or validate a complete MobileCoin transaction. Test
shares, synthetic ledger blocks, mock ERC20, and an in-memory independent
anchor are explicit simulation boundaries. The journal survives process exit,
but production rollback protection requires an external monotonic anchor.

The MLSAG implementation now uses two nonce commitments with a transcript-bound
factor on both curve bases, following the structure of FROST binding factors.
It remains a custom composition requiring independent cryptographic review;
passing the stock verifier and mutation checks is not a concurrent-security
proof. The packet codec provides authentication only when callers provision
trusted roster keys and require the expected seat, session and round context.
