# two-cohort

Two independent cohorts over one composite MobileCoin spend root.

```bash
cargo test --offline -p two-cohort    # 27 tests
```

> **Blocked on a one-line fix in the workspace root manifest.** See
> [Workspace blocker](#workspace-blocker) below. The crate itself builds and
> its tests pass; `cargo` cannot currently load the workspace at all.

```text
b = b_owner + b_gate                  composite spend root
b_owner  shared k-of-n across OWNERS  (own roster, own threshold)
b_gate   shared g-of-m across GATES   (own roster, own threshold)
```

The gate cohort's share enters the one-time key, so it enters the **key
image**. A release attempted without the gates does not produce a rejected
signature — it produces a signature over an image that belongs to no output in
the ring, and consensus itself refuses it. The gate is inside the spend path,
not layered on top of it.

Each cohort is a separate object with its own roster, threshold and Lagrange
weights. Nothing in `Cohort` refers to the other cohort. A design with one
roster and one `t/n` shared between roles cannot express operators-and-gates at
all, because the two cohorts differ in size, in threshold, and in who is behind
them.

## The property that matters

**The key image must be identical across every (owner-subset × gate-subset)
pair.** MobileCoin deduplicates spends on the key image, so an image that
varied with the signing quorum would give one output several images and let it
be spent once per image. Invariance across the full product of qualifying
subsets is the correctness condition for the scheme, not bookkeeping.

## What the tests establish

| test | establishes |
|---|---|
| `cohorts_carry_independent_rosters_and_thresholds` | 2-of-3 owners **and** 1-of-1 gates coexist; each threshold binds only its own roster |
| `composite_root_is_the_sum_of_the_two_cohort_publics` | `D_i = (B_owner + B_gate) + Hs(a‖i)·G`, each half from its own subset |
| **`key_image_is_invariant_across_every_owner_gate_subset_pair`** | **the load-bearing one** — all 9 subset pairs give the *same* image, and each equals upstream `KeyImage::from` |
| `key_image_is_invariant_across_asymmetric_cohorts` | same claim at 3-of-5 × 2-of-4, all 60 pairs — equal-shaped cohorts could hide a dependence on cohort geometry |
| `one_time_key_is_invariant_and_matches_upstream` | differential against upstream `recover_onetime_private_key`; also that `x·G` is the output's target key |
| `an_owner_quorum_without_gates_reaches_a_different_key_image` | the gate contribution is exactly what is missing, checked additively |
| `stock_verifier_accepts_a_two_cohort_signature` | unmodified `RingMLSAG::verify` accepts it, at eUSD token id and ring size 11 |
| `stock_verifier_accepts_every_subset_pair_and_all_agree_on_the_key_image` | 9 signatures, every subset pair, all accepted, all one image |
| `below_threshold_subsets_are_rejected` | sub-threshold subsets cannot contribute, at every entry point |
| `lagrange_weights_match_hand_computed_values` | known-answer: `{1,2}→2,−1`; `{1,2,3}→3,−3,1`; `{1,2,3,4}→4,−6,4,−1`; and Σλ = 1 |
| `unweighted_share_sums_are_subset_dependent_and_weighted_sums_are_not` | the invariance claim is not vacuous — the naive combination *is* subset-dependent |
| `per_participant_terms_sum_to_the_accepted_key_image` | the exposed group terms are the ones the verifier's image is made of, and every term is non-trivial |
| `composite_root_reproduces_mobilecoin_published_subaddress_keys` | known-answer against MobileCoin's own `subaddr_keys_from_acct_priv_keys.jsonl` (10 cases), with `b` arriving as `b_owner + b_gate` |
| `the_subaddress_offset_separates_indices` | the offset really depends on the index |
| 12 tests in `tests/config.rs` | every degenerate configuration is rejected, with the reason demonstrated rather than asserted |

### Known-answer vectors used

* **`vendor/mobilecoin/test-vectors/vectors/account_keys/subaddr_keys_from_acct_priv_keys.jsonl`**
  (rev `05cb699f`) — upstream's own subaddress vectors, consumed by
  `mc-core`'s `subaddr_keys_from_acct_priv_keys` test. `tests/vectors.rs` pins
  this crate's locally-restated `subaddress_offset` against them.
* **Hand-computed Lagrange basis values at 0** for `{1,2}`, `{2,3}`,
  `{1,2,3}`, `{1,2,3,4}` — see the table above.
* **Differentials against upstream code**, which is the nearest thing to a
  vector for the parts MobileCoin publishes no vectors for:
  `mc_crypto_ring_signature::KeyImage::from` and
  `onetime_keys::recover_onetime_private_key`.

### Mutation results

Each of these was injected into `src/` and the suite re-run, with rebuilds
forced (cargo fingerprints on mtime, and a restored tree looks *older* than the
mutated build it replaced — mutations compound silently otherwise). All were
killed; a no-op control survived, so the harness is not simply failing
everything.

| mutation | killed by |
|---|---|
| Lagrange weight always 1 | 9 tests |
| `hash_to_point` domain tag altered | 3 |
| key image taken against `G` instead of `Hp(P)` | 4 |
| `subaddress_offset` ignores the index | 2 |
| gate terms dropped from the key image | 4 |
| participant id 0 accepted | 3 |
| threshold not enforced on a subset | 2 |
| duplicate roster ids accepted | 2 |
| threshold > n accepted | 1 |
| `Debug` prints shares | 1 |
| view-derived term omits the subaddress offset | 5 |
| `ParticipantTerm` weight not zeroized | 1 |

Note that the invariance tests alone do *not* kill the `hash_to_point` domain
tag mutation — a consistently wrong base point is still consistent. It is the
differential against upstream's `KeyImage` that catches it. That is why both
kinds of test are here.

## What this crate does NOT establish

Carried forward from the spike verbatim. None of it got easier because the code
became a library.

* **No live ceremony.** Shares are dealt and combined in one process; `Cohort`
  holds every share. This is the algebra, not a two-round protocol with
  round-one packages, transcripts, or participants that can go offline or lie.
* **No non-reconstruction signing.** `CompositeSpend::onetime` materialises the
  one-time scalar so the stock signer can be driven. The per-participant group
  terms a real signer would combine are exposed (`Cohort::point_terms`,
  `CompositeSpend::key_image_terms`) so such a signer can be written against
  the right shape — but it does not exist here, and a threshold MLSAG needs
  distributed *nonces* as well as distributed keys.
* **Trusted dealer, no DKG.** `CompositeSpend::simulate` generates both
  component secrets itself. No distributed key generation, no
  proof-of-possession, so no rogue-key defence: a cohort able to choose its
  component after seeing the other's public value could steer the sum.
* **No mask-row split.** MLSAG row 1 (the commitment mask) is not split across
  cohorts. Only the spend row and the key image are two-cohort here.
* **No transaction-level acceptance.** The tests drive `RingMLSAG::verify` —
  low-level signature compatibility. Not consensus validation of a whole
  transaction: no range proofs, no fee or balance check, no membership proofs,
  no enclave.
* **Best-effort zeroization.** Secret-bearing types zeroize on drop and redact
  their `Debug`, but `curve25519_dalek::Scalar` is `Copy`, so copies the
  compiler leaves in registers or on the stack are outside this crate's reach.
  `participant_terms_zeroize_their_weight` establishes that the wiring is real;
  it does not establish that dropped memory is scrubbed.

## Workspace blocker

`cargo test --offline -p two-cohort` currently fails before compiling
anything:

```text
error: failed to load manifest for workspace member `crates/two-cohort`
Caused by: failed to parse manifest at `vendor/mobilecoin/crypto/hashes/Cargo.toml`
Caused by: error inheriting `rust-version` from workspace root manifest's
           `workspace.package.rust-version`
Caused by: `workspace.package.rust-version` was not defined
```

Cargo automatically makes any path dependency *residing inside the workspace
directory* a member of that workspace. `vendor/mobilecoin` is a symlink placed
under the workspace root by `scripts/setup.sh`, and cargo does not resolve the
symlink before applying that rule — so the vendored MobileCoin crates are
pulled into this workspace and try to inherit `workspace.package.rust-version`
from the bridge root, which does not define it (MobileCoin's own root does).
This affects every Rust crate in the repo equally, not just this one.

The fix is one line in the root `Cargo.toml`, which this crate does not own:

```toml
[workspace]
members = [...]
exclude = ["vendor"]     # <-- vendored checkouts are not our members
```

Until that lands, the suite can be reproduced with a shadow root that differs
from the real one only by that line:

```bash
SH=$(mktemp -d)
# only two changes to the root manifest: exclude the vendored checkouts, and
# drop the sibling members so this works before they land.
sed 's/^resolver = "2"/resolver = "2"\nexclude = ["vendor"]/' Cargo.toml \
  | grep -Ev '"crates/(ceremony|auditor|mc-return|e2e)"' > "$SH/Cargo.toml"
ln -s "$PWD/vendor" "$SH/vendor"
mkdir -p "$SH/crates" && ln -s "$PWD/crates/two-cohort" "$SH/crates/two-cohort"
(cd "$SH" && cargo test --offline -p two-cohort)
```
