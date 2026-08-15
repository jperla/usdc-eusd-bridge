# two-cohort

Two independent cohorts over one composite MobileCoin spend root.

```bash
cargo test --offline -p two-cohort
```

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

## Control-domain independence

"Different entities" is the premise, and the algebra cannot check it:
interpolation over `{1,2,3}` is the same arithmetic whichever roster those ids
were meant to name. Deal both cohorts over `{1,2,3}` and every owner subset is
also a qualifying gate subset — `gates.weighted(owner_subset)` succeeds, the
gate argument becomes dead code, and a `CompositeSpend` that never consults it
passes the whole rest of the suite. That is a real regression the spike had
already avoided, and it is worth being blunt about it: with equal rosters, the
key-image invariance tests below cannot tell a live gate cohort from a dead
one.

`src/control.rs` therefore makes cohort identity structural, in two places at
once:

* **In the type.** `Owners` and `Gates` are distinct types, so
  `CohortSpec<Owners>` and `CohortSpec<Gates>` are too. Handing
  `CompositeSpend::simulate` its arguments the wrong way round, or building
  both halves from one domain, does not compile —
  pinned by `compile_fail` doctests on `CohortSpec`.
* **In the ids.** Each domain owns a disjoint million-wide band
  (`Owners` from 1, `Gates` from 1_000_001), enforced at `Cohort::deal_in`. An
  id is an owner id or a gate id, never both, so a subset that reaches the
  wrong cohort through a bare `&[u64]` is refused as `UnknownParticipant`
  rather than silently interpolated into a valid answer.

The id bands are what has teeth. The types stop the mistake a human makes at a
call site; the bands stop the one the algebra would otherwise absorb.

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
| **`no_owner_subset_is_ever_a_gate_quorum_or_the_reverse`** | at 2-of-3 × 2-of-3 — same shape both sides — every owner subset is refused by the gate cohort and vice versa, at `Cohort` and at every `CompositeSpend` entry point |
| `the_two_control_domains_own_disjoint_id_bands` | the bands do not overlap, checked at their endpoints, and 0 is in neither |
| `a_roster_that_strays_out_of_its_own_band_is_refused` | a gate roster holding an owner id is rejected at dealing, and the mirror case |
| `a_roster_wider_than_its_band_is_refused` | the id past the owner band is a gate id, so an over-wide roster is refused rather than allowed to collide |
| `cohort_specs_are_not_interchangeable_at_the_type_level` | the swap and the same-domain pair are compile errors (`compile_fail` doctests); this asserts the right way round still works |
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
| **gate subset ignored** (owner subset passed where the gate subset belongs) | **8**, plus the crate-level doctest |
| view-derived term omits the subaddress offset | 5 |
| `ParticipantTerm` weight not zeroized | 1 |

Note that the invariance tests alone do *not* kill the `hash_to_point` domain
tag mutation — a consistently wrong base point is still consistent. It is the
differential against upstream's `KeyImage` that catches it. That is why both
kinds of test are here.

The "gate subset ignored" row is the one that changed. Against the overlapping
`1..=n` rosters this crate was first promoted with, that mutation killed **3**
tests — and all three died on `UnknownParticipant`, an accident of the two
asymmetric-cohort tests using an owner id (5) that the smaller gate roster
happened not to contain. Every load-bearing test survived: all the key-image
invariance tests, the stock-verifier tests, the owner-quorum-without-gates test
and the crate-level doctest passed with the gate cohort consulted at the wrong
subset. With disjoint bands the same mutation kills 8 tests plus the doctest,
because no owner id is ever a gate id.

## What this crate does NOT establish

Carried forward from the spike verbatim. None of it got easier because the code
became a library.

* **~~No live ceremony.~~ CLOSED** by `src/dkg.rs` and `src/ceremony.rs` — see
  the DKG entry below, which is the same closure stated once.
* **~~No non-reconstruction signing.~~ CLOSED** by `src/mlsag.rs`. It produces
  a `RingMLSAG` the unmodified verifier accepts without any process forming the
  one-time scalar: each participant emits only `alpha_i - c*w_i` and the
  coordinator sums those. `CompositeSpend::onetime` remains because the tests
  need an independently computed `x` to check the key image against, and a
  production signer must still not call it. Nonces are derived and bound to the
  session, but there is no concurrency defence — see the crate docs on the
  ROS/Drijvers setting.
* **~~Trusted dealer, no DKG.~~ CLOSED** by `src/dkg.rs` and
  `src/ceremony.rs`. Each cohort runs Serai's PedPoP independently; the two
  components are composed by a commit-then-reveal ceremony with a cross-cohort
  proof of possession; the output is a `CompositionArtifact` that `audit()`
  checks from the artifact alone. The rogue-key attack is exhibited in
  `tests/rogue_key.rs` and refused in `tests/rogue_key_inverted.rs`.
  `Cohort::deal` and `CompositeSpend::simulate` remain for the tests that need
  a dealing to compare against; a production `CompositeSpend` comes from
  `CompositeSpend::from_ceremony` and reports `Provenance::Ceremony`.

  What is still open is stated exactly in `src/ceremony.rs` under *"What a
  funder can check, and what it still cannot"*. In short: the artifact does not
  prove the commitments preceded the reveals — that half of the defence is
  enforced at the share, by `prove_possession` refusing to answer a second
  sealed composition, so it is a property of holders running this code and not
  of the published bytes. It cannot distinguish a cohort that ran a DKG from one
  that used a dealer and deleted the secret. And it does not make the view
  service accountable for the subaddress offset: a lying view service can freeze
  or misdirect a deposit, though unlike a rogue cohort it cannot spend one.

  `run_dkg` and `CompositeSpend::simulate` are ordinary `pub` functions with no
  feature gate, so a single process can still produce an artifact that audits.
  `Provenance` records which route a spend came by, but nothing in this crate
  reads it; refusing `Provenance::Simulated` is a release path's job.
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

