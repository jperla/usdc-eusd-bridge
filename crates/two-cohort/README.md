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

### The ceremony and the artifact

| test | establishes |
|---|---|
| `attribution.rs::one_process_can_produce_an_artifact_that_passes_every_structural_check` | the gap, performed: one process runs both DKGs, satisfies every check about key material, and reconstructs the root scalar it published — then is refused by name under the two organisations' real keys |
| `attribution.rs::the_residual_is_a_party_that_holds_both_organisations_identity_keys` | the exact residual of the attribution check, performed rather than described |
| `attribution.rs::one_organisation_named_for_both_cohorts_is_refused` | `PartiesNotDistinct`; isolated by auditing **one** artifact under two `Parties` values, so only the funder's input differs |
| `attribution.rs::a_holders_proof_is_bound_to_the_counterparty_it_dealt_with` | the two signer keys are inside the pop transcript, not layered beside it |
| **`forgery.rs::a_dealt_owner_cohort_passes_the_audit_and_the_release_gate`** | **the open gap**: a dealt owner cohort, endorsed with the organisation's own real key, reaches a published address that two principals open |
| `forgery.rs` (8 further tests) | endorsement lifted from another ceremony, transposed commitments, transposed reveals, transposed funder keys, an overstated threshold, and a simulated root — each refused by a named error |
| `release_gate.rs::a_simulated_root_reaches_the_funding_path_today` | the gap the gate closes, performed: a simulated root is published at the decided shape and then spent |
| `release_gate.rs::the_gate_refuses_a_key_audited_under_organisations_this_deployment_does_not_name` | a ceremony run by a different pair of organisations differs in nothing else, and is refused on the endorser arm alone |
| `release_gate.rs::the_funder_question_is_answerable_from_the_artifact` + `audit_alone_accepts_a_shape_nobody_decided` | both halves of the funder's sequence, and that the second is load-bearing |
| **`composition.rs::a_dealing_one_seat_can_open_is_refused_even_at_the_declared_degree`** | **declared threshold is minimum coalition size, not only polynomial degree** — the `p(x) = b + a·x(x−1)` dealing that passed before this round |
| `holder_proving.rs` (5 tests) | `CohortShare::prove` is the checked default; `the_raw_prover_signs_what_the_default_entry_point_refuses` separates it from `prove_unchecked` on one share, one composition, one claim |

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

## What a funder can decide, and what it must still take on trust

The audit takes a `CompositionArtifact` and two identity public keys the funder
obtained from the two organisations. A funder that also holds the view private
key `a` runs two calls:

```rust
let address = audit_address(&artifact, &parties, &a, i, &d_i)?;
production::check_decided_structure(address.root())?;
```

**What that answers, at exactly the strength the code supports:**

> Does `D_i` equal `B_owner + B_gate + Hs(a‖i)·G`, where each component opens a
> commitment endorsed under the identity key supplied for its cohort, every
> published verification share carries a proof of possession bound to this
> ceremony, this composition and both endorsers, and the audited canonical
> rosters and exact polynomial degrees are the decided ones?

Plus: the two supplied keys differ; each roster is canonical, non-empty, bounded
and inside its own control domain, so the two are disjoint; no component and no
verification share is the identity; each reveal opens the commitment that was
signed; and no subset smaller than the declared threshold reconstructs a
component. The last of those was **wrong until this round** — the check
enumerated only the `(t−1)`-subsets, which establishes polynomial *degree* and
not minimum *coalition size*. Review supplied `p(x) = b + a·x(x−1)`, a genuine
degree-2 dealing declared 3-of-3 in which seat 1 alone holds `b`;
`a_dealing_one_seat_can_open_is_refused_even_at_the_declared_degree` performs it
and `check_consistency` now enumerates every size below `t`.

**What it does not answer, and none of this is closable by wording:**

* **Who holds the seats.** There is no per-seat identity anywhere in the
  artifact — `Parties` carries one key per *cohort*, while the decided
  structure's argument is per *seat*. So an organisation that runs no DKG, deals
  all three operator shares to itself and endorses the seal with its own real
  key produces an artifact that audits, passes the release gate and reaches a
  published address:
  `tests/forgery.rs::a_dealt_owner_cohort_passes_the_audit_and_the_release_gate`
  performs it, then opens an output paid there with **two** principals against a
  decided `COMPROMISE_THRESHOLD` of **three**. This is the largest open gap.
* **That two keys are two organisations.** A party holding both identity private
  keys signs both halves and the audit passes —
  `attribution.rs::the_residual_is_a_party_that_holds_both_organisations_identity_keys`.
  What changed is the bar, from "somebody says these are two cohorts" to
  "whoever produced this holds the long-term keys of both named organisations",
  which is a question a funder can put to an organisation. Naming *one* key
  twice is now refused outright (`CeremonyError::PartiesNotDistinct`).
* **Chronology.** Signatures have no time in them. The artifact shows that a
  cohort held the other side's commitment when it proved — an ordering between
  two events inside it, not a date. The rule that stops a cohort choosing its
  component after seeing the other's reveal is `prove_possession`'s, enforced
  per share in *this* code, not in the published bytes.
* **The view service.** With `a`, `audit_address` closes it. Without `a`, only
  the *root* is checkable and `D_i` is taken on trust — and this is not a
  formality: an address publisher holding `a` can pick `d`, publish `D = d·G`
  with a matching view component, and open anything sent there with
  `Hs(aR) + d`. An earlier version of the crate docs claimed such a service
  "cannot spend"; review refuted it.
* **Custody since key generation, freshness, and availability.** The artifact is
  a statement about key generation. Nothing in it is dated, and `audit` accepts
  whatever `CeremonyId` the artifact names rather than one the funder expected.
* **Bytes.** "Holding only bytes" is a figure of speech. `audit` takes a typed
  `&CompositionArtifact`; there is no canonical encoding, serialiser or parser
  anywhere in this crate. A funder is trusting somebody's decoder.

`run_dkg`, `Cohort::deal_in` and `CompositeSpend::simulate` are ordinary `pub`
functions, so a single process can still produce an artifact that audits.
`production::authorize_release` now **reads** `Provenance`: it refuses
`Provenance::Simulated`, pins both rosters and thresholds to the decided
structure, and checks the audited endorsers against the organisations the
deployment names. It is the only thing that can issue the `ReleaseAuthorization`
that `deposit_spend_key` takes. That covers a deployment which routes its funding
path through `deposit_spend_key` and publishes its return value — and nothing
else: `CompositeSpend::spend_public`, `simulate`, `AuditedAddress::spend_public`
and `declared_root` + `subaddress_offset` all remain public routes to a fundable
key, and `release_gate.rs`'s own gap test still compiles.

`Pop::prove` is now `pub(crate)`, reachable from outside only as
`Pop::prove_unchecked` behind the default-off `unchecked-proving` feature, and
`CohortShare::prove` is the checked entry point on the type a holder actually
has. That moves the default; it is not a boundary. A holder can recover its own
`s_i` and prove by hand, `Pop::from_parts` is public and `audit` accepts any
proof that verifies, and cargo unifies features across a build graph.

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
  funder can check, and what it still cannot"*, and summarised under **What a
  funder can decide** below.
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

