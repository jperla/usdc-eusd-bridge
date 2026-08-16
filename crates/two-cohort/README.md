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
the ring, and consensus itself refuses it. The gate **cohort** is inside the
spend path, not layered on top of it.

Two different things here are called a gate, and a review reading this sentence
took it for the other one. The claim above is about the gate COHORT's share of
`b` and is a fact about the algebra. The **release gate**,
`production::authorize_release`, is a policy check a caller must remember to ask
for; several public routes to a fundable key do not pass through it, and
`production`'s module docs name them.

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
| **`forgery.rs::a_dealt_owner_cohort_is_refused_at_the_seat_attribution`** | **the inversion**: a dealt owner cohort, endorsed with the organisation's own real key, is now refused at `audit_address` — mounted both ways a dealer WITHOUT seat signatures can (dealer names itself → `SeatUnexpected`; dealer copies the real seat-holders' public keys → `SeatEndorsementInvalid`), with an honest ceremony at the same shape still publishing. A third mounting — collecting genuine signatures — is not refused; see below |
| `seat_identity.rs` (23 tests) | one identity key per seat: sealed by the commitment, welded into every pop transcript, checked under the key the *funder* supplied, and refused when two seats share a key — plus `a_dealer_that_keeps_the_shares_is_refused_at_the_seat_endorsement` (was a passing forgery, now a refusal), `each_half_of_the_linked_endorsement_is_checked_on_its_own` (the **only** test isolating either verification equation), and the two residuals, performed |
| **`seat_forgery.rs` (3 tests)** | **the residual, inverted**: three parties that ran a real DKG and hold real shares are asked to endorse a *substituted* dealing and refuse at `SeatShareNotOwn`; the dealer's own assembly is refused at `SeatEndorsementInvalid`; an honest ceremony at the same shape still reaches its published address — plus the two transposition cases (seat keys within a roster; the deployment's roster against the audit's) that keep the key multiset identical |
| **`seat_challenge_coverage.rs` (2 tests)** | **the guard the whole rework rests on**: each half's commitment must be in the challenge before either response exists. One test forges from a share-holder's position, one from an identity-key holder's, by solving for the commitment after learning the challenge. Each fails under the deletion of its own `h.update` and only its own; before them, deleting either left all 326 tests green |
| **`seat_key_torsion.rs` (6 tests)** | **a seat key must be a key**: replacing the signature with a sigma proof dropped `verify_strict`'s small-order refusal, and a dealer holding every share forged three identity halves over values with no secret behind them and the artifact audited. Now `SeatKeyNotUsable`. Each test asserts the forged equation is *satisfied* before asserting the refusal, so a green test cannot mean the forgery was malformed |
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

The audit takes a `CompositionArtifact` and a `Parties`: two identity public keys
the funder obtained from the two organisations, **and a per-seat roster of
identity public keys for each cohort** — six positions at the decided shape.
This paragraph named only the two organisation keys after the seat rosters
became inputs, and review caught it; the rosters are what makes the attribution
per seat. A funder that also holds the view private key `a` runs two calls:

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

* **That the four named seats are four entities.** `ComponentClaim` now carries
  one identity key per seat, sealed by the commitment and absorbed into every
  proof transcript; `Parties` carries a seat roster; `audit` refuses a seat the
  funder did not name, a seat key that is not the funder's, a seat endorsement
  that does not verify under the funder's key, and any two seats sharing a key
  across the two cohorts. `authorize_release` compares the seat rosters too, so
  `deposit_spend_key` cannot be reached with cohort-level attribution alone.
  What that changed is the **bar**, and the count a later adversarial pass had
  to correct: a forged artifact needed **one** signature nobody honest would
  make, and a dealt-owner forgery at the decided shape now needs **four** — the
  owner organisation's plus one from each of the three operator seats. The gate
  organisation's signature and the gate seat's endorsement are the honest gate's
  own and are not the forger's to collect. A forgery that fabricates *both*
  cohorts collects **six**, every identity signature the artifact carries. This
  paragraph said "five", which is neither.

  It does **not** establish that four keys are four entities, and it does not
  stop a dealer that dealt REAL shares to four real parties while keeping copies.

  **What it now DOES bind, and what it took.** A seat endorsement used to be an
  Ed25519 signature over public bytes: it did not bind the party that signed for
  a seat to a *share* behind it, so a dealer could keep every share, make every
  proof of possession itself, and collect the signatures it needed at no cost to
  the signers. That is closed. `ceremony::endorse_seat` now takes the seat's
  **share** as well as its identity key and produces one AND-composed proof of
  knowledge of `d` (with `Id = d·B`) and `s` (with `V = s·G`) under a single
  challenge over the same transcript the claim was already bound to. Neither
  secret alone yields a verifying endorsement, so a share-less party cannot
  endorse and a share-holding dealer cannot endorse without the named party's
  key. The two tests that performed the passing forgery are now refusals with
  named errors:
  `tests/seat_identity.rs::a_dealer_that_keeps_the_shares_is_refused_at_the_seat_endorsement`
  (`CeremonyError::SeatShareNotOwn` at the holder, `SeatEndorsementInvalid` at
  the audit) and
  `tests/seat_forgery.rs::a_seat_holder_with_a_real_share_cannot_endorse_a_substituted_dealing`,
  where the named parties hold REAL shares of a real DKG and their own key
  material is what refuses the substituted dealing.

  **The two GROUPS are two groups; the two BASES are one number.** Said this way
  because the previous wording — "the two generators are not one generator" —
  leaned on a difference that cannot carry the argument. `Id` is an Ed25519 point
  compressed as an Edwards `y`; `V` is a Ristretto point with its own encoding;
  no point of one is a point of the other. But `RISTRETTO_BASEPOINT_POINT`'s
  representative *is* `ED25519_BASEPOINT_POINT`, so `V`'s representative is `s·B`
  and `Id` is `d·B` over one numeric base. What keeps the two witnesses from
  collapsing is that there are **two responses checked by two equations**, never
  a single `z` against `A + c·(Id + V)` — knowledge of `d + s` alone would
  satisfy that. Sharing the challenge scalar is sound because both groups have
  the same prime order. A **fixed equal-weight** collapse of the two equations is
  unsafe; a batch with **unpredictable random coefficients** is not — an earlier
  version of this line said any batching would break it, which review corrected.
  The rule is: two responses, and no verification equation whose coefficients an
  adversary can predict.
  `seat_identity.rs::an_equal_weight_collapse_of_the_two_equations_is_refused` is
  a tripwire for the unsafe form, labelled as such because no mutation of the
  current `verify` makes it fail — the dangerous shape is not expressible without
  lifting one group into the other.

  **A seat key must be a key, and closing the premise briefly cost that.** The
  Ed25519 signature this replaced went through `verify_strict`, which refuses a
  small-order signer outright. The sigma proof did not, and its comment argued no
  subgroup check was needed — which is false, because `A` is the *prover's*
  choice. A pure-torsion `Id`, behind which no secret exists, admits a verifying
  identity half found by grinding about 8 challenges, so a dealer holding every
  share could fill three seats with values that are not keys and the artifact
  audited. **The first fix was also incomplete**, and adversarial review caught
  it: a subgroup check passes the *identity element*, which is in the subgroup
  and whose `d = 0` is public — its identity half verifies for every challenge
  with no grinding at all. Both are now refused by `ComponentClaim::check_shape`
  as `CeremonyError::SeatKeyNotUsable`, with the cause named, and by
  `IdentityPublic::edwards` on the public verify path.
  `tests/seat_key_torsion.rs` performs both forgeries, asserts the forged equation
  is satisfied before asserting the refusal, and builds complete artifacts so that
  removing the guard makes `audit` return `Ok` — verified by removing both guards
  in a throwaway clone. This is the exact twin of
  `CeremonyError::IdentityVerificationShare`, which had been refusing `V = 0` on
  the share side all along.

  A related scope note raised in review and closed by enumeration rather than by
  argument: Dalek accepts some non-canonical Edwards encodings and neither `Id`
  nor `A` is recompressed. For `Id` the whole non-canonical space is 19 values,
  every curve point among them is the identity or torsion-bearing, and
  `every_non_canonical_seat_key_encoding_is_refused` walks all 19. For `A` the
  challenge absorbs its raw bytes, so a re-encoding is a different transcript.
  `IdentityPublic::unusable_reason` is public so an independent implementation —
  or a deployment collecting seat keys — can apply the same rule.

  **Stated in the form a cryptographer would accept**, because "an act used both
  secrets" is intuition rather than what a proof of knowledge delivers, and
  adversarial review asked for the exact version:

  > Assuming discrete logarithms are hard and the domain-separated BLAKE2b
  > challenge is modelled as a random oracle, a `SeatEndorsement` accepted
  > through `audit` is an *argument of knowledge* for `Id = d·B ∧ V_i = s·G`,
  > where `Id` is the key the **checker** supplied for that seat and `V_i` is the
  > claim's non-identity verification share for it. An efficient producer that
  > succeeds with non-negligible probability admits extraction of both scalars.

  **What it still does not say**, stated because the last four versions of this
  paragraph each overclaimed something:

  * not that ONE actor holds both secrets. Two parties, one with the identity
    key and one with the share, can run the sigma protocol between them. What is
    gone is the *offline, free* endorsement a party with no share could hand over;
  * not that the named party is the share's ONLY holder. Possession is copyable,
    and no proof of possession is a proof of exclusive possession. A dealer that
    dealt real shares to the four named parties and kept copies produces an
    artifact whose every endorsement is genuine and it audits —
    `tests/seat_identity.rs::a_dealer_that_dealt_real_shares_and_kept_copies_still_passes`
    performs it, and it is named so that a reader who has just seen two forgeries
    inverted does not assume this one went with them. The remedy for it is the
    DKG, where no dealer ever holds a share, and whether a cohort ran one is not
    visible in the published bytes;
  * not that four keys are four entities, which no artifact can carry;
  * not that the two witnesses are independent or distinct. A statement
    deliberately built with `s = d` is opened by one scalar. That is not a
    collapse of the protocol, but it is not excluded by it;
  * not present possession, and not which of several collaborating parties
    supplied which scalar.

  Two scope notes that belong with it. The nonce derivation is deterministic and
  safe **for this crate's prover only** — `SeatEndorsement::from_parts` and the
  public challenge helper let an outside implementation build an endorsement any
  way it likes, and one that reuses a nonce gives up its witness as in any
  Schnorr scheme. And the two-party mounting above cannot simply reuse this
  key-derivation function: each nonce absorbs *both* secrets, so two separated
  holders would have to derive independently, and a holder that derives
  deterministically from only its own secret can be made to answer two challenges
  on one commitment by a malicious peer. A real two-holder deployment needs fresh
  one-use nonces with response state, or a distributed Schnorr protocol.

  A deployment cost that comes with it: there are no longer any *bytes* a seat
  can sign to endorse, so a long-term key held in an HSM must be able to answer a
  Schnorr challenge over `B` rather than sign a message.
* **That two keys are two organisations.** A party holding both identity private
  keys signs both halves and the audit passes —
  `attribution.rs::the_residual_is_a_party_that_holds_both_organisations_identity_keys`.
  What changed is the bar, from "somebody says these are two cohorts" to "a
  signature verifying under each named organisation's long-term key exists over
  this composition", which is a question a funder can put to an organisation.
  Not "whoever produced this holds the long-term keys", which this said: a
  producer that collected two signatures, or used a signing service, holds
  neither. Naming *one* key twice is now refused outright
  (`CeremonyError::PartiesNotDistinct`).
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

