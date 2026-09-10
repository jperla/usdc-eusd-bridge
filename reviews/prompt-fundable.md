# Does this artifact establish what its documentation says it establishes?

A verification question about a published byte string, the checks run over it,
and whether the prose around those checks is accurate. Please do not read the
pull request; read the files named below and cite `file:line` for each answer.

## Setting

A MobileCoin spend root is composed additively from two components produced by
two separate groups:

    B = B_owner + B_gate

Each group runs its own distributed key generation (Serai PedPoP, vendored).
The two components are then combined by a commit-then-reveal ceremony whose
output is a `CompositionArtifact` — a value intended to be checkable by a third
party who was not present.

The stated intent is that a party holding (i) the artifact, (ii) two long-term
Ed25519 identity public keys obtained from the two organisations, and (iii) the
MobileCoin view private key `a`, can decide YES or NO about a published deposit
address without trusting anyone's report of the ceremony.

The question for you is narrower and is entirely about accuracy: **for each
claim the code and its comments make, does the code establish that claim, and is
the claim stated at the strength the code supports?**

## The files

* `crates/two-cohort/src/ceremony.rs` — the composition and the audit.
  `ComponentClaim` → `ComponentCommitment::seal` → `SignedCommitment::create`
  → `SealedComposition::new` → `Pop::prove_for` / `prove_possession` →
  `ComponentReveal::assemble` → `SealedComposition::open` →
  `CompositionArtifact` → `audit(artifact, parties)` / `audit_address(...)`.
  The module docs carry an explicit two-part list: what `audit` establishes and
  what it does not.
* `crates/two-cohort/src/production.rs` — the decided access structure written
  as constants, and `authorize_release` / `check_decided_structure` /
  `deposit_spend_key`, which are meant to be the difference between a key that
  may be funded and one that may not.
* `crates/two-cohort/src/identity.rs` — the Ed25519 identity primitive.
* `crates/two-cohort/src/dkg.rs` — `CohortKey`, `CohortShare`,
  `CohortShare::prove`, `note_proved`.
* `crates/two-cohort/src/composite.rs` — `CompositeSpend`, `Provenance`,
  `from_ceremony`, `endorsers`.
* Tests: `crates/two-cohort/tests/{attribution,forgery,release_gate,holder_proving,composition,rogue_key_inverted}.rs`
  and `crates/two-cohort/tests/common/mod.rs`.

The whole workspace builds and tests with

    export PATH="$HOME/.rustup/toolchains/nightly-2024-10-11-aarch64-apple-darwin/bin:$PATH"
    cargo test --offline

Currently 298 passed, 0 failed.

## What I would like verified

Please check each against the source rather than against this description.

1. **Is the funder's question stated at the strength the two calls support?**
   `crates/two-cohort/src/production.rs`, the section "What a funder does,
   holding only bytes", now states the answerable question as a claim about
   *endorsers and published shape* rather than about rosters, and lists three
   trust conditions riding along. Read that paragraph against what
   `audit_address` and `check_decided_structure` actually compute. Is the
   restatement now accurate, is anything in it still stronger than the code, and
   is anything the code does establish missing from it?

2. **Is the per-seat gap described correctly, and is the description of why it
   cannot be closed at this layer correct?** `Parties` (`ceremony.rs`) carries
   one `IdentityPublic` per *cohort*. `ComponentClaim` names its seats by
   participant id and verification share only. The module docs of `ceremony.rs`
   ("That either cohort really ran a DKG, or that its seats are more than one
   entity") and of `production.rs` claim that consequently an organisation which
   deals every share to itself and signs with its own real key produces an
   artifact that audits and passes the release gate.
   `tests/forgery.rs::a_dealt_owner_cohort_passes_the_audit_and_the_release_gate`
   is said to perform this. Does that test do what the docs say? Is the stated
   reason — that the layer's finest grain is the cohort and the decided
   structure's argument is per seat — correct, or is there something in the
   present artifact that could distinguish the two cases?

3. **Does `audit` establish each of the seven bullets its module docs list?**
   The list is in `ceremony.rs`'s "What a funder can check". For each bullet,
   is there a check in `audit` / `check_side` / `check_shape` /
   `check_consistency` / `check_pops` that establishes it, and does that check
   establish exactly it rather than something adjacent? The newest bullet is the
   `Parties::check_distinct` refusal; the oldest is the exact-degree condition
   in `check_consistency`.

4. **Is `Provenance::Ceremony` unforgeable from outside the crate, as
   `authorize_release`'s doc asserts?** The asserted chain is:
   `CompositeSpend::from_parts` is private, `provenance:` is written in exactly
   two places, `from_ceremony` takes an `AuditedAddress`, and only
   `audit_address` issues one. Check each link. Separately, `endorsers` is said
   to be set from the *audited structure* rather than from the artifact's own
   claimed signers — verify which value it actually reads.

5. **Is `ReleaseAuthorization` load-bearing in the way `production.rs` claims,
   and is the newly hedged version of that claim right?** The type has private
   fields, no constructor but the gate, and borrows the `CompositeSpend`. The
   module docs previously said "inside this program the release gate is a TYPE —
   a funding path cannot be reached without it"; they now say that holds only of
   a path taking `&ReleaseAuthorization`, and point at
   `tests/release_gate.rs`'s own `todays_funding_path(spend: &CompositeSpend)`
   as a live demonstration that the bypass remains. Is the hedged statement
   correct and complete, or are there further routes to a fundable public key
   that neither version names?

6. **Is the `unchecked-proving` feature gate described accurately?**
   `Pop::prove` is now `pub(crate)`; `Pop::prove_unchecked` is a `#[cfg(feature
   = "unchecked-proving")]` wrapper; `crates/two-cohort/Cargo.toml` dev-depends
   on itself with the feature on so the integration tests can reach it. The doc
   on `prove_unchecked` claims three limits: the share scalar is recoverable
   from public material anyway, the gate does not touch the dealer case, and
   cargo unifies features within a build so the gate is per build-graph. Are all
   three right? Is there a fourth the doc does not name?

7. **Are these tests capable of failing for the reason their names give?**
   * `attribution.rs::the_hand_built_seal_matches_what_an_honest_cohort_publishes`
     — this was previously tautological (both sides of the `==` were the same
     helper on the same inputs) and has been rewritten to build the expected
     value from `ComponentCommitment::seal` + `SignedCommitment::create`
     directly. Is it now non-vacuous, and do its two `assert_ne!` legs test the
     two drifts the doc names?
   * `attribution.rs::one_organisation_named_for_both_cohorts_is_refused` — does
     its second control genuinely isolate the funder's input as the only
     difference?
   * `attribution.rs::one_process_can_produce_an_artifact_that_passes_every_structural_check`
     — is the reconstruction of the root scalar independent of the audit's own
     computation of the root, or do both come from the same source?
   * `holder_proving.rs::the_raw_prover_signs_what_the_default_entry_point_refuses`
     — does it separate the checked and unchecked provers, or could it pass with
     both forwarding to the same function?
   * `release_gate.rs::the_funder_question_is_answerable_from_the_artifact` and
     `audit_alone_accepts_a_shape_nobody_decided` — is the second genuinely
     evidence that the second half of the funder's sequence is load-bearing?
   * `forgery.rs::the_honest_ceremony_reaches_the_same_path_and_the_same_answers`
     — is it a real control for the dealer forgery, or does it share enough
     construction with it that both would move together?

8. **Are there claims in comments stronger than what the code establishes?**
   Three were found and rewritten this round and I would like the rewrites
   checked as much as the originals:
   * `ReleaseRefused::Roster` (`production.rs`) previously argued that comparing
     rosters as an ordered sequence rather than as a set was a defence; the
     comment now says no test can fail without it because
     `ComponentClaim::check_shape` has already refused non-ascending rosters.
     Is that new statement correct?
   * `Parties::expected_for` and `SealedComposition::signed_for` previously said
     "the match is total rather than defaulted"; they now say sealing enforces
     it downstream but a third domain added inside the crate would compile and
     route to the gate branch. Correct?
   * `commitment_signing_payload` says the cohort name in the signed payload is
     defence in depth that no test can fail without, because `absorb_claim`
     already puts the cohort inside the digest. Correct?

   Beyond those three, please name any other comment in `ceremony.rs`,
   `production.rs`, `dkg.rs` or `composite.rs` that asserts more than the code
   supports, and quote the line.

9. **Is `absorb_composition` / `pop_challenge` binding what the comments say?**
   The comments claim (a) the nonce is a function of every input the challenge is
   a function of, so one share never emits one `R` against two challenges; (b)
   both signer *keys* are in the transcript while the signatures are not, and
   the reasoning given for that choice; (c) the encoding is unambiguous under
   length prefixing. Verify all three, and in particular whether any pair of
   distinct compositions collides in the nonce hash but not the challenge hash.

10. **What, precisely, does a holder of the artifact and the two identity public
    keys still have to take on trust?** The module docs of `ceremony.rs` list
    six such items and `production.rs` lists three more. Read both lists against
    the code and tell me whether the union is complete — that is, whether there
    is a trust condition a reader following these documents would not know they
    were accepting.

Where a claim in a comment or doc is stronger than what the code establishes,
please say so and quote the line. Where a test's name promises more than its
body checks, please say which assertion would have to change.
