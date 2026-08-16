--------------------- MODULE AttributionCoverage ---------------------------
(***************************************************************************)
(* What an artifact ATTRIBUTES, and whether that is enough to support the   *)
(* guarantee the decided structure claims.                                  *)
(*                                                                          *)
(* WHY THIS MODEL EXISTS, AND WHY IT IS WRITTEN FIRST. `audit` is told ONE  *)
(* identity key per COHORT, while the security argument is per SEAT.        *)
(* `crates/two-cohort/tests/forgery.rs::                                    *)
(* a_dealt_owner_cohort_passes_the_audit_and_the_release_gate` performs the  *)
(* consequence end to end: an operator organisation that runs no DKG, deals  *)
(* all three operator shares to itself and endorses the commitment with its  *)
(* own genuine key produces an artifact that audits, passes                  *)
(* `authorize_release`, reaches `deposit_spend_key`, and is then opened by    *)
(* TWO principals against a decided COMPROMISE_THRESHOLD of THREE.           *)
(*                                                                          *)
(* This file states the criterion the per-seat rework is to be measured      *)
(* against BEFORE that rework exists, because the alternative has already    *)
(* failed here once: `ClaimAcceptance.tla` scoped itself out of a question,  *)
(* said so honestly in its header, and the implementation then walked across *)
(* the boundary it had named. `PayoutProvenance.tla` is the model written    *)
(* afterwards to discharge that. This one is written before.                 *)
(*                                                                          *)
(* THE TWO LEVELS, WHICH ARE NOT THE SAME AND MUST NOT BE CONFLATED.        *)
(*                                                                          *)
(*   THE BAR      -- how many separate ATTRIBUTION SLOTS the artifact makes  *)
(*                   a funder fill before it will fund. The funder can count *)
(*                   this. It is `INV_AttributedKeysMeetThreshold`. It does  *)
(*                   NOT say the slots hold distinct key values, nor that    *)
(*                   the parties behind them are distinct entities.          *)
(*                                                                          *)
(*   THE GUARANTEE -- that no coalition of fewer than `CompromiseT`          *)
(*                   PRINCIPALS can open an output paid to the published     *)
(*                   address. Nobody can count this; it is a fact about the  *)
(*                   world. It is `INV_SpendNeedsThresholdPrincipals`.       *)
(*                                                                          *)
(* Per-seat attribution raises the bar from 2 slots to 4. It does NOT by     *)
(* itself deliver the guarantee, and this model is built so that the         *)
(* difference is visible rather than argued: the bar invariant is blind to   *)
(* all THREE residual switches below, and the guarantee invariant is not.    *)
(*                                                                          *)
(* WHAT IS MODELLED. Seats are held by principals. The artifact cannot see   *)
(* that mapping -- it never could, it is not in any byte -- so the mapping   *)
(* is chosen nondeterministically at Init and the model asks what the        *)
(* artifact's attribution CONSTRAINS about it. Cryptography is not modelled: *)
(* whether a Schnorr transcript really binds a seat key is a Rust and vector *)
(* question and lives in `crates/two-cohort`. What is modelled is coverage:  *)
(* given that every check passes, how few principals can still spend?        *)
(*                                                                          *)
(* WHAT THIS MODEL DOES NOT ESTABLISH. Per-seat keys do NOT establish that   *)
(* four keys are four entities, for the same reason two cohort keys do not   *)
(* establish two organisations. They do not stop a dealer that distributed   *)
(* shares to four real parties while keeping copies. Those two remain.       *)
(* The third -- added after an adversarial review showed the first version   *)
(* of this file assumed it away without saying so -- was that they did not   *)
(* bind the party that ENDORSED a seat to the share behind it; that one has  *)
(* since been built and is no longer a residual. All three are switches      *)
(* here: `MaxKeysPerPrincipal`, `NoRetainedCopies`, `EndorserHoldsShare`.    *)
(* Turning any of them off breaks the guarantee.                            *)
(*                                                                          *)
(* THE THREE ARE NOT THE SAME KIND OF THING, and the runner says which is    *)
(* which. The first two are facts about the world that no artifact could     *)
(* carry. The THIRD is a property of THIS implementation, it WAS false, and  *)
(* it has since been built: `ceremony::endorse_seat` now takes the identity  *)
(* key AND the share, and produces an AND-composed proof of knowledge of     *)
(* both under one challenge, so neither secret alone yields a verifying      *)
(* endorsement. The two Rust counterexamples were inverted rather than       *)
(* deleted -- `seat_forgery.rs::a_seat_holder_with_a_real_share_cannot_      *)
(* endorse_a_substituted_dealing` and `seat_identity.rs::a_dealer_that_      *)
(* keeps_the_shares_is_refused_at_the_seat_endorsement`. The FALSE row is    *)
(* kept because it PRICES the fix. It does not price the residual next to    *)
(* it: a dealer that dealt REAL shares and kept copies still passes, which   *)
(* is `NoRetainedCopies` and is not buildable by anyone. (Historic: it was   *)
(* an Ed25519 signature over public bytes, an earlier version of the runner  *)
(* said both of its assumptions were "not buildable by any implementation",  *)
(* which was true of the two it listed and hid the one it did not.)          *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    OwnerSeats,     \* the operator cohort's seats
    GateSeats,      \* the gate cohort's seats
    Principals,     \* the real-world entities. NOT visible to the artifact.
    CohortKeys,     \* the per-cohort key names, used when attribution is per cohort
    NoOne,          \* the "no dealer retained a copy" marker; not a principal

    OwnerT,         \* operator quorum size            (production: OWNER_THRESHOLD = 2)
    GateT,          \* gate quorum size                (production: GATE_THRESHOLD  = 1)
    CompromiseT,    \* principals the claim says are needed
                    \* (production: COMPROMISE_THRESHOLD = OWNER_T + GATE_T = 3)

    (* THE FOUR SWITCHES -- three booleans and one graded. Each is
       mutation-tested by run_attribution_coverage.py: moving one away from the
       baseline must break exactly the properties it is named against, in BOTH
       directions, so a switch that is not load-bearing and a switch that is
       load-bearing for something it does not claim both fail the runner.

       They are three different kinds of thing and the runner labels each one:
       a design choice this repo has now made (`AttributionPerSeat`); two
       assumptions about the world that no design can discharge
       (`MaxKeysPerPrincipal`, `NoRetainedCopies`); and one property of this
       implementation that was buildable, had a Rust counterexample, and has
       now been BUILT (`EndorserHoldsShare`). The FALSE row is kept because it
       prices the fix, not because it describes the tree. *)

    AttributionPerSeat,
        \*  TRUE: the artifact pins one identity key per SEAT, sealed by the
        \*        commitment and bound into every proof transcript. The funder
        \*        obtains one key from each of four named parties.
        \* FALSE: the design BEFORE this rework -- and the words "today" stood
        \*        here until the rework landed. One key per COHORT. The seats
        \*        behind it are whatever
        \*        the endorsing organisation says they are, and the artifact
        \*        carries nothing that could distinguish three organisations
        \*        from one organisation wearing three ids.

    MaxKeysPerPrincipal,
        \* Residual 1, GRADED rather than boolean -- and the grading is what
        \* makes the guarantee below testable at all. The most keys any one
        \* principal may hold. 1 assumes the keys the funder collected from N
        \* named parties are held by N DIFFERENT principals; N assumes nothing;
        \* 2 is one shared controller behind two names -- or one organisation
        \* that lent its seat key. Unfalsifiable from bytes at any setting.
        \*
        \* WHY GRADED, and it is not a refinement -- it repairs a hole an
        \* adversarial review opened in the first version of this file. With
        \* this as a BOOLEAN, the smallest spending coalition was a function of
        \* the switches alone, so the whole mutation matrix was equally well
        \* satisfied by an invariant that never reads the coalition:
        \*
        \*     spend.seats # {} => AttributionPerSeat /\ NoRetainedCopies
        \*                         /\ CompromiseT <= OwnerT + GateT
        \*
        \* That passed baseline, every mutation, and every sensitivity check --
        \* the same guard both causing and detecting the bug, which is a shape
        \* this repo has shipped before. At 2, every boolean is ON and the
        \* arithmetic is untouched, yet the coalition falls to two. A guarantee
        \* written over the constants cannot break there and the real one does,
        \* so the runner's ORACLE section can tell them apart.

    NoRetainedCopies,
        \* Residual 2. TRUE assumes each seat's share is held only by the party
        \* the artifact attributes it to. FALSE lets a dealer that handed shares
        \* to real, distinct parties keep copies of them. A dealt cohort and a
        \* DKG'd one produce the same published material -- forgery.rs notes
        \* that gating `Pop::prove_unchecked` costs a dealer a feature flag and
        \* nothing more -- so this is not observable either.

    EndorserHoldsShare
        \* Was residual 3, and the one this file's first version ASSUMED
        \* WITHOUT SAYING SO. TRUE: the party whose endorsement fills seat s's
        \* attribution slot used s's share to make it. FALSE decouples them:
        \* the slot is filled, by the right key, and says nothing about who
        \* holds the share.
        \*
        \* TRUE is now ENFORCED rather than assumed -- the endorsement is an
        \* AND-composed proof of knowledge of the identity secret and of the
        \* share, under one challenge -- so the FALSE branch prices the fix
        \* rather than describing the tree. Read TRUE narrowly: it says the
        \* share was USED, not that one actor held both secrets, and not that
        \* the named party is its only holder. The second of those is
        \* `NoRetainedCopies`, still FALSE-able and still not buildable.
        \*
        \* WHY IT IS SEPARATE FROM THE OTHER TWO, in both directions. It is not
        \* covered by `MaxKeysPerPrincipal`, which is about how many keys one
        \* principal holds -- here the four key-holders can be four distinct
        \* principals and the equation still fails. It is not covered by
        \* `NoRetainedCopies`, which lets a dealer keep a copy of a share the
        \* named party DOES hold -- here the named party may hold no share of
        \* the published dealing at all. And unlike both it is a fact about
        \* code, not about the world, which is why it could be and was fixed:
        \* `ceremony::endorse_seat` now takes the identity key AND the share
        \* and proves knowledge of both under one challenge.
        \* `seat_forgery.rs::a_seat_holder_with_a_real_share_cannot_endorse_a_
        \* substituted_dealing` is the former counterexample, inverted: the
        \* real share-holders' own key material now refuses the substituted
        \* dealing, by exact error, and the dealer's own assembly of the
        \* artifact is refused at the audit.

Seats == OwnerSeats \cup GateSeats

(* What the funder is handed, and therefore what it can check. This IS the
   change the rework buys, stated as a count: two, or four. *)
AttributedKeys == IF AttributionPerSeat THEN Seats ELSE CohortKeys

ASSUME OwnerSeats \cap GateSeats = {}
ASSUME NoOne \notin Principals
ASSUME Cardinality(OwnerSeats) >= OwnerT /\ Cardinality(GateSeats) >= GateT
ASSUME MaxKeysPerPrincipal >= 1
\* Without enough principals to go round, Init would be empty and TLC would
\* report no initial states -- which the runner would see as an ERROR with a
\* misleading cause. Fail here instead, where the reason is written down.
ASSUME Cardinality(Principals) * MaxKeysPerPrincipal >= Cardinality(AttributedKeys)

\* How many of the attributed keys resolve to principal `p`. The funder cannot
\* compute this -- that is the whole point of it being the residual -- but the
\* model can, and `MaxKeysPerPrincipal` bounds it.
KeysHeldBy(f, p) == Cardinality({k \in DOMAIN f : f[k] = p})

VARIABLES
    seatHolder,   \* Seats -> Principals. THE HIDDEN TRUTH: who holds each share.
    nameHolder,   \* AttributedKeys -> Principals. Who really holds each key the
                  \* funder collected from a named party.
    retainer,     \* per cohort: a dealer that kept copies, or NoOne
    spend         \* the coalition that opened an output, once one has

vars == <<seatHolder, nameHolder, retainer, spend>>

NoSpend == [seats |-> {}, by |-> {}]

NameHolders ==
    { f \in [AttributedKeys -> Principals] :
        \A p \in Principals : KeysHeldBy(f, p) <= MaxKeysPerPrincipal }

(* THE HINGE OF THE WHOLE MODEL.

   With attribution per SEAT, seat s's own key is sealed by the commitment and
   named in s's proof transcript, and the funder got s's key from named party s.
   IF the party that signs for s is also the party that holds s's share, the seat
   map is PINNED to the key map. That "if" is `EndorserHoldsShare` and it is a
   real conjunct, not a restatement: this file's first version wrote the pinning
   as a consequence of per-seat attribution alone, which an adversarial review
   correctly refused. Two mechanisms have to line up and only one of them is
   built. The FALSE branch is the same free seat map as per-cohort attribution,
   reached with all four attribution slots filled and resolving to four
   DISTINCT principals -- slots and holders, not key values, which this model
   does not carry -- which is
   why the bar column stays clean in that row while the guarantee falls.

   With attribution per COHORT, the endorsement says only that the organisation
   signed the seal. It says nothing whatever about who holds the seats, so the
   seat map is free. That freedom is the forgery: `forgery.rs` puts all three
   operator seats on the endorsing organisation itself, and every check passes.

   Note what is NOT written here: nothing makes the pinned map injective. The
   distinctness comes from `NameHolders`, i.e. from `MaxKeysPerPrincipal`, i.e.
   from the assumption -- never from the attribution. Keeping those two apart is
   the point of the file, and the graded knob is what stops them being welded
   back together: at `MaxKeysPerPrincipal = 2` the seat map is still pinned and
   the separation is gone anyway.

   HONESTLY, ABOUT WHAT THIS DEFINITION IS. This is a DEFINITION of what
   per-seat attribution means, not a result derived from one, and it diverges
   from `PayoutProvenance.tla`'s convention on purpose: there the hidden truth is
   drawn independently of the switches and the behaviour is compared against it,
   whereas here the switch says what the artifact CONSTRAINS about the hidden
   truth, because that is the question -- how much of the world does an
   attribution pin down. So the baseline's cleanliness is a consequence of this
   definition plus the two assumptions, and is evidence about the STRUCTURE of
   the argument. It is not evidence that any implementation achieves the
   binding; that is a Rust and test-vector question in crates/two-cohort -- and
   `EndorserHoldsShare` is the part of that question this repo has ANSWERED --
   in the AFFIRMATIVE as of the linked endorsement, with tests that fail without
   it. This sentence said "in the negative" while the row above already said the
   opposite; an adversarial review caught the contradiction. *)
SeatHolders(nh) ==
    IF AttributionPerSeat /\ EndorserHoldsShare
      THEN {[s \in Seats |-> nh[s]]}
      ELSE [Seats -> Principals]

Retainers ==
    IF NoRetainedCopies
      THEN {[owners |-> NoOne, gates |-> NoOne]}
      ELSE [owners: Principals \cup {NoOne}, gates: Principals \cup {NoOne}]

TypeOK ==
    /\ nameHolder \in [AttributedKeys -> Principals]
    /\ seatHolder \in [Seats -> Principals]
    /\ retainer \in [owners: Principals \cup {NoOne}, gates: Principals \cup {NoOne}]
    /\ spend \in [seats: SUBSET Seats, by: SUBSET Principals]

Init ==
    /\ nameHolder \in NameHolders
    /\ seatHolder \in SeatHolders(nameHolder)
    /\ retainer \in Retainers
    /\ spend = NoSpend

RetainerFor(s) == IF s \in OwnerSeats THEN retainer.owners ELSE retainer.gates

(* Everyone who can supply seat s's share: the party it is attributed to, plus
   the dealer that kept a copy, if there was one. *)
Holders(s) ==
    {seatHolder[s]} \cup (IF RetainerFor(s) = NoOne THEN {} ELSE {RetainerFor(s)})

(* The access structure the decided shape really has: a quorum of each cohort.
   Supersets are included, so the model does not quietly test only the minimum
   -- but the minimum is in here too, and a lower bound on coalition size is
   what the invariant asserts, so TLC will find the small ones. *)
Quorums ==
    { os \cup gs :
        os \in {x \in SUBSET OwnerSeats : Cardinality(x) >= OwnerT},
        gs \in {y \in SUBSET GateSeats  : Cardinality(y) >= GateT} }

(* A coalition of principals opens an output. It must cover every seat it uses
   -- some member holds that seat's share -- and every member must be pulling
   its weight, so that a padded coalition cannot make the count look healthy.
   That second conjunct is a pruning condition, not a security assumption: an
   adversary trying to violate a LOWER bound on its own size gains nothing by
   adding members. *)
Spend ==
    /\ spend = NoSpend
    /\ \E q \in Quorums :
         \E c \in SUBSET Principals :
           /\ \A s \in q : Holders(s) \cap c # {}
           /\ \A p \in c : \E s \in q : p \in Holders(s)
           /\ spend' = [seats |-> q, by |-> c]
    /\ UNCHANGED <<seatHolder, nameHolder, retainer>>

Next == Spend \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

(*----------------------------- THE GUARANTEE -----------------------------*)

(* What the decided structure claims: four entities, three of which must be
   compromised before funds can move. Stated over PRINCIPALS, because that is
   what "compromised" counts.

   This is state-dependent: it measures a coalition that actually opened an
   output. It would be an overclaim to say it therefore "cannot hold by
   construction" -- an earlier draft said exactly that and an adversarial review
   was right to strike it. Its truth in the baseline follows from `SeatHolders`'
   definition plus the two assumptions, all three of which are written down
   above; what the runner establishes is that it depends on each of them, and
   the ORACLE section is what establishes that it depends on the COALITION as
   well and not merely on the constants.

   It is also tight rather than slack, and it is measuring the access structure
   rather than a constant. `COV_TightCoalition` below requires a reachable
   coalition of EXACTLY CompromiseT. The runner then moves the numbers in both
   directions with every assumption still on: raising CompromiseT to 4 breaks
   this, and dropping the operator quorum to 1-of-3 breaks it too, at four
   genuinely distinct principals. So the separation this asserts is OwnerT +
   GateT and not the digit in the config -- and attribution is no substitute for
   the release gate's threshold arm, which is the model's counterpart of
   forgery.rs::a_decided_roster_at_an_undecided_threshold_is_refused_on_both_paths. *)
INV_SpendNeedsThresholdPrincipals ==
    spend.seats # {} => Cardinality(spend.by) >= CompromiseT

(*-------------------------------- THE BAR --------------------------------*)

(* The check a funder can actually perform, holding only bytes and a phone: how
   many ATTRIBUTION SLOTS does the artifact make me fill before I fund this
   address? Today two, against a compromise threshold of three. With per-seat
   attribution, four.

   SLOTS, precisely -- and the word is doing real work. `AttributedKeys` is a
   set of NAMES, not of key values: this counts how many separate endorsements
   the artifact demands, and says nothing about whether the things filling them
   are distinct key values or whether the parties behind them are distinct
   entities. That second question is `MaxKeysPerPrincipal` and it lives with the
   guarantee, not here. An earlier draft of the runner rendered this count as
   "4 keys obtained from 4 named parties", which claims both of the things this
   invariant explicitly does not check; an adversarial review caught it.

   This is a constant of the configuration and TLC reports it as an invariant
   that is identically FALSE rather than as a trace; tlc_harness handles that
   case explicitly, and it is still a violation.

   IT IS NOT THE GUARANTEE, and the mutation matrix is the evidence for that
   sentence rather than a promise about it: this invariant survives all THREE
   residual switches being turned off, in runs where the guarantee above is
   being violated by a coalition of ONE. It also survives CompromiseT = 4, in
   the run where the guarantee does not.

   The `EndorserHoldsShare = FALSE` row is the sharpest case, and it is no
   longer the row this implementation is on -- it is the row it CAME FROM, kept
   to price the linked endorsement. Four slots, four distinct genuine keys, four
   distinct principals holding them, no retained copies -- this invariant clean
   -- and a coalition of two spending anyway.

   Stated at the strength the runs actually support, across the configurations
   the runner examines: every configuration that fails this also fails the
   guarantee, and four configurations that pass this fail the guarantee. So
   counting keys does not establish the guarantee here, and no stronger claim
   than that is being made for it. *)
INV_AttributedKeysMeetThreshold ==
    Cardinality(AttributedKeys) >= CompromiseT

(*---------------------- the constants-only stand-in ----------------------*)

(* NOT A PROPERTY OF THE SYSTEM. This is an adversarial review's candidate
   replacement for the guarantee, checked in as an oracle: it reads only the
   CONSTANTS and never touches `spend`, so any configuration where it and the
   real guarantee disagree is evidence that the real one is measuring the state.

   The history is the reason it is in the file rather than in a comment. The
   first version of this model used a boolean collusion switch, and review
   showed the whole matrix was equally satisfied by a constants-only predicate.
   `MaxKeysPerPrincipal` was graded to fix that -- and the NEXT review showed
   the fix insufficient, because the graded knob is itself a constant, so the
   product below survives every row of the repaired matrix too: it is true at
   the baseline and false at every mutation, at the oracle, at CompromiseT = 4
   and at OwnerT = 1.

   What separates them is a configuration where the guarantee HOLDS and this
   does not, which is the direction the runner was not testing at all:

       MaxKeysPerPrincipal = 2, CompromiseT = 2

   Two names may be one principal, so the smallest coalition is 2 and the
   guarantee is CLEAN; the product reads 2 * 2 <= 3 and is FALSE. The runner's
   SURVIVAL section runs exactly that and requires both answers.

   HOW MUCH THIS IS WORTH, stated because the honest limit is unusual and easy
   to overstate in either direction. This model is a deterministic function of
   its constants, so for ANY finite set of configurations SOME constants-only
   predicate agrees with the guarantee on all of them. No matrix can close the
   family. What a row like this does is refute a SPECIFIC stand-in, and two
   review rounds have now each supplied one that the previous rows admitted. The
   argument that the guarantee reads the coalition is, in the end, that you can
   read `Cardinality(spend.by)` in its definition; the oracle rows are what stop
   the MATRIX being cited as that argument. *)
FAKE_ConstantsOnlyGuarantee ==
    /\ AttributionPerSeat
    /\ NoRetainedCopies
    /\ EndorserHoldsShare
    /\ MaxKeysPerPrincipal * CompromiseT <= OwnerT + GateT

(*------------------------------- coverage --------------------------------*)

(* Negative coverage, in the shape PayoutProvenance uses: a model where nothing
   can ever spend satisfies every invariant above. This must be violated, or
   the file proves nothing. *)
COV_CanSpend == spend.seats = {}

(* And the bound must be reachable at exactly CompromiseT, not merely somewhere
   above it. Without this, an invariant asserting `>= 3` would look healthy in a
   model whose smallest coalition happened to be 4, and would be measuring the
   configuration rather than the structure. *)
COV_TightCoalition ==
    ~(spend.seats # {} /\ Cardinality(spend.by) = CompromiseT)

(* THE FORGERY, as a reachability question, deliberately stated WITHOUT any
   reference to the coalition size -- so that it is independent of
   INV_SpendNeedsThresholdPrincipals rather than implied by it.

   One principal holds every seat of the operator cohort while the artifact
   reports a roster of three at a threshold of two, and the spend goes through.
   That is `forgery.rs::a_dealt_owner_cohort_passes_the_audit_and_the_release_gate`.

   The runner checks this in every configuration IT EXERCISES -- which is the
   baseline, each single mutation, and the oracle row, not all eight settings of
   the switches -- as a third column of the matrix, because "unreachable" read
   on its own would be the same overclaim this file exists to prevent. What the
   column shows:

     per-seat, all residuals assumed    UNREACHABLE
     attribution per cohort             REACHABLE   -- forgery.rs
     endorser need not hold a share     REACHABLE   -- seat_forgery.rs, and this
                                                       is the branch the code is
                                                       on TODAY
     MaxKeysPerPrincipal = 4            REACHABLE   -- and INDISTINGUISHABLE
                                                       from the line above,
                                                       from bytes
     MaxKeysPerPrincipal = 2 (oracle)   UNREACHABLE -- yet a coalition of TWO
                                                       spends in that same run
     dealer kept copies                 UNREACHABLE -- yet a coalition of ONE
                                                       spends in that same run

   The last two rows are the ones that matter most. They are the cases where
   this predicate is clean and the guarantee is violated anyway, which is what
   shows that "no cohort collapsed into one principal" is NOT the property, only
   one shape of losing it. *)
COV_ForgeryShape ==
    ~( /\ \E p \in Principals : \A s \in OwnerSeats : seatHolder[s] = p
       /\ spend.seats # {} )

=============================================================================
