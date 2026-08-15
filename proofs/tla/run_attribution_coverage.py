#!/usr/bin/env python3
"""Does what the artifact ATTRIBUTES support the guarantee the structure claims?

Written BEFORE the per-seat rework, so the rework is measured against something
rather than blessing itself. ClaimAcceptance.tla is the reason that ordering is
worth paying for: it named a boundary honestly and the implementation then
walked across it.

Four switches, all mutation-tested, and they are THREE DIFFERENT KINDS of thing:

  * AttributionPerSeat  -- a design choice, and the one this rework made.
  * MaxKeysPerPrincipal, NoRetainedCopies -- assumptions about the world that no
    artifact can discharge.
  * EndorserHoldsShare  -- a property of THIS implementation, currently FALSE,
    with a Rust counterexample. It was added after an adversarial review found
    the model's baseline silently assuming it. Buildable; not built.

They are switches rather than omissions so that each residual is exhibited.

The matrix is the point, and it has three columns because the three properties
respond DIFFERENTLY to the switches. The bar (how many slots the funder fills)
is blind to all three residuals. The forgery SHAPE is blind to two of them. Only
the guarantee (how few principals can actually spend) tracks every one. Those
differences are what stop "four keys" being read as "four entities", and stop
"the forgery is unreachable" being read as "the address is safe".
"""
import sys
from tlc_harness import CLEAN, VIOLATED, ERROR, HERE, expect

MODULE = "AttributionCoverage.tla"

# The guarantee, and the bar. Kept apart everywhere in this file.
GUARANTEE = "INV_SpendNeedsThresholdPrincipals"
BAR = "INV_AttributedKeysMeetThreshold"
INVARIANTS = [GUARANTEE, BAR]

# Checked as a third column rather than once, because "the forgery state is
# unreachable" read on its own is exactly the overclaim this file exists to
# prevent. NoRetainedCopies=FALSE is the row that proves the point: this comes
# back CLEAN there while a coalition of ONE is spending.
SHAPE = "COV_ForgeryShape"

# An adversarial review's candidate replacement for the guarantee, reading only
# the constants. Checked in the model so it can be RUN rather than argued about.
# See the SURVIVAL section, and the definition's own header for why no matrix
# can exclude the whole family it comes from.
FAKE = "FAKE_ConstantsOnlyGuarantee"

BOOLEANS = ["AttributionPerSeat", "NoRetainedCopies", "EndorserHoldsShare"]

# One row of the mutation matrix: a label, the config change, what each of the
# three properties must do, and why. A row whose result differs from `expect`
# fails the runner -- in EITHER direction. A switch that fails to break what it
# claims is not load-bearing; one that breaks something it does not claim means
# the model is not measuring what its names say.
#
# `kw` is passed to write_cfg. Everything not named there stays at the decided
# values, so each row differs from the baseline in exactly one thing.
ROWS = [
    ("AttributionPerSeat = FALSE", dict(off="AttributionPerSeat"),
     {GUARANTEE: True, BAR: True, SHAPE: True},
     "DESIGN     -- this is the rework",
     "one key per cohort: a dealer holds every seat and the artifact reports "
     "three organisations. forgery.rs performs this one to a published address."),

    # The row an adversarial review forced into existence. It is NOT a variant
    # of the two below: here the four slots are filled by four distinct,
    # genuine keys held by four distinct principals, no dealer kept a copy of
    # anything, and the guarantee falls anyway -- because nothing ties the
    # signer of a seat to the holder of that seat's share. Rust performs it.
    ("EndorserHoldsShare = FALSE", dict(off="EndorserHoldsShare"),
     {GUARANTEE: True, BAR: False, SHAPE: True},
     "GAP        -- buildable, and NOT built. This is where the code is TODAY",
     "`ceremony::endorse_seat` is public, takes a claim and an identity key, "
     "and consults no share. seat_forgery.rs::a_seat_holder_with_a_real_share_"
     "endorses_a_substituted_dealing_and_it_audits performs it: a real DKG, "
     "three real share-holders, a substituted dealing, and it audits."),

    ("MaxKeysPerPrincipal = 4", dict(max_keys=4),
     {GUARANTEE: True, BAR: False, SHAPE: True},
     "ASSUMPTION -- not buildable by anyone",
     "four slots filled from four names that all resolve to one controller "
     "(or one organisation that lent its seat key)."),

    ("NoRetainedCopies = FALSE", dict(off="NoRetainedCopies"),
     # Seats really are held by four distinct principals here -- the collapse
     # shape is genuinely unreachable -- and the guarantee falls to the dealer.
     {GUARANTEE: True, BAR: False, SHAPE: False},
     "ASSUMPTION -- not buildable by anyone",
     "the shares really went to distinct parties and the dealer kept copies; "
     "a dealt cohort and a DKG'd one publish the same material."),
]

# How a VIOLATED / CLEAN pair reads for each property. For an invariant,
# violated is bad news about the design; for a reachability probe stated as a
# negation, violated means the state is reachable.
CELL = {
    GUARANTEE: ("BREAKS", "holds"),
    BAR: ("BREAKS", "holds"),
    SHAPE: ("REACHABLE", "unreachable"),
}


def tla(b):
    return "TRUE" if b else "FALSE"


def write_cfg(name, off=None, compromise=3, owner_t=2, max_keys=1, invariants=None):
    """One config. `off` names the single boolean set FALSE, if any."""
    lines = [
        "SPECIFICATION Spec",
        "CONSTANTS",
        # Three operator seats at a quorum of two, one gate seat at a quorum of
        # one: production::owners() and production::gates(), exactly.
        "    OwnerSeats = {o1, o2, o3}",
        "    GateSeats = {g1}",
        # Five principals, so a one-key-each map is not forced to be a bijection
        # and there is a principal spare to play a dealer that holds no seat of
        # its own.
        "    Principals = {p1, p2, p3, p4, p5}",
        "    CohortKeys = {kOwners, kGates}",
        "    NoOne = noone",
        f"    OwnerT = {owner_t}",
        "    GateT = 1",
        f"    CompromiseT = {compromise}",
        f"    MaxKeysPerPrincipal = {max_keys}",
    ]
    for s in BOOLEANS:
        lines.append(f"    {s} = {tla(s != off)}")
    for i in (invariants or INVARIANTS):
        lines.append(f"INVARIANT {i}")
    p = HERE / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def one(name, inv, **kw):
    """Run MODULE with exactly one invariant, requiring exact attribution."""
    return expect(MODULE, write_cfg(name, invariants=[inv], **kw), inv)


def main():
    fails = []

    print("=" * 78)
    print("BASELINE -- per-seat attribution, all three residuals assumed away")
    print("=" * 78)
    print("  This is the BEST CASE, and it is NOT where the code is: it assumes")
    print("  the rework landed, the world cooperates, AND that a seat's endorser")
    print("  holds that seat's share -- which seat_forgery.rs disproves.")
    for inv in ["TypeOK"] + INVARIANTS:
        # Each invariant in its own run. TLC halts at the first violation, so a
        # single run over a list cannot establish that the others were checked.
        r = one(f"_ac_base_{inv}", inv)
        print(f"  {inv:<36} {r.status} ({r.states} states)"
              + (f" {r.detail}" if r.detail else ""))
        if r.status is not CLEAN:
            fails.append(f"baseline: {inv} is {r.status}")

    print()
    print("=" * 78)
    print("COVERAGE -- the model must move, and the bound must be tight")
    print("=" * 78)
    cov = one("_ac_cov_COV_CanSpend", "COV_CanSpend")
    ok = cov.status == VIOLATED
    print(f"  COV_CanSpend                         "
          f"{'violated -- a spend is reachable' if ok else 'NOT VIOLATED -- ' + str(cov.status)}")
    if not ok:
        fails.append("COV_CanSpend was not violated; nothing ever spends")

    # Without this, `>= 3` would look healthy in a model whose smallest
    # coalition happened to be 4, and would be measuring the config.
    cov = one("_ac_cov_COV_TightCoalition", "COV_TightCoalition")
    ok = cov.status == VIOLATED
    print(f"  COV_TightCoalition                   "
          f"{'violated -- a coalition of exactly 3 is reachable' if ok else 'NOT VIOLATED -- ' + str(cov.status)}")
    if not ok:
        fails.append("COV_TightCoalition was not violated; the bound is slack, "
                     "so the invariant is not measuring the structure")

    # The forgery state must be UNREACHABLE once the seats are pinned. Stated
    # without any reference to coalition size, so it is independent of the
    # guarantee rather than implied by it.
    cov = one("_ac_cov_COV_ForgeryShape", "COV_ForgeryShape")
    ok = cov.status == CLEAN
    print(f"  COV_ForgeryShape                     "
          f"{'CLEAN -- one principal holding a whole cohort is unreachable' if ok else 'REACHABLE -- ' + str(cov.status)}")
    if not ok:
        fails.append("COV_ForgeryShape is reachable under per-seat attribution")

    print()
    print("=" * 78)
    print("MUTATION -- one change at a time, one invariant per run")
    print("=" * 78)
    print(f"  {'change from the baseline':<32} {'guarantee':<11} {'bar':<8} {'forgery shape':<13}")
    print(f"  {'(baseline, above)':<32} {'holds':<11} {'holds':<8} {'unreachable':<13}")

    def row(label, kw, expect_break, tag=None):
        """One matrix row. Returns the cells; records any surprise as a failure.

        TypeOK is checked in EVERY configuration, not just the baseline. An
        earlier version checked it only in the all-on run, which left the
        mutated configurations without a type oracle at all.
        """
        slug = label.replace(" ", "").replace("=", "")
        t = one(f"_ac_{slug}_TypeOK", "TypeOK", **kw)
        if t.status is not CLEAN:
            fails.append(f"{label}: TypeOK is {t.status} {t.detail}")
        cells = {}
        for prop in [GUARANTEE, BAR, SHAPE]:
            want = expect_break[prop]
            r = one(f"_ac_{slug}_{prop}", prop, **kw)
            got = r.status == VIOLATED
            hit, miss = CELL[prop]
            if r.status == ERROR:
                cells[prop] = "ERROR"
                fails.append(f"{label} / {prop}: {r.detail}")
            elif got == want:
                cells[prop] = hit if got else miss
            else:
                # Either the change is not load-bearing for what it claims, or
                # it is load-bearing for something it does not claim. Both mean
                # the model is not measuring what its names say.
                cells[prop] = f"UNEXPECTED({r.status})"
                fails.append(f"{label}: expected {prop} to "
                             f"{'break' if want else 'hold'}, it did not")
        print(f"  {label + (' ' + tag if tag else ''):<32} "
              f"{cells[GUARANTEE]:<11} {cells[BAR]:<8} {cells[SHAPE]:<13}")
        return cells

    for label, kw, expect_break, kind, why in ROWS:
        row(label, kw, expect_break)
        print(f"      {kind}")
        print(f"      {why}")

    print()
    print("  Read the last row. The forgery SHAPE is unreachable there -- the")
    print("  seats really are held by four distinct principals -- and the")
    print("  guarantee falls anyway, to a dealer holding copies. 'No cohort")
    print("  collapsed into one principal' is one way to lose, not the property.")

    print()
    print("=" * 78)
    print("ORACLE -- does the guarantee read the COALITION, or just the switches?")
    print("=" * 78)
    print("  Every boolean ON, CompromiseT and both quorums untouched, and only")
    print("  the collusion bound moved from 1 to 2: two of the four named")
    print("  parties turn out to be one entity.")
    # WHY THIS EXISTS. An adversarial review showed that with the collusion
    # residual as a BOOLEAN, this entire file was equally well satisfied by a
    # guarantee that never reads the coalition at all:
    #
    #   spend.seats # {} => AttributionPerSeat /\ NoRetainedCopies
    #                       /\ CompromiseT <= OwnerT + GateT
    #
    # -- clean at baseline, violated by every mutation, violated at
    # CompromiseT = 4 and at OwnerT = 1. The same guard causing and detecting
    # the bug, which this repo has shipped before. This row was the first fix:
    # no BOOLEAN differs from the baseline, so a guarantee written over the
    # booleans cannot break here, and the real one must.
    #
    # It is NOT sufficient on its own, and saying so is the point of the SURVIVAL
    # section below. A second review pass observed that MaxKeysPerPrincipal is
    # itself a constant and supplied a stand-in that survives this row too. Read
    # this row as excluding predicates over the BOOLEANS, and SURVIVAL as
    # excluding the one that beat it.
    cells = row("MaxKeysPerPrincipal = 2", dict(max_keys=2),
                {GUARANTEE: True, BAR: False, SHAPE: False}, tag="")
    print("      The guarantee breaks while every BOOLEAN a fake could read is")
    print("      unchanged. That excludes a predicate over the switches; it does")
    print("      NOT by itself show the guarantee reads spend.by, since this row")
    print("      moves a constant -- see SURVIVAL. The forgery shape stays")
    print("      unreachable: no ONE principal holds a whole cohort, and the")
    print("      separation is gone regardless.")
    print("      Result: the decided structure tolerates ZERO collusion among")
    print("      the named parties. One shared controller across two operator")
    print("      seats already puts a spend below COMPROMISE_THRESHOLD.")

    print()
    print("=" * 78)
    print("SENSITIVITY -- the guarantee must depend on the numbers it asserts")
    print("=" * 78)
    # If the guarantee held for whatever number is written in the config, it
    # would be measuring nothing. Four seats do not give four principals of
    # separation: a quorum is OwnerT + GateT = 3, and that is exactly what
    # per-seat attribution supports -- not one more.
    r = one("_ac_overclaim_guarantee", GUARANTEE, compromise=4)
    ok = r.status == VIOLATED
    print(f"  CompromiseT = 4, {GUARANTEE:<36} "
          f"{'VIOLATED (good)' if ok else 'survives -- ' + str(r.status)}")
    if not ok:
        fails.append("the guarantee survives an inflated CompromiseT, so it is "
                     "not sensitive to the number it asserts")
    # ...while the BAR still passes at 4, because four keys is four keys. That
    # is the separation this file exists to make: the count a funder can check
    # is satisfied in the very run where the guarantee is violated.
    r = one("_ac_overclaim_bar", BAR, compromise=4)
    ok = r.status == CLEAN
    print(f"  CompromiseT = 4, {BAR:<36} "
          f"{'CLEAN -- four slots is still four slots' if ok else 'unexpected -- ' + str(r.status)}")
    if not ok:
        fails.append(f"{BAR} did not survive CompromiseT = 4")

    # And it must track the ACCESS STRUCTURE, not the constant 3. Drop the
    # operator quorum to 1-of-3 and the guarantee falls with every switch still
    # on and four genuinely distinct principals holding four seats: separation
    # is OwnerT + GateT, and attribution does not rescue a threshold nobody
    # decided. That is the model's counterpart of forgery.rs::
    # a_decided_roster_at_an_undecided_threshold_is_refused_on_both_paths, and
    # it is why per-seat keys are not a substitute for the release gate's
    # threshold arm.
    r = one("_ac_undecided_threshold", GUARANTEE, owner_t=1)
    ok = r.status == VIOLATED
    print(f"  OwnerT = 1,      {GUARANTEE:<36} "
          f"{'VIOLATED (good)' if ok else 'survives -- ' + str(r.status)}")
    if not ok:
        fails.append("the guarantee survives a 1-of-3 operator quorum, so it is "
                     "measuring the constant rather than the access structure")

    print()
    print("=" * 78)
    print("SURVIVAL -- the direction the ORACLE row could not test")
    print("=" * 78)
    # WHY THIS SECTION EXISTS. The ORACLE row above holds every constant fixed
    # except MaxKeysPerPrincipal -- but that knob IS a constant, which a second
    # adversarial review used to defeat the whole matrix. Its stand-in,
    # FAKE_ConstantsOnlyGuarantee in the model, is true at the baseline and
    # false at every single row above, including the oracle. Every row so far
    # asks the guarantee to BREAK; a predicate that breaks too easily is never
    # caught by rows like that.
    #
    # This is the missing direction: a configuration where the guarantee must
    # SURVIVE and the stand-in must not. At MaxKeysPerPrincipal = 2 two of the
    # four names may be one principal, so the smallest coalition is two -- which
    # is exactly what a claim of CompromiseT = 2 asserts, so the real guarantee
    # is clean. The stand-in reads 2 * 2 <= 3 and is false.
    print("  MaxKeysPerPrincipal = 2 with the claim lowered to match it: the")
    print("  guarantee must HOLD here. A predicate that merely breaks whenever")
    print("  the constants look wrong cannot pass this row.")
    survive = dict(max_keys=2, compromise=2)
    r = one("_ac_survive_real", GUARANTEE, **survive)
    ok = r.status == CLEAN
    print(f"  {GUARANTEE:<36} "
          f"{'CLEAN (good) -- 2 names, 1 controller, and the claim says 2' if ok else 'UNEXPECTED -- ' + str(r.status)}")
    if not ok:
        fails.append("the guarantee does not survive a claim its own structure "
                     "supports, so it is not measuring coalition size either")

    r = one("_ac_survive_fake", FAKE, **survive)
    ok = r.status == VIOLATED
    print(f"  {FAKE:<36} "
          f"{'VIOLATED (good) -- the stand-in and the guarantee disagree here' if ok else 'AGREES -- ' + str(r.status)}")
    if not ok:
        fails.append(f"{FAKE} agrees with the guarantee in every configuration "
                     "this runner examines, so the matrix does not establish "
                     "that the guarantee reads the coalition")

    # ...and the stand-in must be a genuine stand-in, not something that fails
    # everywhere. If it were already violated at the baseline the row above
    # would be worthless.
    r = one("_ac_survive_fake_base", FAKE)
    ok = r.status == CLEAN
    print(f"  {FAKE + ' at the baseline':<36} "
          f"{'CLEAN -- so it really is a candidate replacement' if ok else 'unexpected -- ' + str(r.status)}")
    if not ok:
        fails.append(f"{FAKE} is not clean at the baseline, so it is not a "
                     "candidate the matrix needed to exclude")

    print()
    print("=" * 78)
    if fails:
        print("FAIL")
        for f in fails:
            print(f"  - {f}")
        return 1

    print("PASS")
    print()
    print("WHAT THIS ESTABLISHES")
    print("  Of the two attribution designs this model compares, only per-seat")
    print("  can support the claim the decided structure makes. Under per-cohort")
    print("  attribution the model reaches a state with one principal holding a")
    print("  whole operator cohort and a spending coalition of TWO against a")
    print("  threshold of three -- the cardinality and the shape that")
    print("  forgery.rs::a_dealt_owner_cohort_passes_the_audit_and_the_release_gate")
    print("  exhibits in Rust. Under per-seat attribution, with all THREE")
    print("  residuals assumed away, that state is unreachable and the smallest")
    print("  coalition is exactly COMPROMISE_THRESHOLD -- derived from OwnerT +")
    print("  GateT, not read off the config, since raising the claim to 4 or")
    print("  dropping the operator quorum to 1 breaks it.")
    print()
    print("  Read 'assumed away' strictly. One of those three is not a fact")
    print("  about the world but a property of this code, and it is FALSE here:")
    print("  the EndorserHoldsShare row is the same coalition of two, at the")
    print("  same shape, with all four attribution slots filled and resolving")
    print("  to four DISTINCT principals, and no dealer retaining anything. So")
    print("  the baseline is the criterion, not a description of the tree.")
    print("  (Slots and their holders, not key VALUES -- this model has no key")
    print("  values in it, and the Rust counterpart is what carries those.)")
    print()
    print("WHAT IT DOES NOT ESTABLISH, stated because two false claims have")
    print("shipped from this repo already:")
    print("  * NOT that per-seat attribution is the only mechanism that could")
    print("    work. The alternative modelled here is one key per cohort, whose")
    print("    false branch leaves the seat map entirely unconstrained. Beating")
    print("    that does not rule out designs this model never considered.")
    print("  * NOT anything about auditing, funding or publication. There is no")
    print("    audit action, no artifact validation and no address in this")
    print("    model; 'every check passes' is its premise, not its result. The")
    print("    end-to-end half is what forgery.rs performs, in Rust.")
    print("  * NOT that four slots hold four distinct KEY VALUES. The bar")
    print("    invariant counts attribution slots the artifact demands. Key")
    print("    values are not modelled.")
    print()
    print("WHAT IT ASSUMES, precisely -- all three are rows above and all three")
    print("break the guarantee. TWO of them are not buildable by anyone. The")
    print("THIRD is buildable, is not built, and is false in this tree today:")
    print("  1. the parties behind the attributed slots are distinct entities.")
    print("     NOT BUILDABLE. The ORACLE row prices it exactly: the decided")
    print("     structure tolerates ZERO collusion. Two names, one controller,")
    print("     and the spend is already below COMPROMISE_THRESHOLD -- with the")
    print("     seats still pinned and no cohort visibly collapsed.")
    print("  2. no dealer kept copies of the shares it handed out. NOT")
    print("     BUILDABLE: a dealt cohort and a DKG'd cohort publish identical")
    print("     material.")
    print("  3. the party that SIGNS for a seat HOLDS a share behind it.")
    print("     BUILDABLE, AND NOT BUILT -- so this one is a design gap, not a")
    print("     fact about the world, and an earlier version of this section")
    print("     said all its assumptions were unbuildable, which hid it.")
    print("     `ceremony::endorse_seat` never consults a share;")
    print("     `seat_forgery.rs::a_seat_holder_with_a_real_share_endorses_a_")
    print("     substituted_dealing_and_it_audits` is the counterexample. Two")
    print("     ways it COULD be built, neither attempted: endorse over a value")
    print("     derived from the share, or route holders through")
    print("     `CohortShare::endorse` and record which entry point signed.")
    print()
    print("  Per-seat attribution therefore raises the BAR from 2 attribution")
    print("  slots to 4. It does not turn four slots into four entities, nor")
    print("  four signatures into four share-holders, and the matrix is what")
    print("  says so rather than a promise: the bar invariant is CLEAN in all")
    print("  FOUR runs where the guarantee is being violated.")
    print()
    print("Scope: this is COVERAGE, not cryptography. Whether a Schnorr")
    print("transcript really binds a seat key, and whether the commitment really")
    print("seals it, is a Rust and test-vector question in crates/two-cohort.")
    print("This says only what such a binding would and would not be worth.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
