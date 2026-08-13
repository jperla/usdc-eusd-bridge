#!/usr/bin/env python3
"""Can a Phase-A pause bind a colluding owner threshold, with no consensus change?

The answer turns entirely on WHERE the gate's contribution lands.
"""
import sys
from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, run

MODULE = "CompositeGate.tla"

# (mode, gates_independent, expected_pause_holds, note)
SCENARIOS = [
    ("indispensable", True, True,
     "gate share enters the key image; consensus rejects without it"),
    ("offChainOnly", True, False,
     "detached signature or advisory policy -- consensus never checks it"),
    ("indispensable", False, False,
     "gates under owner control sign through the pause"),
    # Josh, 2026-08-10: production "simplest configuration is 3 independent
    # parties". If BOTH roles are drawn from that same pool, any coalition
    # reaching the owner threshold also reaches the gate threshold -- which is
    # the non-independent case, and the composite root buys nothing.
    ("indispensable", False, False,
     "3 parties holding BOTH roles: an owner quorum is also a gate quorum"),
]


def write_cfg(name, mode, independent, invariants=None, shared=False):
    lines = [
        "SPECIFICATION Spec", "CONSTANTS",
        "    Owners = {o1, o2, o3}", "    Gates = {g1, g2}",
        "    K = 2", "    G = 2",
        f'    GateMode = "{mode}"',
        f"    GatesIndependent = {'TRUE' if independent else 'FALSE'}",
        f"    SharedPool = {'TRUE' if shared else 'FALSE'}",
        "INVARIANT TypeOK",
    ]
    for i in (invariants or ["INV_PauseStopsUnauthorized", "INV_GateWasRequired"]):
        lines.append(f"INVARIANT {i}")
    p = HERE / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []
    print("=" * 78)
    print("COVERAGE — on the indispensable/independent configuration")
    print("=" * 78)
    for cov in ["COV_CanPause", "COV_CanFinalize", "COV_OwnersReachK",
                "COV_PauseFirst", "COV_AllowedLate"]:
        c = expect(MODULE, write_cfg(f"_cg_cov_{cov}", "indispensable", True,
                                     invariants=[cov]), cov)
        alive = c.status == VIOLATED
        print(f"  {cov:<20} {'reachable' if alive else 'UNREACHABLE'}   {c}")
        if not alive:
            fails.append(f"{cov} unreachable")

    print()
    print("=" * 78)
    print("BASELINE — both invariants, indispensable + independent")
    print("=" * 78)
    b = run(MODULE, write_cfg("CompositeGate", "indispensable", True,
                              invariants=["INV_PauseStopsUnauthorized",
                                          "INV_GateWasRequired"]))
    print(f"  {b}")
    if b.status != CLEAN:
        fails.append(f"baseline: {b}")
    ng = expect(MODULE, write_cfg("CompositeGate-nogate", "offChainOnly", True,
                                  invariants=["INV_GateWasRequired"]),
                "INV_GateWasRequired")
    print(f"  gate omitted -> INV_GateWasRequired  "
          f"{'breaks, as it must' if ng.status == VIOLATED else f'FAIL {ng}'}")
    if ng.status != VIOLATED:
        fails.append("INV_GateWasRequired never checked/violated")

    print()
    print("=" * 78)
    print("DOES A PAUSE BIND A COMPROMISED OWNER THRESHOLD?")
    print("Owners are assumed corrupt and contribute through the pause.")
    print("=" * 78)
    print(f"  {'gate mode':<18} {'independent':<13} result")
    for mode, indep, want, note in SCENARIOS:
        cfg = write_cfg(f"_cg_{mode}_{indep}", mode, indep,
                        invariants=["INV_PauseStopsUnauthorized"])
        r = (run(MODULE, cfg) if want
             else expect(MODULE, cfg, "INV_PauseStopsUnauthorized"))
        if r.status == ERROR:
            print(f"  {mode:<18} {str(indep):<13} TOOL ERROR {r}")
            fails.append(f"{mode}/{indep}: {r}")
            continue
        held = r.status == CLEAN
        print(f"  {mode:<18} {str(indep):<13} "
              f"{'PAUSE HOLDS' if held else 'owners spend anyway'}")
        print(f"  {'':<32} {note}")
        if held != want:
            fails.append(f"{mode}/{indep}: expected "
                         f"{'hold' if want else 'bypass'}")

    print()
    print("=" * 78)
    print("THE SHARED-POOL REDUCTION — claimed in review, now checked")
    print("Both roles drawn from the SAME parties, e.g. '3 independent parties'")
    print("holding an owner share and a gate share each.")
    print("=" * 78)
    coll = run(MODULE, write_cfg("_cg_shared", "indispensable", False,
                                 invariants=["INV_CollapsesToMax"], shared=True))
    print(f"  nothing finalizes below max(K,G)   {coll}")
    if coll.status != CLEAN:
        fails.append(f"shared-pool collapse: {coll}")
    tight = expect(MODULE, write_cfg("_cg_shared_tight", "indispensable", False,
                                     invariants=["COV_ReachesMax"], shared=True),
                   "COV_ReachesMax")
    print(f"  ...and max(K,G) is sufficient      "
          f"{'reachable, so the bound is tight' if tight.status == VIOLATED else f'FAIL {tight}'}")
    if tight.status != VIOLATED:
        fails.append("max(K,G) not reachable; bound not shown tight")
    print()
    print("  So with a shared pool the access structure is EXACTLY a")
    print("  max(K,G)-of-n multisig. The two-cohort split provides no benefit,")
    print("  and this rules out EVERY threshold assignment over shared parties")
    print("  -- including owners 2-of-3 with gates 3-of-3, which is just 3-of-3.")

    print()
    print("=" * 78)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("READING")
    print()
    print("Only the indispensable form works, and the reason is worth being")
    print("precise about. A detached signature and an advisory policy both fail")
    print("for the SAME reason: they are enforced by the party being")
    print("constrained. A colluding coordinator does not attach what consensus")
    print("does not check. The gate share has to land somewhere consensus")
    print("ALREADY verifies -- the key image and row-0 response -- so that")
    print("omitting it yields no valid spend rather than an unauthorized one.")
    print()
    print("The detached and advisory cases are collapsed to offChainOnly.")
    print("They had IDENTICAL transition systems, so presenting them as two")
    print("rows made the model look like it distinguished them when it only")
    print("compared a string. Their bypassability is a design fact, not")
    print("something this model derives from artifacts.")
    print()
    print("Gate independence is a named assumption, not a detail: gates under")
    print("owner control sign straight through the pause, and the composite")
    print("root buys nothing. The security is (k owners) AND (g gates), so an")
    print("attacker must compromise BOTH sets, not either.")
    print()
    print("SCOPE. This is an ACCESS-STRUCTURE result, not a cryptographic one.")
    print("It assumes a composite root B = B_owner + B_gate can be constructed")
    print("such that the gate share is genuinely required to form a valid key")
    print("image, and that MobileCoin's unmodified verifier accepts the result.")
    print("Neither is established here -- both are the open proof obligation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
