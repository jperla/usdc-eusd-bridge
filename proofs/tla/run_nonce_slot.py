#!/usr/bin/env python3
"""Model-check NonceSlot.tla — the one-time slot under snapshot rollback.

The design says, in prose, that fsync is not enough and that a rolled-back or
snapshot-restored signer must be treated as key compromise unless an external
monotonic anchor is present. This turns that sentence into a checked property:
switch off the anti-rollback guard and the model must reach two distinct
bindings on one slot, which RESULTS 2 and 3 in threshold_algebra.py show leaks
the long-lived share.
"""
import sys

from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, matrix, run

MODULE = "NonceSlot.tla"

GUARDS = ["GuardBurnOnAbort", "GuardAntiRollback", "GuardRetransmitOnly"]

INVARIANTS = ["INV_OneContextBound", "INV_OneContextSent",
              "INV_NoWorkAfterBurn", "INV_NoReuseAfterExposure",
              "INV_PersistedBeforeSend"]

PROTECTS = {
    "GuardBurnOnAbort": "INV_NoReuseAfterExposure",
    "GuardAntiRollback": "INV_OneContextBound",
    "GuardRetransmitOnly": None,   # a safety-only weakening; see note below
}


def write_cfg(name, off=None, invariants=None):
    inv = invariants if invariants is not None else INVARIANTS
    lines = [
        "SPECIFICATION Spec",
        "CONSTANTS",
        "    Transcripts = {t1, t2}",
        "    Packages    = {p1, p2}",
        "    MaxGen = 6",   # reserve/expose/bind/respond each advance it
    ]
    for g in GUARDS:
        lines.append(f"    {g} = {'FALSE' if g == off else 'TRUE'}")
    lines.append("INVARIANT TypeOK")
    for i in inv:
        lines.append(f"INVARIANT {i}")
    p = HERE / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []

    print("=" * 78)
    print("BASELINE — full slot discipline, snapshots and rollback allowed")
    print("=" * 78)
    r = run(MODULE, write_cfg("NonceSlot"))
    print(f"  {r}")
    if r.status != CLEAN:
        fails.append(f"baseline: {r}")
    else:
        print("  A rollback cannot produce a second binding while the external")
        print("  anchor is present: the rewound store fails the generation")
        print("  check on the next GUARDED TRANSITION -- not merely the next")
        print("  reservation, which was the earlier and weaker claim.")

    print()
    print("=" * 78)
    print("COVERAGE — each of these is written to FAIL. If one passes, the")
    print("model cannot reach that state and every CLEAN result is worthless.")
    print("=" * 78)
    for cov in ["COV_CanExpose", "COV_CanSend", "COV_CanRollback",
                "COV_BurnThenRollback"]:
        c = expect(MODULE, write_cfg(f"_cov_{cov}", invariants=[cov]), cov)
        alive = c.status == VIOLATED
        print(f"  {cov:<22} {'reachable' if alive else 'UNREACHABLE'}  {c}")
        if not alive:
            fails.append(f"{cov}: state unreachable — the model is dead here")

    print()
    print("=" * 78)
    print("MUTATIONS — each invariant in its own run")
    print("=" * 78)
    for g in GUARDS:
        res = matrix(MODULE, write_cfg, INVARIANTS, off=g)
        errs = sorted(k for k, v in res.items() if v.status == ERROR)
        if errs:
            print(f"  {g:<22} TOOL ERROR on {errs}")
            fails.append(f"{g}: tool error")
            continue
        broke = sorted(k for k, v in res.items() if v.status == VIOLATED)
        want = PROTECTS[g]
        if want is None:
            ok = True
            note = "no safety violation — retransmission is a liveness aid"
        else:
            ok = want in broke
            extra = [b for b in broke if b != want]
            note = f"expected {want}" + (f"; also {extra}" if extra else "")
        print(f"  {g:<22} {str(broke or '(none)'):<40} {'ok' if ok else 'FAIL'}")
        print(f"  {'':<22} {note}")
        if not ok:
            fails.append(f"{g}: expected {want}, broke {broke}")

    print()
    print("=" * 78)
    print("THE RESULT THAT MATTERS")
    print("=" * 78)
    res = expect(MODULE, write_cfg("NonceSlot-rollback", off="GuardAntiRollback",
                                   invariants=["INV_OneContextBound"]),
                 "INV_OneContextBound")
    if res.status == VIOLATED:
        print("  Without an external anti-rollback anchor, a snapshot restore")
        print("  reaches TWO distinct bindings on one slot.")
        print(f"  ({res.states:,} states)")
        print()
        print("  Three bindings recover the long-lived share; two extract only")
        print("  when the same effective nonce answers different challenges.")
        print("  So this is not a hygiene issue: an fsync'd")
        print("  store with no external anchor is insufficient, and restoring a")
        print("  signer from a snapshot must be treated as key compromise.")
    else:
        print(f"  FAIL — expected a violation, got {res}")
        fails.append(f"rollback: expected violation, got {res}")

    print()
    print("=" * 78)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("SCOPE, corrected after review. Models: durable state, commitment")
    print("exposure, anchored transitions, snapshot and restore-from-snapshot.")
    print("Does NOT model: crash/restart or boot validation (there is no Crash")
    print("action); byte-identical retransmission (Retransmit unions an")
    print("already-present pair, so it is a no-op and its mutation proves")
    print("nothing); partial writes WITHIN one durable record; concurrent")
    print("clones racing the anchor; multiple slots or anchor namespaces;")
    print("anchor outage, reset or wrap.")
    print()
    print("The rule this supports is therefore narrower than 'every durable")
    print("write': anchor every nonce-security transition BEFORE its externally")
    print("observable consequence. Torn records need an immutable WAL record")
    print("plus an external digest compare-and-swap -- a bare counter equality")
    print("cannot reject a record holding a current generation beside stale")
    print("phase bytes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
