#!/usr/bin/env python3
"""Who gets paid, how often, and in what order.

The return leg is permissionless by design — anyone may relay a proof. That
makes three things load-bearing, and each is mutation-tested here.
"""
import sys
from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, matrix, run

MODULE = "ClaimAcceptance.tla"

# GuardRevertOnFailure is a CONSTANT the spec still takes, but it is not in
# the established set: its property is not derivable from state here.
GUARDS = ["GuardBeneficiaryFromOutput", "GuardStableClaimId",
          "GuardConsumeBeforeCall"]
ALL_GUARDS = GUARDS + ["GuardRevertOnFailure"]

# INV_NoStrandedClaims is deliberately NOT here. It is a synthetic oracle --
# the same guard introduces the bug and sets the flag that detects it -- so a
# broken rollback escapes it. Quarantined below rather than counted as passing.
INVARIANTS = ["INV_PaidOnlyNamedBeneficiary", "INV_AtMostOnePayout",
              "INV_PendingImpliesConsumed"]

KNOWN_UNPROVED = [
    ("INV_NoStrandedClaims",
     "synthetic oracle: the guard both introduces the bug and sets the "
     "detecting flag; a broken rollback escapes it"),
    ("COV_CanRevert",
     "does not cover ReturnFailure -- its first violation is a pending call, "
     "before any failure has occurred"),
]

PROTECTS = {
    "GuardBeneficiaryFromOutput": "INV_PaidOnlyNamedBeneficiary",
    "GuardStableClaimId": "INV_AtMostOnePayout",
    "GuardConsumeBeforeCall": "INV_PendingImpliesConsumed",

}

WHY = {
    "GuardBeneficiaryFromOutput":
        "paying msg.sender turns the permissionless relay path into a theft path",
    "GuardStableClaimId":
        "keying the registry by epoch/mode permits one payout PER namespace",
    "GuardConsumeBeforeCall":
        "calling before consuming leaves the claim open to a re-entrant payout",

}


def write_cfg(name, off=None, invariants=None):
    lines = [
        "SPECIFICATION Spec",
        "CONSTANTS",
        "    Outputs = {o1, o2}",
        "    Beneficiaries = {alice, bob}",
        "    Relayers = {mallory}",
        "    Epochs = {e1, e2}",
        "    Modes = {m1, m2}",
    ]
    for g in ALL_GUARDS:
        lines.append(f"    {g} = {'FALSE' if g == off else 'TRUE'}")
    lines.append("INVARIANT TypeOK")
    for i in (invariants or INVARIANTS):
        lines.append(f"INVARIANT {i}")
    p = HERE / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []
    print("=" * 78)
    print("BASELINE — all guards on")
    print("=" * 78)
    r = run(MODULE, write_cfg("ClaimAcceptance"))
    print(f"  {r}")
    if r.status != CLEAN:
        fails.append(f"baseline: {r}")

    print()
    print("=" * 78)
    print("COVERAGE — written to FAIL")
    print("=" * 78)
    for cov, off in [("COV_CanPay", None), ("COV_CanPend", None),
                     ("COV_CanRotate", None), ("COV_CanUpgrade", None),
                     ("COV_ConsumedPend", None)]:
        c = expect(MODULE, write_cfg(f"_cacov_{cov}", off=off,
                                     invariants=[cov]), cov)
        alive = c.status == VIOLATED
        tag = "" if off is None else f"  (with {off} off)"
        print(f"  {cov:<18} {'reachable' if alive else 'UNREACHABLE'}   {c}{tag}")
        if not alive:
            fails.append(f"{cov} unreachable")

    print()
    print("=" * 78)
    print("MUTATIONS — each invariant in its own run")
    print("=" * 78)
    for g in GUARDS:
        res = matrix(MODULE, write_cfg, INVARIANTS, off=g)
        errs = sorted(k for k, v in res.items() if v.status == ERROR)
        if errs:
            print(f"  {g:<32} TOOL ERROR on {errs}")
            fails.append(f"{g}: tool error")
            continue
        broke = sorted(k for k, v in res.items() if v.status == VIOLATED)
        want = PROTECTS[g]
        ok = (not broke) if want is None else (want in broke)
        print(f"  {g:<32} {'ok' if ok else 'FAIL'}  breaks {broke or 'nothing'}")
        print(f"  {'':<32} {WHY[g]}")
        if not ok:
            fails.append(f"{g}: expected {want}, broke {broke}")

    print()
    print("=" * 78)
    print("KNOWN UNPROVED — deliberately excluded from the evidence above.")
    print("These are NOT failures and NOT passes; they are checks that were")
    print("found not to establish what they appeared to.")
    print("=" * 78)
    for name, why in KNOWN_UNPROVED:
        print(f"  {name}")
        print(f"      {why}")
    print()
    print("  Consequence: THREE guards are established here, not four.")
    print("  Rollback and retry availability remain PENDING, and need an")
    print("  independent failure-history record plus a retry trace.")

    print()
    print("=" * 78)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("READING: THREE guards are established here. The beneficiary guard")
    print("is the one that turns a")
    print("design feature into a vulnerability: because anyone may relay a")
    print("proof, paying the submitter lets a watcher take someone else's")
    print("redemption by submitting their proof first. The claim-id and CEI")
    print("guards prevent double payment. The revert guard is NOT established")
    print("-- see KNOWN UNPROVED above.")
    print()
    print("SCOPE, corrected after review. Injective BeneficiaryOf is a TEST")
    print("FIXTURE, not a protocol requirement -- multiple outputs may")
    print("legitimately name the same beneficiary; the protocol property is")
    print("immutable per-output decoding. Claim identity is stable across")
    print("epoch and mode, and pending.key is captured at validation so a")
    print("rotation mid-call cannot drift the namespace. Re-entrancy is scoped")
    print("to the pending claim. NOT modelled: amounts, partial fills, the memo")
    print("codec, gas, or two independent contract deployments -- upgrade is a")
    print("mode change over ONE registry. So 'the output names a beneficiary'")
    print("remains an assumption: finalized bytes establish an Ethereum")
    print("address only after schema, decryption, domain and canonical-address")
    print("checks succeed, and none of those are here.")
    print()
    print("NOT PROVED, and do not cite it as such: rollback and retry")
    print("availability. COV_CanRevert does not actually cover ReturnFailure --")
    print("its first violation is a pending call, before any failure -- and")
    print("INV_NoStrandedClaims is a synthetic oracle in which the same guard")
    print("both introduces the bug and sets the flag that detects it. A broken")
    print("rollback escapes it. That needs an observed-failure record derived")
    print("from state, independent of the guard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
