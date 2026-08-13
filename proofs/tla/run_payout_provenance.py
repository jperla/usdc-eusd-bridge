#!/usr/bin/env python3
"""Every value the payout reads must be pinned by the authenticated output.

ClaimAcceptance.tla scoped itself out of this and said so in its header: "the
memo codec is NOT modelled, so 'the output names a beneficiary' is an
ASSUMPTION rather than a result." That assumption was never discharged, and
the implementation shipped with amount, token id and beneficiary all supplied
by the relayer. This runner discharges it: each field is switched off in turn,
and switching any one off must break the property.
"""
import sys
from tlc_harness import CLEAN, VIOLATED, HERE, expect, run

MODULE = "PayoutProvenance.tla"

FIELDS = ["DeriveAmount", "DeriveTokenId", "DerivePayee"]

INVARIANTS = ["INV_PayoutPinnedByOutput", "INV_OneOutputOneOutcome"]

# Which invariant each field is responsible for. A field switched off must
# break exactly this one -- if it breaks a different invariant, the model is
# not measuring what its name says.
PROTECTS = {
    "DeriveAmount":  "INV_PayoutPinnedByOutput",
    "DerivePayee":   "INV_PayoutPinnedByOutput",
    "DeriveTokenId": "INV_PayoutPinnedByOutput",
}

WHY = {
    "DeriveAmount":
        "one authenticated output redeems for any value the submitter names",
    "DerivePayee":
        "one authenticated output redeems to anyone the submitter names",
    "DeriveTokenId":
        "an unbound token id routes a payout through the wrong asset",
}


def write_cfg(name, off=None, invariants=None):
    lines = [
        "SPECIFICATION Spec",
        "CONSTANTS",
        "    Outputs = {o1, o2}",
        "    Values = {v1, v2}",
        "    Tokens = {eusd, other}",
        "    Payees = {alice, mallory}",
    ]
    for f in FIELDS:
        lines.append(f"    {f} = {'FALSE' if f == off else 'TRUE'}")
    for i in (invariants or INVARIANTS):
        lines.append(f"INVARIANT {i}")
    p = HERE / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []

    print("=" * 78)
    print("BASELINE -- every field derived from the output")
    print("=" * 78)
    cfg = write_cfg("PayoutProvenance")
    st = run(MODULE, cfg)
    print(f"  {st.status} ({st.states} states)" + (f" {st.detail}" if st.detail else ""))
    if st.status is not CLEAN:
        fails.append("baseline is not clean")

    print()
    print("=" * 78)
    print("COVERAGE -- the model must actually reach a payout")
    print("=" * 78)
    # COV_CanPay asserts nothing is ever paid. It MUST be violated, or every
    # invariant above is vacuous and this whole file proves nothing.
    cfg = write_cfg("PayoutProvenance-cov", invariants=["COV_CanPay"])
    cov = expect(MODULE, cfg, "COV_CanPay")
    ok = cov.status == VIOLATED
    print(f"  reaches a payout: {'yes' if ok else 'NO -- ' + str(cov.status)}"
          + (f" {cov.detail}" if cov.detail else ""))
    if not ok:
        fails.append("COV_CanPay was not violated; the model never pays")

    print()
    print("=" * 78)
    print("MUTATION -- switch each field to relayer-supplied")
    print("=" * 78)
    for f in FIELDS:
        want = PROTECTS[f]
        cfg = write_cfg(f"PayoutProvenance-off-{f}", off=f)
        r = expect(MODULE, cfg, want)
        ok = r.status == VIOLATED
        print(f"  {f:<14} off -> {want:<28} "
              f"{'BREAKS (good)' if ok else 'SURVIVES/ERROR -- ' + str(r.status)}"
              + (f" {r.detail}" if r.detail else ""))
        print(f"                 {WHY[f]}")
        if not ok:
            fails.append(f"{f} is not load-bearing for {want}")

    print()
    print("=" * 78)
    if fails:
        print("FAIL")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("PASS -- each field is load-bearing, and the model reaches a payout")
    print()
    print("Scope: this is PROVENANCE, not cryptography. Whether the Solidity's")
    print("Blake2b / HKDF / Pedersen opening agrees with MobileCoin is a")
    print("differential question and is tested in contracts/test against")
    print("fixtures its own crates generated. This says only that every field")
    print("the payout reads is a function of the authenticated output -- which")
    print("is the assumption ClaimAcceptance.tla parked and did not discharge.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
