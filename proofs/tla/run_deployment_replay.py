#!/usr/bin/env python3
"""Independent finite model of authenticated deployment domains and replay."""
import sys
import tempfile
from pathlib import Path

from tlc_harness import CLEAN, VIOLATED, ERROR, HERE, expect, run

MODULE = "DeploymentReplay.tla"
GUARDS = ["GuardAuthenticatedDomain", "GuardRejectLegacy", "GuardChain",
          "GuardEscrow", "GuardNamespace", "GuardReplay"]
INVARIANTS = ["INV_OnlyIntendedDeployment", "INV_OnlyBoundMemos", "INV_AtMostOnePayout"]
BREAKS = {
    "GuardAuthenticatedDomain": {INVARIANTS[0], INVARIANTS[2]},
    "GuardRejectLegacy": set(INVARIANTS),
    "GuardChain": {INVARIANTS[0], INVARIANTS[2]},
    "GuardEscrow": {INVARIANTS[0], INVARIANTS[2]},
    # Namespace-only changes retain the chain+escrow replay registry.
    "GuardNamespace": {INVARIANTS[0]},
    "GuardReplay": {INVARIANTS[2]},
}


def config(work, name, invariant=None, off=None):
    lines = ["SPECIFICATION Spec", "CONSTANTS", "Outputs = {o1, o2}",
             "Chains = {c1, c2}", "Escrows = {e1, e2}", "Namespaces = {n1, n2}"]
    lines += [f"{g} = {'FALSE' if g == off else 'TRUE'}" for g in GUARDS]
    lines += ["INVARIANT TypeOK"]
    lines += [f"INVARIANT {i}" for i in ([invariant] if invariant else INVARIANTS)]
    path = work / f"{name}.cfg"
    path.write_text("\n".join(lines) + "\n")
    return path


def main():
    errors = []
    with tempfile.TemporaryDirectory(prefix="deployment-replay-") as raw:
        work = Path(raw)
        r = run(MODULE, config(work, "baseline"))
        print(f"BASELINE: {r}")
        if r.status != CLEAN:
            errors.append(f"baseline: {r}")
        for cov in ["COV_CanPay", "COV_DistinctDestinationsPay", "COV_RelayTagIrrelevant"]:
            r = expect(MODULE, config(work, cov, cov), cov)
            print(f"COVERAGE {cov}: {r}")
            if r.status != VIOLATED:
                errors.append(f"{cov}: {r}")

        for guard in GUARDS:
            results = {inv: expect(MODULE, config(work, f"{guard}-{inv}", inv, guard), inv)
                       for inv in INVARIANTS}
            broken = {inv for inv, r in results.items() if r.status == VIOLATED}
            print(f"MUTATION {guard}: {sorted(broken)}")
            if broken != BREAKS[guard] or any(r.status == ERROR for r in results.values()):
                errors.append(f"{guard}: expected {BREAKS[guard]}, got {results}")

        # Keep every boolean true; substitute the relay tag into the actual
        # comparison so a constants-only assertion cannot catch this for us.
        source = (HERE / MODULE).read_text()
        old = "PresentedDomain(o, tag) = ExpectedDomain(d)"
        if source.count(old) != 1:
            errors.append("source mutation target changed")
        else:
            mutant = work / "DeploymentReplayRelayTag.tla"
            mutant.write_text(source.replace("MODULE DeploymentReplay ",
                                              "MODULE DeploymentReplayRelayTag ")
                              .replace(old, "tag = ExpectedDomain(d)"))
            inv = "INV_OnlyIntendedDeployment"
            r = expect(str(mutant), config(work, "source-mutation", inv), inv)
            print(f"SOURCE MUTATION: {r}")
            if r.status != VIOLATED:
                errors.append(f"source mutation: {r}")
    if errors:
        print("FAIL\n  " + "\n  ".join(errors))
        return 1
    print("PASS: authenticated chain/escrow/namespace, legacy refusal and replay checked.")
    print("Scope: two outputs, two chains, two escrows and two namespaces; one")
    print("persistent registry per chain+escrow. Hash/memo authentication is assumed.")
    print("This is independent design evidence, not Solidity implementation refinement.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
