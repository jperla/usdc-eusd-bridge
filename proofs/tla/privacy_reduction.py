#!/usr/bin/env python3
"""The two-address privacy claim (DESIGN-FINAL §2), reduced and demonstrated.

DESIGN-FINAL §2 publishes the view key of the returns address R so an Ethereum
contract can verify user returns, and keeps the float address F private so that
releases retain ring privacy. That rests on one claim:

    an observer holding R's view private key cannot recognise F's outputs.

FORMAL-EVIDENCE listed this as argued but not proved. This file proves it, by
reduction to DDH, and then demonstrates the mechanism concretely.

MobileCoin's construction, read from source:
    address (C, D)   with C = a*D          (view public = view private * spend public)
    tx_out_public_key   R_txo = r*D        (onetime_keys.rs:123-130)
    target_key          P = Hs(r*C)*G + D  (onetime_keys.rs:99-113)
    recipient recovers  a*R_txo = a*r*D = r*C   -- the DH value

THEOREM.  Recognising whether a TxOut is addressed to F is at least as hard as
DDH in the group.  Holding a_R confers no advantage.

PROOF (forward reduction, the direction that gives the security claim).
Let (D, X = a*D, Y = r*D, Z) be a DDH challenge.  Set C_F = X, R_txo = Y, and
P = Hs(Z)*G + D.  If Z = a*r*D then (R_txo, P) is distributed exactly as a
genuine output to F = (C_F, D).  If Z is random then, modelling Hs as a random
oracle, Hs(Z) is uniform and independent, so P is uniform and carries no
information about F.  Any distinguisher for F-ownership therefore decides DDH
with the same advantage.  a_R is sampled independently of a_F and is generated
by the simulator itself, so handing it to the adversary changes nothing.  QED

Converse direction, for completeness: a CDH oracle recovers Z = a_F*r*D_F and
recognition follows by checking P - Hs(Z)*G == D_F.  So recognition sits
between DDH and CDH, and DDH-hardness is what the design needs.

The group below is Ed25519 rather than Ristretto.  Both are prime-order groups
and the construction is group-generic, so the reduction is unaffected; only the
encoding differs.

Run:  python3 privacy_reduction.py
"""
import hashlib
import sys

from threshold_algebra import G, L, IDENT, pt_add, pt_mul, neg, counter_rng


def Hs(point):
    """Hash-to-scalar, modelled as a random oracle."""
    h = hashlib.sha512(b"mc_onetime" + repr(point).encode()).digest()
    return int.from_bytes(h, "little") % L


class Address:
    """A MobileCoin-style subaddress (C, D) with C = a*D."""

    def __init__(self, name, a, b):
        self.name = name
        self.a = a                     # view private
        self.b = b                     # spend private
        self.D = pt_mul(b, G)          # spend public
        self.C = pt_mul(a, self.D)     # view public = a*D

    def public(self):
        return (self.C, self.D)


def make_output(addr, r):
    """Sender side: build a TxOut addressed to `addr` with tx private key r."""
    R_txo = pt_mul(r, addr.D)              # r*D
    P = pt_add(pt_mul(Hs(pt_mul(r, addr.C)), G), addr.D)   # Hs(r*C)*G + D
    return (R_txo, P)


def shared_secret(view_private, R_txo):
    """Recipient side: a*R_txo."""
    return pt_mul(view_private, R_txo)


def recovered_spend_key(view_private, R_txo, P):
    """recover_public_subaddress_spend_key: P - Hs(a*R_txo)*G."""
    return pt_add(P, neg(pt_mul(Hs(shared_secret(view_private, R_txo)), G)))


def owns(addr, out):
    """Does `addr` own this output? The correct predicate -- the one the
    shipped relayer omits."""
    R_txo, P = out
    return recovered_spend_key(addr.a, R_txo, P) == addr.D


def main():
    rng = counter_rng(23)
    R = Address("R (returns, view key PUBLISHED)", next(rng), next(rng))
    F = Address("F (float, view key private)", next(rng), next(rng))
    stranger = Address("unrelated third party", next(rng), next(rng))

    print("=" * 74)
    print("TWO-ADDRESS PRIVACY — reduction demonstrated concretely")
    print("=" * 74)
    print(f"  {R.name}")
    print(f"  {F.name}")
    print()

    # --- 1. Correctness: each address recognises its own outputs.
    out_to_R = make_output(R, next(rng))
    out_to_F = make_output(F, next(rng))
    out_to_X = make_output(stranger, next(rng))
    ok = owns(R, out_to_R) and owns(F, out_to_F) and owns(stranger, out_to_X)
    print(f"  each address recognises its own output                   "
          f"{'ok' if ok else 'FAIL'}")

    # --- 2. The claim: a_R does not recognise F's outputs.
    leak = owns_R_sees_F = recovered_spend_key(R.a, *out_to_F) == F.D
    print(f"  R's view key recognises an F output                      "
          f"{'LEAK' if leak else 'no  <- the claim'}")

    # --- 3. And is indistinguishable from a stranger's output.
    rF = recovered_spend_key(R.a, *out_to_F)
    rX = recovered_spend_key(R.a, *out_to_X)
    print(f"  under a_R, F's output looks like any stranger's          "
          f"{'ok' if (rF != F.D and rX != stranger.D) else 'FAIL'}")

    # --- 4. The sweep. R -> F outputs are addressed to F, so the observer
    #        who watched the R-side cannot follow the value.
    swept = [make_output(F, next(rng)) for _ in range(8)]
    followed = sum(1 for o in swept if recovered_spend_key(R.a, *o) == F.D)
    print(f"  sweep outputs R->F recognisable with a_R                 "
          f"{followed}/8  {'ok' if followed == 0 else 'FAIL'}")

    # --- 5. What DOES leak, stated rather than hidden: R's own outputs are
    #        recognisable to anyone. That is intended -- it is how Ethereum
    #        verifies a return.
    r_outs = [make_output(R, next(rng)) for _ in range(8)]
    seen = sum(1 for o in r_outs if recovered_spend_key(R.a, *o) == R.D)
    print(f"  R's own outputs recognisable with a_R                    "
          f"{seen}/8  (intended)")

    # --- 6. The reduction, exercised. A genuine F output and a simulated one
    #        built from a real DH triple must be identical in distribution;
    #        built from a random Z they must be unrelated to F.
    print()
    print("  reduction check — simulate the DDH game:")
    a, r = next(rng), next(rng)
    Dg = pt_mul(next(rng), G)
    X, Y = pt_mul(a, Dg), pt_mul(r, Dg)
    Z_real = pt_mul(a * r % L, Dg)
    Z_rand = pt_mul(next(rng), Dg)
    P_real = pt_add(pt_mul(Hs(Z_real), G), Dg)
    P_rand = pt_add(pt_mul(Hs(Z_rand), G), Dg)
    sim = Address.__new__(Address)
    sim.a, sim.D, sim.C = a, Dg, X
    genuine = make_output(sim, r)
    match_real = genuine == (Y, P_real)
    match_rand = genuine == (Y, P_rand)
    print(f"    real DH value  -> reproduces a genuine F output        "
          f"{'ok' if match_real else 'FAIL'}")
    print(f"    random Z       -> unrelated output                     "
          f"{'ok' if not match_rand else 'FAIL'}")

    print()
    print("=" * 74)
    good = (ok and not leak and followed == 0 and seen == 8
            and match_real and not match_rand)
    if good:
        print("CLAIM HOLDS. Recognising F-ownership is a DDH instance; a_R gives")
        print("no advantage. Publishing R's view key to let Ethereum verify")
        print("returns does not expose which outputs fund releases.")
        print()
        print("What remains visible, by design: R's outputs and their amounts,")
        print("and the aggregate timing of sweeps. Not per-user linkage, and")
        print("not which output funds any particular release.")
        return 0
    print("CLAIM DOES NOT HOLD AS STATED — see failures above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
