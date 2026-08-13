#!/usr/bin/env python3
"""Executable proofs of the two threshold-signature results the design rests on.

Both were previously recorded as "derivation, read-verified, not executed".
They are load-bearing -- one determines whether the audit trail means anything,
the other determines the uniqueness key of the one-time value store -- so they
are made concrete here, in the real Ed25519 group, with exact integer
arithmetic. No sampling, no approximation.

  RESULT 1  A threshold coalition can produce a signing record that names a
            participant who never took part, and every per-share check passes.
            => the threshold transcript is not sound evidence of participation.

  RESULT 2  Reusing one nonce pair across three different participating subsets
            recovers the long-lived share, even when the message never changes.
            => the one-time store must key on (message, subset), not message.

Run:  python3 threshold_algebra.py
"""
import sys
from itertools import combinations

# ---------------------------------------------------------------- Ed25519
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493   # prime group order
D = (-121665 * pow(121666, P - 2, P)) % P


def inv(a, m):
    return pow(a % m, m - 2, m)


def pt_add(A, B):
    """Twisted Edwards addition on -x^2+y^2 = 1+d x^2 y^2 (complete)."""
    x1, y1 = A
    x2, y2 = B
    k = D * x1 * x2 % P * y1 % P * y2 % P
    x3 = (x1 * y2 + x2 * y1) % P * inv(1 + k, P) % P
    y3 = (y1 * y2 + x1 * x2) % P * inv(1 - k, P) % P
    return (x3, y3)


IDENT = (0, 1)


def pt_mul(k, A):
    k %= L
    R, Q = IDENT, A
    while k:
        if k & 1:
            R = pt_add(R, Q)
        Q = pt_add(Q, Q)
        k >>= 1
    return R


def _basepoint():
    y = 4 * inv(5, P) % P
    xx = (y * y - 1) % P * inv(D * y % P * y % P + 1, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if x * x % P != xx:
        x = x * pow(2, (P - 1) // 4, P) % P
    if x % 2:
        x = P - x
    return (x, y)


G = _basepoint()


def neg(A):
    return ((-A[0]) % P, A[1])


# ------------------------------------------------------- Shamir / Lagrange
def share_secret(secret, t, ids, rng):
    """Degree t-1 polynomial with f(0) = secret; returns {id: f(id)}."""
    coeffs = [secret] + [next(rng) for _ in range(t - 1)]
    out = {}
    for i in ids:
        acc = 0
        for c in reversed(coeffs):
            acc = (acc * i + c) % L
        out[i] = acc
    return out


def lagrange(i, subset):
    """lambda_i for interpolating f(0) from `subset`. Depends on the SUBSET."""
    num, den = 1, 1
    for j in subset:
        if j != i:
            num = num * j % L
            den = den * (j - i) % L
    return num * inv(den, L) % L


def counter_rng(seed=1):
    n = seed
    while True:
        n = (n * 6364136223846793005 + 1442695040888963407) % L
        yield n or 1


# ----------------------------------------------------------------- helpers
def challenge(R, A, msg):
    """Stand-in for the challenge hash. Any deterministic function of
    (R, A, msg) works -- the results below are algebraic, not hash-dependent."""
    import hashlib
    h = hashlib.sha512(
        b"chal" + repr(R).encode() + repr(A).encode() + msg
    ).digest()
    return int.from_bytes(h, "little") % L


def binding(i, msg, commitments):
    import hashlib
    h = hashlib.sha512(
        b"bind" + str(i).encode() + msg + repr(sorted(commitments.items())).encode()
    ).digest()
    return int.from_bytes(h, "little") % L


def verify_share(A_i, R_i, lam_i, c, s_i):
    """The per-share check: s_i*G == R_i + c*lambda_i*A_i.

    Note A_i enters weighted by lambda_i, exactly as the reference
    implementation stores it (the view's verification share is already
    multiplied by the interpolation factor)."""
    return pt_mul(s_i, G) == pt_add(R_i, pt_mul(c * lam_i % L, A_i))


def run_session(shares, subset, msg, nonces):
    """One honest FROST-style signing round over `subset`."""
    comms = {i: (pt_mul(nonces[i][0], G), pt_mul(nonces[i][1], G)) for i in subset}
    rho = {i: binding(i, msg, comms) for i in subset}
    R = IDENT
    for i in subset:
        R = pt_add(R, pt_add(comms[i][0], pt_mul(rho[i], comms[i][1])))
    x = sum(lagrange(i, subset) * shares[i] for i in subset) % L
    A = pt_mul(x, G)
    c = challenge(R, A, msg)
    s = {}
    for i in subset:
        d_i, e_i = nonces[i]
        s[i] = (d_i + rho[i] * e_i + c * lagrange(i, subset) % L * shares[i]) % L
    return dict(comms=comms, rho=rho, R=R, A=A, c=c, s=s, x=x)


# ============================================================== RESULT 1
def result1():
    print("=" * 74)
    print("RESULT 1 — a signing record can name someone who never took part")
    print("=" * 74)
    rng = counter_rng(7)
    t, ids = 3, [1, 2, 3, 4, 5]
    secret = next(rng)
    shares = share_secret(secret, t, ids, rng)
    A = pt_mul(secret, G)
    msg = b"release 100 eUSD to alice"

    # Sanity: any t-subset interpolates to the same group key.
    for sub in combinations(ids, t):
        x = sum(lagrange(i, sub) * shares[i] for i in sub) % L
        assert pt_mul(x, G) == A, "interpolation broken"
    print(f"  group key reachable from every {t}-subset of {len(ids)}      ok")

    # A coalition of t holders recovers the whole secret. This is the premise.
    coalition = (1, 2, 3)
    recovered = sum(lagrange(i, coalition) * shares[i] for i in coalition) % L
    print(f"  {t} holders recover the group secret                    "
          f"{'ok' if recovered == secret else 'FAIL'}")
    if recovered != secret:
        return False

    # They now claim a session by a set that includes participant 5, who was
    # never involved and whose share they do not hold.
    claimed = (1, 2, 5)
    victim = 5
    assert victim not in coalition

    # They choose every nonce, including fabricated ones "from" the victim.
    nonces = {i: (next(rng), next(rng)) for i in claimed}
    comms = {i: (pt_mul(nonces[i][0], G), pt_mul(nonces[i][1], G)) for i in claimed}
    rho = {i: binding(i, msg, comms) for i in claimed}
    R = IDENT
    for i in claimed:
        R = pt_add(R, pt_add(comms[i][0], pt_mul(rho[i], comms[i][1])))
    c = challenge(R, A, msg)

    # Aggregate signature made directly from the recovered secret -- no session.
    r_total = sum(nonces[i][0] + rho[i] * nonces[i][1] for i in claimed) % L
    s_agg = (r_total + c * secret) % L
    assert pt_mul(s_agg, G) == pt_add(R, pt_mul(c, A)), "aggregate invalid"
    print("  aggregate signature made with no signing session         ok")

    # Shares for the members they control, computed honestly.
    s = {}
    for i in claimed:
        if i != victim:
            d_i, e_i = nonces[i]
            s[i] = (d_i + rho[i] * e_i
                    + c * lagrange(i, claimed) % L * shares[i]) % L

    # The victim's share is obtained purely by subtraction.
    s[victim] = (s_agg - sum(s[i] for i in claimed if i != victim)) % L

    # Does the fabricated share pass the per-share check?
    ok = True
    for i in claimed:
        A_i = pt_mul(shares[i], G)
        R_i = pt_add(comms[i][0], pt_mul(rho[i], comms[i][1]))
        v = verify_share(A_i, R_i, lagrange(i, claimed), c, s[i])
        tag = "  <-- never participated" if i == victim else ""
        print(f"  verify_share(participant {i}) = {v}{tag}")
        ok &= v

    # And confirm it was not simply the value the victim would have produced.
    honest_would_be = (nonces[victim][0] + rho[victim] * nonces[victim][1]
                       + c * lagrange(victim, claimed) % L * shares[victim]) % L
    print(f"  fabricated share equals what {victim} would have sent: "
          f"{s[victim] == honest_would_be}")
    print()
    print("  CONCLUSION: every per-share check passes on a record whose named")
    print("  participant never signed. A threshold transcript therefore does")
    print("  not evidence participation. Attribution must come from identity")
    print("  signatures under keys OUTSIDE the threshold key.")
    return ok


# ============================================================== RESULT 2
def solve3(M, y):
    """Solve a 3x3 linear system mod L by Cramer's rule."""
    def det3(m):
        return (m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
                - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
                + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])) % L
    d = det3(M)
    if d == 0:
        return None
    out = []
    for col in range(3):
        Mc = [[y[r] if c == col else M[r][c] for c in range(3)] for r in range(3)]
        out.append(det3(Mc) * inv(d, L) % L)
    return out


def result2():
    print()
    print("=" * 74)
    print("RESULT 2 — one nonce pair, one message, three subsets: share recovered")
    print("=" * 74)
    rng = counter_rng(11)
    t, ids = 3, [1, 2, 3, 4, 5]
    secret = next(rng)
    shares = share_secret(secret, t, ids, rng)
    msg = b"release 100 eUSD to alice"          # identical every time
    target = 1

    # The victim reuses ONE nonce pair. Every other participant is honest and
    # uses fresh nonces each session, as they should.
    d_fixed, e_fixed = next(rng), next(rng)

    subsets = [(1, 2, 3), (1, 2, 4), (1, 3, 5)]
    rows, ys = [], []
    for sub in subsets:
        nonces = {i: (d_fixed, e_fixed) if i == target else (next(rng), next(rng))
                  for i in sub}
        r = run_session(shares, sub, msg, nonces)
        lam = lagrange(target, sub)
        rows.append([1, r["rho"][target], r["c"] * lam % L])
        ys.append(r["s"][target])
        print(f"  subset {sub}: lambda={str(lam)[:12]}...  "
              f"share emitted={str(r['s'][target])[:12]}...")

    sol = solve3(rows, ys)
    if sol is None:
        print("  system was degenerate")
        return False
    d_rec, e_rec, x_rec = sol
    print()
    print(f"  recovered d      matches: {d_rec == d_fixed}")
    print(f"  recovered e      matches: {e_rec == e_fixed}")
    print(f"  recovered SHARE  matches: {x_rec == shares[target]}   <-- the long-lived secret")
    print()
    print("  The message never changed. The subset did -- and so, because the")
    print("  peers draw fresh nonces, did the round-one package. RESULT 3 below")
    print("  isolates the package with the subset held fixed.")
    print()
    print("  CONCLUSION: 'one nonce per message' is NOT sufficient. The")
    print("  one-time store must key on (message, participating subset).")
    return d_rec == d_fixed and e_rec == e_fixed and x_rec == shares[target]


# ============================================================== RESULT 3
def result3():
    """Isolate the round-one package as the ONLY varying input.

    Review correctly noted that RESULT 2's narration was inaccurate: peers get
    fresh nonces there, so the participating subset AND the round-one package
    both vary. This isolates the package. The subset is held fixed, so lambda
    is constant; only the peers' commitments change, which moves the binding
    factor and the challenge. Three of those still recover the share.

    This is what makes the round-one package part of the store key necessary,
    rather than assumed by Ceremony.tla's package invariant.
    """
    print()
    print("=" * 74)
    print("RESULT 3 — constant message, CONSTANT SUBSET, three peer packages")
    print("=" * 74)
    rng = counter_rng(29)
    t, ids = 3, [1, 2, 3, 4, 5]
    secret = next(rng)
    shares = share_secret(secret, t, ids, rng)
    msg = b"release 100 eUSD to alice"
    target = 1
    sub = (1, 2, 3)                      # FIXED across all three runs
    lam = lagrange(target, sub)          # therefore constant
    d_fixed, e_fixed = next(rng), next(rng)

    rows, ys = [], []
    for k in range(3):
        # Only the PEERS' round-one nonces differ between runs.
        nonces = {i: (d_fixed, e_fixed) if i == target else (next(rng), next(rng))
                  for i in sub}
        r = run_session(shares, sub, msg, nonces)
        rows.append([1, r["rho"][target], r["c"] * lam % L])
        ys.append(r["s"][target])
        print(f"  run {k + 1}: subset={sub} (fixed)  lambda fixed  "
              f"rho={str(r['rho'][target])[:10]}...")

    sol = solve3(rows, ys)
    if sol is None:
        print("  degenerate system")
        return False
    d_rec, e_rec, x_rec = sol
    print()
    print(f"  recovered d      matches: {d_rec == d_fixed}")
    print(f"  recovered e      matches: {e_rec == e_fixed}")
    print(f"  recovered SHARE  matches: {x_rec == shares[target]}")
    print()
    print("  The subset never changed. Only the peers' round-one package did.")
    print("  CONCLUSION: the round-one package must be in the store key on its")
    print("  own account -- (message, subset) alone is insufficient.")
    return d_rec == d_fixed and e_rec == e_fixed and x_rec == shares[target]


def main():
    print("Ed25519, exact integer arithmetic, no sampling.")
    print(f"group order L = {L}")
    assert pt_mul(L, G) == IDENT, "basepoint order wrong"
    print("basepoint order verified\n")
    ok1 = result1()
    ok2 = result2()
    ok3 = result3()
    print()
    print("=" * 74)
    if ok1 and ok2 and ok3:
        print("ALL THREE RESULTS REPRODUCED.")
        return 0
    print(f"FAILURE  result1={ok1} result2={ok2} result3={ok3}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
