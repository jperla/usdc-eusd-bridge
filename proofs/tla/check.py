#!/usr/bin/env python3
"""
Exhaustive state-space checker mirroring BridgeEscrow.tla.

This exists because no JVM is installed, so TLC cannot run here. It is NOT a
substitute for TLC -- it is a pre-flight check that the state machine logic and
the bug switches behave as documented, so we hand over a validated spec rather
than merely a written one.

If this and TLC ever disagree, that disagreement is the most interesting result
in the directory and should be chased down before trusting either.

Usage:
    ./check.py            # baseline + all four bug configs
    ./check.py --verbose  # print a counterexample trace for each violation
"""
import argparse
import itertools
from collections import deque

# --- model constants, matching BridgeEscrow.cfg ------------------------------
OPERATORS = frozenset({"o1", "o2", "o3", "o4", "o5"})
SOURCE_EVENTS = ("e1", "e2")
ESCROW_OUTPUTS = frozenset({"x1", "x2"})
PLAIN_OUTPUTS = frozenset({"p1"})
ALL_OUTPUTS = ESCROW_OUTPUTS | PLAIN_OUTPUTS
NO_OUTPUT = None
K_W = 3      # > K_F and K_OWN so the certificate can be the binding gate,
K_F = 2      # but with headroom: K_W = n would let one expulsion brick the bridge
K_OWN = 2
MAX_EPOCH = 2


class Bugs:
    def __init__(self, cert=False, nullifier=False, rotate=False, legacy=False,
                 epoch=False):
        self.cert = cert            # BUG_OptionalCertificate
        self.nullifier = nullifier  # BUG_NoNullifier
        self.rotate = rotate        # BUG_RotateOwnership
        self.legacy = legacy        # BUG_LegacyPathOpen
        self.epoch = epoch          # BUG_NoEpochCheck


# --- state -------------------------------------------------------------------
# (epoch, unspent, keyImages, nullifiers, fundedBy, paused, expelled, slashed,
#  verdicts, finalized)   -- all sets are frozensets; fundedBy is a tuple
# indexed parallel to SOURCE_EVENTS; verdicts is a frozenset of (claim, kind).

def init():
    gate = tuple(frozenset(OPERATORS) if e == 0 else frozenset()
                 for e in range(MAX_EPOCH + 1))
    return (0, frozenset(ALL_OUTPUTS), frozenset(), frozenset(),
            frozenset(), False, frozenset(),
            frozenset(), frozenset(), frozenset(), gate)


def active(expelled):
    return OPERATORS - expelled


def can_certify(st):
    return len(active(st[6])) >= K_W


def can_gate_at(st, e):
    """Gate capability is PER EPOCH and deliberately not restricted to Active:
    an expelled coalition still holds the gate key of the epoch it was expelled
    from. Rotation issues a new key; it cannot retract the old one."""
    return len(st[10][e]) >= K_F


def can_own(st, bugs):
    """Expelled operators RETAIN K_own shares -- expulsion removes a name, not
    key material. With BUG_RotateOwnership, rotation mints a fresh ownership key
    that cannot generate pre-rotation outputs' key images at all."""
    if bugs.rotate and st[0] > 0:
        return False
    return len(active(st[6])) >= K_OWN


def resolved(verdicts, claim):
    return any(c == claim for c, _ in verdicts)


# --- actions -----------------------------------------------------------------
def successors(st, bugs):
    epoch, unspent, kimgs, nulls, releases, paused, expelled, slashed, verdicts, final, gate = st
    out = []

    # FinalizeDeposit
    if not paused:
        for e in SOURCE_EVENTS:
            if e not in final:
                out.append(("FinalizeDeposit(%s)" % e,
                            (epoch, unspent, kimgs, nulls, releases, paused,
                             expelled, slashed, verdicts, final | {e}, gate)))

    # EscrowRelease -- all four gates
    if not paused:
        for o in sorted(unspent & ESCROW_OUTPUTS):
            for e in sorted(final):
                for ae in range(epoch + 1):          # authorization epoch
                    if not can_own(st, bugs):
                        continue
                    if not can_gate_at(st, ae):
                        continue
                    # consensus must require the authorization epoch to be current
                    if not (ae == epoch or bugs.epoch):
                        continue
                    cert = can_certify(st)
                    if not (cert or bugs.cert):
                        continue
                    if not (bugs.nullifier or e not in nulls):
                        continue
                    stale = ae != epoch
                    tags = ("" if cert else ",UNCERTIFIED") + (",STALE" if stale else "")
                    out.append(("EscrowRelease(%s<-%s@e%d%s)" % (e, o, ae, tags),
                                (epoch, unspent - {o}, kimgs | {o},
                                 nulls if bugs.nullifier else nulls | {e},
                                 releases | {(e, o, cert, stale)},
                                 paused, expelled, slashed, verdicts, final, gate)))

    # LegacySpend -- ordinary path, ownership only
    if not paused:
        for o in sorted(unspent):
            if not (o in PLAIN_OUTPUTS or (o in ESCROW_OUTPUTS and bugs.legacy)):
                continue
            if not can_own(st, bugs):
                continue
            out.append(("LegacySpend(%s)" % o,
                        (epoch, unspent - {o}, kimgs | {o}, nulls, releases,
                         paused, expelled, slashed, verdicts, final, gate)))

    # RejectInadmissible -- no verdict, no slash, no pause (self-loop, skipped)

    # BlameOperator -- slash, expel, pause, rotate
    if not paused and epoch < MAX_EPOCH:
        for c in SOURCE_EVENTS:
            if resolved(verdicts, c) or c not in final:
                continue
            act = active(expelled)
            for r in range(1, len(act) + 1):
                for culprits in itertools.combinations(sorted(act), r):
                    cs = frozenset(culprits)
                    # the new epoch's gate key goes ONLY to the surviving roster
                    ng = list(gate); ng[epoch + 1] = frozenset(act - cs)
                    out.append(("BlameOperator(%s,%s)" % (c, ",".join(culprits)),
                                (epoch + 1, unspent, kimgs, nulls, releases, True,
                                 expelled | cs, slashed | cs,
                                 verdicts | {(c, "op")}, final, tuple(ng))))

    # BlameChallenger -- slash challenger, DO NOT pause
    if not paused:
        for c in SOURCE_EVENTS:
            if resolved(verdicts, c) or c not in final:
                continue
            for ch in sorted(active(expelled)):
                out.append(("BlameChallenger(%s,%s)" % (c, ch),
                            (epoch, unspent, kimgs, nulls, releases, paused,
                             expelled, slashed | {ch},
                             verdicts | {(c, "chal")}, final, gate)))

    # Resume
    if paused:
        out.append(("Resume",
                    (epoch, unspent, kimgs, nulls, releases, False, expelled,
                     slashed, verdicts, final, gate)))

    return out


# --- invariants --------------------------------------------------------------
def invariants(st, bugs):
    epoch, unspent, kimgs, nulls, releases, paused, expelled, slashed, verdicts, final, gate = st
    certified = frozenset(o for (_, o, c, _) in releases if c)
    bad = []

    if not (unspent <= ALL_OUTPUTS and kimgs <= ALL_OUTPUTS):
        bad.append("TypeOK")
    # NoBypass: every consumed escrow output was released WITH a certificate.
    # Tracked, not inferred -- inferring it from the citing event misses an
    # uncertified release entirely.
    if not (kimgs & ESCROW_OUTPUTS) <= certified:
        bad.append("NoBypass")
    # NoDoubleRelease: no source event funds two releases.
    for e in SOURCE_EVENTS:
        if len([r for r in releases if r[0] == e]) > 1:
            bad.append("NoDoubleRelease")
            break
    if unspent & kimgs:
        bad.append("NoDoubleSpend")
    # NoStaleAuthorization: no release authorized under a retired gate key.
    # The containment property that justifies the two-key split.
    if any(stale for (_, _, _, stale) in releases):
        bad.append("NoStaleAuthorization")
    # RotationSound: if enough operators remain to meet the OWNERSHIP threshold,
    # ownership must remain exercisable. Rotating the gate key must not strand
    # pre-rotation outputs. Deliberately independent of the certificate and gate
    # thresholds -- coupling them made this vacuous after any expulsion.
    if len(active(expelled)) >= K_OWN and not can_own(st, bugs):
        bad.append("RotationSound")
    for c in SOURCE_EVENTS:
        if (c, "op") in verdicts and (c, "chal") in verdicts:
            bad.append("BlameExclusive")
            break
    if paused and not any(k == "op" for _, k in verdicts):
        bad.append("ContainmentOK")
    if slashed and not verdicts:
        bad.append("NoSlashUnproven")
    if len(releases) > len(final):
        bad.append("Solvency")
    if any(e not in final for (e, _, _, _) in releases):
        bad.append("CitesOnlyFinalized")
    return bad


# --- exhaustive BFS ----------------------------------------------------------
def check(bugs, verbose=False):
    start = init()
    seen = {start: None}
    q = deque([start])
    violations = {}
    while q:
        st = q.popleft()
        for v in invariants(st, bugs):
            if v not in violations:
                violations[v] = st
        for label, nxt in successors(st, bugs):
            if nxt not in seen:
                seen[nxt] = (st, label)
                q.append(nxt)
    if verbose:
        for v, st in violations.items():
            trace = []
            cur = st
            while seen.get(cur):
                prev, label = seen[cur]
                trace.append(label)
                cur = prev
            print("      trace to %s: %s" % (v, " -> ".join(reversed(trace)) or "<initial>"))
    return len(seen), violations


CONFIGS = [
    ("baseline",       Bugs(),                  set()),
    ("bug-legacy",     Bugs(legacy=True),       {"NoBypass"}),
    ("bug-cert",       Bugs(cert=True),         {"NoBypass"}),
    ("bug-nullifier",  Bugs(nullifier=True),    {"NoDoubleRelease", "Solvency"}),
    ("bug-rotate",     Bugs(rotate=True),       {"RotationSound"}),
    ("bug-epoch",      Bugs(epoch=True),        {"NoStaleAuthorization"}),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    print("Exhaustive check of BridgeEscrow state machine")
    print("(mirror of BridgeEscrow.tla -- not a substitute for TLC)\n")
    ok = True
    for name, bugs, expected in CONFIGS:
        states, viol = check(bugs, args.verbose)
        found = set(viol)
        if name == "baseline":
            passed = not found
            detail = "clean" if passed else "UNEXPECTED: %s" % sorted(found)
        else:
            # the switch must break at least one expected invariant
            passed = bool(found & expected)
            if not found:
                detail = "NO VIOLATION -- spec too weak to catch this defect"
            else:
                detail = "violates %s" % sorted(found)
                if not (found & expected):
                    detail += " but expected one of %s" % sorted(expected)
        ok = ok and passed
        print("  %-14s %7d states  %-6s %s"
              % (name, states, "PASS" if passed else "FAIL", detail))

    print()
    if ok:
        print("All configs behaved as documented: baseline clean, every bug switch bites.")
        print("Next: run the same configs under TLC once a JVM is available.")
    else:
        print("MISMATCH with README.md. Fix the spec (or the documented expectation).")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
