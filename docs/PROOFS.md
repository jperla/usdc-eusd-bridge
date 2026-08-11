# Proofs

Two claims this design rests on have been asserted, argued, and demonstrated by code, but not
*proved*. Both are provable, and proving them changes what we know:

- **Theorem 1** turns "key images don't reveal which output was spent" from a folk claim into a
  reduction to a named hardness assumption — and, more usefully, tells us **exactly who can link and
  who cannot**, which the folk version does not.
- **Theorem 2** generalizes Sol's counterexample from *exhaustive at ring size 3 plus one constructed
  witness at 11* to a theorem for all ring sizes, and adds the quantitative question nobody asked:
  **how fast** does the leak occur.

Notation: prime-order group `𝔾` (Ristretto over Curve25519), order `q`, generator `G`. Hash-to-curve
`Hp : 𝔾 → 𝔾`, modelled as a random oracle. An output has one-time public key `P = xG`; its key image
is `I = x·Hp(P)` (`crypto/ring-signature/src/ring_signature/key_image.rs:22-49`).

---

## Theorem 1 — Linking a key image to its output is exactly DDH

**Claim.** Deciding, for a public output `P` and a public key image `I`, whether `I` is the key image
of `P`, is equivalent to solving Decisional Diffie–Hellman in `𝔾`.

**Proof.**

*(⇒ linking implies solving DDH.)* `Hp(P) ∈ 𝔾` and `𝔾` is cyclic of prime order, so there exists a
unique `h ∈ ℤ_q` with `Hp(P) = hG`. Then

```
P = xG,     Hp(P) = hG,     I = x·Hp(P) = xhG
```

so the tuple `(G, P, Hp(P), I) = (G, xG, hG, xhG)` is a DDH tuple. If instead `I` belongs to a
different output, `I = x'·Hp(P')` for an independent `x'`, and `(G, xG, hG, I)` is a random tuple.
Any algorithm deciding "is `I` the key image of `P`" therefore decides DDH on `(G, xG, hG, I)`.

*(⇐ solving DDH implies linking.)* Given a DDH oracle and a challenge `(G, A, B, C)`, an adversary
can answer the linking question directly: set `A = P`, `B = Hp(P)` — computable publicly, since `Hp`
is a public function of the public `P` — and `C = I`. The oracle's answer is exactly the link.

The reduction is tight in both directions, so the problems are equivalent. ∎

**Corollary 1.1 (the public cannot link).** Under DDH in Ristretto, no public observer can determine
which output a key image consumed, *regardless of what else they know about the output* — including
full knowledge that it belongs to a public bridge-policy pool. Pool membership supplies `P`, and `P`
was already public; it supplies nothing about `x`.

**Corollary 1.2 (who *can* link, and this is the useful part).** The relation `log_G(P) =
log_{Hp(P)}(I)` is exactly a **Chaum–Pedersen** statement. Therefore anyone holding a CP proof for
that pair can link, and — crucially — **that is precisely the artifact the threshold key-image
protocol already produces**: each participant publishes `J_i = b_i·Hp(P)` with a CP proof that
`log_G(B_i) = log_{Hp(P)}(J_i)`.

So the boundary is sharp and asymmetric:

| party | can link key image → output? | why |
|---|---|---|
| public observer | **No** | would require solving DDH |
| the quorum | **Yes** | holds the CP proofs by construction |
| a single warden | **Yes, for the catalog it holds** | same |

**Corollary 1.3 (why the escrow can keep a catalog but the public cannot reconstruct it).** This
resolves an apparent tension in the design: risk C.5 says the quorum cannot read its own balance
without a catalog, while Theorem 1 says nobody can link key images to outputs. Both are true. The
quorum *builds* the catalog from CP proofs it generates; it cannot *derive* it from the chain. Losing
the catalog does not mean the information is publicly recoverable — it means it must be regenerated
by the quorum.

**Corollary 1.4 (this refutes my own earlier analysis, precisely).** The pool-closure computation in
`anonymity.py` assumed an observer can mark specific outputs as spent. By Corollary 1.1 that requires
breaking DDH. The arithmetic is exact; the model is of a different system.

**What this does NOT say.** Theorem 1 concerns *one* `(P, I)` pair in isolation. It says nothing about
information from ring co-membership over time — which is exactly the gap Theorem 2 exploits, and why
Theorem 1 does not rescue unspent-only selection.

---

## Theorem 2 — A public unspent-only decoy rule leaks the real input

**Setting.** Rings `R_1, …, R_n`, each of size `m`, **confirmed** at increasing times. The selection
rule `S` is **public**: every decoy is drawn from outputs unspent at the signer's eligibility
snapshot. Write `real(R)` for the true input of ring `R`.

**Preconditions** (Sol #94, accepted): `R_t` is confirmed before `R_u`'s eligibility snapshot, `R_u`
is accepted and valid, and the selector faithfully enforces `S`. Without these, concurrent
unconfirmed rings may legitimately share a candidate and the lemma fails.

**Lemma 2.1.** If `p ∈ R_t` and `p ∈ R_u` for `u > t`, then `p ≠ real(R_t)`.

*Proof.* Suppose `p = real(R_t)`. **Confirmation** of `R_t` consumes `p`, so `p` is spent at all times
after `R_t` is final. (Sol's correction: *signing* is not enough — concurrent or unconfirmed mempool
rings may legitimately reuse the same then-unspent candidate, so the lemma requires `R_t` confirmed
before `R_u`'s eligibility snapshot, and `R_u` accepted.)
Consider `R_u`. Either `p` is a decoy in `R_u` — impossible, since rule `S` admits only unspent
outputs as decoys and `p` is spent — or `p = real(R_u)`, which would be a double spend and is
rejected by consensus (key-image uniqueness, `validate.rs:63`, `ledger_db.rs:596-598`). Both cases are
contradictory, so `p ≠ real(R_t)`. ∎

**Theorem 2.** If every one of the `m − 1` non-real members of `R_t` reappears in some later ring,
then `real(R_t)` is **uniquely determined**: anonymity for that ring collapses to zero.

*Proof.* By Lemma 2.1 each reappearing member is eliminated. Exactly `m` candidates existed; `m − 1`
are eliminated; the survivor is `real(R_t)`. ∎

**Remark (the inversion).** The theorem's hypothesis is *reappearance*, and the rule `S` is what makes
reappearance informative. Under MobileCoin's actual rule — decoys drawn from **all** outputs, spent or
not — Lemma 2.1 fails at its first step, because a spent output may legitimately appear as a decoy.
**Permitting spent decoys is therefore a privacy feature, not an oversight.** This is the opposite of
what I argued.

**Scope.** The adversary must observe rings. `BlockContents` retains key images, outputs and mint
transactions but **not ordinary transactions** (`blockchain/types/src/block_contents.rs:21-50`), so
rings are not on chain; this requires a mempool observer or a participating node. That bounds *who*,
not *whether*.

---

## The question neither of us asked: how fast?

Theorem 2 is asymptotic. If full elimination needs 10⁶ spends it is a curiosity; if it needs 20 it is
disqualifying. `theorem2_rate.py` computes it exactly — see that file's output. The short version:

**Elimination is fast because it is a coupon-collector process over a small pool.** The first draft
used `H_k/p`, which Sol correctly identified as wrong twice over: it is not the expected maximum of
`k` geometrics, and inclusion events within one ring are **negatively dependent** (sampling without
replacement). Error was 25% at `N=20`.

The exact value, by inclusion–exclusion over the `k = m−1` target decoys:

```
q_j  = C(N-j, s) / C(N, s)                        # a given j-subset entirely missed by one ring
E[T] = Σ_{j=1..k} (-1)^(j+1) · C(k,j) / (1 - q_j)
```

Verified against an independent Markov recurrence (`E[r] = (1 + Σ_j Pr[J=j|r]·E[r-j]) / (1-Pr[J=0|r])`);
the two agree exactly at every `N` tested. Ring size 11:

| pool | exact (s=m) | exact (decoys only) |
|---:|---:|---:|
| 20 | 4.26 | 4.83 |
| 100 | 25.72 | 28.40 |
| 500 | 132.25 | 145.58 |
| 5000 | 1330.47 | 1463.62 |

**Model caveats, accepted from Sol #94:** static pool, complete visibility of accepted rings, uniform
sampling, and an explicit choice of whether the later real input is among the uniform draws. Pool
churn, input demand, multi-input selection, retry correlation and partial observation coverage are
not modelled. **"Disqualifying" is therefore justified relative to the named ring-observing
adversary, not absolutely.**

---

## Status

| | proved | machine-checked | assumption |
|---|---|---|---|
| Theorem 1 | yes, tight reduction | — | DDH in Ristretto; `Hp` a random oracle |
| Corollaries 1.1–1.4 | yes | — | as above |
| Lemma 2.1 | yes | exhaustive, see below | rule `S` public and correctly implemented |
| Theorem 2 | yes | exhaustive, see below | as above |
| Rate | exact under a static-pool model | yes, two independent derivations agree | static pool, full ring visibility, uniform sampling |

**Not proved and still open:** that exchangeability holds *jointly* over every observable feature
(age, amount, provenance, timing, multi-input co-spending). Theorem 2 is a single leak channel; ruling
out the others is a much larger statement that neither of us has attempted, and permutation invariance
alone is insufficient for it — Sol's point, and correct.
