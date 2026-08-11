# USDC ↔ eUSD Bridge — plan summary

---

# Three questions only you can answer

I checked each open item against "could a technical reviewer settle this?" Most could, and
those are listed in the next section so you don't spend time on them. These three cannot be
settled by anyone else, because they are about **who you trust and what you are willing to
give up** — not about cryptography.

### Q1. Who holds the gate keys, and are they genuinely independent of the operators?

The design's answer to "a compromised operator quorum steals the float" is a **composite spend
key**: releasing funds needs *k of n operators* **and** *g of m gates*. We proved that works —
the gate's contribution enters the key image, so consensus rejects a release without it. There
is nothing for a coordinator to quietly skip.

**But it is worth exactly as much as the gates' independence.** Model-checking shows that gates
under operator control sign straight through a pause, and the composite key buys nothing at all.
So: different people, different organization, different failure domain — or the mechanism is
decoration.

### Q2. Are you willing to give up operator-only recovery?

This is the uncomfortable one, and it is a genuine trade rather than a detail.

**Any path that lets the operators recover funds without the gates nullifies the gates.** If
such a path exists, a compromised quorum uses it. So the gate only works if losing the gate keys
means losing the money.

That has to be a deliberate choice. The alternative is keeping a recovery path and accepting
that the gate is advisory — which is a coherent position, just not the one the design currently
assumes.

### Q3. Where does the float come from, how much, and is the incumbent eUSD issuer you?

The bridge holds and releases **existing** eUSD; it does not create it. So someone has to acquire
the starting balance, and that number caps the maximum outstanding position.

Related, and it changes the answer: a live check found production eUSD is **token_id 1**, backed
on Ethereum by **EUSD, not USDC**, held in a **2-of-2 Gnosis Safe**. If that issuer is you, float
sourcing is straightforward. If not, we are buying inventory from a third party and that is a
different conversation.

---

## What we are **not** asking you — we can settle these ourselves

Listed so you can skip them: the two-cohort signing protocol, DKG and proof-of-possession
mechanics, key rotation and share refresh, the specific `k/n` and `g/m` numbers (parameters, set
later), the Ethereum verifier strategy, the memo schema, and everything in the formal models.
Those are engineering questions with technical answers, and a reviewer is already working through
them.

---

## Where the design stands

**Strategy — settled.** Escrow now: the bridge pre-funds an eUSD wallet and releases from it.
Switch to mint/burn later if MobileCoin governance allows. Escrow needs nobody's permission, so
work starts immediately, and it matches your original acceptance test.

**Two addresses.** `R` receives returns with a **published** view key so Ethereum can verify
them; `F` funds releases with a **private** view key so release rings stay private. The sweep is
one-way, `R → F`. Proved: recognising F's outputs reduces to DDH; R's view key confers no
advantage.

**The asymmetry that shapes everything.** Ethereum can verify MobileCoin. MobileCoin cannot
verify Ethereum. So the return leg is cryptographically verified, and the deposit leg is
*attested* by operators, capped, and audited. We do not describe it as trustless.

---

## What is proven

Eight machine-checked models, each mutation-tested — every guard is switched off in turn and must
break exactly the invariant it protects — with negative coverage assertions that catch a model
too dead to move, and a harness that fails closed on tool errors.

Executed rather than argued: three threshold-algebra results in real Ed25519, the DDH privacy
reduction, and the composite-root algebra accepted by MobileCoin's **unmodified** verifier.

**The number worth knowing: of 231 recorded claims, 74 were refuted and 26 disputed.** A third of
what we wrote down got overturned under review — including several defects in the *checking
apparatus* rather than the design. Three findings that changed the design:

- A **fund-loss defect in MobileCoin's own light-client relayer**: it classifies burns with a
  check that never reads the field determining who can spend. Latent today because payouts are
  manual; live the moment they are automated.
- **Threshold signing transcripts are forgeable** by the very quorum they would incriminate, so
  attribution needs identity signatures under separate keys.
- **A pause cannot bind a compromised quorum** without an indispensable MobileCoin-side factor —
  which is why Q1 and Q2 exist.

---

## What can start now

**Four of six components are unblocked:** the Ethereum escrow contract, the MobileCoin block and
inclusion verifier, the deposit auditor, and the signing ceremony state machine built against an
abstract backend.

**Two are behind the gates above:** the threshold signing backend — the existing spike is
single-cohort and cannot express operators-plus-gates at all — and anything that funds a
composite address.

**The critical path is the two-cohort signing spike.** It is what stands between this and a
fundable architecture, and it is what I am building next.

---

## The honest summary

The strategy is settled and the design has been through enough adversarial review that I trust
its shape. What is not settled is one architectural gate, and it is not a cryptography problem —
it is Q1 and Q2. The cryptography for it is demonstrated; what is missing is a decision about who
holds the second key and whether you are willing to be unable to recover without them.
