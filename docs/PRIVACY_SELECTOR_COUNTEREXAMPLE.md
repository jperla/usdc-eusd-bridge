# Privacy selector counterexample: unspent-only sampling leaks over time

Status: **proved structural counterexample for a ring-observing adversary; not a chain-only MobileCoin anonymity measurement.**

## Result

Choosing every decoy only from outputs that the bridge believes are currently
unspent does not preserve an 11-member retrospective anonymity set. Under a
publicly known unspent-only rule, later inclusion of an output proves that the
output was not the real member of any earlier confirmed ring:

```text
output p appears in ring R_t
and p appears again in a later ring R_u, u > t

unspent-only eligibility says p was unspent immediately before u
therefore p was not spent as the real member at t
therefore p is a proved decoy in R_t
```

For an earlier ring of size 11, ten later observations can reinclude its ten
decoys. Those appearances eliminate all ten and leave the earlier real input as
the sole candidate. No public `TxOut <-> KeyImage` mapping is required.

This is why permitting already-spent outputs to appear as decoys can be a
privacy feature: later appearance then conveys no spent-status fact.

## Executable evidence

Run:

```bash
python3 spec/privacy_selector_trace.py --selftest
python3 spec/privacy_selector_trace.py
```

Expected result:

```text
PASS: exhaustive size-3 check and constructive size-11 checks
target ring size: 11
later observed rings: 10
survivors under unspent-only eligibility: ['x0']
survivors when spent outputs may be decoys: 11
scope: ring-observing adversary; current chain-only BlockContents redacts rings
```

The size-3 test exhaustively enumerates all real-member assignments consistent
with the temporal eligibility rule. The size-11 test is a constructive witness
and verifies that each later observation removes exactly one candidate.

## Scope boundary

Stock MobileCoin `BlockContents` stores key images and outputs, but not input
rings (`blockchain/types/src/block_contents.rs:19-37`). Consequently this exact
attack is unavailable to a chain-only observer of the stock ledger. It matters
to any actor that observes complete submitted rings, including the adversary in
MobileCoin's defense-in-depth analysis for a compromised consensus enclave.

The vNext protocol must state which actors see:

1. public policy-pool membership;
2. complete rings versus only commitments;
3. reservation openings and retry rings;
4. the custodians' private spent-output catalog; and
5. timing, amount/capacity-lot, and source-chain correlation data.

Privacy must be evaluated separately for a chain-only observer, a ring-observing
observer, a partial-side-information observer, and a custody insider. Josh has
already accepted that signing parties may know the real ring member, so the
public privacy claim cannot be evaluated using the insider model.

## Correction to the earlier hypergeometric calculation

`spec/anonymity.py` computes correct hypergeometric arithmetic only under an
additional oracle that identifies which exact pool outputs are already spent.
Ordinary MobileCoin key images do not provide that mapping: `I = x*Hp(P)` can be
recognized as repeated without revealing which ring public key `P = x*G`
shares the scalar `x`.

The calculation may be retained as a conditional sensitivity bound, but its
honest label is:

> exact single-ring calculation under a perfect known-spent-set oracle,
> uniform real prior, and uniform decoy sampling.

It is not an exact measurement of chain-observer MobileCoin anonymity. If the
oracle is a complete leaked `TxOut <-> KeyImage` catalog, the current key image
already reveals the real member and the anonymity is zero, rather than
`1 + unspent decoys`.

## Capacity correction

The proposed “11 unspent outputs” floor covers only one input. MobileCoin
requires ring elements to be unique across all ordinary input rings
(`transaction/core/src/validation/validate.rs:183-202`). A transaction with
`m` ordinary inputs therefore needs `11m` distinct final ring members: 22 for
the planned M3 two-input transaction and up to 176 at `MAX_INPUTS = 16`.
Stock `mobilecoind::get_rings` additionally samples 11 mixins per input before
replacing one with each real input, so a new policy selector should avoid that
implementation waste while preserving consensus-required uniqueness.

## Consequence

Do not adopt unspent-only selection or publish the 0.83-bit / 62.7% figures as
MobileCoin bridge results. First define the observation model, then test a full
history-conditioned posterior over age, policy, timing, amount/provenance,
multi-input correlation, retries, and past/future ring appearances. Positional
permutation invariance alone is insufficient; the required property is joint,
history-conditioned exchangeability across every observable feature.
