# M2d — two independent cohorts over one composite spend root

```bash
cargo test --offline    # 8/8
```

The piece three earlier artifacts depend on and none of them supplies.

```text
b = b_owner + b_gate
b_owner  shared k-of-n across OWNERS   (own roster, own threshold)
b_gate   shared g-of-m across GATES    (own roster, own threshold)
```

The existing threshold spike has a **one-cohort shape** — one roster and one
`t/n` shared by the spend and mask keys, one `included` set for both — so it
cannot express operators-and-gates at all. Here each cohort is a separate
object with its own roster, threshold and Lagrange weights, and nothing in the
`Cohort` type refers to the other cohort.

## What is established

| test | establishes |
|---|---|
| `cohorts_carry_independent_rosters_and_thresholds` | 2-of-3 owners **and** 1-of-1 gates coexist — different sizes, different thresholds |
| `composite_root_is_the_sum_of_the_two_cohort_publics` | `B = B_owner + B_gate`, each computed from its own qualifying subset |
| **`key_image_is_invariant_across_every_owner_gate_subset_pair`** | **the load-bearing one** — all 3×3 *minimal* subset pairs produce the *same* key image, and it equals the canonical one. `subsets()` enumerates size exactly `t`, so this is every minimal pair, **not** every qualifying pair |
| `one_time_key_is_invariant_and_matches_upstream` | invariant across pairs, and a genuine differential against upstream `recover_onetime_private_key` |
| `an_owner_quorum_without_gates_reaches_a_different_key_image` | the gate cohort's contribution is exactly what is missing, checked additively |
| `stock_verifier_accepts_a_two_cohort_signature` | unmodified `RingMLSAG::verify` accepts it, at eUSD token id and ring size 11 |
| `stock_verifier_accepts_every_subset_pair_...` | 9 signatures, every *minimal* subset pair, all accepted, all agreeing on one key image |
| **`an_owner_only_scalar_is_rejected_by_the_stock_verifier`** | **the negative case** — signs the same fixed ring with `common + b_owner` and asserts the unmodified verifier REJECTS it. This is what settles gate indispensability at the signature level rather than in the algebra |
| `below_threshold_subsets_are_rejected` | sub-threshold subsets cannot contribute |

## Why key-image invariance is the property that matters

A key image that varied with the signing subset would let **one output be spent
twice under different images** — consensus deduplicates on the image, so two
distinct images for one output is a double spend. Invariance across the full
`owner-subset × gate-subset` product is therefore not bookkeeping; it is the
correctness condition for the whole scheme.

It is **necessary but not sufficient**. The full property set also requires
that no sub-threshold coalition can produce a verifying signature, that
malicious coordinators cannot get a non-canonical image accepted, and that the
result holds across independent signing sessions. None of those is established
here.

## Two cohorts, disjoint id namespaces

The cohorts use **disjoint participant-id ranges** (owners from 1, gates from
101). This is not cosmetic. With both rosters equal to `{1,2,3}`, every owner
subset is also a qualifying gate subset, so `gates.weighted(gsub)` succeeds when
handed the *owner* subset and the gate argument becomes dead code. Review
confirmed it by mutation: swapping `gsub` for `osub` left 8/8 green. With
disjoint ids that mutation kills 5 of 9 tests.

## What this does NOT establish

- **No live ceremony.** Shares are combined in one process. This is the
  algebra, not a two-round protocol with round-one packages and transcripts.
- **No non-reconstruction *signing*.** `onetime()` materialises the scalar so
  the stock signer can be used. A production signer must never form it — the
  per-participant terms are exposed (`weighted`, `key_image_from_shares`) so a
  real implementation can combine in the group, but that implementation does
  not exist here.
- **No DKG, no proof-of-possession, no rogue-key defence.** Cohort secrets are
  dealt by a trusted dealer. A cohort able to choose its component key after
  seeing the other's could try to control the sum; defending that needs
  authenticated DKG with PoP and a non-adaptive ceremony.
- **No mask-row split.** Row 1 belongs to the operator cohort; only the spend
  row and key image are two-cohort here. Review established that this does
  *not* create a bypass — the MLSAG rows are mandatory conjuncts, so row 1
  cannot compensate for a missing gate term in row 0 — and
  `an_owner_only_scalar_is_rejected_by_the_stock_verifier` now demonstrates it.
- **No transaction-level acceptance.** `RingMLSAG::verify` is low-level
  signature compatibility, not consensus validation of a whole transaction.
