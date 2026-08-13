# Check an access-structure analysis before it goes to a decision-maker

A short, self-contained question. Please do not read the pull request.

## Setting

Releasing funds requires two disjoint groups to co-sign: `k of n` OPERATORS
**and** `g of m` GATES. The two shares are summed into one spend key, and the
gate's contribution lands inside the value the network uses to detect double
spends, so a release without it is rejected by consensus. There is deliberately
no recovery path: any way for operators to move funds without the gates would
defeat the arrangement.

`proofs/tla/AccessStructure.tla` (run it with `./scripts/proofs.sh`) proves

    T = max(k, g, k + g − r),    r = |Owners ∩ Gates|

is both a lower bound on the number of principals that must be compromised
before funds can move, and achievable. It assumes compromising a principal
yields BOTH of its role shares.

## The constraint

The decision-maker has said six entities is too many and named "three
independent parties" as the production shape. I have model-checked these:

| configuration                          | entities | T |
|----------------------------------------|----------|---|
| 3 principals, each holding both roles, 2-of-3 | 3 | 2 |
| 3 principals, each holding both roles, 3-of-3 | 3 | 3 |
| 2-of-2 operators + 1 gate               | 3        | 3 |
| 2-of-3 operators + 1 gate               | 4        | 3 |

All four: bound holds, bound is tight, and some coalition can authorize.

## What I would like checked

1. **Did I miss a configuration?** Over at most four principals, is there any
   assignment of roles and thresholds reaching `T = 3` that also tolerates one
   principal becoming permanently unavailable? I believe `2-of-3 operators +
   1 gate` is the smallest, and that at three entities `T = 3` forces `2-of-2`
   operators, which tolerates no loss. Please confirm or correct.

2. **Is `2-of-2 operators + 1 gate` genuinely equivalent to `2-of-3 operators +
   1 gate` in compromise terms, and different only in availability?** Both show
   `T = 3`. My reading is that the fourth entity buys nothing against
   compromise and buys everything against key loss. Is that right, or does the
   larger operator set change the compromise picture in a way `T` alone does
   not capture?

3. **The `3-of-3` row.** It reaches `T = 3` over three shared principals, but
   the same model's finding is that when the same parties hold both roles the
   structure reduces to an ordinary `max(k,g)`-of-n arrangement, so the split
   contributes nothing at the entity level. Is it fair to tell the
   decision-maker that this row is `3-of-3 multisig` with extra steps, or is
   there a residual benefit — for instance against a compromise limited to one
   role's credentials — worth stating?

4. **The assumption itself.** `T` assumes a compromised principal yields both
   its shares. For the shared-role rows that is what collapses them. Is there a
   realistic deployment where the two shares of one principal have genuinely
   different exposure, and if so does the table mislead?

Please cite `file:line` and run the model rather than reasoning from the table
alone. If the analysis is right, saying so plainly is a useful answer.
