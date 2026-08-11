# M2c — composite spend root, stock verifier

Does `B = B_owner + B_gate` produce a key image that MobileCoin's **unchanged**
verifier accepts, and does omitting the gate share yield *no valid spend*
rather than an unauthorized one?

```bash
cargo test --offline
```

## Why this exists

`spec/CompositeGate.tla` established that only an **indispensable** gate
contribution binds a compromised owner threshold — a detached signature or an
advisory policy is enforced by the party being constrained, so a colluding
coordinator simply omits it. That was an access-structure result and it
*assumed* the algebra worked. This spike tests the assumption.

## What is checked

| test | establishes |
|---|---|
| `composite_root_reconstructs_the_canonical_onetime_key` | `B = B_owner + B_gate` is a usable spend root, and `x` decomposes as `common + owner + gate` |
| `recipient_check_passes_for_the_composite_address` | the return-leg `recover_public_subaddress_spend_key` predicate still holds |
| `key_image_is_the_sum_of_per_party_shares` | `I` decomposes additively — each party contributes `s·Hp(P)` and they sum to the canonical `KeyImage` |
| `omitting_the_gate_share_yields_a_different_key_image` | an owner quorum without the gate cannot reach the real key image |
| `stock_verifier_accepts_the_composite_signature` | **unmodified `RingMLSAG::verify` accepts it**, and the signature carries the canonical key image |
| `stock_verifier_rejects_a_signature_built_without_the_gate` | omitting the gate yields **no valid spend**, not an unauthorized one |
| `stock_verifier_matrix_over_positions_and_sizes` | 19 signatures across ring sizes 3/5/11, every real index, all verified by the stock verifier |

## The result

The gate share is **indispensable in the sense the design needs**: it enters the
one-time key, therefore the key image, therefore a value consensus already
checks. There is nothing for a coordinator to omit — omitting it produces a
signature the verifier rejects.

## Caveats, stated so this is not overcited

- `hash_to_point` and `hash_to_scalar` are **replicated locally**, because the
  upstream module that exports them is private. They are not trusted blindly:
  **which test cross-checks what** (an earlier version got this wrong):
  `recipient_check_...` checks the local **`Hs`** replica;
  `key_image_is_the_sum_...` checks **`Hp`** against upstream `KeyImage::from`;
  `composite_root_derives_...` is **not** a differential — it asserts `P = x·G`
  directly, because the earlier version derived `common` *from* upstream and
  added the parts back, which was circular.
- This is **single-party-per-role algebra**. It shows `b_owner + b_gate` works;
  it does *not* run a k-of-n threshold ceremony over either share. Composing
  this with threshold signing is separate work — see the M2b variant.
- Nothing here addresses **who holds the gate shares**, gate independence, or
  the gate's own key lifecycle. `CompositeGate.tla` records independence as a
  named assumption, and it is not established here.
- The **lifecycle** question — when a gate releases, and how that bounds
  `P_irrevocable` — is modelled in `spec/CompositeGate.tla`, not here.
