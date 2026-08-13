# M4 MobileCoin one-time-key offset audit and executable result

## Outcome

At MobileCoin commit
`05cb699f8f4cc1bc21186392545820c5b38408db`, the required additive
one-time-key offset exists and is computable without the root spend private
scalar:

```text
x     = Hs_onetime(a * R) + b + Hs_subaddress(a || i)
delta = x - b
      = Hs_onetime(a * R) + Hs_subaddress(a || i)
```

The proposed API therefore needs only:

```rust
fn derive_onetime_private_key_offset(
    tx_out_public_key: &RistrettoPublic, // R: public
    view_private_key: &RistrettoPrivate, // a: secret
    subaddress_index: u64,               // i: privacy-sensitive metadata
) -> Scalar                              // delta: quorum/privacy-sensitive
```

It neither accepts `b` nor returns `x`. In a Shamir/FROST-style signing
protocol, adding the same `delta` to each evaluated share of `b` changes the
shared polynomial's constant term from `b` to `x`, because the Lagrange
coefficients for any valid signing set sum to one. No participant needs to
assemble `b` or `x` for that transformation.

`delta` is not globally public. It is quorum/privacy-sensitive custody
material. It should be confined to the authenticated signing session, bound to
the selected output and intent, and erased on a best-effort basis after use.

## Pinned source anchors

- `crypto/ring-signature/src/onetime_keys.rs:17-67` states the complete
  derivation, including `x = Hs(a * R) + b + Hs(a | i)`.
- `crypto/ring-signature/src/onetime_keys.rs:84-90` implements the one-time
  point-to-scalar KDF using Blake2b-512, domain tag
  `mc_onetime_key_hash_to_scalar`, and compressed `aR`.
- `crypto/ring-signature/src/onetime_keys.rs:169-184` is the stock
  `recover_onetime_private_key` oracle.
- `core/src/subaddress.rs:37-45` and `core/src/subaddress.rs:66-74` duplicate
  the subaddress offset KDF. It hashes the domain tag `mc_subaddress`, the
  canonical 32-byte scalar encoding of `a`, and the canonical 32-byte encoding
  of `Scalar::from(i)`.
- `core/src/consts.rs:15-16` owns the current private subaddress domain tag.
- `transaction/signer/src/traits.rs:69-91` shows the current local key-image
  path reconstructing the subaddress spend key and complete one-time private
  key before computing the key image.

Pinned source hashes:

```text
4ebe01560708f84ad49f3ee8f876fa630bd596d0addd16c7e63bf877617b9891  core/src/subaddress.rs
4dfb4be8c22e23b53f84e2639f10d823cb9e2ee2f099732777ec32560fa2135d  core/src/consts.rs
2feedcc5b1a672f6b40366b02aa799df1c8b96f6847bff8ec90018caad01156d  crypto/ring-signature/src/onetime_keys.rs
b1720d9e74b02ccb57ad0ea96b3d7be655bca661610be067af799f59ca7d9300  crypto/ring-signature/src/domain_separators.rs
538efde1f46c07ea1c18491b0c5592a0249b2bcd22aca5b0670e06b7547ee209  transaction/signer/src/traits.rs
```

The pinned MobileCoin checkout remained clean after the audit and test.

## Executable evidence

The frozen spike is `/Users/jperla/josh/m4-onetime-offset-spike`. It copies the two exact pinned KDF
formulas because neither complete offset nor both component KDFs are exposed by
the current API. That duplication is acceptable only as a test fixture.

Four tests pass:

1. For indices `0`, `1`, `7`, `787`, `u64::MAX - 2`, and `u64::MAX - 1`,
   `b + delta` byte/point-equates to stock
   `recover_onetime_private_key`, and the public relation
   `P - B == delta * G` holds.
2. A compile-time function-pointer assertion fixes the proposed API to exactly
   `(R, a, i) -> delta`; there is no `b` or `x` parameter.
3. A wrong view key, transaction public key, or subaddress index fails to
   reconstruct the stock key and fails the target-key equality.
4. Swapping/omitting the two domain tags or encoding `i` as raw eight-byte
   little-endian data instead of `Scalar::from(i).as_bytes()` changes the
   result.

The fresh-target commands were:

```sh
PATH=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin:$PATH \
RUSTC=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin/rustc \
RUSTDOC=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin/rustdoc \
CARGO_TARGET_DIR=/tmp/m4-onetime-offset-clean-target \
cargo test --locked --offline --all-targets

PATH=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin:$PATH \
RUSTC=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin/rustc \
RUSTDOC=/tmp/m3-rustup-home/toolchains/nightly-2025-03-01-aarch64-apple-darwin/bin/rustdoc \
CARGO_TARGET_DIR=/tmp/m4-onetime-offset-clean-target \
cargo clippy --locked --offline --all-targets -- -D warnings
```

Toolchain:

```text
rustc 1.87.0-nightly (287487624 2025-02-28)
cargo 1.87.0-nightly (2622e844b 2025-02-28)
```

Result: four tests passed; strict Clippy passed.

Spike hashes:

```text
e42b650b85e0803f473d87d88f3e3088f0bfe401a50e0c0fc31acc78cc0ca4d2  Cargo.toml
76ae35243acbe4ad9810cebe49e2b549d5bb330e22aa7ed17971ccb3a5e7cf83  Cargo.lock
79a58d8418e4611af784e9f10f09d736844a93417d9246f79ec8607862042599  src/lib.rs
0015549b8761cd6708014179209db4dc277e5db11ca302a78c7cb0ff9a77a955  README.md
```

## Clean upstream API placement

### Minimal-change route: two owner-local helpers

The smallest dependency-safe upstream patch is:

1. Extract one canonical `Hs_subaddress(a || i)` helper in
   `mc_core::subaddress` and make both existing private/public subaddress paths
   call it.
2. Extract one canonical `Hs_onetime(a * R)` helper in
   `mc_crypto_ring_signature::onetime_keys` and make target recovery and stock
   one-time private-key recovery call it.
3. Compose them in a leaf threshold-custody crate that already depends on both
   `mc-core` and `mc-crypto-ring-signature`. A convenience facade may also live
   in `mc-transaction-signer`, which already has both dependencies.

This avoids a dependency cycle and eliminates duplicated KDF logic in each
owner. The current `mc-transaction-signer` is a `std` offline/hardware-signer
package, however, so it should not become the only home of a primitive needed
by enclaves or other `no_std` consumers.

Do not put a composite helper in `mc-account-keys` by adding a dependency on
`mc-crypto-ring-signature`: ring-signature currently has a development
dependency back to account-keys. Cargo can stage some normal/dev back-edge
patterns, so this is not asserted to be an unavoidable build failure, but it
makes the ownership and feature/test graph recursive. Duplicating the
ring-signature domain string in account-keys would avoid that edge but create
cryptographic implementation drift instead.

A pragmatic single-facade variant is also acyclic in the normal dependency
graph: expose the subaddress helper from `mc-core`, add a
`default-features = false` dependency from ring-signature to core, and place the
composite function in ring-signature. `mc-core` does not depend on
ring-signature. This is workable, but broadens a low-level cryptographic crate
from `mc-core-types` to the larger `mc-core` package and makes the composite API
less naturally reusable by core itself. It should be evaluated against the SGX
and `no_std` build matrix before adoption.

### Clean long-term route: one lower-level `no_std` crate

If MobileCoin wants one canonical API usable by all custody/signing paths, the
clean design is a small lower-level `no_std` crate (for example,
`mc-crypto-onetime-keys`) that owns:

- both domain tags and scalar KDFs;
- a non-`Copy`, non-`Debug`, non-serializable offset wrapper;
- the composite `(R, a, i) -> delta` function; and
- the public validation helper `P == B + delta * G`.

Then `mc-core`, `mc-crypto-ring-signature`, and the threshold signer depend
downward on that crate. This provides one canonical composite helper without
making either existing core cryptographic package depend upward or own the
other package's domain. The wrapper is an accidental-disclosure barrier, not a
proof of zeroization: Dalek scalars and compiler temporaries can still be
copied.

## Required production binding

The derivation alone does not prove that the selected output belongs to the
threshold account. Before any nonce reservation or round-one commitment, the
signing state machine must verify:

```text
selected_target_key P == root_spend_public B + delta * G
```

and bind at least `R`, `P`, `i`, ring/order/real index, transaction digest,
policy and DKG epochs, key IDs, reservation ID, and retry/session identity into
the authenticated intent. A wrong `(R, a, i)` produces a different scalar but
does not intrinsically return an error.

## Exact secret exposure and exclusions

Production-shaped API exposure:

- input: complete view private scalar `a`;
- intermediates: `aR`, `Hs_onetime(aR)`, `Hs_subaddress(a || i)`, and `delta`;
- output: complete `delta` scalar;
- absent: root spend private scalar `b` and complete one-time scalar `x`.

The equivalence tests additionally instantiate complete `b`, sender scalar `r`,
subaddress spend scalar `d`, and stock `x` as test-oracle material. That is not
a production custody claim. The spike provides no memory-secrecy, threshold
view-key, nonce lifecycle, DKG, authenticated accountability, full MLSAG,
transaction, ledger-membership, consensus, or network-upgrade proof.

## Honest claim

> PINNED MOBILECOIN ONE-TIME-OFFSET ALGEBRA AND API-BOUNDARY PASS: `delta = x -
> b` IS DERIVABLE FROM EXACTLY `(R, a, i)` AND MATCHES STOCK RECOVERY; THE TEST
> ORACLE ALONE RECONSTRUCTS `x`. DISTRIBUTED VIEW-KEY CUSTODY, SECRET-MEMORY
> SAFETY, OUTPUT/INTENT AUTHENTICATION, THRESHOLD MLSAG, CONSENSUS, AND NETWORK
> ACTIVATION ARE NOT PROVED.
