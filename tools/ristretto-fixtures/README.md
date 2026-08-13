# ristretto-fixtures

Generates `contracts/test/fixtures/ristretto.json`, the oracle for
`contracts/src/Ristretto255.sol` and the on-chain recipient check.

```
cd tools/ristretto-fixtures && cargo run --offline > ../../contracts/test/fixtures/ristretto.json
```

Outside the root workspace (own empty `[workspace]`), so `cargo test` never
builds it.

## What it pins

* **`multiples`** — the first sixteen multiples of the Ristretto basepoint.
  `multiples[1]` is the published ristretto255 basepoint encoding
  `e2f2ae0a…2d76`, so a wrong encoder fails immediately rather than
  self-consistently.
* **`rejects`** — encodings that MUST NOT decode: non-canonical field elements,
  negative field elements, non-square `x²`, negative `xy`, and `s = -1`. The
  generator asserts curve25519-dalek rejects each one before writing it, so the
  list cannot silently rot if a vector is mistyped.
* **`scalarMul`**, **`hashToScalar`** — point arithmetic and MobileCoin's
  `hash_to_scalar` (Blake2b512 over the domain tag and the **compressed**
  point; that compression is why the Solidity needs an encoder, not just a
  decoder).
* **`recipients`** — complete cases for the check the verifier must perform.
  Each is built by paying an output to `(C, D)` the way MobileCoin does, and
  the generator asserts `target_key − Hs(a·R)·G == D` closes and that a
  different spend key does not satisfy it.

Nothing here is re-derived: points come from curve25519-dalek and the scalar
hash from MobileCoin's own crate. Agreement with this file is agreement with
MobileCoin.
