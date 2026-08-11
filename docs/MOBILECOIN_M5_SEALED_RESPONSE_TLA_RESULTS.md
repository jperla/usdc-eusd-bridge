# M5 sealed-response handshake TLA+ checkpoint

## Verdict

**Focused bounded safety-model pass.**

`M5SealedResponse.tla` exhaustively models one nonce slot, two distinct request
digests, the vault phases `Absent -> Committed -> Bound -> Sealed -> Released`,
an opaque receipt, receipt persistence, the operation-authority anchor and
release certificate, and raw-response observation. Exact request retries,
changed-request rejection, other idempotent retries, and crash/lost-acknowledgement
stuttering are explicit actions.

The honest configuration passes. Each one-defect configuration produces the
intended named counterexample.

## Executed evidence

Tooling:

```text
TLC2 2.19 (5a47802, 2024-08-08)
OpenJDK 26.0.2 (Homebrew)
workers=1, seed=1, fp=0
```

Results:

| Configuration | Generated | Distinct | Depth | Result |
|---|---:|---:|---:|---|
| `M5SealedResponse.cfg` | 140 | 18 | 10 | PASS; zero states left |
| `M5SealedResponse-bug-cert-without-anchor.cfg` | 40 | 12 | 7 | expected `CertificateRequiresExactAnchor` violation |
| `M5SealedResponse-bug-rebind-changed-request.cfg` | 7 | 5 | 4 | expected `SingleRequestBinding` violation |

The certificate trace reaches `Sealed`, makes the opaque receipt observable,
persists it, then issues a certificate while `authorityAnchored = FALSE` and
`anchoredReceipt = <<"NO_RECEIPT">>`. The rebinding trace first binds
`request-A`, then replaces it with `request-B`; `boundHistory` contains both
digests and the single-slot invariant fails.

The honest model checks:

- `ReceiptObservationSound`: an observable receipt names the deterministic
  exact receipt of a sealed request;
- `CertificateRequiresExactAnchor`: a certificate names the exact persisted,
  authority-anchored receipt;
- `RawObservationSound`: observed raw bytes imply `Released` plus the exact
  persisted/anchored/certified sealed receipt and request;
- `SingleRequestBinding`: the one slot never binds or seals two request
  digests; and
- `StateMonotonic`: the visited vault phases are exactly the prefix ending at
  the current phase, so no transition moves backwards or skips a phase.

`MarkReleased` and `ObserveRawResponse` are separate actions. This leaves an
explicit crash/stutter state after durable `Released` but before raw bytes cross
the vault boundary.

## Commands

Run from `/Users/jperla/josh/spec`. A fresh, writable `-metadir` is required.

```sh
/opt/homebrew/opt/openjdk/bin/java -XX:+UseParallelGC -cp tla2tools.jar \
  tlc2.TLC -nowarning -workers 1 -seed 1 -fp 0 \
  -metadir /tmp/m5-sealed-response-tlc-honest-freeze \
  -config M5SealedResponse.cfg M5SealedResponse.tla

/opt/homebrew/opt/openjdk/bin/java -XX:+UseParallelGC -cp tla2tools.jar \
  tlc2.TLC -nowarning -workers 1 -seed 1 -fp 0 \
  -metadir /tmp/m5-sealed-response-tlc-bug-cert-freeze \
  -config M5SealedResponse-bug-cert-without-anchor.cfg M5SealedResponse.tla

/opt/homebrew/opt/openjdk/bin/java -XX:+UseParallelGC -cp tla2tools.jar \
  tlc2.TLC -nowarning -workers 1 -seed 1 -fp 0 \
  -metadir /tmp/m5-sealed-response-tlc-bug-rebind-freeze \
  -config M5SealedResponse-bug-rebind-changed-request.cfg M5SealedResponse.tla
```

TLC exits nonzero for each mutant because finding the named invariant violation
is the expected result.

## Artifact hashes

```text
M5SealedResponse.tla
  80e518caaac30d5fac5fc82e0def6834e244109b654af4603c865802b25f0a40
M5SealedResponse.cfg
  8aa19a2f5fa5633bb04af222cb9b319e4fa6fbba16128cd561afd035175cfb2c
M5SealedResponse-bug-cert-without-anchor.cfg
  3f1b6953b884660a6078f13268a7004d8c50da350da02e2c781d0cd8ede42565
M5SealedResponse-bug-rebind-changed-request.cfg
  c629feafa4a63e2c0af8eba83903242b3b31c1ea31801db161b9c33181b615e8
tla2tools.jar
  936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
```

## Assumptions and non-claims

Canonical requests, receipts, certificates, and their authentication are
abstract exact tokens. The complete operation-wide sibling vector is assumed
already authorized. Durable transitions are assumed not to roll back, and a
receipt is deterministic for a request in this one-slot abstraction.

This checkpoint does not model or prove FROST/MLSAG arithmetic, nonce entropy or
secrecy, HSM behavior, torn writes, filesystem durability, replicated authority,
remote attestation, finality, availability/liveness, archival, MobileCoin
consensus enforcement, or the bridge acceptance cycle. Explicit stuttering
represents a crash only at an atomic boundary; it is not power-cut evidence.
