// Regenerate contracts/test/fixtures/ristretto-noble.json.
//
//   node contracts/test/fixtures/generate-ristretto-noble.mjs
//
// WHAT THIS IS FOR. `Ristretto255.fromUniformBytes` and its `_map` are pinned
// by two things: four `bToken` values from tools/amount-fixtures (MobileCoin's
// own crates, via curve25519-dalek) and a handful of hand-written property
// tests. That is thin in one specific place. The `abs` in `s' = -|s*t|` --
// which the source itself calls "the easiest way to get this function subtly
// wrong" -- is caught by EXACTLY ONE assertion in the whole suite, the
// evenness property `MAP(t) == MAP(-t)`, and by NONE of the four oracle
// vectors. One hand-written test is a single point of failure for a branch of
// a hash-to-curve.
//
// So this script cross-checks the contract against a THIRD implementation --
// neither the fixture's dalek nor the Solidity -- over a much wider input set,
// and writes the result down where the suite can read it.
//
// MEASURED. Deleting the `abs` in an isolated copy and running the whole suite:
//
//   before  1 test red   ('the map is even: MAP(t) == MAP(-t)')
//   after   3 tests red, and the two new ones report WHERE:
//             20 of 62 from_uniform_bytes vectors disagree
//             21 of 56 token ids disagree
//
// The four `bToken` vectors from amount.json stay GREEN under that mutation --
// 'from_uniform_bytes reproduces MobileCoin's generators(id)' and
// 'generators(token_id) derives MobileCoin's B_token on chain' both pass on
// the broken map. That is the gap this file closes.
//
// WHY A COMMITTED FIXTURE AND NOT A DEPENDENCY. This repo pins its node tree
// with package-lock.json + scripts/node-deps.sh precisely so that two machines
// print the same gas numbers, and `@noble/curves` is not in package.json -- it
// is present only because `@ethereumjs/evm` depends on it, which is a fact
// about today's lockfile and not a promise. Making the SUITE import it would
// turn a transitive pin into a load-bearing one. The repo's existing idiom for
// this is tools/amount-fixtures: a generator that emits a committed JSON file
// which tests read with readFileSync. This follows it, in JavaScript because
// the reference implementation is JavaScript.
//
// So: this script is NOT part of `npm test`. `test/run.mjs` enumerates *.mjs
// in test/ and does not descend into test/fixtures/, so nothing here runs on
// its own. Run it by hand when the map changes or the input set should widen,
// and commit the diff -- a diff in this fixture is a claim that an independent
// implementation now says something different, which is exactly the thing that
// should be read by a human.
//
// PROVENANCE, restated in the fixture's own header so it travels with the
// file: @noble/curves 1.9.7 (RistrettoPoint.hashToCurve, i.e. RFC 9496 4.3.4
// from_uniform_bytes) and @noble/hashes 1.8.0 (blake2b-512). Node's built-in
// crypto supplies the SHA-256 that makes the pseudorandom inputs deterministic.

import { createHash } from 'crypto';
import { writeFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { RistrettoPoint } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'ristretto-noble.json');

const CURVES_VERSION = '1.9.7';
const HASHES_VERSION = '1.8.0';
const DOMAIN_TAG = 'mc_onetime_key_hash_to_point';
/// The seed for every pseudorandom input below. Written down so the file is
/// regenerable byte for byte: input i is SHA-256(SEED || label || u32be(i)).
const SEED = 'bridge/contracts ristretto noble cross-check v1';

const hex = (b) => '0x' + Buffer.from(b).toString('hex');
const unhex = (h) => Buffer.from(h.replace(/^0x/, ''), 'hex');

/// Deterministic bytes: SHA-256 chained until `n` bytes exist.
function stream(label, i, n) {
  const out = [];
  let block = createHash('sha256')
    .update(SEED).update(label).update(Buffer.from([i >> 24, i >> 16, i >> 8, i]))
    .digest();
  while (out.length < n) {
    out.push(...block);
    block = createHash('sha256').update(SEED).update(block).digest();
  }
  return Buffer.from(out.slice(0, n));
}

// ------------------------------------------------------------- the reference

const BASEPOINT = RistrettoPoint.BASE.toBytes();

/// MobileCoin's `generators(token_id)` preimage, computed the way
/// `crypto/ring-signature/src/ring_signature/mod.rs:85` computes it: the
/// compressed ristretto basepoint with the id's eight little-endian bytes
/// XOR-ed over bytes 0..8. The basepoint comes from noble, not from this repo.
function preimage(tokenId) {
  const buf = Buffer.from(BASEPOINT);
  for (let i = 0; i < 8; i++) {
    buf[i] ^= Number((tokenId >> BigInt(8 * i)) & 0xffn);
  }
  return buf;
}

/// `generators(token_id).B`, compressed.
function valueGenerator(tokenId) {
  const digest = blake2b(
    Buffer.concat([Buffer.from(DOMAIN_TAG, 'utf8'), preimage(tokenId)]),
    { dkLen: 64 }
  );
  return RistrettoPoint.hashToCurve(digest).toBytes();
}

/// `from_uniform_bytes(lo || hi)`, compressed.
const fromUniform = (lo, hi) =>
  RistrettoPoint.hashToCurve(Buffer.concat([unhex(lo), unhex(hi)])).toBytes();

// -------------------------------------------------------------- the token ids

/// 56 token ids, chosen to be wide rather than random: every id a byte of the
/// preimage can be, the boundaries of every power of two the XOR can straddle,
/// eUSD's real id and its neighbours, both ends of u64, and a deterministic
/// spread to fill in.
function tokenIds() {
  const ids = new Set();
  for (let i = 0n; i < 16n; i++) ids.add(i);           // every low nibble
  for (const k of [4n, 8n, 12n, 16n, 24n, 32n, 48n, 63n]) {
    ids.add((1n << k) - 1n);
    ids.add(1n << k);
    ids.add((1n << k) + 1n);
  }
  for (const id of [8191n, 8192n, 8193n]) ids.add(id); // eUSD and neighbours
  ids.add((1n << 64n) - 1n);
  ids.add((1n << 64n) - 2n);
  for (let i = 0; ids.size < 56; i++) {
    ids.add(BigInt('0x' + stream('token-id', i, 8).toString('hex')));
  }
  return [...ids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

// ---------------------------------------------------------------- the vectors

const HALF_ZERO = '0x' + '00'.repeat(32);

/// 62 (lo, hi) pairs.
///
/// The single-map cases pair a half with zero. That is MAP(t) alone, because
/// MAP(0) is the identity -- the suite asserts that separately -- so a failure
/// on one of them localises to the map rather than to the sum.
function vectors() {
  const out = [];
  // Deduplicated on the INPUT, so 62 means 62 distinct map inputs. Two of the
  // real digest halves already have bit 255 set, so setting it again is a
  // no-op and would otherwise have bought a repeat instead of a vector.
  const seen = new Set();
  const push = (name, lo, hi) => {
    const key = lo + hi;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ name, lo, hi });
  };

  // The eight halves of the four real generator digests, and the four whole
  // digests. These overlap the existing oracle on purpose: if noble disagreed
  // with dalek here, the whole file would be worthless and it should say so
  // loudly rather than only on inputs nobody else has checked.
  const realIds = [0n, 1n, 8192n, (1n << 64n) - 1n];
  for (const id of realIds) {
    const d = blake2b(
      Buffer.concat([Buffer.from(DOMAIN_TAG, 'utf8'), preimage(id)]),
      { dkLen: 64 }
    );
    const lo = hex(d.slice(0, 32));
    const hi = hex(d.slice(32, 64));
    push(`generator ${id} digest`, lo, hi);
    push(`generator ${id} lo alone`, lo, HALF_ZERO);
    push(`generator ${id} hi alone`, hi, HALF_ZERO);
    // The same halves with bit 255 set. dalek's FieldElement::from_bytes masks
    // it, so these must give the SAME points -- an assertion the contract can
    // only pass if it masks too.
    const loSet = Buffer.from(unhex(lo)); loSet[31] |= 0x80;
    push(`generator ${id} lo, high bit set`, hex(loSet), HALF_ZERO);
  }

  // Field-boundary halves, little-endian, as both a lone map and a full pair.
  const p = (1n << 255n) - 19n;
  const le = (v) => hex(Buffer.from(
    v.toString(16).padStart(64, '0'), 'hex').reverse());
  for (const [name, v] of [
    ['zero', 0n], ['one', 1n], ['p-1', p - 1n], ['p', p], ['p+1', p + 1n],
    ['2^255-1', (1n << 255n) - 1n], ['2^256-1', (1n << 256n) - 1n],
    ['sqrt(-1) input 2', 2n], ['p/2', p / 2n],
  ]) {
    push(`half = ${name}`, le(v & ((1n << 256n) - 1n)), HALF_ZERO);
  }
  push('both halves zero (the identity)', HALF_ZERO, HALF_ZERO);

  // And the rest deterministic, which is what actually widens the coverage:
  // roughly half of all inputs reach the map's non-square branch, and half of
  // those have `s*t` odd, so this is where the `abs` gets exercised.
  for (let i = 0; out.length < 62; i++) {
    const b = stream('uniform', i, 64);
    push(`pseudorandom ${i}`, hex(b.slice(0, 32)), hex(b.slice(32, 64)));
  }
  return out;
}

// ------------------------------------------------------------------- assemble

const ids = tokenIds();
const vecs = vectors();

const fixture = {
  _header: {
    what: 'ristretto255 one-way map (RFC 9496 4.3.4) and MobileCoin '
      + 'generators(token_id).B, computed by an implementation that is '
      + 'neither this repo\'s Solidity nor the curve25519-dalek that produced '
      + 'contracts/test/fixtures/amount.json.',
    producedBy: 'contracts/test/fixtures/generate-ristretto-noble.mjs',
    library: `@noble/curves ${CURVES_VERSION} `
      + `(RistrettoPoint.hashToCurve = from_uniform_bytes), `
      + `@noble/hashes ${HASHES_VERSION} (blake2b-512)`,
    noTestWritesToThisFile:
      'Read-only. contracts/test/ristretto.mjs opens it with readFileSync and '
      + 'compares; nothing in the suite regenerates or repairs it. If a value '
      + 'here disagrees with the contract, exactly one of the two is wrong and '
      + 'the test says which vector.',
    regenerate: 'node contracts/test/fixtures/generate-ristretto-noble.mjs',
    determinism: `pseudorandom inputs are SHA-256(seed || label || u32be(i)) `
      + `with seed ${JSON.stringify(SEED)}; regenerating without editing the `
      + 'script must produce a byte-identical file.',
    domainTag: DOMAIN_TAG,
  },
  basepointCompressed: hex(BASEPOINT),
  generators: ids.map((id) => ({
    tokenId: id.toString(),
    preimage: hex(preimage(id)),
    bToken: hex(valueGenerator(id)),
  })),
  fromUniformBytes: vecs.map((v) => ({
    name: v.name,
    lo: v.lo,
    hi: v.hi,
    encoded: hex(fromUniform(v.lo, v.hi)),
  })),
};

writeFileSync(OUT, JSON.stringify(fixture, null, 2) + '\n');
console.log(`wrote ${OUT}`);
console.log(`  ${fixture.generators.length} token ids, `
  + `${fixture.fromUniformBytes.length} from_uniform_bytes vectors`);
