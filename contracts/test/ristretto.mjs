// ristretto255, MobileCoin's hash_to_scalar, and the on-chain recipient check.
//
// Every expected value comes from tools/ristretto-fixtures, which computes it
// with curve25519-dalek and MobileCoin's own crates -- never from this
// Solidity. The generator also asserts, on the Rust side, that dalek REJECTS
// each of the `rejects` encodings and that the recipient relation closes, so
// the fixture cannot silently rot into agreement with a broken contract.
//
// What has to be true for the bridge to be safe, and is tested here:
//
//   * an encoding that dalek refuses is refused here too (all 10 vectors),
//     plus two families the published list does not isolate -- see the note
//     above those tests, which were checked against dalek before being written
//   * decode and encode are inverse on every published multiple of B
//   * scalar multiplication agrees with dalek on independent points
//   * hash_to_scalar agrees with MobileCoin, including the wide reduction
//   * the ristretto255 one-way map (RFC 9496 4.3.4) reproduces MobileCoin's
//     `generators(token_id).B` for every token id the oracle publishes, at both
//     steps -- the basepoint-XOR-id preimage and the Elligator map itself
//   * the real spend key is accepted and a wrong one is not, per case, and
//     mixing arguments between cases is rejected

import { readFileSync } from 'fs';
import { createHash } from 'crypto';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import {
  Chain, selector, word, b32, dynBytes, test, assert, assertEq, summary,
  revertReason, decodeBool,
} from './harness.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(HERE, 'fixtures', 'ristretto.json'), 'utf8'));
// The one-way map's oracle. amount.json's `generators` are MobileCoin's own
// `generators(token_id)`, published with the 32-byte preimage each one hashes,
// so the derivation can be pinned at both of its steps.
const AMT = JSON.parse(readFileSync(join(HERE, 'fixtures', 'amount.json'), 'utf8'));

const chain = await Chain.create({
  only: ['Ristretto255.sol', 'RecipientCheck.sol', 'MobileCoinGenerators.sol'],
});
const probe = await chain.deploy('Ristretto255Probe_DO_NOT_DEPLOY');

/// L itself, little-endian: the smallest non-canonical scalar encoding.
const L_LE = '0xedd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010';

const FIELD_P = (1n << 255n) - 19n;
const leToBig = (hex) =>
  BigInt('0x' + Buffer.from(hex.replace(/^0x/, ''), 'hex').reverse().toString('hex'));
const bigToLE = (v) =>
  '0x' + Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse().toString('hex');
/// p - s, the other encoding of the same point.
const negateEncoding = (enc) => bigToLE(FIELD_P - leToBig(enc));

/// (bool, bytes32) return -> { ok, out }.
const pair = (r) => ({
  ok: decodeBool(r.ret, 0),
  out: '0x' + r.ret.slice(2).slice(64, 128),
});

const callOk = async (data) => {
  const r = await chain.call(probe, data);
  assert(r.ok, `probe reverted: ${revertReason(r.ret)}`);
  return r;
};

const decodes = async (enc) => {
  const r = await callOk(selector('decodes(bytes32)') + b32(enc));
  return decodeBool(r.ret);
};

const reencode = async (enc) =>
  pair(await callOk(selector('reencode(bytes32)') + b32(enc)));

const addPts = async (a, b) =>
  pair(await callOk(selector('add(bytes32,bytes32)') + b32(a) + b32(b)));

const subPts = async (a, b) =>
  pair(await callOk(selector('sub(bytes32,bytes32)') + b32(a) + b32(b)));

const mul = async (k, p) =>
  pair(await callOk(selector('mul(bytes32,bytes32)') + b32(k) + b32(p)));

const mulBase = async (k) =>
  pair(await callOk(selector('mulBase(bytes32)') + b32(k)));

console.log('\nRistretto255');

// ------------------------------------------------------------------- 1. decode

await test('every published multiple of the basepoint decodes', async () => {
  for (const m of V.multiples) {
    assert(await decodes(m.encoded), `multiple ${m.n} was refused`);
  }
});

await test('the published basepoint encoding decodes', async () => {
  assert(await decodes(V.basepoint), 'basepoint was refused');
});

await test('every encoding dalek rejects is refused', async () => {
  // Non-canonical field encodings, negative s, non-square x^2, negative xy,
  // and s = -1. Each is a near-miss that an Ed25519 decompressor -- or a
  // ristretto decoder missing one branch -- would happily accept, and each
  // accepted near-miss is a second encoding of a point, which would break the
  // byte comparison the recipient check is built on.
  for (const [i, r] of V.rejects.entries()) {
    assert(!(await decodes(r.encoded)), `rejects[${i}] ${r.encoded} was accepted`);
  }
});

// The published reject list does not isolate two of the five branches: every
// one of its negative-s vectors is also non-square or has y == 0, and no
// vector in it reaches the negative-t test at all. Both branches below were
// confirmed refused by curve25519-dalek directly before being written down.

await test('the negation of a valid encoding is refused', async () => {
  // p - s decodes, absent the check, to the SAME point as s. Accepting it
  // would give one point two encodings -- and both the recipient check's
  // equality test and the escrow's replay key are comparisons of encodings.
  for (const m of V.multiples.slice(1)) {
    const neg = negateEncoding(m.encoded);
    assert(neg !== m.encoded, `negation of multiple ${m.n} is a no-op`);
    assert(!(await decodes(neg)), `negated multiple ${m.n} was accepted`);
  }
});

await test('an encoding whose only fault is a negative t is refused', async () => {
  // s = 2, 10 and 16 are canonical and non-negative, and give a square and a
  // non-zero y: negative t is the only branch that rejects them.
  for (const s of [2, 10, 16]) {
    const enc = '0x' + s.toString(16).padStart(2, '0') + '00'.repeat(31);
    assert(!(await decodes(enc)), `s = ${s} was accepted`);
  }
});

/// Each of the five conditions RFC 9496 4.3.1 requires, isolated.
///
/// A vector that fails several conditions at once cannot tell you whether any
/// particular check exists. Review found exactly that hole here: the suite
/// still passed with the canonical-range check removed, because every
/// non-canonical vector in the published list also fails a later condition.
/// Each encoding below fails ONE condition and passes the other four, so
/// removing any single check turns this test red.
const SOLE_FAULT = [
  ['s >= p, non-canonical',
   '0xdaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'],
  ['negative s (odd canonical representative)',
   '0x0b0d51f59543b18e577b569e3affaea0a71cf4955a7d22724959a6ba1f72d209'],
  ['no square root',
   '0x0e00000000000000000000000000000000000000000000000000000000000000'],
  ['negative t',
   '0x0200000000000000000000000000000000000000000000000000000000000000'],
  ['y == 0',
   '0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
];

await test('each of the five decode conditions has a sole-fault witness', async () => {
  for (const [why, enc] of SOLE_FAULT) {
    assert(!(await decodes(enc)), `accepted an encoding whose only fault is: ${why}`);
  }
  // Not vacuous: a neighbouring canonical value must still decode, so this is
  // not a decoder that refuses everything in the vicinity.
  assert(await decodes('0x' + '04' + '00'.repeat(31)), 's = 4 must decode');
});

await test('a decoder that accepted everything would fail this suite', async () => {
  // Guards the guard: if `decodes` ever became a constant, the rejects test
  // above would pass vacuously only if it also stopped accepting real points.
  assert(await decodes(V.basepoint), 'real point refused');
  assert(!(await decodes(V.rejects[0].encoded)), 'bad encoding accepted');
});

// ------------------------------------------------------------------- 2. encode

await test('decode then encode is the identity on every multiple', async () => {
  for (const m of V.multiples) {
    const { ok, out } = await reencode(m.encoded);
    assert(ok, `multiple ${m.n} failed to decode`);
    assertEq(out, m.encoded, `round trip of multiple ${m.n}`);
  }
});

await test('the basepoint constant encodes to the published bytes', async () => {
  // Not a round trip: this encodes the (x, y) constants compiled into the
  // library, so a mistyped basepoint cannot hide behind a decode.
  const r = await callOk(selector('basepointEncoding()'));
  assertEq(r.ret.slice(0, 66), V.basepoint, 'basepoint constant');
});

// --------------------------------------------------------------- 3. arithmetic

await test('adding B walks the published multiples', async () => {
  // multiples[n] + B == multiples[n+1] is dalek's own accumulation, so this
  // checks addition against the oracle at 15 independent points.
  for (let n = 0; n + 1 < V.multiples.length; n++) {
    const { ok, out } = await addPts(V.multiples[n].encoded, V.basepoint);
    assert(ok, `add at ${n} failed to decode`);
    assertEq(out, V.multiples[n + 1].encoded, `multiples[${n}] + B`);
  }
});

await test('subtracting B walks them back', async () => {
  for (let n = 1; n < V.multiples.length; n++) {
    const { ok, out } = await subPts(V.multiples[n].encoded, V.basepoint);
    assert(ok, `sub at ${n} failed to decode`);
    assertEq(out, V.multiples[n - 1].encoded, `multiples[${n}] - B`);
  }
});

await test('scalar multiplication matches dalek on arbitrary points', async () => {
  for (const c of V.scalarMul) {
    const { ok, out } = await mul(c.scalar, c.point);
    assert(ok, `case ${c.case} failed to decode`);
    assertEq(out, c.product, `scalarMul case ${c.case}`);
  }
});

await test('scalar multiplication of the basepoint matches dalek', async () => {
  for (const c of V.scalarMul) {
    const { ok, out } = await mulBase(c.scalar);
    assert(ok, `case ${c.case} scalar was refused`);
    assertEq(out, c.base_product, `mulBase case ${c.case}`);
  }
});

await test('[n]B equals the published multiple for every n', async () => {
  for (const m of V.multiples) {
    const le = m.n.toString(16).padStart(2, '0') + '00'.repeat(31);
    const { ok, out } = await mulBase('0x' + le);
    assert(ok, `scalar ${m.n} refused`);
    assertEq(out, m.encoded, `[${m.n}]B`);
  }
});

await test('an unreduced scalar is refused', async () => {
  // L itself, little-endian. dalek's canonical Scalar encoding is reduced;
  // accepting L would make 0 and L two encodings of one scalar.
  const { ok } = await mulBase(L_LE);
  assert(!ok, 'L was accepted as a scalar');
});

// ------------------------------------------------- 4. Blake2b-512 and the hash

console.log('\nBlake2b512 and hash_to_scalar');

const hashProbe = await chain.deploy('Blake2b256Probe_DO_NOT_DEPLOY');
const TAG = 'mc_onetime_key_hash_to_scalar';

const hash512 = async (hexInput) => {
  const r = await chain.call(hashProbe,
    selector('hash512(bytes)') + word(32) + dynBytes(hexInput));
  assert(r.ok, `hash512 reverted: ${revertReason(r.ret)}`);
  return r.ret.slice(2, 130);
};

await test('Blake2b-512 matches an independent implementation', async () => {
  // Node's OpenSSL blake2b512, not this Solidity. The parameter block carries
  // the digest length, so a 512-bit digest is a different function from the
  // 256-bit one all the way through -- not a truncation of it.
  const cases = [
    '', '616263', 'ff'.repeat(127), 'ff'.repeat(128), 'ff'.repeat(129),
    Buffer.from(TAG).toString('hex') + '11'.repeat(32), // the real preimage shape
  ];
  for (const hex of cases) {
    const want = createHash('blake2b512').update(Buffer.from(hex, 'hex')).digest('hex');
    assertEq(await hash512(hex), want, `blake2b512 of ${hex.length / 2} bytes`);
  }
});

await test('a 512-bit digest is not the 256-bit digest extended', async () => {
  // If `digestLen` were ignored in the parameter block, these would share a
  // first half and every hash_to_scalar below would still be wrong.
  const r = await chain.call(hashProbe,
    selector('hash(bytes)') + word(32) + dynBytes('616263'));
  assert(r.ok, 'hash reverted');
  const wide = await hash512('616263');
  assert(r.ret.slice(2, 66) !== wide.slice(0, 64), '512 is a truncation of 256');
});

// The recipient check's own view key is irrelevant to the hash, so one
// deployment serves the hash vectors.
const hashHost = await chain.deploy(
  'RecipientCheck', b32(V.recipients[0].view_private_key)
);

const hashToScalar = async (point) => {
  const r = await chain.call(hashHost,
    selector('hashToScalar(bytes32)') + b32(point));
  assert(r.ok, `hashToScalar reverted: ${revertReason(r.ret)}`);
  return r.ret.slice(0, 66);
};

await test('hash_to_scalar matches MobileCoin, wide reduction included', async () => {
  for (const c of V.hashToScalar) {
    assertEq(await hashToScalar(c.point), c.scalar, `hashToScalar case ${c.case}`);
  }
});

await test('hash_to_scalar carries the MobileCoin domain tag', async () => {
  // Same point, no tag: a different scalar. Without the tag the same shared
  // secret would produce the same one-time key material under any other
  // protocol that hashes ristretto points with Blake2b.
  const c = V.hashToScalar[0];
  const untagged = createHash('blake2b512')
    .update(Buffer.from(c.point.slice(2), 'hex')).digest('hex');
  const tagged = await hash512(
    Buffer.from(TAG).toString('hex') + c.point.slice(2)
  );
  assert(untagged !== tagged.slice(0, 128), 'the tag is not being hashed');
});

// ------------------------------------------------- 5. the ristretto one-way map

console.log('\nRistretto255 one-way map, and generators(token_id)');

// `B_token` used to be a constructor argument of MobileCoinVerifier, paired
// with a token id nothing related it to. These tests are what let that argument
// be deleted: the map below is the Elligator step the contract "deliberately
// did not implement", and the oracle for it is MobileCoin's own output.

const HASH_TO_POINT_TAG = AMT.generators.hashToPointDomainTag;
assertEq(HASH_TO_POINT_TAG, 'mc_onetime_key_hash_to_point',
  'the oracle changed the hash-to-point domain tag');

/// Blake2b512("mc_onetime_key_hash_to_point" || preimage), as { lo, hi } --
/// digest bytes 0..32 and 32..64. Computed by the CONTRACT's Blake2b, which is
/// pinned against OpenSSL a few tests above, so a failure below is the map's
/// and not the hash's.
const digestOf = async (preimage) => {
  const d = await hash512(
    Buffer.from(HASH_TO_POINT_TAG).toString('hex') + preimage.replace(/^0x/, '')
  );
  return { lo: '0x' + d.slice(0, 64), hi: '0x' + d.slice(64, 128) };
};

const fromUniform = async (lo, hi) =>
  (await callOk(selector('fromUniformBytes(bytes32,bytes32)') + b32(lo) + b32(hi)))
    .ret.slice(0, 66);

const mapToPoint = async (t) =>
  (await callOk(selector('mapToPoint(bytes32)') + b32(t))).ret.slice(0, 66);

/// Both halves of every generator's digest: eight independent map inputs.
const HALVES = [];
for (const g of AMT.generators.byTokenId) {
  const { lo, hi } = await digestOf(g.preimage);
  HALVES.push([`${g.tokenId} lo`, lo], [`${g.tokenId} hi`, hi]);
}

/// bit 255 of a little-endian 32-byte string: the top bit of its LAST byte.
const setHighBit = (h) => {
  const b = Buffer.from(h.replace(/^0x/, ''), 'hex');
  b[31] |= 0x80;
  return '0x' + b.toString('hex');
};
const clearHighBit = (h) => {
  const b = Buffer.from(h.replace(/^0x/, ''), 'hex');
  b[31] &= 0x7f;
  return '0x' + b.toString('hex');
};

const IDENTITY = '0x' + '00'.repeat(32);

await test('from_uniform_bytes reproduces MobileCoin\'s generators(id) for '
  + 'EVERY token id the oracle publishes', async () => {
  // THE ASSERTION THE DELETED CONSTRUCTOR ARGUMENT RESTS ON. Four token ids --
  // 0, 1, 8192 and u64::MAX -- each hashed with the contract's own Blake2b-512
  // and mapped with the contract's own Elligator. `bToken` is what MobileCoin's
  // crates computed for the same id.
  assert(AMT.generators.byTokenId.length >= 4,
    'the oracle lost generators -- this test is weaker than it reads');
  for (const g of AMT.generators.byTokenId) {
    const { lo, hi } = await digestOf(g.preimage);
    assertEq(await fromUniform(lo, hi), g.bToken,
      `generators(${g.tokenId}).B`);
  }

  // Not a function that returns the same point for everything: the four are
  // pairwise distinct, which is also the property that makes a mispaired
  // generator dangerous in the first place.
  const seen = new Set(AMT.generators.byTokenId.map((g) => g.bToken));
  assertEq(seen.size, AMT.generators.byTokenId.length,
    'two token ids share a generator');
});

await test('MAP(0) is the identity, so mapToPoint is ONE map', async () => {
  // Ristretto255Probe_DO_NOT_DEPLOY.mapToPoint pairs its argument with a zero half. That is
  // MAP(t) only because MAP(0) is the identity; if it stopped being, every
  // assertion below would silently be about MAP(t) + something.
  assertEq(await mapToPoint(IDENTITY), IDENTITY, 'MAP(0)');
  assertEq(await fromUniform(IDENTITY, IDENTITY), IDENTITY, 'MAP(0) + MAP(0)');
});

await test('the map is even: MAP(t) == MAP(-t)', async () => {
  // r depends on t^2 and the only other appearance of t is inside an absolute
  // value, so the sign of the input cannot reach the output. Dropping that
  // absolute value -- the easiest single mistake to make in this function --
  // breaks this for every t that lands in the non-square branch.
  let moved = 0;
  for (const [name, t] of HALVES) {
    const canonical = clearHighBit(t);
    const neg = negateEncoding(canonical);
    if (neg === canonical) continue; // t == 0 or t == p/2; neither occurs here
    moved++;
    assertEq(await mapToPoint(neg), await mapToPoint(canonical),
      `MAP(-t) != MAP(t) for ${name}`);
  }
  assertEq(moved, HALVES.length, 'the negation was a no-op somewhere');
});

await test('the high bit of each half is DISCARDED, not kept and not refused',
  async () => {
  // dalek's FieldElement::from_bytes masks bit 255. It is not decode's
  // canonicality rule: 2^255 = 19 (mod p), so keeping the bit maps an input to
  // a different point rather than to an equivalent one.
  for (const [name, t] of HALVES) {
    const cleared = clearHighBit(t);
    assertEq(await mapToPoint(setHighBit(t)), await mapToPoint(cleared),
      `${name}: the high bit changed the point`);
  }

  // And this is load-bearing rather than a property of inputs that never set
  // the bit: some of the oracle's own digest halves have it set.
  //
  // EXACTLY FOUR of the eight, which is what `Ristretto255._fieldFromLE`'s own
  // comment claims. Asserted as a number rather than as `> 0`: a regenerated
  // fixture that dropped to one, or to zero, would still satisfy `> 0` at one
  // and would silently stop exercising the mask at zero -- and the count is
  // the only place the source comment's "four of the eight" is checked.
  const set = HALVES.filter(([, t]) => (Buffer.from(t.slice(2), 'hex')[31] & 0x80) !== 0);
  assertEq(HALVES.length, 8, 'the oracle no longer publishes four generators');
  assertEq(set.length, 4,
    `${set.length} of ${HALVES.length} generator digest halves have the high `
    + 'bit set; Ristretto255._fieldFromLE says four. One of the two is now '
    + `wrong. Set: ${set.map(([n]) => n).join(', ')}`);

  // WHICH four, because the count alone flatters the fixture. Both this test
  // and the source comment used to add "so an implementation that skipped the
  // mask reproduces none of those generators", and that is FALSE. The four set
  // bits are not one per generator:
  //
  //     token 0      low half only
  //     token 1      high half only
  //     token 8192   NEITHER
  //     u64::MAX     both
  //
  // Token 8192 is eUSD -- the only id this bridge deploys for. A loader that
  // never masked would reproduce its `B_token` exactly, so amount.json does not
  // defend the mask where it matters most; the 62-vector @noble/curves
  // cross-check is what does. Asserted so that the claim cannot drift back.
  const affected = (id) => set.some(([n]) => n.startsWith(`${id} `));
  assert(!affected('8192'),
    'token 8192 now has a digest half with the high bit set. That is not a '
    + 'failure, but the comments here and in Ristretto255._fieldFromLE say it '
    + 'does not, and they are the reason the noble cross-check is described as '
    + 'load-bearing for eUSD. Update both.');
  for (const id of ['0', '1']) {
    assert(affected(id),
      `token ${id} no longer has a high-bit half, so the fixture exercises the `
      + 'mask on fewer generators than the comments claim');
  }
});

await test('both halves are load-bearing', async () => {
  // A map that used one half twice, or ignored the second, would still be a
  // hash-to-curve and would still produce points of the fixture's shape.
  for (const g of AMT.generators.byTokenId) {
    const { lo, hi } = await digestOf(g.preimage);
    const real = await fromUniform(lo, hi);
    assert(await fromUniform(lo, lo) !== real, `${g.tokenId}: hi is ignored`);
    assert(await fromUniform(hi, hi) !== real, `${g.tokenId}: lo is ignored`);
    assert(await fromUniform(lo, IDENTITY) !== real,
      `${g.tokenId}: the second map is not being added`);
    assert(await fromUniform(IDENTITY, hi) !== real,
      `${g.tokenId}: the first map is not being added`);
  }
});

await test('the two halves COMMUTE, and that is the construction, not a bug',
  async () => {
  // Recorded because it is the obvious next assertion to write and it is false:
  // from_uniform_bytes adds two mapped points, and addition commutes, so
  // swapping the halves cannot be detected by anything. The byte order that CAN
  // be wrong is the one inside each half, and the fixture pins that.
  for (const g of AMT.generators.byTokenId) {
    const { lo, hi } = await digestOf(g.preimage);
    assertEq(await fromUniform(hi, lo), await fromUniform(lo, hi),
      `${g.tokenId}: the halves stopped commuting`);
  }
});

await test('every point the map produces is a valid ristretto encoding',
  async () => {
  // The map has no failure case -- every 64-byte string is meant to give a
  // point -- so an output the library's own decoder refuses would mean the two
  // halves of this file disagree.
  for (const [name, t] of HALVES) {
    assert(await decodes(await mapToPoint(t)), `MAP(${name}) is not decodable`);
  }
  for (const g of AMT.generators.byTokenId) {
    const { lo, hi } = await digestOf(g.preimage);
    assert(await decodes(await fromUniform(lo, hi)),
      `generators(${g.tokenId}).B is not decodable`);
  }
});

// -------------------------------------------------- 6. generators(token_id)

const gens = await chain.deploy('MobileCoinGeneratorsProbe_DO_NOT_DEPLOY');

const genPreimage = async (id) =>
  (await chain.must(gens, selector('preimage(uint64)') + word(BigInt(id)))).ret;
const genValue = async (id) =>
  (await chain.must(gens, selector('valueGenerator(uint64)') + word(BigInt(id)))).ret;

await test('the hash-to-point preimage is the basepoint XOR the token id',
  async () => {
  // Step one of MobileCoin's `generators`, checked on its own so that a wrong
  // preimage and a wrong map cannot cancel into a right answer. The oracle
  // publishes the preimage precisely so this does not have to be inferred.
  for (const g of AMT.generators.byTokenId) {
    assertEq(await genPreimage(g.tokenId), g.preimage,
      `preimage for token id ${g.tokenId}`);
  }

  // Token id 0 must leave the basepoint alone, and some other id must not --
  // otherwise the XOR could be missing entirely.
  assertEq(await genPreimage(0), AMT.generators.basepointCompressed,
    'token id 0 must hash the bare compressed basepoint');
  assert(await genPreimage(1) !== AMT.generators.basepointCompressed,
    'the token id is not reaching the preimage');

  // The basepoint the contract XORs into is COMPUTED from the library's
  // coordinates, not written down again. Same value the oracle used.
  const encoded = (await callOk(selector('basepointEncoding()'))).ret.slice(0, 66);
  assertEq(encoded, AMT.generators.basepointCompressed,
    'the contract and the oracle disagree about the compressed basepoint');
});

await test('generators(token_id) derives MobileCoin\'s B_token on chain',
  async () => {
  // Both steps together, which is what MobileCoinVerifier's constructor calls.
  for (const g of AMT.generators.byTokenId) {
    assertEq(await genValue(g.tokenId), g.bToken,
      `generators(${g.tokenId}).B`);
  }
});

await test('a value generator that maps to the identity is refused', async () => {
  // `MobileCoinGenerators.DegenerateValueGenerator`, which until now no test
  // could produce: no published token id hashes to a degenerate digest, so
  // deleting the `revert` left the whole suite green. `valueGenerator`'s tail
  // was split into `fromDigestHalves`, which takes the digest as an ARGUMENT,
  // for exactly this -- see the comment on it.
  //
  // The degenerate digest is 64 zero bytes: MAP(0) is the identity (asserted
  // above, in 'MAP(0) is the identity, so mapToPoint is ONE map'), and the
  // identity plus itself is the identity, whose encoding is 32 zero bytes.
  const degenerate = async (id) => chain.call(gens,
    selector('fromDigestHalves(uint64,bytes32,bytes32)') +
    word(BigInt(id)) + b32(IDENTITY) + b32(IDENTITY));

  const SEL = selector('DegenerateValueGenerator(uint64)');
  for (const id of [0n, 1n, 8192n, (1n << 64n) - 1n]) {
    const r = await degenerate(id);
    assert(!r.ok, `token id ${id}: a degenerate generator was accepted`);
    assertEq(r.ret.slice(0, 10), SEL,
      `token id ${id}: refused, but not as DegenerateValueGenerator -- `
      + revertReason(r.ret));
    // The error names the token id, so a failed deployment says which one.
    assertEq(BigInt('0x' + r.ret.slice(10)), id,
      `token id ${id}: the error must carry the id`);
  }

  // The control: fed the digest halves the hash actually produces, this
  // returns exactly what `valueGenerator(id)` returns, which is MobileCoin's
  // own B_token. So the refusals above are about the degenerate digest and not
  // about `fromDigestHalves` refusing everything.
  //
  // WHAT IT DOES NOT SHOW, and the source says the same at the function: that
  // `valueGenerator` still ROUTES through `fromDigestHalves`. Agreement is not
  // identity of code path, and no test can be written for it -- no published
  // token id reaches the refusal either way, so an inlined rewrite that
  // dropped the guard would keep every assertion in this file green.
  for (const g of AMT.generators.byTokenId) {
    const { lo, hi } = await digestOf(g.preimage);
    const ok = await chain.must(gens,
      selector('fromDigestHalves(uint64,bytes32,bytes32)') +
      word(BigInt(g.tokenId)) + b32(lo) + b32(hi));
    assertEq(ok.ret, g.bToken, `fromDigestHalves for ${g.tokenId}`);
    assertEq(ok.ret, await genValue(g.tokenId),
      `fromDigestHalves and valueGenerator disagree for ${g.tokenId}`);
  }
});

// ------------------------- 6b. the map's degenerate branches, SOLVED FOR

// WHY THIS SECTION EXISTS. Everything above feeds the map either MobileCoin's
// own digests or pseudorandom bytes, and neither reaches the two places where
// the map's own arithmetic degenerates: `den` vanishing, and `1 - s^2`
// vanishing. Measured rather than assumed. Over the 236 map inputs this suite
// and fixtures/ristretto-noble.json supply between them -- both halves of all
// 62 vectors and of all 56 token id digests -- and over 20,000 further
// pseudorandom halves, neither ever occurs; each needs `r` to be an exact root
// of a fixed quadratic, which a hash lands on with probability about 2^-252.
// They cannot be sampled into. They have to be SOLVED for.
//
// WHAT IT BUYS, stated as a measurement and not as a hope. Adding
//
//     if (den == 0) den = 1;              // "this cannot happen"
//
// to `Ristretto255._map` leaves all 335 tests in this repo GREEN, and turns
// the two tests below red. That edit is not vandalism, it is the shape a
// defensive change takes -- and it silently gives a DIFFERENT `B_token` to
// every token id whose digest reaches a vanishing denominator, on the one code
// path (`MobileCoinVerifier`'s constructor) where a wrong-but-valid generator
// verifies commitments in the wrong group. This is also what makes
// `DegenerateValueGenerator` a guard rather than a comment: the identity is
// genuinely reachable from the map, not only from a digest of zeros.
//
// WHAT IT DOES NOT BUY, since the obvious stronger claim is false. These
// inputs do not pin what `_sqrtRatio` RETURNS for a zero denominator.
// Answering (true, 0) there instead of dalek's (false, 0) keeps all 337 tests
// green, because `den == 0` forces `w0 = 2*s*den` to zero whichever branch is
// taken, and every point with X = T = 0 is in the identity's coset. The
// (u != 0, v == 0) case of `_sqrtRatio` is separately reached already -- by
// `encode` of the identity, where u1 and u2 are both zero -- and making it
// revert turns 7 existing tests red.
//
// HOW THE INPUTS ARE FOUND. RFC 9496 section 4.3.4 defines MAP(t) over
//
//     r   = i * t^2
//     n   = (r + 1) * (1 - d^2)
//     den = (c - d*r) * (r + d)                    with c = -1
//     s   = sqrt(n / den), or -|s*t| when n/den is not a square
//
// so each degeneracy is a polynomial condition on `r`, and `r = i * t^2` turns
// a root into a concrete 32-byte half whenever r/i is a square. No copy of the
// map lives here -- only the equations the RFC prints. The constants they are
// evaluated on are DEFINITIONS rather than values lifted from
// src/Ristretto255.sol: `d` is -121665/121666, and `i` is a square root of -1
// reached by exponentiation. Editing the contract's constants to agree with a
// mistake would not move these.

const modp = (a) => ((a % FIELD_P) + FIELD_P) % FIELD_P;
const mulp = (a, b) => modp(a * b);
const powp = (b, e) => {
  let r = 1n;
  b = modp(b);
  while (e > 0n) {
    if (e & 1n) r = mulp(r, b);
    b = mulp(b, b);
    e >>= 1n;
  }
  return r;
};
const invp = (a) => powp(a, FIELD_P - 2n);

/// p = 5 (mod 8), so 2 is a non-residue and 2^((p-1)/4) squares to -1.
///
/// The EVEN root, which is the one `Ristretto255.SQRT_M1` holds. That choice
/// is load-bearing, and the comment on that constant says the opposite -- it
/// argues the root cannot matter because `_sqrtRatio` re-normalizes and
/// `encode` discards it, and does not mention `_map`, which multiplies by it
/// directly. Replacing the constant with `p - SQRT_M1` turns 21 tests red.
const SQRT_MINUS_1 = (() => {
  const r = powp(2n, (FIELD_P - 1n) / 4n);
  return (r & 1n) === 0n ? r : FIELD_P - r;
})();

/// The curve constant by its definition, not by its value.
const CURVE_D = mulp(modp(-121665n), invp(121666n));

/// p = 5 (mod 8): a^((p+3)/8) is the root up to a factor of i.
const sqrtp = (a) => {
  a = modp(a);
  if (a === 0n) return 0n;
  let x = powp(a, (FIELD_P + 3n) / 8n);
  if (mulp(x, x) !== a) x = mulp(x, SQRT_MINUS_1);
  return mulp(x, x) === a ? x : null;
};

/// Roots of A*x^2 + B*x + C over F_p. An empty result is an ANSWER and not a
/// failure: it means no `r` satisfies that condition, so no 64-byte input
/// reaches that branch at all.
const rootsOf = (A, B, C) => {
  A = modp(A);
  B = modp(B);
  C = modp(C);
  if (A === 0n) return B === 0n ? [] : [mulp(modp(-C), invp(B))];
  const disc = sqrtp(modp(mulp(B, B) - mulp(4n, mulp(A, C))));
  if (disc === null) return [];
  const twoA = invp(mulp(2n, A));
  return [
    ...new Set([
      mulp(modp(disc - B), twoA),
      mulp(modp(modp(-disc) - B), twoA),
    ]),
  ];
};

/// The 32-byte half that drives the map to a given `r`, or null when r/i is a
/// non-square and no half reaches it.
const halfReaching = (r) => {
  const t = sqrtp(mulp(r, invp(SQRT_MINUS_1)));
  return t === null ? null : bigToLE(t);
};

/// den = (-1 - d*r) * (r + d) vanishes at exactly these two r.
const DEN_ZERO = [modp(-CURVE_D), modp(-invp(CURVE_D))];

/// 1 - s^2 vanishes when s^2 = 1, which kills Y and T of the map's output. In
/// the square branch s^2 = n/den, so the condition is n = den; in the
/// non-square branch s' = -|s*t| with s^2 = i*n/den, so s'^2 = n*r/den and the
/// condition is n*r = den. Expanded over n = (r+1)(1-d^2) and
/// den = -(d*r^2 + (1+d^2)*r + d), each is a quadratic in r:
const S_SQUARED_ONE = [
  ...rootsOf(CURVE_D, 2n, modp(CURVE_D + 1n - mulp(CURVE_D, CURVE_D))),
  ...rootsOf(modp(1n - mulp(CURVE_D, CURVE_D) + CURVE_D), 2n, CURVE_D),
];

await test('the map\'s degenerate branches are REACHED, and every one of them '
  + 'lands on the identity', async () => {
  const cases = [];
  for (const r of DEN_ZERO) {
    const h = halfReaching(r);
    // Both of these must exist. If an edit above made them non-squares this
    // test would quietly stop testing anything, so it is an assertion.
    assert(h !== null, `no 32-byte half reaches den = 0 at r = ${r}`);
    cases.push([`den = 0 at r = ${r}`, h]);
  }
  for (const r of S_SQUARED_ONE) {
    const h = halfReaching(r);
    if (h === null) continue; // that root is not on the map's input side
    cases.push([`1 - s^2 = 0 at r = ${r}`, h]);
  }
  // Asserted as a count so that an arithmetic slip producing an EMPTY list
  // could not leave this test green over a loop that never runs.
  assertEq(cases.length, 6,
    `solved ${cases.length} degenerate inputs, expected 6 -- two where the `
    + 'denominator vanishes and four where s^2 = 1');

  for (const [name, t] of cases) {
    assert(t !== IDENTITY, `${name}: solved to t = 0, the trivial case`);
    assertEq(await mapToPoint(t), IDENTITY,
      `${name}: MAP did not land on the identity`);
    // Evenness holds here too, where `s` is pinned by the branch and not by t.
    assertEq(await mapToPoint(negateEncoding(t)), IDENTITY,
      `${name}: MAP(-t) != MAP(t)`);
    // The map has no failure case, so even a degenerate output has to be an
    // encoding the library's own decoder accepts.
    assert(await decodes(await mapToPoint(t)),
      `${name}: the map produced an encoding decode() refuses`);
  }

  // NON-VACUITY. Landing on the identity is astronomically rare, so the
  // neighbours of every solved input must NOT land there -- otherwise the
  // assertions above would be about the map having collapsed rather than about
  // these inputs in particular.
  for (const [name, t] of cases) {
    const near = bigToLE(modp(leToBig(t) + 1n));
    assert(await mapToPoint(near) !== IDENTITY,
      `${name}: t + 1 maps to the identity too, so this test shows nothing`);
  }
});

await test('DegenerateValueGenerator is reachable THROUGH the map, not only '
  + 'through a digest of zeros', async () => {
  // The existing degeneracy test above feeds 64 zero bytes. That is the one
  // digest which never exercises the map -- MAP(0) is the identity by
  // inspection -- so it shows the guard fires without showing that anything
  // the map COMPUTES can reach it. These two halves are non-zero, are not each
  // other's negation, and each runs the whole Elligator before arriving at the
  // identity through the vanishing denominator solved for above.
  const halves = DEN_ZERO.map(halfReaching);
  assert(halves.every((h) => h !== null && h !== IDENTITY),
    'the solved halves are trivial');
  assert(halves[0] !== halves[1], 'the two halves are the same input');
  assert(halves[0] !== negateEncoding(halves[1]),
    'the halves are negations, so evenness alone would explain the result');

  const bad = await chain.call(gens,
    selector('fromDigestHalves(uint64,bytes32,bytes32)')
    + word(8192n) + b32(halves[0]) + b32(halves[1]));
  assert(!bad.ok, 'a digest whose map output is the identity was accepted');
  assertEq(bad.ret.slice(0, 10), selector('DegenerateValueGenerator(uint64)'),
    `refused, but not as DegenerateValueGenerator -- ${revertReason(bad.ret)}`);
  assertEq(BigInt('0x' + bad.ret.slice(10)), 8192n,
    'the error must carry the token id');

  // THE CONTROL. Each degenerate half paired with a real digest half is
  // ACCEPTED, so the refusal above is about the sum being the identity and not
  // about these particular bytes being rejected on sight.
  for (const h of halves) {
    const ok = await chain.must(gens,
      selector('fromDigestHalves(uint64,bytes32,bytes32)')
      + word(8192n) + b32(h) + b32(HALVES[0][1]));
    assert(ok.ret.slice(0, 66) !== IDENTITY,
      'the control pair is degenerate too, so it controls for nothing');
  }
});

await test('B_blinding is the basepoint and is not derived from anything',
  async () => {
  // MobileCoin's B_BLINDING is RISTRETTO_BASEPOINT_POINT for every token id, so
  // it is neither a parameter nor a derivation. If the oracle ever says
  // otherwise, AmountOpener.requireCommitment is wrong.
  //
  // THE ASSERTION READS THE CONTRACT. It used to be
  // `assertEq(AMT.generators.bBlinding, AMT.generators.basepointCompressed)`
  // -- two fields of one fixture, compared to each other. That is a true
  // statement about MobileCoin which no change to any contract in src/ could
  // turn red, sitting in a suite whose whole purpose is to turn red when a
  // contract changes. Going through `basepointEncoding()` makes the left-hand
  // side the basepoint the library will actually use.
  const encoded = (await callOk(selector('basepointEncoding()'))).ret.slice(0, 66);
  assertEq(encoded, AMT.generators.bBlinding,
    'the contract\'s basepoint is not MobileCoin\'s B_BLINDING');

  // WHAT THIS DOES NOT ESTABLISH. `Ristretto255.basepoint()` is hard-coded
  // into `AmountOpener.requireCommitment`, and the line above reads it through
  // a probe that names the same function -- so it pins the VALUE, not the wiring.
  // What pins the wiring is `verifier.mjs`'s commitment tests: MobileCoin
  // formed those commitments over B_BLINDING, and they only reproduce on chain
  // if `requireCommitment` uses the same point.
  //
  // Kept as well, and labelled: this line guards the ORACLE, not the code. It
  // says amount.json's two fields still agree with each other, which is worth
  // knowing when the fixture is regenerated and worth nothing as coverage.
  assertEq(AMT.generators.bBlinding, AMT.generators.basepointCompressed,
    'ORACLE CHECK (not coverage): amount.json now disagrees with itself about '
    + 'the basepoint');
});

// ------------------------------- 6b. the independent cross-check

/// A THIRD implementation's answers, over a much wider input set.
///
/// contracts/test/fixtures/ristretto-noble.json is produced by
/// contracts/test/fixtures/generate-ristretto-noble.mjs from @noble/curves
/// 1.9.7 and @noble/hashes 1.8.0 -- neither the curve25519-dalek that produced
/// amount.json nor this repo's Solidity. Read-only: nothing in the suite
/// writes to it. Its own `_header` says the same, so the claim travels with
/// the file.
///
/// WHY IT EXISTS. The `abs` in `s' = -|s*t|` was caught by exactly ONE
/// assertion in this whole repo -- 'the map is even: MAP(t) == MAP(-t)' above
/// -- and by none of the four `bToken` vectors, which pass on the broken map.
/// A single hand-written property test standing alone over a branch of a
/// hash-to-curve is a single point of failure.
///
/// MEASURED, by deleting that `abs` in an isolated copy and running the suite:
/// 20 of the 62 vectors below and 21 of the 56 token ids go red, while both
/// oracle-vector tests stay green. One red test became three, and two of them
/// say how many inputs disagree rather than only that one does.
const NOBLE = JSON.parse(readFileSync(
  join(HERE, 'fixtures', 'ristretto-noble.json'), 'utf8'));

await test('@noble/curves agrees with the contract on 62 from_uniform_bytes '
  + 'vectors', async () => {
  assertEq(NOBLE.fromUniformBytes.length, 62,
    'the cross-check fixture changed size -- regenerate it deliberately');
  assertEq(NOBLE.basepointCompressed, AMT.generators.basepointCompressed,
    'noble and MobileCoin disagree about the ristretto basepoint, so this '
    + 'whole file is measuring the wrong curve');

  // Distinct inputs, or "62 vectors" is a count of repeats.
  const inputs = new Set(NOBLE.fromUniformBytes.map((v) => v.lo + v.hi));
  assertEq(inputs.size, NOBLE.fromUniformBytes.length,
    'the cross-check fixture has duplicate inputs');

  // Every mismatch is collected rather than thrown on, because the COUNT is
  // the diagnosis: one wrong vector is a bad vector, half of them wrong is a
  // branch of the map.
  const bad = [];
  for (const v of NOBLE.fromUniformBytes) {
    const got = await fromUniform(v.lo, v.hi);
    if (got.toLowerCase() !== v.encoded.toLowerCase()) {
      bad.push(`${v.name}: got ${got} want ${v.encoded}`);
    }
  }
  assert(bad.length === 0,
    `${bad.length} of ${NOBLE.fromUniformBytes.length} vectors disagree with `
    + `@noble/curves ${'1.9.7'}. First: ${bad[0]}`);
});

await test('@noble/curves agrees with the contract on generators(id) for 56 '
  + 'token ids', async () => {
  // The whole derivation -- preimage, Blake2b-512, both maps, the sum, the
  // encoding -- for fourteen times as many ids as the oracle publishes,
  // including every low nibble, both sides of every power-of-two boundary the
  // XOR can straddle, eUSD's 8192 and both ends of u64.
  assertEq(NOBLE.generators.length, 56,
    'the cross-check fixture changed size -- regenerate it deliberately');

  // The four ids amount.json also publishes must agree between the two
  // independent oracles. If dalek and noble disagreed, a mismatch below would
  // be ambiguous.
  for (const g of AMT.generators.byTokenId) {
    const n = NOBLE.generators.find((x) => x.tokenId === g.tokenId);
    assert(n, `the cross-check lost token id ${g.tokenId}`);
    assertEq(n.bToken, g.bToken,
      `noble and dalek disagree on generators(${g.tokenId}).B`);
    assertEq(n.preimage, g.preimage,
      `noble and dalek disagree on the preimage for ${g.tokenId}`);
  }

  const bad = [];
  for (const g of NOBLE.generators) {
    const pre = await genPreimage(g.tokenId);
    if (pre.toLowerCase() !== g.preimage.toLowerCase()) {
      bad.push(`preimage ${g.tokenId}: got ${pre} want ${g.preimage}`);
      continue;
    }
    const b = await genValue(g.tokenId);
    if (b.toLowerCase() !== g.bToken.toLowerCase()) {
      bad.push(`B_token ${g.tokenId}: got ${b} want ${g.bToken}`);
    }
  }
  assert(bad.length === 0,
    `${bad.length} of ${NOBLE.generators.length} token ids disagree with `
    + `@noble/curves 1.9.7. First: ${bad[0]}`);
});

const gasDerive = (await chain.call(gens,
  selector('valueGenerator(uint64)') + word(8192n))).gas;

// ------------------------------------------------------ 7. the recipient check

console.log('\nRecipientCheck');

const isPayable = async (host, txPub, target, spend) => {
  const r = await chain.call(host,
    selector('isPayableToBridge(bytes32,bytes32,bytes32)')
      + b32(txPub) + b32(target) + b32(spend));
  assert(r.ok, `isPayableToBridge reverted: ${revertReason(r.ret)}`);
  return { ok: decodeBool(r.ret), gas: r.gas };
};

const hosts = [];
for (const c of V.recipients) {
  hosts.push(await chain.deploy('RecipientCheck', b32(c.view_private_key)));
}

await test('the real subaddress spend key is accepted', async () => {
  for (const [i, c] of V.recipients.entries()) {
    const { ok } = await isPayable(
      hosts[i], c.tx_public_key, c.target_key, c.spend_public_key
    );
    assert(ok, `case ${c.case}: a genuine output was refused`);
  }
});

await test('a different subaddress spend key is refused', async () => {
  // This is the whole point: an attacker who can produce a quorum-signed block
  // containing an eUSD output paying THEMSELVES must not be able to redeem it.
  for (const [i, c] of V.recipients.entries()) {
    const { ok } = await isPayable(
      hosts[i], c.tx_public_key, c.target_key, c.wrong_spend_public_key
    );
    assert(!ok, `case ${c.case}: an output to someone else was accepted`);
  }
});

await test('every argument is load-bearing', async () => {
  // A check that ignored any one of its three arguments would pass the two
  // tests above on at least one of these substitutions.
  const [a, b] = V.recipients;
  const swaps = [
    ['tx_public_key', [b.tx_public_key, a.target_key, a.spend_public_key]],
    ['target_key', [a.tx_public_key, b.target_key, a.spend_public_key]],
    ['spend_public_key', [a.tx_public_key, a.target_key, b.spend_public_key]],
  ];
  for (const [name, args] of swaps) {
    const { ok } = await isPayable(hosts[0], ...args);
    assert(!ok, `swapping ${name} between cases was still accepted`);
  }
});

await test('the view private key is load-bearing', async () => {
  // Case 0's output checked by case 1's contract: same code, different `a`.
  const c = V.recipients[0];
  const { ok } = await isPayable(
    hosts[1], c.tx_public_key, c.target_key, c.spend_public_key
  );
  assert(!ok, 'the wrong view key still recognized the output');
});

await test('a one-bit change in the target key is refused', async () => {
  const c = V.recipients[0];
  const flipped = c.target_key.slice(0, -1)
    + (parseInt(c.target_key.slice(-1), 16) ^ 1).toString(16);
  const { ok } = await isPayable(
    hosts[0], c.tx_public_key, flipped, c.spend_public_key
  );
  assert(!ok, 'a mutated target key was accepted');
});

await test('keys that are not ristretto encodings are refused', async () => {
  const c = V.recipients[0];
  for (const bad of V.rejects.map((r) => r.encoded)) {
    let { ok } = await isPayable(hosts[0], bad, c.target_key, c.spend_public_key);
    assert(!ok, `${bad} accepted as a tx public key`);
    ({ ok } = await isPayable(hosts[0], c.tx_public_key, bad, c.spend_public_key));
    assert(!ok, `${bad} accepted as a target key`);
    ({ ok } = await isPayable(hosts[0], c.tx_public_key, c.target_key, bad));
    assert(!ok, `${bad} accepted as a spend key`);
  }
});

await test('a zero spend key is refused', async () => {
  // The identity is the one D for which the relation is solvable by anyone,
  // since the view key is public. A verifier misconfigured that way must
  // redeem nothing, not everything.
  const c = V.recipients[0];
  const zero = '0x' + '00'.repeat(32);
  const { ok } = await isPayable(hosts[0], c.tx_public_key, c.target_key, zero);
  assert(!ok, 'the identity was accepted as the bridge spend key');
});

await test('a view private key that is not a canonical scalar is rejected', async () => {
  for (const bad of [L_LE, '0x' + '00'.repeat(32), '0x' + 'ff'.repeat(32)]) {
    let threw = false;
    try {
      await chain.deploy('RecipientCheck', b32(bad));
    } catch (e) {
      threw = true;
    }
    assert(threw, `deployment accepted view key ${bad}`);
  }
});

// ---------------------------------------------------------------- 8. gas

console.log(`\n  gas: deriving one generators(token_id).B costs ` +
  `${gasDerive.toLocaleString()} (constructor-only; verifyReturn never runs it)`);

const { gas } = await isPayable(
  hosts[0], V.recipients[0].tx_public_key, V.recipients[0].target_key,
  V.recipients[0].spend_public_key
);
console.log(`\n  gas: one full recipient check costs ${gas.toLocaleString()}`);

summary();
