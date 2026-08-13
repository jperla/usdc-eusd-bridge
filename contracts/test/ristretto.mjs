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

const chain = await Chain.create({
  only: ['Ristretto255.sol', 'RecipientCheck.sol'],
});
const probe = await chain.deploy('Ristretto255Probe');

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

const hashProbe = await chain.deploy('Blake2b256Probe');
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

// ------------------------------------------------------ 5. the recipient check

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

// ---------------------------------------------------------------- 6. gas

const { gas } = await isPayable(
  hosts[0], V.recipients[0].tx_public_key, V.recipients[0].target_key,
  V.recipients[0].spend_public_key
);
console.log(`\n  gas: one full recipient check costs ${gas.toLocaleString()}`);

summary();
