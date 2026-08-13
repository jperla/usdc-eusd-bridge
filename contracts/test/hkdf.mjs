// Tests for Hkdf.sol -- HMAC-SHA-512 and HKDF-SHA-512.
//
// Three independent sources of truth, none of them this Solidity code:
//
//   1. RFC 4231's published HMAC-SHA-512 vectors and RFC 5869's published
//      HKDF vectors, transcribed as constants. These are the external anchor;
//      everything else could in principle drift together, these cannot.
//   2. Node's crypto (OpenSSL) -- createHmac and hkdfSync -- used for the
//      randomised differential and for the length sweep, where hand-copying
//      hundreds of vectors is not practical.
//   3. contracts/test/fixtures/amount.json, produced by tools/amount-fixtures
//      out of MobileCoin's own crates. That is what makes the "repo usage"
//      tests below tests of MobileCoin compatibility and not just of RFC
//      compliance.
//
// The bug this file exists to catch is the block size. HMAC pads the key to
// the HASH's block size; SHA-512's is 128 bytes even though its digest is 64.
// A 64-byte-block HMAC is internally consistent -- it round-trips, it is
// deterministic, it changes when its inputs change -- and wrong. So one test
// below builds the wrong answer on purpose and asserts the contract does not
// produce it, rather than only asserting it produces the right one.

import crypto from 'crypto';
import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { keccak256 } from 'ethereum-cryptography/keccak.js';
import {
  Chain, selector, word, b32, dynBytes, test, assert, assertEq, summary,
  revertReason,
} from './harness.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(HERE, 'fixtures', 'amount.json'), 'utf8'));
const SEP = V.domainSeparators;

const HASH_BYTES = 64;
const MAX_OKM = 255 * HASH_BYTES;

// ------------------------------------------------------------------ encoding

const hx = (b) => '0x' + Buffer.from(b).toString('hex');
const buf = (h) => Buffer.from(String(h).replace(/^0x/, ''), 'hex');
const ascii = (s) => Buffer.from(s, 'utf8');

/// ABI-encode a call from a positional type list. The harness only ships a
/// single-trailing-`bytes` encoder and three of these signatures take several.
const encode = (sig, args) => {
  const head = [];
  const tail = [];
  let off = args.length * 32;
  for (const a of args) {
    if (a.t === 'bytes') {
      head.push(word(off));
      const d = dynBytes(hx(a.v));
      tail.push(d);
      off += d.length / 2;
    } else if (a.t === 'bytes32') {
      head.push(b32(hx(a.v)));
    } else {
      head.push(word(a.v));
    }
  }
  return selector(sig) + head.join('') + tail.join('');
};

// ------------------------------------------------- reference implementations

/// HMAC with an explicit block size, so the wrong one can be constructed.
///
/// Built from the bare hash rather than from crypto.createHmac: createHmac
/// picks the block size itself, which is exactly the decision under test.
const hmacRef = (blockBytes, key, data) => {
  let k = Buffer.from(key);
  if (k.length > blockBytes) k = crypto.createHash('sha512').update(k).digest();
  const k0 = Buffer.alloc(blockBytes);
  k.copy(k0);
  const x = (padByte) => {
    const o = Buffer.alloc(blockBytes);
    for (let i = 0; i < blockBytes; i++) o[i] = k0[i] ^ padByte;
    return o;
  };
  const inner = crypto.createHash('sha512')
    .update(Buffer.concat([x(0x36), Buffer.from(data)])).digest();
  return crypto.createHash('sha512')
    .update(Buffer.concat([x(0x5c), inner])).digest();
};

const nodeHmac = (key, data) =>
  crypto.createHmac('sha512', Buffer.from(key)).update(Buffer.from(data)).digest();

const nodeHkdf = (salt, ikm, info, len) =>
  Buffer.from(crypto.hkdfSync('sha512', Buffer.from(ikm), Buffer.from(salt),
    Buffer.from(info), len));

// --------------------------------------------------------------------- chain

const chain = await Chain.create({ only: ['Hkdf.sol'] });
const probe = await chain.deploy('HkdfProbe');

const ERRORS = {
  [selector('HkdfOutputTooLong(uint256,uint256)')]: 'HkdfOutputTooLong',
};

const hmac = async (key, data) => {
  const r = await chain.call(probe,
    encode('hmac(bytes,bytes)', [{ t: 'bytes', v: key }, { t: 'bytes', v: data }]));
  assert(r.ok, `hmac reverted: ${revertReason(r.ret, ERRORS)}`);
  return Buffer.from(r.ret.slice(2), 'hex');
};

const extract = async (salt, ikm) => {
  const r = await chain.call(probe,
    encode('extract(bytes,bytes)', [{ t: 'bytes', v: salt }, { t: 'bytes', v: ikm }]));
  assert(r.ok, `extract reverted: ${revertReason(r.ret, ERRORS)}`);
  return Buffer.from(r.ret.slice(2), 'hex');
};

/// The full four words the probe returns, including whatever sits past
/// `length` in the OKM's final word.
const expandWords = async (prk, info, length) => {
  const r = await chain.call(probe, encode(
    'expandWords(bytes32,bytes32,bytes,uint256)',
    [
      { t: 'bytes32', v: prk.subarray(0, 32) },
      { t: 'bytes32', v: prk.subarray(32, 64) },
      { t: 'bytes', v: info },
      { t: 'uint256', v: length },
    ],
  ));
  return r;
};

const expand = async (prk, info, length) => {
  const r = await expandWords(prk, info, length);
  assert(r.ok, `expand reverted: ${revertReason(r.ret, ERRORS)}`);
  return Buffer.from(r.ret.slice(2), 'hex').subarray(0, length);
};

/// keccak of the OKM plus its length, so lengths past the probe's four-word
/// window are still checkable.
const expandDigest = async (prk, info, length, opts) => {
  const r = await chain.call(probe, encode(
    'expandDigest(bytes32,bytes32,bytes,uint256)',
    [
      { t: 'bytes32', v: prk.subarray(0, 32) },
      { t: 'bytes32', v: prk.subarray(32, 64) },
      { t: 'bytes', v: info },
      { t: 'uint256', v: length },
    ],
  ), opts);
  assert(r.ok, `expandDigest reverted: ${revertReason(r.ret, ERRORS)}`);
  const h = r.ret.slice(2);
  return {
    len: BigInt('0x' + h.slice(0, 64)),
    digest: '0x' + h.slice(64, 128),
  };
};

const derive = async (salt, ikm, info, length) => {
  const r = await chain.call(probe, encode(
    'deriveWords(bytes,bytes,bytes,uint256)',
    [
      { t: 'bytes', v: salt },
      { t: 'bytes', v: ikm },
      { t: 'bytes', v: info },
      { t: 'uint256', v: length },
    ],
  ));
  assert(r.ok, `derive reverted: ${revertReason(r.ret, ERRORS)}`);
  return Buffer.from(r.ret.slice(2), 'hex').subarray(0, length);
};

console.log('\nHkdf');

// ------------------------------------------------------- HMAC-SHA-512, RFC 4231
//
// Transcribed from RFC 4231 s4. Cases 6 and 7 use a 131-byte key, which is the
// only place the "hash a key longer than the block" branch runs; without them
// that branch is dead code that no MobileCoin input would ever reach either.

const RFC4231 = [
  {
    name: 'TC1  20-byte key',
    key: buf('0b'.repeat(20)),
    data: ascii('Hi There'),
    mac: '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde'
       + 'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
  },
  {
    name: 'TC2  4-byte key ("Jefe")',
    key: ascii('Jefe'),
    data: ascii('what do ya want for nothing?'),
    mac: '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554'
       + '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
  },
  {
    name: 'TC3  20-byte key, 50-byte data',
    key: buf('aa'.repeat(20)),
    data: buf('dd'.repeat(50)),
    mac: 'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39'
       + 'bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
  },
  {
    name: 'TC4  25-byte key',
    key: buf('0102030405060708090a0b0c0d0e0f10111213141516171819'),
    data: buf('cd'.repeat(50)),
    mac: 'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db'
       + 'a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
  },
  {
    name: 'TC5  20-byte key, truncation case',
    key: buf('0c'.repeat(20)),
    data: ascii('Test With Truncation'),
    // RFC 4231 publishes only the first 16 bytes for this case; the rest comes
    // from OpenSSL, and the test below asserts the published prefix separately
    // so the transcription is anchored to the RFC either way.
    mac: '415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008'
       + '711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b',
    rfcPrefix: '415fad6271580a531d4179bc891d87a6',
  },
  {
    name: 'TC6  131-byte key (longer than the block)',
    key: buf('aa'.repeat(131)),
    data: ascii('Test Using Larger Than Block-Size Key - Hash Key First'),
    mac: '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352'
       + '6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
  },
  {
    name: 'TC7  131-byte key, 152-byte data',
    key: buf('aa'.repeat(131)),
    data: ascii('This is a test using a larger than block-size key and a '
      + 'larger than block-size data. The key needs to be hashed before '
      + 'being used by the HMAC algorithm.'),
    mac: 'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944'
       + 'b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
  },
];

for (const v of RFC4231) {
  await test(`HMAC-SHA-512 matches RFC 4231 ${v.name}`, async () => {
    assertEq(hx(await hmac(v.key, v.data)), '0x' + v.mac, v.name);
  });
}

await test('the transcribed RFC 4231 vectors are the RFC\'s own', async () => {
  // Guards the transcription itself: a typo in a constant above would
  // otherwise turn into a "the contract is wrong" failure that sends the next
  // reader after the Solidity. OpenSSL is the second opinion, and TC5's
  // published 16-byte prefix is checked against the RFC directly.
  for (const v of RFC4231) {
    assertEq(hx(nodeHmac(v.key, v.data)), '0x' + v.mac, `${v.name} vs OpenSSL`);
  }
  const tc5 = RFC4231.find((v) => v.rfcPrefix);
  assertEq(tc5.mac.slice(0, 32), tc5.rfcPrefix, 'TC5 published prefix');
});

// ------------------------------------------------------------ the block size

await test('HMAC pads the key to 128 bytes, not 64', async () => {
  // The whole point of this file. Both references below are real HMAC
  // constructions and differ only in the block size, so this cannot pass by
  // accident and cannot pass for a 64-byte-block implementation.
  const key = buf('11'.repeat(20));
  const data = ascii('mc_amount_shared_secret');
  const got = hx(await hmac(key, data));

  const right = hx(hmacRef(128, key, data));
  const wrong = hx(hmacRef(64, key, data));
  assert(right !== wrong, 'the two block sizes must give different answers');
  assertEq(hx(nodeHmac(key, data)), right, 'the 128-byte reference is real HMAC');

  assertEq(got, right, 'HMAC-SHA-512 block size');
  assert(got !== wrong, 'contract produced the 64-byte-block answer');
});

await test('a 64-byte-block HMAC would break the real memo derivation', async () => {
  // Same point, but on an input the bridge actually uses, so the failure mode
  // is visible as "the memo decrypts to the wrong beneficiary" rather than as
  // an abstract vector mismatch.
  const m = V.memos[0];
  const salt = ascii(SEP.memoOkmSalt);
  const ikm = buf(m.sharedSecret);
  const got = hx(await extract(salt, ikm));
  assertEq(got, hx(hmacRef(128, salt, ikm)), 'memo PRK');
  assert(got !== hx(hmacRef(64, salt, ikm)), 'memo PRK from a 64-byte block');
});

for (const n of [63, 64, 65, 127, 128, 129, 200]) {
  await test(`HMAC handles a ${n}-byte key`, async () => {
    const key = crypto.createHash('sha512').update(`key-${n}`).digest()
      .toString('hex').repeat(8);
    const k = buf(key).subarray(0, n);
    assertEq(k.length, n, 'key length');
    const data = ascii(`data for ${n}`);
    assertEq(hx(await hmac(k, data)), hx(nodeHmac(k, data)), `${n}-byte key`);
  });
}

await test('a key longer than the block is replaced by its digest', async () => {
  // RFC 2104 s2. Stated as a property rather than a vector: HMAC(K, m) for
  // |K| > 128 must equal HMAC(SHA-512(K), m).
  const k = buf('c3'.repeat(129));
  const m = ascii('over-long key');
  const kh = crypto.createHash('sha512').update(k).digest();
  assertEq(hx(await hmac(k, m)), hx(await hmac(kh, m)), 'K vs H(K)');
});

await test('a key of exactly the block size is NOT hashed', async () => {
  // The boundary is `> 128`, not `>= 128`. An off-by-one here is invisible in
  // every RFC vector (none uses a 128-byte key) and changes the answer for
  // any caller that does.
  const k = buf('c3'.repeat(128));
  const m = ascii('exact block key');
  const kh = crypto.createHash('sha512').update(k).digest();
  const got = hx(await hmac(k, m));
  assertEq(got, hx(nodeHmac(k, m)), '128-byte key');
  assert(got !== hx(await hmac(kh, m)), '128-byte key must not be hashed first');
});

await test('HMAC ignores the memory behind a short key', async () => {
  // The key is loaded a word at a time, so the bytes past its end are
  // allocator slack and must be masked off. In ordinary use that slack is
  // zero and a missing mask is invisible; `hmacDirtyKey` paints it 0xff
  // first, so an unmasked read changes the MAC. Every length below is one
  // whose final word is partial.
  const m = ascii('short key');
  for (const n of [0, 1, 5, 20, 31, 33, 63, 65, 100, 127]) {
    const k = crypto.createHash('sha512').update(`k${n}`).digest()
      .toString('hex').repeat(4);
    const key = buf(k).subarray(0, n);
    const r = await chain.call(probe, encode('hmacDirtyKey(bytes,bytes)',
      [{ t: 'bytes', v: key }, { t: 'bytes', v: m }]));
    assert(r.ok, `hmacDirtyKey reverted: ${revertReason(r.ret, ERRORS)}`);
    assertEq(r.ret, hx(nodeHmac(key, m)), `${n}-byte key with dirty slack`);
    assertEq(hx(await hmac(key, m)), hx(nodeHmac(key, m)), `${n}-byte key, clean`);
  }
});

// -------------------------------------------------------- HKDF, RFC 5869
//
// From the fixture. Only the SHA-512 rows apply -- this library is SHA-512
// only, and the SHA-256 rows are there for a different consumer.

const sha512Vectors = V.hkdf.filter((v) => v.hash === 'SHA-512');
assert(sha512Vectors.length > 0, 'fixture has no SHA-512 HKDF vectors');

for (const v of sha512Vectors) {
  await test(`HKDF-SHA-512 matches fixture vector ${v.name}`, async () => {
    const okm = await derive(buf(v.salt), buf(v.ikm), buf(v.info), v.length);
    assertEq(hx(okm), v.okm, v.name);
  });
}

await test('the fixture\'s RFC 5869 rows are the RFC\'s own', async () => {
  // The three rfc5869-* rows are published vectors; the -sha512 variants are
  // the same inputs under SHA-512. Checking the SHA-256 rows against the RFC
  // constants confirms the fixture's inputs were not mistyped, which is what
  // makes the SHA-512 rows trustworthy.
  const published = {
    'rfc5869-tc1': '0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d'
      + '56ecc4c5bf34007208d5b887185865',
    'rfc5869-tc2': '0xb11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19'
      + 'afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3'
      + 'db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
    'rfc5869-tc3': '0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c'
      + '738d2d9d201395faa4b61a96c8',
  };
  let seen = 0;
  for (const v of V.hkdf) {
    if (!(v.name in published)) continue;
    seen++;
    assertEq(v.okm, published[v.name], `${v.name} OKM`);
    assertEq(v.hash, 'SHA-256', `${v.name} hash`);
  }
  assertEq(seen, 3, 'expected all three RFC 5869 SHA-256 rows');
});

await test('an empty info is handled (RFC 5869 TC3, and the memo path)', async () => {
  const v = sha512Vectors.find((x) => x.name === 'rfc5869-tc3-sha512');
  assert(v && v.info === '0x', 'expected an empty-info SHA-512 vector');
  assertEq(hx(await derive(buf(v.salt), buf(v.ikm), Buffer.alloc(0), v.length)),
    v.okm, 'empty info');
});

await test('an output spanning several expand blocks is handled', async () => {
  // 82 bytes is two T-blocks: the second one has to feed T(1) back in, and an
  // implementation that only ever emits T(1) truncates silently.
  const v = sha512Vectors.find((x) => x.name === 'rfc5869-tc2-sha512');
  assert(v && v.length === 82, 'expected the 82-byte SHA-512 vector');
  const okm = await derive(buf(v.salt), buf(v.ikm), buf(v.info), 82);
  assertEq(hx(okm), v.okm, '82-byte OKM');
  assert(hx(okm.subarray(0, 64)) !== hx(okm.subarray(18, 82)), 'blocks differ');
});

// ----------------------------------------------------------- the repo's usages

await test('derives every amount mask in the fixture', async () => {
  // The real thing: value mask, token-id mask and the 64-byte blinding for all
  // eight MobileCoin-generated cases, from one PRK each.
  const salt = ascii(SEP.amountBlindingFactorsSalt);
  assertEq(V.maskedAmounts.length, 8, 'expected eight amount cases');
  for (const c of V.maskedAmounts) {
    const prk = await extract(salt, buf(c.amountSharedSecret));
    assertEq(hx(await expand(prk, ascii(SEP.amountValueInfo), 8)),
      c.valueMaskBytes, `case ${c.case} value mask`);
    assertEq(hx(await expand(prk, ascii(SEP.amountTokenIdInfo), 8)),
      c.tokenIdMaskBytes, `case ${c.case} token id mask`);
    assertEq(hx(await expand(prk, ascii(SEP.amountBlindingInfo), 64)),
      c.blindingWide, `case ${c.case} blinding`);
  }
});

await test('derives every memo OKM in the fixture', async () => {
  // salt = "mc-memo-okm", info = empty, 48 bytes = AES key (32) || nonce (16).
  const salt = ascii(SEP.memoOkmSalt);
  assertEq(V.memos.length, 4, 'expected four memo cases');
  for (const m of V.memos) {
    const okm = await derive(salt, buf(m.sharedSecret), Buffer.alloc(0), 48);
    assertEq(hx(okm), m.okm, `${m.name} OKM`);
    assertEq(hx(okm.subarray(0, 32)), m.aesKey, `${m.name} AES key`);
    assertEq(hx(okm.subarray(32, 48)), m.aesNonce, `${m.name} AES nonce`);
  }
});

await test('the fixture\'s own hkdf rows agree with the amount and memo cases',
  async () => {
    // The four non-RFC rows in `hkdf` are supposed to be the same calls the
    // cases above make. Pinning that here means a future fixture regeneration
    // that changed one but not the other cannot pass unnoticed.
    const amount = V.maskedAmounts.find(
      (c) => c.amountSharedSecret === V.hkdf.find((h) => h.name === 'mc-amount-value-mask').ikm);
    assert(amount, 'no amount case matches the value-mask row\'s IKM');
    for (const [rowName, field] of [
      ['mc-amount-value-mask', 'valueMaskBytes'],
      ['mc-amount-token-id-mask', 'tokenIdMaskBytes'],
      ['mc-amount-blinding', 'blindingWide'],
    ]) {
      const row = V.hkdf.find((h) => h.name === rowName);
      assertEq(row.salt, hx(ascii(SEP.amountBlindingFactorsSalt)), `${rowName} salt`);
      assertEq(row.okm, amount[field], `${rowName} vs case ${amount.case}`);
    }
    const memoRow = V.hkdf.find((h) => h.name === 'mc-memo-okm');
    const memo = V.memos.find((m) => m.sharedSecret === memoRow.ikm);
    assert(memo, 'no memo case matches the memo row\'s IKM');
    assertEq(memoRow.info, '0x', 'memo info is empty');
    assertEq(memoRow.okm, memo.okm, 'memo row vs memo case');
  });

await test('the salt is the HMAC key, not the IKM', async () => {
  // Swapping extract's two arguments produces a stable, random-looking PRK
  // that is simply not MobileCoin's. Nothing downstream would notice.
  const salt = ascii(SEP.amountBlindingFactorsSalt);
  const ikm = buf(V.maskedAmounts[0].amountSharedSecret);
  const prk = await extract(salt, ikm);
  assertEq(hx(prk), hx(nodeHmac(salt, ikm)), 'PRK = HMAC(key = salt, msg = IKM)');
  assert(hx(prk) !== hx(nodeHmac(ikm, salt)), 'arguments must not be swapped');
  assertEq(hx(await extract(ikm, salt)), hx(nodeHmac(ikm, salt)),
    'the swap is observable, so the check above can fail');
});

await test('derive equals extract followed by expand', async () => {
  const salt = ascii(SEP.amountBlindingFactorsSalt);
  const ikm = buf(V.maskedAmounts[3].amountSharedSecret);
  const info = ascii(SEP.amountBlindingInfo);
  const prk = await extract(salt, ikm);
  assertEq(hx(await derive(salt, ikm, info, 64)), hx(await expand(prk, info, 64)),
    'derive == expand(extract(...))');
});

// ------------------------------------------------------------ structure of expand

await test('an absent salt is the same as 64 zero bytes', async () => {
  // RFC 5869 s2.2: when no salt is provided the spec substitutes HashLen
  // zeros. HMAC's key padding makes those two identical, so this needs no
  // special case in the contract -- but it does need to be true.
  const ikm = buf('42'.repeat(32));
  const a = await extract(Buffer.alloc(0), ikm);
  const b = await extract(Buffer.alloc(64), ikm);
  assertEq(hx(a), hx(b), 'empty salt vs zero salt');
  assertEq(hx(a), hx(nodeHmac(Buffer.alloc(0), ikm)), 'vs OpenSSL');
  // Not vacuous. Any all-zero salt up to 128 bytes pads to the same block, so
  // the equality above holds for a reason and not by accident; at 129 bytes
  // the salt is hashed first and the PRK genuinely changes.
  const longZero = await extract(Buffer.alloc(129), ikm);
  assertEq(hx(await extract(Buffer.alloc(100), ikm)), hx(a), '100 zero bytes');
  assert(hx(longZero) !== hx(a), '129 zero bytes is a different key');
  assertEq(hx(longZero), hx(nodeHmac(Buffer.alloc(129), ikm)), '129 vs OpenSSL');
});

await test('the counter starts at 1 and the previous block is fed back', async () => {
  // T(1) = HMAC(PRK, info || 0x01) and T(2) = HMAC(PRK, T(1) || info || 0x02).
  // Both halves are ways to get a plausible-but-wrong OKM: a counter starting
  // at 0 shifts everything, and dropping the feedback makes T(2) independent
  // of T(1). Neither is visible in a single-block call.
  const prk = await extract(ascii('salt'), ascii('ikm'));
  const info = ascii('mc_amount_blinding');
  const okm = await expandDigest(prk, info, 128);

  const t1 = nodeHmac(prk, Buffer.concat([info, Buffer.from([1])]));
  const t2 = nodeHmac(prk, Buffer.concat([t1, info, Buffer.from([2])]));
  const want = Buffer.concat([t1, t2]);
  assertEq(okm.digest, hx(keccak256(want)), 'T(1) || T(2)');
  assertEq(okm.len, 128n, 'length');

  const noFeedback = Buffer.concat([t1, nodeHmac(prk, Buffer.concat([info, Buffer.from([2])]))]);
  assert(hx(keccak256(noFeedback)) !== okm.digest, 'feedback must be included');
  const zeroBased = nodeHmac(prk, Buffer.concat([info, Buffer.from([0])]));
  assert(hx(keccak256(zeroBased)) !== hx(keccak256(t1)), 'counter must start at 1');
});

await test('the first bytes of a longer OKM match a shorter one', async () => {
  const prk = await extract(ascii('salt'), ascii('ikm'));
  const info = ascii('i');
  const short = await expand(prk, info, 64);
  const long = await expand(prk, info, 128);
  assertEq(hx(long.subarray(0, 64)), hx(short), 'OKM is a prefix-stable stream');
});

await test('nothing is written past the requested length', async () => {
  // The final T-block is 64 bytes and the OKM is usually not a multiple of 64.
  // Writing the block whole and "truncating" afterwards leaves the surplus in
  // memory the caller allocated for something else. The probe returns the
  // OKM's full final word, so surplus bytes show up here as non-zero.
  const prk = await extract(ascii('salt'), ascii('ikm'));
  for (const len of [1, 8, 31, 42, 48, 63, 65, 82, 100]) {
    const r = await expandWords(prk, ascii('info'), len);
    assert(r.ok, `expand(${len}) reverted: ${revertReason(r.ret, ERRORS)}`);
    const all = Buffer.from(r.ret.slice(2), 'hex');
    const covered = Math.ceil(len / 32) * 32;
    assertEq(hx(all.subarray(0, len)),
      hx(nodeHkdf(ascii('salt'), ascii('ikm'), ascii('info'), len)), `okm ${len}`);
    assertEq(hx(all.subarray(len, covered)),
      hx(Buffer.alloc(covered - len)), `tail past ${len} must be zero`);
  }
});

await test('a zero-length output is empty', async () => {
  const prk = await extract(ascii('salt'), ascii('ikm'));
  const r = await expandDigest(prk, ascii('info'), 0);
  assertEq(r.len, 0n, 'length');
  assertEq(r.digest, hx(keccak256(Buffer.alloc(0))), 'keccak of empty');
});

for (const len of [1, 32, 63, 64, 65, 128, 129, 255, 1000]) {
  await test(`HKDF output length ${len} matches OpenSSL`, async () => {
    const salt = ascii(SEP.memoOkmSalt);
    const ikm = buf(V.memos[0].sharedSecret);
    const prk = await extract(salt, ikm);
    const r = await expandDigest(prk, Buffer.alloc(0), len);
    assertEq(r.len, BigInt(len), 'length');
    assertEq(r.digest, hx(keccak256(nodeHkdf(salt, ikm, Buffer.alloc(0), len))),
      `okm ${len}`);
  });
}

await test('the RFC 5869 output cap is enforced at exactly 255*HashLen', async () => {
  const prk = await extract(ascii('salt'), ascii('ikm'));
  const bad = await chain.call(probe, encode(
    'expandDigest(bytes32,bytes32,bytes,uint256)',
    [
      { t: 'bytes32', v: prk.subarray(0, 32) },
      { t: 'bytes32', v: prk.subarray(32, 64) },
      { t: 'bytes', v: Buffer.alloc(0) },
      { t: 'uint256', v: MAX_OKM + 1 },
    ],
  ));
  assert(!bad.ok, 'expected a revert at 255*64 + 1');
  assertEq(revertReason(bad.ret, ERRORS), 'HkdfOutputTooLong', 'error');

  // And the boundary itself is allowed -- otherwise a `>=` typo would pass the
  // rejection test above while quietly refusing a legal length. 255 chained
  // HMACs is ~147M gas, so this one call is given its own limit rather than
  // riding the harness default and failing as "out of gas" if that default or
  // the optimiser settings ever move.
  const ok = await expandDigest(prk, Buffer.alloc(0), MAX_OKM,
    { gasLimit: 600_000_000n });
  assertEq(ok.len, BigInt(MAX_OKM), 'length at the cap');
  assertEq(ok.digest,
    hx(keccak256(nodeHkdf(ascii('salt'), ascii('ikm'), Buffer.alloc(0), MAX_OKM))),
    'OKM at the cap');
});

// --------------------------------------------------------------- differential

await test('randomised differential against OpenSSL', async () => {
  // Deterministic seed: a failure here must be reproducible, and a suite whose
  // pass rate depends on the clock is not a suite.
  let seed = Buffer.from('hkdf-differential-seed');
  const next = (n) => {
    seed = crypto.createHash('sha512').update(seed).digest();
    return seed.subarray(0, n);
  };
  for (let i = 0; i < 12; i++) {
    const saltLen = next(1)[0] % 140;      // straddles the 128-byte block
    const ikmLen = next(1)[0] % 100;
    const infoLen = next(1)[0] % 70;
    const len = 1 + (next(1)[0] % 100);
    const salt = crypto.createHash('sha512').update(next(8)).digest()
      .toString('hex').repeat(4);
    const s = buf(salt).subarray(0, saltLen);
    const k = crypto.createHash('sha512').update(next(8)).digest().subarray(0, ikmLen);
    const inf = crypto.createHash('sha512').update(next(8)).digest().subarray(0, infoLen);
    const r = await expandDigest(await extract(s, k), inf, len);
    assertEq(r.digest, hx(keccak256(nodeHkdf(s, k, inf, len))),
      `case ${i}: salt=${saltLen} ikm=${ikmLen} info=${infoLen} len=${len}`);
  }
});

await test('the output depends on every input', async () => {
  // A library that ignored one of its arguments would satisfy any single
  // vector by construction; each pair below differs in exactly one input.
  const base = { salt: ascii('salt'), ikm: ascii('ikm'), info: ascii('info'), len: 32 };
  const of = async (o) => hx(await derive(o.salt ?? base.salt, o.ikm ?? base.ikm,
    o.info ?? base.info, o.len ?? base.len));
  const b = await of({});
  assert(b !== await of({ salt: ascii('salt2') }), 'salt must matter');
  assert(b !== await of({ ikm: ascii('ikm2') }), 'ikm must matter');
  assert(b !== await of({ info: ascii('info2') }), 'info must matter');
  // `length` is a prefix of the same stream, so it changes the OKM's size
  // rather than its bytes; the sweep above is what pins it.
  assertEq((await of({ len: 33 })).slice(0, 66), b, 'length truncates one stream');
});

summary();
