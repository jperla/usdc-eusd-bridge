// AES-256 known-answer tests.
//
// PUBLISHED VECTORS USED, in this order:
//
//   * FIPS 197 (Nov 2001) Appendix C.3, "AES-256 (Nk=8, Nr=14)": the single
//     block 00112233445566778899aabbccddeeff under key 000102...1e1f.
//   * NIST SP 800-38A (2001 ed.) Appendix F.1.5, "ECB-AES256.Encrypt": the
//     four-block message under key 603deb10...0914dff4. This is the block
//     cipher again, on four more independent inputs.
//   * NIST SP 800-38A Appendix F.5.5, "CTR-AES256.Encrypt": the same key and
//     message with initial counter block f0f1...feff. Its low 64 bits run
//     f8f9fafbfcfdfeff .. f8f9fafbfcfdff02 over the four blocks, so it never
//     reaches the 64-bit wrap and is a valid vector for Ctr64BE as well as for
//     the Ctr128BE that SP 800-38A itself specifies. It pins the counter
//     ORDER and the XOR direction; it cannot pin the counter WIDTH.
//   * The counter width comes from test/fixtures/amount.json's `memoCipher`,
//     whose nonces are placed by hand across the 64-bit boundary.
//
// The NIST vectors below are transcribed by hand, so every one of them is
// first re-derived from Node's OpenSSL bindings inside this file. A typo in a
// transcription would otherwise turn into a Solidity "bug" that is not one --
// or, worse, a Solidity bug papered over by a matching typo.
//
// Nothing here compares the Solidity against itself: the S-box constants are
// checked against the algebraic definition computed in JS, and every ciphertext
// against OpenSSL or against the Rust-generated fixture.

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { createCipheriv } from 'crypto';
import {
  Chain, selector, word, b32, dynBytes, encodeWithTrailingBytes,
  test, assert, assertEq, summary, revertReason,
} from './harness.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const F = JSON.parse(readFileSync(join(HERE, 'fixtures', 'amount.json'), 'utf8'));

const chain = await Chain.create({ only: ['Aes256.sol'] });
const probe = await chain.deploy('Aes256Probe');

// ------------------------------------------------------------------ encoding

const strip = (h) => h.replace(/^0x/, '').toLowerCase();

/// A `bytesN` argument: static, left-aligned, right-padded to a word.
const bN = (hex) => strip(hex).padEnd(64, '0');

/// The probe returns variable-length results as four zero-filled words rather
/// than as a `bytes` -- see the comment on `Aes256Probe`: solc 0.8.26 targets
/// Cancun and ABI-encodes a returned dynamic array with MCOPY, which the
/// Shanghai EVM the harness runs rejects as an invalid opcode. `len` is the
/// number of bytes the caller asked for; anything past it is padding.
const unpack = (ret, len) => {
  const h = strip(ret);
  assert(h.length === 256, `expected four words, got ${h.length / 2} bytes`);
  return h.slice(0, len * 2);
};

const ERRORS = {
  [selector('ProbeOutputTooLong(uint256)')]: 'ProbeOutputTooLong',
  [selector('ProbeBadIndex(uint256)')]: 'ProbeBadIndex',
};

// -------------------------------------------------------------------- calls

async function encryptBlock(key, input) {
  const r = await chain.call(probe,
    selector('encryptBlock(bytes32,bytes16)') + b32(key) + bN(input));
  assert(r.ok, `encryptBlock reverted: ${revertReason(r.ret, ERRORS)}`);
  return strip(r.ret).slice(0, 32);
}

async function keystream(key, nonce, len) {
  const r = await chain.call(probe,
    selector('keystream(bytes32,bytes16,uint256)') + b32(key) + bN(nonce) + word(len));
  assert(r.ok, `keystream reverted: ${revertReason(r.ret, ERRORS)}`);
  return unpack(r.ret, len);
}

async function ctr(key, nonce, data) {
  const r = await chain.call(probe,
    encodeWithTrailingBytes('ctr(bytes32,bytes16,bytes)', [b32(key), bN(nonce)], data));
  assert(r.ok, `ctr reverted: ${revertReason(r.ret, ERRORS)}`);
  return unpack(r.ret, strip(data).length / 2);
}

// ------------------------------------------------------------ JS oracles

/// The AES S-box from its definition (FIPS 197 5.1.1): the multiplicative
/// inverse in GF(2^8) modulo x^8+x^4+x^3+x+1, then the affine transform.
/// Deliberately not a copy of the table -- copies cannot catch a bad copy.
function sboxFromDefinition() {
  const mul = (a, b) => {
    let r = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) r ^= a;
      const hi = a & 0x80;
      a = (a << 1) & 0xff;
      if (hi) a ^= 0x1b;
      b >>= 1;
    }
    return r;
  };
  const inv = new Array(256).fill(0); // inverse of 0 is defined as 0
  for (let a = 1; a < 256; a++) {
    for (let b = 1; b < 256; b++) if (mul(a, b) === 1) { inv[a] = b; break; }
  }
  const out = [];
  for (let x = 0; x < 256; x++) {
    const b = inv[x];
    let s = 0;
    for (let i = 0; i < 8; i++) {
      const bit = ((b >> i) & 1) ^ ((b >> ((i + 4) % 8)) & 1) ^
        ((b >> ((i + 5) % 8)) & 1) ^ ((b >> ((i + 6) % 8)) & 1) ^
        ((b >> ((i + 7) % 8)) & 1) ^ ((0x63 >> i) & 1);
      s |= bit << i;
    }
    out.push(s);
  }
  return Buffer.from(out).toString('hex');
}

const opensslEcb = (key, hex) => {
  const c = createCipheriv('aes-256-ecb', Buffer.from(strip(key), 'hex'), null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(Buffer.from(strip(hex), 'hex')), c.final()]).toString('hex');
};

/// Node's `aes-256-ctr` is Ctr128BE: the whole 16-byte block increments.
const opensslCtr128 = (key, nonce, hex) => {
  const c = createCipheriv('aes-256-ctr',
    Buffer.from(strip(key), 'hex'), Buffer.from(strip(nonce), 'hex'));
  return Buffer.concat([c.update(Buffer.from(strip(hex), 'hex')), c.final()]).toString('hex');
};

const xorHex = (a, b) => {
  const x = Buffer.from(strip(a), 'hex');
  const y = Buffer.from(strip(b), 'hex');
  assert(x.length === y.length, 'xor length mismatch');
  return Buffer.from(x.map((v, i) => v ^ y[i])).toString('hex');
};

// ------------------------------------------------------------------ vectors

// FIPS 197 Appendix C.3.
const C3 = {
  key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  pt: '00112233445566778899aabbccddeeff',
  ct: '8ea2b7ca516745bfeafc49904b496089',
};

// SP 800-38A Appendix F, the shared AES-256 key and four-block message.
const F_KEY = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';
const F_PT = [
  '6bc1bee22e409f96e93d7e117393172a',
  'ae2d8a571e03ac9c9eb76fac45af8e51',
  '30c81c46a35ce411e5fbc1191a0a52ef',
  'f69f2445df4f9b17ad2b417be66c3710',
];
// F.1.5 ECB-AES256.Encrypt.
const F15_CT = [
  'f3eed1bdb5d2a03c064b5a7e3db181f8',
  '591ccb10d410ed26dc5ba74a31362870',
  'b6ed21b99ca6f4f9f153e7b1beafed1d',
  '23304b7a39f9f3ff067d8d8f9e24ecc7',
];
// F.5.5 CTR-AES256.Encrypt.
const F55_IV = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
const F55_CT = [
  '601ec313775789a5b7a7f504bbf3d228',
  'f443e3ca4d62b59aca84e990cacaf5c5',
  '2b0930daa23de94ce87017ba2d84988d',
  'dfc9c58db67aada613c2dd08457941a6',
];

console.log('\nAes256');

// ------------------------------------------------- the transcriptions first

await test('the transcribed NIST vectors are what OpenSSL produces', async () => {
  // If this fails, the fault is in this file, not in the contract. Checking it
  // separately keeps a typo from being reported as a Solidity defect.
  assertEq(opensslEcb(C3.key, C3.pt), C3.ct, 'FIPS 197 C.3');
  assertEq(opensslEcb(F_KEY, F_PT.join('')), F15_CT.join(''), 'SP 800-38A F.1.5');
  assertEq(opensslCtr128(F_KEY, F55_IV, F_PT.join('')), F55_CT.join(''),
    'SP 800-38A F.5.5');
});

// ------------------------------------------------------------------ S-box

await test('the packed S-box constants equal the algebraic S-box', async () => {
  let table = '';
  for (let i = 0; i < 8; i++) {
    const r = await chain.call(probe, selector('sboxWord(uint256)') + word(i));
    assert(r.ok, `sboxWord(${i}) reverted: ${revertReason(r.ret, ERRORS)}`);
    table += strip(r.ret);
  }
  assertEq(table, sboxFromDefinition(), 'S-box');
});

await test('the probe refuses inputs its fixed-word return cannot carry', async () => {
  // These two guards belong to the test wrapper, not to Aes256. They are
  // asserted rather than assumed so neither one is dead code: a silently
  // truncated keystream would make several tests below pass on a prefix.
  const tooLong = await chain.call(probe,
    selector('keystream(bytes32,bytes16,uint256)') + b32(C3.key) + bN(F55_IV) + word(129));
  assert(!tooLong.ok, 'a 129-byte request must revert');
  assertEq(revertReason(tooLong.ret, ERRORS), 'ProbeOutputTooLong', '129 bytes');

  const badIndex = await chain.call(probe, selector('sboxWord(uint256)') + word(8));
  assert(!badIndex.ok, 'sboxWord(8) must revert');
  assertEq(revertReason(badIndex.ret, ERRORS), 'ProbeBadIndex', 'word 8');
});

// ------------------------------------------------------------ block cipher

await test('FIPS 197 C.3: the AES-256 example block', async () => {
  assertEq(await encryptBlock(C3.key, C3.pt), C3.ct, 'C.3');
});

for (let i = 0; i < 4; i++) {
  await test(`SP 800-38A F.1.5: ECB-AES256 block ${i + 1}`, async () => {
    assertEq(await encryptBlock(F_KEY, F_PT[i]), F15_CT[i], `block ${i + 1}`);
  });
}

await test('the all-zero block under the all-zero key matches OpenSSL', async () => {
  // A degenerate input the published vectors do not cover, so a table or a
  // schedule that happens to be right only for high-entropy inputs is caught.
  const k = '00'.repeat(32);
  const p = '00'.repeat(16);
  assertEq(await encryptBlock(k, p), opensslEcb(k, p), 'zero block');
});

await test('the all-ones block under the all-ones key matches OpenSSL', async () => {
  const k = 'ff'.repeat(32);
  const p = 'ff'.repeat(16);
  assertEq(await encryptBlock(k, p), opensslEcb(k, p), 'ones block');
});

await test('one flipped key bit changes the ciphertext', async () => {
  // Guards against a schedule that ignores part of the key -- the halves of a
  // 256-bit key enter at different rounds, and dropping w[8..] entirely would
  // still pass a single fixed vector if that vector were the only test.
  const a = await encryptBlock(C3.key, C3.pt);
  const flipped = C3.key.slice(0, 62) + '1e';
  const b = await encryptBlock(flipped, C3.pt);
  assert(a !== b, 'ciphertext must depend on the last key byte');
  assertEq(b, opensslEcb(flipped, C3.pt), 'flipped key');
});

await test('one flipped plaintext bit changes the ciphertext', async () => {
  const a = await encryptBlock(C3.key, C3.pt);
  const b = await encryptBlock(C3.key, '00112233445566778899aabbccddeefe');
  assert(a !== b, 'ciphertext must depend on the input');
});

// -------------------------------------------------------------------- CTR

await test('SP 800-38A F.5.5: CTR-AES256 over all four blocks', async () => {
  assertEq(await ctr(F_KEY, F55_IV, F_PT.join('')), F55_CT.join(''), 'F.5.5');
});

await test('SP 800-38A F.5.5 keystream equals ciphertext XOR plaintext', async () => {
  // Same vector reached through `keystream` rather than `ctr`, so the XOR
  // wiring and the keystream generation are pinned separately.
  const ks = await keystream(F_KEY, F55_IV, 64);
  assertEq(ks, xorHex(F55_CT.join(''), F_PT.join('')), 'keystream');
});

await test('CTR decryption is CTR encryption', async () => {
  assertEq(await ctr(F_KEY, F55_IV, F55_CT.join('')), F_PT.join(''), 'round trip');
});

await test('keystream lengths 0, 1, 15, 16, 17 and 66 are prefixes of one another',
  async () => {
    // The 66-byte memo is not a whole number of blocks; a partial final block
    // is where a length-handling bug would live.
    const full = await keystream(F_KEY, F55_IV, 66);
    assertEq(full.length, 132, 'byte length');
    for (const n of [0, 1, 15, 16, 17, 33, 65, 66]) {
      assertEq(await keystream(F_KEY, F55_IV, n), full.slice(0, n * 2), `len ${n}`);
    }
  });

await test('a 66-byte keystream matches OpenSSL, which agrees here', async () => {
  // F55_IV's low 64 bits are far from the wrap, so Ctr64BE and Ctr128BE must
  // agree on these five blocks. If they did not, the fixture's wrapping cases
  // below would be the only thing separating them.
  const ks = await keystream(F_KEY, F55_IV, 66);
  assertEq(ks, opensslCtr128(F_KEY, F55_IV, '00'.repeat(66)), '66-byte keystream');
});

await test('one flipped nonce bit changes the keystream', async () => {
  const a = await keystream(F_KEY, F55_IV, 66);
  const b = await keystream(F_KEY, 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfefe', 66);
  assert(a !== b, 'keystream must depend on the nonce');
});

// ------------------------------------------- counter width, from the fixture

const MC = F.memoCipher;

await test('memoCipher: the fixture is Ctr64BE as it says it is', async () => {
  // Read the fixture's own claim rather than assuming it: each case publishes
  // the counter blocks it used, and the keystream must be their ECB images.
  assertEq(MC.mode, 'Ctr64BE<Aes256>', 'declared mode');
  for (const c of MC.cases) {
    const blocks = c.counterBlocks.map(strip).join('');
    assertEq(opensslEcb(MC.key, blocks).slice(0, strip(c.keystream).length),
      strip(c.keystream), `${c.nonce} counter blocks -> keystream`);
  }
});

for (const [i, c] of MC.cases.entries()) {
  await test(`memoCipher case ${i + 1} (${c.wrapsCounter ? 'wraps' : 'no wrap'})`,
    async () => {
      const want = strip(c.keystream);
      assertEq(await keystream(MC.key, c.nonce, want.length / 2), want, c.nonce);
    });
}

await test('the wrapping cases refute Ctr128BE and the third does not', async () => {
  // The whole point of the fixture's hand-placed nonces. Without this test a
  // Ctr128BE implementation passes every other line in this file: the two
  // modes differ only when the low 64 bits come within (blocks - 1) of
  // 2^64 - 1, which no HKDF-derived nonce will ever do by chance.
  let separated = 0;
  for (const c of MC.cases) {
    const len = strip(c.keystream).length / 2;
    const mine = await keystream(MC.key, c.nonce, len);
    const other = opensslCtr128(MC.key, c.nonce, '00'.repeat(len));
    if (c.wrapsCounter) {
      assert(mine !== other,
        `case ${c.nonce} is marked wrapping but Ctr128BE agrees -- ` +
        'this test could not fail and the fixture is wrong');
      separated++;
    } else {
      assertEq(mine, other, `non-wrapping case ${c.nonce} must agree`);
    }
  }
  assert(separated === 2, `expected 2 wrapping cases, got ${separated}`);
});

// ---------------------------------------------------------- real memo cases

for (const m of F.memos) {
  await test(`memo ${m.name}: keystream`, async () => {
    assertEq(await keystream(m.aesKey, m.aesNonce, 66), strip(m.keystream), m.name);
  });

  await test(`memo ${m.name}: decrypts to the plaintext`, async () => {
    const pt = await ctr(m.aesKey, m.aesNonce, m.ciphertext);
    assertEq(pt.length, 132, '66-byte memo');
    assertEq(pt, strip(m.plaintext), m.name);
  });

  await test(`memo ${m.name}: re-encrypts to the ciphertext`, async () => {
    assertEq(await ctr(m.aesKey, m.aesNonce, m.plaintext), strip(m.ciphertext), m.name);
  });
}

await test('a memo decrypted under the wrong key is not the plaintext', async () => {
  // `ctr` returning its input unchanged would satisfy nothing above except by
  // accident; this states outright that the keystream is not the identity.
  const m = F.memos[0];
  const bad = strip(m.aesKey).slice(0, 62) + (strip(m.aesKey).slice(62) === 'd8' ? 'd9' : 'd8');
  const pt = await ctr(bad, m.aesNonce, m.ciphertext);
  assert(pt !== strip(m.plaintext), 'wrong key must not open the memo');
  assert(pt !== strip(m.ciphertext), 'ctr must not be the identity');
});

// -------------------------------------------------------------------- gas

await test('gas for one 66-byte memo is reported', async () => {
  const m = F.memos[0];

  const ks = await chain.call(probe,
    selector('keystreamGas(bytes32,bytes16,uint256)') +
    b32(m.aesKey) + bN(m.aesNonce) + word(66));
  assert(ks.ok, `keystreamGas reverted: ${revertReason(ks.ret, ERRORS)}`);
  const ksUsed = BigInt('0x' + strip(ks.ret).slice(0, 64));

  const cg = await chain.call(probe,
    encodeWithTrailingBytes('ctrGas(bytes32,bytes16,bytes)',
      [b32(m.aesKey), bN(m.aesNonce)], m.ciphertext));
  assert(cg.ok, `ctrGas reverted: ${revertReason(cg.ret, ERRORS)}`);
  const ctrUsed = BigInt('0x' + strip(cg.ret).slice(0, 64));

  console.log(`        keystream, 66 bytes  = 5 blocks + key schedule: ${ksUsed} gas`);
  console.log(`        ctr, 66-byte memo    = the above plus the XOR:  ${ctrUsed} gas`);
  console.log(`        one AES-256 block, external call:               ${
    (await chain.call(probe,
      selector('encryptBlock(bytes32,bytes16)') + b32(m.aesKey) + bN(m.aesNonce))).gas
  } gas`);

  assert(ksUsed > 0n, 'gas measurement must be non-zero');
  assert(ctrUsed > ksUsed, 'ctr must cost more than the keystream it wraps');
});

summary();
