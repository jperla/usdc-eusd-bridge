// Tests for Sha512.sol and Ed25519.sol, executed as real bytecode on a real
// EVM through ../test/harness.mjs.
//
// ORACLES, and why each is trustworthy:
//
//   * SHA-512 known-answer vectors come from FIPS 180-4 Appendix C (the "abc"
//     one-block and the 112-byte two-block examples) plus the empty-string
//     digest. These are fixed published constants, transcribed literally below.
//   * Ed25519 signature vectors come from RFC 8032 section 7.1, transcribed
//     literally below. TEST 1 / TEST 2 / TEST 3 / TEST 1024 / TEST SHA(abc).
//   * Where a sweep is wanted rather than a single vector (padding-boundary
//     lengths, curve arithmetic on many inputs) the oracle is an INDEPENDENT
//     implementation -- node's built-in OpenSSL SHA-512, and @noble/curves for
//     ed25519. Independent, but secondary: no claim in this file rests on one
//     of those alone without a published vector behind it.
//
// Nothing here compares the contract against itself.
//
// The suite was checked by mutation: fifteen single-line defects were injected
// into copies of Sha512.sol and Ed25519.sol -- verify() returning true
// unconditionally, the s >= L check removed, the sign bit dropped, one doubling
// per window instead of two, the two scalar windows swapped, d for 2d in the
// addition, the mod-L reduction of H(R,A,M) skipped, the scalar read
// big-endian, a corrupted round constant, a corrupted padding terminator, the
// message length omitted from the padding, a wrong rotation in Sigma1, and the
// three decompression rejections removed one at a time. All fifteen were
// killed. The mutants live in the scratch directory, not in this repo; the
// claim they support is only that no assertion below is vacuous.

import { createHash } from 'crypto';
import { ed25519 } from '@noble/curves/ed25519';
import {
  Chain,
  test,
  assert,
  assertEq,
  summary,
  selector,
  b32,
  encodeWithTrailingBytes,
  decodeBool,
  decodeUint,
} from './harness.mjs';

// --------------------------------------------------------------------- field

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const D =
  37095705934669439343138083508754565189542113879843219016388785533085940283555n;

const powmod = (b, e, m) => {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
};

const hx = (h) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ''), 'hex'));
const hex = (u8) => Buffer.from(u8).toString('hex');

/// 32-byte little-endian encoding of a field element, as Ed25519 uses.
const leBytes = (v) => {
  let s = '';
  for (let i = 0; i < 32; i++) {
    s += ((v >> BigInt(8 * i)) & 0xffn).toString(16).padStart(2, '0');
  }
  return s;
};
const leRead = (h) => {
  let v = 0n;
  const b = hx(h);
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
};

/// Compressed point encoding: y little-endian with the low bit of x in bit 255.
const compress = (x, y) => leBytes(y | ((x & 1n) << 255n));

const onCurve = (x, y) => {
  const x2 = (x * x) % P;
  const y2 = (y * y) % P;
  return (P - x2 + y2) % P === (1n + ((D * x2) % P) * y2) % P;
};

/// Flip bit `n` of a hex string (bit 0 = LSB of byte 0), matching how a wire
/// corruption would land.
const flipBit = (h, n) => {
  const b = hx(h);
  b[n >> 3] ^= 1 << (n & 7);
  return hex(b);
};

// ------------------------------------------------------------------- vectors

// FIPS 180-4 Appendix C.  Empty-string digest is the standard SHA-512 of "".
const FIPS_SHA512 = [
  [
    'empty string',
    '',
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
      + '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
  ],
  [
    'FIPS 180-4 C.1 "abc"',
    'abc',
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
      + '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
  ],
  [
    'FIPS 180-4 C.2 two-block (112 bytes)',
    'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno'
      + 'ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
    '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018'
      + '501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909',
  ],
];

// RFC 8032 section 7.1. Fields are [name, secret, public, message, signature].
// The secret key is carried only so the transcription of the other three can
// be re-derived and checked; the contract never sees it.
const RFC8032 = [
  [
    'TEST 1',
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    '',
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015'
      + '55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  ],
  [
    'TEST 2',
    '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    '72',
    '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
      + '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  ],
  [
    'TEST 3',
    'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    'af82',
    '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac'
      + '18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
  ],
  [
    'TEST SHA(abc)',
    '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
    'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
      + '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    'dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589'
      + '09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704',
  ],
  [
    'TEST 1024',
    'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5',
    '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',
    // 1023 bytes: with R and A prepended this is nine SHA-512 blocks, so it
    // is the only vector that exercises the multi-block path inside verify().
    '08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98'
      + 'fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8'
      + '79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d'
      + '658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc'
      + '1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe'
      + 'ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e'
      + '06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef'
      + 'efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7'
      + 'aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1'
      + '85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2'
      + 'd17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24'
      + '554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270'
      + '88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc'
      + '2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07'
      + '07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba'
      + 'b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a'
      + 'ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e'
      + 'c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7'
      + '51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c'
      + '42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8'
      + 'ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df'
      + 'f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08'
      + 'd78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649'
      + 'de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4'
      + '88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3'
      + '2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e'
      + '6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f'
      + 'b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5'
      + '0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1'
      + '369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d'
      + 'b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c'
      + '0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0',
    '0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350'
      + 'aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03',
  ],
];

// ------------------------------------------------------------------- helpers

const callSha512 = async (chain, at, msgHex) =>
  chain.must(at, encodeWithTrailingBytes('sha512(bytes)', [], msgHex));

const digestOf = (r) => r.ret.slice(2, 2 + 128);

const callVerify = (chain, at, sigHex, pkHex, msgHex) =>
  chain.call(
    at,
    encodeWithTrailingBytes(
      'verify(bytes32[2],bytes32,bytes)',
      [b32(sigHex.slice(0, 64)), b32(sigHex.slice(64)), b32(pkHex)],
      msgHex
    )
  );

const verified = async (chain, at, sigHex, pkHex, msgHex) => {
  const r = await callVerify(chain, at, sigHex, pkHex, msgHex);
  assert(r.ok, `verify reverted unexpectedly: ${r.error}`);
  return decodeBool(r.ret);
};

const callDecompress = async (chain, at, compHex) => {
  const r = await chain.must(at, selector('decompress(bytes32)') + b32(compHex));
  return {
    ok: decodeBool(r.ret, 0),
    x: decodeUint(r.ret, 1),
    y: decodeUint(r.ret, 2),
  };
};

// ---------------------------------------------------------------------- main

const main = async () => {
  // Transcription guard. Every RFC 8032 field below is re-derived from the
  // published secret key by an implementation this repo did not write. A typo
  // in a public key, message or signature fails HERE, loudly, rather than
  // quietly turning a signature test into a test of nothing.
  for (const [name, sk, pk, msg, sig] of RFC8032) {
    assertEq(
      hex(ed25519.getPublicKey(hx(sk))),
      pk,
      `${name}: transcribed public key`
    );
    assertEq(
      hex(ed25519.sign(hx(msg), hx(sk))),
      sig,
      `${name}: transcribed signature`
    );
  }

  console.log('\nSHA-512 (FIPS 180-4)');
  const chain = await Chain.create();
  const at = await chain.deploy('Ed25519Verifier');

  for (const [name, msg, want] of FIPS_SHA512) {
    await test(name, async () => {
      const r = await callSha512(chain, at, Buffer.from(msg, 'utf8').toString('hex'));
      assertEq(digestOf(r), want, name);
    });
  }

  await test('padding: every length across two block boundaries', async () => {
    // Lengths 0..8 and 100..136 cover both boundary regimes: a message that
    // leaves room for the 17 trailing bytes and one that does not, forcing an
    // extra block. 111 and 112 are the exact transition; 111 is also where the
    // 0x80 terminator shares a 32-byte word with the length field.
    const lens = [
      ...Array.from({ length: 9 }, (_, i) => i),
      ...Array.from({ length: 37 }, (_, i) => 100 + i),
    ];
    for (const n of lens) {
      const msg = Buffer.from(
        Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff)
      );
      const want = createHash('sha512').update(msg).digest('hex'); // OpenSSL
      const r = await callSha512(chain, at, msg.toString('hex'));
      assertEq(digestOf(r), want, `length ${n}`);
    }
  });

  await test('length field records bits, not bytes', async () => {
    // A message and its 8x-longer sibling must not collide, which they would
    // if the padded length were written in bytes. Not provable from the KATs
    // alone, since all three are different lengths anyway.
    const a = Buffer.alloc(8, 0x61);
    const b = Buffer.alloc(64, 0x61);
    const ra = await callSha512(chain, at, a.toString('hex'));
    const rb = await callSha512(chain, at, b.toString('hex'));
    assertEq(digestOf(ra), createHash('sha512').update(a).digest('hex'), '8');
    assertEq(digestOf(rb), createHash('sha512').update(b).digest('hex'), '64');
  });

  console.log('\nPoint decompression');

  await test('RFC 8032 public keys decompress to on-curve points', async () => {
    for (const [name, , pk] of RFC8032) {
      const d = await callDecompress(chain, at, pk);
      assert(d.ok, `${name}: rejected a valid public key`);
      assert(onCurve(d.x, d.y), `${name}: recovered point is not on the curve`);
      // The recovered point must re-encode to exactly the input bytes, which
      // is the property verify() relies on when it compares points instead of
      // comparing encodings.
      assertEq(compress(d.x, d.y), pk, `${name}: re-compression`);
    }
  });

  await test('sign bit selects the right root', async () => {
    // Both roots of the same y are valid points; only the sign bit tells them
    // apart. If the sign handling were dropped, one of these two would come
    // back with the wrong x.
    const pk = RFC8032[0][2];
    const y = leRead(pk) & ((1n << 255n) - 1n);
    const pos = await callDecompress(chain, at, compress(0n, y)); // sign 0
    const neg = await callDecompress(chain, at, compress(1n, y)); // sign 1
    assert(pos.ok && neg.ok, 'one of the two roots was rejected');
    assertEq(pos.x & 1n, 0n, 'sign 0 must give an even x');
    assertEq(neg.x & 1n, 1n, 'sign 1 must give an odd x');
    assertEq((pos.x + neg.x) % P, 0n, 'the two roots must be negatives');
  });

  await test('rejects non-canonical y (y >= p)', async () => {
    // Careful: p + 19 is 2^255, which lands in the sign bit rather than in y.
    // The non-canonical range is exactly [p, 2^255).
    for (const y of [P, P + 1n, P + 2n, (1n << 255n) - 1n]) {
      const d = await callDecompress(chain, at, leBytes(y));
      assert(!d.ok, `accepted non-canonical y = ${y}`);
    }
  });

  await test('rejects points not on the curve', async () => {
    // Search for y values where (y^2-1)/(d y^2+1) is a non-residue; those
    // encodings have no matching x and must be refused.
    let found = 0;
    for (let i = 2n; i < 200n && found < 4; i++) {
      const y2 = (i * i) % P;
      const u = (y2 + P - 1n) % P;
      const w = (((D * y2) % P) + 1n) % P;
      const q = (u * powmod(w, P - 2n, P)) % P;
      if (powmod(q, (P - 1n) / 2n, P) === 1n || q === 0n) continue; // a square
      found++;
      const d = await callDecompress(chain, at, leBytes(i));
      assert(!d.ok, `accepted off-curve y = ${i}`);
    }
    assert(found === 4, `expected 4 non-residue y values, found ${found}`);
  });

  await test('rejects the negative-zero encoding', async () => {
    // y = 1 has the single root x = 0. Encoding it with the sign bit set is a
    // second byte string for the identity, so it must be refused; the same y
    // with the sign bit clear must be accepted.
    const good = await callDecompress(chain, at, compress(0n, 1n));
    assert(good.ok && good.x === 0n && good.y === 1n, 'identity was rejected');
    const bad = await callDecompress(chain, at, leBytes(1n | (1n << 255n)));
    assert(!bad.ok, 'accepted the -0 encoding of the identity');

    // y = -1 is the other y with the single root x = 0 (the order-2 point).
    // It is a genuine curve point and must NOT be caught by the -0 rule.
    const two = await callDecompress(chain, at, compress(0n, P - 1n));
    assert(two.ok && two.x === 0n, 'rejected the order-2 point (0, -1)');
    assert(
      !(await callDecompress(chain, at, leBytes((P - 1n) | (1n << 255n)))).ok,
      'accepted the -0 encoding of the order-2 point'
    );
  });

  console.log('\nEd25519 verification (RFC 8032 s7.1)');

  for (const [name, , pk, msg, sig] of RFC8032) {
    await test(`${name} verifies`, async () => {
      assert(await verified(chain, at, sig, pk, msg), 'valid signature rejected');
    });
  }

  await test('any single flipped signature bit fails', async () => {
    // Swept over R (bits 0..255) and s (bits 256..509) at a stride, plus the
    // boundary bits of each half. A verifier that ignored part of the input --
    // or returned true unconditionally -- fails here.
    const [, , pk, msg, sig] = RFC8032[1];
    const bits = [0, 1, 7, 8, 63, 127, 200, 254, 255, 256, 257, 300, 400, 480];
    for (const n of bits) {
      const bad = flipBit(sig, n);
      assert(
        !(await verified(chain, at, bad, pk, msg)),
        `accepted a signature with bit ${n} flipped`
      );
    }
  });

  await test('any single flipped message bit fails', async () => {
    const [, , pk, msg, sig] = RFC8032[3]; // 64-byte message
    for (const n of [0, 1, 8, 100, 255, 511]) {
      assert(
        !(await verified(chain, at, sig, pk, flipBit(msg, n))),
        `accepted a signature over a message with bit ${n} flipped`
      );
    }
  });

  await test('a valid signature under the wrong public key fails', async () => {
    // Every cross pairing of the five vectors: 20 mismatches, 0 accepted.
    for (const [nameA, , , msg, sig] of RFC8032) {
      for (const [nameB, , pk] of RFC8032) {
        if (nameA === nameB) continue;
        assert(
          !(await verified(chain, at, sig, pk, msg)),
          `${nameA}'s signature verified under ${nameB}'s public key`
        );
      }
    }
  });

  await test('a valid signature over the wrong message fails', async () => {
    const [, , pk, , sig] = RFC8032[1];
    for (const other of ['', '73', '7272', 'af82']) {
      assert(
        !(await verified(chain, at, sig, pk, other)),
        `accepted TEST 2's signature over message ${other || '(empty)'}`
      );
    }
  });

  await test('rejects s >= L (malleability)', async () => {
    // s + L is the classic second encoding of the same signature: the group
    // equation still holds, so only an explicit range check rejects it.
    for (const [name, , pk, msg, sig] of RFC8032) {
      const s = leRead(sig.slice(64));
      assert(s < L, `${name}: vector's own s is already out of range`);
      const malleated = sig.slice(0, 64) + leBytes(s + L);
      assert(
        !(await verified(chain, at, malleated, pk, msg)),
        `${name}: accepted s + L`
      );
      // Independent confirmation that the malleated form is the same group
      // element and is rejected only because of the range check: @noble also
      // rejects it, and the low half (R) is untouched.
      assert(
        !ed25519.verify(hx(malleated), hx(msg), hx(pk)),
        `${name}: @noble accepted s + L`
      );
    }
  });

  await test('rejects a malformed R', async () => {
    // R with a non-canonical y must be refused before any arithmetic runs.
    const [, , pk, msg, sig] = RFC8032[1];
    const bad = leBytes(P) + sig.slice(64);
    assert(!(await verified(chain, at, bad, pk, msg)), 'accepted R with y = p');
  });

  await test('rejects a malformed public key', async () => {
    const [, , , msg, sig] = RFC8032[1];
    assert(
      !(await verified(chain, at, sig, leBytes(P + 1n), msg)),
      'accepted a public key with y = p + 1'
    );
  });

  await test('the identity public key admits forgery, as Ed25519 does', async () => {
    // With A = the neutral element, [h]A is the neutral element for every h,
    // so ANY (R = [r]B, s = r) verifies against any message. That is a property
    // of RFC 8032 cofactorless verification, not a defect here -- @noble agrees
    // below -- but it is the reason the validator registry must refuse the
    // identity as a public key. Recorded as a test so the behaviour is pinned
    // rather than discovered.
    //
    // It also exercises the completeness claim on the addition formula: half
    // the precomputed table is the neutral element, so every window that
    // selects an A-component adds it, and none of those additions may take a
    // special case that the code does not have.
    const identity = compress(0n, 1n);
    const r = 12345678901234567890n;
    const R = ed25519.Point.BASE.multiply(r);
    const sig = hex(R.toBytes()) + leBytes(r);
    for (const msg of ['', 'deadbeef']) {
      assert(
        ed25519.verify(hx(sig), hx(msg), hx(identity)),
        '@noble rejected the identity-key forgery; the premise has changed'
      );
      assert(
        await verified(chain, at, sig, identity, msg),
        'disagreed with @noble on the identity public key'
      );
    }
  });

  await test('agrees with @noble over random signatures', async () => {
    // A differential sweep, deliberately NOT self-referential: the messages,
    // keys and signatures are all produced by @noble, half of them are then
    // corrupted, and the contract's accept/reject must match @noble's on every
    // one. Anchored by the RFC vectors above -- this only widens the input
    // space, it does not establish correctness on its own.
    let flipped = 0;
    for (let i = 0; i < 8; i++) {
      const sk = Uint8Array.from({ length: 32 }, (_, j) => (i * 31 + j * 7) & 0xff);
      const pk = hex(ed25519.getPublicKey(sk));
      const msg = hex(Uint8Array.from({ length: i * 9 }, (_, j) => (i + j) & 0xff));
      let sig = hex(ed25519.sign(hx(msg), sk));
      if (i % 2 === 1) {
        sig = flipBit(sig, (i * 37) % 512);
        flipped++;
      }
      const want = ed25519.verify(hx(sig), hx(msg), hx(pk));
      assertEq(
        await verified(chain, at, sig, pk, msg),
        want,
        `case ${i} (expected ${want})`
      );
    }
    assert(flipped === 4, 'the sweep must include corrupted signatures');
  });

  // ------------------------------------------------------------------- gas
  const [, , gpk, gmsg, gsig] = RFC8032[1];
  const g = await callVerify(chain, at, gsig, gpk, gmsg);
  console.log('');
  console.log(
    `  gas: one verify() over a 1-byte message = ${g.gas} `
      + '(execution gas, excludes the 21000 intrinsic and calldata cost)'
  );
  const gEmpty = await callVerify(chain, at, RFC8032[0][4], RFC8032[0][2], '');
  console.log(`  gas: one verify() over an empty message = ${gEmpty.gas}`);
  const gLong = await callVerify(
    chain, at, RFC8032[4][4], RFC8032[4][2], RFC8032[4][3]
  );
  console.log(`  gas: one verify() over a 1023-byte message = ${gLong.gas}`);
  const gSha = await chain.call(
    at, encodeWithTrailingBytes('sha512(bytes)', [], '616263')
  );
  console.log(`  gas: one sha512("abc") = ${gSha.gas}`);

  summary();
};

main();
