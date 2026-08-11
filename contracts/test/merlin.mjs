// Keccak-f[1600], STROBE-128 and Merlin, checked against things that were not
// written here.
//
// Three independent anchors, because a transcript implementation that is only
// compared to itself proves nothing:
//
//   1. The permutation, against the Keccak team's published intermediate
//      values (all 25 lanes) and against FIPS 202 SHA3-256, plus a
//      length-sweep differential against ethereum-cryptography's keccak256.
//   2. The transcript, against fixtures produced by the merlin 3.0.0 and
//      mc-crypto-digestible 7.1.0 crates themselves -- see
//      tools/merlin-fixtures.
//   3. The digestible framing, against digests hardcoded in MobileCoin's own
//      crypto/digestible/tests/basic.rs. Those values were published by
//      MobileCoin before this repo existed; nothing here can move them.
//
// Read tools/merlin-fixtures/README.md for the one link in the chain that is
// NOT anchored this way.

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { keccak256 } from 'ethereum-cryptography/keccak.js';
import {
  Chain, selector, word, b32, dynBytes, test, assert, assertEq, summary,
} from './harness.mjs';


const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = JSON.parse(
  readFileSync(join(HERE, 'fixtures', 'merlin.json'), 'utf8')
);

// The permutation is expensive in the EVM; a 33KB transcript runs a couple of
// hundred of them. Nothing here is gas-metered as a claim, so the limit is
// just set out of the way.
const GAS = 40_000_000_000n;

// ------------------------------------------------------------------ encoding

const hexToBytes = (h) => {
  const s = h.replace(/^0x/, '');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

const bytesToHex = (b) =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/// Two dynamic `bytes` arguments, both in the tail.
const encodeTwoBytes = (sig, aHex, bHex) => {
  const a = dynBytes(aHex);
  return (
    selector(sig) + word(64) + word(64 + a.length / 2) + a + dynBytes(bHex)
  );
};

const u = (n, bytes) => BigInt(n).toString(16).padStart(bytes * 2, '0');

/// Ops as emitted by the Rust generator -> the MerlinProbe script format
/// documented on MerlinProbe. Big-endian here, deliberately unlike the
/// transcript's own little-endian encodings, so a byte-order confusion between
/// the two shows up rather than cancelling.
function encodeScript(ops) {
  const parts = [];
  for (const o of ops) {
    const ctx = o.ctx;
    const cl = u(ctx.length / 2, 2);
    switch (o.op) {
      case 'append':
        parts.push('00' + cl + ctx + u(o.data.length / 2, 4) + o.data);
        break;
      case 'challenge':
        parts.push('01' + cl + ctx + u(o.len, 4));
        break;
      case 'u64':
        parts.push('02' + cl + ctx + u(o.value, 8));
        break;
      case 'prim':
        parts.push(
          '03' + cl + ctx + u(o.typename.length / 2, 2) + o.typename +
          u(o.data.length / 2, 4) + o.data
        );
        break;
      case 'none':
        parts.push('04' + cl + ctx);
        break;
      case 'seq':
        parts.push('05' + cl + ctx + u(o.len, 8));
        break;
      case 'agg':
        parts.push('06' + cl + ctx + u(o.name.length / 2, 2) + o.name);
        break;
      case 'aggend':
        parts.push('07' + cl + ctx + u(o.name.length / 2, 2) + o.name);
        break;
      case 'var':
        parts.push(
          '08' + cl + ctx + u(o.name.length / 2, 2) + o.name + u(o.which, 4)
        );
        break;
      default:
        throw new Error(`unknown op ${o.op}`);
    }
  }
  return parts.join('');
}

// ------------------------------------------------------- permutation harness

const encLanes = (lanes) => lanes.map((l) => word(l)).join('');

const decLanes = (ret) => {
  const h = ret.replace(/^0x/, '');
  return Array.from({ length: 25 }, (_, i) =>
    BigInt('0x' + h.slice(i * 64, i * 64 + 64))
  );
};

async function permute(chain, probe, lanes) {
  const r = await chain.must(
    probe,
    selector('f1600(uint256[25])') + encLanes(lanes),
    { gasLimit: GAS }
  );
  return decLanes(r.ret);
}

/// A Keccak sponge whose ONLY permutation is the one running in the EVM.
/// `padByte` is the domain separator: 0x06 for SHA-3 (FIPS 202), 0x01 for the
/// original Keccak that Ethereum uses.
async function sponge(chain, probe, rate, msgBytes, padByte, outLen) {
  const blocks = Math.floor(msgBytes.length / rate) + 1;
  const padded = new Uint8Array(blocks * rate);
  padded.set(msgBytes);
  padded[msgBytes.length] = padByte;
  padded[blocks * rate - 1] |= 0x80;

  let lanes = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    // Byte j of a block lands in lane floor(j/8) at bit 8*(j mod 8): the same
    // little-endian lane convention Keccak1600 documents.
    for (let j = 0; j < rate; j++) {
      lanes[j >> 3] ^= BigInt(padded[off + j]) << BigInt((j % 8) * 8);
    }
    lanes = await permute(chain, probe, lanes);
  }

  const out = [];
  let lanesOut = lanes;
  while (out.length < outLen) {
    for (let j = 0; j < rate && out.length < outLen; j++) {
      out.push(Number((lanesOut[j >> 3] >> BigInt((j % 8) * 8)) & 0xffn));
    }
    if (out.length < outLen) lanesOut = await permute(chain, probe, lanesOut);
  }
  return new Uint8Array(out);
}

// ---------------------------------------------------------------------- main

// Only this component's sources: a half-written contract elsewhere in src/ is
// someone else's problem, not a failure of the transcript.
const chain = await Chain.create({ only: ['Keccak1600.sol', 'Merlin.sol'] });
const kp = await chain.deploy('Keccak1600Probe');
const mp = await chain.deploy('MerlinProbe');

// Keccak-f[1600] applied to the all-zero state. All 25 lanes, from the Keccak
// team's KeccakF-1600-IntermediateValues.txt ("After permutation"). Lane 0 is
// the widely quoted f1258f7940e1dde7; the other 24 are the part an
// implementation missing rho, pi or the round constants still gets wrong.
const ZERO_STATE_PERMUTED = [
  0xf1258f7940e1dde7n, 0x84d5ccf933c0478an, 0xd598261ea65aa9een,
  0xbd1547306f80494dn, 0x8b284e056253d057n, 0xff97a42d7f8e6fd4n,
  0x90fee5a0a44647c4n, 0x8c5bda0cd6192e76n, 0xad30a6f71b19059cn,
  0x30935ab7d08ffc64n, 0xeb5aa93f2317d635n, 0xa9a6e6260d712103n,
  0x81a57c16dbcf555fn, 0x43b831cd0347c826n, 0x01f22f1a11a5569fn,
  0x05e5635a21d9ae61n, 0x64befef28cc970f2n, 0x613670957bc46611n,
  0xb87c5a554fd00ecbn, 0x8c3ee88a1ccf32c8n, 0x940c7922ae3a2614n,
  0x1841f924a2c509e4n, 0x16f53526e70465c2n, 0x75f644e97f30a13bn,
  0xeaf1ff7b5ceca249n,
];

await test('keccak-f[1600] of the all-zero state, ALL 25 lanes', async () => {
  const got = await permute(chain, kp, new Array(25).fill(0n));
  for (let i = 0; i < 25; i++) {
    assertEq(
      got[i].toString(16).padStart(16, '0'),
      ZERO_STATE_PERMUTED[i].toString(16).padStart(16, '0'),
      `lane ${i}`
    );
  }
});

await test('the 25-lane gate is not vacuous', async () => {
  // If the probe ignored its argument, or the comparison compared a value to
  // itself, the check above would pass for a permuted input too.
  const perturbed = new Array(25).fill(0n);
  perturbed[7] = 1n;
  const got = await permute(chain, kp, perturbed);
  let same = 0;
  for (let i = 0; i < 25; i++) {
    if (got[i] === ZERO_STATE_PERMUTED[i]) same++;
  }
  assert(same === 0, `one flipped input bit left ${same} lanes unchanged`);
});

await test('FIPS 202: SHA3-256 of the empty string', async () => {
  // a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a is the
  // value in the FIPS 202 / NIST CAVP SHA3-256 short-message set for len 0.
  const got = await sponge(chain, kp, 136, new Uint8Array(0), 0x06, 32);
  assertEq(
    bytesToHex(got),
    'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    'SHA3-256("")'
  );
});

await test('keccak256 length sweep vs ethereum-cryptography', async () => {
  // An independent implementation of the same sponge. The lengths bracket the
  // 136-byte rate so single-block, exact-block and multi-block padding all
  // run.
  for (const n of [0, 1, 135, 136, 137, 200, 272, 273]) {
    const msg = new Uint8Array(n);
    for (let i = 0; i < n; i++) msg[i] = (i * 37 + 11) & 0xff;
    const got = await sponge(chain, kp, 136, msg, 0x01, 32);
    assertEq(bytesToHex(got), bytesToHex(keccak256(msg)), `keccak256 len ${n}`);
  }
});

// ----------------------------------------------------- merlin differentials

/// The probe returns keccak256 of the concatenated challenge output (see
/// MerlinProbe for why it cannot return the bytes themselves), so the fixture's
/// expected hex is hashed the same way before comparing. `head` and `len` come
/// back too, purely so a failure says something.
const runScript = async (label, ops) => {
  const r = await chain.must(
    mp,
    encodeTwoBytes('run(bytes,bytes)', label, encodeScript(ops)),
    { gasLimit: GAS }
  );
  const h = r.ret.replace(/^0x/, '');
  return {
    hash: h.slice(0, 64),
    len: Number(BigInt('0x' + h.slice(64, 128))),
    head: h.slice(128, 192),
  };
};

const expectOutput = (got, expectedHex, what) => {
  assertEq(got.len, expectedHex.length / 2, `${what}: output length`);
  assertEq(
    got.head,
    (expectedHex.slice(0, 64) + '0'.repeat(64)).slice(0, 64),
    `${what}: first 32 output bytes`
  );
  assertEq(
    got.hash,
    bytesToHex(keccak256(hexToBytes(expectedHex))),
    `${what}: keccak256 of the whole output`
  );
};

assert(FIX.cases.length > 0, 'fixture file has no transcript cases');
assert(FIX.merlinVersion === '3.0.0', 'fixtures were built against a different merlin');

for (const c of FIX.cases) {
  await test(`merlin: ${c.name}`, async () => {
    expectOutput(await runScript(c.label, c.ops), c.expected, c.name);
  });
}

for (const c of FIX.digestibleKats) {
  await test(`digestible KAT (upstream): ${c.name}`, async () => {
    expectOutput(await runScript(c.label, c.ops), c.expected, c.name);
  });
}

for (const b of FIX.blockIds) {
  await test(`block id: ${b.name}`, async () => {
    const args =
      word(b.version) + b32(b.parentId) + word(b.index) +
      word(b.cumulativeTxoCount) + word(b.rangeFrom) + word(b.rangeTo) +
      b32(b.rootHash) + b32(b.contentsHash);
    const r = await chain.must(
      mp,
      selector(
        'blockId(uint32,bytes32,uint64,uint64,uint64,uint64,bytes32,bytes32)'
      ) + args,
      { gasLimit: GAS }
    );
    assertEq(r.ret.replace(/^0x/, ''), b.blockId, b.name);
  });
}

// -------------------------------------------------------- negative controls
//
// The fixtures above can only fail if the Solidity is wrong, but they cannot
// tell us that the Solidity is *reading its inputs*. These can.

await test('the domain separator reaches the state', async () => {
  const ops = [{ op: 'challenge', ctx: '63', len: 32 }];
  const a = await runScript('746573742070726f746f636f6c', ops);
  const b = await runScript('746573742070726f746f636f6d', ops); // last byte + 1
  assert(a.hash !== b.hash, 'two different dom-seps produced the same challenge');
});

await test('a one-bit change in an appended message changes the challenge', async () => {
  const c = FIX.cases.find((x) => x.name === 'equivalence-simple');
  const tampered = JSON.parse(JSON.stringify(c.ops));
  const d = tampered[0].data;
  tampered[0].data =
    d.slice(0, d.length - 2) +
    (parseInt(d.slice(-2), 16) ^ 1).toString(16).padStart(2, '0');
  const got = await runScript(c.label, tampered);
  assert(
    got.hash !== bytesToHex(keccak256(hexToBytes(c.expected))),
    'tampered message reproduced the fixture output'
  );
});

await test('the message LENGTH is framed, not just the bytes', async () => {
  // append("ab","") then append("","cd") vs append("ab","cd") -- if the length
  // were not part of the meta-AD these could collide.
  const ch = { op: 'challenge', ctx: '63', len: 32 };
  const a = await runScript('6c', [
    { op: 'append', ctx: '6162', data: '' },
    { op: 'append', ctx: '', data: '6364' },
    ch,
  ]);
  const b = await runScript('6c', [
    { op: 'append', ctx: '6162', data: '6364' },
    ch,
  ]);
  assert(a.hash !== b.hash, 'framing collision between distinct append sequences');
});

await test('every block-id field is bound', async () => {
  const base = FIX.blockIds.find((x) => x.name === 'mixed');
  const call = (o) =>
    selector(
      'blockId(uint32,bytes32,uint64,uint64,uint64,uint64,bytes32,bytes32)'
    ) +
    word(o.version) + b32(o.parentId) + word(o.index) +
    word(o.cumulativeTxoCount) + word(o.rangeFrom) + word(o.rangeTo) +
    b32(o.rootHash) + b32(o.contentsHash);

  const ref = (await chain.must(mp, call(base), { gasLimit: GAS })).ret;
  const mutations = [
    { version: Number(base.version) + 1 },
    { parentId: base.parentId.slice(0, 62) + '00' },
    { index: (BigInt(base.index) + 1n).toString() },
    { cumulativeTxoCount: (BigInt(base.cumulativeTxoCount) + 1n).toString() },
    { rangeFrom: (BigInt(base.rangeFrom) + 1n).toString() },
    { rangeTo: (BigInt(base.rangeTo) + 1n).toString() },
    { rootHash: base.rootHash.slice(0, 62) + '00' },
    { contentsHash: base.contentsHash.slice(0, 62) + '00' },
  ];
  for (const m of mutations) {
    const got = (await chain.must(mp, call({ ...base, ...m }), { gasLimit: GAS })).ret;
    assert(got !== ref, `block id ignored ${Object.keys(m)[0]}`);
  }
});

// ------------------------------------------------------------------ costing
//
// Not an assertion, but the number anyone deciding whether to verify a
// MobileCoin block header on Ethereum needs to see.

await test('report the cost of one block id', async () => {
  const b = FIX.blockIds[0];
  const r = await chain.must(
    mp,
    selector(
      'blockId(uint32,bytes32,uint64,uint64,uint64,uint64,bytes32,bytes32)'
    ) +
      word(b.version) + b32(b.parentId) + word(b.index) +
      word(b.cumulativeTxoCount) + word(b.rangeFrom) + word(b.rangeTo) +
      b32(b.rootHash) + b32(b.contentsHash),
    { gasLimit: GAS }
  );
  console.log(`        one MobileCoin block id: ${r.gas.toLocaleString()} gas`);
  const p = await chain.must(
    kp,
    selector('f1600(uint256[25])') + encLanes(new Array(25).fill(0n)),
    { gasLimit: GAS }
  );
  console.log(`        one keccak-f[1600]:      ${p.gas.toLocaleString()} gas`);
});

summary();
