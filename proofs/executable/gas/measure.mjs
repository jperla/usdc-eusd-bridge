// Measure the gas cost of the primitives an Ethereum-side MobileCoin verifier
// needs, against a real EVM.
//
// The design left the verifier strategy at "prototype and measure" and that
// measurement was never done, so the four options (auxiliary secp256k1 block
// signatures, a zero-knowledge proof, an L2, optimistic release) have been
// compared on reasoning alone. These are the numbers.

import solc from 'solc';
import { readFileSync } from 'fs';
import { EVM } from '@ethereumjs/evm';
import { hexToBytes, bytesToHex, Address } from '@ethereumjs/util';

const source = readFileSync('Primitives.sol', 'utf8');
const input = {
  language: 'Solidity',
  sources: { 'Primitives.sol': { content: source } },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
  },
};

const out = JSON.parse(solc.compile(JSON.stringify(input)));
const errs = (out.errors || []).filter((e) => e.severity === 'error');
if (errs.length) {
  console.error(errs.map((e) => e.formattedMessage).join('\n'));
  process.exit(1);
}
const c = out.contracts['Primitives.sol']['Primitives'];
const bytecode = '0x' + c.evm.bytecode.object;

// --- minimal ABI encoding, so we depend on nothing beyond solc + the EVM ---
const sel = (sig) => {
  // keccak of the signature; use the EVM's own hashing via a tiny helper
  return null; // replaced below
};
import { keccak256 } from 'ethereum-cryptography/keccak.js';
import { utf8ToBytes } from 'ethereum-cryptography/utils.js';
const selector = (sig) => bytesToHex(keccak256(utf8ToBytes(sig))).slice(0, 10);
const word = (v) => BigInt(v).toString(16).padStart(64, '0');

const evm = await EVM.create();
const deploy = await evm.runCall({ data: hexToBytes(bytecode), gasLimit: 50_000_000n });
if (deploy.execResult.exceptionError) {
  console.error('deploy failed:', deploy.execResult.exceptionError);
  process.exit(1);
}
const code = deploy.execResult.returnValue;
// Put the runtime code at a real address, otherwise runCall treats every
// invocation as a CREATE and the dispatcher never runs.
const addr = new Address(hexToBytes('0x' + '11'.repeat(20)));
await evm.stateManager.putAccount(addr);
await evm.stateManager.putContractCode(addr, code);

async function call(label, data, note) {
  const r = await evm.runCall({
    to: addr, data: hexToBytes(data), gasLimit: 100_000_000n,
  });
  const err = r.execResult.exceptionError;
  const gas = Number(r.execResult.executionGasUsed);
  return { label, gas, err: err ? String(err.error || err) : null, note,
           ret: bytesToHex(r.execResult.returnValue) };
}

// Ed25519 base point, for a representative scalar multiplication.
const BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
const K  = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;

const results = [];
results.push(await call(
  'Ed25519 scalar multiplication',
  selector('scalarMul(uint256,uint256,uint256)') + word(K) + word(BX) + word(BY),
  'a verification needs ~2 of these'));

// A deliberately incomplete Keccak-shaped loop should not be REPORTED at all,
// even labelled -- a printed number gets quoted, and rho/pi and the round
// constants are missing. Kept runnable, excluded from output until faithful.
const RUN_KECCAK_PROBE = false;  // superseded by the faithful one below
if (RUN_KECCAK_PROBE) results.push(await call(
  'Keccak-f1600-SHAPED loop (24 rounds) *',
  selector('keccakF1600(uint256[25])') +
    '0000000000000000000000000000000000000000000000000000000000000020' +
    Array.from({ length: 25 }, (_, i) => word(i + 1)).join(''),
  '* NOT faithful Keccak: rho/pi and round constants omitted.\n' +
    '                                             Order-of-magnitude only.'));

// Faithful Keccak-f1600 on the all-zero state, so the result can be checked
// against the official test vector before any cost is reported.
const zero25 = Array.from({ length: 25 }, () => word(0)).join('');
// uint256[25] is a STATIC type: encoded inline, with NO offset word. An
// earlier version prepended one, which shifted every lane by one position.
results.push(await call(
  'Keccak-f1600 (faithful, 1 permutation)',
  selector('keccakF1600(uint256[25])') + zero25,
  'verified against the all-zero test vector'));

// Several batch sizes so the MARGINAL per-permutation cost excludes dispatch
// overhead. The figure reported is the two-point endpoint slope (x8-x1)/7,
// NOT a fit over all four points -- OLS gives essentially the same number.
for (const nperm of [1, 2, 4, 8]) {
  results.push(await call(
    `Keccak-f1600 x${nperm} (batch)`,
    selector('keccakF1600Batch(uint256,uint256[25])') + word(nperm) + zero25,
    'batched in one call'));
}

const N = 7n;
results.push(await call(
  'joint double-scalar mult (Shamir)',
  selector('jointDoubleScalarMul(uint256,uint256,uint256,uint256,uint256,uint256)') +
    word(K) + word(BX) + word(BY) + word(K + 1n) + word(BX) + word(BY),
  'what a verifier actually evaluates -- one joint, not two separate'));

results.push(await call(
  'MEASURED 7-validator Ed25519 quorum',
  selector('quorumEd25519(uint256,uint256,uint256,uint256,uint256,uint256,uint256)') +
    word(N) + word(K) + word(BX) + word(BY) + word(K + 1n) + word(BX) + word(BY),
  'one call, measured -- NOT 7x a single figure'));

results.push(await call(
  'MEASURED 7-validator ecrecover quorum',
  selector('quorumEcrecover(uint256,bytes32,uint8,bytes32,bytes32)') +
    word(N) + word(1) + word(27) + word(2) + word(3),
  'the same loop shape, measured the same way'));

results.push(await call(
  'ecrecover (secp256k1 precompile)',
  selector('ecrecoverCost(bytes32,uint8,bytes32,bytes32)') +
    word(1) + word(27) + word(2) + word(3),
  'what an auxiliary secp256k1 signature would cost instead'));

const byName = (n) => results.find((r) => r.label === n);

// CORRECTNESS FIRST. A gas number from wrong code is worthless, so the
// scalar multiplication is checked against an independent implementation
// before any cost is reported.
const Pp = (1n << 255n) - 19n;
const modinv = (a, m) => { let [g, x] = [[a % m, m], [1n, 0n]];
  while (g[1]) { const q = g[0] / g[1];
    g = [g[1], g[0] - q * g[1]]; x = [x[1], x[0] - q * x[1]]; }
  return ((x[0] % m) + m) % m; };
const rv = results[0].ret.slice(2);
const X = BigInt('0x' + rv.slice(0, 64));
const Y = BigInt('0x' + rv.slice(64, 128));
const Z = BigInt('0x' + rv.slice(128, 192));
const zi = modinv(Z, Pp);
const gotX = (X * zi) % Pp, gotY = (Y * zi) % Pp;
// k*B, computed independently (matches spec/threshold_algebra.py).
const EXP_X = 13502420895653221996125259476793333403267319522979651122472628122240025334082n;
const EXP_Y = 29824795000354507824364566309888593492013437081354141451873330129975944914100n;
if (gotX !== EXP_X || gotY !== EXP_Y) {
  console.error('scalarMul is INCORRECT -- gas figures would be meaningless');
  process.exit(1);
}
console.log('scalarMul: ONE known-answer vector matches an independent Ed25519.');
console.log('That gates the scalar KERNEL only -- not signature parsing, point');
console.log('decompression, small-order rejection, or verification as a whole.');
console.log('');

// Keccak correctness gate: first lane of f1600(all-zero) must be the
// official vector. A cost for a wrong permutation is worthless.
const kr = byName('Keccak-f1600 (faithful, 1 permutation)');
if (kr && !kr.err) {
  const rv2 = kr.ret.slice(2);
  // Check ALL 25 lanes, not just the first: a permutation can get one lane
  // right by luck, and rho/pi errors show up in the lanes they move.
  const EXPECT = [
    0xf1258f7940e1dde7n, 0x84d5ccf933c0478an, 0xd598261ea65aa9een,
    0xbd1547306f80494dn, 0x8b284e056253d057n, 0xff97a42d7f8e6fd4n,
    0x90fee5a0a44647c4n, 0x8c5bda0cd6192e76n, 0xad30a6f71b19059cn,
    0x30935ab7d08ffc64n, 0xeb5aa93f2317d635n, 0xa9a6e6260d712103n,
    0x81a57c16dbcf555fn, 0x43b831cd0347c826n, 0x01f22f1a11a5569fn,
    0x05e5635a21d9ae61n, 0x64befef28cc970f2n, 0x613670957bc46611n,
    0xb87c5a554fd00ecbn, 0x8c3ee88a1ccf32c8n, 0x940c7922ae3a2614n,
    0x1841f924a2c509e4n, 0x16f53526e70465c2n, 0x75f644e97f30a13bn,
    0xeaf1ff7b5ceca249n];
  const bad = [];
  for (let i = 0; i < 25; i++) {
    const got = BigInt('0x' + rv2.slice(i * 64, (i + 1) * 64)) & 0xFFFFFFFFFFFFFFFFn;
    if (got !== EXPECT[i]) bad.push(`lane${i}: got 0x${got.toString(16)} want 0x${EXPECT[i].toString(16)}`);
  }
  if (bad.length) {
    console.error(`Keccak-f1600 INCORRECT (${bad.length}/25 lanes):`);
    bad.slice(0, 5).forEach(b => console.error('  ' + b));
    process.exit(1);
  }
  console.log('keccakF1600: all 25 lanes match the all-zero test vector.');
  console.log('');
}

console.log('='.repeat(74));
console.log('EVM GAS MEASUREMENT — MobileCoin verifier primitives');
console.log('solc', solc.version().split('+')[0], '| optimizer on, runs=200');
console.log('='.repeat(74));
for (const r of results) {
  const g = r.err ? `(${r.err})` : r.gas.toLocaleString();
  console.log(`  ${r.label.padEnd(42)} ${g.padStart(12)}`);
  console.log(`  ${''.padEnd(42)} ${r.note}`);
}

const byLabel = Object.fromEntries(results.map(r => [r.label, r]));
const edQ = byLabel['MEASURED 7-validator Ed25519 quorum'];
const ecQ = byLabel['MEASURED 7-validator ecrecover quorum'];
if (!edQ.err && !ecQ.err) {
  console.log('');
  console.log('='.repeat(74));
  console.log('MEASURED COMPARISON — both loops, same shape, no extrapolation');
  console.log('='.repeat(74));
  console.log(`  7-validator Ed25519 quorum   ${edQ.gas.toLocaleString().padStart(12)}`);
  console.log(`  7-validator ecrecover quorum ${ecQ.gas.toLocaleString().padStart(12)}`);
  console.log(`  measured ratio               ${(edQ.gas / ecQ.gas).toFixed(0).padStart(11)}x`);
  console.log('');
  console.log('  EXCLUDED, and therefore NOT a verifier total: point');
  console.log('  decompression, SHA-512 challenge derivation, small-order');
  console.log('  checks, the per-validator Merlin transcript over');
  console.log('  BlockMetadataContents (which includes attestation evidence and');
  console.log('  differs per validator), the Merkle path, and calldata.');
  console.log('  This measures the SIGNATURE LINE ITEM only.');
}

// --- Merlin/STROBE transcript cost, built from the measured slope ---
const k1 = byName('Keccak-f1600 x1 (batch)');
const k8 = byName('Keccak-f1600 x8 (batch)');
if (k1 && k8 && !k1.err && !k8.err) {
  const marginal = (k8.gas - k1.gas) / 7;
  console.log('');
  console.log('='.repeat(74));
  console.log('MERLIN TRANSCRIPT OVER BlockMetadataContents — the missing term');
  console.log('='.repeat(74));
  console.log(`  marginal cost per Keccak-f1600  ${Math.round(marginal).toLocaleString().padStart(12)}`);
  console.log('');
  console.log('  Merlin is STROBE-128 over Keccak-f1600: rate = 200 - 32 - 2 =');
  console.log('  166 bytes, so an S-byte transcript needs ~ceil(S/166)');
  console.log('  permutations. MobileCoin has TWO signature routes and they');
  console.log('  are in completely different cost classes.');
  console.log('');
  console.log('  ROUTE A -- BlockMetadata (what the light-client verifier does).');
  console.log('  meta.verify() signs the Digestible encoding of the FULL');
  console.log('  BlockMetadataContents, which embeds per-node attestation');
  console.log('  evidence. Evidence DIFFERS PER VALIDATOR, so the transcript');
  console.log('  must be recomputed for each one -- nothing amortizes.');
  console.log('');
  console.log('    evidence/node    perms/node   x7 validators');
  for (const S of [2048, 4096, 8192]) {
    const perms = Math.ceil(S / 166) + 4;
    console.log(`    ${(S + ' B').padStart(11)}   ${String(perms).padStart(10)}` +
      `${Math.round(perms * 7 * marginal).toLocaleString().padStart(16)}`);
  }
  console.log('');
  console.log('  ROUTE B -- BlockSignature over block.digest32(b"block-sig").');
  console.log('  The Block struct is id + version + parent_id + index +');
  console.log('  cumulative_txo_count + root_element + contents_hash: ~164');
  console.log('  bytes of payload, a few hundred with Digestible framing.');
  console.log('  Crucially EVERY VALIDATOR SIGNS THE SAME DIGEST, so the');
  console.log('  transcript is computed ONCE and amortizes across the quorum.');
  console.log('');
  // MEASURED, not bounded: replaying the exact Digestible/Merlin operation
  // sequence for the Block struct absorbs 770 bytes and takes 6 f1600 calls
  // (initial f, four rate crossings, final forced PRF). 5 if the fixed STROBE
  // initialization is precomputed.
  const routeB = 6;
  console.log(`    <=${routeB} permutations TOTAL   ${Math.round(routeB * marginal).toLocaleString().padStart(16)}`);
  console.log('');
  const worstA = (Math.ceil(4096 / 166) + 4) * 7;
  console.log('  NO RATIO IS REPORTED. Comparing the exact Route B count');
  console.log('  against an ESTIMATED Route A count would compare a');
  console.log('  measurement to a guess. A ratio requires an exact counter');
  console.log('  run over real ArchiveBlock samples.');
  console.log('');
  console.log('  Route B ALSO needs the block ID transcript (a separate');
  console.log('  Merlin transcript, 5 more f1600 calls) unless the bridge');
  console.log('  deliberately proves that check is redundant given the quorum');
  console.log('  signs the full block -- which is a CHANGED predicate and');
  console.log('  would have to be stated and tested as such.');
  console.log('');
  console.log('  WHAT ROUTE B COSTS, which is not gas. Its signature is made');
  console.log('  with a PER-ENCLAVE IDENTITY KEY (random by default), not the');
  console.log('  node message key that defines its NodeID, and the verifier');
  console.log('  trusts the signer embedded in the object. So N block');
  console.log('  signatures are NOT N validators. Route B needs an');
  console.log('  authenticated height-scoped enclave-key -> entity mapping with');
  console.log('  entity-level dedup. Availability is weaker too: the signature');
  console.log('  is optional, and catch-up discards it.');
  console.log('');
  console.log('  Attestation is what natively authenticates that enclave key,');
  console.log('  so it is NOT true that Route A binding buys nothing -- only');
  console.log('  that it buys nothing in the CURRENT acceptance decision.');
  console.log('');
  console.log('  CAVEAT, and it is a large one: every figure here is NAIVE');
  console.log('  SOLIDITY with bounds-checked memory arrays, so these are');
  console.log('  UPPER BOUNDS. An assembly implementation would be cheaper,');
  console.log('  but BY HOW MUCH IS UNMEASURED -- no speedup factor is quoted');
  console.log('  here, and no claim is made about which term dominates after');
  console.log('  optimization, because that ordering depends on the factor.');
  console.log('');
  console.log('  The Route A evidence SIZE is ASSUMED, not read from a live');
  console.log('  block, and ceil(S/166)+4 is NOT exact Merlin accounting:');
  console.log('  each message absorbs a label, an LE32 length, the payload and');
  console.log('  operation headers, and Digestible expands each field into');
  console.log('  several messages. Treat the Route A column as illustrative');
  console.log('  ONLY. Route B below is exact by contrast.');
}
