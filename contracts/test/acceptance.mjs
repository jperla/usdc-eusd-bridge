// THE ACCEPTANCE TEST — the objective from docs/FINAL-PLAN.md, end to end.
//
//   1. handle a USDC deposit into an Ethereum escrow account
//   2. upon verified USDC deposit, release eUSD from the eUSD escrow wallet
//   3. when eUSD is returned, release USDC from the Ethereum escrow account
//
// Legs 1 and 3 run here against a real EVM executing real compiled bytecode.
// Leg 2 happens on MobileCoin and is established in Rust against MobileCoin's
// own unmodified verifier; `scripts/acceptance.sh` runs that half first and
// this file asserts the handoff rather than restating it.
//
// Leg 3 uses the REAL MobileCoinVerifier over a proof produced by
// `crates/mc-return` from a real Block, a real BlockSignature, a real TxOut and
// a real membership proof. No mock verifier appears anywhere in the round trip.
//
// WHAT IS STILL NOT ESTABLISHED IS PRINTED AT THE END. Read it before quoting a
// pass here as evidence that the bridge is safe to fund.

import { readFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import {
  Chain, selector, word, addrWord, b32, encodeWithTrailingBytes,
  decodeUint, test, assert, assertEq, summary, revertReason,
} from './harness.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const FIX = JSON.parse(readFileSync(
  join(ROOT, 'crates', 'mc-return', 'fixtures', 'return.json'), 'utf8'));

const GOV = '0x' + '11'.repeat(20);
const AUDITOR = '0x' + '22'.repeat(20);
const ALICE = '0x' + 'a1'.repeat(20);
const RELAYER = '0x' + 'de'.repeat(20);
const MEMO_DOMAIN =
  '0x' + Buffer.from('mc-bridge-return-v1').toString('hex').padEnd(64, '0');

const ANCHOR = FIX.chain[FIX.chain.length - 1];
const SIGS = FIX.quorum.signatures;

// Token, amount and payee all come from the fixture: the escrow must be
// configured for the token that was actually returned, and the payee is
// whoever the proof names -- not a constant chosen here.
const TOKEN_ID = BigInt(FIX.expected.tokenId);
const AMOUNT = BigInt(FIX.expected.amount);
const BOB = FIX.expected.beneficiary;
const CAP = 1_000_000_000000n;

const ENTITY = (i) => '0x' + (i + 1).toString(16).padStart(2, '0').repeat(32);

// -------------------------------------------------------------- proof encoding

const dynB32s = (a) => word(a.length) + a.map(b32).join('');
const dynSigs = (a) => word(a.length) + a.map((s) => b32(s[0]) + b32(s[1])).join('');
const dynBytesArg = (hex) => {
  const h = hex.replace(/^0x/, '');
  return word(h.length / 2) + h.padEnd(Math.ceil(h.length / 64) * 64, '0');
};

function encodeProof(p) {
  const txOutTails = [
    dynBytesArg(p.txOut.maskedTokenId), dynBytesArg(p.txOut.eFogHint),
    dynBytesArg(p.txOut.eMemo),
  ];
  const txOutHead = [
    b32(p.txOut.commitment), word(p.txOut.maskedValue), null,
    b32(p.txOut.targetKey), b32(p.txOut.publicKey), null, null,
  ];
  let tOff = txOutHead.length * 32;
  for (const [slot, t] of [[2, txOutTails[0]], [5, txOutTails[1]], [6, txOutTails[2]]]) {
    txOutHead[slot] = word(tOff);
    tOff += t.length / 2;
  }
  const txOutBlob = txOutHead.join('') + txOutTails.join('');

  const head = [
    b32(p.blockId), word(p.version), b32(p.parentId), word(p.index),
    word(p.cumulativeTxoCount), word(p.rootRangeFrom), word(p.rootRangeTo),
    b32(p.rootHash), b32(p.contentsHash),
    null, null, null,
    word(p.amount), word(p.tokenId),
    b32(p.memoDomainTag), addrWord(p.beneficiary),
    null, word(p.merkleIndex),
  ];
  const tails = [dynB32s(p.signerKeys), dynSigs(p.signatures), txOutBlob,
                 dynB32s(p.merklePath)];
  let off = head.length * 32;
  for (const [slot, t] of [[9, tails[0]], [10, tails[1]], [11, tails[2]], [16, tails[3]]]) {
    head[slot] = word(off);
    off += t.length / 2;
  }
  return word(32) + head.join('') + tails.join('');
}

const proof = () => ({
  blockId: ANCHOR.id,
  version: BigInt(ANCHOR.version),
  parentId: ANCHOR.parent_id,
  index: BigInt(ANCHOR.index),
  cumulativeTxoCount: BigInt(ANCHOR.cumulative_txo_count),
  rootRangeFrom: BigInt(ANCHOR.root_element.range.from),
  rootRangeTo: BigInt(ANCHOR.root_element.range.to),
  rootHash: ANCHOR.root_element.hash,
  contentsHash: ANCHOR.contents_hash,
  signerKeys: SIGS.map((s) => s.signer),
  signatures: SIGS.map((s) => [
    '0x' + s.signature.slice(2, 66), '0x' + s.signature.slice(66, 130)]),
  txOut: {
    commitment: FIX.tx_out.masked_amount.commitment,
    maskedValue: BigInt(FIX.tx_out.masked_amount.masked_value),
    maskedTokenId: FIX.tx_out.masked_amount.masked_token_id,
    targetKey: FIX.tx_out.target_key,
    publicKey: FIX.tx_out.public_key,
    eFogHint: FIX.tx_out.e_fog_hint,
    eMemo: FIX.tx_out.e_memo,
  },
  amount: AMOUNT,
  tokenId: TOKEN_ID,
  memoDomainTag: MEMO_DOMAIN,
  beneficiary: BOB,
  merklePath: FIX.membership_proof.elements.slice(1).map((e) => e.hash),
  merkleIndex: BigInt(FIX.membership_proof.index),
});

// --------------------------------------------------------------------- setup

const chain = await Chain.create({
  only: ['Escrow.sol', 'MobileCoinVerifier.sol', 'ValidatorRegistry.sol',
         'TestMocks.sol'],
});

const balanceOf = async (usdc, who) => decodeUint((await chain.must(
  usdc, selector('balanceOf(address)') + addrWord(who))).ret);

const release = (escrow, p) => chain.call(escrow, encodeWithTrailingBytes(
  'release(bytes)', [], '0x' + encodeProof(p)), { from: RELAYER });

/// The bridge as it would be deployed: escrow, a registry with the block's real
/// signers enrolled as distinct entities, and the real verifier.
async function deployBridge() {
  const usdc = await chain.deploy('MockERC20');

  const reg = await chain.deploy('ValidatorRegistry',
    addrWord(GOV) + word(SIGS.length) + word(0));
  for (let i = 0; i < SIGS.length; i++) {
    const a = b32(SIGS[i].signer) + b32(ENTITY(i)) + word(0) + word(0);
    await chain.must(reg, selector('proposeKey(bytes32,bytes32,uint64,uint64)') + a,
      { from: GOV });
    await chain.must(reg, selector('enrollKey(bytes32,bytes32,uint64,uint64)') + a,
      { from: GOV });
  }

  const rc = await chain.deploy('AcceptsAnyRecipient_DO_NOT_DEPLOY');
  const verifier = await chain.deploy('MobileCoinVerifier',
    addrWord(reg) + b32(FIX.disclosure.recovered_subaddress_spend_key) +
    word(TOKEN_ID) + b32(MEMO_DOMAIN) + addrWord(rc));

  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR));

  return { usdc, reg, verifier, escrow };
}

const B = await deployBridge();

console.log('\nACCEPTANCE — docs/FINAL-PLAN.md, the three legs');

// ---------------------------------------------------------------------- LEG 1

await test('LEG 1: a USDC deposit is custodied and announced to the operators',
  async () => {
  await chain.must(B.usdc,
    selector('mint(address,uint256)') + addrWord(ALICE) + word(AMOUNT));
  await chain.must(B.usdc,
    selector('approve(address,uint256)') + addrWord(B.escrow) + word(AMOUNT),
    { from: ALICE });

  const mobDest = FIX.disclosure.recovered_subaddress_spend_key;
  const r = await chain.call(B.escrow,
    selector('deposit(uint256,bytes32)') + word(AMOUNT) + b32(mobDest),
    { from: ALICE });
  assert(r.ok, `deposit reverted: ${revertReason(r.ret)}`);

  assertEq(await balanceOf(B.usdc, B.escrow), AMOUNT, 'escrow holds the USDC');
  assertEq(await balanceOf(B.usdc, ALICE), 0n, 'alice paid');
  assertEq(decodeUint((await chain.must(B.escrow, selector('outstanding()'))).ret),
    AMOUNT, 'outstanding position opened');

  // Ethereum can announce the deposit; it cannot compel the eUSD release. That
  // asymmetry is why this leg is attested and capped rather than trustless.
  assertEq(r.logs[0].topics[3], mobDest, 'MobileCoin destination announced');
});

// ---------------------------------------------------------------------- LEG 2

await test('LEG 2: releasing eUSD needs BOTH cohorts (proven in Rust)', async () => {
  // scripts/acceptance.sh runs the two-cohort tests before this file. They
  // check the composite spend key against MobileCoin's UNMODIFIED RingMLSAG
  // verifier, including the negative case: a scalar missing the gate cohort's
  // share produces a signature the stock verifier returns InvalidSignature for.
  const spike = join(ROOT, 'proofs', 'executable', 'm2d-two-cohort', 'src', 'lib.rs');
  assert(existsSync(spike), 'two-cohort artifact missing');
  const src = readFileSync(spike, 'utf8');
  for (const t of [
    'an_owner_only_scalar_is_rejected_by_the_stock_verifier',
    'key_image_is_invariant_across_every_owner_gate_subset_pair',
    'stock_verifier_accepts_every_subset_pair',
  ]) assert(src.includes(t), `missing from the artifact: ${t}`);
});

// ---------------------------------------------------------------------- LEG 3

let releaseGas = 0;

await test('LEG 3: a REAL MobileCoin return releases USDC to the payee in the proof',
  async () => {
  const before = await balanceOf(B.usdc, BOB);

  const r = await release(B.escrow, proof());
  assert(r.ok, `release reverted: ${revertReason(r.ret)}`);
  releaseGas = r.gas;

  assertEq(await balanceOf(B.usdc, BOB) - before, AMOUNT, 'payee received the USDC');
  // The relayer carried bytes and got nothing. That is what makes the return
  // leg safe to leave permissionless.
  assertEq(await balanceOf(B.usdc, RELAYER), 0n, 'relayer paid nothing');
  assertEq(decodeUint((await chain.must(B.escrow, selector('outstanding()'))).ret),
    0n, 'round trip closed: nothing outstanding');
});

await test('LEG 3: the same return cannot be redeemed twice', async () => {
  await chain.must(B.usdc,
    selector('mint(address,uint256)') + addrWord(B.escrow) + word(AMOUNT * 4n));
  assert(!(await release(B.escrow, proof())).ok,
    'replay of a spent output must revert');
});

await test('LEG 3: a forged signature releases nothing', async () => {
  // Same escrow, same registry, one bit of one signature flipped. If this ever
  // passes, every other assertion in this file is worthless.
  const forged = proof();
  forged.signatures = forged.signatures.map((s, i) => i === 0
    ? ['0x' + (BigInt(s[0]) ^ 1n).toString(16).padStart(64, '0'), s[1]] : s);

  const before = await balanceOf(B.usdc, BOB);
  assert(!(await release(B.escrow, forged)).ok, 'forged signature must not release');
  assertEq(await balanceOf(B.usdc, BOB), before, 'no USDC moved');
});

await test('LEG 3: an output not in the signed block releases nothing', async () => {
  const foreign = proof();
  foreign.txOut = { ...foreign.txOut,
    publicKey: '0x' + (BigInt(foreign.txOut.publicKey) ^ 1n)
      .toString(16).padStart(64, '0') };

  const before = await balanceOf(B.usdc, BOB);
  assert(!(await release(B.escrow, foreign)).ok, 'foreign output must not release');
  assertEq(await balanceOf(B.usdc, BOB), before, 'no USDC moved');
});

const ok = summary();

console.log('');
console.log(`  one full release (verify + payout): ${releaseGas.toLocaleString()} gas`);
console.log('');
console.log('='.repeat(72));
console.log('ESTABLISHED BY THIS RUN');
console.log('='.repeat(72));
console.log('  Leg 1  USDC is really custodied; the destination is announced.');
console.log("  Leg 2  A scalar missing the gate share cannot satisfy stock MLSAG:");
console.log("         MobileCoin's UNMODIFIED verifier returns InvalidSignature.");
console.log('         Proven in Rust; run by scripts/acceptance.sh.');
console.log('  Leg 3  A proof built by MobileCoin\'s own crates -- real Block,');
console.log('         real BlockSignature, real TxOut, real membership proof --');
console.log('         is checked by the REAL on-chain verifier and pays the');
console.log('         payee named in the proof, not the relayer.');
console.log('         Replayed: refused. Signature bit flipped: refused.');
console.log('         Output swapped: refused.');
console.log('');
console.log('='.repeat(72));
console.log('NOT ESTABLISHED — THE BRIDGE IS NOT READY TO HOLD FUNDS');
console.log('='.repeat(72));
console.log('  * RECIPIENT CHECK. Whether the output is payable to the bridge');
console.log('    (target_key == Hs(a*R)*G + D) is delegated to IRecipientCheck,');
console.log('    and this run wires AcceptsAnyRecipient_DO_NOT_DEPLOY.');
console.log('    Ristretto255 is implemented and agrees with dalek; the check');
console.log('    itself is not wired yet.');
console.log('  * AMOUNT. Proof.amount is asserted by the relayer. The TxOut');
console.log('    digest binds the MASKED value, so the payout figure is not yet');
console.log('    derived from the output. Unmasking needs the same shared secret');
console.log('    the recipient check computes; both close together.');
console.log('  * No non-reconstructing two-cohort signing protocol: the');
console.log('    artifacts reconstruct the composite scalar in one process, so');
console.log('    the architecture gate is NOT closed and a composite address');
console.log('    must not be funded on this evidence.');
console.log('  * No live ceremony, no DKG, no deployment.');
console.log('='.repeat(72));

process.exitCode = ok ? 0 : 1;
