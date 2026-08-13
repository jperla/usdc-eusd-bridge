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
const AMT = JSON.parse(readFileSync(
  join(HERE, 'fixtures', 'amount.json'), 'utf8'));

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
// whoever the OUTPUT names -- not a constant chosen here and, since the payout
// values became derived rather than claimed, not a field of the proof either.
// AMOUNT and BOB are what the contract must arrive at on its own.
const TOKEN_ID = BigInt(FIX.expected.tokenId);
const AMOUNT = BigInt(FIX.expected.amount);
const BOB = FIX.expected.beneficiary;
const CAP = 1_000_000_000000n;

// `B_token` for TOKEN_ID: MobileCoin derives the Pedersen value generator by
// hashing to the curve, which is not something to do on chain, so the point for
// the one token id this bridge accepts is pinned at deployment. This is
// MobileCoin's own `generators(token_id).B`, published by tools/amount-fixtures.
const VALUE_GENERATOR = AMT.generators.byTokenId
  .find((g) => g.tokenId === String(TOKEN_ID)).bToken;

const ENTITY = (i) => '0x' + (i + 1).toString(16).padStart(2, '0').repeat(32);

// -------------------------------------------------------------- proof encoding

const dynB32s = (a) => word(a.length) + a.map(b32).join('');
const dynSigs = (a) => word(a.length) + a.map((s) => b32(s[0]) + b32(s[1])).join('');
const dynBytesArg = (hex) => {
  const h = hex.replace(/^0x/, '');
  return word(h.length / 2) + h.padEnd(Math.ceil(h.length / 64) * 64, '0');
};

function encodeTxOut(t) {
  const tails = [
    dynBytesArg(t.maskedTokenId), dynBytesArg(t.eFogHint), dynBytesArg(t.eMemo),
  ];
  const head = [
    b32(t.commitment), word(t.maskedValue), null,
    b32(t.targetKey), b32(t.publicKey), null, null,
  ];
  let off = head.length * 32;
  for (const [slot, x] of [[2, tails[0]], [5, tails[1]], [6, tails[2]]]) {
    head[slot] = word(off);
    off += x.length / 2;
  }
  return head.join('') + tails.join('');
}

/// The proof the escrow's `release` takes. NOTE WHAT IS NOT IN IT: no amount,
/// no token id, no beneficiary. Those are opened out of the output's own
/// encrypted fields by the verifier; there is no field a relayer could use to
/// name a payout.
function encodeProof(p) {
  const txOutBlob = encodeTxOut(p.txOut);
  const head = [
    b32(p.blockId), word(p.version), b32(p.parentId), word(p.index),
    word(p.cumulativeTxoCount), word(p.rootRangeFrom), word(p.rootRangeTo),
    b32(p.rootHash), b32(p.contentsHash),
    null, null, null,
    b32(p.memoDomainTag),
    null, word(p.merkleIndex),
  ];
  const tails = [dynB32s(p.signerKeys), dynSigs(p.signatures), txOutBlob,
                 dynB32s(p.merklePath)];
  let off = head.length * 32;
  for (const [slot, t] of [[9, tails[0]], [10, tails[1]], [11, tails[2]], [13, tails[3]]]) {
    head[slot] = word(off);
    off += t.length / 2;
  }
  return word(32) + head.join('') + tails.join('');
}

/// The layout `Proof` had while the amount, token id and beneficiary were
/// plaintext claims. Kept so the release path can be handed one and watched to
/// pay nothing.
function encodeLegacyProof(p) {
  const txOutBlob = encodeTxOut(p.txOut);
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
  memoDomainTag: MEMO_DOMAIN,
  merklePath: FIX.membership_proof.elements.slice(1).map((e) => e.hash),
  merkleIndex: BigInt(FIX.membership_proof.index),
});

// --------------------------------------------------------------------- setup

const chain = await Chain.create({
  only: ['Escrow.sol', 'MobileCoinVerifier.sol', 'ValidatorRegistry.sol',
         'RecipientCheck.sol', 'TestMocks.sol'],
});

const balanceOf = async (usdc, who) => decodeUint((await chain.must(
  usdc, selector('balanceOf(address)') + addrWord(who))).ret);

const release = (escrow, p, enc = encodeProof) => chain.call(escrow,
  encodeWithTrailingBytes('release(bytes)', [], '0x' + enc(p)),
  { from: RELAYER });

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

  // The REAL recipient check, constructed with the return address's published
  // view private key. This is the link that decides whether an output was paid
  // to the bridge at all; with a permissive implementation here, anyone able to
  // produce a quorum-signed block containing any output could redeem it.
  const rc = await chain.deploy('RecipientCheck',
    b32(FIX.disclosure.view_private_key));
  const verifier = await chain.deploy('MobileCoinVerifier',
    addrWord(reg) + b32(FIX.disclosure.recovered_subaddress_spend_key) +
    word(TOKEN_ID) + b32(VALUE_GENERATOR) + b32(MEMO_DOMAIN) + addrWord(rc));

  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));

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

await test('LEG 3: a REAL MobileCoin return releases USDC to the payee IN THE OUTPUT',
  async () => {
  const before = await balanceOf(B.usdc, BOB);

  const r = await release(B.escrow, proof());
  assert(r.ok, `release reverted: ${revertReason(r.ret)}`);
  releaseGas = r.gas;

  // BOB and AMOUNT are nowhere in the bytes the relayer sent. They were
  // unmasked from the output's `masked_value` -- and checked against its
  // Pedersen commitment -- and decrypted out of its memo, with the bridge's
  // published view key.
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

await test('LEG 3: a relayer cannot name the amount or the payee', async () => {
  // The defect this run used to print under NOT ESTABLISHED. `Proof` carried
  // `amount`, `tokenId` and `beneficiary` in plaintext and the escrow paid
  // them out, so one genuine, quorum-signed, provably-included return could be
  // resubmitted naming any payee and any amount up to the escrow's balance.
  //
  // Submitting exactly that: the same real proof, in the layout that had those
  // fields, claiming 10x the value for an address of the attacker's choosing.
  // There is no longer a field to put them in.
  const MALLORY = '0x' + 'ba'.repeat(20);
  const usdc = await chain.deploy('MockERC20');
  const rc = await chain.deploy('RecipientCheck',
    b32(FIX.disclosure.view_private_key));
  const verifier = await chain.deploy('MobileCoinVerifier',
    addrWord(B.reg) + b32(FIX.disclosure.recovered_subaddress_spend_key) +
    word(TOKEN_ID) + b32(VALUE_GENERATOR) + b32(MEMO_DOMAIN) + addrWord(rc));
  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));
  await chain.must(usdc,
    selector('mint(address,uint256)') + addrWord(escrow) + word(AMOUNT * 100n));

  const attack = { ...proof(), amount: AMOUNT * 10n, tokenId: TOKEN_ID,
                   beneficiary: MALLORY };
  assert(!(await release(escrow, attack, encodeLegacyProof)).ok,
    'a proof naming its own payout still releases -- THE DEFECT IS OPEN');
  assertEq(await balanceOf(usdc, MALLORY), 0n, 'no USDC moved to the attacker');

  // The control, on the same escrow: the honest proof releases, and it
  // releases the output's own value to the output's own payee.
  const r = await release(escrow, proof());
  assert(r.ok, `the honest proof must release: ${revertReason(r.ret)}`);
  assertEq(await balanceOf(usdc, BOB), AMOUNT, 'the derived payee was paid');
  assertEq(await balanceOf(usdc, MALLORY), 0n, 'and the attacker still was not');
});

await test('LEG 3: the recipient check is load-bearing, not decorative',
  async () => {
  // Same proof, same quorum, same membership -- but a bridge deployed for a
  // DIFFERENT return address. The output is genuinely on MobileCoin and
  // genuinely signed; it simply was not paid to this bridge. If this releases,
  // anyone able to get any output into a signed block drains the escrow.
  const usdc = await chain.deploy('MockERC20');
  const rc = await chain.deploy('RecipientCheck',
    b32(FIX.disclosure.view_private_key));

  // A spend key that is not the one this output was paid to.
  const wrongD = '0x' + (BigInt(FIX.disclosure.recovered_subaddress_spend_key) ^ 1n)
    .toString(16).padStart(64, '0');
  const verifier = await chain.deploy('MobileCoinVerifier',
    addrWord(B.reg) + b32(wrongD) + word(TOKEN_ID) + b32(VALUE_GENERATOR) +
    b32(MEMO_DOMAIN) + addrWord(rc));
  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));
  await chain.must(usdc,
    selector('mint(address,uint256)') + addrWord(escrow) + word(AMOUNT * 4n));

  assert(!(await release(escrow, proof())).ok,
    'an output not paid to this bridge must not release funds');
  assertEq(await balanceOf(usdc, BOB), 0n, 'no USDC moved');
});

await test('LEG 3: the Pedersen commitment check is load-bearing in a FUNDED escrow',
  async () => {
  // Sol's finding: every other assertion in this file survived deleting the
  // commitment comparison, while the closing summary claimed that check was
  // established. The reason is that the amount is Merkle-bound, so a relayer
  // cannot reach the check by editing a proof -- the old-layout attack above
  // dies on ABI decoding, several steps earlier.
  //
  // The one lever that reaches it end to end is the deployment's Pedersen
  // value generator. Same proof, same quorum, same membership, same recipient
  // check, real money in the escrow -- one wrong curve point, and the
  // recomputed commitment cannot be the block's. If the comparison is skipped,
  // this releases and the assertions below fail.
  const usdc = await chain.deploy('MockERC20');
  const rc = await chain.deploy('RecipientCheck',
    b32(FIX.disclosure.view_private_key));

  const wrongGenerator = AMT.generators.byTokenId
    .find((g) => g.bToken !== VALUE_GENERATOR).bToken;
  assert(wrongGenerator && wrongGenerator !== VALUE_GENERATOR,
    'the oracle publishes only one generator -- this test proves nothing');

  const verifier = await chain.deploy('MobileCoinVerifier',
    addrWord(B.reg) + b32(FIX.disclosure.recovered_subaddress_spend_key) +
    word(TOKEN_ID) + b32(wrongGenerator) + b32(MEMO_DOMAIN) + addrWord(rc));
  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));
  await chain.must(usdc,
    selector('mint(address,uint256)') + addrWord(escrow) + word(AMOUNT * 4n));
  assertEq(await balanceOf(usdc, escrow), AMOUNT * 4n,
    'the escrow must actually hold funds, or nothing is at stake here');

  assert(!(await release(escrow, proof())).ok,
    'a commitment that does not open must not release funds');
  assertEq(await balanceOf(usdc, BOB), 0n, 'no USDC moved');
  assertEq(await balanceOf(usdc, escrow), AMOUNT * 4n, 'the escrow is intact');

  // And the SAME proof against a correctly configured escrow does release, so
  // the refusal above is the generator and not some unrelated breakage.
  const good = await chain.deploy('MobileCoinVerifier',
    addrWord(B.reg) + b32(FIX.disclosure.recovered_subaddress_spend_key) +
    word(TOKEN_ID) + b32(VALUE_GENERATOR) + b32(MEMO_DOMAIN) + addrWord(rc));
  const goodEscrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(good) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));
  await chain.must(usdc,
    selector('mint(address,uint256)') + addrWord(goodEscrow) + word(AMOUNT * 4n));
  const ok = await release(goodEscrow, proof());
  assert(ok.ok, `the control must release: ${revertReason(ok.ret)}`);
  assertEq(await balanceOf(usdc, BOB), AMOUNT, 'the control paid the payee');
});

const ok = summary();

const BLOCK_GAS_LIMIT = 30_000_000;
console.log('');
console.log(`  one full release (verify + payout): ${releaseGas.toLocaleString()} gas`);
if (releaseGas > BLOCK_GAS_LIMIT) {
  console.log('');
  console.log('  ' + '!'.repeat(66));
  console.log(`  THIS DOES NOT FIT IN AN ETHEREUM BLOCK. The limit is ` +
    `${BLOCK_GAS_LIMIT.toLocaleString()};`);
  console.log(`  this call needs ${(releaseGas / BLOCK_GAS_LIMIT * 100).toFixed(0)}% of it. ` +
    `A transaction cannot exceed the block`);
  console.log('  limit at any price, so the return leg as built is UNLANDABLE on');
  console.log('  Ethereum L1. It is verified, and it does not fit.');
  console.log('  ' + '!'.repeat(66));
}
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
console.log('         payee named IN THE OUTPUT, not the relayer.');
console.log('         Replayed: refused. Signature bit flipped: refused.');
console.log('         Output swapped: refused. Paid to another address:');
console.log('         refused, by the REAL recipient check (Ristretto255,');
console.log('         target_key == Hs(a*R)*G + D).');
console.log('         THE PAYOUT IS DERIVED, NOT CLAIMED. The amount and token');
console.log('         id are unmasked from the output\'s MaskedAmountV2 and');
console.log('         then checked by recomputing value*B_token +');
console.log('         blinding*B_blinding and requiring it to equal the block\'s');
console.log('         Pedersen commitment; the payee is AES-CTR-decrypted from');
console.log('         the output\'s memo and its type required to be 0x8001.');
console.log('         All three come from one shared secret, S = [a]R, which');
console.log('         the recipient check already had to compute. `Proof` has');
console.log('         no amount, tokenId or beneficiary field: a proof in the');
console.log('         old layout claiming 10x to an attacker releases nothing.');
console.log('');
console.log('='.repeat(72));
console.log('NOT ESTABLISHED — THE BRIDGE IS NOT READY TO HOLD FUNDS');
console.log('='.repeat(72));
console.log('  * No non-reconstructing two-cohort signing protocol: the');
console.log('    artifacts reconstruct the composite scalar in one process, so');
console.log('    the architecture gate is NOT closed and a composite address');
console.log('    must not be funded on this evidence.');
console.log('  * No live ceremony, no DKG, no deployment.');
console.log('  * The verifier cannot check that its pinned Pedersen generator');
console.log('    belongs to its token id -- that would be hash-to-curve on');
console.log('    chain. A mispaired deployment fails OPEN: it verifies');
console.log('    commitments in the wrong group and accepts amounts MobileCoin');
console.log('    refuses (exhibited in test/verifier.mjs). Whoever deploys must');
console.log('    diff eusdValueGenerator() against generators(eusdTokenId).');
console.log('='.repeat(72));

process.exitCode = ok ? 0 : 1;
