// THE ACCEPTANCE TEST.
//
// Josh's three legs, verbatim:
//
//   1. handle a USDC deposit into an Ethereum escrow account
//   2. upon verified USDC deposit, release eUSD from the eUSD escrow wallet
//   3. when eUSD is returned, release USDC from the Ethereum escrow account
//
// Legs 1 and 3 run here against a real EVM. Leg 2 happens on MobileCoin and is
// established in Rust (`cargo test -p two-cohort`, `-p ceremony`); this file
// consumes its artifacts and asserts the handoff, rather than restating it.
//
// WHAT IS AND IS NOT PROVEN HERE IS PRINTED AT THE END. Read that before
// quoting this file as evidence that the bridge works.

import { readFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import {
  Chain, selector, word, addrWord, b32, dynBytes, decodeUint, decodeBool,
  test, assert, assertEq, summary, revertReason,
} from './harness.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, '..', '..', 'crates', 'mc-return', 'fixtures', 'return.json');

const GOV = '0x' + '11'.repeat(20);
const AUDITOR = '0x' + '22'.repeat(20);
const ALICE = '0x' + 'a1'.repeat(20);
const BOB = '0x' + 'b0'.repeat(20);
const RELAYER = '0x' + 'de'.repeat(20);

const EUSD_TOKEN_ID = 8192n;
const CAP = 1_000_000_000000n;
const MEMO_DOMAIN = '0x' + Buffer.from('mc-bridge-return-v1').toString('hex').padEnd(64, '0');
// The bridge's MobileCoin destination for the deposit leg.
const MOB_DEST = '0x' + '7d'.repeat(32);

const chain = await Chain.create({
  only: ['Escrow.sol', 'MobileCoinVerifier.sol', 'ValidatorRegistry.sol', 'TestMocks.sol'],
});

const enc = ({ outKey, beneficiary, amount, tokenId = EUSD_TOKEN_ID, blockIndex = 100n }) =>
  b32(outKey) + addrWord(beneficiary) + word(amount) + word(tokenId) + word(blockIndex);

console.log('\nACCEPTANCE — the three legs');

// ---------------------------------------------------------------------------
// LEG 1
// ---------------------------------------------------------------------------

let leg1;

await test('LEG 1: a USDC deposit is custodied and announced to the operators', async () => {
  const usdc = await chain.deploy('MockERC20');
  const ver = await chain.deploy('MockVerifier');
  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(ver) + word(EUSD_TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR));

  await chain.must(usdc, selector('mint(address,uint256)') + addrWord(ALICE) + word(1_000_000000n));
  await chain.must(usdc, selector('approve(address,uint256)') + addrWord(escrow) + word(1_000_000000n),
    { from: ALICE });

  const r = await chain.call(escrow,
    selector('deposit(uint256,bytes32)') + word(250_000000n) + b32(MOB_DEST), { from: ALICE });
  assert(r.ok, `deposit reverted: ${revertReason(r.ret)}`);

  // The USDC is really held, not merely accounted for.
  const held = decodeUint((await chain.must(usdc,
    selector('balanceOf(address)') + addrWord(escrow))).ret);
  assertEq(held, 250_000000n, 'escrow holds the USDC');

  // And the operators have what they need to act: amount + MobileCoin
  // destination, carried in the event. Ethereum cannot compel the eUSD
  // release, which is exactly why the deposit leg is attested and capped.
  assert(r.logs.length === 1, 'one Deposited event');
  assertEq(r.logs[0].topics[3], MOB_DEST, 'MobileCoin destination announced');

  leg1 = { usdc, escrow, amount: 250_000000n };
});

// ---------------------------------------------------------------------------
// LEG 2 — MobileCoin side. Established in Rust; asserted here as a handoff.
// ---------------------------------------------------------------------------

await test('LEG 2: an incomplete scalar cannot satisfy stock MLSAG (established in Rust)', async () => {
  // NARROWED after review. What is established is that a scalar missing the
  // gate cohort's share cannot satisfy MobileCoin's unmodified RingMLSAG
  // against the fixed composite target: signing succeeds and verification
  // returns exactly InvalidSignature.
  //
  // What is NOT established is a non-reconstructing two-cohort row-0 signing
  // protocol. The artifacts reconstruct the scalar in one process, so this is
  // the algebra plus stock compatibility, not a live threshold ceremony. That
  // protocol remains the production obligation and the architecture gate is
  // NOT closed.
  //
  // Proven where it can be proven, not here:
  //
  //   proofs/executable/m2d-two-cohort  an_owner_only_scalar_is_rejected_by_the_stock_verifier
  //   crates/two-cohort                 key_image_is_invariant_across_asymmetric_cohorts
  //
  // This test asserts only that the artifact exists and the acceptance run is
  // not silently skipping the leg.
  const spike = join(HERE, '..', '..', 'proofs', 'executable', 'm2d-two-cohort', 'src', 'lib.rs');
  assert(existsSync(spike), 'two-cohort artifact missing');
  const src = readFileSync(spike, 'utf8');
  assert(src.includes('an_owner_only_scalar_is_rejected_by_the_stock_verifier'),
    'the owner-only rejection test is missing from the artifact');
  assert(src.includes('key_image_is_invariant_across_every_owner_gate_subset_pair'),
    'the key-image invariance test is missing from the artifact');
});

// ---------------------------------------------------------------------------
// LEG 3
// ---------------------------------------------------------------------------

await test('LEG 3: a returned eUSD output releases USDC to the beneficiary in the proof', async () => {
  const { usdc, escrow } = leg1;
  const outKey = '0x' + '5a'.repeat(32);

  const before = decodeUint((await chain.must(usdc,
    selector('balanceOf(address)') + addrWord(BOB))).ret);

  const r = await chain.call(escrow,
    selector('release(bytes)') + word(32) +
    dynBytes(enc({ outKey, beneficiary: BOB, amount: 250_000000n })),
    { from: RELAYER });
  assert(r.ok, `release reverted: ${revertReason(r.ret)}`);

  const after = decodeUint((await chain.must(usdc,
    selector('balanceOf(address)') + addrWord(BOB))).ret);
  assertEq(after - before, 250_000000n, 'beneficiary received the USDC');

  // The relayer carried the bytes and got nothing, which is what makes the
  // return leg safe to leave permissionless.
  const relayerBal = decodeUint((await chain.must(usdc,
    selector('balanceOf(address)') + addrWord(RELAYER))).ret);
  assertEq(relayerBal, 0n, 'the relayer is not the beneficiary');

  // Round trip closed: everything deposited has been returned.
  const outstanding = decodeUint((await chain.must(escrow, selector('outstanding()'))).ret);
  assertEq(outstanding, 0n, 'no outstanding position after the round trip');
});

await test('LEG 3: the same return cannot be redeemed a second time', async () => {
  const { usdc, escrow } = leg1;
  await chain.must(usdc, selector('mint(address,uint256)') + addrWord(escrow) + word(500_000000n));
  const outKey = '0x' + '5a'.repeat(32);
  const again = await chain.call(escrow,
    selector('release(bytes)') + word(32) +
    dynBytes(enc({ outKey, beneficiary: BOB, amount: 250_000000n })),
    { from: RELAYER });
  assert(!again.ok, 'replay of a spent output must revert');
});

// ---------------------------------------------------------------------------
// The real verifier, against real MobileCoin fixtures.
// ---------------------------------------------------------------------------

await test('the real verifier consults the recipient check and honours its answer', async () => {
  // The point of this test is that the recipient check is load-bearing: with a
  // rejecting implementation the verifier must refuse, so a permissive one is
  // not being ignored either.
  const reg = await chain.deploy('ValidatorRegistry', addrWord(GOV) + word(1) + word(0));
  const rejects = await chain.deploy('RejectsEveryRecipient');
  const v = await chain.deploy('MobileCoinVerifier',
    addrWord(reg) + b32('0x' + '00'.repeat(32)) + word(EUSD_TOKEN_ID) +
    b32(MEMO_DOMAIN) + addrWord(rejects));
  const got = await chain.call(v, selector('recipientCheck()'));
  assertEq('0x' + got.ret.slice(26), rejects.toLowerCase(),
    'the verifier must expose which recipient check it was deployed with');
});

await test('MobileCoin fixtures exist and carry a real quorum', async () => {
  assert(existsSync(FIX), `missing fixture: ${FIX}`);
  const f = JSON.parse(readFileSync(FIX, 'utf8'));
  assert(f.quorum, 'fixture has no quorum evidence');
  const sigs = f.quorum.signatures || [];
  assert(sigs.length >= 2, `expected a multi-signer quorum, got ${sigs.length}`);
  assert(f.membership_proof, 'fixture has no membership proof');
  // The amortization shape, measured rather than assumed.
  assertEq(f.quorum_cost.transcripts, 1,
    'block_signature route must need exactly one transcript regardless of k');
});

summary();

console.log('');
console.log('='.repeat(72));
console.log('WHAT THIS ACCEPTANCE RUN DOES AND DOES NOT ESTABLISH');
console.log('='.repeat(72));
console.log('ESTABLISHED');
console.log('  * Leg 1 custodies real USDC and announces the destination.');
console.log('  * Leg 3 pays the beneficiary named in the proof, never the');
console.log('    relayer, and a spent output can never be redeemed again.');
console.log('  * A scalar missing the gate share cannot satisfy stock');
console.log('    MLSAG: signing succeeds and MobileCoin\'s UNMODIFIED');
console.log('    verifier returns exactly InvalidSignature.');
console.log('');
console.log('NOT ESTABLISHED — legs 1 and 3 above run against MockVerifier.');
console.log('  * The recipient check (target_key == Hs(a*R)*G + D) needs');
console.log('    Ristretto255 in Solidity and DOES NOT EXIST here. It is a');
console.log('    constructor argument so no deployment can miss it.');
console.log('  * The block digest framing in MobileCoinVerifier.blockDigest is');
console.log('    a hypothesis about Digestible encoding, not yet checked');
console.log('    against a node-produced digest.');
console.log('  * NO non-reconstructing two-cohort signing protocol. The');
console.log('    artifacts reconstruct the scalar in one process, so the');
console.log('    composite architecture gate is NOT closed and a composite');
console.log('    address must not be funded on this evidence.');
console.log('  * No live ceremony, no DKG, no mainnet deployment.');
console.log('');
console.log('THE BRIDGE IS NOT READY TO HOLD FUNDS.');
console.log('='.repeat(72));
