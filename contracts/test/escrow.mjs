// Escrow tests: custody, accounting, the replay set, the freeze path, and the
// beneficiary rule.
//
// The MobileCoin cryptography is mocked out here on purpose. These tests are
// about the escrow's own logic -- the properties that came out of the TLA+
// models -- and mixing in signature verification would mean a failure here
// could be either. The real verifier is tested against MobileCoin fixtures
// separately.

import {
  Chain, selector, word, addrWord, b32, dynBytes, decodeUint, decodeAddress,
  test, assert, assertEq, summary, revertReason,
} from './harness.mjs';

const GOV      = '0x' + '11'.repeat(20);
const AUDITOR  = '0x' + '22'.repeat(20);
const ALICE    = '0x' + 'a1'.repeat(20);
const BOB      = '0x' + 'b0'.repeat(20);
const RELAYER  = '0x' + 'de'.repeat(20);

const EUSD_TOKEN_ID = 8192n;
const CAP = 1_000_000_000000n;          // 1M USDC, 6dp
const MOB_DEST = '0x' + '7d'.repeat(32);

// A VerifiedReturn is a static struct: 5 words, encoded inline.
const encReturn = ({ outKey, beneficiary, amount, tokenId = EUSD_TOKEN_ID, blockIndex = 100n }) =>
  b32(outKey) + addrWord(beneficiary) + word(amount) + word(tokenId) + word(blockIndex);

async function fixture(chain, { cap = CAP } = {}) {
  const usdc = await chain.deploy('MockERC20');
  const ver = await chain.deploy('MockVerifier');
  const escrow = await chain.deploy(
    'Escrow',
    addrWord(usdc) + addrWord(ver) + word(EUSD_TOKEN_ID) + word(cap) +
      addrWord(GOV) + addrWord(AUDITOR)
  );
  return { usdc, ver, escrow };
}

const mint = (chain, usdc, to, amt) =>
  chain.must(usdc, selector('mint(address,uint256)') + addrWord(to) + word(amt));
const approve = (chain, usdc, owner, spender, amt) =>
  chain.must(usdc, selector('approve(address,uint256)') + addrWord(spender) + word(amt), { from: owner });
const balanceOf = async (chain, usdc, who) =>
  decodeUint((await chain.must(usdc, selector('balanceOf(address)') + addrWord(who))).ret);
const deposit = (chain, escrow, from, amt, dest = MOB_DEST) =>
  chain.call(escrow, selector('deposit(uint256,bytes32)') + word(amt) + b32(dest), { from });
const release = (chain, escrow, from, retStruct) =>
  chain.call(escrow,
    selector('release(bytes)') + word(32) + dynBytes(retStruct),
    { from });

const chain = await Chain.create();

console.log('\nEscrow');

// ------------------------------------------------------------------ deposit

await test('deposit pulls USDC, records it, and emits the MobileCoin destination', async () => {
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, ALICE, 5_000000n);
  await approve(chain, usdc, ALICE, escrow, 5_000000n);

  const r = await deposit(chain, escrow, ALICE, 5_000000n);
  assert(r.ok, `deposit reverted: ${revertReason(r.ret)}`);
  assertEq(await balanceOf(chain, usdc, escrow), 5_000000n, 'escrow balance');
  assertEq(await balanceOf(chain, usdc, ALICE), 0n, 'alice balance');

  const out = decodeUint((await chain.must(escrow, selector('outstanding()'))).ret);
  assertEq(out, 5_000000n, 'outstanding');
  assert(r.logs.length === 1, 'one Deposited event');
  // topic[3] is the indexed mobDestination.
  assertEq(r.logs[0].topics[3], MOB_DEST, 'destination in event');
});

await test('deposit reverts above the cap, which is what bounds the theft surface', async () => {
  const { usdc, escrow } = await fixture(chain, { cap: 10_000000n });
  await mint(chain, usdc, ALICE, 100_000000n);
  await approve(chain, usdc, ALICE, escrow, 100_000000n);

  assert((await deposit(chain, escrow, ALICE, 10_000000n)).ok, 'at cap should pass');
  const over = await deposit(chain, escrow, ALICE, 1n);
  assert(!over.ok, 'over cap must revert');
});

await test('deposit rejects zero amount and zero destination', async () => {
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, ALICE, 5_000000n);
  await approve(chain, usdc, ALICE, escrow, 5_000000n);
  assert(!(await deposit(chain, escrow, ALICE, 0n)).ok, 'zero amount');
  assert(!(await deposit(chain, escrow, ALICE, 1n, '0x' + '00'.repeat(32))).ok, 'zero dest');
});

await test('deposit reverts when the token transfer fails, leaving no phantom credit', async () => {
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, ALICE, 5_000000n);
  // No approval.
  const r = await deposit(chain, escrow, ALICE, 5_000000n);
  assert(!r.ok, 'must revert without allowance');
  assertEq(decodeUint((await chain.must(escrow, selector('outstanding()'))).ret), 0n,
    'no outstanding recorded');
});

// ------------------------------------------------------------------ release

await test('release pays the beneficiary named in the proof, NOT the relayer', async () => {
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, escrow, 100_000000n);   // pre-funded float

  const outKey = '0x' + '01'.repeat(32);
  const r = await release(chain, escrow, RELAYER,
    encReturn({ outKey, beneficiary: BOB, amount: 7_000000n }));
  assert(r.ok, `release reverted: ${revertReason(r.ret)}`);

  assertEq(await balanceOf(chain, usdc, BOB), 7_000000n, 'bob paid');
  assertEq(await balanceOf(chain, usdc, RELAYER), 0n, 'relayer paid nothing');
});

await test('the same output cannot be redeemed twice', async () => {
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, escrow, 100_000000n);
  const outKey = '0x' + '02'.repeat(32);
  const enc = encReturn({ outKey, beneficiary: BOB, amount: 3_000000n });

  assert((await release(chain, escrow, RELAYER, enc)).ok, 'first redemption');
  const second = await release(chain, escrow, RELAYER, enc);
  assert(!second.ok, 'second redemption must revert');
  assertEq(await balanceOf(chain, usdc, BOB), 3_000000n, 'paid exactly once');
});

await test('replay is keyed on the output key alone, so a different block index does not re-open it', async () => {
  // The point of the ClaimAcceptance model: a nullifier scoped to anything
  // that can be rotated (epoch, key-set version, block) is re-usable by
  // rotating it. Same output, different surrounding data, must still fail.
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, escrow, 100_000000n);
  const outKey = '0x' + '03'.repeat(32);

  assert((await release(chain, escrow, RELAYER,
    encReturn({ outKey, beneficiary: BOB, amount: 1_000000n, blockIndex: 100n }))).ok);
  const again = await release(chain, escrow, RELAYER,
    encReturn({ outKey, beneficiary: ALICE, amount: 9_000000n, blockIndex: 999n }));
  assert(!again.ok, 'same output key must stay spent regardless of other fields');
});

await test('a non-eUSD token id is rejected', async () => {
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, escrow, 100_000000n);
  const r = await release(chain, escrow, RELAYER, encReturn({
    outKey: '0x' + '04'.repeat(32), beneficiary: BOB, amount: 1_000000n, tokenId: 1n,
  }));
  assert(!r.ok, 'wrong token id must revert');
});

await test('release reverts when the verifier rejects the proof', async () => {
  const { usdc, ver, escrow } = await fixture(chain);
  await mint(chain, usdc, escrow, 100_000000n);
  await chain.must(ver, selector('setShouldRevert(bool)') + word(1));
  const r = await release(chain, escrow, RELAYER,
    encReturn({ outKey: '0x' + '05'.repeat(32), beneficiary: BOB, amount: 1_000000n }));
  assert(!r.ok, 'must revert when verification fails');
});

await test('release reverts rather than paying out more than the escrow holds', async () => {
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, escrow, 1_000000n);
  const r = await release(chain, escrow, RELAYER,
    encReturn({ outKey: '0x' + '06'.repeat(32), beneficiary: BOB, amount: 5_000000n }));
  assert(!r.ok, 'insufficient escrow must revert');
});

await test('a zero beneficiary is rejected, so a malformed memo cannot burn funds', async () => {
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, escrow, 100_000000n);
  const r = await release(chain, escrow, RELAYER, encReturn({
    outKey: '0x' + '07'.repeat(32), beneficiary: '0x' + '00'.repeat(20), amount: 1_000000n,
  }));
  assert(!r.ok, 'zero beneficiary must revert');
});

// ------------------------------------------------------------------- freeze

await test('the auditor can freeze, and a freeze blocks releases', async () => {
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, escrow, 100_000000n);
  await chain.must(escrow,
    selector('freeze(string)') + word(32) + word(4) +
      Buffer.from('oops').toString('hex').padEnd(64, '0'),
    { from: AUDITOR });

  const r = await release(chain, escrow, RELAYER,
    encReturn({ outKey: '0x' + '08'.repeat(32), beneficiary: BOB, amount: 1_000000n }));
  assert(!r.ok, 'frozen must block release');
});

await test('a freeze does NOT block deposits', async () => {
  // Freezing deposits would strand users mid-flow without reducing exposure:
  // exposure comes from releases.
  const { usdc, escrow } = await fixture(chain);
  await mint(chain, usdc, ALICE, 5_000000n);
  await approve(chain, usdc, ALICE, escrow, 5_000000n);
  await chain.must(escrow,
    selector('freeze(string)') + word(32) + word(0) + '0'.repeat(64),
    { from: AUDITOR });
  assert((await deposit(chain, escrow, ALICE, 5_000000n)).ok, 'deposit should still work');
});

await test('a random address cannot freeze, and the auditor cannot unfreeze', async () => {
  const { escrow } = await fixture(chain);
  const bad = await chain.call(escrow,
    selector('freeze(string)') + word(32) + word(0) + '0'.repeat(64), { from: ALICE });
  assert(!bad.ok, 'non-auditor freeze must revert');

  await chain.must(escrow,
    selector('freeze(string)') + word(32) + word(0) + '0'.repeat(64), { from: AUDITOR });
  const un = await chain.call(escrow, selector('unfreeze()'), { from: AUDITOR });
  assert(!un.ok, 'auditor must not be able to unfreeze');
  assert((await chain.call(escrow, selector('unfreeze()'), { from: GOV })).ok,
    'governance can unfreeze');
});

// --------------------------------------------------------------- governance

await test('only governance can change the verifier, cap, auditor and governance', async () => {
  const { escrow } = await fixture(chain);
  const other = '0x' + '99'.repeat(20);
  for (const [sig, arg] of [
    ['setVerifier(address)', addrWord(other)],
    ['setDepositCap(uint256)', word(1n)],
    ['setAuditor(address)', addrWord(other)],
    ['transferGovernance(address)', addrWord(other)],
  ]) {
    assert(!(await chain.call(escrow, selector(sig) + arg, { from: ALICE })).ok,
      `${sig} must reject non-governance`);
    assert((await chain.call(escrow, selector(sig) + arg, { from: GOV })).ok,
      `${sig} must accept governance`);
  }
});

// ------------------------------------------------------------- reentrancy

await test('a token that re-enters release cannot double-spend the escrow', async () => {
  const rtoken = await chain.deploy('ReentrantToken');
  const ver = await chain.deploy('MockVerifier');
  const escrow = await chain.deploy('Escrow',
    addrWord(rtoken) + addrWord(ver) + word(EUSD_TOKEN_ID) + word(CAP) +
      addrWord(GOV) + addrWord(AUDITOR));
  await chain.must(rtoken, selector('mint(address,uint256)') + addrWord(escrow) + word(100_000000n));

  const enc = encReturn({ outKey: '0x' + '0a'.repeat(32), beneficiary: BOB, amount: 1_000000n });
  const payload = selector('release(bytes)') + word(32) + dynBytes(enc);
  await chain.must(rtoken,
    selector('arm(address,bytes)') + addrWord(escrow) + word(64) + dynBytes(payload));

  // The re-entrant inner call must fail; ReentrantToken reverts when it does,
  // so the whole outer release reverts. Either way the invariant that matters
  // is that BOB is not paid twice.
  await release(chain, escrow, RELAYER, enc);
  const bal = decodeUint((await chain.must(rtoken,
    selector('balanceOf(address)') + addrWord(BOB))).ret);
  assert(bal <= 1_000000n, `bob must not be paid twice, got ${bal}`);
});

summary();
