// Component acceptance for the objective from docs/FINAL-PLAN.md.
//
//   1. handle a USDC deposit into an Ethereum escrow account
//   2. upon verified USDC deposit, release eUSD from the eUSD escrow wallet
//   3. when eUSD is returned, release USDC from the Ethereum escrow account
//
// Legs 1 and 3 run here against a real EVM executing real compiled bytecode.
// Leg 2's signing primitives are checked separately in Rust against MobileCoin's
// unmodified verifier. `scripts/acceptance.sh` runs those checks first. They do
// not consume this EVM deposit or submit a transaction to MobileCoin.
//
// Leg 3 uses the REAL MobileCoinVerifier over a proof produced by
// `crates/mc-return` from a real Block, a real BlockSignature, a real TxOut and
// a real membership proof. No mock verifier appears anywhere in the round trip.
//
// WHAT IS STILL NOT ESTABLISHED IS PRINTED AT THE END. Read it before quoting a
// pass here as evidence that the bridge is safe to fund.

import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import {
  Chain, selector, word, addrWord, b32, encodeWithTrailingBytes,
  decodeUint, test, assert, assertEq, summary, revertReason,
} from './harness.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
let FIX = JSON.parse(readFileSync(
  join(ROOT, 'crates', 'mc-return', 'fixtures', 'return.json'), 'utf8'));
const AMT = JSON.parse(readFileSync(
  join(HERE, 'fixtures', 'amount.json'), 'utf8'));

const GOV = '0x' + '11'.repeat(20);
const AUDITOR = '0x' + '22'.repeat(20);
const ALICE = '0x' + 'a1'.repeat(20);
const RELAYER = '0x' + 'de'.repeat(20);
const MEMO_DOMAIN =
  '0x' + Buffer.from('mc-bridge-return-v1').toString('hex').padEnd(64, '0');

let ANCHOR = FIX.chain[FIX.chain.length - 1];
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

// `B_token` for TOKEN_ID, as MobileCoin's own `generators(token_id).B`,
// published by tools/amount-fixtures.
//
// NOT a deployment parameter: the verifier's constructor derives it by hashing
// to the curve on chain, so this is the EXPECTED value, to be compared against
// what the deployed contract computed for itself.
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
    null, word(p.merkleIndex),
  ];
  const tails = [dynB32s(p.signerKeys), dynSigs(p.signatures), txOutBlob,
                 dynB32s(p.merklePath)];
  let off = head.length * 32;
  for (const [slot, t] of [[9, tails[0]], [10, tails[1]], [11, tails[2]], [12, tails[3]]]) {
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
  signatures: FIX.quorum.signatures.map((s) => [
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

// A conservative execution budget for the complete transaction, including
// intrinsic calldata cost. This is a regression budget, not a claim about
// the current Ethereum block gas limit.
const TRANSACTION_GAS_BUDGET = 30_000_000;
const releaseData = (p, enc = encodeProof) =>
  encodeWithTrailingBytes('release(bytes)', [], '0x' + enc(p));
const intrinsicGas = (data) => 21_000 + [...Buffer.from(data.slice(2), 'hex')]
  .reduce((sum, byte) => sum + (byte === 0 ? 4 : 16), 0);
const release = (escrow, p, enc = encodeProof) => {
  const data = releaseData(p, enc);
  return chain.call(escrow, data, {
    from: RELAYER,
    gasLimit: BigInt(TRANSACTION_GAS_BUDGET - intrinsicGas(data)),
  });
};
const requireError = (result, signature) => {
  assert(!result.ok, `expected ${signature}, call succeeded`);
  assertEq(result.ret.slice(0, 10), selector(signature),
    `wrong refusal: ${revertReason(result.ret)}`);
};

/// The bridge as it would be deployed: escrow, a registry with the block's real
/// signers enrolled as distinct entities, and the real verifier.
async function deployBridge(memoDomain = MEMO_DOMAIN) {
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
    word(TOKEN_ID) + b32(memoDomain) + addrWord(rc));

  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));

  await targetFixture(verifier, escrow);
  return { usdc, reg, verifier, escrow };
}

async function targetFixture(verifier, escrow) {
  const domain = (await chain.must(verifier, selector('redemptionDomain(address)') + addrWord(escrow))).ret;
  const binary = process.env.BRIDGE_RETURN_FIXTURE_BIN || join(HERE, '../../target/debug/examples/return-fixture');
  if (process.env.BRIDGE_RETURN_FIXTURE_BIN && !existsSync(binary)) throw Error('configured upstream generator is missing');
  const dir = join(HERE, 'fixtures/returns-v2');
  const cached = join(dir, domain.slice(2) + '.json');
  if (existsSync(binary)) {
    const raw = execFileSync(binary, [domain], {encoding: 'utf8', timeout: 30_000});
    FIX = JSON.parse(raw);
    mkdirSync(dir, {recursive:true});
    writeFileSync(cached, JSON.stringify(FIX, null, 2) + '\n');
  } else {
    // Solidity-only CI uses committed upstream-generated proofs. Full local
    // acceptance rebuilds the Rust generator first and regenerates each one.
    FIX = JSON.parse(readFileSync(cached, 'utf8'));
  }
  ANCHOR = FIX.chain[FIX.chain.length - 1];
  assertEq(FIX.disclosure.redemption_domain, domain, 'upstream return domain');
}

const B = await deployBridge();
let depositLog;

console.log('\nEVM ACCEPTANCE — custody and MobileCoin return verification');

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
  depositLog = r.logs[0];
});

if (process.env.BRIDGE_LOCAL_RELEASE_BIN) {
  await test('CONNECTED LOCAL FLOW: deposit log authorizes an authenticated, durable two-cohort intent', async () => {
    assert(depositLog, 'the EVM deposit must have executed');
    const dir = mkdtempSync(join(tmpdir(), 'bridge-local-roundtrip-'));
    const request = {chain_id: '0x'+word(1), escrow: B.escrow,
      topics: depositLog.topics, data: depositLog.data,
      return_output_digest: FIX.tx_out_digest.digest, token_id: TOKEN_ID.toString()};
    const invoke = input => spawnSync(process.env.BRIDGE_LOCAL_RELEASE_BIN, [dir],
      {input:JSON.stringify(input), encoding:'utf8', timeout:30_000});
    try {
      for (const bad of [{...request, data:'0x'+word(0)}, {...request, token_id:'8192'},
                         {...request, topics:[]}, {...request, unknown:true}]) {
        const r = invoke(bad);
        assert(!r.error && r.status !== 0, 'malformed authorization must fail');
      }
      const result = invoke(request);
      assert(!result.error && result.status===0, `local signer: ${result.error || result.stderr}`);
      const signed = JSON.parse(result.stdout);
      assertEq(signed.stock_mlsag_verified, true, 'MobileCoin stock MLSAG verifier');
      assertEq(signed.amount, AMOUNT.toString(), 'exact deposited amount');
      assertEq(signed.destination, depositLog.topics[3], 'exact deposited destination');
      assertEq(signed.return_output_digest, FIX.tx_out_digest.digest, 'bound return association');
      assertEq(signed.authenticated_packets, 10, 'both rounds, all spend seats plus mask');
      const replay = invoke(request);
      assert(!replay.error && replay.status!==0, 'process restart cannot reset nonce state');
    } finally { rmSync(dir, {recursive:true, force:true}); }
  });
}

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
  requireError(await release(B.escrow, proof()), 'AlreadyRedeemed(bytes32)');
});

await test('LEG 3: a forged signature releases nothing', async () => {
  // Same escrow, same registry, one bit of one signature flipped. If this ever
  // passes, every other assertion in this file is worthless.
  const fresh = await deployBridge();
  const forged = proof();
  forged.signatures = forged.signatures.map((s, i) => i === 0
    ? ['0x' + (BigInt(s[0]) ^ 1n).toString(16).padStart(64, '0'), s[1]] : s);

  await chain.must(fresh.usdc,
    selector('mint(address,uint256)') + addrWord(fresh.escrow) + word(AMOUNT));
  requireError(await release(fresh.escrow, forged), 'BadSignature(uint256)');
  assertEq(await balanceOf(fresh.usdc, BOB), 0n, 'no USDC moved');
  // The unmodified proof must still redeem this same funded escrow, proving
  // the negative case did not pass on replay/insolvency and did not consume it.
  assert((await release(fresh.escrow, proof())).ok, 'honest retry must release');
  assertEq(await balanceOf(fresh.usdc, BOB), AMOUNT, 'honest payee received funds');
});

await test('LEG 3: an output not in the signed block releases nothing', async () => {
  const fresh = await deployBridge();
  const foreign = proof();
  foreign.txOut = { ...foreign.txOut,
    publicKey: '0x' + (BigInt(foreign.txOut.publicKey) ^ 1n)
      .toString(16).padStart(64, '0') };

  await chain.must(fresh.usdc,
    selector('mint(address,uint256)') + addrWord(fresh.escrow) + word(AMOUNT));
  requireError(await release(fresh.escrow, foreign), 'MembershipFailed()');
  assertEq(await balanceOf(fresh.usdc, BOB), 0n, 'no USDC moved');
  assert((await release(fresh.escrow, proof())).ok, 'honest retry must release');
  assertEq(await balanceOf(fresh.usdc, BOB), AMOUNT, 'honest payee received funds');
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
    word(TOKEN_ID) + b32(MEMO_DOMAIN) + addrWord(rc));
  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));
  await targetFixture(verifier, escrow);
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
    addrWord(B.reg) + b32(wrongD) + word(TOKEN_ID) +
    b32(MEMO_DOMAIN) + addrWord(rc));
  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));
  await targetFixture(verifier, escrow);
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
  // THE LEVER THIS TEST USED TO PULL IS GONE, DELIBERATELY. It deployed a
  // verifier with a mismatched Pedersen value generator, which was possible
  // only because `B_token` was a constructor argument -- the same fail-open
  // that let a deployment verify commitments in the wrong group. The
  // constructor now derives `B_token` from the token id, so no deployment
  // reaches the commitment check any more.
  //
  // What is asserted instead, on a FUNDED escrow that has just paid out: the
  // deployed verifier's own `openAmount` -- the function `verifyReturn` calls,
  // in the bytecode behind the money -- refuses the block's masked amount
  // paired with any other commitment. Deleting the comparison in AmountOpener
  // turns this red, which is the property the test was written for.
  const usdc = await chain.deploy('MockERC20');
  const rc = await chain.deploy('RecipientCheck',
    b32(FIX.disclosure.view_private_key));
  const verifier = await chain.deploy('MobileCoinVerifier',
    addrWord(B.reg) + b32(FIX.disclosure.recovered_subaddress_spend_key) +
    word(TOKEN_ID) + b32(MEMO_DOMAIN) + addrWord(rc));
  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));
  await targetFixture(verifier, escrow);
  await chain.must(usdc,
    selector('mint(address,uint256)') + addrWord(escrow) + word(AMOUNT * 4n));
  assertEq(await balanceOf(usdc, escrow), AMOUNT * 4n,
    'the escrow must actually hold funds, or nothing is at stake here');

  // Real money moves through this exact verifier.
  const ok = await release(escrow, proof());
  assert(ok.ok, `the honest proof must release: ${revertReason(ok.ret)}`);
  assertEq(await balanceOf(usdc, BOB), AMOUNT, 'the payee was paid');

  // Same contract, same masked amount, same shared secret -- one bit flipped in
  // the commitment the block committed to. `openAmount` is public precisely so
  // this branch is reachable on the production code path rather than on a copy.
  const TXOUT = '(bytes32,uint64,bytes,bytes32,bytes32,bytes,bytes)';
  const openWith = (commitment) => chain.call(verifier,
    selector(`openAmount(bytes32,${TXOUT})`) +
    b32(FIX.disclosure.shared_secret) + word(64) +
    encodeTxOut({ ...proof().txOut, commitment }));

  const real = FIX.tx_out.masked_amount.commitment;
  const flipped = '0x' + (BigInt(real) ^ 1n).toString(16).padStart(64, '0');
  const bad = await openWith(flipped);
  assert(!bad.ok, 'a commitment that is not the output\'s still opened');
  assertEq(bad.ret.slice(0, 10),
    selector('InconsistentCommitment(bytes32,bytes32)'),
    `refused for the wrong reason: ${revertReason(bad.ret)}`);

  // The control: the block's real commitment opens, to the block's real value.
  // So the refusal above is the commitment and nothing else.
  const good = await openWith(real);
  assert(good.ok, `the real commitment must open: ${revertReason(good.ret)}`);
  assertEq(decodeUint(good.ret, 0), AMOUNT, 'the value it opens to');

  // And the reason no deployment can reach that branch: the generator is
  // derived from the token id, and it is MobileCoin's own.
  assertEq((await chain.must(verifier, selector('eusdValueGenerator()'))).ret,
    VALUE_GENERATOR,
    'the derived B_token is not MobileCoin\'s generators(eusdTokenId)');
  assertEq(await balanceOf(usdc, escrow), AMOUNT * 3n,
    'exactly one release came out of the escrow');
});

await test('LIVENESS, NOT SAFETY: an escrow whose token id does not match its '
  + 'verifier\'s releases nothing, ever', async () => {
  // READ THE NAME OF THIS TEST BEFORE QUOTING IT. What is asserted here is a
  // FAIL-CLOSED property: a bridge deployed with `Escrow.eusdTokenId` and
  // `MobileCoinVerifier`'s `_eusdTokenId` set to different values pays nobody.
  // Nobody is overpaid, no wrong payee is paid, no replay opens -- the return
  // leg simply does not work. It is a bricked deployment, not a theft.
  //
  // It is worth a test anyway, and worth being explicit about which kind of
  // property it is, because the two ids are SEPARATE constructor arguments and
  // NOTHING CHECKS THEM AGAINST EACH OTHER AT CONSTRUCTION. Both deployments
  // below succeed. The escrow never reads the verifier's id and the verifier
  // never learns the escrow's; the disagreement surfaces only when the first
  // real return arrives, which on a funded bridge is the worst moment to find
  // out. That is a deployment-checklist item, and this is the test that says
  // what it is protecting against.
  //
  // Note the shape it shares with the fail-open that was just closed: two
  // arguments that have to agree and no code that makes them. That one --
  // token id next to `_eusdValueGenerator` -- failed OPEN and paid out
  // 250,000,000,000. This one fails closed. The difference is luck about which
  // side of a comparison each argument lands on, not design.
  const usdc = await chain.deploy('MockERC20');
  const rc = await chain.deploy('RecipientCheck',
    b32(FIX.disclosure.view_private_key));

  // The verifier is correct: it is deployed for the token id the fixture's
  // output really carries, and it will verify the real proof.
  const verifier = await chain.deploy('MobileCoinVerifier',
    addrWord(B.reg) + b32(FIX.disclosure.recovered_subaddress_spend_key) +
    word(TOKEN_ID) + b32(MEMO_DOMAIN) + addrWord(rc));

  // The escrow is deployed for eUSD's 8192 -- a plausible mistake, since 8192
  // is what a production deployment script would say and TOKEN_ID is what this
  // scenario's ledger actually used.
  const ESCROW_TOKEN_ID = 8192n;
  assert(ESCROW_TOKEN_ID !== TOKEN_ID,
    'this test needs two DIFFERENT token ids to be about anything');
  const escrow = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(ESCROW_TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));

  // THE FINDING, asserted rather than described: both constructors accepted
  // the pairing. Neither reverted, neither emitted a warning, and the getters
  // now disagree in a way only a human comparing two transactions would see.
  assertEq(decodeUint((await chain.must(
    verifier, selector('eusdTokenId()'))).ret, 0), TOKEN_ID,
    'the verifier\'s token id');
  assertEq(decodeUint((await chain.must(
    escrow, selector('eusdTokenId()'))).ret, 0), ESCROW_TOKEN_ID,
    'the escrow\'s token id');

  await targetFixture(verifier, escrow);
  await chain.must(usdc,
    selector('mint(address,uint256)') + addrWord(escrow) + word(AMOUNT * 4n));
  assertEq(await balanceOf(usdc, escrow), AMOUNT * 4n,
    'the escrow must hold funds, or "releases nothing" is not a claim');

  // The real proof -- the same bytes that pay out in LEG 3 above.
  const r = await release(escrow, proof());
  assert(!r.ok, 'a mismatched deployment released funds');
  assertEq(r.ret.slice(0, 10), selector('WrongToken(uint64,uint64)'),
    `refused for the wrong reason: ${revertReason(r.ret)}`);
  // The error names both sides, which is the only diagnosis a deployer gets.
  assertEq(decodeUint('0x' + r.ret.slice(10), 0), TOKEN_ID,
    'the error must report what the verifier returned');
  assertEq(decodeUint('0x' + r.ret.slice(10), 1), ESCROW_TOKEN_ID,
    'the error must report what the escrow wanted');
  assertEq(await balanceOf(usdc, escrow), AMOUNT * 4n, 'no USDC left');
  assertEq(await balanceOf(usdc, BOB), 0n, 'nobody was paid');

  // It is not one bad proof, it is every proof: the verifier is deterministic
  // and its token id is immutable, so there is nothing a relayer can resubmit.
  for (let i = 0; i < 2; i++) {
    assert(!(await release(escrow, proof())).ok, `retry ${i} released funds`);
  }

  // THE CONTROL, and the thing that makes the refusal above about the pairing
  // and not about the proof: the SAME verifier, the SAME proof, an escrow that
  // agrees with it. This one pays.
  const matched = await chain.deploy('Escrow',
    addrWord(usdc) + addrWord(verifier) + word(TOKEN_ID) + word(CAP) +
    addrWord(GOV) + addrWord(AUDITOR) + word(0));
  await targetFixture(verifier, matched);
  await chain.must(usdc,
    selector('mint(address,uint256)') + addrWord(matched) + word(AMOUNT * 4n));
  const good2 = await release(matched, proof());
  assert(good2.ok, `the matched escrow must release: ${revertReason(good2.ret)}`);
  assertEq(await balanceOf(usdc, BOB), AMOUNT, 'the payee was paid');
});

await test('one authenticated return cannot pay a second escrow, even with the same verifier', async () => {
  const first = await deployBridge();
  const old = proof();
  await chain.must(first.usdc, selector('mint(address,uint256)') + addrWord(first.escrow) + word(AMOUNT));
  chain.evm.common.setChain(5);
  try {
    requireError(await release(first.escrow, old), 'WrongMemoDomain(bytes32,bytes32)');
    assertEq(await balanceOf(first.usdc, BOB), 0n, 'cross-chain replay pays nothing');
  } finally { chain.evm.common.setChain(1); }
  assert((await release(first.escrow, old)).ok, 'first payout');
  for (const namespace of [MEMO_DOMAIN, '0x'+'d7'.repeat(32)]) {
    const second = await deployBridge(namespace);
    await chain.must(second.usdc, selector('mint(address,uint256)') + addrWord(second.escrow) + word(AMOUNT));
    requireError(await release(second.escrow, old), 'WrongMemoDomain(bytes32,bytes32)');
    requireError(await release(second.escrow, {...old, memoDomainTag: namespace}), 'WrongMemoDomain(bytes32,bytes32)');
    assertEq(await balanceOf(second.usdc, BOB), 0n, 'no duplicate payout');
    assert((await release(second.escrow, proof())).ok, 'a NEW return naming second escrow pays');
  }
  const sameVerifier = await chain.deploy('Escrow', addrWord(first.usdc) + addrWord(first.verifier) +
    word(TOKEN_ID) + word(CAP) + addrWord(GOV) + addrWord(AUDITOR) + word(0));
  await chain.must(first.usdc, selector('mint(address,uint256)') + addrWord(sameVerifier) + word(AMOUNT));
  requireError(await release(sameVerifier, old), 'WrongMemoDomain(bytes32,bytes32)');
  requireError(await release(first.escrow, old), 'AlreadyRedeemed(bytes32)');
});

await test('the complete return transaction stays within its gas budget', async () => {
  assert(releaseGas > 0, 'the successful payout did not execute');
  const total = releaseGas + intrinsicGas(releaseData(proof()));
  assert(total <= TRANSACTION_GAS_BUDGET,
    `release costs ${total} gas, budget ${TRANSACTION_GAS_BUDGET}`);
});

const ok = summary();

console.log('');
console.log(`  release execution (verify + payout): ${releaseGas.toLocaleString()} gas`);
console.log(`  including intrinsic gas: ${(releaseGas + intrinsicGas(releaseData(proof()))).toLocaleString()}`);
console.log(`  tested transaction budget: ${TRANSACTION_GAS_BUDGET.toLocaleString()} gas`);
console.log('');
console.log('='.repeat(72));
console.log('ESTABLISHED BY THIS RUN');
console.log('='.repeat(72));
console.log('  Leg 1  USDC is really custodied; the destination is announced.');
console.log('  Leg 2  Not executed by this JavaScript suite.');
console.log('         scripts/acceptance.sh runs the actual Rust tests first and');
console.log('         stops on any Rust failure. Source names are not evidence.');
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
console.log('         the output\'s memo and its type required to be 0x8002 with an authenticated chain/escrow/domain.');
console.log('         All three come from one shared secret, S = [a]R, which');
console.log('         the recipient check already had to compute. `Proof` has');
console.log('         no amount, tokenId or beneficiary field: a proof in the');
console.log('         old layout claiming 10x to an attacker releases nothing.');
console.log('         B_token IS DERIVED FROM THE TOKEN ID in the constructor');
console.log('         (ristretto255 one-way map, RFC 9496 4.3.4), so there is');
console.log('         no generator argument a deployment can mispair.');
console.log('');
console.log('='.repeat(72));
console.log('NOT ESTABLISHED — THE BRIDGE IS NOT READY TO HOLD FUNDS');
console.log('='.repeat(72));
console.log('  * NO LIVE CEREMONY AND NO DEPLOYMENT. Everything below is code');
console.log('    and tests. Nobody has generated a key anyone holds.');
console.log('  * These are component integration tests using synthetic MobileCoin');
console.log('    blocks and a test ERC20. No Ethereum deposit observer, real USDC,');
console.log('    MobileCoin transaction submission or independently hosted signers ran.');
if (process.env.BRIDGE_LOCAL_RELEASE_BIN) console.log('    The connected local intent signer ran in a Rust subprocess with test keys.');
console.log('  * v2 memos bind chain, escrow and namespace; old v1 returns are refused.');
console.log('  * An audited 2-of-3 dealing does not prove threshold secrecy:');
console.log('    correlated coefficients can let one owner recover the secret.');
console.log('    The Rust counterexample uses genuine endorsements and passes');
console.log('    the funding gate. Honest independent DKG randomness is required.');
console.log('  * n seat keys are not n entities. Nothing can establish that,');
console.log('    and no later work will change it -- it is the assumption the');
console.log('    whole structure rests on and it is discharged by who is');
console.log('    actually in the room, not by this repo.');
console.log('  * A dealer that dealt real shares and KEPT COPIES produces');
console.log('    genuine artifacts that audit. Performed, by name, as a passing');
console.log('    test: a_dealer_that_dealt_real_shares_and_kept_copies_still_');
console.log('    passes. Exclusive possession is not provable from outside.');
console.log('  * The DKG binds each contribution to the seat that AUTHORIZED');
console.log('    it, not the seat that GENERATED it. A signature cannot link');
console.log('    the identity secret to the polynomial secret; the generation');
console.log('    reading needs an operational signing policy no verifier can');
console.log('    check. Also: Contribution has no serializer, so the guard is');
console.log('    correct and unexercisable in the multi-process setting where');
console.log('    it would help.');
console.log('  * The escrow\'s verifier is replaceable by governance after the');
console.log('    timelock, which is equivalent to being able to forge returns.');
console.log('    That is the trust model, deliberately; it is not a finding.');
console.log('  * Ristretto has specification review, dalek/noble differential');
console.log('    checks and targeted mutation controls, including representative');
console.log('    encodings and all official invalid vectors. This is finite');
console.log('    evidence, not a proof of whole-group implementation correctness');
console.log('    or a substitute for independent cryptographic review.');
console.log('  * "No token id derives the identity" is a cryptographic');
console.log('    heuristic (~2^-188), not a proof.');
console.log('  * The escrow\'s token id and the verifier\'s are separate');
console.log('    constructor arguments checked against each other by nothing.');
console.log('    A mismatch is fail-closed (asserted above) but bricks the');
console.log('    return leg on a funded escrow. It is a deployment');
console.log('    obligation, and there is no deployment procedure yet.');
console.log('='.repeat(72));

process.exitCode = ok ? 0 : 1;
