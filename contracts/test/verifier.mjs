// MobileCoinVerifier, end to end, against the real MobileCoin fixture.
//
// Every number driving this file comes out of `crates/mc-return`, which builds
// blocks with `Block::new`, signs them with
// `BlockSignature::from_block_and_keypair`, hashes the TxOut tree with
// `mc-ledger-db`'s own leaf/node functions, and re-checks its own membership
// proof with upstream's `is_membership_proof_valid` before writing the file. So
// a pass here means the Solidity agrees with MobileCoin, not with itself.
//
// The component pieces (transcript, block id, block-sig digest, Ed25519,
// Blake2b) are pinned in merlin.mjs / ed25519.mjs / blake2b.mjs. What is new
// here is the whole contract: one `verifyReturn` call over an ABI-encoded
// Proof, and one negative case per link in its chain.
//
// THE GAPS THAT REMAIN ARE DEMONSTRATED RATHER THAN ASSERTED AWAY, at the
// bottom of the file under FINDING. Read those before quoting a pass here as
// evidence that the return leg is closed.

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import {
  Chain, selector, word, addrWord, b32, encodeWithTrailingBytes,
  decodeUint, test, assert, assertEq, summary, revertReason,
} from './harness.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = JSON.parse(readFileSync(
  join(HERE, '..', '..', 'crates', 'mc-return', 'fixtures', 'return.json'),
  'utf8'
));

const GOV = '0x' + '11'.repeat(20);
const MEMO_DOMAIN =
  '0x' + Buffer.from('mc-bridge-return-v1').toString('hex').padEnd(64, '0');

// The anchor is the block whose root_element the membership proof reproduces
// and whose digest the quorum signed. It is the only block a verifier needs.
const ANCHOR = FIX.chain[FIX.chain.length - 1];
assertEq(BigInt(ANCHOR.index), BigInt(FIX.anchor_block_index), 'anchor index');
assertEq(ANCHOR.root_element.hash, FIX.merkle.known_root.hash,
  'the membership proof must be against the anchor root');

// Read the token id off the fixture. This scenario is token id 1, not eUSD's
// 8192; hard-coding 8192 here would make every negative case pass for the
// wrong reason.
const TOKEN_ID = BigInt(FIX.expected.tokenId);

const SIGS = FIX.quorum.signatures;
assertEq(SIGS.length, FIX.quorum.threshold, 'fixture quorum size vs threshold');

// Entities, assigned in signature order so that the fixture's own ordering is
// already the ascending-by-entity order isQuorum demands.
const ENTITY = (i) => '0x' + (i + 1).toString(16).padStart(2, '0').repeat(32);

// -------------------------------------------------------------- ABI encoding

const dynB32s = (a) => word(a.length) + a.map(b32).join('');
const dynSigs = (a) =>
  word(a.length) + a.map((s) => b32(s[0]) + b32(s[1])).join('');

/// `MobileCoinVerifier.Proof`, ABI-encoded as the single argument
/// `abi.decode(proof, (Proof))` expects: an offset word, then the tuple.
///
/// Hand-rolled for the same reason the rest of the suite is: the offsets below
/// are part of what is being tested, in the sense that a mis-encoded proof
/// would fail in ways that look like contract bugs.
function encodeProof(p) {
  // TxOutFields contains `bytes`, so it is a DYNAMIC tuple: it appears in the
  // head as an offset and is encoded as its own region with its own internal
  // offsets. Getting this wrong presents as a contract bug, which is why it is
  // written out rather than delegated to a library.
  const dynBytesArg = (hex) => {
    const h = hex.replace(/^0x/, '');
    return word(h.length / 2) + h.padEnd(Math.ceil(h.length / 64) * 64, '0');
  };

  const txOutTails = [
    dynBytesArg(p.txOut.maskedTokenId),
    dynBytesArg(p.txOut.eFogHint),
    dynBytesArg(p.txOut.eMemo),
  ];
  const txOutHead = [
    b32(p.txOut.commitment), word(p.txOut.maskedValue), null,
    b32(p.txOut.targetKey), b32(p.txOut.publicKey), null, null,
  ];
  let tOff = txOutHead.length * 32;
  for (const [slot, tail] of [[2, txOutTails[0]], [5, txOutTails[1]],
                              [6, txOutTails[2]]]) {
    txOutHead[slot] = word(tOff);
    tOff += tail.length / 2;
  }
  const txOutBlob = txOutHead.join('') + txOutTails.join('');

  const head = [
    b32(p.blockId), word(p.version), b32(p.parentId), word(p.index),
    word(p.cumulativeTxoCount), word(p.rootRangeFrom), word(p.rootRangeTo),
    b32(p.rootHash), b32(p.contentsHash),
    null, null,                                   // signerKeys, signatures
    null,                                         // txOut
    word(p.amount), word(p.tokenId),
    b32(p.memoDomainTag), addrWord(p.beneficiary),
    null,                                         // merklePath
    word(p.merkleIndex),
  ];
  const tails = [dynB32s(p.signerKeys), dynSigs(p.signatures), txOutBlob,
                 dynB32s(p.merklePath)];
  let off = head.length * 32;
  for (const [slot, tail] of [[9, tails[0]], [10, tails[1]], [11, tails[2]],
                              [16, tails[3]]]) {
    head[slot] = word(off);
    off += tail.length / 2;
  }
  return word(32) + head.join('') + tails.join('');
}

const callVerify = (chain, verifier, p) =>
  chain.call(verifier, encodeWithTrailingBytes(
    'verifyReturn(bytes)', [], '0x' + encodeProof(p)));

// Custom-error selectors, so a revert is asserted by NAME and a test cannot
// pass on the wrong failure.
const ERR = {};
for (const sig of [
  'QuorumNotMet()', 'BadSignature(uint256)', 'SignerCountMismatch()',
  'WrongTokenId(uint64,uint64)', 'WrongMemoDomain(bytes32,bytes32)',
  'ZeroBeneficiary()', 'NotPayableToBridge()', 'MembershipFailed()',
  'BlockIdMismatch(bytes32,bytes32)',
]) ERR[selector(sig)] = sig;

function assertRevertsWith(r, sig, msg) {
  assert(!r.ok, `${msg}: expected revert, call succeeded`);
  const got = (r.ret || '0x').slice(0, 10);
  assertEq(ERR[got] || revertReason(r.ret, ERR), sig, msg);
  return r;
}

// ------------------------------------------------------------------- fixtures

const chain = await Chain.create({
  only: ['MobileCoinVerifier.sol', 'ValidatorRegistry.sol', 'TestMocks.sol'],
});

async function registry(entityOf) {
  const reg = await chain.deploy('ValidatorRegistry',
    addrWord(GOV) + word(SIGS.length) + word(0));
  for (let i = 0; i < SIGS.length; i++) {
    const args = b32(SIGS[i].signer) + b32(entityOf(i)) + word(0) + word(0);
    await chain.must(reg,
      selector('proposeKey(bytes32,bytes32,uint64,uint64)') + args, { from: GOV });
    await chain.must(reg,
      selector('enrollKey(bytes32,bytes32,uint64,uint64)') + args, { from: GOV });
  }
  return reg;
}

async function verifier(reg, recipientCheckContract) {
  const rc = await chain.deploy(recipientCheckContract);
  return chain.deploy('MobileCoinVerifier',
    addrWord(reg) + b32(FIX.disclosure.recovered_subaddress_spend_key) +
    word(TOKEN_ID) + b32(MEMO_DOMAIN) + addrWord(rc));
}

const REG = await registry(ENTITY);
const V = await verifier(REG, 'AcceptsAnyRecipient_DO_NOT_DEPLOY');

/// A proof that should verify. Every field is read from the fixture.
const good = () => ({
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
    '0x' + s.signature.slice(2, 66), '0x' + s.signature.slice(66, 130),
  ]),
  txOut: {
    commitment: FIX.tx_out.masked_amount.commitment,
    maskedValue: BigInt(FIX.tx_out.masked_amount.masked_value),
    maskedTokenId: FIX.tx_out.masked_amount.masked_token_id,
    targetKey: FIX.tx_out.target_key,
    publicKey: FIX.tx_out.public_key,
    eFogHint: FIX.tx_out.e_fog_hint,
    eMemo: FIX.tx_out.e_memo,
  },
  amount: BigInt(FIX.expected.amount),
  tokenId: TOKEN_ID,
  memoDomainTag: MEMO_DOMAIN,
  beneficiary: FIX.expected.beneficiary,
  merklePath: FIX.membership_proof.elements.slice(1).map((e) => e.hash),
  merkleIndex: BigInt(FIX.membership_proof.index),
});

const mutate = (over) => ({ ...good(), ...over });
const flip = (h) => '0x' + (BigInt(h) ^ 1n).toString(16).padStart(64, '0');
const flip64 = (h) => '0x' + (BigInt(h) ^ 1n).toString(16).padStart(16, '0');
const flipLast = (h) => h.slice(0, -1) +
  (parseInt(h.slice(-1), 16) ^ 1).toString(16);

console.log('\nMobileCoinVerifier vs the MobileCoin fixture');

// --------------------------------------------------------------- happy path

let happyGas = 0;

await test('a real MobileCoin return verifies end to end', async () => {
  const r = await callVerify(chain, V, good());
  assert(r.ok, `verifyReturn reverted: ${revertReason(r.ret, ERR)}`);
  happyGas = r.gas;

  assertEq('0x' + r.ret.slice(2, 66), FIX.expected.outputPublicKey,
    'outputPublicKey');
  assertEq('0x' + r.ret.slice(2 + 64 + 24, 2 + 128), FIX.expected.beneficiary,
    'beneficiary');
  assertEq(decodeUint(r.ret, 2), BigInt(FIX.expected.amount), 'amount');
  assertEq(decodeUint(r.ret, 3), TOKEN_ID, 'tokenId');
});

await test('report the gas for one full verifyReturn', async () => {
  assert(happyGas > 0, 'the happy path did not run');
  // Reported, not asserted: a gas number is a fact about today's contract, and
  // pinning it would turn every optimisation into a failing test. What IS
  // worth stating is the ceiling. A transaction cannot exceed the block gas
  // limit, so above ~30M this function is not merely expensive, it is
  // unlandable on Ethereum mainnet at any price.
  const BLOCK_GAS_LIMIT = 30_000_000;
  console.log(`        verifyReturn: ${happyGas.toLocaleString()} gas ` +
    `(${SIGS.length} signatures, ${good().merklePath.length} Merkle levels)` +
    `\n        ${(happyGas / BLOCK_GAS_LIMIT * 100).toFixed(0)}% of a 30M ` +
    `block gas limit` +
    (happyGas > BLOCK_GAS_LIMIT
      ? ' -- OVER. This call cannot fit in a mainnet block.'
      : ''));
});

// ------------------------------------------------- link 1: this block, signed

await test('tampering with ANY header field is caught as BlockIdMismatch', async () => {
  // The id is a field of the block, so it is recomputed rather than trusted:
  // otherwise a relayer pairs one block's id -- and its signatures -- with
  // another block's contents.
  const fields = [
    'blockId', 'version', 'parentId', 'index', 'cumulativeTxoCount',
    'rootRangeFrom', 'rootRangeTo', 'rootHash', 'contentsHash',
  ];
  for (const f of fields) {
    const base = good()[f];
    const over = typeof base === 'bigint' ? base ^ 1n : flip(base);
    const r = await callVerify(chain, V, mutate({ [f]: over }));
    assertRevertsWith(r, 'BlockIdMismatch(bytes32,bytes32)', `field ${f}`);
  }
});

await test('a forged signature is rejected, and the failing index is named', async () => {
  for (let i = 0; i < SIGS.length; i++) {
    const sigs = good().signatures;
    sigs[i] = [sigs[i][0], flip(sigs[i][1])];
    const r = await callVerify(chain, V, mutate({ signatures: sigs }));
    assertRevertsWith(r, 'BadSignature(uint256)', `signer ${i}`);
    assertEq(decodeUint('0x' + r.ret.slice(10)), BigInt(i),
      `BadSignature must name signer ${i}`);
  }
});

await test('signatures and keys must be parallel', async () => {
  const r = await callVerify(chain, V,
    mutate({ signatures: good().signatures.slice(1) }));
  assertRevertsWith(r, 'SignerCountMismatch()', 'short signature list');
});

// ----------------------------------------------------- link 2: a real quorum

await test('an unenrolled signer is not a quorum', async () => {
  const spare = FIX.quorum.signers.find((k) => !SIGS.some((s) => s.signer === k));
  assert(spare, 'fixture has no signer outside the signing set');
  const keys = good().signerKeys;
  keys[keys.length - 1] = spare;
  const r = await callVerify(chain, V, mutate({ signerKeys: keys }));
  assertRevertsWith(r, 'QuorumNotMet()', 'unenrolled signer');
});

await test('two keys from ONE entity are not a quorum', async () => {
  // The forgery ValidatorRegistry exists to stop: BlockSignature is signed
  // with a per-enclave identity key, so one operator running several enclaves
  // holds several perfectly valid keys and would meet any key-counting
  // threshold alone. Same keys, same signatures, same block as the happy path
  // -- only the entity mapping differs.
  const collided = await registry((i) => ENTITY(i === 2 ? 1 : i));
  const v = await verifier(collided, 'AcceptsAnyRecipient_DO_NOT_DEPLOY');
  const r = await callVerify(chain, v, good());
  assertRevertsWith(r, 'QuorumNotMet()', 'entity collision');

  // The control, so the revert above cannot be some unrelated deployment
  // difference: the same key list, asked of both registries.
  const ask = (reg) => chain.must(reg,
    selector('isQuorum(bytes32[],uint64)') +
    word(64) + word(BigInt(ANCHOR.index)) + dynB32s(good().signerKeys));
  assertEq(decodeUint((await ask(REG)).ret), 1n, 'distinct entities are a quorum');
  assertEq(decodeUint((await ask(collided)).ret), 0n, 'collided entities are not');
});

// -------------------------------------------------- link 3: in THAT block

await test('a broken membership path is caught', async () => {
  for (let i = 0; i < good().merklePath.length; i++) {
    const path = good().merklePath;
    path[i] = flip(path[i]);
    const r = await callVerify(chain, V, mutate({ merklePath: path }));
    assertRevertsWith(r, 'MembershipFailed()', `path element ${i}`);
  }
});

await test('the membership index is bound: a shifted walk fails', async () => {
  // Placement at each level comes from a bit of merkleIndex, so lying about
  // the index puts a sibling on the wrong side and misses the signed root.
  const r = await callVerify(chain, V,
    mutate({ merkleIndex: BigInt(FIX.membership_proof.index) ^ 1n }));
  assertRevertsWith(r, 'MembershipFailed()', 'flipped index');
});

/// Mutate one field of the nested TxOut.
const withTxOut = (over) => mutate({ txOut: { ...good().txOut, ...over } });

await test('a TxOut that is not in the tree is not a member', async () => {
  const r = await callVerify(chain, V,
    withTxOut({ commitment: flip(FIX.tx_out.masked_amount.commitment) }));
  assertRevertsWith(r, 'MembershipFailed()', 'foreign TxOut');
});

// ------------------------------------------- links 4 and 5: token, memo, payee

await test('a different token id is refused, and both ids are reported', async () => {
  const wrong = TOKEN_ID + 8191n;
  const r = await callVerify(chain, V, mutate({ tokenId: wrong }));
  assertRevertsWith(r, 'WrongTokenId(uint64,uint64)', 'wrong token');
  assertEq(decodeUint('0x' + r.ret.slice(10), 0), wrong, 'got');
  assertEq(decodeUint('0x' + r.ret.slice(10), 1), TOKEN_ID, 'want');
});

await test('a memo written for another domain cannot be replayed here', async () => {
  const other = '0x' + Buffer.from('mc-bridge-return-v2')
    .toString('hex').padEnd(64, '0');
  const r = await callVerify(chain, V, mutate({ memoDomainTag: other }));
  assertRevertsWith(r, 'WrongMemoDomain(bytes32,bytes32)', 'wrong domain');
});

await test('a memo naming nobody is refused', async () => {
  const r = await callVerify(chain, V,
    mutate({ beneficiary: '0x' + '00'.repeat(20) }));
  assertRevertsWith(r, 'ZeroBeneficiary()', 'zero beneficiary');
});

await test('a rejecting recipient check stops an otherwise perfect proof', async () => {
  // The recipient check is the one link the Solidity cannot yet compute, so
  // the thing to prove is that its answer is load-bearing rather than advisory.
  const v = await verifier(REG, 'RejectsEveryRecipient');
  const r = await callVerify(chain, v, good());
  assertRevertsWith(r, 'NotPayableToBridge()', 'rejecting recipient check');
});

// ------------------------------------------------------------------ FINDINGS

await test('the redeemed output is BOUND to the one proven to be in the block',
  async () => {
  // This closes a real defect. The Merkle leaf used to cover a caller-supplied
  // `txOutHash` with nothing relating it to the public key or amount also
  // supplied, so the path proved that SOME output was in the block while the
  // caller named a different one -- and since the public key is the escrow's
  // replay key (IMobileCoinVerifier.sol), one genuinely included output could
  // be redeemed unboundedly under invented identities.
  //
  // The leaf preimage is now recomputed from the output's own fields, so any
  // change to the output changes the leaf and the membership walk fails.
  for (const [name, over] of [
    ['public key', { publicKey: flip(FIX.tx_out.public_key) }],
    ['target key', { targetKey: flip(FIX.tx_out.target_key) }],
    ['masked value', {
      maskedValue: BigInt(FIX.tx_out.masked_amount.masked_value) ^ 1n }],
    ['masked token id', {
      maskedTokenId: flip64(FIX.tx_out.masked_amount.masked_token_id) }],
    ['memo', { eMemo: flipLast(FIX.tx_out.e_memo) }],
    ['fog hint', { eFogHint: flipLast(FIX.tx_out.e_fog_hint) }],
  ]) {
    const r = await callVerify(chain, V, withTxOut(over));
    assertRevertsWith(r, 'MembershipFailed()', `altered ${name}`);
  }
});

await test('FINDING: the amount and the beneficiary are still the relayer\'s word', async () => {
  // The test above binds the TxOut's own fields. Those fields are the
  // ENCRYPTED ones: `masked_amount` is a Pedersen commitment plus a masked
  // value, and `e_memo` is ciphertext. `amount` and `beneficiary` are the
  // PLAINTEXT the relayer claims they open to, and nothing on this chain
  // opens them -- that needs the bridge's view key, which Ethereum must never
  // have. See crates/mc-return/README.md "Limitations": the fixture sets
  // disclosure.on_chain_verifiable = false precisely so this is not assumed.
  //
  // So a relayer holding one genuine, quorum-signed, provably-included return
  // still names its value and its payee freely, and that is the whole payout.
  // Pinned rather than left to the README, because every other test in this
  // file passes and a green run must not read as "the return leg is closed".
  //
  // tokenId is NOT free in the same way -- it is checked against eusdTokenId
  // -- but it is checked against a constant, not against masked_token_id, so
  // it is asserted rather than proven too.
  const r = await callVerify(chain, V, mutate({
    amount: 1_000_000_000_000n,
    beneficiary: '0x' + 'ba'.repeat(20),
  }));
  assert(r.ok, 'if this now reverts, the disclosure gap is closed -- delete this');
  assertEq(decodeUint(r.ret, 2), 1_000_000_000_000n,
    'an invented amount came back as the payout');
  assertEq('0x' + r.ret.slice(2 + 64 + 24, 2 + 128), '0x' + 'ba'.repeat(20),
    'an invented beneficiary came back as the payee');
});

await test('FINDING: blockIndex reports the anchor, not the originating block', async () => {
  // IMobileCoinVerifier.sol:21 documents blockIndex as "index of the block the
  // output was finalized in", and the fixture's expected.blockIndex is
  // origin_block_index (the block that CREATED the TxOut). The contract
  // returns Proof.index, which must be the ANCHOR height -- it is the block
  // whose digest was signed and whose root the membership proof reproduces,
  // and it is what ValidatorRegistry scopes key validity to.
  //
  // Proof carries one index and cannot carry both, so this is a naming and
  // documentation defect, not an exploitable one: blockIndex is only emitted
  // (Escrow.sol:240). Left alone because the honest fix is renaming a field in
  // an interface this task does not own.
  const r = await callVerify(chain, V, good());
  assert(r.ok, 'happy path must still verify');
  assertEq(decodeUint(r.ret, 4), BigInt(ANCHOR.index), 'returned blockIndex');
  assert(BigInt(FIX.expected.blockIndex) !== BigInt(ANCHOR.index),
    'fixture no longer disagrees -- re-read this test');
});

summary();
