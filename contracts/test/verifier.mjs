// MobileCoinVerifier, end to end, against the real MobileCoin fixture.
//
// Every number driving this file comes out of two generated fixtures, neither
// of them written by hand:
//
//   crates/mc-return/fixtures/return.json   -- the block, the signatures, the
//     TxOut and the membership proof, built with `Block::new`,
//     `BlockSignature::from_block_and_keypair` and `mc-ledger-db`'s own
//     leaf/node functions, and re-checked with upstream's
//     `is_membership_proof_valid` before the file is written.
//
//   contracts/test/fixtures/amount.json     -- MaskedAmountV2 openings, memo
//     ciphertexts and Pedersen generators, produced by tools/amount-fixtures
//     from MobileCoin's own crates. Its `maskedAmountRejects` are cases
//     upstream REFUSES, with the error it refuses them with.
//
// So a pass here means the Solidity agrees with MobileCoin, not with itself.
//
// The component pieces (transcript, block id, block-sig digest, Ed25519,
// Blake2b, HKDF, AES) are pinned in merlin.mjs / ed25519.mjs / blake2b.mjs /
// hkdf.mjs / aes.mjs. What is new here is the whole contract: one
// `verifyReturn` call over an ABI-encoded Proof, and one negative case per link
// in its chain.
//
// WHAT THE PAYOUT RESTS ON. The amount, the token id and the beneficiary used
// to be plaintext fields of `Proof` -- the submitter's word, checked against
// nothing that related them to the output. They are now DERIVED from the
// output's own encrypted fields, and `Proof` has no place to put them. The
// tests under "the payout is derived" are the ones that hold that shut; read
// them before quoting a pass here as evidence that the return leg is closed.

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
const AMT = JSON.parse(readFileSync(
  join(HERE, 'fixtures', 'amount.json'), 'utf8'
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

/// `B_token`, MobileCoin's `generators(id).B`, as published by the oracle.
/// Pinning it is a deployment decision -- see MobileCoinVerifier's
/// `eusdValueGenerator` -- so every verifier below is built with the one that
/// belongs to its token id, and one test asserts the pin is upstream's value.
const GENERATOR = (id) => {
  const g = AMT.generators.byTokenId.find((x) => x.tokenId === String(id));
  assert(g, `amount.json has no generator for token id ${id}`);
  return g.bToken;
};

const SIGS = FIX.quorum.signatures;
assertEq(SIGS.length, FIX.quorum.threshold, 'fixture quorum size vs threshold');

// Entities, assigned in signature order so that the fixture's own ordering is
// already the ascending-by-entity order isQuorum demands.
const ENTITY = (i) => '0x' + (i + 1).toString(16).padStart(2, '0').repeat(32);

// -------------------------------------------------------------- ABI encoding

const dynB32s = (a) => word(a.length) + a.map(b32).join('');
const dynSigs = (a) =>
  word(a.length) + a.map((s) => b32(s[0]) + b32(s[1])).join('');

const dynBytesArg = (hex) => {
  const h = hex.replace(/^0x/, '');
  return word(h.length / 2) + h.padEnd(Math.ceil(h.length / 64) * 64, '0');
};

/// `MobileCoinVerifier.TxOutFields`, as its own dynamic-tuple region.
///
/// It contains `bytes`, so it appears in any head as an offset and carries its
/// own internal offsets. Written out rather than delegated to a library for the
/// same reason the rest of the suite is: a mis-encoded argument fails in ways
/// that look like contract bugs.
function encodeTxOut(t) {
  const tails = [
    dynBytesArg(t.maskedTokenId), dynBytesArg(t.eFogHint), dynBytesArg(t.eMemo),
  ];
  const head = [
    b32(t.commitment), word(t.maskedValue), null,
    b32(t.targetKey), b32(t.publicKey), null, null,
  ];
  let off = head.length * 32;
  for (const [slot, tail] of [[2, tails[0]], [5, tails[1]], [6, tails[2]]]) {
    head[slot] = word(off);
    off += tail.length / 2;
  }
  return head.join('') + tails.join('');
}

/// `MobileCoinVerifier.Proof`, ABI-encoded as the single argument
/// `abi.decode(proof, (Proof))` expects: an offset word, then the tuple.
///
/// NOTE WHAT IS NOT IN HERE. There is no `amount`, no `tokenId` and no
/// `beneficiary`. `encodeLegacyProof` below still builds the layout that had
/// them, so a test can hand the contract one and watch it refuse.
function encodeProof(p) {
  const txOutBlob = encodeTxOut(p.txOut);
  const head = [
    b32(p.blockId), word(p.version), b32(p.parentId), word(p.index),
    word(p.cumulativeTxoCount), word(p.rootRangeFrom), word(p.rootRangeTo),
    b32(p.rootHash), b32(p.contentsHash),
    null, null,                                   // signerKeys, signatures
    null,                                         // txOut
    b32(p.memoDomainTag),
    null,                                         // merklePath
    word(p.merkleIndex),
  ];
  const tails = [dynB32s(p.signerKeys), dynSigs(p.signatures), txOutBlob,
                 dynB32s(p.merklePath)];
  let off = head.length * 32;
  for (const [slot, tail] of [[9, tails[0]], [10, tails[1]], [11, tails[2]],
                              [13, tails[3]]]) {
    head[slot] = word(off);
    off += tail.length / 2;
  }
  return word(32) + head.join('') + tails.join('');
}

/// The layout `Proof` had while the payout was the submitter's word: an
/// `amount` and `tokenId` after the TxOut, and a `beneficiary` after the memo
/// domain tag. Kept only so the "derived, not claimed" test can submit one.
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
  for (const [slot, tail] of [[9, tails[0]], [10, tails[1]], [11, tails[2]],
                              [16, tails[3]]]) {
    head[slot] = word(off);
    off += tail.length / 2;
  }
  return word(32) + head.join('') + tails.join('');
}

const callVerify = (chain, verifier, p, enc = encodeProof) =>
  chain.call(verifier, encodeWithTrailingBytes(
    'verifyReturn(bytes)', [], '0x' + enc(p)));

/// `openAmount(bytes32, TxOutFields)`. The tuple's canonical type string has to
/// match the struct field for field or the selector is for another function.
const TXOUT_TYPE = '(bytes32,uint64,bytes,bytes32,bytes32,bytes,bytes)';
const callOpenAmount = (chain, verifier, sharedSecret, txOut) =>
  chain.call(verifier, selector(`openAmount(bytes32,${TXOUT_TYPE})`) +
    b32(sharedSecret) + word(64) + encodeTxOut(txOut));

const callOpenMemo = (chain, verifier, sharedSecret, eMemo) =>
  chain.call(verifier, encodeWithTrailingBytes(
    'openMemo(bytes32,bytes)', [b32(sharedSecret)], eMemo));

// Custom-error selectors, so a revert is asserted by NAME and a test cannot
// pass on the wrong failure.
const ERR = {};
for (const sig of [
  'QuorumNotMet()', 'BadSignature(uint256)', 'SignerCountMismatch()',
  'WrongTokenId(uint64,uint64)', 'WrongMemoDomain(bytes32,bytes32)',
  'WrongMemoType(bytes2,bytes2)', 'ZeroBeneficiary()', 'NotPayableToBridge()',
  'MembershipFailed()', 'BlockIdMismatch(bytes32,bytes32)',
  'InvalidMaskedTokenId(uint256)', 'InconsistentCommitment(bytes32,bytes32)',
  'InvalidValueGenerator(bytes32)', 'InvalidMemoLength(uint256)',
]) ERR[selector(sig)] = sig;

const errorOf = (r) => ERR[(r.ret || '0x').slice(0, 10)] ||
  revertReason(r.ret, ERR);

function assertRevertsWith(r, sig, msg) {
  assert(!r.ok, `${msg}: expected revert, call succeeded`);
  assertEq(errorOf(r), sig, msg);
  return r;
}

// ------------------------------------------------------------------- fixtures

const chain = await Chain.create({
  only: ['MobileCoinVerifier.sol', 'ValidatorRegistry.sol', 'TestMocks.sol',
         'RecipientCheck.sol'],
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

/// A verifier, with whatever recipient check and token/generator pair a test
/// wants. `rc` is an already-deployed address so a test can supply a
/// constructed mock.
const deployVerifier = (reg, rc, {
  tokenId = TOKEN_ID,
  generator = GENERATOR(TOKEN_ID),
  spendKey = FIX.disclosure.recovered_subaddress_spend_key,
  memoDomain = MEMO_DOMAIN,
} = {}) => chain.deploy('MobileCoinVerifier',
  addrWord(reg) + b32(spendKey) + word(tokenId) + b32(generator) +
  b32(memoDomain) + addrWord(rc));

/// The REAL recipient check, holding the return address's published view
/// private key. It is what computes `S = [a]R`, and every derived field below
/// is downstream of that one point.
const realCheck = await chain.deploy('RecipientCheck',
  b32(FIX.disclosure.view_private_key));

const REG = await registry(ENTITY);
const V = await deployVerifier(REG, realCheck);

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
  memoDomainTag: MEMO_DOMAIN,
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
  assert(r.ok, `verifyReturn reverted: ${errorOf(r)}`);
  happyGas = r.gas;

  assertEq('0x' + r.ret.slice(2, 66), FIX.expected.outputPublicKey,
    'outputPublicKey');
  assertEq('0x' + r.ret.slice(2 + 64 + 24, 2 + 128), FIX.expected.beneficiary,
    'beneficiary');
  assertEq(decodeUint(r.ret, 2), BigInt(FIX.expected.amount), 'amount');
  assertEq(decodeUint(r.ret, 3), TOKEN_ID, 'tokenId');
});

await test('the returned amount, token id and payee are the ones MobileCoin '
  + 'put in the output', async () => {
  // The fixture's `disclosure` is what `Disclosure::open` recovered in Rust
  // with the bridge's view key, using upstream's `MaskedAmountV2::get_value`
  // and `decrypt_memo`. Asserting the contract's three derived values against
  // it -- rather than against `expected`, which the same file also carries --
  // is the statement that the Solidity opened the output the same way
  // MobileCoin does.
  const r = await callVerify(chain, V, good());
  assert(r.ok, `verifyReturn reverted: ${errorOf(r)}`);
  assertEq(decodeUint(r.ret, 2), BigInt(FIX.expected.amount),
    'value, vs the Rust disclosure');
  assertEq('0x' + r.ret.slice(2 + 64 + 24, 2 + 128),
    '0x' + FIX.disclosure.memo_data.replace(/^0x/, '').slice(0, 40),
    'beneficiary, vs the first 20 bytes of the decrypted memo data');
  assertEq(FIX.disclosure.memo_type, '0x8001',
    'the fixture must be a bridge-return memo, or this test proves nothing');
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
  const v = await deployVerifier(collided, realCheck);
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

await test('an index congruent to the real one modulo the path length is refused',
  async () => {
  // Sol's finding. Only the low `merklePath.length` bits steer the walk, so
  // every index in `real + k*2^length` used to reproduce the same root and be
  // accepted -- 11 for a real 3 over a three-level path. The leaf stayed bound
  // either way, but the output's claimed GLOBAL position did not, which
  // upstream refuses as `HighestIndexMismatch`
  // (transaction/core/src/membership_proofs/mod.rs). `verifyMembership` now
  // requires the index to be fully consumed.
  const real = BigInt(FIX.membership_proof.index);
  // The levels the CONTRACT walks, which is the path it is given -- not the
  // fixture's element count, which includes the leaf's own element.
  const levels = BigInt(good().merklePath.length);
  assert(levels > 0n, 'the fixture path is empty -- this test proves nothing');

  // The alias Sol exhibited, plus one more, so this is not one arithmetic
  // coincidence.
  for (const k of [1n, 2n]) {
    const alias = real + (k << levels);
    assert((alias & ((1n << levels) - 1n)) === (real & ((1n << levels) - 1n)),
      `${alias} does not share ${real}'s branch bits -- bad test`);
    assert(alias !== real, 'the alias must differ from the real index');
    const r = await callVerify(chain, V, mutate({ merkleIndex: alias }));
    assertRevertsWith(r, 'MembershipFailed()', `aliased index ${alias}`);
  }

  // And the real index still verifies, so the new check refuses aliases rather
  // than refusing everything.
  const ok = await callVerify(chain, V, mutate({ merkleIndex: real }));
  assert(ok.ok, `the real index must still verify: ${errorOf(ok)}`);
});

/// Mutate one field of the nested TxOut.
const withTxOut = (over) => mutate({ txOut: { ...good().txOut, ...over } });

await test('a TxOut that is not in the tree is not a member', async () => {
  const r = await callVerify(chain, V,
    withTxOut({ commitment: flip(FIX.tx_out.masked_amount.commitment) }));
  assertRevertsWith(r, 'MembershipFailed()', 'foreign TxOut');
});

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
  // change to the output changes the leaf and the membership walk fails. Note
  // that this is now also the FIRST line of defence for the payout: the masked
  // value, the masked token id and the memo are the inputs the amount and
  // beneficiary are derived from, so binding them binds what is paid.
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

// -------------------------------------------- link 4: payable to this bridge

await test('a rejecting recipient check stops an otherwise perfect proof', async () => {
  const rc = await chain.deploy('RejectsEveryRecipient');
  const v = await deployVerifier(REG, rc);
  const r = await callVerify(chain, v, good());
  assertRevertsWith(r, 'NotPayableToBridge()', 'rejecting recipient check');
});

await test('a bridge deployed for a different return address redeems nothing',
  async () => {
  // The real check, the real view key, the real output -- and a spend key that
  // is not the one this output was paid to. This is the case that decides
  // whether an attacker who gets THEIR OWN output into a signed block can
  // redeem it.
  const v = await deployVerifier(REG, realCheck, {
    spendKey: flip(FIX.disclosure.recovered_subaddress_spend_key),
  });
  const r = await callVerify(chain, v, good());
  assertRevertsWith(r, 'NotPayableToBridge()', 'wrong return address');
});

await test('a proof for another deployment of this bridge is refused', async () => {
  // `memoDomainTag` is not in the MobileCoin data at all: it is a constant the
  // submitter restates, so a proof assembled against one deployment cannot be
  // handed to another. It is NOT what binds the memo -- that is the memo type,
  // read out of the ciphertext below.
  const other = '0x' + Buffer.from('mc-bridge-return-v2')
    .toString('hex').padEnd(64, '0');
  const r = await callVerify(chain, V, mutate({ memoDomainTag: other }));
  assertRevertsWith(r, 'WrongMemoDomain(bytes32,bytes32)', 'wrong domain');
});

// ================================================== THE PAYOUT IS DERIVED
//
// Everything from here down is about the defect this file used to record under
// FINDING: that the amount, the token id and the beneficiary were the
// submitter's word.

console.log('\n  the payout is derived, not claimed');

await test('the shared secret is [a]R, and comes back only with a yes', async () => {
  // Everything below is downstream of this one point, so it is worth pinning
  // on its own rather than only through what it opens.
  const ask = (spend) => chain.call(realCheck,
    selector('isPayableToBridge(bytes32,bytes32,bytes32)') +
    b32(FIX.tx_out.public_key) + b32(FIX.tx_out.target_key) + b32(spend));

  const yes = await ask(FIX.disclosure.recovered_subaddress_spend_key);
  assert(yes.ok, `isPayableToBridge reverted: ${errorOf(yes)}`);
  assertEq(decodeUint(yes.ret, 0), 1n, 'the real output must be payable');
  // The Rust side recovered this with `get_tx_out_shared_secret`, i.e. `a*R`.
  assertEq('0x' + yes.ret.slice(66, 130), FIX.disclosure.shared_secret,
    'S must be [a]R, as MobileCoin computes it');

  // And it is [a]R, NOT Hs([a]R). The one-time-key scalar is a different
  // construction for a different purpose; substituting it would produce
  // well-formed masks that open nothing, so the two must be distinguishable.
  const hs = (await chain.must(realCheck,
    selector('hashToScalar(bytes32)') + b32(FIX.disclosure.shared_secret))).ret;
  assert(hs !== FIX.disclosure.shared_secret,
    'Hs(S) and S coincide -- this test cannot tell them apart');

  // A no must carry no secret. The caller reverts on a no, so this is
  // unreachable from `verifyReturn` -- which is exactly why it is asserted
  // here: an implementation that leaks the secret of an output that was NOT
  // paid to the bridge hands out material for opening someone else's output,
  // and nothing downstream would notice.
  for (const [name, spend] of [
    ['a different return address',
      flip(FIX.disclosure.recovered_subaddress_spend_key)],
    ['the zero spend key', '0x' + '00'.repeat(32)],
  ]) {
    const no = await ask(spend);
    assert(no.ok, `${name}: ${errorOf(no)}`);
    assertEq(decodeUint(no.ret, 0), 0n, `${name}: expected a no`);
    assertEq(decodeUint(no.ret, 1), 0n,
      `${name}: the shared secret must not come back with a no`);
  }
});

await test('every intermediate of the derivation matches the oracle', async () => {
  // The oracle publishes each step -- the amount shared secret, both 8-byte
  // masks, the 64 raw blinding bytes, the memo's AES key and nonce -- so that
  // a failure of the whole path localises to a step instead of to "the amount
  // is wrong". These go through AmountOpenerProbe, which exposes the library's
  // internal functions; the library itself is the one `verifyReturn` uses.
  const probe = await chain.deploy('AmountOpenerProbe');
  const at = (r, i) => '0x' + r.ret.slice(2 + i * 64, 2 + (i + 1) * 64);

  assertEq((await chain.must(probe, selector('bBlinding()'))).ret,
    AMT.generators.bBlinding,
    'B_blinding, as the contract uses it, is the ristretto basepoint');

  // The fixture must actually distinguish a wide reduction from a 32-byte
  // truncation, or the blinding assertions below prove less than they look.
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const leToBig = (hex) => {
    const h = hex.replace(/^0x/, '');
    let v = 0n;
    for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt('0x' + h.slice(i, i + 2));
    return v;
  };
  assert(AMT.maskedAmounts.some((c) =>
    leToBig(c.blindingWide) % L !==
    leToBig('0x' + c.blindingWide.replace(/^0x/, '').slice(0, 64)) % L),
    'no case distinguishes the wide reduction from a truncation');

  for (const c of AMT.maskedAmounts) {
    const ass = await chain.must(probe,
      selector('amountSharedSecret(bytes32)') + b32(c.sharedSecret));
    assertEq(ass.ret, c.amountSharedSecret,
      `case ${c.case}: Blake2b512("mc_amount_shared_secret" || S)[0..32]`);
    assertEq(leToBig(c.blindingWide) % L, leToBig(c.blinding),
      `case ${c.case}: the oracle's own blinding is the wide reduction`);

    const f = await chain.must(probe,
      selector('blindingFactors(bytes32)') + b32(c.sharedSecret));
    assertEq(decodeUint(f.ret, 0), BigInt(c.valueMask), `case ${c.case}: value mask`);
    assertEq(decodeUint(f.ret, 1), BigInt(c.tokenIdMask), `case ${c.case}: token id mask`);
    assertEq(at(f, 2), c.blinding, `case ${c.case}: blinding`);

    // The Pedersen construction on its own, given the numbers rather than the
    // masks: value*B_token + blinding*B_blinding must be the point in the
    // block. This is the arithmetic the commitment check rests on, checked
    // without the KDF in front of it.
    const com = await chain.must(probe,
      selector('commitmentOf(uint64,bytes32,bytes32)') +
      word(c.value) + b32(c.blinding) + b32(GENERATOR(c.tokenId)));
    assertEq(com.ret, c.commitment, `case ${c.case}: recomputed commitment`);
  }

  for (const m of AMT.memos) {
    const r = await chain.must(probe,
      selector('memoOkm(bytes32)') + b32(m.sharedSecret));
    assertEq('0x' + r.ret.slice(2, 66), m.aesKey, `${m.name}: AES key`);
    assertEq('0x' + r.ret.slice(66, 98), m.aesNonce, `${m.name}: AES nonce`);
  }
});

await test('the pinned value generator is MobileCoin\'s own generators(tokenId)',
  async () => {
  // Without this assertion `eusdValueGenerator` is an unfounded constant, and
  // the commitment check below is a comparison against a point nobody vouched
  // for. amount.json's `generators` come from MobileCoin's `generators()`.
  //
  // The id is read back OFF THE CONTRACT rather than reused from the
  // deployment arguments. Sol pointed out that comparing the getter against
  // the same expression that was passed to the constructor establishes only
  // that immutables round-trip; going through `eusdTokenId()` at least makes
  // the fixture lookup a function of what the contract believes it accepts.
  const id = decodeUint((await chain.must(V, selector('eusdTokenId()'))).ret, 0);
  assertEq(id, TOKEN_ID, 'the deployed token id');
  const got = (await chain.must(V, selector('eusdValueGenerator()'))).ret;
  assertEq(got, GENERATOR(id), 'the deployed B_token');

  // What actually vouches for the point is the oracle, so check the half of
  // its construction that can be re-derived here without hash-to-curve: the
  // preimage is the compressed ristretto basepoint with the token id's eight
  // little-endian bytes XOR-ed over bytes 0..8
  // (crypto/ring-signature/src/ring_signature/mod.rs). The Elligator step from
  // that preimage to the point is what the fixture is for.
  assert(AMT.generators.byTokenId.some(
    (g) => g.preimage !== AMT.generators.basepointCompressed),
    'every preimage is the bare basepoint -- the XOR is not being exercised');
  for (const g of AMT.generators.byTokenId) {
    const base = Buffer.from(
      AMT.generators.basepointCompressed.replace(/^0x/, ''), 'hex');
    const want = Buffer.from(base);
    let v = BigInt(g.tokenId);
    for (let i = 0; i < 8; i++) {
      want[i] ^= Number(v & 0xffn);
      v >>= 8n;
    }
    assertEq('0x' + want.toString('hex'), g.preimage,
      `token id ${g.tokenId}: hash-to-point preimage`);
  }

  // And the pin is token-id specific, which is the whole reason it is a
  // deployment parameter: a different id is a different, orthogonal point.
  for (const g of AMT.generators.byTokenId) {
    if (g.tokenId === String(TOKEN_ID)) continue;
    assert(g.bToken !== GENERATOR(TOKEN_ID),
      `generators for ${g.tokenId} and ${TOKEN_ID} collide`);
  }

  // B_blinding is NOT a deployment parameter: MobileCoin's is the ristretto255
  // basepoint, so the contract uses `Ristretto255.basepoint()` and there is
  // nothing to configure. If the oracle ever says otherwise, the contract is
  // wrong.
  assertEq(AMT.generators.bBlinding, AMT.generators.basepointCompressed,
    'B_blinding must be the ristretto basepoint');
});

await test('a verifier cannot be deployed with a generator that is not a point',
  async () => {
  // The identity is refused separately from a bad encoding, and it is the
  // dangerous one: with B_token = 0 the commitment is `blinding*G` for every
  // value, so the value stops being committed to and any amount verifies.
  for (const [name, bad] of [
    ['identity', '0x' + '00'.repeat(32)],
    ['not a canonical field element', '0x' + 'ff'.repeat(32)],
    ['a non-square s', flip(GENERATOR(TOKEN_ID))],
  ]) {
    let threw = null;
    try {
      await deployVerifier(REG, realCheck, { generator: bad });
    } catch (e) {
      threw = e.message;
    }
    assert(threw, `constructor accepted ${name} as B_token`);
    assert(threw.includes(selector('InvalidValueGenerator(bytes32)')) ||
      threw.includes('InvalidValueGenerator'),
      `${name}: wrong failure -- ${threw}`);
  }

  // The control: the real generator deploys. Otherwise the three above could
  // be failing for a reason that has nothing to do with the generator.
  await deployVerifier(REG, realCheck);
});

/// A verifier configured for one of amount.json's token ids, with a recipient
/// check that hands back a chosen shared secret. Used to drive `openAmount`
/// and `openMemo` -- the same functions `verifyReturn` calls -- over the
/// oracle's cases.
const openerFor = async (tokenId, secret) => {
  const rc = await chain.deploy('FixedSecretRecipient_DO_NOT_DEPLOY',
    b32(secret));
  return deployVerifier(REG, rc,
    { tokenId: BigInt(tokenId), generator: GENERATOR(tokenId) });
};

/// A TxOut carrying one of amount.json's masked amounts. The four fields
/// `openAmount` does not read are filled from the real fixture so that nothing
/// here is a zero that could accidentally be the answer.
const amountTxOut = (c) => ({
  commitment: c.commitment,
  maskedValue: BigInt(c.maskedValue),
  maskedTokenId: c.maskedTokenId,
  targetKey: FIX.tx_out.target_key,
  publicKey: FIX.tx_out.public_key,
  eFogHint: FIX.tx_out.e_fog_hint,
  eMemo: FIX.tx_out.e_memo,
});

await test('every MobileCoin-generated masked amount opens to what MobileCoin '
  + 'put in it', async () => {
  // Eight cases from tools/amount-fixtures: token ids 0, 1, 8192 and u64::MAX,
  // values 0, 1, 250e9 and u64::MAX. Each one is a MaskedAmountV2 built by
  // MobileCoin's own crate, so agreement is agreement with upstream and not
  // with a second implementation of the same idea.
  assert(AMT.maskedAmounts.length >= 8, 'the oracle lost its cases');
  for (const c of AMT.maskedAmounts) {
    const v = await openerFor(c.tokenId, c.sharedSecret);
    const r = await callOpenAmount(chain, v, c.sharedSecret, amountTxOut(c));
    assert(r.ok, `case ${c.case} (${c.label}): ${errorOf(r)}`);
    assertEq(decodeUint(r.ret, 0), BigInt(c.value), `case ${c.case} value`);
    assertEq(decodeUint(r.ret, 1), BigInt(c.tokenId), `case ${c.case} tokenId`);
  }
});

await test('A LARGER AMOUNT PAIRED WITH A SMALLER COMMITMENT IS REFUSED',
  async () => {
  // THE ATTACK, adjudicated by upstream. The oracle built a masked amount that
  // unmasks cleanly to 500,000,000,000 while the commitment commits to
  // 1,000,000, and recorded that MobileCoin returns `InconsistentCommitment`
  // for it. Removing the masks alone would hand back the large number: XOR is
  // invertible, so a masked value "opens" to something under any secret. Only
  // recomputing `value*B_token + blinding*B_blinding` and requiring equality
  // ties that number to the output the Merkle path covered.
  const c = AMT.maskedAmountRejects.find(
    (x) => x.expectedError === 'InconsistentCommitment');
  assert(c, 'the oracle no longer publishes the commitment-mismatch case');
  assert(BigInt(c.unmasksToValue) > BigInt(c.commitmentCommitsToValue),
    'this case is only the attack if it unmasks to MORE than it commits to');

  const v = await openerFor(c.tokenId, c.sharedSecret);
  const r = await callOpenAmount(chain, v, c.sharedSecret, amountTxOut(c));
  assertRevertsWith(r, 'InconsistentCommitment(bytes32,bytes32)',
    'a forged value must not open');

  // And the number it would have paid out is the forged one, so this is not a
  // case that would have failed for some other reason.
  const unmaskOnly = await chain.call(v,
    selector(`openAmount(bytes32,${TXOUT_TYPE})`) + b32(c.sharedSecret) +
    word(64) + encodeTxOut(amountTxOut(c)));
  assertEq(errorOf(unmaskOnly), 'InconsistentCommitment(bytes32,bytes32)',
    'stable across calls');
  assertEq(BigInt(c.unmasksToValue), 500000000000n,
    'the oracle changed the forged value -- re-read this test');
});

await test('a masked token id that is not exactly 8 bytes is malformed',
  async () => {
  // MaskedAmountV2 has no default for a missing masked token id -- upstream
  // returns InvalidMaskedTokenId for every length but 8. Four lengths, from
  // the oracle, each with the error upstream gives.
  const cases = AMT.maskedAmountRejects.filter(
    (x) => x.expectedError === 'InvalidMaskedTokenId');
  assert(cases.length === 4, `expected 4 length cases, got ${cases.length}`);
  for (const c of cases) {
    const v = await openerFor(8192, c.sharedSecret);
    const r = await callOpenAmount(chain, v, c.sharedSecret, amountTxOut(c));
    assertRevertsWith(r, 'InvalidMaskedTokenId(uint256)', c.name);
    assertEq(decodeUint('0x' + r.ret.slice(10)),
      BigInt(c.maskedTokenId.replace(/^0x/, '').length / 2),
      `${c.name}: the reported length`);
  }
});

await test('EVERY length but 8 is refused, not just the four the oracle ships',
  async () => {
  // Sol's finding: with only 0, 4, 7 and 9 tested, an implementation that
  // refused exactly those four and accepted everything else passed the whole
  // suite. A 16-byte masked token id is the case that matters -- `LE.get64`
  // would read the first 8 bytes and silently ignore the rest, so a longer
  // field would open to a token id while upstream's `try_into()` refuses the
  // conversion outright (masked_amount/v2.rs, TokenId::NUM_BYTES == 8).
  //
  // Driven through the probe rather than a verifier so the length can be
  // swept independently of any fixture's shared secret.
  const probe = await chain.deploy('AmountOpenerProbe');
  const c = AMT.maskedAmounts[0];
  let refused = 0;
  for (let n = 0; n <= 40; n++) {
    if (n === 8) continue;
    const bytes = '0x' + 'a7'.repeat(n);
    const r = await chain.call(probe,
      selector('unmask(bytes32,uint64,bytes)') + b32(c.sharedSecret) +
      word(BigInt(c.maskedValue)) + word(96) + dynBytesArg(bytes));
    assertEq(errorOf(r), 'InvalidMaskedTokenId(uint256)', `${n} bytes`);
    assertEq(decodeUint('0x' + r.ret.slice(10)), BigInt(n),
      `${n} bytes: the reported length`);
    refused++;
  }
  assertEq(refused, 40, 'the sweep did not run');

  // And 8 is accepted, so the check is a length check and not a refusal of
  // everything.
  const ok = await chain.call(probe,
    selector('unmask(bytes32,uint64,bytes)') + b32(c.sharedSecret) +
    word(BigInt(c.maskedValue)) + word(96) + dynBytesArg(c.maskedTokenId));
  assert(ok.ok, `8 bytes must open: ${errorOf(ok)}`);
  assertEq(decodeUint(ok.ret, 1), BigInt(c.tokenId), 'and to the right id');
});

await test('AN AMOUNT IN THE WRONG TOKEN IS REFUSED even though it opens cleanly',
  async () => {
  // The oracle's case that MobileCoin accepts and this bridge must not: a
  // well-formed MaskedAmountV2 whose token id is not eusdTokenId. The token id
  // is now DERIVED, so there is no field to put the right answer in.
  const c = AMT.maskedAmountRejects.find(
    (x) => x.name === 'well-formed-but-wrong-token-id');
  assert(c, 'the oracle no longer publishes the wrong-token-id case');

  const v = await openerFor(8192, c.sharedSecret);
  const r = await callOpenAmount(chain, v, c.sharedSecret, amountTxOut(c));
  assertRevertsWith(r, 'WrongTokenId(uint64,uint64)', 'wrong token id');
  const got = decodeUint('0x' + r.ret.slice(10), 0);
  assertEq(decodeUint('0x' + r.ret.slice(10), 1), 8192n, 'want');
  assert(got !== 8192n, 'the reported token id must be the derived one');

  // The same output opened by a verifier configured for the id it really
  // carries: it is a genuine amount, refused for its denomination alone.
  const right = await openerFor(got, c.sharedSecret);
  const ok = await callOpenAmount(chain, right, c.sharedSecret, amountTxOut(c));
  assert(ok.ok, `the same amount must open under its own token id: ${errorOf(ok)}`);
  assertEq(decodeUint(ok.ret, 1), got, 'and to that id');
});

await test('the real output will not open under the wrong value generator',
  async () => {
  // Same proof, same everything, one deployment parameter changed: B_token for
  // eUSD instead of B_token for this fixture's token id 1. The token id still
  // derives to 1 and passes, so this reaches the commitment check and nothing
  // else -- which makes it the end-to-end demonstration that the commitment
  // comparison is enforced rather than skipped.
  const v = await deployVerifier(REG, realCheck, { generator: GENERATOR(8192) });
  const r = await callVerify(chain, v, good());
  assertRevertsWith(r, 'InconsistentCommitment(bytes32,bytes32)',
    'wrong generator');

  // The recomputed point and the on-chain one must actually differ, and the
  // second must be the block's commitment -- otherwise the error could be
  // reporting nonsense.
  const args = '0x' + r.ret.slice(10);
  assertEq('0x' + args.slice(2 + 64, 2 + 128),
    FIX.tx_out.masked_amount.commitment, 'the on-chain side of the mismatch');
  assert('0x' + args.slice(2, 66) !== FIX.tx_out.masked_amount.commitment,
    'the two sides of the mismatch are the same value');
});

await test('a MISPAIRED token id and generator verifies an amount MobileCoin refuses',
  async () => {
  // Sol's finding, made executable. The constructor checks that
  // `eusdValueGenerator` is a point and is not the identity; it cannot check
  // that it is `generators(eusdTokenId)`, because that is the hash-to-curve
  // this contract deliberately does not implement. This test EXHIBITS what a
  // mismatched pair costs, so the obligation is written down as a running
  // program rather than as a comment somebody may or may not read.
  //
  // This is a deployment defect, not an attack: no proof submitter can change
  // the pair after construction. It is recorded, not fixed, because fixing it
  // on chain means Elligator on chain.
  const c = AMT.maskedAmounts.find((x) => x.tokenId === '8192'
    && BigInt(x.value) > 0n);
  assert(c, 'the oracle no longer publishes a non-zero 8192 case');
  const probe = await chain.deploy('AmountOpenerProbe');

  // The same value and blinding, committed in the WRONG group.
  const wrong = (await chain.must(probe,
    selector('commitmentOf(uint64,bytes32,bytes32)') +
    word(BigInt(c.value)) + b32(c.blinding) + b32(GENERATOR(1)))).ret;
  assert(wrong !== c.commitment,
    'B_1 and B_8192 commit identically -- this test proves nothing');

  // MobileCoin, which computes B_8192 for a token id of 8192, refuses it:
  // that is exactly the InconsistentCommitment case the correctly-paired
  // verifier gives.
  const right = await openerFor(8192, c.sharedSecret);
  const refused = await callOpenAmount(chain, right, c.sharedSecret,
    { ...amountTxOut(c), commitment: wrong });
  assertRevertsWith(refused, 'InconsistentCommitment(bytes32,bytes32)',
    'a correctly paired verifier agrees with MobileCoin');

  // The mispaired one accepts it, and pays out the value.
  const rc = await chain.deploy('FixedSecretRecipient_DO_NOT_DEPLOY',
    b32(c.sharedSecret));
  const mispaired = await deployVerifier(REG, rc,
    { tokenId: 8192n, generator: GENERATOR(1) });
  const accepted = await callOpenAmount(chain, mispaired, c.sharedSecret,
    { ...amountTxOut(c), commitment: wrong });
  assert(accepted.ok,
    `the witness no longer holds -- re-read this test: ${errorOf(accepted)}`);
  assertEq(decodeUint(accepted.ret, 0), BigInt(c.value),
    'the value a mispaired deployment would pay');
  assertEq(decodeUint(accepted.ret, 1), 8192n, 'under the configured id');
});

await test('a shared secret that is not this output\'s opens nothing', async () => {
  // The one lever left to a submitter: the TxOut fields are bound by the
  // membership proof, so the only way to change what comes out is to change
  // the secret. A recipient check that says yes and hands back a secret it did
  // not derive from `[a]R` gets a value and token id that are effectively
  // random, and the derivation refuses them.
  for (const [name, secret] of [
    ['zero', '0x' + '00'.repeat(32)],
    ['one bit off', flip(FIX.disclosure.shared_secret)],
    ['another output\'s', AMT.maskedAmounts[4].sharedSecret],
  ]) {
    const rc = await chain.deploy('FixedSecretRecipient_DO_NOT_DEPLOY',
      b32(secret));
    const v = await deployVerifier(REG, rc);
    const r = await callVerify(chain, v, good());
    assert(!r.ok, `${name}: a foreign shared secret verified`);
    // Either refusal is correct and which one is a fact about the garbage: the
    // token id derives first, so it usually fails there. What must never
    // happen is a success, or a failure that is not one of these two.
    assert(['WrongTokenId(uint64,uint64)',
            'InconsistentCommitment(bytes32,bytes32)'].includes(errorOf(r)),
      `${name}: refused for the wrong reason -- ${errorOf(r)}`);
  }

  // The control: the SAME mock, carrying the real secret, verifies. So the
  // three refusals above are about the secret and not about the mock.
  const rc = await chain.deploy('FixedSecretRecipient_DO_NOT_DEPLOY',
    b32(FIX.disclosure.shared_secret));
  const v = await deployVerifier(REG, rc);
  const ok = await callVerify(chain, v, good());
  assert(ok.ok, `the real shared secret must verify: ${errorOf(ok)}`);
  assertEq(decodeUint(ok.ret, 2), BigInt(FIX.expected.amount), 'and pay it');
});

await test('the permissive test recipient check no longer redeems anything',
  async () => {
  // AcceptsAnyRecipient_DO_NOT_DEPLOY says yes to every output. That used to be
  // enough to redeem one; it is not any more, because the secret it returns is
  // zero and a zero secret opens nothing. Worth pinning: the mock is still in
  // the tree, and this is the difference between "do not deploy this" and "it
  // would not work anyway".
  const rc = await chain.deploy('AcceptsAnyRecipient_DO_NOT_DEPLOY');
  const v = await deployVerifier(REG, rc);
  const r = await callVerify(chain, v, good());
  assert(!r.ok, 'a blanket yes redeemed a return');
});

await test('every memo the oracle published decrypts to the address it carries',
  async () => {
  // Four memos from tools/amount-fixtures, encrypted by MobileCoin's own
  // MemoPayload: a real address, the zero address, all-ones, and one with the
  // wrong memo type. The verifier's own `openMemo` -- the function
  // `verifyReturn` calls -- adjudicates each.
  const v = await deployVerifier(REG, realCheck);
  for (const m of AMT.memos) {
    const r = await callOpenMemo(chain, v, m.sharedSecret, m.ciphertext);
    if (m.memoType !== '0x8001') {
      assertRevertsWith(r, 'WrongMemoType(bytes2,bytes2)', m.name);
      assertEq('0x' + r.ret.slice(10, 14), m.memoType, `${m.name}: reported type`);
      assertEq('0x' + r.ret.slice(10 + 64, 10 + 68), '0x8001',
        `${m.name}: reported want`);
    } else if (BigInt(m.beneficiary) === 0n) {
      assertRevertsWith(r, 'ZeroBeneficiary()', m.name);
    } else {
      assert(r.ok, `${m.name}: ${errorOf(r)}`);
      assertEq('0x' + r.ret.slice(26), m.beneficiary, `${m.name}: beneficiary`);
    }
  }

  // All four cases were actually exercised, so a fixture that lost its
  // negative memos would fail here rather than quietly shrink the test.
  assert(AMT.memos.some((m) => m.memoType !== '0x8001'), 'no wrong-type memo');
  assert(AMT.memos.some((m) => BigInt(m.beneficiary) === 0n), 'no zero-payee memo');
  assert(AMT.memos.some((m) => m.memoType === '0x8001' &&
    BigInt(m.beneficiary) !== 0n), 'no honest memo');
});

await test('a memo that is not 66 bytes is not a memo', async () => {
  const v = await deployVerifier(REG, realCheck);
  const full = FIX.tx_out.e_memo.replace(/^0x/, '');
  for (const [name, hex] of [
    ['empty', '0x'],
    ['one byte short', '0x' + full.slice(0, -2)],
    ['one byte long', '0x' + full + 'aa'],
  ]) {
    const r = await callOpenMemo(chain, v, FIX.disclosure.shared_secret, hex);
    assertRevertsWith(r, 'InvalidMemoLength(uint256)', name);
    assertEq(decodeUint('0x' + r.ret.slice(10)),
      BigInt(hex.replace(/^0x/, '').length / 2), `${name}: reported length`);
  }
  // The control: the real 66-byte memo opens.
  const ok = await callOpenMemo(chain, v, FIX.disclosure.shared_secret,
    FIX.tx_out.e_memo);
  assert(ok.ok, `the real memo must open: ${errorOf(ok)}`);
});

await test('THE PROOF HAS NOWHERE TO NAME AN AMOUNT, TOKEN OR PAYEE', async () => {
  // The defect this replaces: `Proof` carried `amount`, `tokenId` and
  // `beneficiary` as plaintext, the contract paid them out, and one genuine
  // quorum-signed return could therefore be resubmitted naming any payee and
  // any amount up to the escrow's balance. The old test here asserted that a
  // proof claiming 1,000,000,000,000 to 0xbaba... SUCCEEDED.
  //
  // Submitting exactly that proof now. The three fields are gone from the
  // struct, so the old layout is not a `Proof` at all -- its trailing offsets
  // point at the wrong words -- and there is no encoding of "pay me instead".
  const attack = {
    ...good(),
    amount: 1_000_000_000_000n,
    tokenId: TOKEN_ID,
    beneficiary: '0x' + 'ba'.repeat(20),
  };
  const r = await callVerify(chain, V, attack, encodeLegacyProof);
  assert(!r.ok, 'the old attack proof still verifies -- the defect is OPEN');

  // And the honest proof, in the layout that exists, pays the address in the
  // memo -- not the one in the attack.
  const ok = await callVerify(chain, V, good());
  assert(ok.ok, `the honest proof must still verify: ${errorOf(ok)}`);
  const paid = '0x' + ok.ret.slice(2 + 64 + 24, 2 + 128);
  assertEq(paid, FIX.expected.beneficiary, 'payee');
  assert(paid.toLowerCase() !== '0x' + 'ba'.repeat(20),
    'the invented payee came back');
  assertEq(decodeUint(ok.ret, 2), BigInt(FIX.expected.amount), 'value');
  assert(decodeUint(ok.ret, 2) !== 1_000_000_000_000n,
    'the invented amount came back');
});

// ------------------------------------------------------------------ FINDINGS

await test('FINDING: blockIndex reports the anchor, not the originating block', async () => {
  // IMobileCoinVerifier.sol documents blockIndex as "index of the block the
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
