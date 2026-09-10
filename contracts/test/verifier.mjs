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
// tools/ristretto-fixtures' `rejects`: encodings curve25519-dalek itself
// refuses, asserted refused on the Rust side before the file is written. Read
// here for one reason -- `AmountOpener.decodeGenerator` has a refusal for a
// generator that is not a point, and this is the only published supply of
// things that are not points.
const RIS = JSON.parse(readFileSync(
  join(HERE, 'fixtures', 'ristretto.json'), 'utf8'
));

const FIXTURE_ESCROW = '0x' + '71'.repeat(20);
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
///
/// NOT a deployment parameter any more. The constructor derives it from the
/// token id, so this is only ever the EXPECTED value here: what the fixture
/// says upstream computes, to be compared against what the contract computed.
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
    null,                                         // merklePath
    word(p.merkleIndex),
  ];
  const tails = [dynB32s(p.signerKeys), dynSigs(p.signatures), txOutBlob,
                 dynB32s(p.merklePath)];
  let off = head.length * 32;
  for (const [slot, tail] of [[9, tails[0]], [10, tails[1]], [11, tails[2]],
                              [12, tails[3]]]) {
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
    'verifyReturn(bytes)', [], '0x' + enc(p)), { from: FIXTURE_ESCROW });

/// `openAmount(bytes32, TxOutFields)`. The tuple's canonical type string has to
/// match the struct field for field or the selector is for another function.
const TXOUT_TYPE = '(bytes32,uint64,bytes,bytes32,bytes32,bytes,bytes)';
const callOpenAmount = (chain, verifier, sharedSecret, txOut) =>
  chain.call(verifier, selector(`openAmount(bytes32,${TXOUT_TYPE})`) +
    b32(sharedSecret) + word(64) + encodeTxOut(txOut));

const callOpenMemo = (chain, verifier, sharedSecret, eMemo) =>
  chain.call(verifier, encodeWithTrailingBytes(
    'openMemo(bytes32,bytes)', [b32(sharedSecret)], eMemo), { from: FIXTURE_ESCROW });

// Custom-error selectors, so a revert is asserted by NAME and a test cannot
// pass on the wrong failure.
const ERR = {};
for (const sig of [
  'QuorumNotMet()', 'BadSignature(uint256)', 'SignerCountMismatch()',
  'WrongTokenId(uint64,uint64)', 'WrongMemoDomain(bytes32,bytes32)',
  'NonzeroMemoReserved(bytes12)', 'WrongMemoType(bytes2,bytes2)', 'ZeroBeneficiary()', 'NotPayableToBridge()',
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

/// A verifier, with whatever recipient check and token id a test wants. `rc` is
/// an already-deployed address so a test can supply a constructed mock.
///
/// THERE IS NO `generator` OPTION, and that is the point of this change: the
/// constructor derives `B_token` from `tokenId`, so no test -- and no deployer
/// -- can pair one with the other's point.
const deployVerifier = (reg, rc, {
  tokenId = TOKEN_ID,
  spendKey = FIX.disclosure.recovered_subaddress_spend_key,
  memoDomain = MEMO_DOMAIN,
} = {}) => chain.deploy('MobileCoinVerifier',
  addrWord(reg) + b32(spendKey) + word(tokenId) +
  b32(memoDomain) + addrWord(rc));

/// What one `MobileCoinVerifier` deployment actually costs and produces: the
/// whole transaction's gas, and the runtime code EIP-170 has to accept.
///
/// THE TRANSACTION, NOT THE EXECUTION. This used to return
/// `executionGasUsed` alone, under a comment saying "a deployment is a
/// transaction, so it has to fit in a block like any other" -- which is the
/// argument for measuring the other ~509,000 gas it was leaving out. A
/// contract creation pays, before a single opcode runs:
///
///   * 21,000 G_transaction, the base cost of any transaction,
///   * 32,000 G_txcreate, charged because `to` is empty. MEASURED, not
///     assumed: `evm.runCall` on init code that returns an empty runtime
///     reports 6 gas, so ethereumjs charges this at the transaction layer,
///     which this suite does not use. Leaving it out understates a deployment
///     by 32,000 -- and the note that prompted this change left it out too.
///   * 16 gas per non-zero and 4 per zero byte of init code, as calldata
///     (EIP-2028); init code here is ~28.8 KB and almost entirely non-zero,
///     which is where the bulk of the number comes from, and
///   * 2 gas per 32-byte word of init code (EIP-3860, Shanghai).
///
/// The 200-gas-per-byte code deposit is NOT added here: it is already inside
/// `executionGasUsed`. Measured the same way -- init code returning 32 bytes
/// of runtime reports 6,409 gas, of which 6,400 is the deposit.
///
/// EIP-3860 also caps init code at 49,152 bytes, which is the other cliff and
/// is reported below.
///
/// The calldata term depends on the ARGUMENT bytes as well as the code, so two
/// deployments of the same contract differ by a few hundred gas according to
/// how many zero bytes their addresses and keys happen to contain. That is
/// real -- it is what the deployer pays -- and it is why this is reported
/// rather than pinned.
/// The intrinsic charge of a creation transaction: G_transaction + G_txcreate.
/// Asserted below rather than only spelled out here -- see the gas-accounting
/// test, which measures that neither term is already inside `executionGasUsed`.
const G_TRANSACTION = 21_000;
const G_TXCREATE = 32_000;

/// A fresh EVM carrying EIP-2929's INITIAL ACCESS SET, which is what makes the
/// execution term below a property of the contract rather than of whatever ran
/// before it.
///
/// WHY THIS IS NOT `chain.evm`. `deployCost` used to run on the shared EVM,
/// which by then had already deployed a `MobileCoinVerifier` at module scope.
/// ethereumjs carries warm-account state across `runCall`s, so the execution
/// term was warm -- and warm BY ACCIDENT. Deleting the module-scope deploy, or
/// merely moving this test above it, would have moved the published figure by
/// 5,000 gas with nothing turning red.
///
/// WHY THE FIX IS NOT SIMPLY "USE A FRESH EVM". A fresh `runCall` is COLDER
/// than a real transaction, so that would have overstated the bill by the same
/// 5,000. EIP-2929: "accessed_addresses is initialized to include the
/// tx.sender, tx.to (or the address being created if it is a contract creation
/// transaction) and the set of all precompiles." ethereumjs applies that
/// initialization in `runTx`, in @ethereumjs/vm -- a package this repo does not
/// install -- while `evm.runCall` warms only the created address
/// (evm.js:688). So the sender and the precompiles have to be warmed here.
///
/// It is exactly two precompiles that matter, and they are why the number
/// moved: the constructor calls modexp (0x05) and blake2f (0x09), at 2,500 gas
/// each for a cold account access.
///
/// Measured all three ways, same init code: fresh EVM 5,021,677; fresh EVM
/// with this initial set 5,016,677; shared EVM after a prior deploy 5,016,677.
/// The last two agree, which is the point -- the modelled number and the
/// accidental one are the same, so this change fixes the reasoning without
/// moving the published figure.
async function freshCreationEvm() {
  const { EVM } = await import('@ethereumjs/evm');
  const { Account } = await import('@ethereumjs/util');
  const evm = await EVM.create();
  await evm.stateManager.putAccount(chain.deployer, new Account(0n, 10n ** 24n));
  evm.journal.addAlwaysWarmAddress(chain.deployer.toString());
  // The precompiles. 0x01..0x0a covers every one this chain has; warming an
  // address the constructor never touches costs nothing and models the EIP.
  for (let i = 1; i <= 10; i++) {
    evm.journal.addAlwaysWarmAddress('0x' + i.toString(16).padStart(40, '0'));
  }
  return evm;
}

async function deployCost(encodedArgs) {
  const { hexToBytes, bytesToHex } = await import('@ethereumjs/util');
  const initCode = hexToBytes(chain._bytecode('MobileCoinVerifier') + encodedArgs);
  let zero = 0;
  for (const b of initCode) if (b === 0) zero++;
  const calldata = zero * 4 + (initCode.length - zero) * 16;
  const initWords = 2 * Math.ceil(initCode.length / 32);

  // The constructor reads its address arguments but calls none of them, so a
  // state with nothing else deployed measures the same work.
  const evm = await freshCreationEvm();
  const r = await evm.runCall({
    data: initCode,
    gasLimit: 500_000_000n,
    caller: chain.deployer,
    origin: chain.deployer,
  });
  assert(!r.execResult.exceptionError,
    `deploy failed: ${revertReason(bytesToHex(r.execResult.returnValue))}`);

  const execution = Number(r.execResult.executionGasUsed);
  const intrinsic = G_TRANSACTION + G_TXCREATE;
  return {
    initCodeBytes: initCode.length,
    runtimeBytes: r.execResult.returnValue.length,
    intrinsic,
    calldata,
    initWords,
    execution,
    total: intrinsic + calldata + initWords + execution,
  };
}

/// EIP-170's runtime code limit, and EIP-3860's init code limit.
const EIP_170_LIMIT = 24_576;
const EIP_3860_LIMIT = 49_152;

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
  assertEq(FIX.disclosure.memo_type, '0x8002',
    'the fixture must be a bridge-return memo, or this test proves nothing');
});

await test('report the gas for one deployment TRANSACTION, derivation included',
  async () => {
  // The number the deleted constructor argument was traded for. `B_token` used
  // to be handed to the constructor because deriving it needs hash-to-curve;
  // deriving it costs this much, ONCE, and `verifyReturn` never runs it.
  //
  // Reported against a ceiling rather than pinned: a deployment is a
  // transaction, so it has to fit in a block like any other -- and that
  // sentence is why this measures the transaction. `executionGasUsed` alone,
  // which is what this test used to print, understates the bill by
  // G_transaction, G_txcreate, the calldata cost of ~28.8 KB of init code and
  // EIP-3860's per-word charge: about 509,000 gas, or 9% of the total.
  const args = addrWord(REG) +
    b32(FIX.disclosure.recovered_subaddress_spend_key) + word(TOKEN_ID) +
    b32(MEMO_DOMAIN) + addrWord(realCheck);
  const c = await deployCost(args);

  assert(c.total < 30_000_000,
    `the deployment transaction does not fit in a block: ${c.total}`);
  console.log(`        deployment TRANSACTION: ${c.total.toLocaleString()} gas`
    + ` (${(c.total / 30_000_000 * 100).toFixed(1)}% of a 30M block)`);
  console.log(`          ${c.intrinsic.toLocaleString()} intrinsic `
    + `(21,000 + 32,000 G_txcreate) + ${c.calldata.toLocaleString()} calldata `
    + `+ ${c.initWords.toLocaleString()} EIP-3860 initcode words + `
    + `${c.execution.toLocaleString()} execution (deposit included)`);
  console.log(`          over ${c.initCodeBytes.toLocaleString()} bytes of `
    + `init code (EIP-3860 limit ${EIP_3860_LIMIT.toLocaleString()}, `
    + `${(c.initCodeBytes / EIP_3860_LIMIT * 100).toFixed(0)}%)`);

  // The pre-execution charge is most of a small transaction on its own, and it
  // is the part that scales with code size rather than with work done. Stated
  // as an assertion so that a change which doubles the code cannot quietly
  // present itself as costing only its own execution.
  //
  // THE THRESHOLD ALONE IS NOT ENOUGH, and that is why the line below it
  // exists. `calldata` is 453,008 on its own, so `preExecution > 450_000`
  // passes with the intrinsic term set to ZERO -- measured: reverting
  // `intrinsic` to a bare 21,000 leaves this test green and printing
  // 5,492,489. The 32,000 G_txcreate correction is the whole reason this
  // helper was rewritten, so it gets an assertion of its own.
  const preExecution = c.intrinsic + c.calldata + c.initWords;
  assert(preExecution > 450_000,
    `the pre-execution charge collapsed to ${preExecution} -- either the code `
    + 'shrank enormously or this test stopped measuring the transaction');
  assertEq(c.intrinsic, 53_000,
    'a creation transaction pays G_transaction (21,000) AND G_txcreate '
    + '(32,000). The gas-accounting test below measures that neither is '
    + 'already inside executionGasUsed, which is what makes adding them right.');

  // And it is a derivation, not a stored constant: eUSD's 8192 costs
  // essentially the same as this fixture's token id 1, because the work does
  // not depend on the id.
  const eusd = await deployCost(
    addrWord(REG) + b32(FIX.disclosure.recovered_subaddress_spend_key) +
    word(8192n) + b32(MEMO_DOMAIN) + addrWord(realCheck));
  console.log(`        the same for eUSD's token id 8192: `
    + `${eusd.total.toLocaleString()} gas`);
  assert(Math.abs(eusd.execution - c.execution) < 50_000,
    `deriving 8192 costs ${eusd.execution} against ${c.execution} for `
    + `${TOKEN_ID} -- the derivation is not id-independent`);
});

await test('WHAT executionGasUsed DOES AND DOES NOT ALREADY CONTAIN', async () => {
  // The two facts the deployment figure is assembled from. Both were measured
  // when `deployCost` was written and then recorded only in a comment, which
  // is the same as not having measured them: a later ethereumjs that moved
  // either charge would leave every gas number in this file wrong and every
  // test green.
  //
  // Neither probe involves MobileCoinVerifier. They are two-instruction init
  // codes, so they isolate the accounting from the contract.
  const { EVM } = await import('@ethereumjs/evm');
  const { Account, hexToBytes } = await import('@ethereumjs/util');

  const run = async (code) => {
    const evm = await EVM.create();
    await evm.stateManager.putAccount(chain.deployer, new Account(0n, 10n ** 24n));
    const r = await evm.runCall({
      data: hexToBytes(code), gasLimit: 500_000_000n,
      caller: chain.deployer, origin: chain.deployer,
    });
    assert(!r.execResult.exceptionError, `probe failed: ${code}`);
    return {
      gas: Number(r.execResult.executionGasUsed),
      runtime: r.execResult.returnValue.length,
    };
  };

  // PUSH1 0, PUSH1 0, RETURN -- deploys an empty runtime.
  const empty = await run('0x60006000f3');
  assertEq(empty.runtime, 0, 'the empty probe must deploy no runtime');
  // 6 gas is three 3-gas pushes/returns and nothing else. If G_txcreate were
  // charged inside execution this would be at least 32,000, and adding it in
  // deployCost would be double-counting.
  assert(empty.gas < 1_000,
    `an empty creation reports ${empty.gas} gas. G_txcreate (32,000) appears `
    + 'to be charged inside executionGasUsed after all -- deployCost adds it '
    + 'on top, so the published deployment figure is now 32,000 too high.');

  // PUSH1 32, PUSH1 0, RETURN -- deploys 32 bytes of runtime.
  const small = await run('0x60206000f3');
  assertEq(small.runtime, 32, 'the deposit probe must deploy 32 bytes');
  // The 200-gas-per-byte code deposit IS inside execution: 32 * 200 = 6,400.
  assert(small.gas - empty.gas >= 6_400,
    `depositing 32 bytes of runtime added only ${small.gas - empty.gas} gas, `
    + 'where 6,400 is the EIP-170 deposit price. If the deposit is NOT inside '
    + 'executionGasUsed then deployCost is understating every deployment by '
    + '200 gas per runtime byte -- about 4.8M for this contract.');
});

await test('report the runtime code size against EIP-170 -- 345 bytes to spare',
  async () => {
  // THE NEARER CLIFF, AND THE ONE NOTHING USED TO MENTION. The deployment has
  // 5.5x of headroom on gas. It has 1.4% on SIZE. A contract that cannot be
  // deployed at all is a worse failure than one that is expensive to deploy.
  //
  // THIS TEST ONLY REPORTS, AND THAT IS NOT A CHOICE OF STYLE. It cannot be
  // the assertion, because it cannot run when the assertion would be needed:
  // this file deploys a verifier at module scope, so a MobileCoinVerifier over
  // 24,576 bytes kills the whole suite at import with "code size to deposit
  // exceeds maximum code size" before the first test executes. Measured, by
  // padding the contract with 40 trivial external functions in an isolated
  // copy: verifier.mjs produced no summary at all.
  //
  // THE ASSERTION LIVES IN contracts/test/deployables.mjs, which reads the
  // runtime image out of the compiler and deploys nothing, so it still runs --
  // and turns red -- when the contract is over the limit. That file also
  // carries the note on what breaks and what the next change has to give up.
  const c = await deployCost(addrWord(REG) +
    b32(FIX.disclosure.recovered_subaddress_spend_key) + word(TOKEN_ID) +
    b32(MEMO_DOMAIN) + addrWord(realCheck));

  const headroom = EIP_170_LIMIT - c.runtimeBytes;
  console.log(`        runtime code: ${c.runtimeBytes.toLocaleString()} of `
    + `${EIP_170_LIMIT.toLocaleString()} bytes `
    + `(${(c.runtimeBytes / EIP_170_LIMIT * 100).toFixed(1)}%), `
    + `${headroom} bytes of headroom -- asserted in deployables.mjs`);

  // The init code has its own limit and a much wider margin, and unlike the
  // runtime limit this one CAN be asserted here: an over-3860 contract still
  // deploys on the ethereumjs EVM the suite runs, so this file survives to
  // report it.
  assert(c.initCodeBytes <= EIP_3860_LIMIT,
    `EIP-3860: ${c.initCodeBytes} bytes of init code exceeds ${EIP_3860_LIMIT}`);
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

await test('the memo binds chain, escrow and namespace; relay retagging is ineffective', async () => {
  const original = await callVerify(chain, V, good());
  assert(original.ok, 'honest domain control');
  const other = '0x' + 'd7'.repeat(32);
  const second = await deployVerifier(REG, realCheck, { memoDomain: other });
  assertRevertsWith(await callVerify(chain, second, mutate({ memoDomainTag: other })),
    'WrongMemoDomain(bytes32,bytes32)', 'namespace replay');
  const wrongCaller = await chain.call(V, encodeWithTrailingBytes(
    'verifyReturn(bytes)', [], '0x' + encodeProof(good())), { from: GOV });
  assertRevertsWith(wrongCaller, 'WrongMemoDomain(bytes32,bytes32)', 'escrow replay');
  const domain = await chain.must(V, selector('redemptionDomain(address)') + addrWord(FIXTURE_ESCROW));
  assertEq(domain.ret, FIX.disclosure.redemption_domain, 'Rust memo vs EVM domain');
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
  // is wrong". These go through AmountOpenerProbe_DO_NOT_DEPLOY, which exposes the library's
  // internal functions; the library itself is the one `verifyReturn` uses.
  const probe = await chain.deploy('AmountOpenerProbe_DO_NOT_DEPLOY');
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

await test('the constructor DERIVES MobileCoin\'s generators(tokenId) for every '
  + 'token id the oracle publishes', async () => {
  // What `eusdValueGenerator` used to be: an argument, vouched for by nothing
  // but a comment asking the deployer to compare two getters. It is now a
  // function of `eusdTokenId`, so this asserts a DERIVATION rather than that
  // immutables round-trip.
  //
  // Every id in the fixture, not only the one this scenario uses: the four
  // between them exercise both branches of the Elligator map and both settings
  // of the masked high bit, and a verifier deployed for eUSD's 8192 must derive
  // 8192's point on the same code path as this fixture's 1.
  assert(AMT.generators.byTokenId.length >= 4,
    'the oracle lost generators -- this test is weaker than it reads');
  for (const g of AMT.generators.byTokenId) {
    const v = await deployVerifier(REG, realCheck, { tokenId: BigInt(g.tokenId) });
    // The id is read back OFF THE CONTRACT rather than reused from the
    // deployment arguments. Sol pointed out that comparing the getter against
    // the same expression that was passed to the constructor establishes only
    // that immutables round-trip; going through `eusdTokenId()` makes the
    // fixture lookup a function of what the contract believes it accepts.
    const id = decodeUint((await chain.must(v, selector('eusdTokenId()'))).ret, 0);
    assertEq(id, BigInt(g.tokenId), 'the deployed token id');
    assertEq((await chain.must(v, selector('eusdValueGenerator()'))).ret,
      GENERATOR(id), `the derived B_token for token id ${g.tokenId}`);
  }

  // And the derivation is token-id specific, which is why a mispaired
  // deployment used to be dangerous: a different id is a different, orthogonal
  // point.
  for (const g of AMT.generators.byTokenId) {
    if (g.tokenId === String(TOKEN_ID)) continue;
    assert(g.bToken !== GENERATOR(TOKEN_ID),
      `generators for ${g.tokenId} and ${TOKEN_ID} collide`);
  }

  // B_blinding is NOT derived and NOT a parameter: MobileCoin's is the
  // ristretto255 basepoint, so the contract uses `Ristretto255.basepoint()` and
  // there is nothing to configure. If the oracle ever says otherwise, the
  // contract is wrong.
  //
  // READ OFF THE CONTRACT. This line used to compare two fields of amount.json
  // to each other, which no change to src/ could falsify -- coverage-shaped
  // and not coverage. `bBlinding()` evaluates `Ristretto255.basepoint()`, so
  // changing the library's basepoint constants turns it red (measured: it
  // does).
  //
  // WHAT IT STILL DOES NOT ESTABLISH: the probe names the same expression
  // `requireCommitment` names, it does not run `requireCommitment`. This pins
  // the VALUE, not the wiring. The wiring is pinned by the commitment tests
  // below -- MobileCoin formed those commitments over B_BLINDING, and they
  // only reproduce on chain if `requireCommitment` uses the same point.
  const probe = await chain.deploy('AmountOpenerProbe_DO_NOT_DEPLOY');
  assertEq((await chain.must(probe, selector('bBlinding()'))).ret,
    AMT.generators.bBlinding,
    'the contract\'s B_blinding is not MobileCoin\'s');
  assertEq(AMT.generators.bBlinding, AMT.generators.basepointCompressed,
    'ORACLE CHECK (not coverage): amount.json now disagrees with itself about '
    + 'the basepoint');
});

// THE CONSTRUCTOR-ARITY CHECK USED TO LIVE HERE, and could not do its job from
// here. It asserted that `_eusdValueGenerator` is gone, under a comment saying
// "Re-adding the argument turns this red" -- which was false for the mutation
// it names. This file deploys a verifier at module scope, so re-adding a sixth
// constructor argument makes `deployVerifier` pass five where six are wanted,
// the deployment reverts, and verifier.mjs and acceptance.mjs die at IMPORT.
// The named test never runs. It only fired once `deployVerifier` was also
// updated to pass the new argument -- that is, against a regression that had
// already been half-fixed.
//
// That is the identical defect this change diagnosed for EIP-170 and wrote up
// at length: a check that deploys before it measures is dead exactly when it is
// needed. It now lives in contracts/test/deployables.mjs, which reads the ABI
// out of the compiler and deploys nothing, so it survives the import death and
// turns red on the minimal mutation.

/// A verifier configured for one of amount.json's token ids, with a recipient
/// check that hands back a chosen shared secret. Used to drive `openAmount`
/// and `openMemo` -- the same functions `verifyReturn` calls -- over the
/// oracle's cases.
const openerFor = async (tokenId, secret) => {
  const rc = await chain.deploy('FixedSecretRecipient_DO_NOT_DEPLOY',
    b32(secret));
  return deployVerifier(REG, rc, { tokenId: BigInt(tokenId) });
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
  const probe = await chain.deploy('AmountOpenerProbe_DO_NOT_DEPLOY');
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
  // The commitment comparison, on the library `verifyReturn` calls, with the
  // block's own numbers: B_token for eUSD instead of B_token for this fixture's
  // token id 1. Deleting the comparison in AmountOpener turns this red.
  //
  // DRIVEN THROUGH THE PROBE, NOT A DEPLOYMENT, and that is a change worth
  // noting rather than hiding. This used to be a verifier deployed with a
  // mismatched generator -- which was possible only because the mismatch itself
  // was possible. The lever is gone with the argument; the check is not.
  const probe = await chain.deploy('AmountOpenerProbe_DO_NOT_DEPLOY');
  const openWith = (generator) => chain.call(probe,
    selector('openAmount(bytes32,bytes32,uint64,bytes,bytes32)') +
    b32(FIX.disclosure.shared_secret) +
    b32(FIX.tx_out.masked_amount.commitment) +
    word(BigInt(FIX.tx_out.masked_amount.masked_value)) +
    word(160) + b32(generator) +
    dynBytesArg(FIX.tx_out.masked_amount.masked_token_id));

  const r = await openWith(GENERATOR(8192));
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

  // The control: the generator the constructor derives for this token id opens
  // the same output. So the refusal above is the generator and nothing else.
  const ok = await openWith(GENERATOR(TOKEN_ID));
  assert(ok.ok, `the right generator must open it: ${errorOf(ok)}`);
  assertEq(decodeUint(ok.ret, 0), BigInt(FIX.expected.amount), 'the value');
  assertEq((await chain.must(V, selector('eusdValueGenerator()'))).ret,
    GENERATOR(TOKEN_ID),
    'and it is the one the deployed verifier derived for itself');
});

// ------------------- the two refusals in AmountOpener.decodeGenerator
//
// RESTORED COVERAGE, and worth saying why it needs restoring. The change that
// derived `B_token` on chain deleted `a verifier cannot be deployed with a
// generator that is not a point`, which was the only test that reached either
// refusal, and replaced it with nothing. Measured afterwards: deleting BOTH
// `revert InvalidValueGenerator` statements left the suite at 323 passed, 0
// failed. AmountOpener's own comment -- "The two refusals here are cheap and
// are kept: they are what makes a degenerate generator fail loudly rather than
// verify everything" -- was true of the code and unfalsifiable by the suite,
// and `InvalidValueGenerator(bytes32)` sat in the ERR table above with nothing
// producing it.
//
// The lever the old test used is gone with the constructor argument, so these
// go through `AmountOpenerProbe_DO_NOT_DEPLOY.decodeGenerator`, which is the
// library function itself and not a copy of it. One test per refusal, so a
// mutation names which one it broke.

await test('a value generator that is not a point is refused', async () => {
  // The `decode` refusal. Every encoding here is one curve25519-dalek itself
  // rejects -- tools/ristretto-fixtures asserts that on the Rust side before
  // writing the file -- so an implementation that accepted any of them would
  // be decoding something dalek says is not a ristretto point and then
  // committing amounts against it.
  const probe = await chain.deploy('AmountOpenerProbe_DO_NOT_DEPLOY');
  const decode = (enc) =>
    chain.call(probe, selector('decodeGenerator(bytes32)') + b32(enc));

  assert(RIS.rejects.length >= 10, 'the ristretto oracle lost its rejects');
  for (const [i, r] of RIS.rejects.entries()) {
    // The identity has its own refusal and its own test; it is not in this
    // list, but assert that rather than assume it.
    assert(BigInt(r.encoded) !== 0n, `rejects[${i}] is the identity`);
    const got = await decode(r.encoded);
    assertRevertsWith(got, 'InvalidValueGenerator(bytes32)',
      `rejects[${i}] ${r.encoded}`);
    // The error names the encoding it refused, so a deployer reading a failed
    // transaction can see WHICH bytes were wrong.
    assertEq('0x' + got.ret.slice(10), '0x' + b32(r.encoded),
      `rejects[${i}]: the error must carry the encoding`);
  }

  // The control. Every generator the oracle publishes decodes and re-encodes
  // to itself, so the refusals above are about those encodings and not about
  // `decodeGenerator` refusing everything -- which would also make the suite
  // green while breaking every deployment.
  for (const g of AMT.generators.byTokenId) {
    const ok = await chain.must(probe,
      selector('decodeGenerator(bytes32)') + b32(g.bToken));
    assertEq(ok.ret, g.bToken, `B_token for ${g.tokenId} must decode`);
  }
});

await test('the identity is refused as a value generator, because under it '
  + 'every amount verifies', async () => {
  // The other refusal, and the one that matters most: `bytes32(0)` is a
  // perfectly valid ristretto encoding, so `decode` accepts it. With
  // `B_token = 0` the commitment is `blinding*B_blinding` for EVERY value, so
  // the value stops being committed to and any amount opens. That is a silent
  // fail-open, not a wrong answer.
  const probe = await chain.deploy('AmountOpenerProbe_DO_NOT_DEPLOY');
  const IDENTITY = '0x' + '00'.repeat(32);

  const r = await chain.call(probe,
    selector('decodeGenerator(bytes32)') + b32(IDENTITY));
  assertRevertsWith(r, 'InvalidValueGenerator(bytes32)', 'the identity');
  assertEq('0x' + r.ret.slice(10), '0x' + b32(IDENTITY),
    'the error must carry the encoding it refused');

  // NOT VACUOUS, in the two senses that matter.
  //
  // First: `decode` ACCEPTS the identity. If it refused it, this guard would
  // be a restatement of the one above and deleting it would cost nothing.
  const ris = await chain.deploy('Ristretto255Probe_DO_NOT_DEPLOY');
  const decodes = await chain.must(ris,
    selector('decodes(bytes32)') + b32(IDENTITY));
  assertEq(decodeUint(decodes.ret, 0), 1n,
    'the identity must decode -- otherwise this refusal is dead weight and '
    + 'the comment explaining it is wrong');

  // Second: under B_token = 0 the value really does drop out. `[k]0 == 0` for
  // every k, so `value*B_token` is the identity whatever the value is, and the
  // commitment is `blinding*B_blinding` alone -- one point that opens to every
  // amount at once.
  for (const k of [1n, 250000000000n, (1n << 64n) - 1n]) {
    const kLE = b32('0x' + Buffer.from(
      k.toString(16).padStart(64, '0'), 'hex').reverse().toString('hex'));
    const r2 = await chain.must(ris,
      selector('mul(bytes32,bytes32)') + kLE + b32(IDENTITY));
    assertEq(decodeUint(r2.ret, 0), 1n, `mul by ${k} failed`);
    assertEq('0x' + r2.ret.slice(2).slice(64, 128), '0x' + b32(IDENTITY),
      `[${k}]0 must be the identity -- if it is not, the reason given for `
      + 'refusing B_token = 0 is not the real one');
  }
});

await test('THE MISPAIRING THAT USED TO VERIFY 250,000,000,000 IS NOW REFUSED, '
  + 'BY CONSTRUCTION', async () => {
  // What this test was. Sol's finding: `eusdValueGenerator` was an argument, so
  // deploying `(8192, generators(1).B)` produced a verifier that passed the
  // token-id check and then compared commitments in the WRONG group. The old
  // test asserted that such a deployment ACCEPTED a commitment MobileCoin
  // rejects as InconsistentCommitment, and paid out 250,000,000,000 for it.
  //
  // What it is now. 8192 is a token id a deployer could plausibly pair with the
  // wrong point -- it is eUSD's, and the point that used to sit next to it in a
  // deployment script belonged to token id 1. The witness is unchanged: the
  // same value and blinding, committed under B_1. A verifier deployed for 8192
  // now DERIVES B_8192 and refuses it, and no deployment argument can make it
  // do otherwise.
  // The witness is the oracle's 250,000 eUSD case -- the one the old test named
  // in its failure, selected by its value rather than by position so that a
  // reordered fixture fails here instead of quietly testing a value of 1.
  const c = AMT.maskedAmounts.find((x) => x.tokenId === '8192'
    && BigInt(x.value) === 250000000000n);
  assert(c, 'the oracle no longer publishes the 250,000,000,000 eUSD case');
  const probe = await chain.deploy('AmountOpenerProbe_DO_NOT_DEPLOY');

  // The same value and blinding, committed in the WRONG group.
  const wrong = (await chain.must(probe,
    selector('commitmentOf(uint64,bytes32,bytes32)') +
    word(BigInt(c.value)) + b32(c.blinding) + b32(GENERATOR(1)))).ret;
  assert(wrong !== c.commitment,
    'B_1 and B_8192 commit identically -- this test proves nothing');

  // A verifier for eUSD's token id. There is no second argument to get wrong.
  const v = await openerFor(8192, c.sharedSecret);
  assertEq((await chain.must(v, selector('eusdValueGenerator()'))).ret,
    GENERATOR(8192), 'the constructor derived B_8192');
  assert((await chain.must(v, selector('eusdValueGenerator()'))).ret
    !== GENERATOR(1),
    'B_1 and B_8192 are the same point -- this test proves nothing');

  // The forged commitment, which the mispaired deployment used to accept.
  const refused = await callOpenAmount(chain, v, c.sharedSecret,
    { ...amountTxOut(c), commitment: wrong });
  assertRevertsWith(refused, 'InconsistentCommitment(bytes32,bytes32)',
    'the mispairing must no longer verify');

  // And the honest commitment still opens on the same deployment, so the
  // refusal above is about the forged point and not about the verifier.
  const ok = await callOpenAmount(chain, v, c.sharedSecret, amountTxOut(c));
  assert(ok.ok, `the genuine 8192 amount must open: ${errorOf(ok)}`);
  assertEq(decodeUint(ok.ret, 0), BigInt(c.value), 'the genuine value');
  assertEq(decodeUint(ok.ret, 1), 8192n, 'under its own token id');
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

await test('legacy upstream memos remain decryptable but cannot authorize v2 payouts', async () => {
  const v = await deployVerifier(REG, realCheck);
  const probe = await chain.deploy('AmountOpenerProbe_DO_NOT_DEPLOY');
  for (const m of AMT.memos) {
    const raw = await chain.must(probe, encodeWithTrailingBytes(
      'openMemo(bytes32,bytes)', [b32(m.sharedSecret)], m.ciphertext));
    assertEq('0x' + raw.ret.slice(2,6), m.memoType, 'upstream type');
    assertEq('0x' + raw.ret.slice(90,130), m.beneficiary, 'upstream beneficiary');
    assertRevertsWith(await callOpenMemo(chain, v, m.sharedSecret, m.ciphertext),
      'WrongMemoType(bytes2,bytes2)', m.name);
  }
  assert(AMT.memos.length >= 4, 'oracle coverage');
});

await test('v2 memo refuses legacy type, nonzero reserved bytes, wrong domain and zero payee', async () => {
  const v = await deployVerifier(REG, realCheck);
  // CTR bit changes yield precisely chosen plaintext changes. These isolated
  // opener controls do not claim altered ciphertext retains a block signature.
  const edit = (start, bytes) => {
    const ct = Buffer.from(FIX.tx_out.e_memo.slice(2), 'hex');
    const pt = Buffer.from(FIX.disclosure.memo_type.slice(2) + FIX.disclosure.memo_data.slice(2), 'hex');
    for (let i=0;i<bytes.length;i++) ct[start+i] ^= pt[start+i] ^ bytes[i];
    return '0x'+ct.toString('hex');
  };
  for (const [start, bytes, error] of [
    [0, [0x80, 1], 'WrongMemoType(bytes2,bytes2)'],
    [22, Array(32).fill(0), 'WrongMemoDomain(bytes32,bytes32)'],
    [54, [1], 'NonzeroMemoReserved(bytes12)'],
    [65, [1], 'NonzeroMemoReserved(bytes12)'],
    [2, Array(20).fill(0), 'ZeroBeneficiary()'],
  ]) assertRevertsWith(await callOpenMemo(chain, v, FIX.disclosure.shared_secret, edit(start, bytes)), error, error);
  assert((await callOpenMemo(chain, v, FIX.disclosure.shared_secret, FIX.tx_out.e_memo)).ok, 'honest retry');
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
