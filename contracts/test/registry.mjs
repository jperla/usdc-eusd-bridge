// ValidatorRegistry tests.
//
// This contract is the trust root of the return leg: whoever controls it can
// mint arbitrary MobileCoin "returns". The tests target the ways a quorum
// could be faked.
//
// The headline case is the one that motivated the design. MobileCoin's cheap
// proof route (`BlockSignature`) is signed with a PER-ENCLAVE identity key,
// not the node's SCP message key that defines its NodeID. So several keys can
// belong to one validator entity, and counting keys instead of entities lets
// one operator satisfy any threshold alone.

import {
  Chain, selector, word, addrWord, b32, decodeBool, decodeUint,
  test, assert, assertEq, summary, revertReason,
} from './harness.mjs';

const GOV = '0x' + '11'.repeat(20);
const MALLORY = '0x' + 'ee'.repeat(20);
const DELAY = 0n;            // 0 so enrollment is testable in one block
const H = 1000n;             // a block height inside every enrolled range

const K = (n) => '0x' + n.toString(16).padStart(2, '0').repeat(32);
const E = (n) => '0x' + ('e' + n.toString(16).padStart(1, '0')).repeat(32);

const dynB32Array = (arr) => word(arr.length) + arr.map((k) => b32(k)).join('');

async function fresh(chain, { threshold = 3n, delay = DELAY } = {}) {
  return chain.deploy('ValidatorRegistry',
    addrWord(GOV) + word(threshold) + word(delay));
}

async function enroll(chain, reg, key, entity, from = 0n, to = 0n) {
  const args = b32(key) + b32(entity) + word(from) + word(to);
  await chain.must(reg, selector('proposeKey(bytes32,bytes32,uint64,uint64)') + args, { from: GOV });
  await chain.must(reg, selector('enrollKey(bytes32,bytes32,uint64,uint64)') + args, { from: GOV });
}

const isQuorum = async (chain, reg, keys, height = H) => {
  const data = selector('isQuorum(bytes32[],uint64)') + word(64) + word(height) + dynB32Array(keys);
  const r = await chain.call(reg, data);
  assert(r.ok, `isQuorum reverted: ${revertReason(r.ret)}`);
  return decodeBool(r.ret);
};

/// Order keys by the entity they map to, as isQuorum requires.
const byEntity = (pairs) => pairs.slice()
  .sort((a, b) => (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
  .map((p) => p[0]);

const chain = await Chain.create({ only: ['ValidatorRegistry.sol'] });

console.log('\nValidatorRegistry');

// ------------------------------------------------------- the entity property

await test('THREE keys from ONE entity are not a quorum', async () => {
  // The defect this contract exists to prevent. A single operator running
  // three enclaves holds three perfectly valid signing keys.
  const reg = await fresh(chain);
  await enroll(chain, reg, K(1), E(1));
  await enroll(chain, reg, K(2), E(1));
  await enroll(chain, reg, K(3), E(1));
  assert(!(await isQuorum(chain, reg, [K(1), K(2), K(3)])),
    'three keys of one entity must not be a quorum');
});

await test('three keys from three entities are a quorum', async () => {
  const reg = await fresh(chain);
  const pairs = [[K(1), E(1)], [K(2), E(2)], [K(3), E(3)]];
  for (const [k, e] of pairs) await enroll(chain, reg, k, e);
  assert(await isQuorum(chain, reg, byEntity(pairs)), 'should be a quorum');
});

await test('two entities plus a second key of one of them is still not a quorum', async () => {
  const reg = await fresh(chain);
  const pairs = [[K(1), E(1)], [K(2), E(2)], [K(3), E(2)]];
  for (const [k, e] of pairs) await enroll(chain, reg, k, e);
  assert(!(await isQuorum(chain, reg, byEntity(pairs))),
    'a padded second key must not lift two entities to three');
});

// ------------------------------------------------------------ height scoping

await test('a key is rejected outside the height range it was enrolled for', async () => {
  const reg = await fresh(chain, { threshold: 1n });
  await enroll(chain, reg, K(1), E(1), 500n, 900n);
  assert(await isQuorum(chain, reg, [K(1)], 600n), 'inside range');
  assert(!(await isQuorum(chain, reg, [K(1)], 400n)), 'before range');
  assert(!(await isQuorum(chain, reg, [K(1)], 900n)), 'toHeight is exclusive');
  assert(!(await isQuorum(chain, reg, [K(1)], 1500n)), 'after range');
});

await test('a rotation cannot be counted twice across its own boundary', async () => {
  // Same entity, an old key and its replacement, ranges abutting. At any
  // single height only one is valid, and both map to one entity anyway.
  const reg = await fresh(chain, { threshold: 2n });
  await enroll(chain, reg, K(1), E(1), 0n, 1000n);
  await enroll(chain, reg, K(2), E(1), 1000n, 0n);
  assert(!(await isQuorum(chain, reg, [K(1), K(2)], 999n)), 'at 999');
  assert(!(await isQuorum(chain, reg, [K(1), K(2)], 1000n)), 'at 1000');
});

// -------------------------------------------------------------- basic checks

await test('fewer keys than the threshold is not a quorum', async () => {
  const reg = await fresh(chain);
  const pairs = [[K(1), E(1)], [K(2), E(2)]];
  for (const [k, e] of pairs) await enroll(chain, reg, k, e);
  assert(!(await isQuorum(chain, reg, byEntity(pairs))), 'two of three');
});

await test('an unenrolled key never counts, even beside real ones', async () => {
  const reg = await fresh(chain);
  const pairs = [[K(1), E(1)], [K(2), E(2)]];
  for (const [k, e] of pairs) await enroll(chain, reg, k, e);
  assert(!(await isQuorum(chain, reg, [K(1), K(2), K(9)])), 'unenrolled key');
});

await test('a revoked key stops counting immediately', async () => {
  const reg = await fresh(chain);
  const pairs = [[K(1), E(1)], [K(2), E(2)], [K(3), E(3)]];
  for (const [k, e] of pairs) await enroll(chain, reg, k, e);
  const ordered = byEntity(pairs);
  assert(await isQuorum(chain, reg, ordered), 'quorum before revocation');
  await chain.must(reg, selector('revokeKey(bytes32)') + b32(K(2)), { from: GOV });
  assert(!(await isQuorum(chain, reg, ordered)), 'quorum must break after revocation');
});

await test('a list not ordered by entity is rejected rather than silently accepted', async () => {
  const reg = await fresh(chain);
  const pairs = [[K(1), E(1)], [K(2), E(2)], [K(3), E(3)]];
  for (const [k, e] of pairs) await enroll(chain, reg, k, e);
  const desc = byEntity(pairs).reverse();
  assert(!(await isQuorum(chain, reg, desc)), 'descending must be rejected');
});

// ------------------------------------------------------------- authorisation

await test('enrollment requires a proposal first', async () => {
  const reg = await fresh(chain);
  const args = b32(K(1)) + b32(E(1)) + word(0) + word(0);
  assert(!(await chain.call(reg,
    selector('enrollKey(bytes32,bytes32,uint64,uint64)') + args, { from: GOV })).ok,
    'enroll without propose must revert');
});

await test('the timelock is enforced when there is a delay', async () => {
  const reg = await fresh(chain, { delay: 3600n });
  const args = b32(K(1)) + b32(E(1)) + word(0) + word(0);
  await chain.must(reg, selector('proposeKey(bytes32,bytes32,uint64,uint64)') + args, { from: GOV });
  assert(!(await chain.call(reg,
    selector('enrollKey(bytes32,bytes32,uint64,uint64)') + args, { from: GOV })).ok,
    'enroll before the delay must revert');
});

await test('only governance can propose, enroll, revoke or retune', async () => {
  const reg = await fresh(chain);
  const args = b32(K(1)) + b32(E(1)) + word(0) + word(0);
  for (const [sig, arg] of [
    ['proposeKey(bytes32,bytes32,uint64,uint64)', args],
    ['enrollKey(bytes32,bytes32,uint64,uint64)', args],
    ['revokeKey(bytes32)', b32(K(1))],
    ['setThreshold(uint8)', word(1)],
    ['transferGovernance(address)', addrWord(MALLORY)],
  ]) {
    assert(!(await chain.call(reg, selector(sig) + arg, { from: MALLORY })).ok,
      `${sig} must reject non-governance`);
  }
});

await test('the threshold cannot exceed the number of known entities', async () => {
  const reg = await fresh(chain);
  await enroll(chain, reg, K(1), E(1));
  assert(!(await chain.call(reg, selector('setThreshold(uint8)') + word(2), { from: GOV })).ok,
    'threshold above entity count');
  assert((await chain.call(reg, selector('setThreshold(uint8)') + word(1), { from: GOV })).ok,
    'threshold equal to entity count is fine');
  assert(!(await chain.call(reg, selector('setThreshold(uint8)') + word(0), { from: GOV })).ok,
    'zero threshold');
});

await test('a key cannot be enrolled twice, and an inverted height range is rejected', async () => {
  const reg = await fresh(chain);
  await enroll(chain, reg, K(1), E(1));
  const args = b32(K(1)) + b32(E(1)) + word(0) + word(0);
  assert(!(await chain.call(reg,
    selector('proposeKey(bytes32,bytes32,uint64,uint64)') + args, { from: GOV })).ok,
    're-enrolling an existing key must revert');

  const bad = b32(K(7)) + b32(E(7)) + word(900) + word(500);
  assert(!(await chain.call(reg,
    selector('proposeKey(bytes32,bytes32,uint64,uint64)') + bad, { from: GOV })).ok,
    'toHeight <= fromHeight must revert');
});

await test('a zero entity is rejected, so an unenrolled key cannot masquerade as entity 0', async () => {
  const reg = await fresh(chain);
  const args = b32(K(1)) + b32('0x' + '00'.repeat(32)) + word(0) + word(0);
  assert(!(await chain.call(reg,
    selector('proposeKey(bytes32,bytes32,uint64,uint64)') + args, { from: GOV })).ok,
    'zero entity must revert');
});

summary();
