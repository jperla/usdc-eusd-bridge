// ValidatorRegistry tests.
//
// This contract is the trust root of the whole return leg: whoever controls it
// can mint arbitrary MobileCoin "returns". So the tests are about the things
// that would let someone bypass it -- duplicate keys counted as a quorum, a
// rotation landing without its timelock, a threshold left above the roster.

import {
  Chain, selector, word, addrWord, b32, decodeUint, decodeBool,
  test, assert, assertEq, summary, revertReason,
} from './harness.mjs';

const GOV = '0x' + '11'.repeat(20);
const MALLORY = '0x' + 'ee'.repeat(20);
const DELAY = 3600n;

const K = (n) => '0x' + n.toString(16).padStart(2, '0').repeat(32);
// Sorted ascending, as isQuorum requires.
const KEYS = [K(1), K(2), K(3), K(4), K(5)];

/// bytes32[] as a constructor arg: dynamic, so head is an offset.
const dynB32Array = (arr) => word(arr.length) + arr.map((k) => b32(k)).join('');

async function fixture(chain, { keys = KEYS, threshold = 3n, delay = DELAY } = {}) {
  // constructor(address, bytes32[] memory, uint8, uint64)
  const head = addrWord(GOV) + word(4 * 32) + word(threshold) + word(delay);
  return chain.deploy('ValidatorRegistry', head + dynB32Array(keys));
}

const isQuorum = async (chain, reg, keys) => {
  const data = selector('isQuorum(bytes32[])') + word(32) + dynB32Array(keys);
  const r = await chain.call(reg, data);
  assert(r.ok, `isQuorum reverted: ${revertReason(r.ret)}`);
  return decodeBool(r.ret);
};

const chain = await Chain.create();

console.log('\nValidatorRegistry');

await test('a threshold-sized set of distinct registered keys is a quorum', async () => {
  const reg = await fixture(chain);
  assert(await isQuorum(chain, reg, [KEYS[0], KEYS[1], KEYS[2]]), 'should be quorum');
  assert(await isQuorum(chain, reg, KEYS), 'full set should be quorum');
});

await test('fewer than threshold is not a quorum', async () => {
  const reg = await fixture(chain);
  assert(!(await isQuorum(chain, reg, [KEYS[0], KEYS[1]])), 'two of three');
});

await test('ONE key repeated is not a quorum', async () => {
  // Without the distinctness check this is the cheapest possible forgery: a
  // single compromised validator signs the same digest three times.
  const reg = await fixture(chain);
  assert(!(await isQuorum(chain, reg, [KEYS[0], KEYS[0], KEYS[0]])), 'repeats');
});

await test('an unregistered key never counts, even alongside real ones', async () => {
  const reg = await fixture(chain);
  const fake = K(0xaa);
  assert(!(await isQuorum(chain, reg, [KEYS[0], KEYS[1], fake].sort())), 'fake key');
});

await test('an unsorted set is rejected rather than silently accepted', async () => {
  const reg = await fixture(chain);
  assert(!(await isQuorum(chain, reg, [KEYS[2], KEYS[1], KEYS[0]])), 'descending');
});

await test('rotation requires a proposal AND the timelock to elapse', async () => {
  const reg = await fixture(chain);
  const nk = K(0x7f);

  // Execute without proposing.
  assert(!(await chain.call(reg,
    selector('execute(bytes32,bool)') + b32(nk) + word(1), { from: GOV })).ok,
    'execute without propose must revert');

  assert((await chain.call(reg,
    selector('propose(bytes32,bool)') + b32(nk) + word(1), { from: GOV })).ok,
    'propose should succeed');

  // Still inside the delay: ethereumjs keeps block.timestamp fixed here, so
  // this asserts the timelock is enforced at all rather than that time passes.
  assert(!(await chain.call(reg,
    selector('execute(bytes32,bool)') + b32(nk) + word(1), { from: GOV })).ok,
    'execute before delay must revert');
});

await test('only governance can propose, execute or change the threshold', async () => {
  const reg = await fixture(chain);
  const nk = K(0x7e);
  for (const [sig, arg] of [
    ['propose(bytes32,bool)', b32(nk) + word(1)],
    ['execute(bytes32,bool)', b32(nk) + word(1)],
    ['setThreshold(uint8)', word(2)],
    ['transferGovernance(address)', addrWord(MALLORY)],
  ]) {
    assert(!(await chain.call(reg, selector(sig) + arg, { from: MALLORY })).ok,
      `${sig} must reject non-governance`);
  }
});

await test('the threshold cannot be set to zero or above the roster', async () => {
  const reg = await fixture(chain);
  assert(!(await chain.call(reg, selector('setThreshold(uint8)') + word(0), { from: GOV })).ok,
    'zero threshold');
  assert(!(await chain.call(reg, selector('setThreshold(uint8)') + word(99), { from: GOV })).ok,
    'threshold above roster');
  assert((await chain.call(reg, selector('setThreshold(uint8)') + word(5), { from: GOV })).ok,
    'threshold equal to roster is fine');
});

await test('a registry cannot be constructed with an impossible threshold', async () => {
  let threw = false;
  try {
    await fixture(chain, { threshold: 9n });
  } catch (e) { threw = true; }
  assert(threw, 'constructing with threshold > roster must revert');
});

await test('duplicate keys cannot be registered at construction', async () => {
  let threw = false;
  try {
    await fixture(chain, { keys: [K(1), K(1), K(2)], threshold: 2n });
  } catch (e) { threw = true; }
  assert(threw, 'duplicate initial validators must revert');
});

summary();
