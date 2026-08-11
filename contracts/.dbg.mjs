import { Chain, selector, word, dynBytes } from './test/harness.mjs';
const chain = await Chain.create({ only: ['Keccak1600.sol', 'Merlin.sol'] });
const mp = await chain.deploy('MerlinProbe');
const enc1 = (sig, a) => selector(sig) + word(32) + dynBytes(a);
for (const [sig, arg] of [['dbg1(bytes)', '74657374'], ['dbg2(bytes)', '74657374']]) {
  const r = await chain.call(mp, enc1(sig, arg), { gasLimit: 200000000n });
  console.log(sig, r.ok, r.error, r.gas, r.ret.slice(0, 200));
}
const r3 = await chain.call(mp, selector('dbg3()'), { gasLimit: 200000000n });
console.log('dbg3', r3.ok, r3.error, r3.ret.slice(0,200));
