import { Chain, selector } from './test/harness.mjs';
const chain = await Chain.create({ only: ['Keccak1600.sol', 'Merlin.sol'] });
const kp = await chain.deploy('Keccak1600Probe');
for (const f of ['dbgU()', 'dbgB()']) {
  const r = await chain.call(kp, selector(f), { gasLimit: 200000000n });
  console.log('kp', f, r.ok, r.error, r.ret.slice(0, 200));
}
