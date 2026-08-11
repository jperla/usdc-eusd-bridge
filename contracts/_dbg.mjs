import { Chain, selector, b32, word, encodeWithTrailingBytes, decodeUint } from './test/harness.mjs';
import { createHash } from 'crypto';
const chain = await Chain.create();
const at = await chain.deploy('Ed25519Verifier');
for (const m of ['', '22', '2233']) {
  const r = await chain.call(at, encodeWithTrailingBytes('dbgPack(bytes32,bytes32,bytes)', [b32('00'.repeat(32)), b32('11'.repeat(32))], m));
  const want = createHash('sha512').update(Buffer.from('00'.repeat(32)+'11'.repeat(32)+m,'hex')).digest('hex');
  console.log('pack', JSON.stringify(m), r.ok, r.error, r.ok ? decodeUint(r.ret,0) : '', r.ok ? (r.ret.slice(2+64,2+192)===want) : '');
}
const r2 = await chain.call(at, selector('dbgLe(bytes32)') + b32('01'+'00'.repeat(31)));
console.log('le', r2.ok, r2.error, r2.ok && decodeUint(r2.ret).toString(16));
