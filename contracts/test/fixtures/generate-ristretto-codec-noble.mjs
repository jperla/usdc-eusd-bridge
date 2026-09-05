// Regenerate the independent codec/algebra oracle. Like generate-ristretto-
// noble.mjs, this uses the pinned transitive dependency only at generation
// time; normal tests read the committed JSON and never repair expectations.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RistrettoPoint } from '@noble/curves/ed25519';

const HERE = dirname(fileURLToPath(import.meta.url));
const version = JSON.parse(readFileSync(join(HERE,
  '../../node_modules/@noble/curves/package.json'), 'utf8')).version;
if (version !== '1.9.7') throw new Error(`review oracle change: noble ${version}`);
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const hex = (bytes) => '0x' + Buffer.from(bytes).toString('hex');
const le = (n) => hex(Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse());
const scalar = (bytes) => BigInt(hex(Buffer.from(bytes).reverse())) % L;
const stream = (label, i) => createHash('sha512')
  .update(`bridge-ristretto-codec-v1:${label}:${i}`).digest();
const raw = (point) => {
  const { x, y } = point.toAffine();
  return [x.toString(), y.toString(), '1', (x * y % P).toString()];
};

const inputs = new Set();
for (let i = 0; i < 256; ++i) inputs.add(hex(stream('decode', i).subarray(0, 32)));
for (let i = -32n; i < 32n; ++i) inputs.add(le(P + i));
for (let i = 0; i < 32; ++i)
  inputs.add(hex(RistrettoPoint.hashToCurve(stream('valid', i)).toRawBytes()));
const decode = [...inputs].map((encoded) => {
  try {
    const p = RistrettoPoint.fromHex(encoded.slice(2));
    return { encoded, ok: true, roundTrip: hex(p.toRawBytes()) };
  } catch { return { encoded, ok: false }; }
});

const representatives = [RistrettoPoint.ZERO, RistrettoPoint.BASE];
for (let i = 0; i < 8; ++i)
  representatives.push(RistrettoPoint.hashToCurve(stream('point', i)));
const algebra = Array.from({ length: 12 }, (_, i) => {
  const p = RistrettoPoint.hashToCurve(stream('algebra-p', i));
  const q = RistrettoPoint.hashToCurve(stream('algebra-q', i));
  const k = i === 0 ? 0n : i === 1 ? L - 1n : scalar(stream('scalar', i));
  return {
    p: hex(p.toRawBytes()), q: hex(q.toRawBytes()), scalar: le(k),
    sum: hex(p.add(q).toRawBytes()), difference: hex(p.subtract(q).toRawBytes()),
    product: hex((k === 0n ? RistrettoPoint.ZERO : p.multiply(k)).toRawBytes()),
  };
});
const fixture = {
  _header: {
    source: `@noble/curves ${version}, RistrettoPoint`,
    regenerate: 'node contracts/test/fixtures/generate-ristretto-codec-noble.mjs',
    determinism: 'SHA-512 of bridge-ristretto-codec-v1:<label>:<decimal index>',
    limitation: 'Finite differential evidence; not a proof over the whole group.',
  },
  decode,
  representatives: representatives.map((p) => ({
    encoded: hex(p.toRawBytes()), coordinates: raw(p),
  })),
  algebra,
};
writeFileSync(join(HERE, 'ristretto-codec-noble.json'),
  JSON.stringify(fixture, null, 2) + '\n');
console.log(`wrote ${decode.length} codec cases, ${representatives.length} `
  + `representatives and ${algebra.length} algebra cases`);
