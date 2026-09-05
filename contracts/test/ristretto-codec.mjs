// Direct RFC vectors plus independent codec/group properties. The raw-point
// tests deliberately avoid decode->encode: decode produces a restricted
// representative, so round trips alone can leave encode's rotation uncovered.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Chain, selector, b32, word, test, assert, assertEq, decodeBool, summary,
} from './harness.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(HERE,
  'fixtures/ristretto-codec-noble.json'), 'utf8'));
const chain = await Chain.create({ only: ['Ristretto255.sol'] });
const probe = await chain.deploy('Ristretto255Probe_DO_NOT_DEPLOY');
const call = (sig, args) => chain.must(probe, selector(sig) + args);

// RFC 9496 Appendix A.2, complete and in its published category order:
// https://www.rfc-editor.org/rfc/rfc9496.html#appendix-A.2
// These are specification vectors, not a family derived by this repository.
const RFC_REJECTS = [
  ['non-canonical', [
    '00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  ]],
  ['negative s', [
    '0100000000000000000000000000000000000000000000000000000000000000',
    '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20',
    'c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562',
    'c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78',
    '47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24',
    'f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72',
    '87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309',
  ]],
  ['non-square', [
    '26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371',
    '4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f',
    'de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b',
    'bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042',
    '2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08',
    'f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22',
    '8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731',
    '2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b',
  ]],
  ['negative t', [
    '3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e',
    'a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220',
    'd483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e',
    '8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32',
    '32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b',
    '227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165',
    '5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e',
    '445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b',
  ]],
  ['zero y', [
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  ]],
];

for (const [category, encodings] of RFC_REJECTS) {
  await test(`RFC 9496 A.2 rejects every ${category} vector`, async () => {
    for (const enc of encodings) {
      assertEq(enc.length, 64, 'transcribed RFC vector width');
      const r = await call('decodes(bytes32)', enc);
      assert(!decodeBool(r.ret), `RFC ${category}: accepted ${enc}`);
    }
  });
}

await test('decoder agrees with noble on 352 arbitrary, boundary and valid encodings',
  async () => {
    assertEq(V.decode.length, 352, 'independent corpus size');
    let accepted = 0;
    for (const c of V.decode) {
      const r = await call('reencode(bytes32)', b32(c.encoded));
      assertEq(decodeBool(r.ret), c.ok, `decode ${c.encoded}`);
      if (c.ok) {
        ++accepted;
        assertEq('0x' + r.ret.slice(66, 130), c.roundTrip,
          `canonical re-encoding ${c.encoded}`);
        assertEq(c.roundTrip, c.encoded, 'oracle round trip');
      }
    }
    assert(accepted >= 32 && accepted < V.decode.length / 2,
      `both success and rejection must be exercised: ${accepted} accepted`);
  });

const P = (1n << 255n) - 19n;
const mod = (v) => ((v % P) + P) % P;
const I = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

await test('all four torsion-equivalent representatives and projective rescalings encode identically',
  async () => {
    assertEq(V.representatives.length, 10, 'representative corpus size');
    for (const c of V.representatives) {
      const [x, y, z, t] = c.coordinates.map(BigInt);
      // Add each point in the order-four Edwards subgroup. The addition
      // formula simplifies to these transforms for (0,+/-1), (+/-i,0).
      const reps = [
        [x, y, z, t], [mod(-x), mod(-y), z, t],
        [mod(I * y), mod(I * x), z, mod(-t)],
        [mod(-I * y), mod(-I * x), z, mod(-t)],
      ];
      for (const rep of reps) for (const scale of [1n, 2n, P - 1n, P - 2n]) {
        const q = rep.map((v) => mod(v * scale));
        const [X, Y, Z, T] = q;
        assert(Z !== 0n, 'invalid projective input');
        assertEq(mod(X * Y - Z * T), 0n, 'extended-coordinate identity');
        assertEq(mod((Y * Y - X * X) * Z * Z - Z ** 4n - D * X * X * Y * Y),
          0n, 'Edwards curve identity');
        const r = await call('encodeCoordinates(uint256,uint256,uint256,uint256)',
          q.map(word).join(''));
        assertEq(r.ret, c.encoded, `coset ${c.encoded}, scale ${scale}, rep ${rep}`);
      }
    }
  });

await test('addition, subtraction and multiplication agree with independent arbitrary-point vectors',
  async () => {
    assertEq(V.algebra.length, 12, 'algebra corpus size');
    for (const c of V.algebra) {
      for (const [signature, args, want] of [
        ['add(bytes32,bytes32)', b32(c.p) + b32(c.q), c.sum],
        ['sub(bytes32,bytes32)', b32(c.p) + b32(c.q), c.difference],
        ['mul(bytes32,bytes32)', b32(c.scalar) + b32(c.p), c.product],
      ]) {
        const r = await call(signature, args);
        assert(decodeBool(r.ret), `${signature}: valid input refused`);
        assertEq('0x' + r.ret.slice(66, 130), want, `${signature} of ${c.p}`);
      }
    }
  });

summary();
