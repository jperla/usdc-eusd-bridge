// Component integration: actual Escrow log -> real Rust auditor decision ->
// Escrow.freeze -> blocked payout. Release records, token and return verifier
// are fixtures/mocks; this does not claim live-chain or full-bridge coverage.
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Chain, selector, word, addrWord, b32, dynBytes, decodeUint, decodeBool,
  assert, assertEq,
} from '../contracts/test/harness.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const TC_ROOT = join(homedir(), '.rustup/toolchains');
const pinned = existsSync(TC_ROOT)
  ? readdirSync(TC_ROOT).find((s) => s.startsWith('nightly-2024-10-11-')) : undefined;
const env = { ...process.env };
if (pinned) env.PATH = join(TC_ROOT, pinned, 'bin') + ':' + env.PATH;
const cargo = process.env.BRIDGE_CARGO || 'cargo';
// Compile once, then run the executable Cargo actually produced. Re-running
// `cargo run` for each decision reacquires the build lock and can stall the
// handoff behind unrelated compilation. Cargo's artifact path also respects
// CARGO_TARGET_DIR without guessing where the binary lives.
const build = spawnSync(cargo,
  ['build', '--offline', '--locked', '--message-format=json', '-p', 'e2e', '--bin', 'auditor-decision'],
  { cwd: ROOT, env, encoding: 'utf8', timeout: 600_000, maxBuffer: 16 * 1024 * 1024 });
if (build.error || build.status !== 0)
  throw new Error(`Rust auditor build failed (${build.status}): ${build.error || build.stderr}`);
const artifact = build.stdout.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
  .find((item) => item.reason === 'compiler-artifact'
    && item.target?.name === 'auditor-decision' && item.executable);
assert(artifact, 'Cargo must report the freshly built auditor-decision executable');
const invokeAuditor = (input) => {
  const result = spawnSync(artifact.executable, [],
    { cwd: ROOT, env, input: JSON.stringify(input), encoding: 'utf8', timeout: 30_000 });
  if (result.error || result.status !== 0)
    throw new Error(`Rust auditor did not run (${result.status}): ${result.error || result.stderr}`);
  return JSON.parse(result.stdout);
};

const GOV = '0x' + '11'.repeat(20);
const AUDITOR = '0x' + '22'.repeat(20);
const USER = '0x' + '33'.repeat(20);
const PAYEE = '0x' + '44'.repeat(20);
const DEST = '0x' + '55'.repeat(32);
const AMOUNT = 50_000_000n;
const chain = await Chain.create({ only: ['Escrow.sol', 'TestMocks.sol'] });
const token = await chain.deploy('MockERC20');
const verifier = await chain.deploy('MockVerifier');
const escrow = await chain.deploy('Escrow', addrWord(token) + addrWord(verifier)
  + word(8192) + word(AMOUNT) + addrWord(GOV) + addrWord(AUDITOR) + word(60));
const balance = async (address) => decodeUint((await chain.must(token,
  selector('balanceOf(address)') + addrWord(address))).ret);
const frozen = async () => decodeBool((await chain.must(escrow, selector('frozen()'))).ret);
await chain.must(token, selector('mint(address,uint256)') + addrWord(USER) + word(AMOUNT));
await chain.must(token, selector('approve(address,uint256)') + addrWord(escrow) + word(AMOUNT),
  { from: USER });
const depositTx = await chain.must(escrow, selector('deposit(uint256,bytes32)')
  + word(AMOUNT) + b32(DEST), { from: USER });
assertEq(depositTx.logs.length, 1, 'one actual Deposited log');
const log = depositTx.logs[0];
assertEq(log.topics.length, 4, 'Deposited indexed fields');
// Full keccak256("Deposited(uint256,address,uint256,bytes32)").
assertEq(log.topics[0], '0x7b3f420dafb58e077d56c4160850ae727d598bf03fd39b4e4113e31d43e1fe37',
  'Deposited event signature');
assertEq(log.data.length, 66, 'one non-indexed amount word');
const depositId = BigInt(log.topics[1]);
assert(depositId <= BigInt(Number.MAX_SAFE_INTEGER), 'adapter refuses lossy deposit ids');
const stored = await chain.must(escrow, selector('deposits(uint256)') + word(depositId));
const timestamp = decodeUint(stored.ret, 3);
assert(timestamp <= BigInt(Number.MAX_SAFE_INTEGER), 'adapter refuses lossy timestamps');
const deposit = {
  deposit_id: Number(depositId), depositor: '0x' + log.topics[2].slice(-40),
  amount: decodeUint(log.data).toString(), mob_destination: log.topics[3],
  // runCall's default block has height zero; timestamp is read from the
  // contract's stored deposit. No live finality is inferred from this context.
  block_number: 0, log_index: 0, timestamp: Number(timestamp),
};
assertEq(deposit.amount, AMOUNT.toString(), 'decoded deposited value');
assertEq(deposit.depositor, USER, 'decoded depositor');
assertEq(deposit.mob_destination, DEST, 'decoded destination');
assertEq(await balance(escrow), AMOUNT, 'deposit actually moved tokens');
const seconds = (secs) => ({ secs, nanos: 0 });
const request = {
  deposits: [deposit], releases: [], now: 2,
  policy: {
    matching: { clock_skew_tolerance: seconds(600), stale_deposit_after: seconds(3600) },
    bound: {
      remaining_balance: (await balance(escrow)).toString(),
      rho: { max_amount: AMOUNT.toString(), window: seconds(60) },
      delta_eff: seconds(60), recall_horizon: seconds(0),
    },
    freeze_on_anomaly: true,
  },
};
const honest = {
  release_id: '0x' + '66'.repeat(32), claimed_deposit_id: deposit.deposit_id,
  amount: deposit.amount, mob_destination: deposit.mob_destination,
  block_index: 1, timestamp: 1,
};
const clean = invokeAuditor({ ...request, releases: [honest] });
assertEq(clean.decision.Continue.stats.matched, 1, 'actual audit matches the decoded log');
assertEq(clean.escrow_reason, null, 'Continue has no freeze calldata');
assert(!(await frozen()), 'clean audit leaves escrow unfrozen');
console.log('PASS actual Deposited log reaches Rust auditor and matching release continues');

const double = invokeAuditor({ ...request, releases: [honest,
  { ...honest, release_id: '0x' + '77'.repeat(32), block_index: 2 }] });
assertEq(double.decision.Freeze.reason, 'DoubleRelease', 'second issuance freezes');
assert(double.escrow_reason.startsWith('auditor/double-release '), 'auditor double-release reason');
const rogue = invokeAuditor({ ...request, releases: [
  { ...honest, claimed_deposit_id: null }] });
assertEq(rogue.decision.Freeze.reason, 'UnbackedRelease', 'unbacked issuance freezes');
assert(rogue.escrow_reason.startsWith('auditor/unbacked-release '), 'auditor unbacked reason');
console.log('PASS real auditor identifies double and unbacked MobileCoin release records');

const reasonHex = Buffer.from(rogue.escrow_reason).toString('hex');
const freezeCall = selector('freeze(string)') + word(32) + dynBytes(reasonHex);
const unauthorized = await chain.call(escrow, freezeCall, { from: USER });
assert(!unauthorized.ok, 'ordinary user cannot impersonate auditor');
assertEq(unauthorized.ret.slice(0, 10),
  selector('NotAuditorOrGovernance(address,address,address)'), 'freeze authority error');
const freezeTx = await chain.must(escrow, freezeCall, { from: AUDITOR });
assert(await frozen(), 'returned Rust reason caused on-chain freeze');
assertEq(freezeTx.logs.length, 1, 'one Frozen log');
// Full keccak256("Frozen(address,string)").
assertEq(freezeTx.logs[0].topics[0],
  '0x221731fdd006121b8ac15bc0c1e5c1603cd6308727de01d3aec94ba13c62e596', 'Frozen event signature');
assertEq(freezeTx.logs[0].topics[1], '0x' + addrWord(AUDITOR), 'Frozen actor');
const freezeData = freezeTx.logs[0].data;
assertEq(decodeUint(freezeData), 32n, 'Frozen reason ABI offset');
const reasonLength = Number(decodeUint(freezeData, 1));
assertEq(Buffer.from(freezeData.slice(130, 130 + reasonLength * 2), 'hex').toString(),
  rogue.escrow_reason, 'exact Rust reason survives transaction/event boundary');

const outKey = '0x' + '88'.repeat(32);
const proof = b32(outKey) + addrWord(PAYEE) + word(5_000_000n) + word(8192) + word(10);
const releaseCall = selector('release(bytes)') + word(32) + dynBytes(proof);
const blocked = await chain.call(escrow, releaseCall, { from: USER });
assert(!blocked.ok, 'frozen release must fail');
assertEq(blocked.ret.slice(0, 10), selector('IsFrozen()'), 'specifically the freeze blocks it');
assertEq(await balance(PAYEE), 0n, 'blocked payout transfers nothing');
assertEq(await balance(escrow), AMOUNT, 'blocked payout preserves escrow');
assert(!decodeBool((await chain.must(escrow, selector('redeemed(bytes32)') + b32(outKey))).ret),
  'blocked release does not consume replay key');
const wrongUnfreeze = await chain.call(escrow, selector('unfreeze()'), { from: AUDITOR });
assert(!wrongUnfreeze.ok, 'auditor cannot override governance-only unfreeze');
assertEq(wrongUnfreeze.ret.slice(0, 10), selector('NotGovernance(address,address)'),
  'unfreeze fails specifically because auditor is not governance');
assert(await frozen(), 'failed unfreeze preserves pause');
await chain.must(escrow, selector('unfreeze()'), { from: GOV });
assert(!(await frozen()), 'governance can unfreeze');
await chain.must(escrow, releaseCall, { from: USER });
assertEq(await balance(PAYEE), 5_000_000n, 'same proof pays after unfreeze');
console.log('PASS Rust freeze reason reaches Escrow; frozen payout is blocked; governance unfreeze restores it');
console.log('Auditor handoff: 3 integration checks passed (component scope; mock return verifier).');
