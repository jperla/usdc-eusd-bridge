// Shared EVM test harness: compile every contract in src/, deploy against a
// real EVM (ethereumjs), and call it with minimal hand-rolled ABI encoding.
//
// Deliberately no ethers/hardhat: the whole point of these tests is that the
// numbers and the acceptance results come from a real EVM executing real
// bytecode, with as little between the test and the machine as possible.

import solc from 'solc';
import { readFileSync, readdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { EVM } from '@ethereumjs/evm';
import { hexToBytes, bytesToHex, Address } from '@ethereumjs/util';
import { keccak256 } from 'ethereum-cryptography/keccak.js';
import { utf8ToBytes } from 'ethereum-cryptography/utils.js';

const HERE = dirname(fileURLToPath(import.meta.url));
export const SRC = join(HERE, '..', 'src');

// ------------------------------------------------------------------ encoding

export const selector = (sig) =>
  bytesToHex(keccak256(utf8ToBytes(sig))).slice(0, 10);

export const word = (v) => {
  let b = BigInt(v);
  if (b < 0n) b = (1n << 256n) + b;          // two's complement
  return b.toString(16).padStart(64, '0');
};

export const addrWord = (a) => word(BigInt(a));

export const b32 = (hexOrBytes) => {
  const h = typeof hexOrBytes === 'string'
    ? hexOrBytes.replace(/^0x/, '')
    : bytesToHex(hexOrBytes).slice(2);
  if (h.length > 64) throw new Error(`b32 overflow: ${h.length} nibbles`);
  return h.padStart(64, '0');
};

/// Dynamic `bytes`: length word then right-padded data.
export const dynBytes = (hex) => {
  const h = hex.replace(/^0x/, '');
  if (h.length % 2) throw new Error('odd-length hex');
  const len = h.length / 2;
  const padded = h.padEnd(Math.ceil(len / 32) * 64, '0');
  return word(len) + padded;
};

/// Encode a call with a single trailing dynamic `bytes` argument, plus any
/// leading static words.
export const encodeWithTrailingBytes = (sig, staticWords, hex) => {
  const head = staticWords.join('');
  const offset = word((staticWords.length + 1) * 32);
  return selector(sig) + head + offset + dynBytes(hex);
};

export const decodeAddress = (ret, wordIndex = 0) =>
  '0x' + ret.slice(2).slice(wordIndex * 64, (wordIndex + 1) * 64).slice(24);

export const decodeUint = (ret, wordIndex = 0) =>
  BigInt('0x' + ret.slice(2).slice(wordIndex * 64, (wordIndex + 1) * 64));

export const decodeBool = (ret, wordIndex = 0) =>
  decodeUint(ret, wordIndex) === 1n;

/// Solidity revert data -> a readable reason. Handles Error(string) and the
/// 4-byte custom-error selectors this repo uses.
export function revertReason(retHex, errorSelectors = {}) {
  const h = (retHex || '0x').replace(/^0x/, '');
  if (h.length === 0) return '(no revert data)';
  const sel = '0x' + h.slice(0, 8);
  if (sel === '0x08c379a0') {
    const len = parseInt(h.slice(8 + 64, 8 + 128), 16);
    const str = h.slice(8 + 128, 8 + 128 + len * 2);
    return Buffer.from(str, 'hex').toString('utf8');
  }
  return errorSelectors[sel] || `custom error ${sel}`;
}

// ------------------------------------------------------------------ compiling

/// Resolve a file's local imports transitively, so a suite can compile only
/// what it needs. Without this, one contributor's half-written contract in
/// src/ breaks every other suite in the repo -- which is a coordination
/// failure, not a test failure, and should not look like one.
function withImports(entry, seen = new Set()) {
  if (seen.has(entry)) return seen;
  seen.add(entry);
  const body = readFileSync(join(SRC, entry), 'utf8');
  for (const m of body.matchAll(/import\s+[^;]*?["']\.\/([^"']+)["']/g)) {
    withImports(m[1], seen);
  }
  return seen;
}

export function compileAll({ optimize = true, runs = 200, only = null } = {}) {
  const sources = {};
  let wanted;
  if (only) {
    wanted = new Set();
    for (const f of only) for (const g of withImports(f)) wanted.add(g);
  } else {
    wanted = new Set(readdirSync(SRC).filter((f) => f.endsWith('.sol')));
  }
  for (const f of wanted) {
    sources[f] = { content: readFileSync(join(SRC, f), 'utf8') };
  }
  const input = {
    language: 'Solidity',
    sources,
    settings: {
      optimizer: { enabled: optimize, runs },
      // viaIR keeps the deep-stack verifier compiling.
      viaIR: true,
      // `deployedBytecode` is the RUNTIME image -- what EIP-170's 24,576-byte
      // limit applies to, and what `bytecode` is not. Selected so a size check
      // can read it from the compiler instead of from a successful deployment:
      // a contract that is over the limit cannot be deployed at all, so a
      // check that deploys first cannot be the check that catches it.
      outputSelection: {
        '*': {
          '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'],
        },
      },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const errs = (out.errors || []).filter((e) => e.severity === 'error');
  if (errs.length) {
    throw new Error(errs.map((e) => e.formattedMessage).join('\n'));
  }
  return out.contracts;
}

// ------------------------------------------------------------------- chain

export class Chain {
  constructor(evm, contracts) {
    this.evm = evm;
    this.contracts = contracts;
    this._next = 0x1000;
  }

  static async create(opts) {
    const contracts = compileAll(opts);
    return Chain.fromCompiled(contracts);
  }

  // Fresh state from already compiled sources: independent funded controls
  // need the same deployment layout without recompiling the whole verifier.
  static async fromCompiled(contracts) {
    const evm = await EVM.create();
    const c = new Chain(evm, contracts);
    c.deployer = new Address(hexToBytes('0x' + 'de'.repeat(19) + 'a1'));
    const { Account } = await import('@ethereumjs/util');
    await evm.stateManager.putAccount(c.deployer, new Account(0n, 10n ** 24n));
    return c;
  }

  _bytecode(name) {
    for (const file of Object.keys(this.contracts)) {
      if (this.contracts[file][name]) {
        return '0x' + this.contracts[file][name].evm.bytecode.object;
      }
    }
    throw new Error(`contract not found: ${name}`);
  }

  /// Deploy via a real CREATE and use the address the EVM actually created.
  ///
  /// The obvious shortcut -- run the creation code, then install the returned
  /// runtime code at an address of your choosing -- is WRONG and fails
  /// silently: the constructor's storage writes land in the created account,
  /// so moving only the code leaves every constructor-assigned storage
  /// variable at zero while `immutable`s (which live in the code) survive.
  /// That reads as "governance is address(0), the cap is 0, the verifier is
  /// address(0)" and looks like a contract bug rather than a harness bug.
  async deploy(name, encodedArgs = '') {
    const data = this._bytecode(name) + encodedArgs;
    const r = await this.evm.runCall({
      data: hexToBytes(data),
      gasLimit: 500_000_000n,
      caller: this.deployer,
      origin: this.deployer,
    });
    if (r.execResult.exceptionError) {
      throw new Error(
        `deploy ${name} failed: ${r.execResult.exceptionError.error} ` +
          `:: ${revertReason(bytesToHex(r.execResult.returnValue))}`
      );
    }
    if (!r.createdAddress) {
      throw new Error(`deploy ${name}: no createdAddress returned`);
    }
    // Bump the deployer nonce so the next CREATE gets a distinct address.
    const acct = await this.evm.stateManager.getAccount(this.deployer);
    acct.nonce += 1n;
    await this.evm.stateManager.putAccount(this.deployer, acct);
    return '0x' + r.createdAddress.toString().replace(/^0x/, '');
  }

  async call(to, data, { from, gasLimit = 200_000_000n, value = 0n } = {}) {
    const opts = {
      to: new Address(hexToBytes(to)),
      data: hexToBytes(data),
      gasLimit,
      value,
    };
    if (from) opts.caller = new Address(hexToBytes(from));
    if (from) opts.origin = new Address(hexToBytes(from));
    const r = await this.evm.runCall(opts);
    return {
      ok: !r.execResult.exceptionError,
      error: r.execResult.exceptionError
        ? String(r.execResult.exceptionError.error)
        : null,
      gas: Number(r.execResult.executionGasUsed),
      ret: bytesToHex(r.execResult.returnValue),
      logs: (r.execResult.logs || []).map((l) => ({
        topics: l[1].map((t) => bytesToHex(t)),
        data: bytesToHex(l[2]),
      })),
    };
  }

  /// Call and throw on revert. Use in tests where success is the assertion.
  async must(to, data, opts) {
    const r = await this.call(to, data, opts);
    if (!r.ok) {
      throw new Error(
        `call reverted: ${r.error} :: ${revertReason(r.ret)}`
      );
    }
    return r;
  }
}

// -------------------------------------------------------------------- runner

let passed = 0;
let failed = 0;
const failures = [];

export async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failed++;
    failures.push({ name, e });
    console.log(`  FAIL  ${name}`);
    console.log(`        ${e.message.split('\n').slice(0, 4).join('\n        ')}`);
  }
}

export function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

export function assertEq(got, want, msg) {
  const g = typeof got === 'bigint' ? got.toString() : String(got);
  const w = typeof want === 'bigint' ? want.toString() : String(want);
  if (g.toLowerCase() !== w.toLowerCase()) {
    throw new Error(`${msg || 'mismatch'}\n          got:  ${g}\n          want: ${w}`);
  }
}

export async function assertReverts(promiseOrResult, msg) {
  const r = await promiseOrResult;
  if (r.ok) throw new Error(msg || 'expected revert, call succeeded');
  return r;
}

export function summary() {
  console.log('');
  console.log(`  ${passed} passed, ${failed} failed`);
  if (failed) {
    process.exitCode = 1;
  }
  return failed === 0;
}
