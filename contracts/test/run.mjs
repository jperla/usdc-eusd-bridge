// Run every contract suite in one process-per-suite pass.
//
// Separate processes on purpose: the suites compile different source subsets,
// and a compile failure in one contract must not be able to mask another
// suite's results.

import { spawnSync } from 'child_process';
import { readdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const HERE = dirname(fileURLToPath(import.meta.url));
const suites = readdirSync(HERE)
  .filter((f) => f.endsWith('.mjs') && !['run.mjs', 'harness.mjs'].includes(f))
  .sort();

let totalPass = 0;
let totalFail = 0;
const broken = [];

for (const s of suites) {
  const r = spawnSync('node', [join(HERE, s)], { encoding: 'utf8' });
  const out = (r.stdout || '') + (r.stderr || '');
  const m = out.match(/(\d+) passed, (\d+) failed/);
  if (!m) {
    broken.push(s);
    console.log(`\n=== ${s} === DID NOT REPORT A SUMMARY`);
    console.log(out.split('\n').slice(-15).join('\n'));
    continue;
  }
  const [, p, f] = m;
  totalPass += Number(p);
  totalFail += Number(f);
  console.log(`  ${s.padEnd(16)} ${p.padStart(4)} passed  ${f.padStart(3)} failed`);
  if (Number(f) > 0) {
    console.log(out.split('\n').filter((l) => l.includes('FAIL')).join('\n'));
  }
}

console.log('');
console.log('='.repeat(52));
console.log(`  TOTAL: ${totalPass} passed, ${totalFail} failed`);
if (broken.length) console.log(`  SUITES THAT DID NOT RUN: ${broken.join(', ')}`);
console.log('='.repeat(52));
if (totalFail > 0 || broken.length) process.exitCode = 1;
