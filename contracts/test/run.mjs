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
  const r = spawnSync(process.execPath, [join(HERE, s)], {
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  });
  const out = (r.stdout || '') + (r.stderr || '');
  const summaries = [...out.matchAll(/^\s*(\d+) passed, (\d+) failed\s*$/gm)];
  // A summary printed before an uncaught exception, process signal, or output
  // overflow is not a successful suite. Reject ambiguous and empty runs too.
  if (r.error || r.signal || r.status !== 0 || summaries.length !== 1
      || Number(summaries[0][1]) + Number(summaries[0][2]) === 0) {
    broken.push(s);
    console.log(`\n=== ${s} === FAILED (exit=${r.status}, signal=${r.signal}, `
      + `summaries=${summaries.length})`);
    if (r.error) console.log(r.error.message);
    console.log(out.split('\n').slice(-15).join('\n'));
    continue;
  }
  const [, p, f] = summaries[0];
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
if (totalFail > 0 || broken.length || suites.length === 0) process.exitCode = 1;
