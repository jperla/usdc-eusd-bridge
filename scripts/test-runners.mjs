// Exercise the actual entrypoints with deliberately failing child programs.
// These controls must never compile contracts or silently use cached fixtures
// after a required Rust stage failed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, cpSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

function temporary(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'bridge-runner-test-'));
  try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function runSuite(programs) {
  return temporary((dir) => {
    cpSync(join(root, 'contracts/test/run.mjs'), join(dir, 'run.mjs'));
    for (const [name, source] of Object.entries(programs)) {
      writeFileSync(join(dir, name + '.mjs'), source);
    }
    return spawnSync(process.execPath, [join(dir, 'run.mjs')], {
      encoding: 'utf8', timeout: 10_000,
    });
  });
}

test('contract runner accepts a completed nonempty passing suite', () => {
  const r = runSuite({ suite: "console.log('  1 passed, 0 failed');" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

for (const [name, source] of [
  ['exit after success summary', "console.log('1 passed, 0 failed'); process.exit(42);"],
  ['throw after success summary', "console.log('1 passed, 0 failed'); throw Error('late failure');"],
  ['signal after success summary', "console.log('1 passed, 0 failed'); process.kill(process.pid, 'SIGTERM');"],
  ['duplicate summaries', "console.log('1 passed, 0 failed\\n1 passed, 0 failed');"],
  ['empty suite', "console.log('0 passed, 0 failed');"],
  ['missing summary', "console.log('did not execute assertions');"],
  ['reported test failure', "console.log('1 passed, 1 failed');"],
]) {
  test(`contract runner rejects ${name}`, () => {
    const r = runSuite({ suite: source });
    assert.equal(r.status, 1, r.stdout + r.stderr);
  });
}

test('contract runner rejects no discovered suites', () => {
  assert.equal(runSuite({}).status, 1);
});

for (const failedStage of ['two-cohort', 'spike', 'mc-return']) {
  test(`acceptance stops if ${failedStage} fails, even after printing success`, () => {
    temporary((dir) => {
      mkdirSync(join(dir, 'scripts'));
      mkdirSync(join(dir, 'proofs/executable/m2d-two-cohort'), { recursive: true });
      cpSync(join(root, 'scripts/acceptance.sh'), join(dir, 'scripts/acceptance.sh'));
      const cargo = join(dir, 'cargo-stub');
      writeFileSync(cargo, `#!/usr/bin/env bash
echo 'test result: ok. 1 passed; 0 failed;'
case "$*" in
  *two-cohort*) stage=two-cohort ;;
  *mc-return*) stage=mc-return ;;
  *) stage=spike ;;
esac
[ "$stage" != "$BRIDGE_FAIL_STAGE" ] || exit 42
`, { mode: 0o755 });
      const r = spawnSync('bash', [join(dir, 'scripts/acceptance.sh')], {
        encoding: 'utf8', timeout: 10_000,
        env: { ...process.env, BRIDGE_CARGO: cargo, BRIDGE_SPIKE_CARGO: cargo,
          BRIDGE_FAIL_STAGE: failedStage },
      });
      assert.equal(r.status, 42, r.stdout + r.stderr);
      assert.doesNotMatch(r.stdout, /LEGS 1 AND 3/);
    });
  });
}
