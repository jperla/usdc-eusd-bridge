// WHICH CONTRACTS IN src/ ARE MEANT TO BE DEPLOYED.
//
// `src/TestMocks.sol` states this repo's convention: "Keeping them in a file
// named TestMocks makes it obvious in a diff when one is reachable from
// production code." EIGHT contracts break the letter of it and cannot be fixed
// by moving them: the `*Probe_DO_NOT_DEPLOY` wrappers in Aes256.sol,
// Blake2b256.sol, Hkdf.sol, Keccak1600.sol, Merlin.sol,
// MobileCoinGenerators.sol, Ristretto255.sol and AmountOpener.sol wrap
// `internal` library functions, so they have to be compiled against the
// library that declares them, which means they have to sit in that library's
// file.
//
// So the convention is enforced here instead of by file layout, and by a test
// rather than by prose. Every `contract` declared under src/ must be either
//
//   * on DEPLOYABLE below -- the contracts a deployment script is allowed to
//     name -- or
//   * marked test-only, which means BOTH a `_DO_NOT_DEPLOY` suffix on the name
//     AND `/// TEST ONLY -- NEVER DEPLOY.` as the FIRST line of the doc comment
//     above it -- first, so it is the first thing read and not a sentence
//     buried under eight lines of rationale -- or a declaration inside
//     TestMocks.sol.
//
// What that buys a reviewer: adding a genuinely deployable contract to src/
// cannot be done without editing the allowlist in this file, and that edit is
// the diff to argue about. Adding a probe cannot be done without spelling out
// in its own name that it is not for deployment.
//
// The marking checks read the SOURCE TEXT rather than the compiler's output,
// because the thing being checked is what a reader of a diff sees. The EIP-170
// check at the bottom compiles, but still deploys nothing -- see the note on
// it for why that distinction is the whole reason it lives here.
//
// A text scan is only as complete as its pattern, and this one was not
// complete: an INDENTED declaration used to be invisible to it, which made the
// guarantee in the paragraph above false rather than merely weak. The first
// test in this file now measures the scan against the compiler, so a pattern
// that goes blind fails loudly instead of passing quietly.

import { readFileSync, readdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { compileAll, test, assert, assertEq, summary } from './harness.mjs';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

/// The contracts a deployment is allowed to name. Everything else in src/ is
/// either a library, an interface, or test-only.
///
/// Adding a name here is the decision "this is production". Do not add a name
/// to make this test pass.
const DEPLOYABLE = new Set([
  'Escrow',
  'MobileCoinVerifier',
  'ValidatorRegistry',
  'RecipientCheck',
  // Not a probe, and not currently reachable from any of the four above
  // either: its own comment says it exists so a caller can reach the Ed25519
  // checks ACROSS A CALL and stay under the 24 KB code limit. Nothing in src/
  // takes that option today, so it is a spare part -- deployable by design,
  // deployed by nobody. Listed rather than suffixed because suffixing it would
  // assert it is test-only, which its comment denies.
  'Ed25519Verifier',
]);

const BANNER = '/// TEST ONLY -- NEVER DEPLOY.';
const TEST_ONLY_FILE = 'TestMocks.sol';

/// Every `contract X` in src/, with the file it is in and the first line of
/// the `///` block above it.
///
/// Deliberately not the compiler's output: an `abstract contract` or a
/// contract behind a failing compile still ships in the file, and the point of
/// this check is the file.
function declarations() {
  const out = [];
  for (const file of readdirSync(SRC).filter((f) => f.endsWith('.sol'))) {
    const lines = readFileSync(join(SRC, file), 'utf8').split('\n');
    lines.forEach((line, i) => {
      // `^\s*`, not `^`: this anchored at column 0 until an indented
      // declaration was shown to slip past every check in this file. See
      // 'THE TEXT SCAN SEES EVERY TYPE THE COMPILER DOES' below.
      const m = /^\s*(abstract\s+)?contract\s+([A-Za-z0-9_$]+)/.exec(line);
      if (!m) return;
      // Walk back over the contiguous doc comment; its FIRST line is the one
      // that has to carry the marking.
      let j = i;
      while (j > 0 && lines[j - 1].trimStart().startsWith('///')) j--;
      out.push({
        file,
        abstract: Boolean(m[1]),
        name: m[2],
        docHead: j === i ? '' : lines[j].trim(),
        line: i + 1,
      });
    });
  }
  return out;
}

/// Compiled once and shared: solc is by far the slowest thing in this file.
const CONTRACTS = compileAll();

/// The RUNTIME image of `name`, in bytes, read from the compiler. Not from a
/// deployment: a contract over EIP-170's limit cannot be deployed, so a size
/// check that deploys first is dead exactly when it is needed.
function runtimeBytes(name) {
  for (const file of Object.keys(CONTRACTS)) {
    const c = CONTRACTS[file][name];
    if (c) return (c.evm.deployedBytecode.object || '').length / 2;
  }
  throw new Error(`contract not found: ${name}`);
}

/// Every `library X` in src/, with the file it is in.
function libraries() {
  const out = [];
  for (const file of readdirSync(SRC).filter((f) => f.endsWith('.sol'))) {
    for (const line of readFileSync(join(SRC, file), 'utf8').split('\n')) {
      const m = /^\s*library\s+([A-Za-z0-9_$]+)/.exec(line);
      if (m) out.push({ file, name: m[1] });
    }
  }
  return out;
}

/// Every type name the TEXT SCAN can see in `file`, of any kind. Used only to
/// measure the scan against the compiler; the checks above care which kind a
/// declaration is, and this one does not.
function scannedNames(file) {
  const out = new Set();
  for (const line of readFileSync(join(SRC, file), 'utf8').split('\n')) {
    const m = /^\s*(abstract\s+)?(contract|library|interface)\s+([A-Za-z0-9_$]+)/
      .exec(line);
    if (m) out.add(m[3]);
  }
  return out;
}

console.log('\nsrc/ deployables');

await test('THE TEXT SCAN SEES EVERY TYPE THE COMPILER DOES', async () => {
  // WHY THIS EXISTS. Every marking check in this file reads source TEXT,
  // deliberately -- what is being enforced is what a reader of a diff sees.
  // But that makes those checks only as complete as one regular expression,
  // and a regular expression that misses a declaration does not fail. It
  // reports nothing and passes, which is the worst way for a guard to be
  // wrong: the file went on claiming "adding a genuinely deployable contract
  // to src/ cannot be done without editing the allowlist" while it could.
  //
  // It was wrong exactly this way. `declarations()` and `libraries()` anchored
  // at column 0, so a declaration with ONE LEADING SPACE was invisible.
  // Measured: appending
  //
  //     ␠␠contract SneakyHelper {
  //     ␠␠    function ping() external pure returns (uint256) { return 1; }
  //     ␠␠}
  //
  // to src/LE.sol -- unmarked, unallowlisted, and genuinely deployable -- left
  // this suite at 5 passed, 0 failed. With the anchors fixed it is caught by
  // the marking test; with them fixed AND this test present, the next gap in
  // the pattern is caught even though the marking test cannot see it.
  //
  // The compiler is the right oracle because it cannot be fooled by layout: it
  // does not care about indentation, about how many spaces follow the keyword,
  // or about which column a declaration starts in. If solc reports a type in a
  // file and the scan did not see it, the scan is blind and every marking
  // guarantee in this file is void for that type.
  const missing = [];
  for (const file of Object.keys(CONTRACTS)) {
    const seen = scannedNames(file);
    for (const name of Object.keys(CONTRACTS[file])) {
      if (!seen.has(name)) missing.push(`${file}:${name}`);
    }
  }
  assert(missing.length === 0,
    `the compiler reports ${missing.length} type(s) in src/ that the text scan `
    + `in this file cannot see: ${missing.join(', ')}. Every marking and `
    + 'allowlist check here reads that scan, so anything it misses is '
    + 'unguarded. Widen the pattern in declarations()/libraries()/'
    + 'scannedNames() -- do NOT add the name to DEPLOYABLE.');

  // Not vacuous: if the compiler reported nothing, the loop above is empty and
  // proves nothing.
  const total = Object.values(CONTRACTS)
    .reduce((n, f) => n + Object.keys(f).length, 0);
  assert(total >= 20,
    `the compiler reports only ${total} types across src/ -- this test is `
    + 'blind, and so is every other check in this file');
});

await test('THE CONSTRUCTOR HAS NO GENERATOR ARGUMENT TO MISPAIR', async () => {
  // The structural half of the fail-open fix, asserted against the compiled
  // ABI rather than against prose. While `_eusdValueGenerator` existed, a
  // deployment could name token id 8192 and hand over `generators(1).B`; the
  // contract checked that the point was a point and paid out anything
  // committed in the wrong group.
  //
  // WHY IT LIVES HERE AND NOT IN verifier.mjs, where it was written. Its
  // comment there claimed "re-adding the argument turns this red", and that
  // was false for the minimal mutation. verifier.mjs deploys a verifier at
  // module scope, so re-adding a sixth constructor argument makes the
  // deployment revert and kills verifier.mjs AND acceptance.mjs at import --
  // the test never runs, and the suite reports "SUITES THAT DID NOT RUN"
  // rather than this failure. It only fired if `deployVerifier` was updated to
  // pass the new argument too, i.e. against a regression already half-repaired.
  //
  // This suite reads the ABI out of the compiler and deploys nothing, which is
  // the same reason the EIP-170 assertion lives here. Re-adding the argument
  // now turns THIS red, on the minimal mutation and with no other edit.
  const abi = Object.values(CONTRACTS)
    .flatMap((f) => Object.entries(f))
    .find(([name]) => name === 'MobileCoinVerifier')[1].abi;
  const ctor = abi.find((e) => e.type === 'constructor');
  assert(ctor, 'MobileCoinVerifier has no constructor');
  const types = ctor.inputs.map((i) => `${i.type} ${i.name}`);
  assert(!ctor.inputs.some((i) => /generator/i.test(i.name)),
    `a generator argument is back: ${types.join(', ')}`);
  assertEq(ctor.inputs.length, 5, `constructor arity: ${types.join(', ')}`);

  // Not vacuous: the token id IS still an argument, and it is the thing the
  // generator is now derived from.
  assert(ctor.inputs.some((i) => i.name === '_eusdTokenId'),
    `the token id argument vanished: ${types.join(', ')}`);
});

await test('every contract in src/ is either on the deployable allowlist or '
  + 'marked TEST ONLY in its name and above its declaration', async () => {
  const decls = declarations();
  assert(decls.length > 0, 'no contracts found in src/ -- this test is blind');

  const unmarked = [];
  for (const d of decls) {
    // `abstract contract` has no creation bytecode; solc refuses to deploy it
    // and there is nothing to mark. `Governed` is the only one today.
    if (d.abstract) continue;
    if (DEPLOYABLE.has(d.name)) continue;
    if (d.file === TEST_ONLY_FILE) continue;
    const named = d.name.endsWith('_DO_NOT_DEPLOY');
    const bannered = d.docHead === BANNER;
    if (named && bannered) continue;
    unmarked.push(
      `${d.file}:${d.line} ${d.name}` +
      `${named ? '' : ' [unsuffixed]'}${bannered ? '' : ' [unbannered]'}`
    );
  }
  // One line per complaint would be hidden: the harness prints only the first
  // four lines of a failure. Everything goes on one.
  assert(unmarked.length === 0,
    `${unmarked.length} contract(s) in src/ neither on DEPLOYABLE nor marked `
    + `test-only: ${unmarked.join('; ')}\n          Add it to DEPLOYABLE in `
    + `this file -- which is the statement that it is production -- or give it `
    + `a _DO_NOT_DEPLOY suffix and "${BANNER}" as its first doc line.`);
});

await test('the allowlist names contracts that exist, and every probe is '
  + 'covered by it', async () => {
  // The allowlist rots in the direction that matters: a deleted or renamed
  // production contract leaves a name here that guards nothing, and the next
  // contract to take that name inherits a pass it never earned.
  const names = new Set(declarations().map((d) => d.name));
  for (const d of DEPLOYABLE) {
    assert(names.has(d), `DEPLOYABLE names ${d}, which is not in src/`);
  }

  // And the exception is a fixed, countable set rather than a recollection.
  // EIGHT probes sit outside TestMocks.sol, one per library with `internal`
  // functions a test has to reach: Aes256, Blake2b256, Hkdf, Keccak1600,
  // Merlin, MobileCoinGenerators, Ristretto255 and AmountOpener. A ninth means
  // a new library grew a wrapper; that is fine, and it should be counted here
  // deliberately rather than slipped in.
  const probes = declarations()
    .filter((d) => d.name.endsWith('_DO_NOT_DEPLOY')
      && d.file !== TEST_ONLY_FILE);
  assertEq(probes.length, 8,
    `probes outside TestMocks.sol: ${probes.map((p) => p.file + ':' + p.name)
      .join(', ')}`);
});

// ------------------------------------------------------- EIP-170

/// EIP-170: a contract's RUNTIME code may not exceed 24,576 bytes. EIP-3860
/// (Shanghai) caps INIT code at 49,152.
const EIP_170_LIMIT = 24_576;

await test('EVERY DEPLOYABLE CONTRACT FITS UNDER EIP-170', async () => {
  // THE NEAREST CLIFF IN THIS REPO, AND UNTIL NOW ASSERTED NOWHERE.
  // `MobileCoinVerifier` deploys for ~5.5M gas against a 30M block -- 5.5x of
  // headroom. Its runtime code is 24,231 bytes against 24,576 -- 345 bytes,
  // 1.4%. Gas is the number the suite prints; size is the number that ends the
  // project.
  //
  // WHAT BREAKS WHEN IT IS EXCEEDED. Nothing subtle and nothing recoverable:
  // CREATE/CREATE2 fail, the creation transaction consumes all its gas and
  // deploys nothing. There is no price at which it succeeds, no parameter to
  // raise, no partial deployment to salvage. The contract cannot exist on
  // mainnet. Measured in an isolated copy by padding MobileCoinVerifier with
  // 40 trivial external functions: the EVM returns "code size to deposit
  // exceeds maximum code size", and every suite that deploys it dies at import
  // rather than reporting a failure.
  //
  // WHY THE CHECK IS HERE AND NOT IN verifier.mjs. That is the same measurement
  // and it cannot make it. verifier.mjs deploys a verifier at module scope, so
  // an over-limit contract kills the file before its first test runs -- the
  // check would be dead exactly when it was needed. This suite reads the
  // runtime image out of the COMPILER, deploying nothing, so an over-limit
  // contract turns this named test red.
  //
  // WHAT THE NEXT CHANGE HAS TO GIVE UP. 345 bytes is roughly one more custom
  // error with arguments plus a short branch. Everything MobileCoinVerifier
  // uses -- Ristretto255, Merlin, Ed25519, Blake2b, Hkdf, Aes256, Sha512,
  // Keccak1600, AmountOpener, MemoOpener -- is an `internal` library, so all of
  // it is INLINED into that one runtime image and none of it can be shrunk by
  // sharing. The realistic escapes, cheapest first:
  //
  //   * lower the optimizer's `runs` from 200: smaller code, more gas per
  //     call, and every gas number this repo publishes moves;
  //   * move a self-contained library behind an external call -- Aes256 and
  //     the memo path are the candidates, since they run once per verification
  //     -- at the cost of a SECOND deployment whose address is a constructor
  //     argument. Note what that reintroduces: exactly the mispaired-deployment
  //     class of fail-open that deleting `_eusdValueGenerator` just removed. It
  //     is a real option and it is not a free one;
  //   * drop an entry point. `openAmount`/`openMemo` are external mostly so the
  //     tests can reach the production code path rather than a copy of it.
  const over = [];
  for (const name of [...DEPLOYABLE].sort()) {
    const size = runtimeBytes(name);
    const headroom = EIP_170_LIMIT - size;
    console.log(`        ${name.padEnd(20)} ${String(size).padStart(6)} bytes`
      + ` (${(size / EIP_170_LIMIT * 100).toFixed(1)}% of EIP-170), `
      + `${headroom} to spare`);
    if (size > EIP_170_LIMIT) over.push(`${name} by ${size - EIP_170_LIMIT}`);
  }
  assert(over.length === 0,
    `EIP-170: over the ${EIP_170_LIMIT}-byte runtime limit: ${over.join(', ')}. `
    + 'These contracts cannot be deployed at any gas price.');

  // The alarm, on the one contract that is anywhere near it. Measured at
  // 24,231 bytes -- 345 of headroom -- with solc 0.8.26, optimizer on,
  // runs=200, viaIR, all pinned by contracts/package.json and test/harness.mjs,
  // so the figure is reproducible and not incidental.
  //
  // NOT PINNED TO 24,231, deliberately, and this is the repo's existing rule
  // for gas applied to size: pinning the exact count would turn every
  // optimisation into a failing test. The hard limit above is the guard; this
  // is a shape check. 4 KB is far outside anything an ordinary edit produces,
  // so it fires on a build that changed CHARACTER -- a library that stopped
  // inlining, an optimizer setting that moved, a suite compiling a subset it
  // did not mean to -- rather than on progress. The exact figure is printed
  // every run, so it cannot go stale unnoticed.
  const verifier = runtimeBytes('MobileCoinVerifier');
  const headroom = EIP_170_LIMIT - verifier;
  assert(headroom < 4_096,
    `MobileCoinVerifier has ${headroom} bytes of headroom, where 345 was `
    + 'measured. Above 4 KB means the build changed shape, not that the '
    + 'contract got smaller -- check the optimizer settings and the compile set '
    + 'before believing it.');
});

await test('no library in src/ is deployable, so the allowlist above is the '
  + 'whole list', async () => {
  // THE GAP THE TEXT SCAN LEAVES. `declarations()` matches `contract`, and a
  // `library` is not one -- but a library is deployable the moment it grows a
  // `public` or `external` function, at which point it has to be deployed and
  // linked separately and is exactly the kind of second deployment this repo
  // just spent a change removing. It would pass every check above by not being
  // spelled "contract".
  //
  // The compiler answers it cleanly. A library whose functions are all
  // `internal` inlines into its callers and compiles to a 57-byte stub -- the
  // same 57 bytes for all sixteen libraries in src/, since the stub is
  // boilerplate and not code. Anything materially larger is real code with a
  // dispatcher in front of it.
  const STUB = 64; // the 57-byte stub, plus slack for a compiler revision
  const libs = libraries();
  // Not vacuous: this repo is mostly libraries, so a low count means the scan
  // is looking in the wrong place rather than that the news is good.
  assert(libs.length >= 10,
    `only ${libs.length} libraries found in src/ -- this test is blind`);

  const deployable = libs
    .map((l) => ({ ...l, size: runtimeBytes(l.name) }))
    .filter((l) => l.size > STUB && !DEPLOYABLE.has(l.name));
  assert(deployable.length === 0,
    'a library in src/ compiles to real runtime code, which means it has a '
    + 'public or external function and must be DEPLOYED and LINKED: '
    + `${deployable.map((l) => `${l.file}:${l.name} (${l.size} bytes)`)
        .join(', ')}. That is a second deployment address to get wrong. Make `
    + 'the functions internal, or add it to DEPLOYABLE above and say who '
    + 'deploys it.');
});

await test('TestMocks.sol still exists and still holds the mocks that CAN '
  + 'move', async () => {
  // The convention this file enforces is TestMocks.sol's, so it has to still
  // be there. A probe that stops needing library internals should move back
  // into it rather than keep the suffix.
  const decls = declarations().filter((d) => d.file === TEST_ONLY_FILE);
  assert(decls.length >= 4,
    `TestMocks.sol declares ${decls.length} contracts -- it used to hold the `
    + 'escrow mocks; if they moved, this convention moved with them');
});

summary();
