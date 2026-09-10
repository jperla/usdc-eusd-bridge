// Return the executable Cargo just built, respecting CARGO_TARGET_DIR.
import { spawnSync } from 'node:child_process';
const [pkg, kind, name] = process.argv.slice(2);
if (!pkg || !['--bin','--example'].includes(kind) || !name) throw Error('package --bin|--example name required');
const r = spawnSync(process.env.BRIDGE_CARGO || 'cargo',
  ['build','--offline','--locked','--message-format=json','-p',pkg,kind,name],
  {encoding:'utf8', timeout:600_000, maxBuffer:32*1024*1024});
if (r.error || r.status !== 0) throw Error(`Cargo build failed: ${r.error || r.stderr}`);
const a = r.stdout.trim().split('\n').map(s=>JSON.parse(s)).find(a=>
  a.reason==='compiler-artifact' && a.target?.name===name && a.executable);
if (!a) throw Error('Cargo did not report the requested executable');
console.log(a.executable);
