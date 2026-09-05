#!/usr/bin/env bash
# Run the TLA+ models and their mutation runners.
#
# Kept separate from scripts/test.sh because these need a JVM and take minutes,
# where the Rust and Solidity suites need neither. But they ARE part of the
# evidence the README cites, so they need a command that runs them: a claim
# nothing executes is a claim nobody checks.
set -euo pipefail
cd "$(dirname "$0")/../proofs/tla"

# The tool is a jar, so a JVM is required. Homebrew's openjdk is keg-only and
# is not linked into PATH by default, which presents as TLC "not finding a Java
# runtime" while `brew list` shows it installed.
JAVA_BIN=$(python3 -c 'from tlc_harness import JAVA; print(JAVA)')
export JAVA_BIN
if ! "$JAVA_BIN" -version >/dev/null 2>&1; then
  echo "no JVM found. Install one (brew install openjdk) or put java on PATH." >&2
  exit 2
fi
TLA2TOOLS_JAR=$(python3 -c 'from tlc_harness import JAR; print(JAR)')
export TLA2TOOLS_JAR
[ -f "$TLA2TOOLS_JAR" ] || {
  echo "proofs/tla/tla2tools.jar is missing. It is deliberately not committed" >&2
  echo "Run ./scripts/setup-proofs.sh from the repository root to fetch the pinned tool." >&2
  exit 2
}

shopt -s nullglob
runners=(run_*.py)
[ ${#runners[@]} -gt 0 ] || { echo "no proof runners found" >&2; exit 2; }
pass=0; fail=0; failed=()
for r in "${runners[@]}"; do
  printf '%-34s ' "$r"
  if out=$(python3 "$r" 2>&1); then
    echo "PASS"; pass=$((pass + 1))
  else
    echo "FAIL"; fail=$((fail + 1)); failed+=("$r")
    echo "$out" | tail -6 | sed 's/^/      /'
  fi
done

echo
echo "$pass passed, $fail failed"
if [ ${#failed[@]} -gt 0 ]; then
  printf 'failing: %s\n' "${failed[*]}"
  exit 1
fi
