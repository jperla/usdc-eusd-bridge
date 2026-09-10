#!/usr/bin/env bash
# Run a Sol (gpt-5.6-sol, via codex-cli) review over a target directory.
#
# Sol has refuted or narrowed something in every artifact reviewed so far,
# including defects in the checking apparatus rather than the design. Nothing
# in this repo counts as evidence until it has been through this.
#
#   ./scripts/sol-review.sh <target-dir> <prompt-file> [out-file]
#
# read-only sandbox: the reviewer must never be able to edit what it reviews,
# or a "fix" can silently replace a finding.
set -euo pipefail

TARGET=${1:?target directory required}
PROMPT_FILE=${2:?prompt file required}
OUT=${3:-/dev/stdout}

[ -d "$TARGET" ] || { echo "no such directory: $TARGET" >&2; exit 1; }
[ -f "$PROMPT_FILE" ] || { echo "no such prompt: $PROMPT_FILE" >&2; exit 1; }

# Resolve before the cd, or a relative out/prompt path silently lands in (or
# fails against) the target directory instead of the caller's.
PROMPT_FILE=$(cd "$(dirname "$PROMPT_FILE")" && pwd)/$(basename "$PROMPT_FILE")
if [ "$OUT" != "/dev/stdout" ]; then
  mkdir -p "$(dirname "$OUT")"
  OUT=$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")
fi

cd "$TARGET"
# stdin MUST be closed: with a prompt passed as an argument, codex still
# reads stdin if it is open, and a background invocation with no tty simply
# hangs on "Reading additional input from stdin..." producing a one-line file
# that looks like a crashed review rather than a stalled one.
codex exec \
  --sandbox read-only \
  --skip-git-repo-check \
  "$(cat "$PROMPT_FILE")" \
  < /dev/null 2>&1 | tee "$OUT"
