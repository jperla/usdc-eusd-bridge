#!/usr/bin/env bash
# Fetch the exact public TLC artifact used by the checked proof runners.
set -euo pipefail
proof_root=$(cd "$(dirname "$0")/.." && pwd)
proof_jar=${TLA2TOOLS_JAR:-"$proof_root/proofs/tla/tla2tools.jar"}
proof_url=https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
proof_sha256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88

verify_jar() {
  local actual
  actual=$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1")
  if [ "$actual" != "$proof_sha256" ]; then
    echo "TLC checksum mismatch for $1" >&2
    echo "expected $proof_sha256; got $actual" >&2
    return 1
  fi
}

# Do not overwrite a user-supplied tool when it differs from the pinned one.
if [ -e "$proof_jar" ]; then
  verify_jar "$proof_jar"
  echo "TLC v1.7.4 / 2.19 verified: $proof_jar"
  exit 0
fi

proof_parent=$(dirname "$proof_jar")
mkdir -p "$proof_parent"
proof_download=$(mktemp "$proof_parent/.tla2tools-download.XXXXXX")
trap 'rm -f -- "$proof_download"' EXIT
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 120 --output "$proof_download" "$proof_url"
verify_jar "$proof_download"
# -n also preserves a tool installed by another setup process during download.
mv -n -- "$proof_download" "$proof_jar"
verify_jar "$proof_jar"
echo "TLC v1.7.4 / 2.19 installed and verified: $proof_jar"
