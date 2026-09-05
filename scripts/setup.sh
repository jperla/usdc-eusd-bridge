#!/usr/bin/env bash
# Clone the upstream checkouts this workspace builds against, at the exact
# revisions every proof and measurement in this repo was produced under.
set -euo pipefail
cd "$(dirname "$0")/.."
DEFAULT_CARGO="$(command -v cargo || true)"
mkdir -p vendor

clone_at() {
  local url=$1 dir=$2 rev=$3
  if [ -d "vendor/$dir/.git" ]; then
    echo "vendor/$dir already present"
  else
    git clone --filter=blob:none "$url" "vendor/$dir"
  fi
  # Do not refresh a large partial checkout unnecessarily. This also leaves
  # unrelated local vendor edits alone when it already names the pinned commit.
  if [ "$(git -C "vendor/$dir" rev-parse HEAD)" != "$rev" ]; then
    git -C "vendor/$dir" checkout -q "$rev"
  fi
  echo "vendor/$dir at $(git -C "vendor/$dir" rev-parse --short HEAD)"
}

clone_at https://github.com/mobilecoinfoundation/mobilecoin.git mobilecoin \
  05cb699f8f4cc1bc21186392545820c5b38408db
clone_at https://github.com/serai-dex/serai.git serai \
  4b89cf0206184886e96d0663861596312e5b47d2

# The test commands deliberately run offline. Populate their locked caches at
# setup time, using the same cargo executables as test.sh and acceptance.sh.
# Different cargo versions can use different registry cache directories.
for TC in "$HOME"/.rustup/toolchains/nightly-2024-10-11-*/bin; do
  if [ -d "$TC" ]; then
    export PATH="$TC:$PATH"
    break
  fi
done
cargo fetch --locked
( cd proofs/executable/m2d-two-cohort \
    && "${DEFAULT_CARGO:-cargo}" fetch --locked )
