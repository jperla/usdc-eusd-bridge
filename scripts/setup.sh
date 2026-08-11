#!/usr/bin/env bash
# Clone the upstream checkouts this workspace builds against, at the exact
# revisions every proof and measurement in this repo was produced under.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p vendor

clone_at() {
  local url=$1 dir=$2 rev=$3
  if [ -d "vendor/$dir/.git" ]; then
    echo "vendor/$dir already present"
  else
    git clone --filter=blob:none "$url" "vendor/$dir"
  fi
  git -C "vendor/$dir" checkout -q "$rev"
  echo "vendor/$dir at $(git -C "vendor/$dir" rev-parse --short HEAD)"
}

clone_at https://github.com/mobilecoinfoundation/mobilecoin.git mobilecoin \
  05cb699f8f4cc1bc21186392545820c5b38408db
clone_at https://github.com/serai-dex/serai.git serai \
  4b89cf0206184886e96d0663861596312e5b47d2
