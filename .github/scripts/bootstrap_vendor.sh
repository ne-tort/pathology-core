#!/usr/bin/env bash
# Bootstrap sibling vendor/ tree expected by go.mod replace and Makefile:
#   ../vendor/sing-box-lx
#   ../vendor/sing-vmess
# Relative to pathology-core repo root (GITHUB_WORKSPACE).
set -euo pipefail

SING_BOX_LX_REF="${SING_BOX_LX_REF:-lx}"
SING_VMESS_REF="${SING_VMESS_REF:-3aed155119a174c9290a4099841049f0cb275e02}"
PARENT="$(cd .. && pwd)"
VENDOR="$PARENT/vendor"
mkdir -p "$VENDOR"

LX_URL="https://github.com/ne-tort/sing-box-lx.git"
if [[ -n "${GH_PAT:-}" ]]; then
  LX_URL="https://x-access-token:${GH_PAT}@github.com/ne-tort/sing-box-lx.git"
fi
if [[ ! -d "$VENDOR/sing-box-lx/.git" ]]; then
  echo "Cloning ne-tort/sing-box-lx@$SING_BOX_LX_REF -> $VENDOR/sing-box-lx"
  git clone --filter=blob:none --branch "$SING_BOX_LX_REF" \
    "$LX_URL" "$VENDOR/sing-box-lx"
else
  echo "Updating sing-box-lx to $SING_BOX_LX_REF"
  git -C "$VENDOR/sing-box-lx" fetch --filter=blob:none "$LX_URL" "$SING_BOX_LX_REF"
  git -C "$VENDOR/sing-box-lx" checkout -q FETCH_HEAD
fi
git -C "$VENDOR/sing-box-lx" submodule update --init --recursive --depth 1

if [[ ! -d "$VENDOR/sing-vmess/.git" ]]; then
  echo "Cloning SagerNet/sing-vmess -> $VENDOR/sing-vmess"
  git clone --filter=blob:none https://github.com/SagerNet/sing-vmess.git "$VENDOR/sing-vmess"
fi
echo "Checking out sing-vmess@$SING_VMESS_REF"
git -C "$VENDOR/sing-vmess" fetch --filter=blob:none origin "$SING_VMESS_REF"
git -C "$VENDOR/sing-vmess" checkout -q "$SING_VMESS_REF"

test -f "$VENDOR/sing-box-lx/.github/CRONET_GO_VERSION"
echo "OK: vendor siblings ready"
ls -la "$VENDOR"
