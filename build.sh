#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BUILD_TAGS="with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_naive_outbound,with_purego,badlinkname,tfogo_checklinkname0"

if command -v go >/dev/null 2>&1; then
  GO_CMD="go"
elif command -v go.exe >/dev/null 2>&1; then
  GO_CMD="go.exe"
else
  echo "Error: go/go.exe not found in PATH."
  exit 1
fi

VERSION="$("$GO_CMD" run ./cmd/internal/read_tag 2>/dev/null || true)"
if [[ -z "$VERSION" ]]; then
  VERSION="unknown"
fi

mkdir -p dist

CGO_ENABLED=0 \
GOOS=linux \
GOARCH=amd64 \
"$GO_CMD" build -v -trimpath \
  -o "dist/sing-box" \
  -tags "$BUILD_TAGS" \
  -ldflags "-s -buildid= -X github.com/sagernet/sing-box/constant.Version=${VERSION} -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0" \
  ./cmd/sing-box

echo "Built dist/sing-box (linux/amd64, version=${VERSION})"
echo "Note: CI additionally packages libcronet.so for naive outbound runtime."