#!/bin/sh
# Checks install.sh against a local fake release built from dist/.
#   goreleaser release --snapshot --clean && sh scripts/test-install.sh
# Serves dist/ on 127.0.0.1 only. Nothing is downloaded from the internet.
set -eu
cd "$(dirname "$0")/.."
ver=$(sed -n 's/.*"version":"\([^"]*\)".*/\1/p' dist/metadata.json)
[ -n "$ver" ] || { echo "run goreleaser release --snapshot --clean first" >&2; exit 1; }
work=$(mktemp -d)
port=18099
cleanup() { kill "$srv" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT INT TERM
mkdir -p "$work/rel/v$ver" "$work/rel/v9.9.9"
cp dist/*.tar.gz dist/checksums.txt "$work/rel/v$ver/"
(cd "$work/rel" && exec python3 -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1) &
srv=$!
sleep 1
base="http://127.0.0.1:$port"

TATTLR_VERSION="$ver" TATTLR_BASE_URL="$base" TATTLR_INSTALL_DIR="$work/bin" sh ./install.sh
"$work/bin/tattlr" version | grep -q "$ver" || { echo "FAIL: installed binary has the wrong version" >&2; exit 1; }
echo "ok: installs and verifies"

# Same archive under another name with a wrong checksum: must refuse.
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m); case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
cp "dist/tattlr_${ver}_${os}_${arch}.tar.gz" "$work/rel/v9.9.9/tattlr_9.9.9_${os}_${arch}.tar.gz"
echo "0000000000000000000000000000000000000000000000000000000000000000  tattlr_9.9.9_${os}_${arch}.tar.gz" >"$work/rel/v9.9.9/checksums.txt"
if TATTLR_VERSION=v9.9.9 TATTLR_BASE_URL="$base" TATTLR_INSTALL_DIR="$work/bad" sh ./install.sh 2>/dev/null; then
	echo "FAIL: installed despite a bad checksum" >&2; exit 1
fi
[ ! -e "$work/bad/tattlr" ] || { echo "FAIL: binary left behind" >&2; exit 1; }
echo "ok: refuses a bad checksum"
