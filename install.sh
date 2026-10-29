#!/bin/sh
# Install tattlr from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/kaygaaf/tattlr/main/install.sh | sh
#
# Settings (all optional):
#   TATTLR_VERSION      tag to install, like v0.1.0. Default: the latest release.
#   TATTLR_INSTALL_DIR  where the binary goes. Default: ~/.local/bin
#   TATTLR_BASE_URL     release download root, for mirrors and testing.
#                       Needs TATTLR_VERSION. Files are read from
#                       $TATTLR_BASE_URL/<tag>/<file>.
#
# It downloads one archive plus checksums.txt, checks the sha256, and copies
# one binary. No sudo unless you point TATTLR_INSTALL_DIR somewhere that needs
# it and run the script with sudo yourself.

set -eu

REPO="kaygaaf/tattlr"
VERSION="${TATTLR_VERSION:-}"
INSTALL_DIR="${TATTLR_INSTALL_DIR:-$HOME/.local/bin}"
BASE_URL="${TATTLR_BASE_URL:-https://github.com/$REPO/releases/download}"

say() { printf 'tattlr: %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "needs $1, which is not installed"; }

fetch() { # fetch URL FILE
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https,http' -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "needs curl or wget"
	fi
}

latest_tag() {
	# /releases/latest redirects to /releases/tag/vX.Y.Z. Following the
	# redirect avoids the rate limited API.
	url="https://github.com/$REPO/releases/latest"
	if command -v curl >/dev/null 2>&1; then
		final=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$url") || return 1
	else
		final=$(wget -q -S --max-redirect=5 -O /dev/null "$url" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r')
	fi
	tag=${final##*/}
	case "$tag" in
		v[0-9]*) printf '%s\n' "$tag" ;;
		*) return 1 ;;
	esac
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$1" | sed 's/^.*= *//'
	else
		die "needs sha256sum, shasum or openssl to check the download"
	fi
}

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
	linux | darwin) ;;
	mingw* | msys* | cygwin*) die "on Windows, grab the zip from https://github.com/$REPO/releases or use: npm i -g tattlr" ;;
	*) die "no prebuilt binary for $os. Try: go install github.com/$REPO/cmd/tattlr@latest" ;;
esac

arch=$(uname -m)
case "$arch" in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) die "no prebuilt binary for $arch. Try: go install github.com/$REPO/cmd/tattlr@latest" ;;
esac

need tar
need uname

if [ -z "$VERSION" ]; then
	[ -z "${TATTLR_BASE_URL:-}" ] || die "TATTLR_BASE_URL needs TATTLR_VERSION too"
	VERSION=$(latest_tag) || die "could not find the latest release. Set TATTLR_VERSION=v0.1.0 or check https://github.com/$REPO/releases"
fi
case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac
num=${VERSION#v}

archive="tattlr_${num}_${os}_${arch}.tar.gz"
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t tattlr)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $archive ($VERSION)"
fetch "$BASE_URL/$VERSION/$archive" "$tmp/$archive" || die "download failed: $BASE_URL/$VERSION/$archive"
fetch "$BASE_URL/$VERSION/checksums.txt" "$tmp/checksums.txt" || die "could not get checksums.txt for $VERSION"

want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || die "$archive is not listed in checksums.txt"
got=$(sha256_of "$tmp/$archive")
[ "$want" = "$got" ] || die "checksum mismatch for $archive (want $want, got $got). Not installing."
say "checksum ok"

tar -xzf "$tmp/$archive" -C "$tmp" tattlr || die "could not unpack $archive"
mkdir -p "$INSTALL_DIR"
# Copy then rename so a running tattlr is never half overwritten.
cp "$tmp/tattlr" "$INSTALL_DIR/.tattlr.new"
chmod 755 "$INSTALL_DIR/.tattlr.new"
mv -f "$INSTALL_DIR/.tattlr.new" "$INSTALL_DIR/tattlr"

say "installed $("$INSTALL_DIR/tattlr" version 2>/dev/null || echo tattlr) to $INSTALL_DIR/tattlr"
case ":$PATH:" in
	*":$INSTALL_DIR:"*) ;;
	*) say "$INSTALL_DIR is not on your PATH. Add this to your shell profile:"
	   say "  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
say "next: run tattlr"
