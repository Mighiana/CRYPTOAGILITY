#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="${CRYPTOAGILITY_TOOLS_DIR:-$ROOT/.tools}"
VERSION=3.5.9
SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
PREFIX="$TOOLS/openssl"
if [[ -x "$PREFIX/bin/openssl" ]] && "$PREFIX/bin/openssl" version | grep -q "OpenSSL $VERSION "; then
    exit 0
fi
mkdir -p "$TOOLS/cache"
ARCHIVE="$TOOLS/cache/openssl-$VERSION.tar.gz"
verify() { printf '%s  %s\n' "$SHA256" "$1" | sha256sum --check --status -; }
if [[ -f "$ARCHIVE" ]] && ! verify "$ARCHIVE"; then
    echo "Cached OpenSSL archive failed checksum; re-downloading" >&2
    rm -f "$ARCHIVE"
fi
if [[ ! -f "$ARCHIVE" ]]; then
    PARTIAL="$(mktemp "$TOOLS/cache/openssl-$VERSION.XXXXXX.part")"
    trap 'rm -f "$PARTIAL"' EXIT
    curl --fail --location --retry 3 --max-time 180 \
        "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz" \
        --output "$PARTIAL"
    verify "$PARTIAL" || { echo "Downloaded OpenSSL archive failed checksum" >&2; exit 1; }
    mv "$PARTIAL" "$ARCHIVE"
    trap - EXIT
fi
rm -rf "$TOOLS/cache/openssl-$VERSION"
tar -xzf "$ARCHIVE" -C "$TOOLS/cache"
cd "$TOOLS/cache/openssl-$VERSION"
./Configure --prefix="$PREFIX" --openssldir="$PREFIX/ssl" no-shared no-tests
make -j "${BUILD_JOBS:-4}"
make install_sw
"$PREFIX/bin/openssl" version -a
