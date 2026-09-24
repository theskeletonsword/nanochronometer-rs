#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Signs the built drivers with the test certificate using osslsigncode
# (Linux side). Run `make all` first, then `make sign`.
#
# Output: build/signed/{x64,arm64}/nanochrono.sys
#
# The .pfx is created by certs/make-test-cert.sh and is never committed.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

OUT="build/signed"
KEYS="certs-private"

command -v osslsigncode >/dev/null || {
    echo "osslsigncode not found (dnf install osslsigncode)" >&2
    exit 1
}

if [[ ! -f "$KEYS/nanochrono-test.pfx" ]]; then
    echo "== generating test certificate ($KEYS/ is gitignored) =="
    certs/make-test-cert.sh
fi

mkdir -p "$OUT"

for a in x64 arm64; do
    f="build/$a/nanochrono.sys"
    [[ -f "$f" ]] || { echo "missing $f — run 'make all' first" >&2; exit 1; }
    base="$a/nanochrono.sys"
    mkdir -p "$OUT/$a"
    echo "== signing $f"
    rm -f "$OUT/$base"
    osslsigncode sign \
        -certs "$KEYS/nanochrono-test.pem" \
        -key "$KEYS/nanochrono-test.key" \
        -h sha256 \
        -n "NanoChronometer test driver" \
        -i "https://github.com/skels/nanochronometer" \
        -in "$f" \
        -out "$OUT/$base"
done

echo "== verifying signatures"
for f in "$OUT"/*/nanochrono.sys; do
    echo "--- $f"
    osslsigncode verify -CAfile "$KEYS/nanochrono-test.pem" "$f" | grep -E "Signature verification|Verifying|error|ok" | head -n 6
done

echo "== done: signed drivers in $OUT"