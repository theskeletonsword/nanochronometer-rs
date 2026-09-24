#!/usr/bin/env bash
# Installs NanoChronometer for the current user.
#
# Everything lands under ~/.local, so no root is required and an uninstall is
# just removing the same paths. Pass --system to install under /usr/local
# instead, which does need root.
set -euo pipefail

prefix="${HOME}/.local"
if [[ "${1:-}" == "--system" ]]; then
    prefix="/usr/local"
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
app_id="io.nanochronometer.NanoChrono"

echo "Building release binaries..."
cargo build --profile dist --manifest-path "${repo_root}/Cargo.toml" \
    -p nanochrono-cli -p nanochrono-gui -p nanochrono-ffi

install -Dm755 "${repo_root}/target/dist/nanochrono"     "${prefix}/bin/nanochrono"
install -Dm755 "${repo_root}/target/dist/nanochrono-gui" "${prefix}/bin/nanochrono-gui"
install -Dm644 "${repo_root}/target/dist/libnanochrono.so" "${prefix}/lib/libnanochrono.so"
# The header is generated from the Rust FFI crate, never hand-written.
"${repo_root}/tools/gen-header.sh"
install -Dm644 "${repo_root}/include/nanochrono.h"          "${prefix}/include/nanochrono.h"

install -Dm644 "${repo_root}/packaging/linux/${app_id}.desktop" \
    "${prefix}/share/applications/${app_id}.desktop"

# The application icon.
#
# Extracted from assets/nanochrono.ico rather than kept as a second copy, so
# there is one drawing in the tree and Windows, macOS and Linux all get the
# same one.
#
# The SVG in assets/ is deliberately *not* used here. It is a 1020x225
# wordmark — a banner, not an icon — and installing it as `scalable/apps`
# made things worse than having no icon at all: icon themes prefer scalable
# over bitmap, so it won over anything else, and a 4.5:1 banner squeezed into
# a square slot renders as an illegible smear of lettering. That is what a
# desktop showing a stray letter instead of the logo is showing.
# An older version of this script installed that banner as
# scalable/apps/<app_id>.svg. Icon themes prefer scalable over bitmap, so it
# would keep winning over everything installed below and the upgrade would
# appear to do nothing. Removed rather than left to shadow the real icon.
rm -f "${prefix}/share/icons/hicolor/scalable/apps/${app_id}.svg"

icon_png="$(mktemp -t nanochrono-icon-XXXXXX.png)"
trap 'rm -f "${icon_png}"' EXIT
python3 "${repo_root}/tools/extract-icon.py" \
    "${repo_root}/assets/nanochrono.ico" "${icon_png}"

# 512 is the source size and every desktop will scale it down. Installing it
# alone is correct; the loop below only adds crisper small sizes when a
# resizer happens to be present, because a panel icon downscaled from 512 in
# one step is softer than one rendered for its size.
install -Dm644 "${icon_png}" \
    "${prefix}/share/icons/hicolor/512x512/apps/${app_id}.png"

resize=""
if command -v magick >/dev/null 2>&1; then
    resize="magick"
elif command -v convert >/dev/null 2>&1; then
    resize="convert"
fi
if [[ -n "${resize}" ]]; then
    for size in 16 22 24 32 48 64 128 256; do
        sized="$(mktemp -t nanochrono-icon-${size}-XXXXXX.png)"
        if "${resize}" "${icon_png}" -resize "${size}x${size}" "${sized}" 2>/dev/null; then
            install -Dm644 "${sized}" \
                "${prefix}/share/icons/hicolor/${size}x${size}/apps/${app_id}.png"
        fi
        rm -f "${sized}"
    done
fi

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "${prefix}/share/applications" || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "${prefix}/share/icons/hicolor" 2>/dev/null || true
fi
# KDE keeps its own index of desktop entries, and Plasma's task manager reads
# the window icon out of that rather than off the filesystem. Without this,
# a freshly installed entry is not found until the next login — which looks
# exactly like the install having failed.
for sycoca in kbuildsycoca6 kbuildsycoca5; do
    if command -v "${sycoca}" >/dev/null 2>&1; then
        "${sycoca}" --noincremental >/dev/null 2>&1 || true
        break
    fi
done

echo
echo "Installed to ${prefix}"
echo "  nanochrono-gui   desktop application"
echo "  nanochrono       command-line toolkit"
echo "  libnanochrono.so C ABI for the language wrappers"
echo
if [[ ":${PATH}:" != *":${prefix}/bin:"* ]]; then
    echo "Note: ${prefix}/bin is not on PATH."
fi
