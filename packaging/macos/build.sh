#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Cross-compiles NanoChronometer for macOS: the CLI, the GUI as a .app bundle,
# and shared and static libraries — for Apple Silicon, Intel, and as universal
# binaries carrying both.
#
# Nothing here is hardcoded into the repository. The osxcross path comes from
# OSXCROSS_ROOT (or ~/toolchains/mac, or ~/toolchains/osxcross), and the SDK
# and target triple are discovered from what is installed, so a checkout stays
# portable and does not go stale when the SDK is updated.
#
# Usage:
#   packaging/macos/build.sh              # both architectures, plus universal
#   packaging/macos/build.sh arm64        # Apple Silicon only
#   packaging/macos/build.sh x86_64       # Intel only
#
# Building on a Mac works too: with no osxcross present it falls through to the
# native toolchain, which is what `cargo build --target` would use anyway.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out_dir="${repo_root}/dist/macos"

# The deployment target. 11.0 is the first release that ran on Apple Silicon,
# so it is the floor for a universal binary; going lower would build an arm64
# slice that no machine can run.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"

native_darwin=0
[[ "$(uname -s)" == "Darwin" ]] && native_darwin=1

osxcross="${OSXCROSS_ROOT:-}"
if [[ -z "${osxcross}" ]]; then
    for candidate in "${HOME}/toolchains/mac" "${HOME}/toolchains/osxcross"; do
        [[ -d "${candidate}/bin" ]] && { osxcross="${candidate}"; break; }
    done
fi

if [[ -n "${osxcross}" && -d "${osxcross}/bin" ]]; then
    export PATH="${osxcross}/bin:${PATH}"
    # The SDK directory names its own version, and the clang wrappers carry the
    # Darwin release in their filename. Both are discovered rather than
    # written down, so updating osxcross does not silently break this.
    sdk="$(find "${osxcross}/SDK" -maxdepth 1 -name 'MacOSX*.sdk' | sort -V | tail -1)"
    if [[ -z "${sdk}" ]]; then
        echo "error: no MacOSX SDK under ${osxcross}/SDK" >&2
        exit 1
    fi
    export SDKROOT="${sdk}"
    darwin_ver="$(basename "$(find "${osxcross}/bin" -name 'x86_64-apple-darwin*-clang' | head -1)" \
                  | sed 's/^x86_64-apple-\(darwin[0-9.]*\)-clang$/\1/')"
    echo "osxcross at ${osxcross}"
    echo "SDK        $(basename "${sdk}")"
    echo "host tools ${darwin_ver}"
elif [[ ${native_darwin} -eq 1 ]]; then
    echo "building natively on macOS"
    darwin_ver=""
else
    echo "error: no osxcross toolchain found" >&2
    echo "       set OSXCROSS_ROOT, or install to ~/toolchains/mac" >&2
    exit 1
fi
echo "deployment target ${MACOSX_DEPLOYMENT_TARGET}"
echo

# `lipo` glues the two slices together. osxcross prefixes it; a Mac has it bare.
lipo_bin="lipo"
[[ -n "${darwin_ver}" ]] && lipo_bin="x86_64-apple-${darwin_ver}-lipo"

# Architecture -> Rust target, osxcross clang wrapper.
declare -A arch_target=(
    [arm64]="aarch64-apple-darwin"
    [x86_64]="x86_64-apple-darwin"
)
declare -A arch_clang=(
    [arm64]="oa64-clang"
    [x86_64]="o64-clang"
)

requested=("$@")
[[ ${#requested[@]} -eq 0 ]] && requested=(arm64 x86_64)

rm -rf "${out_dir}"
mkdir -p "${out_dir}"

built=()
for arch in "${requested[@]}"; do
    target="${arch_target[${arch}]:-}"
    if [[ -z "${target}" ]]; then
        echo "error: unknown architecture '${arch}' (want arm64 or x86_64)" >&2
        exit 1
    fi

    if [[ -n "${darwin_ver}" ]]; then
        # Cargo reads these per-target, upper-cased with dashes as underscores;
        # `cc` reads the lower-case forms. Both are set so a dependency with a
        # build script links with the same toolchain as the crate.
        upper="$(echo "${target}" | tr 'a-z-' 'A-Z_')"
        export "CARGO_TARGET_${upper}_LINKER=${arch_clang[${arch}]}"
        export "CC_${target//-/_}=${arch_clang[${arch}]}"
        export "AR_${target//-/_}=${arch}-apple-${darwin_ver}-ar"
    fi

    echo "=== ${arch} (${target})"
    rustup target add "${target}" >/dev/null 2>&1 || true
    cargo build --profile dist --target "${target}" \
        -p nanochrono-cli -p nanochrono-ffi -p nanochrono-gui

    src="${repo_root}/target/${target}/dist"
    dst="${out_dir}/${arch}"
    mkdir -p "${dst}"
    cp "${src}/nanochrono" "${dst}/"
    cp "${src}/nanochrono-gui" "${dst}/"
    cp "${src}/libnanochrono.dylib" "${dst}/"
    cp "${src}/libnanochrono.a" "${dst}/"
    built+=("${arch}")
done

# A universal binary is only possible with both slices present.
if [[ ${#built[@]} -eq 2 ]]; then
    echo
    echo "=== universal (arm64 + x86_64)"
    mkdir -p "${out_dir}/universal"
    for artifact in nanochrono nanochrono-gui libnanochrono.dylib libnanochrono.a; do
        "${lipo_bin}" -create \
            "${out_dir}/arm64/${artifact}" \
            "${out_dir}/x86_64/${artifact}" \
            -output "${out_dir}/universal/${artifact}"
    done
fi

# The GUI is only launchable from Finder as a bundle: macOS refuses to give a
# bare executable a Dock icon or keyboard focus, so it would start without a
# usable window. The CLI needs no such thing.
make_app_bundle() {
    local arch_dir="$1"
    local app="${arch_dir}/NanoChronometer.app"
    mkdir -p "${app}/Contents/MacOS" "${app}/Contents/Resources"
    cp "${arch_dir}/nanochrono-gui" "${app}/Contents/MacOS/NanoChronometer"

    # The Dock and Finder icon. Built from the same assets/nanochrono.ico that
    # Windows and Linux use, so there is one drawing in the tree.
    #
    # Written by a script rather than by `iconutil`, which is macOS-only:
    # cross-compiling from Linux is the normal case here, and a bundle that
    # silently shipped without an icon whenever it was built on the wrong host
    # is exactly the kind of thing nobody notices until it is released.
    python3 "${repo_root}/tools/extract-icon.py" \
        "${repo_root}/assets/nanochrono.ico" \
        "${app}/Contents/Resources/NanoChronometer.icns"

    sed -e "s/@VERSION@/${version}/g" \
        "${repo_root}/packaging/macos/Info.plist.in" \
        > "${app}/Contents/Info.plist"
    printf 'APPL????' > "${app}/Contents/PkgInfo"
}

version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1)"
for dir in "${out_dir}"/*/; do
    [[ -f "${dir}/nanochrono-gui" ]] && make_app_bundle "${dir%/}"
done

# The header the C ABI is consumed through, generated from the Rust source.
"${repo_root}/tools/gen-header.sh" >/dev/null
mkdir -p "${out_dir}/include"
cp "${repo_root}/include/nanochrono.h" "${out_dir}/include/"
cp "${repo_root}/LICENSE" "${repo_root}/NOTICE" "${out_dir}/"

echo
echo "=== ${out_dir}"
find "${out_dir}" -maxdepth 2 \( -type f -o -name '*.app' \) -print0 \
    | sort -z | while IFS= read -r -d '' path; do
    if [[ -d "${path}" ]]; then
        printf '%s  (bundle)\n' "${path}"
    else
        printf '%s  %s bytes\n' "${path}" "$(stat -c%s "${path}" 2>/dev/null || stat -f%z "${path}")"
    fi
done
