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
# The same layout packaging/release/build-all.sh writes: build/macos-aarch64,
# build/macos-x86_64 and build/macos-universal.
out_root="${repo_root}/build"
target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"

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
# Architecture -> output directory under build/.
declare -A arch_out=(
    [arm64]="macos-aarch64"
    [x86_64]="macos-x86_64"
)

requested=("$@")
[[ ${#requested[@]} -eq 0 ]] && requested=(arm64 x86_64)

# No build-machine path in what ships (packaging/remap-paths.sh).
# shellcheck source=packaging/remap-paths.sh
source "${repo_root}/packaging/remap-paths.sh"
remap="$(remap_rustflags "${repo_root}")"
# OPT= picks the optimisation level (packaging/opt-level.sh); default -O2.
# shellcheck source=packaging/opt-level.sh
source "${repo_root}/packaging/opt-level.sh"
set_opt_args dist
# Debug information in files of its own (packaging/debuginfo.sh).
# shellcheck source=packaging/debuginfo.sh
source "${repo_root}/packaging/debuginfo.sh"
debug_objcopy >/dev/null || exit 1
# A .dSYM per binary, shipped beside it (packaging/remap-paths.sh): the debug
# map written relative to $HOME, and a dsymutil that knows where that is.
dsym_tools="${target_dir}/macos-tools"
if remap_dsymutil "${dsym_tools}" "${osxcross:+${osxcross}/bin}"; then
    export PATH="${dsym_tools}:${PATH}"
    export CARGO_PROFILE_DIST_SPLIT_DEBUGINFO=packed
else
    echo "note: no dsymutil; the binaries ship without a .dSYM"
fi

# Only the directories this run rebuilds are cleared: build/ holds every other
# platform's release too.
produced=()
for arch in "${requested[@]}"; do
    [[ -n "${arch_out[${arch}]:-}" ]] && rm -rf "${out_root:?}/${arch_out[${arch}]}"
done
rm -rf "${out_root:?}/macos-universal"

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
        export "CFLAGS_${target//-/_}=$(remap_cflags "${repo_root}")"
        export "AR_${target//-/_}=${arch}-apple-${darwin_ver}-ar"
    fi

    export "CARGO_TARGET_$(echo "${target}" | tr 'a-z-' 'A-Z_')_RUSTFLAGS=${remap} $(remap_macos_rustflags)"

    echo "=== ${arch} (${target})"
    rustup target add "${target}" >/dev/null 2>&1 || true
    cargo build --profile dist "${OPT_ARGS[@]}" --target "${target}" \
        --target-dir "${target_dir}" \
        -p nanochrono-cli -p nanochrono-ffi -p nanochrono-gui

    src="${target_dir}/${target}/dist"
    # An install prefix: bin/, lib/ (Darwin has no lib64) and include/.
    dst="${out_root}/${arch_out[${arch}]}"
    mkdir -p "${dst}/bin" "${dst}/lib"
    cp "${src}/nanochrono" "${dst}/bin/"
    cp "${src}/nanochrono-gui" "${dst}/bin/"
    cp "${src}/libnanochrono.dylib" "${dst}/lib/"
    cp "${src}/libnanochrono.a" "${dst}/lib/"
    # The static library as built under debug/lib/, without its debug
    # sections in lib/ (packaging/debuginfo.sh).
    split_debug_archive "${dst}" lib libnanochrono.a
    # Each .dSYM beside its binary (Cargo links them into the profile
    # directory; -L copies the bundle, not the link).
    for f in bin/nanochrono bin/nanochrono-gui lib/libnanochrono.dylib; do
        [[ -e "${src}/$(basename "${f}").dSYM" ]] && cp -RL "${src}/$(basename "${f}").dSYM" "${dst}/${f}.dSYM"
    done
    built+=("${arch}")
    produced+=("${dst}")
done

# A universal binary is only possible with both slices present.
if [[ ${#built[@]} -eq 2 ]]; then
    echo
    echo "=== universal (arm64 + x86_64)"
    universal="${out_root}/macos-universal"
    mkdir -p "${universal}/bin" "${universal}/lib" "${universal}/debug/lib"
    for artifact in bin/nanochrono bin/nanochrono-gui lib/libnanochrono.dylib lib/libnanochrono.a \
                    debug/lib/libnanochrono.a; do
        "${lipo_bin}" -create \
            "${out_root}/macos-aarch64/${artifact}" \
            "${out_root}/macos-x86_64/${artifact}" \
            -output "${universal}/${artifact}"
    done
    # A .dSYM holds one DWARF file per binary, which joins the same way.
    for artifact in bin/nanochrono bin/nanochrono-gui lib/libnanochrono.dylib; do
        a="${out_root}/macos-x86_64/${artifact}.dSYM" b="${out_root}/macos-aarch64/${artifact}.dSYM"
        [[ -d "${a}" && -d "${b}" ]] || continue
        dwa="$(ls "${a}"/Contents/Resources/DWARF/* | head -1)"
        dwb="$(ls "${b}"/Contents/Resources/DWARF/* | head -1)"
        cp -R "${b}" "${universal}/${artifact}.dSYM"
        "${lipo_bin}" -create "${dwa}" "${dwb}" \
            -output "${universal}/${artifact}.dSYM/Contents/Resources/DWARF/$(basename "${dwb}")"
    done
    produced+=("${universal}")
fi

# The GUI is only launchable from Finder as a bundle: macOS refuses to give a
# bare executable a Dock icon or keyboard focus, so it would start without a
# usable window. The CLI needs no such thing.
make_app_bundle() {
    local arch_dir="$1"
    local app="${arch_dir}/NanoChronometer.app"
    mkdir -p "${app}/Contents/MacOS" "${app}/Contents/Resources"
    cp "${arch_dir}/bin/nanochrono-gui" "${app}/Contents/MacOS/NanoChronometer"

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
for dir in "${produced[@]}"; do
    [[ -f "${dir}/bin/nanochrono-gui" ]] && make_app_bundle "${dir}"
done

# The header the C ABI is consumed through, generated from the Rust source,
# next to each set of libraries.
"${repo_root}/tools/gen-header.sh" >/dev/null
for dir in "${produced[@]}"; do
    mkdir -p "${dir}/include"
    cp "${repo_root}/include/nanochrono.h" "${dir}/include/"
    cp "${repo_root}/LICENSE" "${repo_root}/NOTICE" "${dir}/"
done

echo
echo "=== ${produced[*]}"
find "${produced[@]}" -maxdepth 2 \( -type f -o -name '*.app' \) -print0 \
    | sort -z | while IFS= read -r -d '' path; do
    if [[ -d "${path}" ]]; then
        printf '%s  (bundle)\n' "${path}"
    else
        printf '%s  %s bytes\n' "${path}" "$(stat -c%s "${path}" 2>/dev/null || stat -f%z "${path}")"
    fi
done
