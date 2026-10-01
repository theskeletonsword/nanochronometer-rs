#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Cross-compiles NanoChronometer for Android: shared and static libraries plus
# the CLI, for all four ABIs.
#
# Nothing here is hardcoded into the repository. The NDK path comes from
# ANDROID_NDK_HOME (or ANDROID_NDK_ROOT, or ~/toolchains/android-ndk), and the
# toolchain variables are exported per invocation, so a checkout stays portable.
#
# Usage:
#   packaging/android/build.sh                 # all ABIs
#   packaging/android/build.sh arm64-v8a       # one ABI
#   ANDROID_API=24 packaging/android/build.sh  # raise the minimum API level
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out_dir="${repo_root}/build/android"
# Where cargo builds. The repository may sit on a filesystem that corrupts
# incremental caches (exFAT), so a caller can point this somewhere else.
target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"

# API 21 is the NDK r27 floor and covers every device still receiving apps.
api="${ANDROID_API:-21}"

ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${HOME}/toolchains/android-ndk}}"
if [[ ! -f "${ndk}/source.properties" ]]; then
    echo "error: no Android NDK at ${ndk}" >&2
    echo "       set ANDROID_NDK_HOME to your NDK directory" >&2
    exit 1
fi

host_tag="linux-x86_64"
case "$(uname -s)" in
    Darwin) host_tag="darwin-x86_64" ;;
esac
toolchain="${ndk}/toolchains/llvm/prebuilt/${host_tag}"
bin="${toolchain}/bin"
if [[ ! -d "${bin}" ]]; then
    echo "error: no prebuilt toolchain at ${toolchain}" >&2
    exit 1
fi

ndk_version="$(sed -n 's/^Pkg.Revision *= *//p' "${ndk}/source.properties")"
echo "NDK ${ndk_version} at ${ndk}, minimum API ${api}"
echo

# ABI name -> Rust target, clang wrapper prefix
#
# The clang wrapper prefix is not always the Rust triple: armeabi-v7a builds
# with `armv7a-linux-androideabi`, while Rust calls the target
# `armv7-linux-androideabi`.
declare -A rust_target=(
    [arm64-v8a]=aarch64-linux-android
    [armeabi-v7a]=armv7-linux-androideabi
    [x86_64]=x86_64-linux-android
    [x86]=i686-linux-android
)
declare -A clang_prefix=(
    [arm64-v8a]=aarch64-linux-android
    [armeabi-v7a]=armv7a-linux-androideabi
    [x86_64]=x86_64-linux-android
    [x86]=i686-linux-android
)

abis=("$@")
if [[ ${#abis[@]} -eq 0 ]]; then
    abis=(arm64-v8a armeabi-v7a x86_64 x86)
fi

# No build-machine path in what ships (packaging/remap-paths.sh).
# shellcheck source=packaging/remap-paths.sh
source "${repo_root}/packaging/remap-paths.sh"
remap="$(remap_rustflags "${repo_root}")"
# A pkg-config file per ABI (packaging/pkgconfig.sh).
# shellcheck source=packaging/pkgconfig.sh
source "${repo_root}/packaging/pkgconfig.sh"
# Debug information in files of its own (packaging/debuginfo.sh).
# shellcheck source=packaging/debuginfo.sh
source "${repo_root}/packaging/debuginfo.sh"
debug_objcopy >/dev/null || exit 1
version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1)"
# OPT= picks the optimisation level (packaging/opt-level.sh); default -O2.
# shellcheck source=packaging/opt-level.sh
source "${repo_root}/packaging/opt-level.sh"
set_opt_args dist

# A target with no prebuilt standard library (x86_64-linux-android on some
# nightlies) gets one built from rust-src, which needs a nightly `cargo`.
sysroot="$(rustc --print sysroot)"

# Archiver and ranlib are ABI-independent in a unified NDK toolchain.
export AR="${bin}/llvm-ar"
export RANLIB="${bin}/llvm-ranlib"

for abi in "${abis[@]}"; do
    target="${rust_target[${abi}]:-}"
    if [[ -z "${target}" ]]; then
        echo "error: unknown ABI '${abi}' (expected one of: ${!rust_target[*]})" >&2
        exit 1
    fi

    cc="${bin}/${clang_prefix[${abi}]}${api}-clang"
    if [[ ! -x "${cc}" ]]; then
        echo "error: no compiler for ${abi} at API ${api}: ${cc}" >&2
        exit 1
    fi

    # Cargo reads the linker from CARGO_TARGET_<TRIPLE>_LINKER, uppercased with
    # dashes turned into underscores. The `cc` crate reads CC_<triple> with the
    # triple spelled exactly as Rust spells it.
    linker_var="CARGO_TARGET_$(echo "${target}" | tr 'a-z-' 'A-Z_')_LINKER"

    echo "=== ${abi} (${target}) ==="
    build_env=(
        "${linker_var}=${cc}"
        "CC_${target}=${cc}"
        "AR_${target}=${AR}"
        "RANLIB_${target}=${RANLIB}"
        "CARGO_TARGET_$(echo "${target}" | tr 'a-z-' 'A-Z_')_RUSTFLAGS=${remap} --print native-static-libs"
        "CFLAGS_${target}=$(remap_cflags "${repo_root}")"
    )

    extra=()
    if [[ ! -d "${sysroot}/lib/rustlib/${target}" ]]; then
        extra=(-Zbuild-std=std,panic_abort)
        echo "    (no prebuilt std for ${target}; building it from rust-src)"
    fi

    # Dynamically linked against bionic: the shared library an app loads, and
    # the static archive an NDK build links.
    env "${build_env[@]}" \
        cargo build --profile dist "${OPT_ARGS[@]}" --target "${target}" "${extra[@]}" \
            --manifest-path "${repo_root}/Cargo.toml" \
            --target-dir "${target_dir}" \
            -p nanochrono-ffi -p nanochrono-cli 2>&1 | tee "${target_dir}/${target}.native.log"

    # Each ABI is an install prefix of its own: bin/, lib64/ (lib/ for the
    # 32-bit ABIs) and include/nanochrono.h beside it.
    staging="${out_dir}/${abi}"
    libdir="lib64"
    case "${abi}" in armeabi-v7a | x86) libdir="lib" ;; esac
    rm -rf "${staging}"
    mkdir -p "${staging}/bin" "${staging}/${libdir}"
    install -m644 "${target_dir}/${target}/dist/libnanochrono.so" "${staging}/${libdir}/"
    install -m644 "${target_dir}/${target}/dist/libnanochrono.a"  "${staging}/${libdir}/"
    install -m755 "${target_dir}/${target}/dist/nanochrono"       "${staging}/bin/"
    write_pc "${staging}" "${libdir}" "$(native_libs "${target_dir}/${target}.native.log")" "${version}"

    # A second, statically linked CLI. `adb push` plus `chmod +x` is enough to
    # run this on any device of the right ABI — no library path to arrange, and
    # no dependency on the device's bionic version.
    #
    # Two things NDK r30's static libc.a needs that rustc's -nodefaultlibs link
    # does not bring:
    #  * It carries a Rust standard library of its own (bionic has Rust parts),
    #    with its own `rust_eh_personality`, so the link sees that symbol
    #    twice. Both are Rust's GCC personality routine; the program's own
    #    comes first on the link line and is the one kept.
    #  * Its clone() calls compiler-rt's SME support (`__arm_za_disable` on
    #    arm64), which the NDK's clang would link by default. The driver names
    #    the builtins archive for this ABI.
    builtins="$("${cc}" -rtlib=compiler-rt --print-libgcc-file-name)"
    env "${build_env[@]}" \
        RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--allow-multiple-definition -C link-arg=${builtins} ${remap}" \
        cargo build --profile dist "${OPT_ARGS[@]}" --target "${target}" "${extra[@]}" \
            --manifest-path "${repo_root}/Cargo.toml" \
            --target-dir "${target_dir}/static-android" \
            -p nanochrono-cli
    install -m755 "${target_dir}/static-android/${target}/dist/nanochrono" \
        "${staging}/bin/nanochrono-static"

    # The GUI is deliberately excluded: iced needs a windowing system, and
    # Android's is not one winit drives from a plain executable.
    #
    # Nothing is stripped of its symbols — nothing shipped looks as though it
    # hides what it is — but the debug information goes to files of its own
    # (packaging/debuginfo.sh), to keep the release light.
    for f in "${staging}/bin/nanochrono" "${staging}/bin/nanochrono-static" \
             "${staging}/${libdir}/libnanochrono.so"; do
        split_debug "${f}" || { echo "error: could not split the debug information of ${f}" >&2; exit 1; }
    done
    split_debug_archive "${staging}" "${libdir}" libnanochrono.a ||
        { echo "error: could not split the debug information of libnanochrono.a" >&2; exit 1; }
    echo
done

# The header is generated from the Rust FFI crate, never hand-written.
"${repo_root}/tools/gen-header.sh"
for abi in "${abis[@]}"; do
    install -Dm644 "${repo_root}/include/nanochrono.h" "${out_dir}/${abi}/include/nanochrono.h"
done
install -Dm644 "${repo_root}/LICENSE"              "${out_dir}/LICENSE"
install -Dm644 "${repo_root}/NOTICE"               "${out_dir}/NOTICE"

echo "=== build/android ==="
find "${out_dir}" -type f -printf '%-46p %8s bytes\n' | sort
