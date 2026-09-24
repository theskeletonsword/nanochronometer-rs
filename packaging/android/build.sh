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
out_dir="${repo_root}/dist/android"

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
    )

    # Dynamically linked against bionic: the shared library an app loads, and
    # the static archive an NDK build links.
    env "${build_env[@]}" \
        cargo build --profile dist --target "${target}" \
            --manifest-path "${repo_root}/Cargo.toml" \
            -p nanochrono-ffi -p nanochrono-cli

    staging="${out_dir}/${abi}"
    mkdir -p "${staging}"
    install -m644 "${repo_root}/target/${target}/dist/libnanochrono.so" "${staging}/"
    install -m644 "${repo_root}/target/${target}/dist/libnanochrono.a"  "${staging}/"
    install -m755 "${repo_root}/target/${target}/dist/nanochrono"       "${staging}/"

    # A second, statically linked CLI. `adb push` plus `chmod +x` is enough to
    # run this on any device of the right ABI — no library path to arrange, and
    # no dependency on the device's bionic version.
    env "${build_env[@]}" RUSTFLAGS="-C target-feature=+crt-static" \
        cargo build --profile dist --target "${target}" \
            --manifest-path "${repo_root}/Cargo.toml" \
            --target-dir "${repo_root}/target/static-android" \
            -p nanochrono-cli
    install -m755 "${repo_root}/target/static-android/${target}/dist/nanochrono" \
        "${staging}/nanochrono-static"

    # The GUI is deliberately excluded: iced needs a windowing system, and
    # Android's is not one winit drives from a plain executable.
    #
    # Stripping is what makes these shippable: debug info dominates the size of
    # a Rust cdylib and an Android package has no use for it.
    "${bin}/llvm-strip" --strip-unneeded \
        "${staging}/libnanochrono.so" \
        "${staging}/nanochrono" \
        "${staging}/nanochrono-static"
    echo
done

# The header is generated from the Rust FFI crate, never hand-written.
"${repo_root}/tools/gen-header.sh"
install -Dm644 "${repo_root}/include/nanochrono.h" "${out_dir}/include/nanochrono.h"
install -Dm644 "${repo_root}/LICENSE"              "${out_dir}/LICENSE"
install -Dm644 "${repo_root}/NOTICE"               "${out_dir}/NOTICE"

echo "=== dist/android ==="
find "${out_dir}" -type f -printf '%-46p %8s bytes\n' | sort
