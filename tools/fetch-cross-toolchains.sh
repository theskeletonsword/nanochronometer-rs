#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Downloads the cross toolchains the non-x86_64 Linux builds need: a C
# compiler for `ring` (pulled in by nanochrono-crypto) and a glibc sysroot to
# link and run against under qemu-user. Bootlin's prebuilt GCC + glibc
# toolchains, one per target, each checked against the sha256 Bootlin
# publishes next to it.
#
#   tools/fetch-cross-toolchains.sh            # all of them
#   tools/fetch-cross-toolchains.sh riscv64    # one
#   tools/fetch-cross-toolchains.sh mingw ndk  # Windows (i686) and Android
#
# `mingw` is llvm-mingw (clang + MinGW-w64 headers and import libraries),
# which both compiles `ring` for Windows and links windows-gnu binaries that
# then run under Wine. `ndk` is Google's Android NDK, for the Android
# targets; a statically linked Android binary also runs on a Linux host
# (natively for i686, under qemu-arm for armv7).
#
# Then `source tools/cross-env.sh` and build with `--target <triple>`.
set -euo pipefail

release="${BOOTLIN_RELEASE:-stable-2026.08-1}"
dest="${NANOCHRONO_TOOLCHAINS:-${HOME}/.cache/nanochrono/toolchains}"
base="https://toolchains.bootlin.com/downloads/releases/toolchains"

declare -A bootlin=(
    [ppc64le]="powerpc64le-power8"
    [ppc64]="powerpc64-power8"
    [ppc]="powerpc-e300c3"
    [riscv64]="riscv64-lp64d"
    [riscv32]="riscv32-ilp32d"
    [armv7]="armv7-eabihf"
    [aarch64]="aarch64"
    [i686]="x86-i686"
)

mingw_release="${LLVM_MINGW_RELEASE:-20260922}"
ndk_release="${ANDROID_NDK_RELEASE:-r30}"
ndk_sha1="${ANDROID_NDK_SHA1:-5107f898313790e449e87eee2183d9a20602dee9}"

fetch_mingw() {
    local name="llvm-mingw-${mingw_release}-ucrt-ubuntu-22.04-x86_64"
    [[ -d "${dest}/${name}" ]] && { echo "=== mingw: already at ${dest}/${name}"; return; }
    local url="https://github.com/mstorsjo/llvm-mingw/releases/download/${mingw_release}/${name}.tar.xz"
    echo "=== mingw: ${name}"
    curl -fL --retry 3 -o "${dest}/${name}.tar.xz" "${url}"
    # GitHub publishes a sha256 digest for every release asset.
    local digest
    digest="$(curl -fsSL "https://api.github.com/repos/mstorsjo/llvm-mingw/releases/tags/${mingw_release}" \
        | grep -A30 "\"name\": \"${name}.tar.xz\"" | grep -oE 'sha256:[0-9a-f]{64}' | head -1 | cut -d: -f2)"
    if [[ -n "${digest}" ]]; then
        echo "${digest}  ${dest}/${name}.tar.xz" | sha256sum -c -
    else
        echo "warning: no published digest found for ${name}; not verified" >&2
    fi
    tar -C "${dest}" -xJf "${dest}/${name}.tar.xz"
    rm -f "${dest}/${name}.tar.xz"
}

fetch_ndk() {
    local name="android-ndk-${ndk_release}"
    [[ -d "${dest}/${name}" ]] && { echo "=== ndk: already at ${dest}/${name}"; return; }
    echo "=== ndk: ${name}"
    curl -fL --retry 3 -o "${dest}/${name}-linux.zip" "https://dl.google.com/android/repository/${name}-linux.zip"
    echo "${ndk_sha1}  ${dest}/${name}-linux.zip" | sha1sum -c -
    (cd "${dest}" && unzip -q "${name}-linux.zip")
    rm -f "${dest}/${name}-linux.zip"
}

wanted=("$@")
[[ ${#wanted[@]} -eq 0 ]] && wanted=("${!bootlin[@]}" mingw ndk)

mkdir -p "${dest}"
for key in "${wanted[@]}"; do
    case "${key}" in
        mingw) fetch_mingw; continue ;;
        ndk) fetch_ndk; continue ;;
    esac
    name="${bootlin[${key}]:-}"
    if [[ -z "${name}" ]]; then
        echo "error: unknown toolchain '${key}' (want: ${!bootlin[*]} mingw ndk)" >&2
        exit 1
    fi
    dir="${name}--glibc--${release}"
    if [[ -d "${dest}/${dir}" ]]; then
        echo "=== ${key}: already at ${dest}/${dir}"
        continue
    fi
    tarball="${dir}.tar.xz"
    echo "=== ${key}: ${tarball}"
    curl -fL --retry 3 -o "${dest}/${tarball}" "${base}/${name}/tarballs/${tarball}"
    curl -fsSL -o "${dest}/${tarball}.sha256" "${base}/${name}/tarballs/${dir}.sha256"
    (cd "${dest}" && sha256sum -c "${tarball}.sha256")
    tar -C "${dest}" -xJf "${dest}/${tarball}"
    rm -f "${dest}/${tarball}" "${dest}/${tarball}.sha256"
    # Bootlin toolchains are relocatable once this has run.
    [[ -x "${dest}/${dir}/relocate-sdk.sh" ]] && "${dest}/${dir}/relocate-sdk.sh" >/dev/null
done
