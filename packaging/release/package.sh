#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Packs what packaging/release/build-all.sh left in build/ into the release
# assets, in build/release-<version>/ (or the directory given) — exactly what
# a release publishes, and nothing else:
#
#   nanochronometer-<v>-<os>.zip      an operating system's release: a
#                                     directory per architecture, each an
#                                     install prefix, and the licence texts at
#                                     the top; light — every program and
#                                     library keeps its symbol table, without
#                                     its debug information
#   nanochronometer-<v>.apk and its .idsig
#   nanochronometer-<v>-baremetal-<arch>.iso   the bootable images, as they are
#   SHA256SUMS
#
# for linux (x86_64, i686, aarch64, armv7, riscv64), windows (x86_64,
# aarch64, i686), macos (x86_64, aarch64, universal), android (arm64-v8a,
# armeabi-v7a, x86_64, x86) and baremetal (the nine architectures, with the
# plugins and the documentation).
#
# The debug information goes to debug/ beside them, and is not published:
#
#   debug/nanochronometer-<v>-<os>-debug.zip  a .debug per program and
#                                     library (ELF, PE), the .dSYM bundles
#                                     (macOS), and <arch>/debug/<libdir>/, the
#                                     static library with its debug sections
#   debug/nanochronometer-<v>-android-apk-debug.zip  the JNI libraries'
#   debug/SHA256SUMS
#
# A -debug.zip holds the same top directory as its release zip: unzipped in
# the same place, each .debug lands beside the file it belongs to, where GDB
# and LLDB look for it (.gnu_debuglink), and each .dSYM beside its binary.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build="${repo}/build"
version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "${repo}/Cargo.toml" | head -1)"
out="${1:-${build}/release-${version}}"
cache="${NANOCHRONO_CACHE:-${HOME}/.cache/nanochrono}"
mkdir -p "${cache}"
stage="$(mktemp -d "${cache}/package.XXXXXX")"
trap 'command rm -rf "${stage}"' EXIT
# Every file in a zip gets the same date — the release tag's commit time — so
# packing the same build/ twice gives the same assets.
epoch="${SOURCE_DATE_EPOCH:-$(git -C "${repo}" log -1 --format=%ct "v${version}" 2>/dev/null ||
    git -C "${repo}" log -1 --format=%ct)}"

command rm -rf "${out}"
dbgout="${out}/debug"
mkdir -p "${out}" "${dbgout}"

# Every asset carries the licence texts: NanoChronometer's (LICENSE, NOTICE),
# those of the crates it links in (tools/third-party-licenses.py), and the
# notices of the toolchain runtime a platform's binaries contain — the
# mingw-w64 runtime on Windows, which asks for its notices in any binary
# distribution, and the NDK's (bionic, in the static CLI) on Android.
python3 "${repo}/tools/third-party-licenses.py" > "${stage}/THIRD-PARTY-LICENSES.txt"
mingw_notice="${MINGW_SRC:-${HOME}/llvm-mingw}/mingw-w64/COPYING.MinGW-w64-runtime/COPYING.MinGW-w64-runtime.txt"
ndk="${ANDROID_NDK_HOME:-$(ls -d "${ANDROID_HOME:-${HOME}/Android/Sdk}"/ndk/*/ 2>/dev/null | sort -V | tail -1)}"
ndk_notice="${ndk%/}/NOTICE"
for f in "${mingw_notice}" "${ndk_notice}"; do
    [[ -f "${f}" ]] || { echo "error: no ${f} (set MINGW_SRC / ANDROID_NDK_HOME)" >&2; exit 1; }
done

# build/ may sit on exFAT, where every file reads as 0755: what goes into an
# asset gets ordinary modes — 0644, and 0755 for directories, programs and
# shared libraries.
modes() {
    find "$1" -type d -exec chmod 755 {} +
    find "$1" -type f -exec chmod 644 {} +
    find "$1" -type f -not -path '*.dSYM/*' -not -name '*.debug' \
        \( -path '*/bin/*' -o -name '*.so' -o -name '*.dylib' -o -path '*.app/Contents/MacOS/*' \) \
        -exec chmod 755 {} +
}

# zip_tree <parent> <top> <zip>: <parent>/<top> as a zip, entries in a fixed
# order and with no owner or extended timestamps in them.
zip_tree() {
    find "$1/$2" -exec touch -h -d "@${epoch}" {} +
    (cd "$1" && find "$2" -print | LC_ALL=C sort | TZ=UTC zip -q -X -9 -@ "$3")
}

# pack <os> <dir>:<prefix>... [-- <file or directory for the top>...]: an
# operating system's asset, each prefix from build/ as a directory of it (an
# empty <dir> puts it at the top), and, if there is debug information, its
# -debug.zip.
pack() {
    local os="$1"; shift
    local top="nanochronometer-${version}-${os}"
    local main="${stage}/main" dbg="${stage}/debug"
    command rm -rf "${main}" "${dbg}"
    mkdir -p "${main}/${top}" "${dbg}/${top}"
    while [[ $# -gt 0 && "$1" != -- ]]; do
        mkdir -p "${main}/${top}/${1%%:*}"
        command cp -R "${1#*:}/." "${main}/${top}/${1%%:*}/"
        shift
    done
    [[ "${1:-}" == -- ]] && shift
    local extra
    for extra in "$@"; do
        command cp -R "${extra}" "${main}/${top}/"
    done
    # One copy of the licence texts, at the top and from the repository,
    # whatever copies build/ holds.
    find "${main}/${top}" -mindepth 2 -maxdepth 2 -type f \( -name LICENSE -o -name NOTICE \) -delete
    command cp -f "${repo}/LICENSE" "${repo}/NOTICE" "${stage}/THIRD-PARTY-LICENSES.txt" "${main}/${top}/"
    case "${os}" in
        windows) install -Dm644 "${mingw_notice}" "${main}/${top}/licenses/MinGW-w64-runtime.txt" ;;
        android) install -Dm644 "${ndk_notice}" "${main}/${top}/licenses/Android-NDK-NOTICE.txt" ;;
    esac
    # The kernel drivers are built on their own (kernel/) and may sit in a
    # prefix — nanochrono.ko on Linux, driver/nanochrono.sys on Windows; they
    # are not part of the release. The bootable images are assets of their own.
    find "${main}/${top}" \( -name '*.ko' -o -name '*.iso' \) -delete
    find "${main}/${top}" -type d -name driver -prune -exec rm -rf {} +
    # The debug information moves to the -debug.zip, at the same paths.
    local p items
    mapfile -t items < <(cd "${main}/${top}" &&
        find . \( -name '*.dSYM' -o \( -type d -name debug \) \) -prune -print -o -name '*.debug' -print)
    for p in "${items[@]}"; do
        mkdir -p "${dbg}/${top}/$(dirname "${p}")"
        mv "${main}/${top}/${p}" "${dbg}/${top}/${p}"
    done
    modes "${main}"
    zip_tree "${main}" "${top}" "${out}/${top}.zip"
    if [[ -n "$(find "${dbg}/${top}" -type f -print -quit)" ]]; then
        modes "${dbg}"
        zip_tree "${dbg}" "${top}" "${dbgout}/${top}-debug.zip"
    fi
}

# prefixes <build/ name pattern, with %s for the arch> <arch>...: the
# <arch>:<prefix> arguments pack takes.
prefixes() {
    local pattern="$1" a; shift
    for a in "$@"; do
        # shellcheck disable=SC2059
        printf '%s:%s\n' "${a}" "${build}/$(printf "${pattern}" "${a}")"
    done
}

mapfile -t dirs < <(prefixes 'linux-%s' x86_64 i686 aarch64 armv7 riscv64)
pack linux "${dirs[@]}"
mapfile -t dirs < <(prefixes 'windows-%s' x86_64 aarch64 i686)
pack windows "${dirs[@]}"
mapfile -t dirs < <(prefixes 'macos-%s' x86_64 aarch64 universal)
pack macos "${dirs[@]}"
mapfile -t dirs < <(prefixes 'android/%s' arm64-v8a armeabi-v7a x86_64 x86)
pack android "${dirs[@]}"
install -m644 "${build}/android/nanochronometer-${version}.apk" \
    "${build}/android/nanochronometer-${version}.apk.idsig" "${out}/"
if [[ -d "${build}/android/apk-debug" ]]; then
    top="nanochronometer-${version}-android-apk"
    command rm -rf "${stage}/apk"
    mkdir -p "${stage}/apk/${top}"
    command cp -R "${build}/android/apk-debug/." "${stage}/apk/${top}/"
    modes "${stage}/apk"
    zip_tree "${stage}/apk" "${top}" "${dbgout}/${top}-debug.zip"
fi

# Bare metal: build/baremetal as it is — a directory per architecture, the
# plugins — with the documentation from the repository, as the licence texts
# are. The ISOs stay images, to be written to a stick or a CD as they are.
bm="${build}/baremetal"
install -Dm644 "${repo}/packaging/baremetal/README.release.md" "${stage}/bmdocs/README.md"
pack baremetal ":${bm}" -- "${stage}/bmdocs/README.md" \
    "${repo}/docs/BAREMETAL_LIBRARIES.md" "${repo}/docs/BAREMETAL_DRIVERS.md"
for row in x86_64:x86_64 i386:i386 ppc_of:ppc-openfirmware; do
    install -m644 "${bm}/nanochronometer_${row%%:*}.iso" "${out}/nanochronometer-${version}-baremetal-${row#*:}.iso"
done

# One SHA256SUMS per directory: the published one covers what is published.
for d in "${out}" "${dbgout}"; do
    (cd "${d}" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort |
        xargs -d '\n' sha256sum -- > SHA256SUMS)
done
for f in "${out}"/* "${dbgout}"/*; do
    [[ -f "${f}" ]] || continue
    printf '%10s  %s\n' "$(numfmt --to=iec "$(stat -c %s "${f}")")" "${f#"${out}/"}"
done
echo "=== to publish: $(find "${out}" -maxdepth 1 -type f | wc -l) files, $(du -sh --exclude=debug "${out}" | cut -f1), in ${out}"
echo "=== not published: the debug information, $(du -sh "${dbgout}" | cut -f1), in ${dbgout}"
