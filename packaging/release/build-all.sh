#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds every release — CLI, desktop GUI and C library — for every desktop
# OS and architecture, plus the universal Android APK, and copies the results
# to build/<os>-<arch>/.
#
#   packaging/release/build-all.sh               # everything
#   packaging/release/build-all.sh linux-aarch64 macos-aarch64   # some
#
# Run it as the user who owns the toolchains, not as root. Build trees live
# on a real filesystem (CARGO_HOME-style cache under ~/.cache/nanochrono),
# one per rustc, so the second run of a target reuses every dependency and
# two compilers never read each other's metadata. The repository itself may
# sit on exFAT, which corrupts incremental caches; nothing is built in it.
#
# Toolchains (override with the variables in brackets):
#   Linux    Buildroot/Bootlin SDKs in ~/toolchains/linux/<arch>  [LINUX_TC]
#   Windows  llvm-mingw (UCRT) in ~/toolchains/mingw               [MINGW_TC]
#   macOS    osxcross in ~/toolchains/osxcross                     [OSXCROSS]
#   Android  the SDK/NDK, via packaging/android/build-app.sh       [ANDROID_HOME]
#   Rust     rustup's stable and nightly; nightly builds a target's std from
#            rust-src (-Zbuild-std) where no prebuilt one is installed.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${repo}/build"
cache="${NANOCHRONO_CACHE:-${HOME}/.cache/nanochrono}"
linux_tc="${LINUX_TC:-${HOME}/toolchains/linux}"
mingw_tc="${MINGW_TC:-${HOME}/toolchains/mingw}"
osxcross="${OSXCROSS:-${HOME}/toolchains/osxcross/target}"
rustup_home="${RUSTUP_HOME:-${HOME}/.rustup}"
host="x86_64-unknown-linux-gnu"
packages=(-p nanochrono-cli -p nanochrono-gui -p nanochrono-ffi)
logs="${cache}/logs"
mkdir -p "${logs}" "${out}"

toolchain_bin() { echo "${rustup_home}/toolchains/$1-${host}/bin"; }

# name | rust target | rust toolchain
targets=(
    "linux-x86_64|x86_64-unknown-linux-gnu|stable"
    "linux-i686|i686-unknown-linux-gnu|nightly"
    "linux-aarch64|aarch64-unknown-linux-gnu|nightly"
    "linux-armv7|armv7-unknown-linux-gnueabihf|nightly"
    "linux-riscv64|riscv64gc-unknown-linux-gnu|nightly"
    "windows-x86_64|x86_64-pc-windows-gnullvm|stable"
    "windows-aarch64|aarch64-pc-windows-gnullvm|stable"
    "windows-i686|i686-pc-windows-gnullvm|nightly"
    "macos-x86_64|x86_64-apple-darwin|nightly"
    "macos-aarch64|aarch64-apple-darwin|nightly"
)

# Buildroot SDK directory and GNU triple per Linux target.
declare -A sdk=(
    [i686-unknown-linux-gnu]="x86-i686:i686-buildroot-linux-gnu"
    [aarch64-unknown-linux-gnu]="aarch64:aarch64-buildroot-linux-gnu"
    [armv7-unknown-linux-gnueabihf]="armv7-eabihf:arm-buildroot-linux-gnueabihf"
    [riscv64gc-unknown-linux-gnu]="riscv64-lp64d:riscv64-buildroot-linux-gnu"
)

build_one() {
    local name="$1" target="$2" chain="$3"
    local bin; bin="$(toolchain_bin "${chain}")"
    local tdir="${cache}/release-${chain}"
    local t_=${target//-/_}
    local T; T="$(echo "${target}" | tr 'a-z-' 'A-Z_')"
    local env_=(PATH="${bin}:${PATH}" RUSTUP_TOOLCHAIN="${chain}-${host}")
    local extra=()

    if [[ ! -d "$("${bin}/rustc" --print sysroot)/lib/rustlib/${target}" ]]; then
        extra=(-Zbuild-std=std,panic_abort)
    fi

    case "${target}" in
        *-linux-gnu*)
            if [[ "${target}" != "${host}" ]]; then
                local d="${sdk[${target}]%%:*}" triple="${sdk[${target}]#*:}"
                # Nightly links x86 Linux with its own rust-lld, which does not
                # resolve glibc's private loader symbols (_dl_x86_cpu_features)
                # against a Buildroot sysroot; the toolchain's own ld does.
                local nolld=""
                [[ "${chain}" == nightly && "${target}" == i686-* ]] && nolld=" -Clinker-features=-lld -Zunstable-options"
                local root="${linux_tc}/${d}" sysroot
                sysroot="${root}/${triple}/sysroot"
                local cc; cc="$(ls "${root}/bin/${triple}"-gcc-*.br_real 2>/dev/null | head -1)"
                [[ -n "${cc}" ]] || cc="${root}/bin/${triple}-gcc"
                env_+=("CARGO_TARGET_${T}_LINKER=${cc}"
                       "CARGO_TARGET_${T}_RUSTFLAGS=-C link-arg=--sysroot=${sysroot}${nolld}"
                       "CC_${t_}=${cc}" "CFLAGS_${t_}=--sysroot=${sysroot}"
                       "AR_${t_}=${root}/bin/${triple}-ar")
            fi
            ;;
        *-windows-gnullvm)
            local arch="${target%%-*}"
            env_+=("CARGO_TARGET_${T}_LINKER=${mingw_tc}/bin/${arch}-w64-mingw32-clang"
                   "CC_${t_}=${mingw_tc}/bin/${arch}-w64-mingw32-clang"
                   "AR_${t_}=${mingw_tc}/bin/llvm-ar" "AR=${mingw_tc}/bin/llvm-ar"
                   "WINDRES=${mingw_tc}/bin/${arch}-w64-mingw32-windres")
            ;;
        *-apple-darwin)
            local arch="${target%%-*}"
            local cc; cc="$(ls "${osxcross}/bin/${arch}-apple-darwin"*-clang | head -1)"
            # osxcross's ld links against its own libxar, which is not on the
            # system library path.
            env_+=("PATH=${osxcross}/bin:${bin}:${PATH}"
                   "LD_LIBRARY_PATH=${osxcross}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
                   "CARGO_TARGET_${T}_LINKER=${cc}" "CC_${t_}=${cc}"
                   "AR_${t_}=${cc%-clang}-ar" "MACOSX_DEPLOYMENT_TARGET=11.0")
            ;;
    esac

    echo "=== ${name} (${target}, ${chain}${extra:+, std from source})"
    if ! env "${env_[@]}" "${bin}/cargo" build --profile dist --target "${target}" "${extra[@]}" \
            --manifest-path "${repo}/Cargo.toml" --target-dir "${tdir}" "${packages[@]}" \
            > "${logs}/${name}.log" 2>&1; then
        echo "!!! ${name} FAILED — see ${logs}/${name}.log"
        grep -E '^error' "${logs}/${name}.log" | head -5
        return 1
    fi

    local rel="${tdir}/${target}/dist" dest="${out}/${name}"
    mkdir -p "${dest}"
    for f in nanochrono nanochrono-gui nanochrono.exe nanochrono-gui.exe nanochrono.dll \
             libnanochrono.so libnanochrono.dylib libnanochrono.a libnanochrono.dll.a; do
        [[ -f "${rel}/${f}" ]] && command cp -f "${rel}/${f}" "${dest}/"
    done
    dress "${name}"
    echo "    -> ${dest}"
}

# What makes a directory of binaries look like the application on its OS:
# the icon and logo each desktop expects, from assets/icons/ (regenerated by
# tools/gen-icons.py). Windows needs nothing here — both .exe files carry the
# icon as a resource (see the build.rs files).
dress() {
    local name="$1" dest="${out}/$1" icons="${repo}/assets/icons"
    local app_id="io.nanochronometer.NanoChrono"
    case "${name}" in
        linux-*)
            # The layout install.sh and a distribution package use: the
            # .desktop entry names the icon by the app id, which is also the
            # Wayland application_id, so the window and the entry match.
            command rm -rf "${dest}/share"
            install -Dm644 "${repo}/packaging/linux/${app_id}.desktop" \
                "${dest}/share/applications/${app_id}.desktop"
            local d n
            for d in "${icons}"/linux/hicolor/*/; do
                n="$(basename "${d}")"
                if [[ "${n}" == scalable ]]; then
                    install -Dm644 "${d}apps/nanochronometer.svg" \
                        "${dest}/share/icons/hicolor/scalable/apps/${app_id}.svg"
                else
                    install -Dm644 "${d}apps/nanochronometer.png" \
                        "${dest}/share/icons/hicolor/${n}/apps/${app_id}.png"
                fi
            done
            install -Dm644 "${repo}/assets/nanochronometer_logo_dark.svg" \
                "${dest}/share/pixmaps/nanochronometer_logo_dark.svg"
            install -Dm644 "${repo}/assets/nanochronometer_logo.svg" \
                "${dest}/share/pixmaps/nanochronometer_logo.svg"
            ;;
        macos-*)
            # The GUI only gets a Dock icon and keyboard focus as a bundle.
            [[ -f "${dest}/nanochrono-gui" ]] || return 0
            local app="${dest}/NanoChronometer.app" version
            version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "${repo}/Cargo.toml" | head -1)"
            command rm -rf "${app}"
            mkdir -p "${app}/Contents/MacOS" "${app}/Contents/Resources"
            command cp -f "${dest}/nanochrono-gui" "${app}/Contents/MacOS/NanoChronometer"
            command cp -f "${icons}/macos/nanochrono.icns" "${app}/Contents/Resources/NanoChronometer.icns"
            sed -e "s/@VERSION@/${version}/g" "${repo}/packaging/macos/Info.plist.in" \
                > "${app}/Contents/Info.plist"
            printf 'APPL????' > "${app}/Contents/PkgInfo"
            ;;
    esac
}

# macOS: one binary for both architectures.
universal_macos() {
    local a="${out}/macos-x86_64" b="${out}/macos-aarch64" u="${out}/macos-universal"
    [[ -d "${a}" && -d "${b}" ]] || return 0
    mkdir -p "${u}"
    for f in nanochrono nanochrono-gui libnanochrono.dylib libnanochrono.a; do
        [[ -f "${a}/${f}" && -f "${b}/${f}" ]] &&
            "${osxcross}/bin/lipo" -create "${a}/${f}" "${b}/${f}" -output "${u}/${f}"
    done
    dress macos-universal
    echo "=== macos-universal -> ${u}"
}

android() {
    echo "=== android (universal APK: arm64-v8a, armeabi-v7a, x86_64, x86)"
    if RUST_BIN="$(toolchain_bin nightly)" CARGO_INCREMENTAL=0 \
            "${repo}/packaging/android/build-app.sh" > "${logs}/android.log" 2>&1; then
        mkdir -p "${out}/android"
        command cp -f "${repo}"/dist/android-app/nanochronometer-*.apk "${out}/android/"
        echo "    -> ${out}/android"
    else
        echo "!!! android FAILED — see ${logs}/android.log"
    fi
}

wanted=("$@")
failed=0
for row in "${targets[@]}"; do
    IFS='|' read -r name target chain <<<"${row}"
    if [[ ${#wanted[@]} -gt 0 && ! " ${wanted[*]} " =~ " ${name} " ]]; then
        continue
    fi
    build_one "${name}" "${target}" "${chain}" || failed=$((failed + 1))
done
if [[ ${#wanted[@]} -eq 0 || " ${wanted[*]} " =~ " macos-universal " ]]; then
    universal_macos
fi
if [[ ${#wanted[@]} -eq 0 || " ${wanted[*]} " =~ " android " ]]; then
    android
fi
echo "failed: ${failed}"
