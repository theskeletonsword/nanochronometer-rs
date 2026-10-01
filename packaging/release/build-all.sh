#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds every release into build/:
#
#   build/<os>-<arch>/    for every desktop OS and architecture, laid out as
#                         an install prefix: bin/ (CLI, desktop GUI; the DLL
#                         on Windows), lib64/ or lib/ (libnanochrono shared
#                         and static) and include/nanochrono.h beside it;
#                         build/macos-universal/ joins both Macs
#   build/android/        the libraries and the terminal CLI per ABI, and the
#                         universal APK
#   build/baremetal/      the freestanding kernels, their static and shared
#                         libraries per architecture, and the bootable ISOs
#
#   packaging/release/build-all.sh               # everything
#   packaging/release/build-all.sh linux-aarch64 macos-aarch64   # some
#   packaging/release/build-all.sh android baremetal             # by name
#   OPT=-Os packaging/release/build-all.sh                       # another level
#
# OPT picks the optimisation level: -O0 -Og -O1 -O2 -O3 -Os -Oz, or -Ofast
# (not recommended; see packaging/opt-level.sh). The default is -O2, which
# is what the published releases are.
#
# The bare-metal kernels trust the plugin signing roots named by
# NCPLU_ROOT_CREATOR / NCPLU_ROOT_TREE and sign the bundled plugins with
# NCPLU_SIGN_KEYS, when those are set (see packaging/baremetal/build.sh);
# without them every plugin runs as a community plugin, at ring 3.
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

# No build-machine path in what ships (packaging/remap-paths.sh).
# shellcheck source=packaging/remap-paths.sh
source "${repo}/packaging/remap-paths.sh"
remap="$(remap_rustflags "${repo}")" || exit 1
cflags_remap="$(remap_cflags "${repo}")"

# OPT= (packaging/opt-level.sh), checked once here and passed on.
# shellcheck source=packaging/opt-level.sh
source "${repo}/packaging/opt-level.sh"
set_opt_args dist || exit 1

# The C header ships next to every library. It is generated from the Rust
# source when cbindgen is available; otherwise the checked-out copy is used.
header="${repo}/include/nanochrono.h"
if command -v cbindgen >/dev/null 2>&1; then
    "${repo}/tools/gen-header.sh" >/dev/null
elif [[ ! -f "${header}" ]]; then
    echo "note: no cbindgen and no include/nanochrono.h; the libraries ship without it"
fi

# pkg-config files (packaging/pkgconfig.sh).
# shellcheck source=packaging/pkgconfig.sh
source "${repo}/packaging/pkgconfig.sh"

# Debug information in files of its own (packaging/debuginfo.sh).
# shellcheck source=packaging/debuginfo.sh
source "${repo}/packaging/debuginfo.sh"
debug_objcopy >/dev/null || exit 1
version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "${repo}/Cargo.toml" | head -1)"

# ship_pkgconfig <name> <target> <dest> <libdir>: the pkg-config file, and on
# Windows what its static link needs that MinGW does not have — the
# windows-targets import library — with libunwind named as the archive, so a
# C program does not end up importing libunwind.dll either.
ship_pkgconfig() {
    local name="$1" target="$2" dest="$3" libdir="$4" private
    private="$(native_libs "${logs}/${name}.log")"
    if [[ -z "${private}" ]]; then
        echo "note: no native-static-libs for ${name}; nanochrono.pc lists none"
    fi
    if [[ "${target}" == *-windows-gnullvm ]]; then
        local arch="${target%%-*}" lib file
        for lib in ${private}; do
            [[ "${lib}" == -lwindows.* ]] || continue
            # -lwindows.0.52.0 comes from windows_<arch>_gnullvm 0.52.x.
            local ver="${lib#-lwindows.}"
            file="$(ls -d "${CARGO_HOME:-${HOME}/.cargo}"/registry/src/*/windows_"${arch}"_gnullvm-"${ver%.*}".*/lib/libwindows."${ver}".a 2>/dev/null | sort -V | tail -1)"
            if [[ -n "${file}" ]]; then
                command cp -f "${file}" "${dest}/${libdir}/"
            else
                echo "note: no libwindows.${ver}.a found for ${name}"
            fi
        done
        private="$(sed 's/\(^\| \)-lunwind\( \|$\)/\1-l:libunwind.a\2/g' <<<"${private}")"
    fi
    write_pc "${dest}" "${libdir}" "${private}" "${version}"
}

# Where a platform keeps its libraries: lib64/ for 64-bit Linux, as the
# distributions do; lib/ for 32-bit Linux, and for macOS and Windows, which
# have no lib64 whatever the width.
lib_dir() {
    case "$1" in
        linux-x86_64 | linux-aarch64 | linux-riscv64) echo lib64 ;;
        *) echo lib ;;
    esac
}

# The header and the licence texts, beside a directory of libraries.
ship_header() {
    local dest="$1"
    [[ -f "${header}" ]] && install -Dm644 "${header}" "${dest}/include/nanochrono.h"
    command cp -f "${repo}/LICENSE" "${repo}/NOTICE" "${dest}/"
}

# Every Windows binary links llvm-mingw's runtime into itself — the mingw-w64
# CRT, and libunwind (statically: no libunwind.dll to ship) — and as
# llvm-mingw builds that runtime, it names the machine that built the
# toolchain: the CRT's debug information and libunwind's __FILE__ strings.
# mingw_runtime <arch> prints a toolchain whose runtime does not: a copy of
# the toolchain (a reflink copy, which costs no space on btrfs or XFS) with the
# CRT and libunwind rebuilt from its own sources ([MINGW_SRC], default
# ~/llvm-mingw), configured as llvm-mingw's build-mingw-w64.sh and
# build-libcxx.sh configure them, the paths remapped. Without those sources,
# or if a rebuild fails, it prints the toolchain itself.
mingw_src="${MINGW_SRC:-${HOME}/llvm-mingw}"
mingw_runtime() {
    local arch="$1" rev root crt_flags flags extra=""
    if [[ ! -d "${mingw_src}/mingw-w64/mingw-w64-crt" || ! -d "${mingw_src}/llvm-project/libunwind" ]]; then
        echo "${mingw_tc}"
        return 0
    fi
    rev="$(git -C "${mingw_src}/mingw-w64" rev-parse --short=12 HEAD 2>/dev/null || echo src)"
    rev+="-$(git -C "${mingw_src}/llvm-project" rev-parse --short=12 HEAD 2>/dev/null || echo src)"
    root="${cache}/mingw-runtime/${rev}"
    if [[ ! -d "${root}/toolchain" ]]; then
        mkdir -p "${root}"
        command rm -rf "${root}/toolchain.tmp"
        command cp -a --reflink=auto "${mingw_tc}" "${root}/toolchain.tmp" &&
            mv "${root}/toolchain.tmp" "${root}/toolchain" || { echo "${mingw_tc}"; return 0; }
    fi
    if [[ ! -f "${root}/done-${arch}" ]]; then
        flags="-g -O2 ${cflags_remap} -ffile-prefix-map=${mingw_src}=/llvm-mingw"
        case "${arch}" in
            i686) crt_flags="--enable-lib32 --disable-lib64"; extra="-D__USE_MINGW_ANSI_STDIO=1" ;;
            x86_64) crt_flags="--disable-lib32 --enable-lib64"; extra="-D__USE_MINGW_ANSI_STDIO=1" ;;
            aarch64) crt_flags="--disable-lib32 --disable-lib64 --enable-libarm64" ;;
        esac
        local log="${logs}/mingw-runtime-${arch}.log" tc="${root}/toolchain"
        command rm -rf "${root}/crt-${arch}" "${root}/unwind-${arch}"
        mkdir -p "${root}/crt-${arch}"
        # shellcheck disable=SC2086
        if ! (cd "${root}/crt-${arch}" && env -u CC PATH="${tc}/bin:${PATH}" \
                    CFLAGS="${flags}" CCASFLAGS="${flags}" \
                    "${mingw_src}/mingw-w64/mingw-w64-crt/configure" --host="${arch}-w64-mingw32" \
                    --prefix="${tc}/${arch}-w64-mingw32" ${crt_flags} --with-default-msvcrt=ucrt \
                    --enable-silent-rules --enable-cfguard &&
                env -u CC PATH="${tc}/bin:${PATH}" make -j"$(nproc)" &&
                env -u CC PATH="${tc}/bin:${PATH}" make install) > "${log}" 2>&1 ||
           ! PATH="${tc}/bin:${PATH}" cmake -G Ninja -S "${mingw_src}/llvm-project/runtimes" \
                -B "${root}/unwind-${arch}" \
                -DCMAKE_BUILD_TYPE=Release \
                -DCMAKE_C_COMPILER="${arch}-w64-mingw32-clang" \
                -DCMAKE_CXX_COMPILER="${arch}-w64-mingw32-clang++" \
                -DCMAKE_CXX_COMPILER_TARGET="${arch}-w64-windows-gnu" \
                -DCMAKE_SYSTEM_NAME=Windows \
                -DCMAKE_C_COMPILER_WORKS=TRUE -DCMAKE_CXX_COMPILER_WORKS=TRUE \
                -DCMAKE_AR="${tc}/bin/llvm-ar" -DCMAKE_RANLIB="${tc}/bin/llvm-ranlib" \
                -DLLVM_ENABLE_RUNTIMES=libunwind \
                -DLIBUNWIND_USE_COMPILER_RT=TRUE \
                -DLIBUNWIND_ENABLE_SHARED=ON -DLIBUNWIND_ENABLE_STATIC=ON \
                -DCMAKE_C_FLAGS_INIT="-mguard=cf ${extra} ${flags#-g -O2 }" \
                -DCMAKE_CXX_FLAGS_INIT="-mguard=cf ${extra} ${flags#-g -O2 }" \
                -DCMAKE_ASM_FLAGS_INIT="${extra} ${flags#-g -O2 }" \
                >> "${log}" 2>&1 ||
           ! PATH="${tc}/bin:${PATH}" cmake --build "${root}/unwind-${arch}" --target unwind_static \
                >> "${log}" 2>&1; then
            echo "note: the ${arch} MinGW runtime did not rebuild (${log}); linking the toolchain's" >&2
            echo "${mingw_tc}"
            return 0
        fi
        command cp -f "${root}/unwind-${arch}/lib/libunwind.a" "${tc}/${arch}-w64-mingw32/lib/libunwind.a"
        touch "${root}/done-${arch}"
    fi
    echo "${root}/toolchain"
}

# macOS: a .dSYM per binary, through the dsymutil remap_dsymutil writes here.
macos_tools="${cache}/macos-tools"

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
    # No 32-bit Arm Windows build: Windows 11 24H2 and later no longer run
    # 32-bit Arm programs at all, and Rust has only tier-3 MSVC targets for
    # them (thumbv7a-pc-windows-msvc), with no prebuilt std and no gnullvm
    # variant for llvm-mingw to link.
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
    local extra=() rustflags="" cflags="${cflags_remap}"

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
                rustflags="-C link-arg=--sysroot=${sysroot}${nolld}"
                cflags="--sysroot=${sysroot} ${cflags_remap}"
                env_+=("CARGO_TARGET_${T}_LINKER=${cc}"
                       "CC_${t_}=${cc}"
                       "AR_${t_}=${root}/bin/${triple}-ar")
            fi
            ;;
        *-windows-gnullvm)
            local arch="${target%%-*}" tc
            # The toolchain with its runtime rebuilt (mingw_runtime, above).
            tc="$(mingw_runtime "${arch}")"
            # libunwind linked in rather than imported: llvm-mingw's
            # libunwind.dll is no part of Windows, and a release that needs
            # it does not start on a machine without that toolchain.
            rustflags="-C target-feature=+crt-static"
            env_+=("CARGO_TARGET_${T}_LINKER=${tc}/bin/${arch}-w64-mingw32-clang"
                   "CC_${t_}=${tc}/bin/${arch}-w64-mingw32-clang"
                   "AR_${t_}=${tc}/bin/llvm-ar" "AR=${tc}/bin/llvm-ar"
                   "WINDRES=${tc}/bin/${arch}-w64-mingw32-windres")
            ;;
        *-apple-darwin)
            local arch="${target%%-*}"
            local cc; cc="$(ls "${osxcross}/bin/${arch}-apple-darwin"*-clang | head -1)"
            # The debug map relative to $HOME, and a .dSYM per binary
            # (packaging/remap-paths.sh).
            remap_dsymutil "${macos_tools}" "${osxcross}/bin" ||
                echo "note: no dsymutil; the macOS binaries ship without a .dSYM"
            rustflags="$(remap_macos_rustflags)"
            # osxcross's ld links against its own libxar, which is not on the
            # system library path.
            env_+=("PATH=${macos_tools}:${osxcross}/bin:${bin}:${PATH}"
                   "CARGO_PROFILE_DIST_SPLIT_DEBUGINFO=packed"
                   "LD_LIBRARY_PATH=${osxcross}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
                   "CARGO_TARGET_${T}_LINKER=${cc}" "CC_${t_}=${cc}"
                   "AR_${t_}=${cc%-clang}-ar" "MACOSX_DEPLOYMENT_TARGET=11.0")
            ;;
    esac
    # Every target's rustflags carry the path remapping, after its own, and
    # ask rustc for the system libraries the static library needs (for the
    # pkg-config file, below). CFLAGS does the same for the C that cc-crate
    # dependencies build, so the archived C objects name no build path either.
    env_+=("CARGO_TARGET_${T}_RUSTFLAGS=${rustflags:+${rustflags} }${remap} --print native-static-libs"
           "CFLAGS_${t_}=${cflags}")

    echo "=== ${name} (${target}, ${chain}${extra:+, std from source})"
    if ! env "${env_[@]}" "${bin}/cargo" build --profile dist "${OPT_ARGS[@]}" \
            --target "${target}" "${extra[@]}" \
            --manifest-path "${repo}/Cargo.toml" --target-dir "${tdir}" "${packages[@]}" \
            > "${logs}/${name}.log" 2>&1; then
        echo "!!! ${name} FAILED — see ${logs}/${name}.log"
        grep -E '^error' "${logs}/${name}.log" | head -5
        return 1
    fi

    local rel="${tdir}/${target}/dist" dest="${out}/${name}" libdir f
    libdir="$(lib_dir "${name}")"
    # A fresh prefix. Only what this script writes is cleared — the flat
    # layout of older releases included — so anything else kept here (a
    # kernel driver built on its own) stays.
    command rm -rf "${dest}/bin" "${dest}/lib" "${dest}/lib64" "${dest}/include" "${dest}/debug"
    for f in nanochrono nanochrono-gui nanochrono.exe nanochrono-gui.exe nanochrono.dll \
             libnanochrono.so libnanochrono.dylib libnanochrono.a libnanochrono.dll.a; do
        command rm -f "${dest}/${f}"
    done
    mkdir -p "${dest}/bin" "${dest}/${libdir}"
    # Programs in bin/. So is the DLL: Windows finds it beside the .exe.
    for f in nanochrono nanochrono-gui nanochrono.exe nanochrono-gui.exe nanochrono.dll; do
        [[ -f "${rel}/${f}" ]] && command cp -f "${rel}/${f}" "${dest}/bin/"
    done
    for f in libnanochrono.so libnanochrono.dylib libnanochrono.a libnanochrono.dll.a; do
        [[ -f "${rel}/${f}" ]] && command cp -f "${rel}/${f}" "${dest}/${libdir}/"
    done
    # macOS: each binary's .dSYM beside it (Cargo links them into the profile
    # directory; -L copies the bundle, not the link).
    for f in nanochrono nanochrono-gui; do
        [[ -e "${rel}/${f}.dSYM" ]] && command cp -RL "${rel}/${f}.dSYM" "${dest}/bin/"
    done
    [[ -e "${rel}/libnanochrono.dylib.dSYM" ]] &&
        command cp -RL "${rel}/libnanochrono.dylib.dSYM" "${dest}/${libdir}/"
    # The debug information beside what ships rather than in it
    # (packaging/debuginfo.sh): a .debug per program and shared library —
    # macOS has its .dSYM already — and the static library as built under
    # debug/.
    if [[ "${target}" != *-apple-darwin ]]; then
        for f in "${dest}"/bin/* "${dest}/${libdir}/libnanochrono.so"; do
            split_debug "${f}" || { echo "!!! ${name}: could not split the debug information of ${f}"; return 1; }
        done
    fi
    split_debug_archive "${dest}" "${libdir}" libnanochrono.a ||
        { echo "!!! ${name}: could not split the debug information of libnanochrono.a"; return 1; }
    ship_header "${dest}"
    ship_pkgconfig "${name}" "${target}" "${dest}" "${libdir}"
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
            [[ -f "${dest}/bin/nanochrono-gui" ]] || return 0
            local app="${dest}/NanoChronometer.app" version
            version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "${repo}/Cargo.toml" | head -1)"
            command rm -rf "${app}"
            mkdir -p "${app}/Contents/MacOS" "${app}/Contents/Resources"
            command cp -f "${dest}/bin/nanochrono-gui" "${app}/Contents/MacOS/NanoChronometer"
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
    command rm -rf "${u}"
    mkdir -p "${u}/bin" "${u}/lib" "${u}/debug/lib"
    for f in bin/nanochrono bin/nanochrono-gui lib/libnanochrono.dylib lib/libnanochrono.a \
             debug/lib/libnanochrono.a; do
        [[ -f "${a}/${f}" && -f "${b}/${f}" ]] &&
            "${osxcross}/bin/lipo" -create "${a}/${f}" "${b}/${f}" -output "${u}/${f}"
    done
    # A .dSYM holds one DWARF file per binary, which joins the same way.
    local d dwa dwb
    for f in bin/nanochrono bin/nanochrono-gui lib/libnanochrono.dylib; do
        d="${f}.dSYM"
        [[ -d "${a}/${d}" && -d "${b}/${d}" ]] || continue
        dwa="$(ls "${a}/${d}"/Contents/Resources/DWARF/* | head -1)"
        dwb="$(ls "${b}/${d}"/Contents/Resources/DWARF/* | head -1)"
        command cp -R "${b}/${d}" "${u}/${d}"
        "${osxcross}/bin/lipo" -create "${dwa}" "${dwb}" \
            -output "${u}/${d}/Contents/Resources/DWARF/$(basename "${dwb}")"
    done
    ship_header "${u}"
    write_pc "${u}" lib "$(native_libs "${logs}/macos-aarch64.log")" "${version}"
    dress macos-universal
    echo "=== macos-universal -> ${u}"
}

# Android: the libraries and the terminal CLI per ABI (build/android/<abi>/),
# then the universal APK (build/android/). Nightly, for the ABIs whose std has
# to be built from rust-src.
android() {
    local sdk="${ANDROID_HOME:-${HOME}/Android/Sdk}" ndk
    ndk="${ANDROID_NDK_HOME:-$(ls -d "${sdk}"/ndk/*/ 2>/dev/null | sort -V | tail -1)}"
    ndk="${ndk%/}"
    echo "=== android libraries and CLI (arm64-v8a, armeabi-v7a, x86_64, x86)"
    if PATH="$(toolchain_bin nightly):${PATH}" ANDROID_NDK_HOME="${ndk}" CARGO_INCREMENTAL=0 \
            CARGO_TARGET_DIR="${cache}/android-libs" \
            "${repo}/packaging/android/build.sh" > "${logs}/android-libs.log" 2>&1; then
        echo "    -> ${out}/android/<abi>"
    else
        echo "!!! android libraries FAILED — see ${logs}/android-libs.log"
        failed=$((failed + 1))
    fi
    echo "=== android (universal APK: arm64-v8a, armeabi-v7a, x86_64, x86)"
    if ANDROID_HOME="${sdk}" ANDROID_NDK_HOME="${ndk}" RUST_BIN="$(toolchain_bin nightly)" \
            CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${cache}/android-app" \
            "${repo}/packaging/android/build-app.sh" > "${logs}/android.log" 2>&1; then
        echo "    -> ${out}/android"
    else
        echo "!!! android APK FAILED — see ${logs}/android.log"
        failed=$((failed + 1))
    fi
}

# Bare metal: every architecture's kernel, static archive and shared object,
# and the ISOs (packaging/baremetal/build.sh, release mode). It runs `cargo
# +nightly` through rustup, so the caller's PATH is kept as it is.
baremetal() {
    echo "=== baremetal (kernels, static and shared libraries, ISOs)"
    if CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${cache}/baremetal" \
            "${repo}/packaging/baremetal/build.sh" > "${logs}/baremetal.log" 2>&1; then
        echo "    -> ${out}/baremetal"
    else
        echo "!!! baremetal FAILED — see ${logs}/baremetal.log"
        failed=$((failed + 1))
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
if [[ ${#wanted[@]} -eq 0 || " ${wanted[*]} " =~ " baremetal " ]]; then
    baremetal
fi
echo "failed: ${failed}"
