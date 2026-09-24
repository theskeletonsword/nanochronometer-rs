# SPDX-License-Identifier: Apache-2.0
#
# Source this after tools/fetch-cross-toolchains.sh. For every Linux target
# whose toolchain is present it exports, in Cargo's per-target spelling:
#
#   CC_<target>                          the cross C compiler (for `ring`)
#   CARGO_TARGET_<TARGET>_LINKER         the same driver, which knows its sysroot
#   CARGO_TARGET_<TARGET>_RUNNER         qemu-user with that sysroot, so
#                                        `cargo test --target <triple>` runs
#
#   source tools/cross-env.sh
#   cargo test -p nanochrono-core --target riscv64gc-unknown-linux-gnu
#
# ppc32 runs on a G4 (`-cpu 7450`) rather than QEMU's default: the classic
# 32-bit Time Base encoding is exactly what that core is there to check.

_nc_tc="${NANOCHRONO_TOOLCHAINS:-${HOME}/.cache/nanochrono/toolchains}"
_nc_rel="${BOOTLIN_RELEASE:-stable-2026.08-1}"

# rust target | bootlin name | gcc prefix | qemu-user binary and flags
_nc_map=(
    "powerpc64le-unknown-linux-gnu|powerpc64le-power8|powerpc64le-buildroot-linux-gnu|qemu-ppc64le -cpu power9"
    "powerpc64-unknown-linux-gnu|powerpc64-power8|powerpc64-buildroot-linux-gnu|qemu-ppc64 -cpu power8"
    "powerpc-unknown-linux-gnu|powerpc-e300c3|powerpc-buildroot-linux-gnu|qemu-ppc -cpu 7450"
    "riscv64gc-unknown-linux-gnu|riscv64-lp64d|riscv64-buildroot-linux-gnu|qemu-riscv64 -cpu rv64,v=true,vlen=256"
    "riscv32gc-unknown-linux-gnu|riscv32-ilp32d|riscv32-buildroot-linux-gnu|qemu-riscv32 -cpu rv32,v=true,vlen=128"
    "armv7-unknown-linux-gnueabihf|armv7-eabihf|arm-buildroot-linux-gnueabihf|qemu-arm -cpu cortex-a15"
    "aarch64-unknown-linux-gnu|aarch64|aarch64-buildroot-linux-gnu|qemu-aarch64 -cpu max"
    "i686-unknown-linux-gnu|x86-i686|i686-buildroot-linux-gnu|"
)

for _nc_row in "${_nc_map[@]}"; do
    IFS='|' read -r _nc_target _nc_name _nc_prefix _nc_qemu <<<"${_nc_row}"
    _nc_dir="${_nc_tc}/${_nc_name}--glibc--${_nc_rel}"
    [[ -d "${_nc_dir}" ]] || continue
    _nc_cc="${_nc_dir}/bin/${_nc_prefix}-gcc"
    _nc_sysroot="${_nc_dir}/${_nc_prefix}/sysroot"
    _nc_up="$(echo "${_nc_target}" | tr 'a-z-' 'A-Z_')"
    _nc_low="$(echo "${_nc_target}" | tr '-' '_')"
    export "CC_${_nc_low}=${_nc_cc}"
    export "AR_${_nc_low}=${_nc_dir}/bin/${_nc_prefix}-ar"
    export "CARGO_TARGET_${_nc_up}_LINKER=${_nc_cc}"
    # i686 runs natively on an x86-64 host, but against the toolchain's
    # glibc, through its own loader.
    if [[ -n "${_nc_qemu}" ]]; then
        export "CARGO_TARGET_${_nc_up}_RUNNER=${_nc_qemu} -L ${_nc_sysroot}"
    else
        export "CARGO_TARGET_${_nc_up}_RUNNER=${_nc_sysroot}/lib/ld-linux.so.2 --library-path ${_nc_sysroot}/lib"
    fi
done
# Windows, 32-bit x86: llvm-mingw compiles `ring` and links; Wine runs.
_nc_mingw="$(ls -d "${_nc_tc}"/llvm-mingw-*-x86_64 2>/dev/null | tail -1)"
if [[ -n "${_nc_mingw}" ]]; then
    export CC_i686_pc_windows_gnullvm="${_nc_mingw}/bin/i686-w64-mingw32-clang"
    export AR_i686_pc_windows_gnullvm="${_nc_mingw}/bin/llvm-ar"
    export CARGO_TARGET_I686_PC_WINDOWS_GNULLVM_LINKER="${_nc_mingw}/bin/i686-w64-mingw32-clang"
    # A private prefix, so the tests never touch ~/.wine, and no Mono or
    # Gecko: their installers open a dialog that nothing headless can answer.
    export WINEPREFIX="${NANOCHRONO_WINEPREFIX:-${HOME}/.cache/nanochrono/wine}"
    export WINEDLLOVERRIDES="mscoree,mshtml="
    export WINEDEBUG="-all"
    command -v wine >/dev/null && export CARGO_TARGET_I686_PC_WINDOWS_GNULLVM_RUNNER="wine"
fi

# Android: the NDK's clang for API 24. Statically linked, an Android
# executable also runs on a Linux host — natively for x86, under qemu-arm for
# ARM — which is how the tests run without a device.
#
# From NDK r30 the static libc.a carries Android's own Rust standard library,
# so a static Rust executable defines `rust_eh_personality` twice (identical
# code from two copies of std). Only the static test link is affected — an
# app links libc dynamically — so the duplicate is allowed here and nowhere
# else.
_nc_ndk="$(ls -d "${_nc_tc}"/android-ndk-r* 2>/dev/null | grep -v '\.zip$' | tail -1)"
if [[ -n "${_nc_ndk}" ]]; then
    _nc_bin="${_nc_ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin"
    export CC_armv7_linux_androideabi="${_nc_bin}/armv7a-linux-androideabi24-clang"
    export AR_armv7_linux_androideabi="${_nc_bin}/llvm-ar"
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="${_nc_bin}/armv7a-linux-androideabi24-clang"
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--allow-multiple-definition"
    # 32-bit bionic's pthread mutexes only hold PIDs up to 65535 and abort
    # past that; a desktop host hands out larger ones. A fresh PID namespace
    # (unprivileged) gives the test a small PID, as a device would.
    # TMPDIR too: without it Android's temp_dir() is /data/local/tmp, which
    # exists on a device and not on the host.
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUNNER="unshare -Urpf env TMPDIR=/tmp qemu-arm -cpu cortex-a15"
    export CC_i686_linux_android="${_nc_bin}/i686-linux-android24-clang"
    export AR_i686_linux_android="${_nc_bin}/llvm-ar"
    export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="${_nc_bin}/i686-linux-android24-clang"
    # The Rust in that libc.a also wants compiler-rt's CPU-model symbols on
    # x86, which a Rust link does not pull in on its own.
    _nc_rt="$(ls "${_nc_ndk}"/toolchains/llvm/prebuilt/linux-x86_64/lib/clang/*/lib/linux/libclang_rt.builtins-i686-android.a 2>/dev/null | tail -1)"
    export CARGO_TARGET_I686_LINUX_ANDROID_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--allow-multiple-definition -C link-arg=${_nc_rt}"
    export CARGO_TARGET_I686_LINUX_ANDROID_RUNNER="unshare -Urpf env TMPDIR=/tmp"
fi
unset _nc_mingw _nc_ndk _nc_bin _nc_rt

unset _nc_tc _nc_rel _nc_map _nc_row _nc_target _nc_name _nc_prefix _nc_qemu _nc_dir _nc_cc _nc_sysroot _nc_up _nc_low
