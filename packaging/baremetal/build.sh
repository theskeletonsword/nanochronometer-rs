#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the freestanding kernel and, with `run`, boots it under QEMU.
#
# The crate is outside the workspace: it targets `x86_64-unknown-none` /
# `aarch64-unknown-none`, has no `main`, and links through its own script, so
# `cargo build --workspace` would try to build it for the host and fail.
#
# Usage:
#   packaging/baremetal/build.sh                 # every architecture
#   packaging/baremetal/build.sh x86_64          # one
#   packaging/baremetal/build.sh run x86_64      # build and boot under QEMU
#   packaging/baremetal/build.sh test            # the host-side unit tests
#   packaging/baremetal/build.sh debug [arch]    # -O0 -g + frame pointers
#   packaging/baremetal/build.sh debug-og [arch] # the same at -Og (Rust's opt-level 1):
#                                                # bugs that only optimised code shows,
#                                                # still steppable. DEBUG_OPT=Og does the
#                                                # same for gdb and boot
#   packaging/baremetal/build.sh gdb x86_64 [crashtest=<de|pf|gp|ud|so|df|panic>] [plugin=<name>]
#                                                # debug build, QEMU stopped for GDB
#   packaging/baremetal/build.sh boot x86_64 [crashtest=...] [plugin=<name>]
#                                                # the same, running at once (no GDB wait);
#                                                # mode=desktop|cli, kbd=es|us,
#                                                # wallpaper=<n> and ncdri.*= reach the
#                                                # kernel command line as well
#
# OPT=-O0|-Og|-O1|-O2|-O3|-Os|-Oz|-Ofast builds at that level instead of the
# mode's default (release -O2, debug -O0, debug-og -Og); see
# packaging/opt-level.sh. The code must be correct at every one.
#
# NCPLU_EXTRA="a.NCPLU b.NCPLU" adds plugins built elsewhere (the C SDK's, in
# sdk/) to the ISO's FAT partition beside the in-tree ones.
#
# Plugin signing (ML-DSA-87 + P-521; keys from tools/ncplu-sign, kept OUTSIDE
# the repository). Without a root every plugin is a community one, at ring 3:
#   NCPLU_ROOT_CREATOR=KEYDIR/root_pubkeys.bin   the creator's root (the green
#                                                check tier; runs in the kernel)
#   NCPLU_ROOT_TREE=KEYDIR/root_pubkeys.bin      a root the owner trusts (the
#                                                tree tier; runs in the kernel)
#   NCPLU_ROOT_PUBKEYS                           the old name for the creator's
#   NCPLU_SIGN_KEYS=KEYDIR                       sign every plugin on the ISO
#   PLUGIN_PROFILE=debug|debug-og|release        plugins at -O0, -Og or -O2; by
#                                                default they follow the kernel
#
# Output, build/baremetal/ (build/baremetal-debug/ for debug, gdb and boot;
# build/baremetal-debug-og/ at -Og):
#   <arch>/nanochrono-kernel.elf        the kernel, with its symbols (for
#                                       tools/nanodump.py and GDB)
#   <arch>/lib64/ (lib/ when 32-bit)    libnanochrono.a, and in a release
#                                       libnanochrono.so: the same library,
#                                       position independent, which needs a
#                                       loader of your own (README.md)
#   <arch>/include/nanochrono.h         the C/assembly header for both
#   nanochronometer_*.iso, plugins/     bootable images and packed plugins
#   README.md                           what all of this is and how to use it
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
crate="${repo_root}/crates/nanochrono-baremetal"
# NC_BUILD_ROOT=<dir> writes everything below to <dir>/baremetal... instead of
# build/: a trial build that leaves the release and debug output alone.
build_root="${NC_BUILD_ROOT:-${repo_root}/build}"
out_dir="${build_root}/baremetal"

# `x86_64-nanochrono-none` is a custom spec: the built-in `x86_64-unknown-none`
# has a soft-float ABI where no vector register can be allocated, so the SIMD
# probes cannot be built for it. That needs nightly and `rust-src`; pass
# `--stable` to fall back to the built-in target with SIMD off.
declare -A arch_target=(
    [x86_64]="x86_64-nanochrono-none"
    [i386]="i686-nanochrono-none"
    [aarch64]="aarch64-unknown-none"
    [arm32]="armv7a-none-eabihf"
    [ppc64]="powerpc64-nanochrono-none"
    [ppc64le]="powerpc64le-nanochrono-none"
    [ppc]="powerpc-nanochrono-none"
    [riscv64]="riscv64gc-unknown-none-elf"
    [riscv32]="riscv32imac-unknown-none-elf"
)
declare -A arch_features=(
    # plugin-verify: the ML-DSA-87 + P-521 check on .ncplu plugins, against
    # the root keys in NCPLU_ROOT_PUBKEYS (none given: every plugin Community).
    [x86_64]="--features simd,plugin-verify"
    [i386]="--features simd"
    [aarch64]="--features simd"
    [arm32]="--features simd"
    [ppc64]="--features simd"
    [ppc64le]="--features simd"
    [ppc]="--features simd"
    [riscv64]="--features simd"
    [riscv32]="--features simd"
)
toolchain="+nightly"
export RUST_TARGET_PATH="${crate}/targets"

# Set once the mode is known, below: `release` for a shipping build, `debug`
# for the `debug` and `gdb` modes.
build_kind="release"

# Where an architecture's libraries go: lib64/ on a 64-bit target, lib/ on a
# 32-bit one, as a Unix prefix lays them out, with include/ beside it.
lib_dir() {
    case "$1" in
        i386 | arm32 | ppc | riscv32) echo lib ;;
        *) echo lib64 ;;
    esac
}

# The toolchain's own LLVM linker, which links every target here; it links
# the shared objects (build_shared).
rust_lld() {
    local sysroot host
    sysroot="$(rustc ${toolchain} --print sysroot)"
    host="$(rustc ${toolchain} -vV | sed -n 's/^host: //p')"
    echo "${sysroot}/lib/rustlib/${host}/bin/rust-lld"
}

# No build-machine path in a release (packaging/remap-paths.sh), through
# `--config`, which adds to the rustflags .cargo/config.toml sets rather than
# replacing them as RUSTFLAGS would. A debug build keeps the real paths, for
# GDB to find the sources.
# shellcheck source=packaging/remap-paths.sh
source "${repo_root}/packaging/remap-paths.sh"
remap_toml="$(remap_toml_array "${repo_root}")"

# OPT= (packaging/opt-level.sh), applied to whichever profile each build uses.
# shellcheck source=packaging/opt-level.sh
source "${repo_root}/packaging/opt-level.sh"
if [[ -n "${OPT:-}" ]]; then
    rust_opt_level "${OPT}" >/dev/null || exit 1
fi

# A pkg-config file beside each architecture's libraries (packaging/
# pkgconfig.sh); freestanding, so nothing else to link.
# shellcheck source=packaging/pkgconfig.sh
source "${repo_root}/packaging/pkgconfig.sh"

# A release's debug information in files of its own (packaging/debuginfo.sh).
# shellcheck source=packaging/debuginfo.sh
source "${repo_root}/packaging/debuginfo.sh"
pc_version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "${crate}/Cargo.toml" | head -1)"

# The C/assembly header, generated from src/abi.rs (tools/gen-header.sh) when
# cbindgen is here; otherwise the copy a previous run generated is used.
header="${repo_root}/include/baremetal/nanochrono.h"
if command -v cbindgen >/dev/null 2>&1; then
    "${repo_root}/tools/gen-header.sh" >/dev/null
elif [[ ! -f "${header}" ]]; then
    echo "note: no cbindgen and no include/baremetal/nanochrono.h; the libraries ship without it"
fi

# The shared object: the same library as the static archive, not a trimmed
# one. A `cdylib` would keep only the `#[no_mangle]` entry points and what
# they reach. This builds the crate again, position independent (the arch's
# `-dylib` spec: PIC, dynamically linkable, no kernel code model), with the
# manifest's own crate types — rlib and staticlib, as the static archive is
# built, so rustc makes the same symbols public (a staticlib-only build would
# internalise the Rust-level ones) — and links every object of that archive
# with --whole-archive. Every public symbol is exported, the same set the
# static archive offers; what the compiler hid there (compiler_builtins, private
# generic copies) stays inside, unexported, as it does in the archive.
#
# `-Bsymbolic` binds the library's references to its own symbols inside it —
# there is no symbol interposition on bare metal — which is what lets the boot
# and trap assembly address them PC- or TOC-relative. `__bss_end` comes from
# the kernel's linker script, which a shared object does not use; here it is
# the end of the object's own .bss (`_end`). `-z notext` lets an absolute
# address stay in the text for the loader to relocate. It still needs a loader
# of the kernel's own — bare metal has none; see README.md.
build_shared() {
    local arch="$1" spec="${arch_target[$1]}-dylib"
    local target_dir="${CARGO_TARGET_DIR:-${crate}/target}"
    local libdir so
    libdir="$(lib_dir "${arch}")"
    so="${out_dir}/${arch}/${libdir}/libnanochrono.so"
    echo "=== ${arch} shared object (${spec})"
    set_opt_args release
    # shellcheck disable=SC2086
    (cd "${crate}" && cargo ${toolchain} build --release --lib "${OPT_ARGS[@]}" \
        --config "target.${spec}.rustflags=${remap_toml}" \
        --target "${spec}" ${arch_features[${arch}]})
    "$(rust_lld)" -flavor gnu -shared -Bsymbolic --defsym=__bss_end=_end \
        --whole-archive "${target_dir}/${spec}/release/libnanochrono_baremetal.a" \
        --no-whole-archive \
        -soname libnanochrono.so -z notext --hash-style=both --build-id \
        -o "${so}"
    split_debug "${so}" || { echo "error: could not split the debug information of ${so}" >&2; exit 1; }
    check_header_symbols "${arch}" "${so}"
}

# The OpenPOWER image must be entered the same way by both of its loaders
# (boot/powerpc64.ld): skiboot runs the file in place from 0x2000_0000, so
# every address is 0x2000_0000 plus its file offset; a kexec enters at the
# start of the loaded segment, so that must be the entry point.
check_ppc64_layout() {
    local elf="$1" entry off vaddr
    entry="$(llvm-readelf -h "${elf}" | awk '/Entry point/ { print $NF }')"
    read -r off vaddr < <(llvm-readelf -l -W "${elf}" | awk '$1 == "LOAD" { print $2, $3; exit }')
    if (( vaddr - off != 0x20000000 || entry != vaddr )); then
        echo "error: ${elf##*/}: segment ${vaddr} at offset ${off}, entry ${entry}:" \
             "skiboot and kexec would not both enter at _start (boot/powerpc64.ld)" >&2
        exit 1
    fi
}

# The header declares the library's whole symbol table: every C-named symbol
# the .so exports or imports (nm -D) — abi.rs's functions, and what
# src/abi_symbols.h adds for the rest. Checked by compiling, for the arch's
# target, a file that takes each symbol's address: an undeclared one is an
# error, so a new symbol cannot ship without its declaration.
declare -A header_triple=(
    [x86_64]=x86_64-unknown-none-elf [i386]=i686-unknown-none-elf
    [aarch64]=aarch64-unknown-none-elf [arm32]=armv7a-none-eabihf
    [ppc64]=powerpc64-unknown-none-elf [ppc64le]=powerpc64le-unknown-none-elf
    [ppc]=powerpc-unknown-none-eabi
    [riscv64]=riscv64-unknown-elf [riscv32]=riscv32-unknown-elf
)
check_header_symbols() {
    local arch="$1" so="$2" check
    [[ -f "${header}" ]] && command -v clang >/dev/null 2>&1 && command -v llvm-nm >/dev/null 2>&1 ||
        return 0
    check="$(mktemp --suffix=.c)"
    {
        echo '#include "nanochrono.h"'
        echo 'void *nc_header_check[] = {'
        llvm-nm -D "${so}"
    } | awk 'NR <= 2 { print; next }
             { n = $NF; if (n ~ /^(_ZN|_R)/) next
               if (n == "__global_pointer$") n = "nc_global_pointer"
               print "    (void *)&" n "," }
             END { print "};" }' > "${check}"
    if ! clang --target="${header_triple[${arch}]}" -ffreestanding -std=c11 -fsyntax-only \
            -I "$(dirname "${header}")" "${check}"; then
        echo "error: ${header#"${repo_root}/"} does not declare every symbol of ${so##*/} (${arch})" >&2
        command rm -f "${check}"
        exit 1
    fi
    command rm -f "${check}"
}

build_one() {
    local arch="$1" target="${arch_target[$1]}"
    local target_dir="${CARGO_TARGET_DIR:-${crate}/target}"
    echo "=== ${arch} (${target}, ${build_kind})"
    rustup target add "${target}" >/dev/null 2>&1 || true

    local profile_args=(--release --config "target.${target}.rustflags=${remap_toml}")
    local profile_dir="release"
    if [[ "${build_kind}" == "debug" ]]; then
        # Cargo's dev profile — `-O0` with full debug information — plus
        # frame pointers, so GDB unwinds without CFI and the crash dump's
        # stack trace can walk the RBP chain. Through `--config`, not
        # RUSTFLAGS: the environment variable would *replace* the target's
        # rustflags in .cargo/config.toml (no-redzone, unstable-options)
        # where `--config` appends to them.
        profile_args=(--config "target.${target}.rustflags=[\"-C\",\"force-frame-pointers=yes\"]")
        profile_dir="debug"
        if [[ "${debug_opt}" == "Og" ]]; then
            profile_args+=(--profile debug-og)
            profile_dir="debug-og"
        fi
    fi
    local cargo_profile="release"
    [[ "${build_kind}" == "debug" ]] && cargo_profile="dev"
    [[ "${profile_dir}" == "debug-og" ]] && cargo_profile="debug-og"
    set_opt_args "${cargo_profile}"
    # shellcheck disable=SC2086
    (cd "${crate}" && cargo ${toolchain} build "${profile_args[@]}" "${OPT_ARGS[@]}" \
        --target "${target}" ${arch_features[${arch}]})

    local libdir
    libdir="$(lib_dir "${arch}")"
    mkdir -p "${out_dir}/${arch}/${libdir}"
    local elf="${target_dir}/${target}/${profile_dir}/nanochrono-kernel"
    # The kernel keeps its symbol table, in a release too: it is what
    # tools/nanodump.py resolves a crash dump's addresses against, and a boot
    # image stripped of its names looks as though it hides what it is. It costs
    # under 200 KiB on any architecture.
    cp "${elf}" "${out_dir}/${arch}/nanochrono-kernel.elf"
    if [[ "${arch}" == ppc64 || "${arch}" == ppc64le ]]; then
        check_ppc64_layout "${out_dir}/${arch}/nanochrono-kernel.elf"
    fi
    # Shipped as libnanochrono, the name every platform's release uses, so a
    # C kernel links it with -lnanochrono and includes nanochrono.h.
    cp "${target_dir}/${target}/${profile_dir}/libnanochrono_baremetal.a" \
        "${out_dir}/${arch}/${libdir}/libnanochrono.a"
    if [[ "${build_kind}" == "release" ]]; then
        # The debug information goes to files of its own (packaging/
        # debuginfo.sh) before anything uses the kernel: the ISOs, the EFI
        # application and QEMU all get it as light as it ever was.
        split_debug "${out_dir}/${arch}/nanochrono-kernel.elf" &&
            split_debug_archive "${out_dir}/${arch}" "${libdir}" libnanochrono.a ||
            { echo "error: could not split the debug information for ${arch}" >&2; exit 1; }
    fi
    if [[ -f "${header}" ]]; then
        install -Dm644 "${header}" "${out_dir}/${arch}/include/nanochrono.h"
    fi
    write_pc "${out_dir}/${arch}" "${libdir}" "" "${pc_version}"

    if [[ "${build_kind}" == "release" ]]; then
        build_shared "${arch}"
    fi

    if [[ "${arch}" == "x86_64" ]]; then
        # QEMU's multiboot loader takes a 32-bit ELF only, because multiboot
        # entry is 32-bit protected mode. The image is ELF64 with a 32-bit
        # entry stub, so the container is rewritten rather than the code: every
        # address is below 4 GiB, so nothing is lost. GRUB accepts either.
        objcopy -O elf32-i386 "${out_dir}/${arch}/nanochrono-kernel.elf" \
            "${out_dir}/${arch}/nanochrono-kernel.mb.elf"
    fi
}

# The host's architecture, in this script's names. Detected, never assumed:
# whichever machine runs this decides which guest gets KVM.
host_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo x86_64 ;;
        aarch64 | arm64) echo aarch64 ;;
        ppc64le) echo ppc64le ;;
        ppc64) echo ppc64 ;;
        riscv64) echo riscv64 ;;
        *) echo unknown ;;
    esac
}

# Sets `accel` (an array) for booting `$1`: KVM when the guest is the host's
# own architecture, QEMU has a KVM path for the machine this script boots it
# on, and /dev/kvm is usable; TCG otherwise. `$2` is the `-cpu` for TCG.
#
# KVM only runs a guest of the host's own ISA, so on an x86_64 PC it is the
# x86_64 guest, on an ARM server the aarch64 one, on a RISC-V board riscv64.
# The POWER guests stay on TCG even on a POWER host: they boot on `powernv`
# (bare OpenPOWER) and `ppce500`, and neither machine has a KVM path in QEMU —
# KVM on POWER means `pseries`, a different firmware interface.
accel_for() {
    local arch="$1" tcg_cpu="$2" kvm_cpu="host"
    [[ "${arch}" == "x86_64" ]] && kvm_cpu="host,invtsc=on,pmu=on"
    case "${arch}" in
        x86_64 | aarch64 | riscv64)
            if [[ "${arch}" == "$(host_arch)" && -r /dev/kvm && -w /dev/kvm ]]; then
                accel=(-accel kvm -cpu "${kvm_cpu}")
                echo "    (KVM: guest matches the $(host_arch) host)"
                return
            fi
            [[ "${arch}" == "$(host_arch)" ]] &&
                echo "    (no usable /dev/kvm; falling back to TCG)"
            ;;
    esac
    accel=(-accel tcg -cpu "${tcg_cpu}")
}

run_one() {
    local arch="$1"
    local accel=()
    case "${arch}" in
        x86_64)
            echo "=== booting x86_64 under QEMU (Ctrl-A X to quit)"
            # On an x86_64 host KVM applies: the guest runs on the real CPU.
            # That matters here beyond speed. Under TCG, `-cpu max` is the
            # widest feature set QEMU offers but has no architectural PMU —
            # CPUID.0AH reports version 0, and the self-test correctly says
            # there is nothing to read. Under KVM with `-cpu host` the counters
            # are the silicon's, so the PMU section measures instead of
            # skipping, and the TSC is the real invariant one.
            #
            # Falls back to TCG when /dev/kvm is absent or unreadable (a
            # container, a nested guest, a machine without VT-x/AMD-V). The
            # kernel behaves identically either way; only what it can measure
            # changes.
            #
            # `invtsc=on` passes CPUID.80000007H bit 8 through, so the kernel
            # sees the invariant TSC the host actually has and calibrates
            # against it rather than distrusting it. `pmu=on` asks KVM to
            # virtualize the architectural counters; whether they appear also
            # depends on the host, which ships `kvm.enable_pmu=N` on many
            # distributions. When it is off the self-test says version 0 and
            # skips, which is the truthful answer, not a failure.
            accel_for x86_64 max
            # From the ISO when there is one: QEMU's own -kernel loader
            # implements multiboot1 only, which carries no framebuffer
            # request, so the interface would have nothing to draw on.
            if [[ -f "${out_dir}/nanochronometer_x86_64.iso" ]]; then
                qemu-system-x86_64 -cdrom "${out_dir}/nanochronometer_x86_64.iso" \
                    "${accel[@]}" -m 256 -vga std -no-reboot -serial stdio
            else
                qemu-system-x86_64 \
                    -kernel "${out_dir}/${arch}/nanochrono-kernel.mb.elf" \
                    "${accel[@]}" -m 128 -display none -no-reboot -serial stdio
            fi
            ;;
        i386)
            echo "=== booting i386 under QEMU (Ctrl-A X to quit)"
            # A 32-bit x86 guest runs under KVM on an x86_64 host too; the
            # accelerator follows the host, as for every other guest.
            local host; host="$(host_arch)"
            accel=(-accel tcg -cpu max)
            if [[ "${host}" == x86_64 && -r /dev/kvm && -w /dev/kvm ]]; then
                accel=(-accel kvm -cpu host)
            fi
            if [[ -f "${out_dir}/nanochronometer_i386.iso" ]]; then
                qemu-system-i386 -cdrom "${out_dir}/nanochronometer_i386.iso" \
                    "${accel[@]}" -m 256 -vga std -no-reboot -serial stdio
            else
                qemu-system-i386 -kernel "${out_dir}/i386/nanochrono-kernel.elf" \
                    "${accel[@]}" -m 128 -display none -no-reboot -serial stdio
            fi
            ;;
        arm32)
            echo "=== booting arm32 on virt (Cortex-A15) under QEMU (Ctrl-A X to quit)"
            # TCG: no KVM for AArch32 guests on the hosts this runs on. ramfb
            # is the screen; the keyboard is this terminal (the PL011).
            qemu-system-arm -M virt -cpu cortex-a15 -accel tcg -m 256 \
                -kernel "${out_dir}/${arch}/nanochrono-kernel.elf" \
                -device ramfb -no-reboot -serial stdio
            ;;
        aarch64)
            echo "=== booting aarch64 under QEMU (Ctrl-A X to quit)"
            # KVM on an AArch64 host, TCG anywhere else. Under TCG the timing
            # numbers it prints are QEMU's, not a real core's — enough for the
            # decoding paths, and the self-test says which it ran under.
            #
            # `virt` maps a PL011 at 0x09000000, which the serial driver
            # assumes, and its `-cpu max` does implement PMCCNTR_EL0.
            accel_for aarch64 max
            # ramfb is the screen; the keyboard is this terminal (the PL011).
            qemu-system-aarch64 \
                -M virt "${accel[@]}" -m 256 \
                -kernel "${out_dir}/${arch}/nanochrono-kernel.elf" \
                -device ramfb -no-reboot -serial stdio
            ;;
        ppc64|ppc64le)
            echo "=== booting ${arch} on powernv9 under QEMU (Ctrl-A X to quit)"
            # TCG always: see `accel_for`. `powernv` is OpenPOWER bare metal: QEMU's
            # bundled skiboot boots the ELF in place at 0x20000000 and the
            # console is OPAL's. Both byte orders run on the same machine —
            # skiboot enters big-endian and the little-endian image switches
            # itself. `powernv8` and `powernv10` work the same way.
            qemu-system-ppc64 \
                -M powernv9 -accel tcg -m 2G \
                -kernel "${out_dir}/${arch}/nanochrono-kernel.elf" \
                -display none -no-reboot -serial stdio
            ;;
        ppc)
            echo "=== booting ppc on ppce500 (e500mc) under QEMU (Ctrl-A X to quit)"
            # With -kernel and no -bios QEMU boots the ELF directly, ePAPR
            # style. e500mc because it has the classic FPU the `ppc` target's
            # hard-float ABI needs (the default e500v2 has SPE instead).
            qemu-system-ppc \
                -M ppce500 -cpu e500mc -accel tcg -m 256 \
                -kernel "${out_dir}/${arch}/nanochrono-kernel.elf" \
                -display none -no-reboot -serial stdio
            ;;
        ppc-g4)
            echo "=== booting ppc on a G4 PowerMac (mac99, OpenBIOS) under QEMU"
            # The same ELF as the e500 run, entered the other way: Open
            # Firmware loads it from the CD and passes its client interface
            # in r5, which is how a real G3/G4 Mac boots it too. -nographic
            # puts OpenBIOS's stdout — the kernel's console — on the serial
            # line; with a display it would go to the screen.
            # -g ...x32: the interface draws on Open Firmware's screen at
            # 32 bits per pixel; the Mac's keyboard is the input.
            qemu-system-ppc -M mac99 -cpu G4 -accel tcg -m 256 -g 1024x768x32 \
                -cdrom "${out_dir}/nanochronometer_ppc_of.iso" -boot d \
                -prom-env 'boot-device=cd:,\nanochro.elf' \
                -no-reboot -serial stdio
            ;;
        riscv64|riscv32)
            echo "=== booting ${arch} on virt under QEMU (Ctrl-A X to quit)"
            # KVM for riscv64 on a RISC-V host, TCG otherwise (RV32 has no
            # KVM). QEMU's bundled OpenSBI (fw_dynamic) runs in M-mode and
            # enters the ELF in S-mode with the device tree in a1. `v=true`
            # gives RV64 a vector unit under TCG so the RVV probe has something
            # to run on; under KVM the host's own extensions apply.
            local qemu="qemu-system-${arch}" cpu="rv32"
            [[ "${arch}" == "riscv64" ]] && cpu="rv64,v=true,vlen=256"
            accel_for "${arch}" "${cpu}"
            # ramfb is the screen; the keyboard is this terminal (the UART).
            "${qemu}" -M virt "${accel[@]}" -m 256 \
                -kernel "${out_dir}/${arch}/nanochrono-kernel.elf" \
                -device ramfb -no-reboot -serial stdio
            ;;
    esac
}

# Boots the debug kernel under QEMU stopped at the reset vector (`-S`) with a
# GDB stub on localhost:1234 (`-s`), and waits for
#   gdb -x packaging/baremetal/gdb/x86_64.gdb
# from the repository root. `-no-reboot` turns a triple fault into QEMU
# exiting rather than a silent reboot loop, and `-d int,cpu_reset` logs every
# exception and reset to qemu-int.log. The serial output goes to the terminal
# and to serial.log, which is where a crash dump is read back from.
#
# The ISO is booted **as a USB stick** — a copy of it, so build/ is not
# written to — because that is how it runs on hardware, and because the stick
# is then the crash dump's USB target as well: a fault writes CRASH.DMP into
# the stick's own NANOCRASH partition, and this reads it back afterwards.
# With `crashtest=<name>`, a one-off ISO whose default entry passes it is
# built first. QEMU_DISPLAY (e.g. `none`) is passed to -display when set.
run_gdb() {
    local accel=()
    accel_for x86_64 max
    local iso="${out_dir}/nanochronometer_x86_64.iso"
    local extra="${crashtest}${kernel_extra}"
    if [[ -n "${extra}" ]]; then
        iso="${out_dir}/gdb.iso"
        build_iso_x86 x86_64 "${iso}" "${extra# }"
    fi
    if [[ ! -f "${iso}" ]]; then
        echo "error: no ISO to boot (is grub-mkrescue installed?)" >&2
        return 1
    fi
    # NC_BUILD_ONLY=1: the ISO (with the arguments) and nothing else — for
    # a test harness that boots it itself.
    if [[ -n "${NC_BUILD_ONLY:-}" ]]; then
        echo "=== built ${iso}"
        return 0
    fi
    local stick="${out_dir}/gdb-stick.img"
    cp "${iso}" "${stick}"
    local display=()
    [[ -n "${QEMU_DISPLAY:-}" ]] && display=(-display "${QEMU_DISPLAY}")

    local log="${out_dir}/qemu-int.log" serial="${out_dir}/serial.log"
    rm -f "${log}" "${serial}" "${out_dir}/CRASH.DMP" "${out_dir}/CRASH-usb.DMP"
    # `boot`: the same machine, running at once instead of waiting for GDB.
    local stop=(-s -S)
    if [[ "${mode}" == "boot" ]]; then
        stop=()
        echo "=== booting the -${debug_opt} build under QEMU (not waiting for GDB)"
    else
        echo "=== QEMU is stopped at the reset vector, GDB stub on localhost:1234"
        echo "    in another terminal, from ${repo_root}:"
        if [[ "${debug_opt}" == "Og" ]]; then
            echo "        NC_GDB_ELF=${out_dir#"${repo_root}/"}/x86_64/nanochrono-kernel.elf gdb -x packaging/baremetal/gdb/x86_64.gdb"
        else
            echo "        gdb -x packaging/baremetal/gdb/x86_64.gdb"
        fi
    fi
    echo "    booting ${iso##*/} as a USB stick (copy: ${stick##*/})"
    echo "    exceptions and resets: ${log}"
    echo "    serial (and any crash dump): ${serial}"
    if [[ "${accel[1]}" == "kvm" ]]; then
        # Not a reason to leave KVM: the guest is this host's ISA. What changes
        # is how a triple fault shows — QEMU exits (-no-reboot) and the log
        # has a "CPU Reset" after the two at power-on.
        echo "    (KVM: -d int logs nothing, the exceptions happen in the kernel's"
        echo "     hands; a triple fault shows as QEMU exiting and a CPU Reset line)"
    fi
    qemu-system-x86_64 "${accel[@]}" -m 512 -vga std "${display[@]}" \
        -device qemu-xhci,id=xhci \
        -drive "if=none,id=stick,file=${stick},format=raw" \
        -device usb-storage,bus=xhci.0,drive=stick,bootindex=0 \
        "${stop[@]}" -no-reboot -d int,cpu_reset -D "${log}" \
        -chardev "stdio,id=com1,logfile=${serial}" -serial chardev:com1 || true

    if grep -q "BEGIN NANOCHRONO DUMP" "${serial}" 2>/dev/null; then
        echo
        echo "=== crash dump found in ${serial}"
        "${repo_root}/tools/nanodump.py" extract "${serial}" -o "${out_dir}/CRASH.DMP"
        "${repo_root}/tools/nanodump.py" show "${out_dir}/CRASH.DMP" \
            --elf "${out_dir}/x86_64/nanochrono-kernel.elf"
    fi
    if "${repo_root}/tools/nanodump.py" extract-image "${stick}" \
        -o "${out_dir}/CRASH-usb.DMP" >/dev/null 2>&1; then
        echo
        echo "=== and read back from the stick's CRASH.DMP: ${out_dir}/CRASH-usb.DMP"
        if cmp -s "${out_dir}/CRASH.DMP" "${out_dir}/CRASH-usb.DMP"; then
            echo "    identical to the serial copy"
        fi
    fi
}

mode="build"
if [[ "${1:-}" == "run" || "${1:-}" == "test" || "${1:-}" == "debug" || "${1:-}" == "debug-og" ||
      "${1:-}" == "gdb" || "${1:-}" == "boot" ]]; then
    mode="$1"
    shift
fi

crashtest=""
kernel_extra=""
# Debug builds come at two levels: -O0 (`debug`; `gdb` and `boot` by default)
# and -Og (`debug-og`, or DEBUG_OPT=Og) — Rust has no -Og, so the debug-og
# profile: opt-level 1 with the same symbols and checks. Bugs that only show
# once code is optimised turn up there while they can still be stepped.
debug_opt="O0"
if [[ "${mode}" == "debug-og" || "${DEBUG_OPT:-O0}" == "Og" ]]; then
    debug_opt="Og"
fi
if [[ "${mode}" == "debug" || "${mode}" == "debug-og" || "${mode}" == "gdb" || "${mode}" == "boot" ]]; then
    build_kind="debug"
    # Beside the release output, not over it: a debug kernel is 8 MiB of
    # DWARF and never ships.
    out_dir="${build_root}/baremetal-debug"
    [[ "${debug_opt}" == "Og" ]] && out_dir+="-og"
    if [[ "${mode}" == "gdb" || "${mode}" == "boot" ]]; then
        args=()
        for a in "$@"; do
            case "${a}" in
                crashtest=*) crashtest="${a}" ;;
                plugin=* | mode=* | kbd=* | wallpaper=* | ncdri.*=*)
                    kernel_extra="${kernel_extra} ${a}" ;;
                *) args+=("${a}") ;;
            esac
        done
        set -- "${args[@]:-x86_64}"
        if [[ "$*" != "x86_64" ]]; then
            echo "error: ${mode} mode supports x86_64 only (packaging/baremetal/gdb/x86_64.gdb)" >&2
            exit 1
        fi
    fi
    # One architecture unless told otherwise: the debugging flow is x86_64's.
    [[ $# -eq 0 ]] && set -- x86_64
fi

if [[ "${mode}" == "test" ]]; then
    # The decoding logic — the CPUID performance-monitoring leaf, the hybrid
    # core type, the counter-width mask — is pure and runs on the host, which
    # is the only place it can be driven with the values that matter: one
    # thread on a hybrid part can never observe both core types. It lives in
    # the `nanochrono-core` crate, which has a hosted test build; the
    # bare-metal crate is unconditionally `no_std` with its own panic handler,
    # so a test harness cannot link it by construction.
    (cd "${repo_root}/crates/nanochrono-core" && cargo test --lib)
    exit 0
fi

requested=("$@")
# `ppc-g4` is a way to run the `ppc` build, not a build of its own.
run_requested=("${requested[@]}")
for i in "${!requested[@]}"; do
    [[ "${requested[$i]}" == "ppc-g4" ]] && requested[$i]="ppc"
done
[[ ${#requested[@]} -eq 0 ]] && requested=(x86_64 i386 aarch64 arm32 ppc64 ppc64le ppc riscv64 riscv32)

rm -rf "${out_dir}"
for arch in "${requested[@]}"; do
    if [[ -z "${arch_target[${arch}]:-}" ]]; then
        echo "error: unknown architecture '${arch}' (want x86_64, aarch64, ppc64, ppc64le, ppc, ppc-g4, riscv64 or riscv32)" >&2
        exit 1
    fi
    build_one "${arch}"
done

# A CD image Open Firmware can boot on a G3/G4 Mac (and QEMU's mac99): ISO
# 9660 with an HFS+ hybrid, the kernel ELF at the root. From the OF prompt:
#   boot cd:,\nanochro.elf
build_iso_ppc_of() {
    local mkiso
    mkiso="$(command -v xorriso || true)"
    if [[ -z "${mkiso}" ]]; then
        echo "note: no xorriso; skipping the Open Firmware ISO"
        return
    fi
    local staging="${out_dir}/.iso-ppc"
    rm -rf "${staging}"
    mkdir -p "${staging}"
    cp "${out_dir}/ppc/nanochrono-kernel.elf" "${staging}/nanochro.elf"
    "${mkiso}" -as mkisofs -quiet -r -J -hfsplus \
        -o "${out_dir}/nanochronometer_ppc_of.iso" "${staging}" >/dev/null 2>&1
    rm -rf "${staging}"
}

# A bootable image, so the kernel can be written to a USB stick and started
# on real hardware. grub-mkrescue produces a hybrid ISO: an MBR with a boot
# signature plus El Torito images for both BIOS and UEFI, which is what makes
# it work with dd, Rufus, Ventoy, YUMI and UNetbootin alike.
# Builds every plugin under crates/nanochrono-plugins/ at -O0 and packs each
# into build/.../plugins/<NAME>.NCPLU, ready to drop onto the crash partition.
# A plugin is a shared object on the -dylib target; tools/ncplu.py flattens it
# into the loader's format. GPL plugins (DOOM, a GPL decoder) are built the
# same way but live outside this repository.
build_plugins() {
    local plugins_dir="${repo_root}/crates/nanochrono-plugins"
    [[ -d "${plugins_dir}" ]] || return 0
    mkdir -p "${out_dir}/plugins"

    # Debug plugins are -O0 (or -Og, with an -Og kernel) with debug info, to
    # step through under GDB; release plugins are -O2 (their Cargo.toml's
    # [profile.release]) — the build a user runs, and the one that gets
    # signed. They follow the kernel's build unless
    # PLUGIN_PROFILE=debug|debug-og|release says otherwise, so a release
    # plugin can be tried on a debug kernel.
    local profile="${PLUGIN_PROFILE:-${build_kind}}"
    [[ "${profile}" == "debug" && "${debug_opt}" == "Og" ]] && profile="debug-og"
    local profile_args=() opt="-O0" profile_dir="debug" cargo_profile="dev"
    case "${profile}" in
        release)
            profile_args=(--release --config "target.x86_64-nanochrono-none-dylib.rustflags=${remap_toml}")
            opt="-O2" profile_dir="release" cargo_profile="release" ;;
        debug-og)
            profile_args=(--profile debug-og)
            opt="-Og" profile_dir="debug-og" cargo_profile="debug-og" ;;
    esac
    set_opt_args "${cargo_profile}"
    profile_args+=("${OPT_ARGS[@]}")
    opt="${OPT:-${opt}}"

    local crate name target so out
    for crate in "${plugins_dir}"/*/; do
        [[ -f "${crate}Cargo.toml" ]] || continue
        name="$(basename "${crate}")"
        echo "=== plugin ${name} (${profile}, ${opt})"
        # Its own .cargo/config selects the -dylib target and build-std. A
        # target dir of its own, off the (exFAT) repo, so it neither collides
        # with the kernel's shared object nor trips the incremental-cache ICE.
        target="${HOME}/.cache/nanochrono/plugin-${name}"
        # shellcheck disable=SC2086
        if ! (cd "${crate}" && CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${target}" \
            cargo ${toolchain} build "${profile_args[@]}"); then
            echo "note: plugin ${name} failed to build; skipping"
            continue
        fi
        so="$(ls "${target}/x86_64-nanochrono-none-dylib/${profile_dir}/"*.so 2>/dev/null | head -1)"
        if [[ -z "${so}" ]]; then
            echo "note: no shared object for plugin ${name}; skipping"
            continue
        fi
        out="${out_dir}/plugins/${name^^}.NCPLU"
        "${repo_root}/tools/ncplu.py" pack "${so}" -o "${out}" >/dev/null
        echo "    packed ${out##*/} ($(stat -c%s "${out}") bytes)"
    done
    # Plugins built outside the tree (sdk/: C plugins), already packed.
    local extra
    for extra in ${NCPLU_EXTRA:-}; do
        if [[ -f "${extra}" ]]; then
            command cp -f "${extra}" "${out_dir}/plugins/"
            echo "=== plugin ${extra##*/} (NCPLU_EXTRA)"
        else
            echo "note: NCPLU_EXTRA: ${extra} not found; skipping"
        fi
    done
    sign_plugins
}

# With NCPLU_SIGN_KEYS pointing at a key directory from `ncplu-sign keygen`
# (outside the repository), every plugin on the ISO is signed with ML-DSA-87
# and P-521. A kernel built with the matching NCPLU_ROOT_PUBKEYS then loads
# them as Official. Without it the plugins keep an empty signature block and
# load as Community. The private keys are only ever read by the host tool.
sign_plugins() {
    [[ -n "${NCPLU_SIGN_KEYS:-}" ]] || return 0
    if [[ ! -f "${NCPLU_SIGN_KEYS}/mldsa.seed" || ! -f "${NCPLU_SIGN_KEYS}/p521.scalar" ]]; then
        echo "error: NCPLU_SIGN_KEYS=${NCPLU_SIGN_KEYS} holds no ncplu-sign keys" >&2
        return 1
    fi
    local tool_dir="${HOME}/.cache/nanochrono/ncplu-sign"
    (cd "${repo_root}/tools/ncplu-sign" && CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${tool_dir}" \
        cargo build --quiet) || return 1
    local plug
    for plug in "${out_dir}/plugins/"*.NCPLU; do
        [[ -f "${plug}" ]] || continue
        "${tool_dir}/debug/ncplu-sign" sign "${plug}" --keys "${NCPLU_SIGN_KEYS}" >/dev/null || return 1
        echo "    signed ${plug##*/} (ML-DSA-87 + P-521)"
    done
}

# The crash dump's partition, for the x86_64 ISO: a 4 MiB FAT16 volume
# labelled NANOCRASH holding a pre-allocated CRASH.DMP. Appended to the hybrid
# ISO as a GPT partition, it makes a stick written from the ISO with `dd` its
# own dump target: the kernel finds the file at boot, and a fault writes the
# dump into its blocks. FAT16 because FAT32 needs at least 65525 clusters —
# some 33 MiB — where FAT16 fits in four; the kernel reads both.
#
# $1: the image to write. Returns non-zero, with a note, when the tools are
# missing; the ISO is then built without the partition.
make_crash_partition() {
    local img="$1"
    if ! command -v mkfs.vfat >/dev/null || ! command -v mcopy >/dev/null; then
        echo "note: no mkfs.vfat/mtools; the ISO carries no CRASH.DMP partition"
        return 1
    fi
    rm -f "${img}"
    # 16 MiB: room for CRASH.DMP and a handful of plugins (a -O0 Snake is
    # ~90 KiB; a packed DOOM is a few hundred). Still a FAT16 with 512-byte
    # clusters, which the kernel reads.
    dd if=/dev/zero of="${img}" bs=1M count=16 status=none
    mkfs.vfat -F 16 -s 1 -n NANOCRASH "${img}" >/dev/null
    local files
    files="$(mktemp -d)"
    # 64 KiB: four times the largest dump (crashdump.rs, CAPACITY), zeroed so
    # that a stick that never crashed holds no stale-looking dump.
    head -c 65536 /dev/zero > "${files}/CRASH.DMP"
    cat > "${files}/README.TXT" <<'TXT'
NanoChronometer crash dump partition.

CRASH.DMP is written by the bare-metal kernel when it faults: raw writes into
the blocks this file already occupies, nothing else on this volume is touched.
Do not delete, move or shrink it - the kernel finds it by name at boot and
never allocates space for it. All zeros means nothing has crashed since.

Read it with:  tools/nanodump.py show CRASH.DMP --elf nanochrono-kernel.elf
TXT
    MTOOLS_SKIP_CHECK=1 mcopy -i "${img}" "${files}/CRASH.DMP" "${files}/README.TXT" ::/
    # Every packed plugin, if any were built. mtools writes a proper VFAT long
    # name for the five-character .NCPLU extension.
    local plug
    for plug in "${out_dir}/plugins/"*.NCPLU; do
        [[ -e "${plug}" ]] || continue
        MTOOLS_SKIP_CHECK=1 mcopy -i "${img}" "${plug}" "::/${plug##*/}"
    done
    rm -rf "${files}"
}

# Builds a GRUB hybrid ISO for x86_64 or i386.
#
# $1: arch; $2: the ISO to write (default: the release name in out_dir);
# $3: extra kernel arguments for the default entries (the `gdb` mode passes a
# crashtest this way).
build_iso_x86() {
    local arch="$1"
    local iso="${2:-${out_dir}/nanochronometer_${arch}.iso}"
    local kernel_args="${3:-}"
    local grub_mkrescue
    grub_mkrescue="$(command -v grub-mkrescue || command -v grub2-mkrescue || true)"
    if [[ -z "${grub_mkrescue}" ]]; then
        echo "note: no grub-mkrescue; skipping the ${arch} ISO"
        echo "      the ELF still boots with qemu -kernel"
        return
    fi

    local staging="${out_dir}/.iso-${arch}"
    rm -rf "${staging}"
    mkdir -p "${staging}/boot/grub"
    cp "${out_dir}/${arch}/nanochrono-kernel.elf" "${staging}/boot/nanochrono-kernel"
    # The menu's own wallpaper: the first of the embedded ones.
    local background
    background="$(ls "${repo_root}/assets/wallpapers/"*.png 2>/dev/null | head -1)"
    [[ -n "${background}" ]] && cp "${background}" "${staging}/boot/grub/background.png"
    # Packages and drivers travel on the ISO and reach the kernel as
    # multiboot2 modules, each filed under its path (src/vfs.rs): the
    # Desktop Experience and the CLI list and run them. x86_64 only, where
    # the loader for them exists.
    local modules=""
    if [[ "${arch}" == "x86_64" ]]; then
        build_plugins
        local plug
        for plug in "${out_dir}/plugins/"*.NCPLU "${out_dir}/plugins/"*.ncplu "${out_dir}/plugins/"*.NCDRI \
                    "${out_dir}/plugins/"*.ncdri "${out_dir}/plugins/"*.nsdyn; do
            [[ -f "${plug}" ]] || continue
            local dest="/apps/${plug##*/}"
            case "${plug,,}" in
                *.ncdri) dest="/boot/drivers/${plug##*/}" ;;
                *.nsdyn) dest="/usr/lib/${plug##*/}" ;;
            esac
            mkdir -p "${staging}$(dirname "${dest}")"
            command cp -f "${plug}" "${staging}${dest}"
            modules+="    module2 ${dest} ${dest}"$'\n'
        done
    fi
    sed -e "s/@ARCH@/${arch}/g" -e "s/@ARGS@/${kernel_args}/g" > "${staging}/boot/grub/grub.cfg" <<'CFG'
set timeout=5
set default=0

insmod all_video
insmod gfxterm
insmod png

set gfxmode=1920x1200x32,1920x1080x32,1680x1050x32,1600x900x32,1440x900x32,1366x768x32,1280x1024x32,1280x800x32,1024x768x32,auto
terminal_output gfxterm
set gfxpayload=keep
if background_image /boot/grub/background.png; then
    set menu_color_normal=white/black
    set menu_color_highlight=black/light-green
    set color_normal=light-gray/black
fi

menuentry "NanoChronometer (@ARCH@)" {
    multiboot2 /boot/nanochrono-kernel @ARGS@
@MODULES@    set gfxpayload=keep
    boot
}

menuentry "NanoChronometer Desktop Experience (@ARCH@)" {
    multiboot2 /boot/nanochrono-kernel mode=desktop @ARGS@
@MODULES@    set gfxpayload=keep
    boot
}

menuentry "NanoChronometer CLI (@ARCH@)" {
    multiboot2 /boot/nanochrono-kernel mode=cli @ARGS@
@MODULES@    set gfxpayload=keep
    boot
}

menuentry "NanoChronometer CLI, Spanish keyboard (@ARCH@)" {
    multiboot2 /boot/nanochrono-kernel mode=cli kbd=es @ARGS@
@MODULES@    set gfxpayload=keep
    boot
}

menuentry "NanoChronometer (@ARCH@, text mode)" {
    set gfxpayload=text
    multiboot2 /boot/nanochrono-kernel @ARGS@
    boot
}
CFG
    # The module lines go where @MODULES@ stands (sed cannot take a
    # multi-line replacement portably; this can).
    python3 - "${staging}/boot/grub/grub.cfg" "${modules}" <<'PY'
import sys
path, modules = sys.argv[1], sys.argv[2]
cfg = open(path).read().replace("@MODULES@", modules)
open(path, "w").write(cfg)
PY
    # The debug ISO boots straight into each forced fault as well, to check
    # on real hardware that a fault ends in a crash dump and the stop screen
    # rather than a reset (see crashdump::CrashTest).
    if [[ "${build_kind}" == "debug" && "${arch}" == "x86_64" ]]; then
        local t
        for t in de pf gp ud so df panic; do
            cat >> "${staging}/boot/grub/grub.cfg" <<CFG

menuentry "Crash test: crashtest=${t}" {
    multiboot2 /boot/nanochrono-kernel crashtest=${t}
    set gfxpayload=keep
    boot
}
CFG
        done
    fi
    # x86_64 only, where the crash dumper exists. Arguments after `--` reach
    # xorriso in its native dialect, where `appended_part_as=gpt` keeps the
    # MBR purely protective, as UEFI expects; the partition is in the GPT,
    # which is where the kernel looks when it sees the protective entry.
    local xorriso_args=()
    if [[ "${arch}" == "x86_64" ]]; then
        local fat="${staging}.crashfat.img"
        if make_crash_partition "${fat}"; then
            xorriso_args=(-- -append_partition 3 0x0e "${fat}"
                -boot_image any appended_part_as=gpt)
        fi
    fi
    # Its output is kept rather than discarded: a failure here used to end
    # the script with nothing said.
    if ! "${grub_mkrescue}" -o "${iso}" "${staging}" "${xorriso_args[@]}" \
        >"${staging}.log" 2>&1; then
        echo "error: grub-mkrescue failed for ${arch}:" >&2
        grep -iE "failure|error|sorry" "${staging}.log" >&2 || cat "${staging}.log" >&2
        rm -rf "${staging}" "${staging}.crashfat.img" "${staging}.log"
        return 1
    fi
    rm -rf "${staging}" "${staging}.crashfat.img" "${staging}.log"
}

# Build a PE/COFF EFI application out of the AArch64 kernel.
#
# GRUB2's arm64-efi port cannot load a bare ELF kernel: its `linux` command
# wants a Linux image with an EFI stub, and there is no multiboot2 on ARM. The
# supported way to start other code from GRUB2 on AArch64 is `chainloader`,
# which transfers control to a PE/COFF EFI application. That application is:
#
#   * a small C loader (boot/efi_loader_aarch64.c) that gets the system table
#     from UEFI, allocates memory, copies the embedded kernel there and jumps
#     to it;
#   * the kernel ELF itself, embedded verbatim (boot/kernel_blob.S) and copied
#     out at boot.
#
# The kernel's AArch64 image keeps absolute addresses (Rust vtables, statics)
# that assume its linked base, so the loader copies the embedded ELF to
# exactly that base and jumps to its entry; `_start` then sets up its own
# stack and .bss and calls `kmain`, which takes no arguments.
#
# clang emits the ARM64 COFF objects, and lld-link produces a valid
# `Subsystem: EFI application` PE32+ image (the GNU aarch64-ld cannot emit PE
# for this target).  The image base must be zero: this firmware refuses fixed
# nonzero bases (0x180000000 and 0x40000000 both crash it, exactly the shape
# of a loader that does not run its relocations), while base 0 works.
build_efi_app() {
    local kernel_elf="$1" out_efi="$2"
    local stub_dir="${repo_root}/crates/nanochrono-baremetal/boot"

    local clang lld
    clang="$(command -v clang || true)"
    lld="$(command -v lld-link || true)"
    if [[ -z "${clang}" ]] || [[ -z "${lld}" ]]; then
        echo "note: clang/lld-link not found; skipping the ARM64 ISO"
        return 1
    fi

    local work
    work="$(mktemp -d)"
    trap 'rm -rf "${work:-}"' RETURN

    # The loader as an ARM64 COFF object.
    "${clang}" --target=aarch64-unknown-windows-msvc -ffreestanding -O2 \
        -Wno-int-to-void-pointer-cast -Wno-int-to-pointer-cast \
        -c "${stub_dir}/efi_loader_aarch64.c" -o "${work}/loader.obj" 2>&1 || {
        echo "error: clang failed to compile the ARM64 EFI loader" >&2
        return 1
    }

    # The kernel blob embedded in `.rodata`, as an ARM64 COFF object.
    "${clang}" --target=aarch64-unknown-windows-msvc -c \
        -DKERNEL_BLOB=\"${kernel_elf}\" \
        "${stub_dir}/kernel_blob.S" -o "${work}/blob.obj" 2>&1 || {
        echo "error: clang failed to assemble the ARM64 kernel blob" >&2
        return 1
    }

    # Link into a PE32+ EFI application. `-dll` plus `-subsystem:efi_application`
    # and `-entry:efi_main` is what makes the image bootable by both UEFI
    # firmware and GRUB's chainloader; `/base:0` keeps the loader relocatable,
    # which this firmware requires.
    "$lld" /entry:efi_main /subsystem:efi_application \
        /nodefaultlib /dll /base:0 \
        /out:"${out_efi}" \
        "${work}/loader.obj" "${work}/blob.obj" || {
        echo "error: lld-link failed to link the ARM64 EFI application" >&2
        return 1
    }
}

# The EFI loader for 32-bit ARM and RISC-V (boot/efi_loader.c), with the
# kernel embedded, as a PE/COFF EFI application: compiled for the target,
# linked as one flat image (boot/efi_loader.ld) — at two bases, which must give
# the same bytes, so it holds no absolute address — and wrapped by
# tools/mkefi.py, since lld links no PE for these targets. Debug builds
# compile it at the kernel's debug level, releases at -O2.
build_efi_loader() {
    local arch="$1" kernel_elf="$2" out_efi="$3"
    local boot="${repo_root}/crates/nanochrono-baremetal/boot"
    local target march
    case "${arch}" in
        arm32) target=armv7a-none-eabi march=(-marm -mfloat-abi=soft) ;;
        riscv64) target=riscv64-unknown-elf march=(-march=rv64imac -mabi=lp64 -mcmodel=medany -mno-relax) ;;
        riscv32) target=riscv32-unknown-elf march=(-march=rv32imac -mabi=ilp32 -mcmodel=medany -mno-relax) ;;
        *) echo "error: no EFI loader for ${arch}" >&2; return 1 ;;
    esac
    local opt=-O2
    if [[ "${build_kind}" == "debug" ]]; then
        opt="-${debug_opt}"
    fi
    local clang lld
    clang="$(command -v clang || true)"
    lld="$(command -v ld.lld || true)"
    if [[ -z "${clang}" || -z "${lld}" ]]; then
        echo "note: clang/ld.lld not found; skipping the ${arch} ISO"
        return 1
    fi
    local work
    work="$(mktemp -d)"
    # The kernel as the firmware loads it: its debug information stays in
    # the build directory (a release kernel has none in it already).
    llvm-objcopy --strip-debug "${kernel_elf}" "${work}/kernel.elf"
    "${clang}" --target="${target}" "${march[@]}" "${opt}" -g -ffreestanding -fno-builtin -nostdlib \
        -fPIE -fvisibility=hidden -fno-stack-protector -fno-jump-tables -Wall -Wextra -Werror \
        -c "${boot}/efi_loader.c" -o "${work}/loader.o" &&
    "${clang}" --target="${target}" "${march[@]}" -c -DKERNEL_BLOB="\"${work}/kernel.elf\"" \
        "${boot}/kernel_blob.S" -o "${work}/blob.o" || { command rm -rf "${work}"; return 1; }
    local b
    for b in 0x1000 0x101000; do
        "${lld}" -static -nostdlib -T "${boot}/efi_loader.ld" --defsym=EFI_BASE="${b}" \
            "${work}/loader.o" "${work}/blob.o" -o "${work}/loader-${b}.elf" &&
            llvm-objcopy -O binary "${work}/loader-${b}.elf" "${work}/image-${b}.bin" ||
            { command rm -rf "${work}"; return 1; }
    done
    if ! cmp -s "${work}/image-0x1000.bin" "${work}/image-0x101000.bin"; then
        echo "error: the ${arch} EFI loader holds an absolute address (its images differ by base)" >&2
        command rm -rf "${work}"
        return 1
    fi
    python3 "${repo_root}/tools/mkefi.py" "${work}/loader-0x1000.elf" "${out_efi}"
    local rc=$?
    command rm -rf "${work}"
    return "${rc}"
}

# An ISO that UEFI firmware — and U-Boot, through its EFI support — boots from
# its removable-media path, EFI/BOOT/<name>: the loader above in a FAT EFI
# system partition, as the El Torito EFI boot image (a CD) and as an MBR
# partition appended to the image (a USB stick or a disk).
build_iso_efi() {
    local arch="$1" name="$2"
    local mkiso
    mkiso="$(command -v xorriso || true)"
    if [[ -z "${mkiso}" ]] || ! command -v mkfs.fat >/dev/null || ! command -v mcopy >/dev/null; then
        echo "note: no xorriso, mkfs.fat or mtools; skipping the ${arch} ISO"
        return
    fi
    local staging="${out_dir}/.iso-${arch}"
    rm -rf "${staging}"
    mkdir -p "${staging}/iso/EFI/BOOT"
    if ! build_efi_loader "${arch}" "${out_dir}/${arch}/nanochrono-kernel.elf" \
            "${staging}/iso/EFI/BOOT/${name}"; then
        echo "error: could not build the ${arch} EFI loader" >&2
        rm -rf "${staging}"
        return
    fi
    local esp="${staging}/iso/efiboot.img" kib
    kib=$(( $(stat -c %s "${staging}/iso/EFI/BOOT/${name}") / 1024 + 1024 ))
    mkfs.fat -C "${esp}" "${kib}" >/dev/null &&
        MTOOLS_SKIP_CHECK=1 mmd -i "${esp}" ::/EFI ::/EFI/BOOT &&
        MTOOLS_SKIP_CHECK=1 mcopy -i "${esp}" "${staging}/iso/EFI/BOOT/${name}" "::/EFI/BOOT/${name}" &&
        "${mkiso}" -as mkisofs -quiet -R -J -V "NANOCHRONO" \
            -e efiboot.img -no-emul-boot -append_partition 2 0xef "${esp}" \
            -o "${out_dir}/nanochronometer_${arch}.iso" "${staging}/iso" >/dev/null 2>&1 ||
        echo "error: could not write the ${arch} ISO" >&2
    rm -rf "${staging}"
}

# An ISO for OpenPOWER machines, which boot through petitboot: a Linux in
# the firmware that reads the GRUB configuration on a medium and kexecs the
# kernel it names. Here, /boot/grub/grub.cfg names the kernel ELF beside it;
# the kernel takes whichever byte order the kexec enters it in, and OPAL from
# the device tree (src/arch/ppc.rs, src/main.rs).
build_iso_petitboot() {
    local arch="$1"
    local mkiso
    mkiso="$(command -v xorriso || true)"
    if [[ -z "${mkiso}" ]]; then
        echo "note: no xorriso; skipping the ${arch} ISO"
        return
    fi
    local staging="${out_dir}/.iso-${arch}"
    rm -rf "${staging}"
    mkdir -p "${staging}/boot/grub"
    # The kernel as the firmware loads it; its debug information stays here.
    llvm-objcopy --strip-debug "${out_dir}/${arch}/nanochrono-kernel.elf" "${staging}/boot/nanochrono-kernel.elf"
    cat > "${staging}/boot/grub/grub.cfg" <<CFG
set timeout=5
set default=0

menuentry "NanoChronometer (${arch})" {
    linux /boot/nanochrono-kernel.elf
}
CFG
    "${mkiso}" -as mkisofs -quiet -R -J -V "NANOCHRONO" \
        -o "${out_dir}/nanochronometer_${arch}.iso" "${staging}" >/dev/null 2>&1 ||
        echo "error: could not write the ${arch} ISO" >&2
    rm -rf "${staging}"
}

build_iso_arm64() {
    local grub_mkrescue
    grub_mkrescue="$(command -v grub-mkrescue || command -v grub2-mkrescue || true)"
    if [[ -z "${grub_mkrescue}" ]]; then
        echo "note: no grub-mkrescue; skipping the ARM64 ISO"
        return
    fi

    # The arm64-efi GRUB modules. Prefer an explicit override, then the
    # system location, then nothing. The modules are not installed with the
    # x86 host toolchain: `grub2-efi-aa64-modules` supplies `/usr/lib/grub/
    # arm64-efi`. GRUB_MKRESCUE_AARCH64_MODULES can point at an extracted
    # copy (for a checkout on a machine without the package, or a CI
    # artifact).
    local grub_modules_dir="${GRUB_MKRESCUE_AARCH64_MODULES:-}"
    if [[ -z "${grub_modules_dir}" || ! -d "${grub_modules_dir}" ]]; then
        grub_modules_dir="/usr/lib/grub/arm64-efi"
    fi
    # Or the package unpacked into the cache, without installing it:
    #   dnf download grub2-efi-aa64-modules; rpm2cpio *.rpm | cpio -idm
    # run in ~/.cache/nanochrono/grub.
    local cached="${NANOCHRONO_CACHE:-${HOME}/.cache/nanochrono}/grub/usr/lib/grub/arm64-efi"
    if [[ ! -d "${grub_modules_dir}" && -d "${cached}" ]]; then
        grub_modules_dir="${cached}"
    fi
    if [[ ! -d "${grub_modules_dir}" ]]; then
        echo "note: no arm64-efi GRUB modules; skipping the ARM64 ISO"
        echo "      install grub2-efi-aa64-modules, or point"
        echo "      GRUB_MKRESCUE_AARCH64_MODULES at an extracted copy"
        return
    fi

    local kernel_elf="${out_dir}/aarch64/nanochrono-kernel.elf"

    local staging="${out_dir}/.iso-arm64"
    rm -rf "${staging}"
    mkdir -p "${staging}/boot/grub"

    if ! build_efi_app "${kernel_elf}" "${staging}/boot/nanochrono-kernel.efi"; then
        echo "error: could not build the ARM64 EFI application" >&2
        rm -rf "${staging}"
        return
    fi

    cat > "${staging}/boot/grub/grub.cfg" <<'CFG'
set timeout=3
set default=0

insmod all_video
insmod gfxterm
terminal_output gfxterm

menuentry "NanoChronometer ARM64 (freestanding)" {
    chainloader /boot/nanochrono-kernel.efi
    boot
}

menuentry "NanoChronometer ARM64 (text mode)" {
    chainloader /boot/nanochrono-kernel.efi
    boot
}
CFG
    "${grub_mkrescue}" -d "${grub_modules_dir}" \
        -o "${out_dir}/nanochronometer_arm64.iso" "${staging}" >/dev/null 2>&1
    rm -rf "${staging}"
}

# The ISOs are built in `run` mode too, before anything boots: the x86 run
# boots from the ISO when there is one, because QEMU's own -kernel loader
# speaks multiboot1 only and hands over no framebuffer.
#
# Built in the order they were requested so that a one-architecture run
# produces that architecture's ISO and nothing else. Only ISOs that exist
# afterwards are reported — each builder skips quietly when its tools are
# missing.
iso_made=""
for arch in x86_64 i386; do
    if [[ -f "${out_dir}/${arch}/nanochrono-kernel.elf" ]]; then
        build_iso_x86 "${arch}"
        [[ -f "${out_dir}/nanochronometer_${arch}.iso" ]] && iso_made="${iso_made} ${arch}"
    fi
done
if [[ -f "${out_dir}/aarch64/nanochrono-kernel.elf" ]]; then
    build_iso_arm64
    [[ -f "${out_dir}/nanochronometer_arm64.iso" ]] && iso_made="${iso_made} arm64"
fi
for arch in ppc64 ppc64le; do
    if [[ -f "${out_dir}/${arch}/nanochrono-kernel.elf" ]]; then
        build_iso_petitboot "${arch}"
        [[ -f "${out_dir}/nanochronometer_${arch}.iso" ]] && iso_made="${iso_made} ${arch}"
    fi
done
for row in arm32:BOOTARM.EFI riscv64:BOOTRISCV64.EFI riscv32:BOOTRISCV32.EFI; do
    arch="${row%%:*}"
    if [[ -f "${out_dir}/${arch}/nanochrono-kernel.elf" ]]; then
        build_iso_efi "${arch}" "${row#*:}"
        [[ -f "${out_dir}/nanochronometer_${arch}.iso" ]] && iso_made="${iso_made} ${arch}"
    fi
done
if [[ -f "${out_dir}/ppc/nanochrono-kernel.elf" ]]; then
    build_iso_ppc_of
    [[ -f "${out_dir}/nanochronometer_ppc_of.iso" ]] && iso_made="${iso_made} ppc-of"
fi
[[ -n "${iso_made}" ]] && echo "ISOs built for:${iso_made}"

if [[ "${mode}" == "run" ]]; then
    for arch in "${run_requested[@]}"; do
        run_one "${arch}"
    done
    exit 0
fi

if [[ "${mode}" == "gdb" || "${mode}" == "boot" ]]; then
    run_gdb
    exit 0
fi

if [[ "${mode}" == "debug" || "${mode}" == "debug-og" ]]; then
    echo
    echo "=== ${out_dir}"
    find "${out_dir}" -type f -printf '%p  %s bytes\n' | sort
    exit 0
fi

if [[ "${mode}" == "build" ]]; then
    cp "${repo_root}/LICENSE" "${repo_root}/NOTICE" "${out_dir}/"
    cp "${repo_root}/docs/BAREMETAL_LIBRARIES.md" "${repo_root}/docs/BAREMETAL_DRIVERS.md" \
        "${out_dir}/"
    cp "${repo_root}/packaging/baremetal/README.release.md" "${out_dir}/README.md"
    echo
    echo "=== ${out_dir}"
    find "${out_dir}" -type f -printf '%p  %s bytes\n' | sort
fi
