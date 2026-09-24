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
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
crate="${repo_root}/crates/nanochrono-baremetal"
out_dir="${repo_root}/dist/baremetal"

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
    [x86_64]="--features simd"
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

build_one() {
    local arch="$1" target="${arch_target[$1]}"
    echo "=== ${arch} (${target})"
    rustup target add "${target}" >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    (cd "${crate}" && cargo ${toolchain} build --release --target "${target}" \
        ${arch_features[${arch}]})

    mkdir -p "${out_dir}/${arch}"
    local elf="${crate}/target/${target}/release/nanochrono-kernel"
    cp "${elf}" "${out_dir}/${arch}/nanochrono-kernel.elf"
    cp "${crate}/target/${target}/release/libnanochrono_baremetal.a" "${out_dir}/${arch}/"

    # The shared object needs its own spec: position independent, dynamically
    # linkable, and without the kernel code model. It also needs a loader that
    # does not exist on bare metal — see docs/BAREMETAL_LIBRARIES.md.
    if [[ "${arch}" == "x86_64" ]]; then
        # shellcheck disable=SC2086
        (cd "${crate}" && cargo ${toolchain} rustc --release --lib \
            --target "${target}-dylib" --crate-type cdylib \
            ${arch_features[${arch}]}) || true
        local so="${crate}/target/${target}-dylib/release/libnanochrono_baremetal.so"
        [[ -f "${so}" ]] && cp "${so}" "${out_dir}/${arch}/"
    fi

    if [[ "${arch}" == "x86_64" ]]; then
        # QEMU's multiboot loader takes a 32-bit ELF only, because multiboot
        # entry is 32-bit protected mode. The image is ELF64 with a 32-bit
        # entry stub, so the container is rewritten rather than the code: every
        # address is below 4 GiB, so nothing is lost. GRUB accepts either.
        objcopy -O elf32-i386 "${elf}" "${out_dir}/${arch}/nanochrono-kernel.mb.elf"
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

mode="build"
if [[ "${1:-}" == "run" || "${1:-}" == "test" ]]; then
    mode="$1"
    shift
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
build_iso_x86() {
    local arch="$1"
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
    sed "s/@ARCH@/${arch}/g" > "${staging}/boot/grub/grub.cfg" <<'CFG'
set timeout=3
set default=0

insmod all_video
insmod gfxterm

set gfxmode=1920x1200x32,1920x1080x32,1680x1050x32,1600x900x32,1440x900x32,1366x768x32,1280x1024x32,1280x800x32,1024x768x32,auto
terminal_output gfxterm
set gfxpayload=keep

menuentry "NanoChronometer @ARCH@ (freestanding)" {
    multiboot2 /boot/nanochrono-kernel
    set gfxpayload=keep
    boot
}

menuentry "NanoChronometer @ARCH@ (text mode)" {
    set gfxpayload=text
    multiboot2 /boot/nanochrono-kernel
    boot
}
CFG
    "${grub_mkrescue}" -o "${out_dir}/nanochronometer_${arch}.iso" "${staging}" >/dev/null 2>&1
    rm -rf "${staging}"
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

if [[ "${mode}" == "build" ]]; then
    cp "${repo_root}/LICENSE" "${repo_root}/NOTICE" "${out_dir}/"
    cp "${repo_root}/docs/BAREMETAL_LIBRARIES.md" "${repo_root}/docs/BAREMETAL_DRIVERS.md" \
        "${out_dir}/"
    echo
    echo "=== ${out_dir}"
    find "${out_dir}" -type f -printf '%p  %s bytes\n' | sort
fi
