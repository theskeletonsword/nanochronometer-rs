// SPDX-License-Identifier: Apache-2.0
//! The freestanding kernel.
//!
//! Boots, measures, prints, halts. On x86-64 it is entered from `boot32.S`
//! once long mode is up; on AArch64 the loader lands directly on the stub
//! below; on PowerPC on the stub in `arch::ppc`.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(x86_any)]
use nanochrono_baremetal::acpi;
#[allow(unused_imports)]
use nanochrono_baremetal::println;
// `arch` only where an entry point still names it directly (the AArch64 MMU,
// the e500 TLB, RISC-V's vector check); elsewhere the console took it over.
#[cfg(any(target_arch = "aarch64", target_arch = "powerpc", target_arch = "riscv32", target_arch = "riscv64"))]
use nanochrono_baremetal::arch;
use nanochrono_baremetal::{selftest, serial::Serial};
// Only the text-mode banner names it, and that path is x86 firmware.
#[cfg(x86_any)]
use nanochrono_baremetal::VERSION;
#[cfg(x86_any)]
use nanochrono_baremetal::{gui, multiboot, panic, progress};

/// What a multiboot2 loader leaves in `EAX`. GRUB2 uses this one.
///
/// Checked rather than assumed: booted some other way, the info pointer in
/// `RSI` is not a multiboot structure and reading it would be reading
/// whatever happened to be in the register.
#[cfg(x86_any)]
const MULTIBOOT2_BOOTLOADER_MAGIC: u64 = 0x36D7_6289;

/// What a multiboot1 loader leaves in `EAX`. QEMU's `-kernel` uses this one.
#[cfg(x86_any)]
const MULTIBOOT1_BOOTLOADER_MAGIC: u64 = 0x2BAD_B002;

/// Entry point, called from `boot32.S` (x86_64) or `boot_i386.S` (i386) with
/// the multiboot magic and the info structure pointer.
///
/// # Safety
/// Called once, by the boot stub, at CPL 0 with a valid stack and paging on.
#[cfg(x86_any)]
#[no_mangle]
pub unsafe extern "C" fn kmain(magic: usize, multiboot_info: usize) -> ! {
    // Register-width arguments: RDI/RSI from boot32.S on x86_64, two cdecl
    // stack slots from boot_i386.S on i386. Widened once, here.
    let (magic, multiboot_info) = (magic as u64, multiboot_info as u64);
    // SAFETY: at CPL 0, and nothing else is driving COM1.
    unsafe { Serial::init() };

    let loader = match magic {
        MULTIBOOT2_BOOTLOADER_MAGIC => "multiboot2",
        MULTIBOOT1_BOOTLOADER_MAGIC => "multiboot1",
        other => {
            println!("warning: boot magic is {other:#x}, neither multiboot1 nor 2");
            println!("         the boot information structure is not being read");
            "unknown"
        }
    };
    println!("booted by: {loader}");
    // SAFETY: CPL 0; the APIC page is uncached (boot map) or paging is off.
    unsafe { nanochrono_baremetal::irq_priority::open() };

    // The tag parsers below read the multiboot2 layout. A multiboot1 info
    // structure starts with a flags word, not a total size, and read as a
    // multiboot2 tag list it is garbage: a stray "framebuffer tag" in it
    // would hand the renderer an arbitrary address to write pixels to. So
    // the pointer is only given to them when the magic says multiboot2.
    let mb2_info = if magic == MULTIBOOT2_BOOTLOADER_MAGIC { multiboot_info } else { 0 };

    // The loader was asked for a graphics mode in the multiboot header; this
    // is where it says whether it managed one. Without it everything still
    // works over serial, which is why the tag is marked optional.
    // SAFETY: `multiboot_info` is what the boot stub passed through from the
    // loader, and the magic above says whether it means anything.
    let mut fb = unsafe { multiboot::framebuffer(mb2_info) };

    // Where ACPI's root table is. **Only the loader can say this on a UEFI
    // machine**: the RSDP's address comes from the EFI configuration table,
    // and nothing puts a copy where the legacy scan looks — so a kernel that
    // only scans finds no ACPI at all on a recent laptop, and everything that
    // depends on the DSDT fails with it.
    // SAFETY: as above.
    if let Some(rsdp) = unsafe { multiboot::acpi_rsdp(mb2_info) } {
        acpi::set_root_table(rsdp);
    }

    // Before any device is brought up: take bus mastering away from every
    // device this kernel does not drive. With no IOMMU programmed, the bit is
    // all that stands between a device and the whole of memory — see
    // `pci::restrict_bus_masters` for what this does and does not stop.
    // SAFETY: CPL 0, single core, nothing driven yet.
    let dma = unsafe { nanochrono_baremetal::pci::restrict_bus_masters() };
    println!("dma: bus mastering revoked on {}, kept on {}", dma.revoked, dma.kept);

    // How much memory the machine has, which the interface reports and which
    // only the loader can say.
    // SAFETY: as above.
    let memory = match magic {
        MULTIBOOT2_BOOTLOADER_MAGIC => unsafe { multiboot::memory(multiboot_info) },
        // SAFETY: as above; the magic says this is a multiboot1 structure.
        MULTIBOOT1_BOOTLOADER_MAGIC => unsafe { multiboot::memory_v1(multiboot_info) },
        _ => multiboot::Memory::default(),
    };

    // The back buffer, before anything is drawn. Everything after this point
    // draws into RAM and copies out only what changed — see
    // `framebuffer` for why an uncached firmware framebuffer cannot be
    // animated directly.
    if let Some(surface) = fb.as_mut() {
        // SAFETY: called once, here, before any drawing.
        let composited = unsafe { surface.attach_back_buffer() };
        if !composited {
            println!("mode too large for the back buffer; drawing directly");
        }
    }
    // Handed to the panic handler, which takes no arguments and so cannot be
    // given one any other way.
    panic::set_framebuffer(fb);

    // And to the progress marker, before anything that could stop. On a
    // machine with no serial port this is the only way to see how far a boot
    // got — see `progress`.
    progress::attach(fb);
    progress::leave(progress::Phase::Entered);

    match fb {
        // SAFETY: at CPL 0, with a framebuffer the loader described.
        Some(ref fb) => {
            println!(
                "framebuffer: {}x{}, drawing the interface",
                fb.width, fb.height
            );
            // SAFETY: at CPL 0, which the selftest's PMU programming needs.
            unsafe { selftest::run() };
            // SAFETY: at CPL 0, with a framebuffer the loader described.
            unsafe { gui::run(fb, memory) }
        }
        None => {
            // No linear framebuffer. On a BIOS machine the loader left a VGA
            // text mode behind, and that is somewhere to say so — without it
            // this halts with no output at all and the loader's last message
            // stays on screen, which is indistinguishable from a kernel that
            // never started. That is exactly how this failed on real
            // hardware.
            // SAFETY: at CPL 0. On a UEFI machine the write reaches ordinary
            // RAM and is merely invisible.
            unsafe { nanochrono_baremetal::vga::activate() };
            println!();
            println!("NanoChronometer {} — freestanding", VERSION);
            println!();
            println!("No linear framebuffer: the loader handed over a text mode.");
            println!("The graphical interface needs one; the measurements below do not.");
            println!();
            // SAFETY: at CPL 0, which the selftest's PMU programming needs.
            unsafe { selftest::run() };
            println!();
            println!("Boot with gfxpayload=keep for the interface.");
            // SAFETY: at CPL 0; the serial console needs no framebuffer.
            unsafe { nanochrono_baremetal::console::run() }
        }
    }
}

// AArch64 entry.
//
// `global_asm!` rather than a second `.S` file: nothing here has to sit at a
// fixed offset the way a multiboot header does, and the loader enters in
// 64-bit mode with the ABI already valid — so the only work is enabling
// FP/SIMD, a stack, a zeroed `.bss`, an exception vector table, and parking
// the secondary cores.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
.section .text.boot, "ax"
.global _start
_start:
    // Only the core whose affinity is all zeros runs the kernel. The others
    // are parked rather than left to race through the same code with the
    // same stack.
    //
    // All four affinity fields — Aff0 [7:0], Aff1 [15:8], Aff2 [23:16] and
    // Aff3 [39:32] — not just Aff0: on a multi-cluster part (and under QEMU
    // with more than one socket or cluster) core 0 of cluster 1 also has
    // Aff0 == 0, and masking only that byte lets it run too.
    mrs x0, mpidr_el1
    mov x1, #0xFFFFFF
    movk x1, #0xFF, lsl #32
    tst x0, x1
    b.eq 1f
0:  wfe
    b 0b

1:  // Enable FP and SIMD before any Rust runs.
    //
    // The AArch64 counterpart of what boot32.S does with CR0/CR4 on x86:
    // `aarch64-unknown-none` has NEON on, so the compiler emits vector
    // instructions freely, and every one of them traps until the controls
    // at *every* implemented level above this one allow it.
    //
    // x9 = ID_AA64PFR0_EL1.SVE != 0, x10 = ID_AA64PFR1_EL1.SME != 0. The SVE
    // and SME controls are only written when the feature exists: on a part
    // without them several of those bits are RES1 at EL2, and clearing them
    // would be writing a reserved field.
    mrs x0, id_aa64pfr0_el1
    ubfx x9, x0, #32, #4
    mrs x0, id_aa64pfr1_el1
    ubfx x10, x0, #24, #4

    mrs x0, CurrentEL
    lsr x0, x0, #2
    cmp x0, #3
    b.eq 7f
    cmp x0, #2
    b.eq 5f
    b 4f

7:  // EL3: CPTR_EL3.TFP (bit 10) traps FP when set; EZ (bit 8) and ESM
    // (bit 12) *enable* SVE and SME when set.
    mrs x0, cptr_el3
    bic x0, x0, #(1 << 10)
    cbz x9, 71f
    orr x0, x0, #(1 << 8)
71: cbz x10, 72f
    orr x0, x0, #(1 << 12)
72: msr cptr_el3, x0
    isb
    // Falls through to EL2's controls only if EL2 exists, which from EL3 is
    // not knowable without ID_AA64PFR0_EL1.EL2; the kernel stays at EL3, so
    // only EL3's and EL1's controls matter.
    b 4f

5:  // EL2. The layout of CPTR_EL2 depends on HCR_EL2.E2H.
    mrs x0, hcr_el2
    tbnz x0, #34, 51f

    // E2H == 0: the "trap" layout. TFP (bit 10) traps FP when set, TZ
    // (bit 8) traps SVE, TSM (bit 12) traps SME.
    mrs x0, cptr_el2
    bic x0, x0, #(1 << 10)
    cbz x9, 52f
    bic x0, x0, #(1 << 8)
52: cbz x10, 53f
    bic x0, x0, #(1 << 12)
53: msr cptr_el2, x0
    b 54f

51: // E2H == 1 (VHE): CPTR_EL2 takes CPACR_EL1's "enable" layout — FPEN
    // [21:20], ZEN [17:16], SMEN [25:24] — and clearing TFP-style bits would
    // leave FP trapped.
    mrs x0, cptr_el2
    orr x0, x0, #(3 << 20)
    cbz x9, 55f
    orr x0, x0, #(3 << 16)
55: cbz x10, 56f
    orr x0, x0, #(3 << 24)
56: msr cptr_el2, x0

54: isb
    // Fall through: CPACR_EL1 as well, so that anything later run at EL1
    // under this EL2 is not trapped either.

4:  // CPACR_EL1: FPEN [21:20], ZEN [17:16], SMEN [25:24] = 0b11, no trap at
    // EL0 or EL1. With E2H == 1 an EL2 write here is redirected to
    // CPTR_EL2, which was already set above to the same thing.
    mrs x0, cpacr_el1
    orr x0, x0, #(3 << 20)
    cbz x9, 41f
    orr x0, x0, #(3 << 16)
41: cbz x10, 42f
    orr x0, x0, #(3 << 24)
42: msr cpacr_el1, x0
    isb

    // The loader's stack, if any, is not ours. Point sp at the reserved
    // region below. `__boot_stack_top` is 16-byte aligned, which AAPCS64
    // requires of sp at every public interface.
    adrp x0, __boot_stack_top
    add  x0, x0, :lo12:__boot_stack_top
    mov  sp, x0

    // Rust assumes .bss is zeroed; nothing has done that yet. The linker
    // script aligns both bounds to 16, so the 8-byte stores neither start
    // misaligned nor run past the end.
    adrp x0, __bss_start
    add  x0, x0, :lo12:__bss_start
    adrp x1, __bss_end
    add  x1, x1, :lo12:__bss_end
2:  cmp  x0, x1
    b.hs 3f
    str  xzr, [x0], #8
    b    2b

3:  // Exception vectors, before anything can fault. Without them the first
    // synchronous exception — an undefined instruction, an alignment fault,
    // a hypercall nobody answers — jumps through an UNKNOWN VBAR and the
    // machine dies silently. VBAR_EL1 first; at EL2 VBAR_EL2 as well (with
    // E2H == 1 the EL1 write is redirected there and the EL2 write below
    // then replaces it with the EL2 table, which is the one that is used).
    bl nanochrono_install_vectors

    bl kmain
    // kmain does not return; if it somehow does, park.
9:  wfe
    b 9b

.section .bss
.balign 16
__boot_stack_bottom:
    .skip 65536
__boot_stack_top:
"#
);

/// AArch64 entry point, called from the stub above.
///
/// # Safety
/// Called once, at EL1 or EL2, with a valid stack and `.bss` zeroed.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn kmain() -> ! {
    // SAFETY: at EL1+, and nothing else is driving the UART.
    unsafe { Serial::init() };
    // Caches on for the image before anything is measured; see
    // `arch::arm::enable_mmu` for why the MMU-off numbers are wrong.
    // SAFETY: once, at the entry level, MMU still off.
    if let Err(why) = unsafe { arch::arm::enable_mmu() } {
        println!("warning: MMU left off ({why}); memory is Device, loads are uncached");
    }
    // SAFETY: at EL1+, which the PMU programming requires.
    unsafe { selftest::run() };

    // QEMU puts the devicetree at the start of RAM for an ELF linked clear
    // of it (see boot/aarch64.ld); from it, a screen: the firmware's
    // simple-framebuffer, or QEMU's ramfb.
    // SAFETY: the start of RAM is identity-mapped; `from_ptr` checks the magic.
    let tree = unsafe { nanochrono_baremetal::fdt::Fdt::from_ptr(0x4000_0000 as *const u8) };
    // SAFETY: EL1, the GIC's window mapped as device memory.
    unsafe { nanochrono_baremetal::irq_priority::open(tree.as_ref()) };
    // SAFETY: EL1+, RAM and MMIO mapped.
    unsafe { devicetree_interface(tree) }
}

/// The interface on a devicetree machine: its screen is the firmware's
/// simple-framebuffer or QEMU's ramfb; with neither, the serial console.
///
/// # Safety
/// Supervisor mode, with RAM and the devices the tree names mapped.
#[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "riscv64", target_arch = "riscv32"))]
unsafe fn devicetree_interface(tree: Option<nanochrono_baremetal::fdt::Fdt<'static>>) -> ! {
    // SAFETY: devices come from the tree; forwarded from the contract.
    let fb = tree.as_ref().and_then(|t| unsafe {
        nanochrono_baremetal::ramfb::simple_framebuffer(t).or_else(|| nanochrono_baremetal::ramfb::ramfb(t))
    });
    match fb {
        Some(mut fb) => {
            println!("framebuffer: {}x{}, drawing the interface", fb.width, fb.height);
            // SAFETY: once, before any drawing.
            unsafe { fb.attach_back_buffer() };
            // SAFETY: forwarded; a framebuffer the tree described.
            unsafe { nanochrono_baremetal::gui::run(&fb, nanochrono_baremetal::multiboot::Memory::default()) }
        }
        None => {
            println!(
                "no framebuffer (devicetree {}; add -device ramfb under QEMU)",
                if tree.is_some() { "found" } else { "not found" }
            );
            // SAFETY: forwarded; the console owns the machine from here on.
            unsafe { nanochrono_baremetal::console::run() }
        }
    }
}

/// OpenPOWER entry point, called from the stub in `arch::ppc` with the
/// device tree, OPAL base and OPAL entry skiboot handed over.
///
/// # Safety
/// Called once, by the boot stub, in hypervisor real mode with a valid stack,
/// TOC and `.bss`, and `MSR[FP,VEC,VSX]` set.
#[cfg(target_arch = "powerpc64")]
#[no_mangle]
pub unsafe extern "C" fn kmain(fdt: usize, _opal_base: u64, _opal_entry: u64) -> ! {
    // SAFETY: OPAL's entry point was recorded by the stub; nothing else is
    // driving the console.
    unsafe { Serial::init() };
    println!("booted by: skiboot (OPAL)");
    nanochrono_baremetal::irq_priority::open_unset();

    // SAFETY: skiboot passes the flattened tree in r3; translation is off, so
    // the address is directly readable.
    match unsafe { nanochrono_baremetal::fdt::Fdt::from_ptr(fdt as *const u8) } {
        Some(tree) => {
            if let Some(hz) = tree.timebase_frequency() {
                nanochrono_core::arch::powerpc::set_timebase_hz(hz);
            }
        }
        None => println!("warning: r3 does not hold a valid device tree"),
    }

    // SAFETY: hypervisor state, which the PMU programming needs.
    unsafe { selftest::run() };
    // SAFETY: as above; the console owns the machine from here on.
    unsafe { nanochrono_baremetal::console::run() }
}

/// Where the e500 UART's 1 MiB window is mapped. Above the RAM the loader
/// mapped from 0, below the top of the address space.
#[cfg(target_arch = "powerpc")]
const UART_WINDOW_VIRT: u32 = 0xF000_0000;

/// 32-bit PowerPC entry point, called from the stub in `arch::ppc` with
/// either the device tree an ePAPR loader passed (e500), or the Open Firmware
/// client interface entry (G3/G4, Pegasos) — the stub told them apart.
///
/// # Safety
/// Called once, by the boot stub, in supervisor state with a valid stack and
/// `.bss`, `MSR[FP]` set and, on e500, the exception vectors installed.
#[cfg(target_arch = "powerpc")]
#[no_mangle]
pub unsafe extern "C" fn kmain(fdt: usize, of_entry: usize) -> ! {
    if of_entry != 0 {
        // SAFETY: forwarded from this function's contract.
        unsafe { kmain_open_firmware(of_entry) }
    }
    // SAFETY: ePAPR passes the flattened tree in r3, inside the loader's
    // initial mapping.
    let tree = unsafe { nanochrono_baremetal::fdt::Fdt::from_ptr(fdt as *const u8) };
    let mut uart = None;
    if let Some(tree) = tree {
        if let Some(hz) = tree.timebase_frequency() {
            nanochrono_core::arch::powerpc::set_timebase_hz(hz);
        }
        // The UART has to be mapped before anything can be said, so the
        // tree is read in silence first.
        if let Some(phys) = tree.find_compatible_reg(b"ns16550") {
            let window = phys & !0xF_FFFF;
            // The highest TLB1 entry: loaders fill from slot 0 up.
            let tlb1cfg: usize;
            // SAFETY: TLB1CFG (SPR 689) is readable in supervisor state.
            unsafe {
                core::arch::asm!("mfspr {v}, 689", v = out(reg) tlb1cfg,
                                 options(nomem, nostack, preserves_flags));
            }
            let slot = ((tlb1cfg & 0xFFF) as u32).saturating_sub(1);
            // SAFETY: supervisor state on an e500; `slot` is the last entry,
            // which the loader's slot-0 RAM mapping is not, and the window
            // sits above RAM.
            if slot > 0 && unsafe { arch::ppc::e500_map_device(slot, UART_WINDOW_VIRT, window, 1 << 20) } {
                let virt = UART_WINDOW_VIRT as usize + (phys - window) as usize;
                nanochrono_baremetal::serial::set_uart_base(virt);
                uart = Some(phys);
                // The same 1 MiB CCSR window holds the MPIC's per-CPU page.
                // SAFETY: supervisor state; the window was just mapped.
                unsafe {
                    nanochrono_baremetal::irq_priority::open_mpic(&tree, window, UART_WINDOW_VIRT as usize, 1 << 20)
                };
            }
        }
    }

    // SAFETY: supervisor state; the UART, if any, was just mapped.
    unsafe { Serial::init() };
    match (tree.is_some(), uart) {
        (true, Some(phys)) => println!("booted by: ePAPR loader, uart at {phys:#x}"),
        (true, None) => println!("booted by: ePAPR loader, no ns16550 in the device tree"),
        (false, _) => println!("booted by: unknown; r3 does not hold a valid device tree"),
    }

    // SAFETY: supervisor state.
    unsafe { selftest::run() };
    // SAFETY: as above; the console owns the machine from here on.
    unsafe { nanochrono_baremetal::console::run() }
}

// 32-bit ARM entry (ARMv7-A, QEMU `virt` with a Cortex-A7/A15).
//
// QEMU enters an ELF `-kernel` in SVC mode with the MMU and caches off and
// every core running. Before Rust: park the secondaries, give PL1 and PL0
// access to the VFP/NEON coprocessors (CPACR cp10/cp11) and switch the unit
// on (FPEXC.EN) — the hard-float ABI uses it from the first function — then
// a stack and a zeroed `.bss`.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
.section .text.boot, "ax"
.arm
.fpu neon
.global _start
_start:
    mrc p15, 0, r0, c0, c0, 5       @ MPIDR
    ands r0, r0, #3
    bne 9f
    mrc p15, 0, r0, c1, c0, 2       @ CPACR
    orr r0, r0, #(0xf << 20)        @ cp10, cp11: full access
    mcr p15, 0, r0, c1, c0, 2
    isb
    mov r0, #0x40000000             @ FPEXC.EN
    vmsr fpexc, r0
    ldr sp, =__arm_stack_top
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    mov r2, #0
1:  cmp r0, r1
    strlo r2, [r0], #4
    blo 1b
    bl kmain
9:  wfe
    b 9b

.section .bss
.balign 16
__arm_stack_bottom:
    .skip 131072
__arm_stack_top:
"#
);

/// 32-bit ARM entry point, called from the stub above.
///
/// # Safety
/// Called once, in SVC mode, with a stack and `.bss` zeroed.
#[cfg(target_arch = "arm")]
#[no_mangle]
pub unsafe extern "C" fn kmain() -> ! {
    // SAFETY: PL1; nothing else drives the PL011.
    unsafe { Serial::init() };
    println!("booted by: -kernel (AArch32, SVC mode)");
    // As on AArch64: QEMU leaves the devicetree at the start of RAM for an
    // ELF linked clear of it (boot/arm32.ld).
    // SAFETY: MMU off, so every physical address is directly readable.
    let tree = unsafe { nanochrono_baremetal::fdt::Fdt::from_ptr(0x4000_0000 as *const u8) };
    if let Some(t) = tree.as_ref() {
        // The PSCI conduit, as the tree names it.
        let smc = t.compatible_str(b"arm,psci-1.0", b"method")
            .or_else(|| t.compatible_str(b"arm,psci-0.2", b"method"))
            .or_else(|| t.compatible_str(b"arm,psci", b"method"))
            == Some(b"smc");
        nanochrono_baremetal::acpi::set_psci_smc(smc);
    }
    // SAFETY: PL1, MMU off.
    unsafe { nanochrono_baremetal::irq_priority::open(tree.as_ref()) };
    // SAFETY: PL1, which the PMU and counter reads require.
    unsafe { selftest::run() };
    // SAFETY: PL1, MMU off: RAM and MMIO are directly addressed.
    unsafe { devicetree_interface(tree) }
}

/// RISC-V entry point, called from the stub in `arch::riscv` with the hart ID
/// and device tree the SBI passed in a0/a1.
///
/// # Safety
/// Called once, by the boot stub, in S-mode with a valid stack, `gp` and
/// `.bss`, `sstatus.FS`/`VS` set and `stvec` installed.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[no_mangle]
pub unsafe extern "C" fn kmain(hart: usize, fdt: usize) -> ! {
    use nanochrono_core::arch::riscv as rv;
    // SAFETY: the SBI passes the flattened tree in a1; with `satp` Bare its
    // address is directly readable.
    let tree = unsafe { nanochrono_baremetal::fdt::Fdt::from_ptr(fdt as *const u8) };
    let mut uart = None;
    if let Some(tree) = tree {
        if let Some(hz) = tree.timebase_frequency() {
            rv::set_timebase_hz(hz);
        }
        // V needs both the device tree's word and a live sstatus.VS; see
        // `arch::riscv::vector_state_enabled`. The newer `riscv,isa-extensions`
        // string list is asked first, then the classic ISA string.
        let listed = tree
            .cpu_property(b"riscv,isa-extensions")
            .is_some_and(|list| list.split(|&b| b == 0).any(|ext| ext == b"v"))
            || tree.cpu_property(b"riscv,isa").is_some_and(rv::isa_string_has_vector);
        rv::set_vector_available(listed && arch::riscv::vector_state_enabled());
        // The first `ns16550a` the tree lists; with none, the console is the
        // SBI's.
        if let Some(phys) = tree.find_compatible_reg(b"ns16550a") {
            nanochrono_baremetal::serial::set_uart_base(phys as usize);
            uart = Some(phys);
        }
    }

    // SAFETY: S-mode; nothing else drives the UART.
    unsafe { Serial::init() };
    match (tree.is_some(), uart) {
        (true, Some(phys)) => println!("booted by: SBI, hart {hart}, uart at {phys:#x}"),
        (true, None) => println!("booted by: SBI, hart {hart}, console via SBI"),
        (false, _) => println!("booted by: SBI, hart {hart}; a1 does not hold a valid device tree"),
    }

    // SAFETY: S-mode with `satp` Bare.
    unsafe { nanochrono_baremetal::irq_priority::open(tree.as_ref(), hart) };
    // SAFETY: S-mode.
    unsafe { selftest::run() };
    // SAFETY: S-mode with `satp` Bare: every physical address is reachable.
    unsafe { devicetree_interface(tree) }
}

/// The Open Firmware half of the 32-bit PowerPC entry: console and Time Base
/// rate from the client interface, `MSR[VEC]` on a G4.
///
/// # Safety
/// As `kmain`; `of_entry` is the client interface firmware passed in r5.
#[cfg(target_arch = "powerpc")]
unsafe fn kmain_open_firmware(of_entry: usize) -> ! {
    use nanochrono_baremetal::arch::ppc::{self as ppc, of};
    of::set_entry(of_entry);
    let console = of::open_console();
    if let Some(hz) = of::timebase_frequency() {
        nanochrono_core::arch::powerpc::set_timebase_hz(hz as u64);
    }
    if nanochrono_core::cpu::features().altivec {
        // SAFETY: supervisor state, on a core whose PVR says AltiVec.
        unsafe { ppc::enable_altivec() };
    }
    // SAFETY: supervisor state.
    unsafe { Serial::init() };
    nanochrono_baremetal::irq_priority::open_unset();
    println!(
        "booted by: Open Firmware, client interface at {of_entry:#x}{}",
        if console { "" } else { " (no stdout)" }
    );
    // SAFETY: supervisor state.
    unsafe { selftest::run() };

    // The screen, as Open Firmware describes it: the `screen` alias, and on
    // it the standard display properties. OpenBIOS sets the mode (QEMU's
    // `-g WxHxD`) before handing over, and keeps its mapping of the address.
    let screen = of::finddevice(b"screen\0").and_then(|node| {
        let prop = |name: &[u8]| of::getprop_u32(node, name);
        Some((
            prop(b"address\0")?,
            prop(b"width\0")?,
            prop(b"height\0")?,
            prop(b"linebytes\0")?,
            prop(b"depth\0")?,
        ))
    });
    match screen {
        Some((address, width, height, linebytes, 32)) if address != 0 && width > 0 && height > 0 => {
            println!("framebuffer: {width}x{height} at {address:#x}, drawing the interface");
            // SAFETY: Open Firmware maps its framebuffer for the client.
            let mut fb = unsafe {
                nanochrono_baremetal::framebuffer::Framebuffer::new(address as *mut u8, width, height, linebytes, 32)
            };
            // SAFETY: once, before any drawing.
            unsafe { fb.attach_back_buffer() };
            // SAFETY: supervisor state, a framebuffer the firmware described.
            unsafe { nanochrono_baremetal::gui::run(&fb, nanochrono_baremetal::multiboot::Memory::default()) }
        }
        Some((_, w, h, _, depth)) => {
            println!("screen is {w}x{h} at {depth} bpp; the interface needs 32 (QEMU: -g 1024x768x32)");
            // SAFETY: as above; the console owns the machine from here on.
            unsafe { nanochrono_baremetal::console::run() }
        }
        None => {
            // SAFETY: as above.
            unsafe { nanochrono_baremetal::console::run() }
        }
    }
}
