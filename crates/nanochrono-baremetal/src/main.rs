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
// the e500 TLB, OPAL from the device tree, RISC-V's vector check); elsewhere
// the console took it over.
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv32",
    target_arch = "riscv64"
))]
use nanochrono_baremetal::arch;
use nanochrono_baremetal::{selftest, serial::Serial};
// Only the text-mode banner names it, and that path is x86 firmware.
#[cfg(x86_any)]
use nanochrono_baremetal::VERSION;
#[cfg(x86_any)]
use nanochrono_baremetal::{multiboot, panic, progress};

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
    // The processor controls, from what CPUID says (cpu_control): before
    // anything that relies on them — the PMU, the counter, the hypervisor.
    // SAFETY: CPL 0, once, before any plugin.
    unsafe { nanochrono_baremetal::cpu_control::configure() };
    // The kernel stacks: NMI, #MC and #DB on stacks of their own, every other
    // exception on RSP0 or the current stack (docs/NCCALL.md §3). boot32.S's
    // early tables covered everything up to here.
    // SAFETY: CPL 0, once, interrupts masked.
    #[cfg(target_arch = "x86_64")]
    if let Err(e) = unsafe { nanochrono_baremetal::kstack::install() } {
        println!("kstack: {e}; the boot-time stack plan stays");
    }

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

    // Physical pages, from the loader's memory map: for what the image cannot
    // size in advance — a back buffer larger than the static one (a 4K
    // screen), a driver module's memory (palloc).
    if magic == MULTIBOOT2_BOOTLOADER_MAGIC || magic == MULTIBOOT1_BOOTLOADER_MAGIC {
        // SAFETY: once, before anything is allocated; the magic says which
        // structure `multiboot_info` is.
        let pages = unsafe {
            nanochrono_baremetal::palloc::init_multiboot(multiboot_info, magic == MULTIBOOT2_BOOTLOADER_MAGIC)
        };
        println!(
            "memory: {} MiB in {} runs free for pages, below {} MiB",
            pages.free >> 20,
            pages.runs,
            nanochrono_baremetal::palloc::CEILING >> 20
        );
    }

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

    // `crashtest=<de|pf|gp|ud|so|df|xm|mf|nm|panic>` on the command line
    // raises that fault on purpose (i386: all but so, which needs a guard
    // page its 4 MiB pages cannot hold): the way to prove, on the machine in question, that a fault —
    // the floating-point and SIMD ones too — ends in a crash dump and a stop
    // screen rather than a reset. It is *armed* here and fired later — after
    // the interface has brought up USB and handed the dumper the stick — so
    // the dump exercises the USB path too, not only serial. The
    // no-framebuffer console path, which brings up no USB, fires it
    // immediately before it starts. GRUB: press `e` on the entry and append
    // it to the `multiboot2` line. QEMU: `-append`.
    {
        // SAFETY: the magic says which structure `multiboot_info` is.
        let line = unsafe {
            match magic {
                MULTIBOOT2_BOOTLOADER_MAGIC => multiboot::command_line(multiboot_info),
                MULTIBOOT1_BOOTLOADER_MAGIC => multiboot::command_line_v1(multiboot_info),
                _ => None,
            }
        };
        if let Some(line) = line {
            println!("command line: {line}");
            nanochrono_baremetal::boot::record_command_line(line);
            if let Some(test) = nanochrono_baremetal::crashdump::CrashTest::from_command_line(line) {
                nanochrono_baremetal::crashdump::arm_crashtest(test);
            }
            // `plugin=<name>` loads and runs <NAME>.ncplu from the boot
            // medium's FAT partition once the interface is up.
            #[cfg(target_arch = "x86_64")]
            if let Some(name) = line
                .split_ascii_whitespace()
                .find_map(|w| w.strip_prefix("plugin="))
            {
                nanochrono_baremetal::ncplu::arm_plugin(name);
            }
        }
    }

    // The modules the loader placed in memory: packages, libraries, drivers,
    // an initrd — filed under their paths for the session (`boot`, `vfs`).
    // SAFETY: the magic says which structure `multiboot_info` is.
    unsafe {
        multiboot::modules(
            multiboot_info,
            magic == MULTIBOOT2_BOOTLOADER_MAGIC,
            nanochrono_baremetal::boot::record_module,
        )
    };
    for m in nanochrono_baremetal::boot::modules() {
        println!("module: {} ({} bytes at {:#x})", m.name, m.end - m.start, m.start);
    }

    // Driver modules (`/boot/drivers/*.ncdri`): what the kernel does not
    // build in. A display driver that sets the monitor's native mode hands
    // its screen over here, and the session draws there instead of on the
    // firmware's framebuffer (docs/NCDRI.md).
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: once, at CPL 0, after the modules are recorded and the page
        // allocator is up, before anything draws the session.
        let drivers = unsafe { nanochrono_baremetal::ncdri::load_boot_drivers() };
        if drivers.found > 0 {
            println!(
                "ncdri: {} module(s): {} loaded, {} refused; {} device(s) attached",
                drivers.found, drivers.loaded, drivers.refused, drivers.attached
            );
        }
        if let Some(mut screen) = drivers.screen {
            if let Some(m) = drivers.monitor {
                match m.native {
                    Some((w, h, mhz)) => println!(
                        "display: monitor {} ({}), native {w}x{h} at {}.{:03} Hz",
                        m.name(), m.maker(), mhz / 1000, mhz % 1000
                    ),
                    None => println!("display: monitor {} ({}), no native mode stated", m.name(), m.maker()),
                }
            }
            // SAFETY: the old screen is never drawn on again: the panic
            // handler and the progress marker are handed the new one below.
            let composited = unsafe { screen.attach_back_buffer() };
            println!(
                "display: {}x{} from {}, {}",
                screen.width,
                screen.height,
                drivers.screen_device(),
                if composited { "composited" } else { "drawn directly (no memory for a back buffer)" }
            );
            fb = Some(screen);
            panic::set_framebuffer(fb);
            progress::attach(fb);
        }
    }

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
            unsafe { nanochrono_baremetal::session::start(Some(fb), memory) }
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
            // The console brings up no USB, so an armed crashtest fires here,
            // with only the serial dump available.
            // SAFETY: CPL 0, the IDT is installed; faulting is the point.
            unsafe {
                nanochrono_baremetal::crashdump::fire_pending_crashtest()
            };
            // SAFETY: at CPL 0; the serial console (or the CLI, over serial
            // and the text screen) needs no framebuffer.
            unsafe { nanochrono_baremetal::session::start(None, memory) }
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

    // The vector lengths. Enabling SVE and SME above only stops them
    // trapping; how wide they run is ZCR_ELx.LEN and SMCR_ELx.LEN, which
    // reset to UNKNOWN values, and each level's field caps every level below
    // it. Left alone, SVE and streaming SVE run at whatever width reset left
    // — the 128-bit floor, or anything up to the hardware's maximum — and the
    // probes measure that instead of the core. Each reachable level's LEN is
    // set to all ones, which reads as "the longest this core supports" (an
    // unimplemented length rounds down to one that is). Written after the
    // trap controls, which also gate these registers, at this level and EL1:
    //   ZCR_EL1  S3_0_C1_C2_0   ZCR_EL2  S3_4_C1_C2_0   ZCR_EL3  S3_6_C1_C2_0
    //   SMCR_EL1 S3_0_C1_C2_6   SMCR_EL2 S3_4_C1_C2_6   SMCR_EL3 S3_6_C1_C2_6
    // (generic names: the assembler needs no +sve/+sme to write them). SMCR
    // also holds FA64 (bit 31: the full A64 instruction set in streaming
    // mode) and EZT0 (bit 30: SME2's ZT0 register), set where
    // ID_AA64SMFR0_EL1.FA64 and ID_AA64PFR1_EL1.SME >= 2 say they exist; set
    // where they do not, they would be writes to RES0 bits.
    mrs x0, CurrentEL
    lsr x0, x0, #2
    cbz x9, 60f
    mov x1, #0xF
    cmp x0, #3
    b.ne 61f
    msr S3_6_C1_C2_0, x1
    b 62f
61: cmp x0, #2
    b.ne 62f
    msr S3_4_C1_C2_0, x1
62: msr S3_0_C1_C2_0, x1
    isb
60: cbz x10, 65f
    mov x1, #0xF
    mrs x2, S3_0_C0_C4_5
    tbz x2, #63, 63f
    orr x1, x1, #(1 << 31)
63: cmp x10, #2
    b.lo 64f
    orr x1, x1, #(1 << 30)
64: cmp x0, #3
    b.ne 66f
    msr S3_6_C1_C2_6, x1
    b 67f
66: cmp x0, #2
    b.ne 67f
    msr S3_4_C1_C2_6, x1
67: msr S3_0_C1_C2_6, x1
    isb
65:

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
    .skip 262144
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
    // SAFETY: EL1+, once.
    unsafe { nanochrono_baremetal::cpu_control::configure() };
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
    // The command line and the initrd, as the tree's /chosen carries them
    // (QEMU's -append and -initrd, or a loader's).
    if let Some(t) = tree.as_ref() {
        if let Some(args) = t.bootargs() {
            println!("command line: {args}");
            nanochrono_baremetal::boot::record_command_line(args);
        }
        if let Some((start, end)) = t.initrd() {
            println!("initrd: {} bytes at {start:#x}", end - start);
            nanochrono_baremetal::boot::record_module(nanochrono_baremetal::multiboot::Module {
                start,
                end,
                name: "initrd",
            });
        }
    }
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
            unsafe { nanochrono_baremetal::session::start(Some(&fb), nanochrono_baremetal::multiboot::Memory::default()) }
        }
        None => {
            println!(
                "no framebuffer (devicetree {}; add -device ramfb under QEMU)",
                if tree.is_some() { "found" } else { "not found" }
            );
            // SAFETY: forwarded; the console (or the CLI) owns the machine.
            unsafe { nanochrono_baremetal::session::start(None, nanochrono_baremetal::multiboot::Memory::default()) }
        }
    }
}

/// What skiboot puts in r6: it enters a kernel ePAPR style.
#[cfg(target_arch = "powerpc64")]
const EPAPR_MAGIC: u64 = 0x6550_4150;

/// OpenPOWER entry point, called from the stub in `arch::ppc` with the
/// device tree, OPAL base and OPAL entry the loader handed over (r3, r8,
/// r9), and r6 — [`EPAPR_MAGIC`] when that loader is skiboot rather than a
/// kexec from petitboot.
///
/// # Safety
/// Called once, by the boot stub, in hypervisor real mode with a valid stack,
/// TOC and `.bss`, and `MSR[FP,VEC,VSX]` set.
#[cfg(target_arch = "powerpc64")]
#[no_mangle]
pub unsafe extern "C" fn kmain(fdt: usize, opal_base: u64, opal_entry: u64, r6: u64) -> ! {
    // SAFETY: r3 holds the flattened tree, from skiboot or from a kexec;
    // translation is off, so the address is directly readable.
    let tree = unsafe { nanochrono_baremetal::fdt::Fdt::from_ptr(fdt as *const u8) };
    // OPAL as the device tree names it — skiboot publishes it there as well
    // as in r8/r9, and a kexec's purgatory is not bound to pass it on.
    let published = tree.as_ref().and_then(opal_from_tree);
    if let Some((base, entry)) = published {
        // SAFETY: before the first OPAL call.
        unsafe { arch::ppc::set_opal(base, entry) };
    }
    // SAFETY: OPAL's entry point is recorded; nothing else is driving the
    // console.
    unsafe { Serial::init() };
    let loader = if r6 == EPAPR_MAGIC { "skiboot" } else { "kexec (petitboot)" };
    let source = match published {
        Some(p) if p == (opal_base, opal_entry) => "the device tree and r8/r9",
        Some(_) => "the device tree",
        None => "r8/r9",
    };
    println!("booted by: {loader}, OPAL from {source}");
    // SAFETY: hypervisor state, once.
    unsafe { nanochrono_baremetal::cpu_control::configure() };
    nanochrono_baremetal::irq_priority::open_unset();

    match tree {
        Some(tree) => {
            if let Some(hz) = tree.timebase_frequency() {
                nanochrono_core::arch::powerpc::set_timebase_hz(hz);
            }
            // The command line petitboot (or QEMU's -append) put in /chosen.
            if let Some(args) = tree.bootargs() {
                println!("command line: {args}");
                nanochrono_baremetal::boot::record_command_line(args);
            }
        }
        None => println!("warning: r3 does not hold a valid device tree"),
    }

    // SAFETY: hypervisor state, which the PMU programming needs.
    unsafe { selftest::run() };
    // No framebuffer driver here: the session is the CLI, over the console.
    // SAFETY: as above; the session owns the machine from here on.
    unsafe { nanochrono_baremetal::session::start(None, nanochrono_baremetal::multiboot::Memory::default()) }
}

/// OPAL's base and entry from the `ibm,opal` node: `opal-base-address` and
/// `opal-entry-address`, 64-bit big-endian.
#[cfg(target_arch = "powerpc64")]
fn opal_from_tree(tree: &nanochrono_baremetal::fdt::Fdt<'_>) -> Option<(u64, u64)> {
    let be64 = |v: &[u8]| Some(u64::from_be_bytes(v.get(..8)?.try_into().ok()?));
    [&b"ibm,opal-v3"[..], b"ibm,opal-v2"].iter().find_map(|compatible| {
        let base = tree.compatible_property(compatible, b"opal-base-address")?;
        let entry = tree.compatible_property(compatible, b"opal-entry-address")?;
        Some((be64(base)?, be64(entry)?))
    })
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
    // ePAPR means an e500, whose IVORs the entry stub installed: nccall's
    // `sc` has its handler (IVOR8).
    nanochrono_baremetal::nccall::hal::set_trap_ready();
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
    // SAFETY: supervisor state, once.
    unsafe { nanochrono_baremetal::cpu_control::configure() };
    match (tree.is_some(), uart) {
        (true, Some(phys)) => println!("booted by: ePAPR loader, uart at {phys:#x}"),
        (true, None) => println!("booted by: ePAPR loader, no ns16550 in the device tree"),
        (false, _) => println!("booted by: unknown; r3 does not hold a valid device tree"),
    }
    if let Some(args) = tree.and_then(|t| t.bootargs()) {
        println!("command line: {args}");
        nanochrono_baremetal::boot::record_command_line(args);
    }

    // SAFETY: supervisor state.
    unsafe { selftest::run() };
    // No framebuffer driver here: the session is the CLI, over the UART.
    // SAFETY: as above; the session owns the machine from here on.
    unsafe { nanochrono_baremetal::session::start(None, nanochrono_baremetal::multiboot::Memory::default()) }
}

// 32-bit ARM entry (ARMv7-A, QEMU `virt` with a Cortex-A7/A15).
//
// QEMU enters an ELF `-kernel` in SVC mode with the MMU and caches off and
// every core running — or in HYP mode, on a machine with the virtualization
// extensions switched on (`-M virt,virtualization=on`), which is also how a
// hypervisor-capable bootloader hands over. Before Rust: park the
// secondaries, then make VFP and Advanced SIMD (NEON) usable at every level
// that could trap them — the hard-float ABI uses them from the first
// function:
//
// * HYP: HCPTR.TCP10/TCP11 trap cp10/cp11 (VFP and NEON) to HYP, TASE traps
//   Advanced SIMD alone and TTA trace access; all four cleared. The kernel
//   then drops to SVC, where it runs: its exception vectors and banked
//   stacks are PL1's.
// * CPACR (PL1): cp10/cp11 full access, and ASEDIS (bit 31) and D32DIS
//   (bit 30) cleared — set, they disable Advanced SIMD or registers
//   D16-D31 with VFP still on, and NEON code then dies on its first
//   instruction. NSACR, the secure side's say over the same coprocessors,
//   is not writable from the non-secure state the kernel is entered in; QEMU
//   and firmware set it for the non-secure world.
// * FPEXC.EN switches the unit on.
//
// Then the exception vectors (`arch::arm32`): without them an undefined
// instruction — a VFP or NEON one with the unit off, say — or an abort jumps
// through whatever VBAR reset left, and the core dies silently. Last, a stack
// and a zeroed `.bss`.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
.section .text.boot, "ax"
.arm
.fpu neon
.arch_extension virt
.arch_extension sec
.global _start
_start:
    mrc p15, 0, r0, c0, c0, 5       @ MPIDR
    ands r0, r0, #3
    bne 9f
    mrs r0, cpsr
    and r0, r0, #0x1f
    cmp r0, #0x1a                   @ HYP mode?
    bne 2f
    mrc p15, 4, r0, c1, c1, 2       @ HCPTR
    bic r0, r0, #(3 << 10)          @ TCP10, TCP11
    bic r0, r0, #(1 << 15)          @ TASE
    bic r0, r0, #(1 << 20)          @ TTA
    mcr p15, 4, r0, c1, c1, 2
    isb
    mov r0, #0xd3                   @ SVC, IRQ and FIQ masked
    orr r0, r0, #0x100              @ asynchronous aborts masked
    msr spsr_hyp, r0
    adr r0, 2f
    msr elr_hyp, r0
    eret
2:  mrc p15, 0, r0, c1, c0, 2       @ CPACR
    orr r0, r0, #(0xf << 20)        @ cp10, cp11: full access
    bic r0, r0, #(3 << 30)          @ ASEDIS, D32DIS
    mcr p15, 0, r0, c1, c0, 2
    isb
    mov r0, #0x40000000             @ FPEXC.EN
    vmsr fpexc, r0
    ldr r0, =nanochrono_arm32_vectors
    mcr p15, 0, r0, c12, c0, 0      @ VBAR
    mrc p15, 0, r0, c1, c0, 0       @ SCTLR
    bic r0, r0, #(1 << 13)          @ V: vectors at VBAR, not 0xffff0000
    bic r0, r0, #(1 << 30)          @ TE: exceptions taken in ARM state, as the table is
    mcr p15, 0, r0, c1, c0, 0
    isb
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
    .skip 262144
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
    // Caches on for the image, as on AArch64: the counterpart of x86's
    // CR0.PG (see `arch::arm32::enable_mmu`).
    // SAFETY: once, at PL1, MMU still off.
    if let Err(why) = unsafe { arch::arm32::enable_mmu() } {
        println!("warning: MMU left off ({why}); memory is strongly ordered, loads are uncached");
    }
    // SAFETY: PL1, once.
    unsafe { nanochrono_baremetal::cpu_control::configure() };
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
    // Translation on, identity-mapped: the counterpart of x86's CR0.PG (see
    // `arch::riscv::enable_paging`).
    // SAFETY: once, in S-mode with satp Bare.
    if let Err(why) = unsafe { arch::riscv::enable_paging() } {
        println!("warning: paging left off ({why})");
    }
    // SAFETY: S-mode, once.
    unsafe { nanochrono_baremetal::cpu_control::configure() };
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
    // SAFETY: supervisor state, once.
    unsafe { nanochrono_baremetal::cpu_control::configure() };
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
            unsafe { nanochrono_baremetal::session::start(Some(&fb), nanochrono_baremetal::multiboot::Memory::default()) }
        }
        Some((_, w, h, _, depth)) => {
            println!("screen is {w}x{h} at {depth} bpp; the interface needs 32 (QEMU: -g 1024x768x32)");
            // SAFETY: as above; the session (the CLI, with no screen) owns the
            // machine from here on.
            unsafe { nanochrono_baremetal::session::start(None, nanochrono_baremetal::multiboot::Memory::default()) }
        }
        None => {
            // SAFETY: as above.
            unsafe { nanochrono_baremetal::session::start(None, nanochrono_baremetal::multiboot::Memory::default()) }
        }
    }
}
