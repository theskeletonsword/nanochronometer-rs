// SPDX-License-Identifier: Apache-2.0
//! RISC-V: entry, the trap vector, and the SBI.
//!
//! The kernel runs in S-mode under an SBI implementation (OpenSBI on QEMU's
//! `virt` and on most boards), which enters it with the MMU off (`satp` =
//! Bare), `a0` = this hart's ID and `a1` = the device tree. Only one hart
//! enters: the SBI's hart state management keeps the others stopped until
//! someone starts them, so there is nothing to park.
//!
//! # What the stub fixes before Rust
//!
//! * **`gp`**, the global pointer the linker may relax accesses against.
//! * **`sp`**, 16-byte aligned (the psABI's requirement at every call).
//! * **`.bss`**, zeroed.
//! * **`sstatus.FS` and `sstatus.VS`** set to Initial. With either at Off,
//!   every floating-point or vector instruction is an illegal instruction —
//!   the RISC-V counterpart of `CR0.EM` on x86 and `CPACR_EL1.FPEN` on
//!   AArch64. Both fields are WARL, so the write is harmless on a hart
//!   without F or V (privileged spec, "Extension Context Status").
//! * **`stvec`**, before anything can fault.
//!
//! RISC-V has no red zone in its ABI, so there is nothing to disable there.

use core::arch::asm;

macro_rules! entry_asm {
    ($store:literal, $stride:literal, $fcsr:literal) => {
        concat!(
            r#"
.section .text.boot, "ax"
.global _start
_start:
    csrw sie, zero
    csrci sstatus, 2

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    la t0, __bss_start
    la t1, __bss_end
1:  bgeu t0, t1, 2f
    "#, $store, r#" zero, 0(t0)
    addi t0, t0, "#, $stride, r#"
    j 1b

2:  la sp, nc_stack_top

    // sstatus.FS (bits 14:13) and VS (bits 10:9) = Initial.
    li t0, (1 << 13) | (1 << 9)
    csrs sstatus, t0
    "#, $fcsr, r#"

    la t0, nc_trap_entry
    csrw stvec, t0

    // a0 = hart ID, a1 = device tree: kmain's arguments, untouched above.
    call kmain
3:  wfi
    j 3b

// ---------------------------------------------------------------------------
// The trap vector (direct mode: every trap lands here).
//
// Every trap is fatal except one: an illegal instruction at one of the
// counter probe sites below, which is how the PMU driver learns whether
// firmware let S-mode read `cycle` and `instret`. There the handler steps
// over the 4-byte `csrr`, reports failure in a1, and returns.
// ---------------------------------------------------------------------------
.section .text.nc_trap, "ax"
.balign 4
nc_trap_entry:
    csrw sscratch, t0
    csrr t0, scause
    xori t0, t0, 2
    bnez t0, 9f
    csrr t0, sepc
    // Not a probe site means fatal, so a1 need not survive past here.
    la a1, nc_rv_probe_site_cycle
    beq t0, a1, 8f
    la a1, nc_rv_probe_site_instret
    beq t0, a1, 8f
    j 9f
8:  addi t0, t0, 4
    csrw sepc, t0
    li a0, 0
    li a1, 0
    csrr t0, sscratch
    sret

9:  // Fatal: a private stack (the fault may have been a stack overflow).
    la sp, nc_exc_stack_top
    csrr a0, scause
    csrr a1, sepc
    csrr a2, stval
    call nanochrono_riscv_exception
4:  wfi
    j 4b

// Probes: a0 = the counter's low word, a1 = 1 if it was readable.
.section .text.nc_probe, "ax"
.global nc_rv_try_cycle
nc_rv_try_cycle:
    li a1, 1
.global nc_rv_probe_site_cycle
nc_rv_probe_site_cycle:
    .option push
    .option norvc
    csrr a0, cycle
    .option pop
    ret

.global nc_rv_try_instret
nc_rv_try_instret:
    li a1, 1
.global nc_rv_probe_site_instret
nc_rv_probe_site_instret:
    .option push
    .option norvc
    csrr a0, instret
    .option pop
    ret

.section .bss.nc_stack, "aw", @nobits
.balign 16
nc_stack_bottom:
    .skip 65536
nc_stack_top:
.balign 16
nc_exc_stack_bottom:
    .skip 16384
nc_exc_stack_top:
"#
        )
    };
}

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(entry_asm!("sd", "8", "csrw fcsr, zero"));

// RV32 is built as `imac` here: no F, so no `fcsr` to clear (writing it
// would be an illegal instruction), and 4-byte stores.
#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(entry_asm!("sw", "4", ""));

extern "C" {
    fn nc_rv_try_cycle() -> ProbeResult;
    fn nc_rv_try_instret() -> ProbeResult;
}

/// What a probe stub returns in `a0`/`a1`.
#[repr(C)]
struct ProbeResult {
    _low: usize,
    readable: usize,
}

/// Whether S-mode may read `cycle` (firmware set `mcounteren.CY`).
pub fn cycle_readable() -> bool {
    // SAFETY: the stub's only possible fault is the one the trap vector
    // turns into `readable = 0`.
    unsafe { nc_rv_try_cycle() }.readable != 0
}

/// Whether S-mode may read `instret` (firmware set `mcounteren.IR`).
pub fn instret_readable() -> bool {
    // SAFETY: as above.
    unsafe { nc_rv_try_instret() }.readable != 0
}

/// Reports a fatal trap and stops. Entered from the trap vector on a private
/// stack; never returns.
#[no_mangle]
extern "C" fn nanochrono_riscv_exception(scause: usize, sepc: usize, stval: usize) -> ! {
    let interrupt = scause >> (usize::BITS - 1) != 0;
    let code = scause & !(1 << (usize::BITS - 1));
    let name = if interrupt {
        "interrupt"
    } else {
        match code {
            0 => "instruction address misaligned",
            1 => "instruction access fault",
            2 => "illegal instruction",
            3 => "breakpoint",
            4 => "load address misaligned",
            5 => "load access fault",
            6 => "store address misaligned",
            7 => "store access fault",
            8 => "environment call from U-mode",
            9 => "environment call from S-mode",
            12 => "instruction page fault",
            13 => "load page fault",
            15 => "store page fault",
            _ => "other",
        }
    };
    crate::println!();
    crate::println!("exception: scause={scause:#x} ({name})");
    crate::println!("  sepc={sepc:#x} stval={stval:#x}");
    crate::println!("stopped; not restarting");
    crate::arch::halt()
}

// ---------------------------------------------------------------------------
// SBI
// ---------------------------------------------------------------------------

/// SBI extension IDs and function IDs used here (SBI specification v2.0).
pub mod sbi {
    pub const EXT_BASE: usize = 0x10;
    pub const BASE_GET_SPEC_VERSION: usize = 0;
    pub const BASE_GET_IMPL_ID: usize = 1;
    pub const BASE_GET_IMPL_VERSION: usize = 2;
    pub const BASE_PROBE_EXTENSION: usize = 3;
    /// Debug console, "DBCN".
    pub const EXT_DBCN: usize = 0x4442_434E;
    pub const DBCN_WRITE: usize = 0;
    pub const DBCN_READ: usize = 1;
    /// The legacy console getchar (extension 0x02): a0 = the byte, or -1.
    pub const EXT_LEGACY_GETCHAR: usize = 0x02;
    /// The legacy console putchar (extension 0x01, no function ID).
    pub const EXT_LEGACY_PUTCHAR: usize = 0x01;

    /// Implementation names, by the IDs the specification assigns.
    pub fn impl_name(id: usize) -> &'static str {
        match id {
            0 => "BBL",
            1 => "OpenSBI",
            2 => "Xvisor",
            3 => "KVM",
            4 => "RustSBI",
            5 => "Diosix",
            6 => "Coffer",
            7 => "Xen",
            8 => "PolarFire HSS",
            9 => "coreboot",
            10 => "oreboot",
            11 => "bhyve",
            _ => "unknown",
        }
    }
}

/// One SBI call: `ecall` with a7 = extension, a6 = function. Returns
/// `(error, value)`.
///
/// # Safety
/// S-mode, and the arguments must be what the called function defines —
/// addresses passed are physical, which is what they are with `satp` Bare.
pub unsafe fn sbi_call(ext: usize, fid: usize, a0: usize, a1: usize, a2: usize) -> (isize, usize) {
    let (error, value): (isize, usize);
    // SAFETY: forwarded from this function's contract. The SBI preserves
    // every register except a0 and a1.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") a0 => error,
            inlateout("a1") a1 => value,
            in("a2") a2,
            in("a6") fid,
            in("a7") ext,
            options(nostack),
        );
    }
    (error, value)
}

/// Whether the SBI implements extension `ext`.
pub fn sbi_has(ext: usize) -> bool {
    // SAFETY: the base extension exists on every SBI v0.2+ implementation,
    // and probing is a pure query.
    let (error, value) = unsafe { sbi_call(sbi::EXT_BASE, sbi::BASE_PROBE_EXTENSION, ext, 0, 0) };
    error == 0 && value != 0
}

/// `(spec version, implementation ID, implementation version)`.
pub fn sbi_identity() -> (usize, usize, usize) {
    // SAFETY: base-extension queries; no side effects.
    unsafe {
        let spec = sbi_call(sbi::EXT_BASE, sbi::BASE_GET_SPEC_VERSION, 0, 0, 0).1;
        let id = sbi_call(sbi::EXT_BASE, sbi::BASE_GET_IMPL_ID, 0, 0, 0).1;
        let version = sbi_call(sbi::EXT_BASE, sbi::BASE_GET_IMPL_VERSION, 0, 0, 0).1;
        (spec, id, version)
    }
}

/// `sstatus`.
pub fn sstatus() -> usize {
    let v: usize;
    // SAFETY: readable in S-mode, no side effects.
    unsafe { asm!("csrr {v}, sstatus", v = out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Whether `sstatus.VS` took the stub's write.
///
/// Necessary but not sufficient for V: the privileged spec lets a hart with
/// S-mode and no vector registers keep a writable VS field ("may optionally
/// be read-only zero"). The device tree's ISA string is the other half; the
/// kernel requires both before a vector instruction is dispatched.
pub fn vector_state_enabled() -> bool {
    sstatus() & (0b11 << 9) != 0
}
