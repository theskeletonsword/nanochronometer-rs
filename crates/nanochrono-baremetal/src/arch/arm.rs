// SPDX-License-Identifier: Apache-2.0
//! AArch64 registers a hosted process cannot reach.
//!
//! Unlike x86, the counters themselves are already unprivileged here — the
//! shared crate reads `CNTVCT_EL0` and `CNTFRQ_EL0` from EL0. What needs EL1
//! is the PMU control block, which lives in `pmu`, and the exception-level
//! query below.

/// The exception level this code is executing at.
///
/// `CurrentEL[3:2]`. A kernel loaded by QEMU's `-kernel` starts at EL2 on a
/// machine with virtualization, and at EL1 otherwise, so this is worth knowing
/// before touching a register whose availability depends on it.
pub fn current_el() -> u8 {
    let v: u64;
    // SAFETY: `CurrentEL` is readable at every exception level and has no
    // side effects.
    unsafe {
        core::arch::asm!("mrs {v}, CurrentEL", v = out(reg) v,
                         options(nomem, nostack, preserves_flags));
    }
    ((v >> 2) & 0b11) as u8
}

// ---------------------------------------------------------------------------
// Exception vectors
// ---------------------------------------------------------------------------
//
// One table per exception level the kernel can be entered at, each 2 KiB
// aligned with sixteen 128-byte slots, as the architecture lays them out.
// Every slot but one is fatal: it reports the syndrome over the UART and
// stops. The exception is the synchronous slot for "current EL, SPx", which
// first checks for the one fault this kernel *expects* — an `HVC` that
// nothing answers — and turns it into the SMCCC "not supported" return.
//
// Why that one is expected: `HVC` from EL1 is UNDEFINED when EL2 is absent
// or disabled, and there is no way to ask beforehand. The old guard was a
// guess from `CNTFRQ_EL0`, which both let the call through on real hardware
// clocked at 1 GHz and blocked it under KVM on a board clocked at 54 MHz.
// Catching the fault is exact.
//
// The fatal path moves to a dedicated stack first, because the fault may
// have been a stack overflow, and a handler that pushes onto the stack that
// just overflowed faults again with nothing left to report it.
core::arch::global_asm!(
    r#"
.macro NC_FATAL el, kind
    .balign 128
    mov x3, #\kind
    b nc_fatal_el\el
.endm

.macro NC_VECTORS el
.section .text.nc_vectors_el\el, "ax"
.balign 2048
.global nanochrono_vectors_el\el
nanochrono_vectors_el\el:
    NC_FATAL \el, 0
    NC_FATAL \el, 1
    NC_FATAL \el, 2
    NC_FATAL \el, 3
    .balign 128
    b nc_sync_el\el
    NC_FATAL \el, 5
    NC_FATAL \el, 6
    NC_FATAL \el, 7
    NC_FATAL \el, 8
    NC_FATAL \el, 9
    NC_FATAL \el, 10
    NC_FATAL \el, 11
    NC_FATAL \el, 12
    NC_FATAL \el, 13
    NC_FATAL \el, 14
    NC_FATAL \el, 15

nc_sync_el\el:
    stp x0, x1, [sp, #-16]!
    mrs x0, esr_el\el
    lsr x0, x0, #26
    // EC 0 is "unknown reason", which is what an UNDEFINED HVC raises.
    cbnz x0, 1f
    mrs x0, elr_el\el
    adrp x1, nanochrono_hvc_insn
    add x1, x1, :lo12:nanochrono_hvc_insn
    cmp x0, x1
    b.ne 1f
    // Resume after the HVC with x0 = SMCCC_RET_NOT_SUPPORTED (-1).
    add x0, x0, #4
    msr elr_el\el, x0
    ldp x0, x1, [sp], #16
    mov x0, #-1
    eret
1:  ldp x0, x1, [sp], #16
    mov x3, #4
    b nc_fatal_el\el

nc_fatal_el\el:
    mrs x0, esr_el\el
    mrs x1, elr_el\el
    mrs x2, far_el\el
    mov x4, #\el
    adrp x5, nc_exception_stack_top
    add x5, x5, :lo12:nc_exception_stack_top
    mov sp, x5
    bl nanochrono_exception
2:  wfe
    b 2b
.endm

NC_VECTORS 1
NC_VECTORS 2
NC_VECTORS 3

// SMCCC call through HVC: x0 = function ID, x1 = argument, x2 = where to
// store x0..x3 on return. SMCCC 1.0 lets the callee clobber x0-x17, all of
// which AAPCS64 already treats as caller-saved, so only the output pointer
// and the link register need to survive the call.
.section .text.nanochrono_hvc, "ax"
.global nanochrono_hvc
nanochrono_hvc:
    stp x2, x30, [sp, #-16]!
    mov x2, xzr
    mov x3, xzr
.global nanochrono_hvc_insn
nanochrono_hvc_insn:
    hvc #0
    ldp x9, x30, [sp], #16
    stp x0, x1, [x9]
    stp x2, x3, [x9, #16]
    ret

.section .bss.nc_exception_stack, "aw", %nobits
.balign 16
nc_exception_stack_bottom:
    .skip 16384
nc_exception_stack_top:
"#
);

extern "C" {
    static nanochrono_vectors_el1: u8;
    static nanochrono_vectors_el2: u8;
    static nanochrono_vectors_el3: u8;
    fn nanochrono_hvc(function: u64, arg: u64, out: *mut [u64; 4]);
}

/// Points `VBAR_ELx` at the tables above, for this level and EL1.
///
/// Called by the entry stub, once, before `kmain`.
#[no_mangle]
extern "C" fn nanochrono_install_vectors() {
    let el = current_el();
    // SAFETY: the tables are 2 KiB aligned by construction and live for the
    // whole run. VBAR_EL1 is writable from EL1 and above; the higher
    // registers are written only at the level that owns them.
    unsafe {
        let v1 = &raw const nanochrono_vectors_el1 as u64;
        core::arch::asm!("msr vbar_el1, {v}", "isb", v = in(reg) v1,
                         options(nostack, preserves_flags));
        if el == 2 {
            let v2 = &raw const nanochrono_vectors_el2 as u64;
            core::arch::asm!("msr vbar_el2, {v}", "isb", v = in(reg) v2,
                             options(nostack, preserves_flags));
        }
        if el == 3 {
            let v3 = &raw const nanochrono_vectors_el3 as u64;
            core::arch::asm!("msr vbar_el3, {v}", "isb", v = in(reg) v3,
                             options(nostack, preserves_flags));
        }
    }
}

/// Issues an SMCCC call through `HVC` and returns `x0..x3`.
///
/// If nothing at EL2 answers, the instruction is UNDEFINED; the vector table
/// catches exactly that case and the call returns `x0 = -1`
/// (`SMCCC_RET_NOT_SUPPORTED`), which is what a hypervisor that does not know
/// the function would have said anyway.
///
/// # Safety
/// Must be called at EL1 with the vectors installed. At EL2 the call traps to
/// this kernel itself; callers check [`current_el`] first.
pub unsafe fn hvc(function: u64, arg: u64) -> [u64; 4] {
    let mut regs = [0u64; 4];
    // SAFETY: forwarded from this function's contract; `regs` is a live,
    // correctly sized out-parameter.
    unsafe { nanochrono_hvc(function, arg, &mut regs) };
    regs
}

/// Reports a fatal exception and stops. Entered from the vector table on a
/// private stack; never returns.
#[no_mangle]
extern "C" fn nanochrono_exception(esr: u64, elr: u64, far: u64, kind: u64, el: u64) -> ! {
    const SOURCE: [&str; 4] = ["current EL, SP0", "current EL, SPx", "lower EL, AArch64", "lower EL, AArch32"];
    const TYPE: [&str; 4] = ["synchronous", "IRQ", "FIQ", "SError"];
    let kind = (kind & 15) as usize;
    let ec = (esr >> 26) & 0x3F;
    crate::println!();
    crate::println!(
        "exception at EL{el}: {} ({})",
        TYPE[kind & 3],
        SOURCE[kind >> 2]
    );
    crate::println!("  esr={esr:#x} (ec={ec:#04x}: {})", ec_name(ec));
    crate::println!("  elr={elr:#x} far={far:#x}");
    crate::println!("stopped; not restarting");
    crate::arch::halt()
}

/// The exception classes worth naming, from the ESR_ELx.EC table.
fn ec_name(ec: u64) -> &'static str {
    match ec {
        0x00 => "unknown / undefined instruction",
        0x01 => "WFI/WFE trapped",
        0x07 => "FP/SIMD access trapped",
        0x0E => "illegal execution state",
        0x15 => "SVC",
        0x16 => "HVC",
        0x17 => "SMC",
        0x18 => "MSR/MRS/system instruction trapped",
        0x19 => "SVE access trapped",
        0x1D => "SME access trapped",
        0x20 | 0x21 => "instruction abort",
        0x22 => "PC alignment fault",
        0x24 | 0x25 => "data abort",
        0x26 => "SP alignment fault",
        0x2C => "FP exception",
        0x2F => "SError",
        0x3C => "BRK",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// The MMU
// ---------------------------------------------------------------------------
//
// With the MMU off every data access is Device-nGnRnE: uncached, unbuffered,
// in order. That is correct and slow, and for a chronometer it is *wrong* in
// a subtler way: a load probe measures a trip to DRAM every time, which is
// not what a load costs on the same machine under an operating system.
//
// So the kernel turns the MMU on with the plainest possible map: an identity
// map, 4 KiB granule, 39-bit addresses, one level-1 table of 1 GiB blocks —
// all Device and execute-never — except the gigabyte holding the kernel,
// which gets a level-2 table of 2 MiB blocks in which exactly the blocks the
// image occupies are Normal write-back. Nothing else is ever cacheable: MMIO
// on an unknown board may sit anywhere, including the kernel's own
// gigabyte, and a cacheable mapping of a device is a correctness bug, not a
// performance one.
//
// Table walks are Normal *non-cacheable* (TCR IRGN0/ORGN0 = 0): the tables
// were written with the MMU off, straight to memory, and a cacheable walk
// could read a stale line instead.

use core::arch::asm;

/// `MAIR_ELx`: attribute 0 Device-nGnRnE, attribute 1 Normal write-back
/// read/write-allocate, inner and outer.
const MAIR: u64 = 0xFF << 8;
const DESC_VALID_BLOCK: u64 = 0b01;
const DESC_TABLE: u64 = 0b11;
const DESC_AF: u64 = 1 << 10;
const DESC_ATTR_NORMAL: u64 = 1 << 2;
const DESC_SH_INNER: u64 = 3 << 8;
/// UXN / XN (bit 54): execute-never, in every translation regime.
const DESC_XN: u64 = 1 << 54;
/// PXN (bit 53): only defined in the EL1&0 regime.
const DESC_PXN: u64 = 1 << 53;

#[repr(C, align(4096))]
struct Table([u64; 512]);

static mut L1_TABLE: Table = Table([0; 512]);
static mut L2_TABLE: Table = Table([0; 512]);

/// Whether [`enable_mmu`] succeeded, for the report.
static MMU_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether the MMU is on with the kernel image cacheable.
pub fn mmu_enabled() -> bool {
    MMU_ON.load(core::sync::atomic::Ordering::Relaxed)
}

/// Builds the identity map and turns on the MMU and both caches for the
/// current exception level.
///
/// # Safety
/// Called once, early, at EL1, EL2 or EL3 with the MMU off, before anything
/// holds a pointer the new attributes could invalidate (none can: the map is
/// the identity).
pub unsafe fn enable_mmu() -> Result<(), &'static str> {
    extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    let el = current_el();
    let start = &raw const __kernel_start as u64;
    let end = &raw const __kernel_end as u64;
    let gib = start >> 30;
    if end <= start || (end - 1) >> 30 != gib {
        return Err("the image spans two gigabytes");
    }

    let mmfr0: u64;
    // SAFETY: ID registers are readable at EL1 and above.
    unsafe {
        asm!("mrs {v}, ID_AA64MMFR0_EL1", v = out(reg) mmfr0, options(nomem, nostack, preserves_flags));
    }
    let parange = mmfr0 & 0xF;
    let pa_bits: u64 = match parange {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        5 => 48,
        _ => 52,
    };
    // The output size is capped at 40 bits: a 39-bit input space cannot
    // name more, and IPS must not exceed what the part implements.
    let ips = parange.min(2);
    let blocks = if pa_bits >= 39 { 512 } else { 1u64 << (pa_bits - 30) };
    if gib >= blocks {
        return Err("the image lies above the implemented physical range");
    }

    let xn = if el == 1 { DESC_XN | DESC_PXN } else { DESC_XN };
    let device = |address: u64| address | DESC_AF | DESC_VALID_BLOCK | xn;
    let normal = |address: u64| address | DESC_AF | DESC_ATTR_NORMAL | DESC_SH_INNER | DESC_VALID_BLOCK;

    // SAFETY: called once, before anything else references the tables; the
    // MMU is off, so these stores go straight to memory.
    unsafe {
        let l1 = &raw mut L1_TABLE.0;
        let l2 = &raw mut L2_TABLE.0;
        for i in 0..512u64 {
            (*l1)[i as usize] = if i < blocks { device(i << 30) } else { 0 };
        }
        let base = gib << 30;
        let first = (start - base) >> 21;
        let last = (end - 1 - base) >> 21;
        for j in 0..512u64 {
            let address = base + (j << 21);
            (*l2)[j as usize] = if (first..=last).contains(&j) { normal(address) } else { device(address) };
        }
        (*l1)[gib as usize] = l2 as u64 | DESC_TABLE;
    }

    let l1 = &raw const L1_TABLE as u64;
    // T0SZ = 25 (39-bit), 4 KiB granule, walks non-cacheable non-shareable.
    let tcr = match el {
        // EL1, and EL2 with E2H = 1, use the EL1 layout: EPD1 (bit 23)
        // disables the upper-half walk, IPS at 34:32.
        1 => 25 | (1 << 23) | (ips << 32),
        2 if hcr_e2h() => 25 | (1 << 23) | (ips << 32),
        // EL2 with E2H = 0 and EL3: PS at 18:16, bits 31 and 23 RES1.
        _ => 25 | (ips << 16) | (1 << 31) | (1 << 23),
    };

    // SAFETY: the tables are complete. Stale lines over the image are
    // discarded first: everything written so far went straight to memory,
    // and a line left in the cache by the loader for these addresses would
    // otherwise shadow it once the region becomes cacheable. The loader is
    // required to have cleaned the image it loaded (the arm64 boot protocol),
    // so nothing of the image itself is lost.
    unsafe {
        let ctr: u64;
        asm!("mrs {v}, ctr_el0", v = out(reg) ctr, options(nomem, nostack, preserves_flags));
        let line = 4u64 << ((ctr >> 16) & 0xF);
        let mut at = start & !(line - 1);
        asm!("dsb sy", options(nostack, preserves_flags));
        while at < end {
            asm!("dc ivac, {a}", a = in(reg) at, options(nostack, preserves_flags));
            at += line;
        }
        asm!("dsb sy", "ic iallu", "dsb sy", "isb", options(nostack, preserves_flags));

        match el {
            1 => asm!(
                "msr mair_el1, {mair}",
                "msr tcr_el1, {tcr}",
                "msr ttbr0_el1, {ttbr}",
                "isb",
                "tlbi vmalle1",
                "dsb sy",
                "isb",
                "mrs {t}, sctlr_el1",
                "bic {t}, {t}, #(1 << 1)",
                "orr {t}, {t}, #(1 << 0)",
                "orr {t}, {t}, #(1 << 2)",
                "orr {t}, {t}, #(1 << 12)",
                "msr sctlr_el1, {t}",
                "isb",
                mair = in(reg) MAIR, tcr = in(reg) tcr, ttbr = in(reg) l1, t = out(reg) _,
                options(nostack, preserves_flags),
            ),
            2 => asm!(
                "msr mair_el2, {mair}",
                "msr tcr_el2, {tcr}",
                "msr ttbr0_el2, {ttbr}",
                "isb",
                "tlbi alle2",
                "dsb sy",
                "isb",
                "mrs {t}, sctlr_el2",
                "bic {t}, {t}, #(1 << 1)",
                "orr {t}, {t}, #(1 << 0)",
                "orr {t}, {t}, #(1 << 2)",
                "orr {t}, {t}, #(1 << 12)",
                "msr sctlr_el2, {t}",
                "isb",
                mair = in(reg) MAIR, tcr = in(reg) tcr, ttbr = in(reg) l1, t = out(reg) _,
                options(nostack, preserves_flags),
            ),
            _ => asm!(
                "msr mair_el3, {mair}",
                "msr tcr_el3, {tcr}",
                "msr ttbr0_el3, {ttbr}",
                "isb",
                "tlbi alle3",
                "dsb sy",
                "isb",
                "mrs {t}, sctlr_el3",
                "bic {t}, {t}, #(1 << 1)",
                "orr {t}, {t}, #(1 << 0)",
                "orr {t}, {t}, #(1 << 2)",
                "orr {t}, {t}, #(1 << 12)",
                "msr sctlr_el3, {t}",
                "isb",
                mair = in(reg) MAIR, tcr = in(reg) tcr, ttbr = in(reg) l1, t = out(reg) _,
                options(nostack, preserves_flags),
            ),
        }
    }
    MMU_ON.store(true, core::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// `HCR_EL2.E2H`, at EL2.
fn hcr_e2h() -> bool {
    let hcr: u64;
    // SAFETY: only called at EL2, where HCR_EL2 is readable.
    unsafe { asm!("mrs {v}, hcr_el2", v = out(reg) hcr, options(nomem, nostack, preserves_flags)) };
    hcr & (1 << 34) != 0
}
