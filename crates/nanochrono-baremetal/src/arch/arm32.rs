// SPDX-License-Identifier: Apache-2.0
//! 32-bit ARM exception vectors.
//!
//! The entry stub in `main.rs` points VBAR at [`nanochrono_arm32_vectors`]
//! before any Rust runs. One vector returns: the supervisor call, which is
//! `nccall` — answered by the dispatcher through `nanochrono_nccall_arm`
//! (src/nccall/hal.rs). Every other one is fatal: there are no interrupts to
//! take (they stay masked for the whole run) and no fault this kernel
//! expects, so each one reports what happened over the UART — the faulting
//! instruction, and for an abort the fault status and address — and stops.
//! Without the table the core would branch through whatever VBAR reset left
//! and die with nothing said; that is how an undefined VFP or NEON
//! instruction used to end.
//!
//! Each exception mode (UND, ABT, IRQ, FIQ) has a banked stack pointer that
//! nothing set up, so every handler loads one of its own first: the dedicated
//! exception stack, which also survives a fault that was a stack overflow.

core::arch::global_asm!(
    r#"
.section .text.nc_vectors_arm32, "ax"
.arm
.balign 32
.global nanochrono_arm32_vectors
nanochrono_arm32_vectors:
    b nc_arm32_reset
    b nc_arm32_undef
    b nc_arm32_svc
    b nc_arm32_prefetch
    b nc_arm32_data
    b nc_arm32_unused
    b nc_arm32_irq
    b nc_arm32_fiq

@ r0 = kind, r1 = the faulting instruction's address, r2 = SPSR, r3 = FSR,
@ and the FAR on the stack as the fifth argument.
.macro NC_ARM32_FATAL kind, lr_back, fsr, far
    ldr sp, =nc_arm32_exception_stack_top
    sub r1, lr, #\lr_back
    mrs r2, spsr
    .if \fsr == 1
    mrc p15, 0, r3, c5, c0, 0       @ DFSR
    mrc p15, 0, r12, c6, c0, 0      @ DFAR
    .elseif \fsr == 2
    mrc p15, 0, r3, c5, c0, 1       @ IFSR
    mrc p15, 0, r12, c6, c0, 2      @ IFAR
    .else
    mov r3, #0
    mov r12, #0
    .endif
    @ The fifth argument at [sp], keeping the stack 8-byte aligned (AAPCS).
    sub sp, sp, #8
    str r12, [sp]
    mov r0, #\kind
    bl nanochrono_arm32_exception
1:  wfi
    b 1b
.endm

nc_arm32_reset:    NC_ARM32_FATAL 0, 0, 0, 0
@ LR_und points past the undefined instruction: 4 bytes in ARM state. (In
@ Thumb state it is 2, which the report notes from the SPSR's T bit.)
nc_arm32_undef:    NC_ARM32_FATAL 1, 4, 0, 0
@ nccall. SVC mode's stack is the kernel's: from user mode the CPU switched
@ to it, from SVC mode (the self-test) it is the caller's own, and AAPCS
@ keeps nothing below the stack pointer. The frame: r0..r12, the return
@ address, the SPSR, a pad word — 64 bytes. The glue writes r0, r1 and the
@ C flag (SPSR bit 29); every other register comes back as it went in.
nc_arm32_svc:
    sub sp, sp, #8
    stmfd sp!, {{r0-r12, lr}}
    mrs r0, spsr
    str r0, [sp, #56]
    mov r0, sp
    mov r4, sp                      @ the frame, across the call (callee-saved)
    bic sp, sp, #7                  @ AAPCS: 8-byte aligned at a call
    bl nanochrono_nccall_arm
    mov sp, r4
    ldr r0, [sp, #56]
    msr spsr_cxsf, r0
    ldmfd sp!, {{r0-r12, lr}}
    add sp, sp, #8
    movs pc, lr                     @ back past the svc, CPSR from SPSR
nc_arm32_prefetch: NC_ARM32_FATAL 3, 4, 2, 0
@ LR_abt is 8 past the instruction that made a data abort.
nc_arm32_data:     NC_ARM32_FATAL 4, 8, 1, 0
nc_arm32_unused:   NC_ARM32_FATAL 5, 0, 0, 0
nc_arm32_irq:      NC_ARM32_FATAL 6, 4, 0, 0
nc_arm32_fiq:      NC_ARM32_FATAL 7, 4, 0, 0

.section .bss.nc_arm32_exception_stack, "aw", %nobits
.balign 16
nc_arm32_exception_stack_bottom:
    .skip 16384
.global nc_arm32_exception_stack_top
nc_arm32_exception_stack_top:
"#
);

/// Reports a fatal exception and stops. Entered from the vector table on the
/// private stack; never returns.
#[no_mangle]
extern "C" fn nanochrono_arm32_exception(kind: u32, pc: u32, spsr: u32, fsr: u32, far: u32) -> ! {
    const NAMES: [&str; 8] = [
        "reset",
        "undefined instruction",
        "supervisor call",
        "prefetch abort",
        "data abort",
        "reserved vector",
        "IRQ",
        "FIQ",
    ];
    let thumb = spsr & (1 << 5) != 0;
    // The undefined-instruction LR is 2 past a Thumb instruction, not 4.
    let pc = if kind == 1 && thumb { pc.wrapping_add(2) } else { pc };
    crate::println!();
    crate::println!(
        "exception: {} at pc={pc:#010x} ({} state), spsr={spsr:#010x}",
        NAMES.get(kind as usize).copied().unwrap_or("?"),
        if thumb { "Thumb" } else { "ARM" }
    );
    if kind == 3 || kind == 4 {
        crate::println!("  fsr={fsr:#x} ({}) far={far:#010x}", fault_status(fsr));
    }
    if kind == 1 {
        // The usual undefined instruction here is a VFP/NEON one that found
        // the unit off: say what the controls read now.
        let (cpacr, fpexc): (u32, u32);
        // SAFETY: CPACR and FPEXC are readable at PL1 and reading has no side
        // effects; FPEXC is readable even with the unit disabled.
        unsafe {
            core::arch::asm!("mrc p15, 0, {c}, c1, c0, 2", "vmrs {f}, fpexc",
                             c = out(reg) cpacr, f = out(reg) fpexc,
                             options(nomem, nostack, preserves_flags));
        }
        crate::println!(
            "  cpacr={cpacr:#010x} (cp10/cp11 {}), fpexc={fpexc:#010x} (unit {})",
            if (cpacr >> 20) & 0xF == 0xF { "full access" } else { "restricted" },
            if fpexc & (1 << 30) != 0 { "on" } else { "off" }
        );
    }
    crate::println!("stopped; not restarting");
    crate::arch::halt()
}

/// The short-descriptor fault status, FS[4] (bit 10) and FS[3:0].
fn fault_status(fsr: u32) -> &'static str {
    match ((fsr >> 6) & 0x10) | (fsr & 0xF) {
        0x01 => "alignment fault",
        0x02 => "debug event",
        0x03 | 0x06 => "access flag fault",
        0x05 | 0x07 => "translation fault",
        0x08 => "synchronous external abort",
        0x09 | 0x0B => "domain fault",
        0x0D | 0x0F => "permission fault",
        0x16 => "asynchronous external abort",
        0x19 => "parity/ECC error",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// The MMU
// ---------------------------------------------------------------------------
//
// With the MMU off every access is Strongly-ordered: no data cache, no
// instruction cache to speak of, no unaligned access — correct and slow, and
// for a chronometer wrong in the way AArch64's MMU-off numbers are (see
// `arch::arm::enable_mmu`): a load probe measures DRAM every time.
//
// So the same plain map as AArch64's, in the short-descriptor format: an
// identity map of the 4 GiB in 1 MiB sections, every section Device and
// execute-never except the ones the kernel image occupies, which are Normal
// write-back write-allocate. Nothing else is ever cacheable — MMIO may sit
// anywhere on an unknown board, and a cacheable device is a correctness bug.
// Domain 0, client: the access permissions apply (full access, AP = 0b011).
// Table walks are non-cacheable (TTBR0's walk attributes zero), as on
// AArch64: the table was written with the MMU off, straight to memory.

#[repr(C, align(16384))]
struct L1Table([u32; 4096]);

static mut L1: L1Table = L1Table([0; 4096]);

static MMU_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether [`enable_mmu`] turned the MMU and caches on.
pub fn mmu_enabled() -> bool {
    MMU_ON.load(core::sync::atomic::Ordering::Relaxed)
}

/// Section descriptor bits.
const SECTION: u32 = 0b10;
const B: u32 = 1 << 2;
const C: u32 = 1 << 3;
const XN: u32 = 1 << 4;
/// AP[1:0] = 0b11 (with AP[2] = 0): read/write at every level.
const AP_FULL: u32 = 0b11 << 10;
/// TEX = 0b001: with C and B, Normal write-back write-allocate.
const TEX_001: u32 = 0b001 << 12;
const SHAREABLE: u32 = 1 << 16;

/// Builds the identity map and turns on the MMU, both caches and branch
/// prediction.
///
/// # Safety
/// Once, early, at PL1 with the MMU off, before anything relies on memory
/// attributes (nothing can: the map is the identity).
pub unsafe fn enable_mmu() -> Result<(), &'static str> {
    extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    let start = &raw const __kernel_start as u32;
    let end = &raw const __kernel_end as u32;
    if end <= start {
        return Err("empty image bounds");
    }
    let first = start >> 20;
    let last = (end - 1) >> 20;
    // SAFETY: once, before anything else references the table; the MMU is
    // off, so these stores go straight to memory.
    unsafe {
        let table = &raw mut L1.0;
        for i in 0..4096u32 {
            let base = i << 20;
            (*table)[i as usize] = if (first..=last).contains(&i) {
                base | SECTION | AP_FULL | TEX_001 | C | B | SHAREABLE
            } else {
                // Shareable Device (TEX 000, C 0, B 1), never executed.
                base | SECTION | AP_FULL | B | XN
            };
        }
    }
    let ttbr0 = &raw const L1 as u32;
    // SAFETY: the table is complete. The image's lines are invalidated first
    // (to the point of coherency), as AArch64 does, so a stale line from the
    // loader cannot shadow what went to memory; then the TLB, the I-cache
    // and the branch predictor; then the MMU on.
    unsafe {
        let ctr: u32;
        core::arch::asm!("mrc p15, 0, {}, c0, c0, 1", out(reg) ctr, options(nomem, nostack, preserves_flags));
        let line = 4u32 << ((ctr >> 16) & 0xF);
        let mut at = start & !(line - 1);
        core::arch::asm!("dsb", options(nostack, preserves_flags));
        while at < end {
            core::arch::asm!("mcr p15, 0, {}, c7, c6, 1", in(reg) at, options(nostack, preserves_flags));
            at = at.wrapping_add(line);
            if at < line {
                break;
            }
        }
        core::arch::asm!(
            "dsb",
            "mcr p15, 0, {zero}, c2, c0, 2",   // TTBCR = 0: TTBR0 translates everything
            "mcr p15, 0, {ttbr}, c2, c0, 0",   // TTBR0, walks non-cacheable
            "mcr p15, 0, {dacr}, c3, c0, 0",   // DACR: domain 0 client
            "mcr p15, 0, {zero}, c8, c7, 0",   // TLBIALL
            "mcr p15, 0, {zero}, c7, c5, 0",   // ICIALLU
            "mcr p15, 0, {zero}, c7, c5, 6",   // BPIALL
            "dsb",
            "isb",
            "mrc p15, 0, {t}, c1, c0, 0",      // SCTLR
            "bic {t}, {t}, #(1 << 1)",         // A: no alignment checking
            "bic {t}, {t}, #(1 << 28)",        // TRE: TEX remap off
            "bic {t}, {t}, #(1 << 29)",        // AFE: AP[0] is an access bit only with this
            "orr {t}, {t}, #(1 << 0)",         // M: the MMU
            "orr {t}, {t}, #(1 << 2)",         // C: data and unified caches
            "orr {t}, {t}, #(1 << 11)",        // Z: branch prediction
            "orr {t}, {t}, #(1 << 12)",        // I: instruction cache
            "mcr p15, 0, {t}, c1, c0, 0",
            "isb",
            zero = in(reg) 0u32, ttbr = in(reg) ttbr0, dacr = in(reg) 0b01u32, t = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
    MMU_ON.store(true, core::sync::atomic::Ordering::Relaxed);
    Ok(())
}
