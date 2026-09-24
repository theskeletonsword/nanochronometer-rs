// SPDX-License-Identifier: Apache-2.0
//! The interrupt-controller priority floor, set to a known value at boot.
//!
//! Each architecture has one register that says which interrupt priorities
//! a core accepts: x86_64's CR8 (the local APIC's task priority), the APIC
//! TPR itself on i386, the GIC's priority mask on ARM, the PLIC's threshold
//! on RISC-V, the OpenPIC's current task priority on 32-bit POWER. Firmware
//! may leave any value there. This sets each to "accept every priority" and
//! enables the controller where that is a separate step (the local APIC), so
//! a driver that moves to interrupts starts from a stated state rather than
//! from whatever the firmware left.
//!
//! **It enables no interrupt.** This kernel polls, with interrupts masked at
//! the core (IF, DAIF, `sstatus.SIE`, `MSR[EE]`), because an interrupt taken
//! between two counter reads is part of what the stopwatch would measure.
//! The priority floor only decides what would get through once a driver
//! unmasks one.

/// What was done, for the machine card.
#[derive(Debug, Clone, Copy)]
pub struct State {
    /// The register, as the architecture names it.
    pub register: &'static str,
    /// What happened: "0 (all priorities)", "no controller found", ...
    pub outcome: &'static str,
}

static mut STATE: State = State { register: "-", outcome: "not set" };

/// What [`open`] did.
pub fn state() -> State {
    // SAFETY: written once, at boot, before anything reads it; single core.
    unsafe { *core::ptr::addr_of!(STATE) }
}

fn record(register: &'static str, outcome: &'static str) {
    // SAFETY: as in `state`.
    unsafe { *core::ptr::addr_of_mut!(STATE) = State { register, outcome } };
}

// ---------------------------------------------------------------------------
// x86: the local APIC. CR8 on x86_64, the TPR register on i386.
// ---------------------------------------------------------------------------

/// # Safety
/// CPL 0, identity-mapped (x86_64, with the APIC page uncached, which the
/// boot map's PCD bit gives every entry past the first GiB) or paging off
/// (i386).
#[cfg(x86_any)]
pub unsafe fn open() {
    use crate::arch::x86::{cpuid, rdmsr, wrmsr};
    const IA32_APIC_BASE: u32 = 0x1B;
    const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
    const SVR: usize = 0xF0;
    const SVR_ENABLE: u32 = 1 << 8;

    if cpuid(1, 0)[3] & (1 << 9) == 0 {
        record(if cfg!(target_arch = "x86_64") { "cr8" } else { "apic tpr" }, "no local apic");
        return;
    }
    // SAFETY: CPL 0; the MSR exists wherever CPUID reports an APIC.
    let base_msr = unsafe { rdmsr(IA32_APIC_BASE) };
    if base_msr & APIC_GLOBAL_ENABLE == 0 {
        // SAFETY: as above; setting the enable bit keeps the base address.
        unsafe { wrmsr(IA32_APIC_BASE, base_msr | APIC_GLOBAL_ENABLE) };
    }
    let base = (base_msr & 0xFFFF_F000) as usize;
    // Software-enable the APIC (SVR bit 8), spurious vector 0xFF. The
    // register is 32 bits wide and must be written as such.
    // SAFETY: the APIC's register page, uncached (see the contract).
    unsafe {
        let svr = (base + SVR) as *mut u32;
        let v = core::ptr::read_volatile(svr);
        core::ptr::write_volatile(svr, v | SVR_ENABLE | 0xFF);
    }
    #[cfg(target_arch = "x86_64")]
    {
        // CR8 is the TPR's architectural alias in long mode: priority class
        // 0, every interrupt class accepted.
        // SAFETY: CPL 0; writing CR8 has no effect while IF is clear.
        unsafe { core::arch::asm!("mov cr8, {}", in(reg) 0usize, options(nomem, nostack, preserves_flags)) };
        record("cr8", "0 (all priorities), lapic on");
    }
    #[cfg(target_arch = "x86")]
    {
        // No CR8 in protected mode: the TPR register itself, offset 0x80.
        // SAFETY: the APIC's register page.
        unsafe { core::ptr::write_volatile((base + 0x80) as *mut u32, 0) };
        record("apic tpr", "0 (all priorities), lapic on");
    }
}

// ---------------------------------------------------------------------------
// ARM (both widths): the GIC CPU interface's priority mask.
// ---------------------------------------------------------------------------

/// # Safety
/// EL1 / PL1, with the GIC's MMIO mapped as device memory (AArch64) or the
/// MMU off (AArch32).
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub unsafe fn open(tree: Option<&crate::fdt::Fdt<'_>>) {
    let Some(tree) = tree else {
        record("gic pmr", "no devicetree");
        return;
    };
    // GICv2 (and v1): the CPU interface is the second register window;
    // GICC_PMR is at +0x4. 0xFF lets every priority through.
    for compat in [&b"arm,cortex-a15-gic"[..], b"arm,gic-400", b"arm,cortex-a9-gic", b"arm,cortex-a7-gic"] {
        if let Some(gicc) = tree.compatible_reg_at(compat, 1) {
            // SAFETY: the CPU interface window the tree names, mapped.
            unsafe { core::ptr::write_volatile((gicc as usize + 0x4) as *mut u32, 0xFF) };
            record("gicc_pmr", "0xff (all priorities)");
            return;
        }
    }
    // GICv3: the priority mask is a system register, ICC_PMR_EL1, reached
    // once the system-register interface is on (ICC_SRE_EL1.SRE).
    #[cfg(target_arch = "aarch64")]
    if tree.find_compatible_reg(b"arm,gic-v3").is_some() {
        // SAFETY: EL1 with a GICv3 present; SRE then PMR, with an ISB so the
        // second write sees the first.
        unsafe {
            core::arch::asm!(
                "mrs {t}, S3_0_C12_C12_5",   // ICC_SRE_EL1
                "orr {t}, {t}, #1",
                "msr S3_0_C12_C12_5, {t}",
                "isb",
                "mov {t}, #0xff",
                "msr S3_0_C4_C6_0, {t}",     // ICC_PMR_EL1
                t = out(reg) _,
                options(nostack),
            );
        }
        record("icc_pmr_el1", "0xff (all priorities)");
        return;
    }
    record("gic pmr", "no gic in the devicetree");
}

// ---------------------------------------------------------------------------
// RISC-V: the PLIC threshold of this hart's supervisor context.
// ---------------------------------------------------------------------------

/// # Safety
/// S-mode with `satp` Bare, so the PLIC's MMIO is directly addressed.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub unsafe fn open(tree: Option<&crate::fdt::Fdt<'_>>, hart: usize) {
    let Some(base) = tree.and_then(|t| {
        t.find_compatible_reg(b"riscv,plic0").or_else(|| t.find_compatible_reg(b"sifive,plic-1.0.0"))
    }) else {
        record("plic threshold", "no plic in the devicetree");
        return;
    };
    // Contexts come in (M, S) pairs per hart on QEMU `virt` and SiFive
    // parts; the supervisor one is odd. Threshold registers start at
    // +0x200000, one 4 KiB page per context.
    let context = hart * 2 + 1;
    // SAFETY: the PLIC window the tree names; the threshold is 32 bits.
    unsafe { core::ptr::write_volatile((base as usize + 0x20_0000 + context * 0x1000) as *mut u32, 0) };
    record("plic threshold", "0 (all priorities)");
}

// ---------------------------------------------------------------------------
// POWER: the OpenPIC's current task priority (32-bit); XIVE is OPAL's.
// ---------------------------------------------------------------------------

/// Records that POWER's controller is left as firmware configured it: the
/// G4's OpenPIC belongs to Open Firmware until it is quiesced, and on
/// powernv XIVE is programmed through OPAL. (The e500's MPIC is set, by
/// [`open_mpic`].)
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
pub fn open_unset() {
    record(
        if cfg!(target_arch = "powerpc64") { "xive cppr" } else { "openpic ctpr" },
        "left to firmware",
    );
}

/// The e500's MPIC: CTPR for CPU 0 at MPIC + 0x20080, reached through the
/// TLB window the entry point already maps over CCSR (`window_virt` is that
/// window's virtual base, `window_phys` its physical one).
///
/// # Safety
/// Supervisor state; the window is mapped cache-inhibited and covers the
/// MPIC's per-CPU page.
#[cfg(target_arch = "powerpc")]
pub unsafe fn open_mpic(tree: &crate::fdt::Fdt<'_>, window_phys: u64, window_virt: usize, window_len: u64) {
    let Some(mpic) = tree.find_compatible_reg(b"chrp,open-pic").or_else(|| tree.find_compatible_reg(b"fsl,mpic")) else {
        record("openpic ctpr", "no mpic in the devicetree");
        return;
    };
    let ctpr = mpic + 0x2_0080;
    if ctpr < window_phys || ctpr + 4 > window_phys + window_len {
        record("openpic ctpr", "outside the mapped ccsr window");
        return;
    }
    // SAFETY: inside the mapped window (checked above); 32-bit register.
    unsafe { core::ptr::write_volatile((window_virt + (ctpr - window_phys) as usize) as *mut u32, 0) };
    record("openpic ctpr", "0 (all priorities)");
}
