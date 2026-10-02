// SPDX-License-Identifier: Apache-2.0
//! The processor-control dispatcher: which control bits this kernel turns on,
//! decided from what the processor reports — `CPUID` on x86, the ID registers
//! (`MRS`) on ARM — and never assumed. The policy and its reasons are
//! `nanochrono_core::cpu_control`, tested on the host; this applies it and
//! keeps what it did for the report (the boot log, `cpuctl` in the shell,
//! the desktop's system information).
//!
//! What has to precede any Rust is done by the boot stubs, with the same
//! rules: SSE and the XSAVE-managed state on x86 (`boot32.S`,
//! `boot_i386.S`: `OSXSAVE` only with AVX), FP/AdvSIMD, SVE and SME and
//! their vector lengths on AArch64, VFP/NEON on 32-bit ARM, `sstatus.FS/VS`
//! on RISC-V, `MSR[FP,VEC,VSX]` on PowerPC. What remains — and can wait for
//! Rust — is here.

use nanochrono_core::cpu_control::Decision;

/// What [`configure`] did.
#[derive(Debug, Clone, Copy)]
pub struct Report {
    /// The register the decisions are about, for the report's heading.
    pub register: &'static str,
    pub before: u64,
    pub after: u64,
    pub decisions: [Option<Decision>; 16],
    /// A second register the dispatcher wrote first, with its old and new
    /// value: `IA32_FEATURE_CONTROL` on x86.
    pub extra: Option<(&'static str, u64, u64)>,
}

impl Report {
    const fn empty(register: &'static str) -> Report {
        Report { register, before: 0, after: 0, decisions: [None; 16], extra: None }
    }

    fn push(&mut self, d: Decision) {
        if let Some(slot) = self.decisions.iter_mut().find(|s| s.is_none()) {
            *slot = Some(d);
        }
    }

    pub fn decisions(&self) -> impl Iterator<Item = &Decision> {
        self.decisions.iter().flatten()
    }
}

static mut REPORT: Option<Report> = None;

/// What [`configure`] did, once it has run.
pub fn report() -> Option<Report> {
    // SAFETY: written once at boot, before anything reads it, on one core.
    unsafe { *core::ptr::addr_of!(REPORT) }
}

/// Applies the policy and prints what it decided.
///
/// # Safety
/// Once, at boot, at the kernel's privilege level (CPL 0 / EL1+ / PL1 /
/// S-mode), before any ring-3 plugin runs.
pub unsafe fn configure() {
    // SAFETY: forwarded.
    let report = unsafe { apply() };
    crate::println!("cpu control ({}): {:#x} -> {:#x}", report.register, report.before, report.after);
    if let Some((name, before, after)) = report.extra {
        crate::println!("  {name}: {before:#x} -> {after:#x}");
    }
    for d in report.decisions() {
        let mut place = crate::text::Text::<16>::new();
        place.str(d.register);
        if d.bit != 0xFF {
            place.str(".").num(d.bit as u64);
        }
        crate::println!("  {:<12} {:<11} {:<3} {}", place.as_str(), d.name, if d.on { "on" } else { "off" }, d.reason);
    }
    // SAFETY: once, at boot, on one core.
    unsafe { *core::ptr::addr_of_mut!(REPORT) = Some(report) };
}

#[cfg(x86_any)]
unsafe fn apply() -> Report {
    use crate::arch::x86::{rdmsr, read_cr4, wrmsr, write_cr4};
    use nanochrono_core::arch::x86::cpuid;
    use nanochrono_core::cpu_control::x86 as policy;

    let max_leaf = cpuid(0, 0)[0];
    let leaf1 = cpuid(1, 0);
    let leaf7 = if max_leaf >= 7 { cpuid(7, 0) } else { [0; 4] };
    let pmu_version = if max_leaf >= 0x0A { (cpuid(0x0A, 0)[0] & 0xFF) as u8 } else { 0 };
    let amd = matches!(nanochrono_core::cpu::vendor(), nanochrono_core::cpu::Vendor::Amd);
    // IA32_FEATURE_CONTROL exists when VMX or SMX does (SDM Vol. 4, MSR 3AH).
    let vmx_or_smx = leaf1[2] & (policy::ECX_VMX | policy::ECX_SMX) != 0;
    // SAFETY: CPL 0 (this function's contract) and the MSR exists.
    let feature_control = vmx_or_smx.then(|| unsafe { rdmsr(0x3A) });
    #[cfg(target_arch = "x86_64")]
    let cr3_low = {
        let cr3: u64;
        // SAFETY: reading CR3 at CPL 0 has no side effects.
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
        (cr3 & 0xFFF) as u16
    };
    #[cfg(target_arch = "x86")]
    let cr3_low = 0;
    let ids = policy::Ids {
        leaf1_ecx: leaf1[2],
        leaf1_edx: leaf1[3],
        leaf7_ebx: leaf7[1],
        leaf7_ecx: leaf7[2],
        pmu_version,
        amd_counters: amd,
        long_mode: cfg!(target_arch = "x86_64"),
        paging: {
            let cr0: usize;
            // SAFETY: reading CR0 at CPL 0 has no side effects.
            unsafe { core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags)) };
            cr0 & (1 << 31) != 0
        },
        cr3_low,
        feature_control,
    };
    let plan = policy::plan(&ids);
    let mut report = Report::empty("cr4");
    report.before = read_cr4();

    if let (Some(value), Some(before)) = (plan.feature_control, feature_control) {
        // SAFETY: CPL 0; unlocked (the plan only asks when the lock bit is
        // clear), and the bits it sets exist with VMX (and SMX).
        unsafe { wrmsr(0x3A, value) };
        // SAFETY: as the read above.
        report.extra = Some(("ia32_feature_control", before, unsafe { rdmsr(0x3A) }));
    }

    // The boot stub owns OSFXSR, OSXMMEXCPT and OSXSAVE — they had to be
    // right before the first SSE instruction — so this touches the rest.
    let ours: u64 = [
        policy::TSD,
        policy::PSE,
        policy::PGE,
        policy::PCE,
        policy::UMIP,
        policy::VMXE,
        policy::SMXE,
        policy::FSGSBASE,
        policy::PCIDE,
    ]
    .iter()
    .fold(0, |m, &b| m | 1 << b);
    let mut cr4 = report.before;
    // TSD first and alone: clearing it can never fault.
    cr4 &= !(plan.clear & ours);
    // SAFETY: CPL 0; clearing bits is always legal.
    unsafe { write_cr4(cr4) };
    // Then each bit on its own, PCIDE last: a write that faults should name
    // the bit that did, and PCIDE is the one with preconditions.
    for bit in [policy::PSE, policy::PGE, policy::PCE, policy::UMIP, policy::VMXE, policy::SMXE, policy::FSGSBASE, policy::PCIDE] {
        if plan.set & (1 << bit) != 0 {
            cr4 |= 1 << bit;
            // SAFETY: CPL 0; the plan sets a bit only when CPUID reports its
            // feature (and, for PCIDE, long mode with CR3[11:0] clear).
            unsafe { write_cr4(cr4) };
        }
    }
    report.after = read_cr4();
    for d in plan.decisions {
        // The stub's bits are reported as they really are, not as planned.
        let mut d = d;
        if d.register == "cr4" && matches!(d.bit, policy::OSFXSR | policy::OSXMMEXCPT | policy::OSXSAVE) {
            d.on = report.after & (1 << d.bit) != 0;
        }
        report.push(d);
    }
    report
}

#[cfg(target_arch = "aarch64")]
unsafe fn apply() -> Report {
    use nanochrono_core::cpu_control::aarch64 as policy;
    let read = |which: u8| -> u64 {
        let v: u64;
        // SAFETY: the ID registers are readable at EL1 and above, with no
        // side effects.
        unsafe {
            match which {
                0 => core::arch::asm!("mrs {}, id_aa64pfr0_el1", out(reg) v, options(nomem, nostack, preserves_flags)),
                1 => core::arch::asm!("mrs {}, id_aa64pfr1_el1", out(reg) v, options(nomem, nostack, preserves_flags)),
                2 => core::arch::asm!("mrs {}, id_aa64dfr0_el1", out(reg) v, options(nomem, nostack, preserves_flags)),
                _ => core::arch::asm!("mrs {}, id_aa64mmfr0_el1", out(reg) v, options(nomem, nostack, preserves_flags)),
            }
        }
        v
    };
    let el = crate::arch::arm::current_el();
    let ids = policy::Ids { pfr0: read(0), pfr1: read(1), dfr0: read(2), mmfr0: read(3), el };
    let plan = policy::plan(&ids);
    let mut report = Report::empty("cntkctl_el1");
    let mut cntkctl: u64;
    // SAFETY: CNTKCTL_EL1 is accessible at EL1 and above (at EL2 with E2H
    // set, the same encoding reaches CNTHCTL_EL2, whose low bits have the
    // same meaning).
    unsafe { core::arch::asm!("mrs {}, cntkctl_el1", out(reg) cntkctl, options(nomem, nostack, preserves_flags)) };
    report.before = cntkctl;
    if plan.el0_counter {
        cntkctl |= 0b11; // EL0PCTEN, EL0VCTEN
        // SAFETY: as the read.
        unsafe { core::arch::asm!("msr cntkctl_el1, {}", "isb", in(reg) cntkctl, options(nostack, preserves_flags)) };
    }
    if plan.el0_pmu {
        // EN, CR (cycle counter read), ER (event counter read).
        let v: u64 = 0b1101;
        // SAFETY: PMUv3 exists (ID_AA64DFR0_EL1.PMUVer); writable at EL1+.
        unsafe { core::arch::asm!("msr pmuserenr_el0, {}", "isb", in(reg) v, options(nostack, preserves_flags)) };
    }
    if plan.hypervisor_calls {
        let mut scr: u64;
        // SAFETY: at EL3 (the plan asks only there); HCE is bit 8.
        unsafe {
            core::arch::asm!("mrs {}, scr_el3", out(reg) scr, options(nomem, nostack, preserves_flags));
            let before = scr;
            scr |= 1 << 8;
            core::arch::asm!("msr scr_el3, {}", "isb", in(reg) scr, options(nostack, preserves_flags));
            report.extra = Some(("scr_el3", before, scr));
        }
    }
    // SAFETY: as the first read.
    unsafe { core::arch::asm!("mrs {}, cntkctl_el1", out(reg) cntkctl, options(nomem, nostack, preserves_flags)) };
    report.after = cntkctl;
    for d in plan.decisions {
        report.push(d);
    }
    let mmu = crate::arch::arm::mmu_enabled();
    report.push(Decision::new(
        "sctlr",
        0,
        "MMU",
        mmu,
        if mmu { "identity map, image write-back, blocks (CR0.PG and PSE's counterpart)" } else { "left off" },
    ));
    report.push(Decision::new("tpidr_el0", 0xFF, "thread ptr", true, "EL0-accessible by design (FSGSBASE's counterpart)"));
    report.push(Decision::new("far_elx", 0xFF, "fault addr", true, "reported by the vectors (CR2's counterpart)"));
    report
}

#[cfg(target_arch = "arm")]
unsafe fn apply() -> Report {
    let (pfr1, dfr0): (u32, u32);
    // SAFETY: ID_PFR1 and ID_DFR0 are readable at PL1 with no side effects.
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c0, c1, 1", out(reg) pfr1, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mrc p15, 0, {}, c0, c1, 2", out(reg) dfr0, options(nomem, nostack, preserves_flags));
    }
    let timer = (pfr1 >> 16) & 0xF != 0;
    let pmu = matches!((dfr0 >> 24) & 0xF, 1..=0xE);
    let virt = (pfr1 >> 12) & 0xF != 0;
    let mut report = Report::empty("cntkctl");
    if timer {
        let mut v: u32;
        // SAFETY: the generic timer exists (ID_PFR1.GenTimer); CNTKCTL is
        // PL1's.
        unsafe {
            core::arch::asm!("mrc p15, 0, {}, c14, c1, 0", out(reg) v, options(nomem, nostack, preserves_flags));
            report.before = v as u64;
            v |= 0b11; // PL0PCTEN, PL0VCTEN
            core::arch::asm!("mcr p15, 0, {}, c14, c1, 0", "isb", in(reg) v, options(nostack, preserves_flags));
        }
        report.after = v as u64;
    }
    if pmu {
        // SAFETY: a PMU exists (ID_DFR0.PerfMon); PMUSERENR.EN is PL1's.
        unsafe { core::arch::asm!("mcr p15, 0, {}, c9, c14, 0", "isb", in(reg) 1u32, options(nostack, preserves_flags)) };
    }
    report.push(Decision { register: "cpacr", bit: 0xFF, name: "VFP/NEON", on: true, reason: "CPACR cp10/cp11, ASEDIS/D32DIS clear, FPEXC.EN (boot stub)" });
    report.push(Decision {
        register: "cntkctl",
        bit: 0xFF,
        name: "PL0 counter",
        on: timer,
        reason: if timer { "CNTKCTL: physical and virtual counter at PL0" } else { "no generic timer" },
    });
    report.push(Decision {
        register: "pmuserenr",
        bit: 0xFF,
        name: "PL0 PMU",
        on: pmu,
        reason: if pmu { "PMUSERENR.EN: PMU readable at PL0" } else { "no PMU" },
    });
    report.push(Decision {
        register: "hcptr",
        bit: 0xFF,
        name: "HYP",
        on: virt,
        reason: if virt { "virtualization extensions: HCPTR cleared when entered in HYP" } else { "absent" },
    });
    let mmu = crate::arch::arm32::mmu_enabled();
    report.push(Decision::new(
        "sctlr",
        0,
        "MMU",
        mmu,
        if mmu { "identity map, 1 MiB sections, image write-back (CR0.PG and PSE's counterpart)" } else { "left off" },
    ));
    report.push(Decision::new("dfar/ifar", 0xFF, "fault addr", true, "reported by the vectors (CR2's counterpart)"));
    report
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
unsafe fn apply() -> Report {
    let mut report = Report::empty("scounteren");
    let before: usize;
    // SAFETY: scounteren is an S-mode CSR; reading has no side effects.
    unsafe { core::arch::asm!("csrr {}, scounteren", out(reg) before, options(nomem, nostack, preserves_flags)) };
    // CY, TM, IR: cycle, time and instret readable in U-mode — what the
    // firmware's mcounteren lets through to S-mode, passed on.
    let after = before | 0b111;
    // SAFETY: as above; the write only widens U-mode read access.
    unsafe { core::arch::asm!("csrw scounteren, {}", in(reg) after, options(nostack, preserves_flags)) };
    report.before = before as u64;
    report.after = after as u64;
    let f = nanochrono_core::cpu::features();
    report.push(Decision { register: "sstatus", bit: 0xFF, name: "FS", on: true, reason: "sstatus.FS initial (boot stub)" });
    report.push(Decision {
        register: "sstatus",
        bit: 0xFF,
        name: "VS",
        on: f.rvv,
        reason: if f.rvv { "sstatus.VS initial (boot stub)" } else { "no vector extension" },
    });
    report.push(Decision { register: "scounteren", bit: 0xFF, name: "U counters", on: true, reason: "scounteren CY|TM|IR" });
    let paging = crate::arch::riscv::paging_enabled();
    report.push(Decision::new(
        "satp",
        0xFF,
        "paging",
        paging,
        if paging {
            if cfg!(target_arch = "riscv64") {
                "sv39 identity map, 1 GiB pages (CR0.PG and PSE's counterpart)"
            } else {
                "sv32 identity map, 4 MiB pages (CR0.PG and PSE's counterpart)"
            }
        } else {
            "bare: this hart lacks the mode"
        },
    ));
    report.push(Decision::new("stval", 0xFF, "fault addr", true, "reported by the trap handler (CR2's counterpart)"));
    report
}

#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
unsafe fn apply() -> Report {
    let mut report = Report::empty("msr");
    let msr: usize;
    // SAFETY: mfmsr is a supervisor read with no side effects.
    unsafe { core::arch::asm!("mfmsr {}", out(reg) msr, options(nomem, nostack, preserves_flags)) };
    report.before = msr as u64;
    report.after = msr as u64;
    let bit = |b: u32| msr & (1 << b) != 0;
    // MSR bit numbers counted from the least significant end: FP 13, VEC 25,
    // VSX 23 (Book3S).
    report.push(Decision { register: "msr", bit: 13, name: "FP", on: bit(13), reason: "set by the boot stub" });
    report.push(Decision { register: "msr", bit: 25, name: "VEC", on: bit(25), reason: "AltiVec/VMX where the core has it" });
    #[cfg(target_arch = "powerpc64")]
    report.push(Decision { register: "msr", bit: 23, name: "VSX", on: bit(23), reason: "VSX where the core has it" });
    report.push(Decision { register: "", bit: 0xFF, name: "time base", on: true, reason: "readable in problem state by the architecture" });
    // MSR[IR, DR]: translation. powernv runs in hypervisor real mode (off),
    // the e500 is always translated by its TLB, Open Firmware leaves its own
    // map on.
    let translated = bit(5) && bit(4);
    report.push(Decision::new(
        "msr",
        0xFF,
        "IR/DR",
        translated,
        if translated { "translation on (the firmware's map)" } else { "real mode: no translation (hypervisor state)" },
    ));
    report
}
