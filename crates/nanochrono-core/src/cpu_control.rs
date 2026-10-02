// SPDX-License-Identifier: Apache-2.0
//! Which processor controls a freestanding kernel switches on, decided from
//! what the processor says about itself: `CPUID` on x86, the ID registers
//! (read with `MRS`) on ARM.
//!
//! # Why a dispatcher and not a list of bits
//!
//! A control bit for a feature the part does not have is at best inert and at
//! worst a fault on the write: setting `CR4.VMXE` without VMX, or `CR4.PCIDE`
//! without PCID, is `#GP`. And a feature switched on that nothing can use is
//! not free either: `CR4.OSXSAVE` on a part without AVX enables XSAVE state
//! management — `XGETBV`/`XSETBV`, a larger save area, extended state the
//! hardware then tracks — for registers that do not exist, costing power for
//! nothing. So each bit is decided from the hardware's own report, never
//! assumed, and the decision is kept, with its reason, for the report.
//!
//! Pure functions over the numbers the kernel read: the policy is tested here,
//! on the host, with the combinations no single machine can show.
//!
//! # The x86 policy (`CR4`)
//!
//! | bit | name | on when |
//! |---|---|---|
//! | 2 | TSD | never: `RDTSC` stays readable at every privilege level — the time-stamp counter is the instrument, and a ring-3 plugin times with it |
//! | 4 | PSE | the part has 4 MiB pages: the i386 kernel's identity map is made of them (in long mode the bit is ignored, and set anyway) |
//! | 7 | PGE | the part has global pages: kernel mappings marked global survive `CR3` loads (and the VM exits that load it) |
//! | 8 | PCE | there is a PMU to read (`CPUID.0AH` version > 0, or AMD's core counters): `RDPMC` at every privilege level, as NC_PMU wants |
//! | 9 | OSFXSR | FXSR: SSE |
//! | 10 | OSXMMEXCPT | SSE: an unmasked SIMD floating-point exception is `#XM`, not `#UD` |
//! | 11 | UMIP | the part has it: `SGDT`/`SIDT`/`SLDT`/`SMSW`/`STR` refused outside ring 0 |
//! | 13 | VMXE | VMX, and the firmware has not locked it off: the VM manager's hypervisor |
//! | 14 | SMXE | SMX (Intel TXT): `GETSEC` usable |
//! | 16 | FSGSBASE | the part has it, in long mode: `RDFSBASE`/`WRFSBASE`/`RDGSBASE`/`WRGSBASE` at every privilege level (safe here: the kernel keeps nothing behind GS) |
//! | 17 | PCIDE | PCID, in long mode, with `CR3[11:0]` clear (the write is `#GP` otherwise) |
//! | 18 | OSXSAVE | XSAVE **and** AVX: no AVX, no wider state worth managing |
//!
//! And `CR0.PG` (bit 31), reported: long mode requires paging, and the i386
//! kernel turns it on in its boot stub. `CR2` is not a control: the processor
//! writes the faulting address there on a page fault, and the fault handler
//! and the crash dump read it.
//!
//! # The AArch64 policy
//!
//! The same questions, the ARM way: FP/AdvSIMD, SVE and SME trap controls
//! (`CPACR_EL1`/`CPTR_ELx`, set by the boot stub before any Rust runs) and
//! their vector lengths (`ZCR_ELx`, `SMCR_ELx`); EL0 access to the generic
//! timer (`CNTKCTL_EL1`, TSD's counterpart) and to the PMU (`PMUSERENR_EL0`,
//! PCE's); hypervisor calls (`SCR_EL3.HCE`, at EL3); 16-bit ASIDs
//! (`TCR_ELx.AS`, PCIDE's counterpart).

/// One control's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// The register the bit is in (`cr4`, `cr0`, ...), or `""` for a control
    /// that is not a single bit of one register.
    pub register: &'static str,
    /// The bit in that register, or 0xFF for one that is not a single bit.
    pub bit: u8,
    pub name: &'static str,
    pub on: bool,
    /// Why, in a few words, for the report.
    pub reason: &'static str,
}

impl Decision {
    pub const fn new(register: &'static str, bit: u8, name: &'static str, on: bool, reason: &'static str) -> Decision {
        Decision { register, bit, name, on, reason }
    }
}

/// x86 (`CR4`), for 32- and 64-bit kernels alike.
pub mod x86 {
    use super::Decision;

    pub const TSD: u8 = 2;
    pub const PSE: u8 = 4;
    pub const PGE: u8 = 7;
    pub const PCE: u8 = 8;
    pub const OSFXSR: u8 = 9;
    pub const OSXMMEXCPT: u8 = 10;
    pub const UMIP: u8 = 11;
    pub const VMXE: u8 = 13;
    pub const SMXE: u8 = 14;
    pub const FSGSBASE: u8 = 16;
    pub const PCIDE: u8 = 17;
    pub const OSXSAVE: u8 = 18;
    /// `CR0.PG`.
    pub const PG: u8 = 31;

    /// What the kernel read before deciding.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Ids {
        /// `CPUID.01H:ECX` and `EDX`.
        pub leaf1_ecx: u32,
        pub leaf1_edx: u32,
        /// `CPUID.(07H,0):EBX` and `ECX`; zero when leaf 7 is absent.
        pub leaf7_ebx: u32,
        pub leaf7_ecx: u32,
        /// `CPUID.0AH:EAX[7:0]`, the architectural PMU's version; zero when
        /// absent (and under a hypervisor that hides it).
        pub pmu_version: u8,
        /// AMD's core performance counters (`CPUID.80000001H:ECX[23]`), or an
        /// AMD part at all: its four legacy counters need no CPUID bit.
        pub amd_counters: bool,
        /// Running in IA-32e mode — PCIDE and FSGSBASE exist only there.
        pub long_mode: bool,
        /// `CR0.PG` as it stands.
        pub paging: bool,
        /// `CR3[11:0]`, which must be zero for the PCIDE write to succeed.
        pub cr3_low: u16,
        /// `IA32_FEATURE_CONTROL` (MSR 3AH), when it was readable.
        pub feature_control: Option<u64>,
    }

    /// `CPUID.01H:ECX` bits.
    pub const ECX_VMX: u32 = 1 << 5;
    pub const ECX_SMX: u32 = 1 << 6;
    pub const ECX_PCID: u32 = 1 << 17;
    pub const ECX_XSAVE: u32 = 1 << 26;
    pub const ECX_AVX: u32 = 1 << 28;
    /// `CPUID.01H:EDX` bits.
    pub const EDX_PSE: u32 = 1 << 3;
    pub const EDX_PGE: u32 = 1 << 13;
    pub const EDX_FXSR: u32 = 1 << 24;
    pub const EDX_SSE: u32 = 1 << 25;
    /// `CPUID.(07H,0):ECX[2]`.
    pub const LEAF7_ECX_UMIP: u32 = 1 << 2;
    /// `CPUID.(07H,0):EBX[0]`.
    pub const LEAF7_EBX_FSGSBASE: u32 = 1 << 0;

    /// `IA32_FEATURE_CONTROL` bits.
    pub const FC_LOCK: u64 = 1 << 0;
    pub const FC_VMX_IN_SMX: u64 = 1 << 1;
    pub const FC_VMX_OUTSIDE_SMX: u64 = 1 << 2;

    /// What to do with `CR4`, and with `IA32_FEATURE_CONTROL` first.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Plan {
        pub set: u64,
        pub clear: u64,
        /// `Some(value)`: write this to `IA32_FEATURE_CONTROL` before setting
        /// `CR4.VMXE` — the firmware left it unlocked, so the kernel enables
        /// VMX outside SMX (and inside it, with SMX) and locks it, as an
        /// operating system does.
        pub feature_control: Option<u64>,
        pub decisions: [Decision; 13],
    }

    /// The policy in the module docs, as bits.
    pub fn plan(ids: &Ids) -> Plan {
        let has = |word: u32, bit: u32| word & bit != 0;
        let mut set = 0u64;
        let mut clear = 0u64;
        let mut decide = |bit: u8, name: &'static str, on: bool, reason: &'static str| {
            if on {
                set |= 1 << bit;
            } else {
                clear |= 1 << bit;
            }
            Decision::new("cr4", bit, name, on, reason)
        };

        let tsd = decide(TSD, "TSD", false, "kept clear: RDTSC readable at every privilege level");
        let pse = if has(ids.leaf1_edx, EDX_PSE) {
            decide(PSE, "PSE", true, if ids.long_mode { "4 MiB pages (ignored in long mode)" } else { "4 MiB pages: the identity map" })
        } else {
            decide(PSE, "PSE", false, "no 4 MiB pages")
        };
        let pge = if has(ids.leaf1_edx, EDX_PGE) {
            decide(PGE, "PGE", true, "global pages supported")
        } else {
            decide(PGE, "PGE", false, "no global pages")
        };
        let pce = if ids.pmu_version > 0 || ids.amd_counters {
            decide(PCE, "PCE", true, "PMU present: RDPMC at every privilege level")
        } else {
            decide(PCE, "PCE", false, "no PMU reported")
        };
        let osfxsr = if has(ids.leaf1_edx, EDX_FXSR) {
            decide(OSFXSR, "OSFXSR", true, "FXSAVE/SSE supported")
        } else {
            decide(OSFXSR, "OSFXSR", false, "no FXSR")
        };
        let osxmm = if has(ids.leaf1_edx, EDX_SSE) {
            decide(OSXMMEXCPT, "OSXMMEXCPT", true, "SSE: #XM for unmasked SIMD exceptions")
        } else {
            decide(OSXMMEXCPT, "OSXMMEXCPT", false, "no SSE")
        };
        let umip = if has(ids.leaf7_ecx, LEAF7_ECX_UMIP) {
            decide(UMIP, "UMIP", true, "supported: descriptor-table reads ring 0 only")
        } else {
            decide(UMIP, "UMIP", false, "not supported")
        };

        let mut feature_control = None;
        let vmxe = if !has(ids.leaf1_ecx, ECX_VMX) {
            decide(VMXE, "VMXE", false, "no VMX")
        } else {
            match ids.feature_control {
                Some(fc) if fc & FC_LOCK == 0 => {
                    let mut want = fc | FC_LOCK | FC_VMX_OUTSIDE_SMX;
                    if has(ids.leaf1_ecx, ECX_SMX) {
                        want |= FC_VMX_IN_SMX;
                    }
                    feature_control = Some(want);
                    decide(VMXE, "VMXE", true, "VMX; feature control unlocked: enabled and locked")
                }
                Some(fc) if fc & FC_VMX_OUTSIDE_SMX == 0 => {
                    decide(VMXE, "VMXE", false, "VMX locked off by the firmware")
                }
                Some(_) => decide(VMXE, "VMXE", true, "VMX enabled by the firmware"),
                // MSR unreadable (a hypervisor that does not model it): the
                // bit itself is legal with VMX; VMXON will say the rest.
                None => decide(VMXE, "VMXE", true, "VMX; feature control not readable"),
            }
        };
        let smxe = if has(ids.leaf1_ecx, ECX_SMX) {
            decide(SMXE, "SMXE", true, "SMX (TXT) supported: GETSEC usable")
        } else {
            decide(SMXE, "SMXE", false, "no SMX")
        };
        let fsgsbase = if !has(ids.leaf7_ebx, LEAF7_EBX_FSGSBASE) {
            decide(FSGSBASE, "FSGSBASE", false, "not supported")
        } else if !ids.long_mode {
            decide(FSGSBASE, "FSGSBASE", false, "64-bit mode only")
        } else {
            decide(FSGSBASE, "FSGSBASE", true, "RD/WR FS/GS base at every privilege level")
        };
        let pcide = if !has(ids.leaf1_ecx, ECX_PCID) {
            decide(PCIDE, "PCIDE", false, "no PCID")
        } else if !ids.long_mode {
            decide(PCIDE, "PCIDE", false, "needs long mode")
        } else if ids.cr3_low != 0 {
            decide(PCIDE, "PCIDE", false, "CR3 low bits not clear")
        } else {
            decide(PCIDE, "PCIDE", true, "PCID supported, CR3 tag 0")
        };
        let osxsave = if !has(ids.leaf1_ecx, ECX_XSAVE) {
            decide(OSXSAVE, "OSXSAVE", false, "no XSAVE")
        } else if !has(ids.leaf1_ecx, ECX_AVX) {
            decide(OSXSAVE, "OSXSAVE", false, "XSAVE but no AVX: no wider state to manage")
        } else {
            decide(OSXSAVE, "OSXSAVE", true, "XSAVE and AVX")
        };

        let pg = Decision::new(
            "cr0",
            PG,
            "PG",
            ids.paging,
            match (ids.paging, ids.long_mode) {
                (true, true) => "paging: required by long mode",
                (true, false) => "paging: 4 MiB identity map (boot stub)",
                (false, _) => "paging off",
            },
        );
        Plan {
            set,
            clear,
            feature_control,
            decisions: [tsd, pse, pge, pce, osfxsr, osxmm, umip, vmxe, smxe, fsgsbase, pcide, osxsave, pg],
        }
    }
}

/// AArch64: the ID-register half of the same dispatcher.
pub mod aarch64 {
    use super::Decision;

    /// What the kernel read: `ID_AA64PFR0_EL1`, `ID_AA64PFR1_EL1`,
    /// `ID_AA64DFR0_EL1`, `ID_AA64MMFR0_EL1`, and the exception level.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Ids {
        pub pfr0: u64,
        pub pfr1: u64,
        pub dfr0: u64,
        pub mmfr0: u64,
        pub el: u8,
    }

    fn field(reg: u64, shift: u32) -> u64 {
        (reg >> shift) & 0xF
    }

    /// Controls the Rust half sets (the boot stub already did the trap
    /// controls and vector lengths, which have to precede any Rust).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Plan {
        /// `CNTKCTL_EL1.EL0VCTEN | EL0PCTEN`: the counter readable at EL0.
        pub el0_counter: bool,
        /// `PMUSERENR_EL0.EN | CR | ER`: the PMU readable at EL0.
        pub el0_pmu: bool,
        /// `SCR_EL3.HCE`: HVC enabled below EL3 (at EL3 only).
        pub hypervisor_calls: bool,
        /// `TCR_ELx.AS`: 16-bit ASIDs.
        pub asid16: bool,
        pub decisions: [Decision; 7],
    }

    /// The policy, from the ID registers.
    pub fn plan(ids: &Ids) -> Plan {
        const NONE: u8 = 0xFF;
        let fp = field(ids.pfr0, 16) != 0xF;
        let advsimd = field(ids.pfr0, 20) != 0xF;
        let sve = field(ids.pfr0, 32) != 0;
        let sme = field(ids.pfr1, 24) != 0;
        let el2 = field(ids.pfr0, 8) != 0;
        let pmu = !matches!(field(ids.dfr0, 8), 0 | 0xF);
        let asid16 = field(ids.mmfr0, 4) == 2;
        let decisions = [
            Decision::new("cpacr", NONE, "FP/AdvSIMD", fp && advsimd, if fp && advsimd { "CPACR.FPEN: no trap" } else { "absent" }),
            Decision::new("zcr", NONE, "SVE", sve, if sve { "ZEN on, ZCR.LEN at the maximum" } else { "absent" }),
            Decision::new("smcr", NONE, "SME", sme, if sme { "SMEN on, SMCR.LEN at the maximum" } else { "absent" }),
            Decision::new("cntkctl", NONE, "EL0 counter", true, "virtual and physical counter at EL0 (TSD's counterpart)"),
            Decision::new("pmuserenr", NONE, "EL0 PMU", pmu, if pmu { "PMU readable at EL0 (PCE's counterpart)" } else { "no PMU" }),
            Decision::new(
                "scr_el3",
                NONE,
                "HVC",
                el2,
                match (el2, ids.el) {
                    (false, _) => "no EL2",
                    (true, 3) => "SCR_EL3.HCE: hypervisor calls enabled",
                    (true, _) => "EL2 present (HCE is EL3's to set)",
                },
            ),
            Decision::new("tcr", NONE, "ASID16", asid16, if asid16 { "16-bit ASIDs (PCIDE's counterpart)" } else { "8-bit ASIDs only" }),
        ];
        Plan { el0_counter: true, el0_pmu: pmu, hypervisor_calls: el2 && ids.el == 3, asid16, decisions }
    }
}

#[cfg(test)]
mod tests {
    use super::x86::*;

    fn modern() -> Ids {
        Ids {
            leaf1_ecx: ECX_VMX | ECX_PCID | ECX_XSAVE | ECX_AVX,
            leaf1_edx: EDX_PSE | EDX_PGE | EDX_FXSR | EDX_SSE,
            leaf7_ebx: LEAF7_EBX_FSGSBASE,
            leaf7_ecx: LEAF7_ECX_UMIP,
            pmu_version: 5,
            amd_counters: false,
            long_mode: true,
            paging: true,
            cr3_low: 0,
            feature_control: Some(FC_LOCK | FC_VMX_OUTSIDE_SMX),
        }
    }

    fn on(plan: &Plan, bit: u8) -> bool {
        plan.set & (1 << bit) != 0
    }

    #[test]
    fn a_modern_part_gets_everything_it_has() {
        let p = plan(&modern());
        for bit in [PSE, PGE, PCE, OSFXSR, OSXMMEXCPT, UMIP, VMXE, FSGSBASE, PCIDE, OSXSAVE] {
            assert!(on(&p, bit), "bit {bit}");
        }
        assert!(!on(&p, SMXE), "no SMX in this part");
        assert!(p.clear & (1 << TSD) != 0, "TSD is always cleared");
        assert_eq!(p.feature_control, None, "locked by firmware: left alone");
    }

    #[test]
    fn no_avx_means_no_osxsave_even_with_xsave() {
        let mut ids = modern();
        ids.leaf1_ecx &= !ECX_AVX;
        let p = plan(&ids);
        assert!(!on(&p, OSXSAVE));
        assert!(p.clear & (1 << OSXSAVE) != 0);
    }

    #[test]
    fn pcide_needs_long_mode_pcid_and_a_clean_cr3() {
        let mut ids = modern();
        ids.long_mode = false;
        assert!(!on(&plan(&ids), PCIDE));
        let mut ids = modern();
        ids.cr3_low = 0x18;
        assert!(!on(&plan(&ids), PCIDE));
        let mut ids = modern();
        ids.leaf1_ecx &= !ECX_PCID;
        assert!(!on(&plan(&ids), PCIDE));
    }

    #[test]
    fn fsgsbase_is_64_bit_only() {
        let mut ids = modern();
        ids.long_mode = false;
        assert!(!on(&plan(&ids), FSGSBASE));
        assert!(on(&plan(&ids), PSE), "PSE is for the 32-bit map above all");
    }

    #[test]
    fn vmx_follows_feature_control() {
        let mut ids = modern();
        ids.feature_control = Some(FC_LOCK);
        assert!(!on(&plan(&ids), VMXE), "locked off");
        ids.feature_control = Some(0);
        let p = plan(&ids);
        assert!(on(&p, VMXE));
        assert_eq!(p.feature_control, Some(FC_LOCK | FC_VMX_OUTSIDE_SMX));
        ids.leaf1_ecx |= ECX_SMX;
        assert_eq!(plan(&ids).feature_control, Some(FC_LOCK | FC_VMX_OUTSIDE_SMX | FC_VMX_IN_SMX));
        ids.leaf1_ecx &= !ECX_VMX;
        assert!(!on(&plan(&ids), VMXE));
    }

    #[test]
    fn nothing_is_set_on_a_bare_part() {
        let ids = Ids::default();
        let p = plan(&ids);
        assert_eq!(p.set, 0);
        assert_eq!(p.decisions.len(), 13);
        assert!(!p.decisions[12].on, "CR0.PG reported off");
    }

    #[test]
    fn aarch64_reads_its_id_fields() {
        use super::aarch64::{plan, Ids};
        // FP and AdvSIMD implemented (0), SVE (1 at [35:32]), EL2 (1 at
        // [11:8]); SME 2 at PFR1[27:24]; PMUv3 at DFR0[11:8]; 16-bit ASIDs.
        let ids = Ids { pfr0: 1 << 32 | 1 << 8, pfr1: 2 << 24, dfr0: 4 << 8, mmfr0: 2 << 4, el: 3 };
        let p = plan(&ids);
        assert!(p.el0_pmu && p.hypervisor_calls && p.asid16);
        assert!(p.decisions.iter().all(|d| d.on));
        // No FP (0xF), no PMU (0xF = IMPLEMENTATION DEFINED, not PMUv3).
        let bare = Ids { pfr0: 0xF << 16 | 0xF << 20, pfr1: 0, dfr0: 0xF << 8, mmfr0: 0, el: 1 };
        let p = plan(&bare);
        assert!(!p.el0_pmu && !p.hypervisor_calls && !p.asid16);
        assert!(!p.decisions[0].on);
    }
}
