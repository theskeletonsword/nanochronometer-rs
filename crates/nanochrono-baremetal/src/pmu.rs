// SPDX-License-Identifier: Apache-2.0
//! Performance counters with no kernel underneath.
//!
//! Everywhere else in this toolkit the PMU is reached through the OS —
//! `perf_event_open`, the Windows thread-profiling API — because the kernel
//! owns the counters, schedules them per thread and corrects for multiplexing.
//! Here there is no kernel. This code *is* ring 0, so it programs the counters
//! itself and reads them with `RDPMC` (x86) or `PMCCNTR_EL0` (AArch64).
//!
//! That inverts every argument for avoiding those instructions in a hosted
//! build. There is no context switch to survive, no multiplexing to miss, and
//! no scheduler to move the thread — so a raw counter read is not merely
//! acceptable, it is the only correct option.
//!
//! # There is no Rust intrinsic for this
//!
//! `core::arch::x86_64` has `_rdtsc` and `__rdtscp` but **not** `_rdpmc` —
//! stdarch lists it in `missing_x86_common.txt`, so it is a known gap rather
//! than a naming question. `RDMSR`/`WRMSR` and every AArch64 system register
//! have no intrinsics either. All of it is `core::arch::asm!`, which is what
//! the rest of this project uses anyway.
//!
//! # Hybrid CPUs
//!
//! On a P-core/E-core part the two core types are different
//! microarchitectures that happen to share an instruction set. They report
//! **different `CPUID.0AH` values** — a different number of general-purpose
//! counters, and potentially a different counter width — so a PMU
//! configuration derived on one is not valid on the other. Worse, a cycle
//! count from a P-core and one from an E-core are not comparable at all: the
//! same work takes a different number of cycles by design.
//!
//! So [`CorePmu::detect`] must run **on the core it describes**, and every
//! reading carries the [`CoreType`] it came from. Nothing here averages
//! across core types, because that number would be meaningless.

use crate::arch;

// The decoding lives in `nanochrono-core` because it is pure logic that has
// to be tested with values this target cannot be driven with: on a hybrid
// part, one thread can only ever observe one of the two core types. What
// stays here is the privileged half — programming the counters and reading
// them — which needs ring 0 / EL1 and so cannot be tested from a host.
pub use nanochrono_core::pmu_leaf::{
    classify_core, decode_pmu_leaf, mask_to_width, CoreType, PmuLeaf, Reading,
};

/// Which counter [`CorePmu::enable`] found actually works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterRoute {
    /// The architectural fixed counter. Preferred: it means the same thing on
    /// every core type, which no general-purpose event encoding does.
    Fixed,
    /// A general-purpose counter programmed with an architectural event.
    General(u32),
    /// Nothing on this core counts. No measurement will be reported.
    None,
}

impl CounterRoute {
    pub const fn name(self) -> &'static str {
        match self {
            CounterRoute::Fixed => "fixed",
            CounterRoute::General(_) => "general-purpose",
            CounterRoute::None => "none",
        }
    }
}

/// What one core's PMU can do, and which core said so.
///
/// The description and the core type travel together because on a hybrid part
/// neither means anything without the other.
#[derive(Debug, Clone, Copy)]
pub struct CorePmu {
    pub leaf: PmuLeaf,
    pub core_type: CoreType,
    /// Filled in by [`enable`](Self::enable); `None` until then.
    pub route: CounterRoute,
    /// Which register interface this core's counters live behind.
    ///
    /// Decided from `CPUID.0H` before any MSR is touched — see [`PmuKind`].
    pub kind: PmuKind,
    /// Per-core bookkeeping: what each counter was programmed with.
    ///
    /// Kept because a counter is a piece of shared hardware and this is the
    /// only record of what it currently means. Reading a counter that
    /// something else reprogrammed gives a number that looks perfectly
    /// reasonable and answers a different question, and the difference is
    /// invisible without this.
    pub slots: [Slot; MAX_TRACKED_COUNTERS],
}

/// Counters this tracks per core.
///
/// Eight covers Intel's eight general-purpose counters on a P-core and AMD's
/// six; a part with more has the extras left unprogrammed rather than
/// unrecorded.
pub const MAX_TRACKED_COUNTERS: usize = 8;

/// What one counter on this core is currently doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Slot {
    /// The event select value written, or zero if the counter is not ours.
    pub event: u64,
    /// Whether this code programmed it, as opposed to finding it in use.
    pub owned: bool,
}

// ---------------------------------------------------------------------------
// x86-64
// ---------------------------------------------------------------------------

/// Which register interface this core's counters live behind.
///
/// # The dispatch, and why it is by vendor rather than by feature
///
/// A performance counter is not architectural the way `RDTSC` is. Intel's
/// live behind `IA32_PERFEVTSEL0` at MSR `0x186`; AMD's behind
/// `0xC0010000` or `0xC0010200`, in pairs, with a different bit layout and a
/// different event encoding. There is no feature bit that says "the Intel
/// MSRs are here" — `CPUID.0AH` describes Intel's architectural PMU and AMD
/// answers it with zeros — so the only way to know which registers exist is
/// to know who made the part.
///
/// Getting that wrong is not a wrong reading, it is a dead machine: `WRMSR`
/// to an MSR the part does not implement raises `#GP`, and this kernel has no
/// interrupt descriptor table to take it. So the vendor is read first, from
/// `CPUID.0H`, and nothing touches an MSR until it is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmuKind {
    /// Intel's architectural PMU, enumerated by `CPUID.0AH`.
    ///
    /// Shared with Zhaoxin and VIA/Centaur, which are not imitations of it:
    /// Zhaoxin's own Linux driver reads `CPUID.0AH` and requires version 2,
    /// the same interface at the same registers.
    IntelArchitectural,
    /// AMD's core counters at `0xC0010200`, in `(select, counter)` pairs.
    ///
    /// Six by default since Family 15h, and exactly as many as
    /// `CPUID.80000022H:EBX[3:0]` states where that leaf exists.
    AmdCore,
    /// AMD's original four at `0xC0010000` / `0xC0010004`.
    ///
    /// Family 0Fh through 10h, and any part that does not report the
    /// extended-counter feature bit.
    AmdLegacy,
    /// AArch64's PMU, behind `PMCR_EL0`, `PMCNTENSET_EL0` and `PMCCNTR_EL0`.
    ///
    /// These are system registers rather than MSRs, and the counter is
    /// unprivileged where the x86 ones are not — but they are still per-core
    /// hardware with the same owner problem, so they are tracked with the
    /// same interface descriptor.
    ArmSystemRegister,
    /// 64-bit Book3S (POWER8 and later): `MMCR0` controls, `PMC5` counts
    /// instructions completed and `PMC6` cycles, both fixed-function.
    PowerMmcr,
    /// RISC-V's `cycle` and `instret` CSRs, readable in S-mode when M-mode
    /// firmware set `mcounteren.CY`/`IR`.
    RiscvCounters,
    /// The 32-bit classic PowerPC PMU (G3 750, G4 74xx): `MMCR0` selects
    /// events for `PMC1`/`PMC2` at SPRs 952-954.
    Classic7xx,
    /// A part whose counters this does not know how to reach. Nothing is
    /// programmed and no measurement is reported — which is the only safe
    /// answer, because the alternative is guessing at an MSR address.
    Unknown,
}

impl PmuKind {
    pub const fn name(self) -> &'static str {
        match self {
            PmuKind::IntelArchitectural => "intel architectural",
            PmuKind::AmdCore => "amd core (0xc0010200)",
            PmuKind::AmdLegacy => "amd k8 (0xc0010000)",
            PmuKind::ArmSystemRegister => "arm64 system registers",
            PmuKind::PowerMmcr => "power book3s (mmcr0, pmc5/pmc6)",
            PmuKind::RiscvCounters => "risc-v cycle/instret csrs",
            PmuKind::Classic7xx => "classic 7xx/74xx (mmcr0, pmc1/pmc2)",
            PmuKind::Unknown => "unknown",
        }
    }
}

#[cfg(x86_any)]
mod x86 {
    use super::{
        classify_core, decode_pmu_leaf, mask_to_width, CorePmu, CoreType, CounterRoute, Reading,
    };
    use crate::arch::x86::{cpuid, rdmsr, rdpmc, wrmsr};
    use nanochrono_core::cpu::Vendor;

    use super::PmuKind;

    /// `IA32_FIXED_CTR_CTRL`. Four bits per fixed counter.
    const IA32_FIXED_CTR_CTRL: u32 = 0x38D;
    /// `IA32_PERF_GLOBAL_CTRL`. Bit `n` enables general counter `n`; bit
    /// `32 + n` enables fixed counter `n`.
    const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;

    /// `IA32_PERFEVTSEL0`, the first general-purpose event select.
    const IA32_PERFEVTSEL0: u32 = 0x186;
    /// `IA32_PMC0`, the first general-purpose counter.
    const IA32_PMC0: u32 = 0xC1;

    /// `IA32_PERF_GLOBAL_OVF_CTRL` / `..._STATUS_RESET`, which clears any
    /// overflow the firmware left latched. A latched overflow can leave a
    /// counter frozen depending on the control settings.
    ///
    /// **Only implemented counter bits may be written.** The register is
    /// mostly reserved, and `WRMSR` raises `#GP` on a reserved bit that is
    /// set — which in a kernel with no IDT is a triple fault. An emulator
    /// ignores the write; real silicon does not, and this was a live bug:
    /// clearing it with `u64::MAX` worked under QEMU and killed the machine
    /// on a laptop.
    const IA32_PERF_GLOBAL_OVF_CTRL: u32 = 0x390;

    /// `CPU_CLK_UNHALTED.THREAD` as a general-purpose event.
    ///
    /// Event `0x3C`, umask `0x00`. This is one of the seven *architectural*
    /// events — the set `CPUID.0AH:EBX` reports availability for — which is
    /// the whole reason it can be used without knowing whether this is a
    /// Raptor Cove or a Gracemont. A model-specific event select would mean
    /// something different on each, and that is precisely how a hybrid part
    /// turns a working measurement into a plausible wrong one.
    const ARCH_EVENT_UNHALTED_CORE_CYCLES: (u8, u8) = (0x3C, 0x00);

    /// The bit in `CPUID.0AH:EBX` that would mark it unavailable.
    const EBX_BIT_UNHALTED_CORE_CYCLES: u32 = 1;

    /// `RDPMC` selects a fixed counter by setting bit 30 of `ECX`.
    const RDPMC_FIXED: u32 = 1 << 30;

    /// Fixed counter 1 is `CPU_CLK_UNHALTED.THREAD` — this core's cycles,
    /// which is the quantity a chronometer wants. Fixed counter 0 is
    /// instructions retired and 2 is the reference (TSC-rate) clock.
    pub const FIXED_CORE_CYCLES: u32 = 1;
    pub const FIXED_INSTRUCTIONS: u32 = 0;
    pub const FIXED_REF_CYCLES: u32 = 2;

    fn core_type() -> CoreType {
        let max_leaf = cpuid(0, 0)[0];
        let leaf7_edx = if max_leaf >= 7 { cpuid(7, 0)[3] } else { 0 };
        let leaf1a_eax = if max_leaf >= 0x1A {
            cpuid(0x1A, 0)[0]
        } else {
            0
        };
        classify_core(max_leaf, leaf7_edx, leaf1a_eax)
    }

    /// Describes the PMU of the core this runs on.
    /// Describes this core's PMU, dispatching on the vendor before anything
    /// is touched.
    ///
    /// The order is deliberate and is the whole safety argument:
    ///
    /// 1. `CPUID.0H` for the vendor string. Reading CPUID is safe anywhere.
    /// 2. From the vendor, which register interface exists — see [`PmuKind`].
    /// 3. Only then the enumeration leaf, which differs per interface.
    ///
    /// Nothing writes an MSR here. A `WRMSR` to a register the part does not
    /// implement is `#GP`, and with no interrupt descriptor table that is a
    /// triple fault; so the address space is established before it is used,
    /// rather than probed by trying.
    pub(super) fn detect() -> CorePmu {
        let core_type = core_type();
        let vendor = nanochrono_core::cpu::vendor();

        let (kind, leaf) = match vendor {
            // Intel's architectural PMU, and the two vendors that implement
            // the same interface rather than an imitation of it.
            Vendor::Intel | Vendor::Zhaoxin | Vendor::Centaur => {
                if cpuid(0, 0)[0] < 0x0A {
                    (PmuKind::Unknown, Default::default())
                } else {
                    let [eax, ebx, _ecx, edx] = cpuid(0x0A, 0);
                    (PmuKind::IntelArchitectural, decode_pmu_leaf(eax, ebx, edx))
                }
            }
            Vendor::Amd => amd::detect(),
            Vendor::Other(_) => (PmuKind::Unknown, Default::default()),
        };

        CorePmu {
            leaf,
            core_type,
            route: CounterRoute::None,
            kind,
            slots: [Default::default(); super::MAX_TRACKED_COUNTERS],
        }
    }

    /// AMD's core performance counters.
    ///
    /// # Reference
    ///
    /// Register addresses, the `(select, counter)` pairing, the counter
    /// widths and the enumeration order follow FreeBSD's
    /// `sys/dev/hwpmc/hwpmc_amd.c` and `hwpmc_amd.h`, which are BSD-2-Clause
    /// and whose terms ask for attribution in return; see `NOTICE`. The event
    /// numbers are from AMD's own BIOS and Kernel Developer's Guide,
    /// publication 32559.
    pub(in crate::pmu) mod amd {
        use super::{cpuid, rdmsr, wrmsr, PmuKind};
        use nanochrono_core::pmu_leaf::{amd_event_select, PmuLeaf};

        /// The original four counters. Family 0Fh through 10h.
        const K8_EVSEL_0: u32 = 0xC001_0000;
        const K8_PERFCTR_0: u32 = 0xC001_0004;
        const K8_COUNTERS: u8 = 4;

        /// The extended set, in `(select, counter)` pairs two MSRs apart:
        /// select `n` at `BASE + 2n`, counter `n` at `BASE + 2n + 1`.
        const CORE_BASE: u32 = 0xC001_0200;
        /// Six since Family 15h, unless `CPUID.80000022H` says otherwise.
        const CORE_DEFAULT: u8 = 6;

        /// `CPUID.80000001H:ECX[23]`, PerfCtrExtCore: the extended counters
        /// exist. FreeBSD calls this `AMDID2_PCXC`.
        const PERFCTR_EXT_CORE: u32 = 1 << 23;

        /// `CPUID.80000022H`, which states the counts exactly where it
        /// exists. `EBX[3:0]` is the number of core counters.
        const EXT_PERFMON_LEAF: u32 = 0x8000_0022;

        /// AMD counters are 48 bits wide, on both interfaces.
        const COUNTER_WIDTH: u8 = 48;

        /// Event select bits. The layout is AMD's, not Intel's: the enable
        /// bit is 22 rather than 22-with-different-neighbours, and the event
        /// number is split across bits 7:0 and 35:32.
        const EVSEL_USR: u64 = 1 << 16;
        const EVSEL_OS: u64 = 1 << 17;
        const EVSEL_ENABLE: u64 = 1 << 22;

        /// `CPU Clocks not Halted`, event `0x76`. AMD BKDG 32559, §11.2.1.6.
        const EVENT_CYCLES: u16 = 0x76;
        /// `Retired Instructions`, event `0xC0`. AMD BKDG 32559, §11.2.1.6.
        /// The K8 family calls it `Retired x86 Instructions`; Family 10h and
        /// later use the same code for the same event. This is the number
        /// FreeBSD's `amd_event_codes` maps `PMC_EV_K8_FR_RETIRED_X86_INSTRUCTIONS`
        /// to, identical on every AMD core family back to K8.
        const EVENT_INSTRUCTIONS: u16 = 0xC0;

        /// What this core's counters are and where they live.
        pub(in crate::pmu) fn detect() -> (PmuKind, PmuLeaf) {
            // The extended leaf states the count exactly. Preferred over the
            // feature bit's default, which is only a default.
            let extended = cpuid(0x8000_0000, 0)[0] >= EXT_PERFMON_LEAF;
            let stated = if extended {
                (cpuid(EXT_PERFMON_LEAF, 0)[1] & 0x0F) as u8
            } else {
                0
            };

            let has_ext_core = cpuid(0x8000_0000, 0)[0] >= 0x8000_0001
                && cpuid(0x8000_0001, 0)[2] & PERFCTR_EXT_CORE != 0;

            let (kind, counters) = if has_ext_core {
                (
                    PmuKind::AmdCore,
                    if stated != 0 { stated } else { CORE_DEFAULT },
                )
            } else if cpuid(0x8000_0000, 0)[0] >= 0x8000_0001 {
                (PmuKind::AmdLegacy, K8_COUNTERS)
            } else {
                // No extended CPUID at all: not an x86-64 AMD this knows.
                return (PmuKind::Unknown, PmuLeaf::default());
            };

            (
                kind,
                PmuLeaf {
                    // AMD has no architectural-PMU version; one is the
                    // honest answer for "counters exist and are readable".
                    version: 1,
                    general_counters: counters.min(super::super::MAX_TRACKED_COUNTERS as u8),
                    general_width: COUNTER_WIDTH,
                    // No fixed counters: every AMD counter is programmable.
                    fixed_counters: 0,
                    fixed_width: 0,
                    ..PmuLeaf::default()
                },
            )
        }

        /// The `(select, counter)` MSR pair for counter `index`.
        fn msrs(kind: PmuKind, index: u32) -> Option<(u32, u32)> {
            match kind {
                PmuKind::AmdCore => Some((CORE_BASE + 2 * index, CORE_BASE + 2 * index + 1)),
                PmuKind::AmdLegacy => Some((K8_EVSEL_0 + index, K8_PERFCTR_0 + index)),
                _ => None,
            }
        }

        /// Programmes counter zero to count unhalted core cycles.
        ///
        /// Returns the counter index on success. Nothing is written unless
        /// the interface was identified, so a part this does not recognise
        /// leaves its MSRs alone.
        ///
        /// # Safety
        /// Writes MSRs; requires CPL 0 and an AMD part.
        pub(in crate::pmu) unsafe fn enable_cycles(
            kind: PmuKind,
            counters: u8,
        ) -> Option<(u32, u64)> {
            // SAFETY: forwarded from this function's own contract.
            unsafe { enable_general(kind, counters, 0, EVENT_CYCLES) }
        }

        /// Programmes counter one to count retired instructions.
        ///
        /// Only when a second counter exists — the K8 group always has four,
        /// and nothing with a core counter ever has one, but the leaf owns
        /// the truth and a counter this did not check for is an MSR this
        /// would not touch.
        ///
        /// # Safety
        /// Writes MSRs; requires CPL 0 and an AMD part.
        pub(in crate::pmu) unsafe fn enable_instructions(
            kind: PmuKind,
            counters: u8,
        ) -> Option<(u32, u64)> {
            // SAFETY: forwarded from this function's own contract.
            unsafe { enable_general(kind, counters, 1, EVENT_INSTRUCTIONS) }
        }

        /// Programmes counter `index` with an event, if the interface was
        /// identified and the counter exists.
        ///
        /// The event number goes through [`amd_event_select`] because AMD
        /// splits it across bits 7:0 and 35:32; a byte that just happened to
        /// fit would stop being correct the day an event above `0xFF` is
        /// used. Counting is enabled for both privilege levels (`USR | OS`),
        /// so the count does not depend on where the caller runs, and no
        /// interrupt is raised on overflow — there is no handler for one.
        ///
        /// # Safety
        /// Writes MSRs; requires CPL 0 and an AMD part.
        unsafe fn enable_general(
            kind: PmuKind,
            counters: u8,
            index: u32,
            event_code: u16,
        ) -> Option<(u32, u64)> {
            if index >= counters as u32 {
                return None;
            }
            let (evsel, perfctr) = msrs(kind, index)?;
            let event = amd_event_select(event_code, 0) | EVSEL_USR | EVSEL_OS | EVSEL_ENABLE;

            // SAFETY: the addresses come from `msrs`, which only answers for
            // an interface `detect` positively identified, and the counter
            // index was bounds-checked against the leaf above. Order
            // matters: the counter is zeroed while the select is still
            // disabled, so it cannot count between the two writes.
            unsafe {
                wrmsr(evsel, 0);
                wrmsr(perfctr, 0);
                wrmsr(evsel, event);
            }
            Some((index, event))
        }

        /// Reads counter `index`, sign-extended from its 48 bits.
        ///
        /// # Safety
        /// Reads an MSR; requires CPL 0 and an AMD part.
        pub(in crate::pmu) unsafe fn read(kind: PmuKind, index: u32) -> Option<u64> {
            let (_, perfctr) = msrs(kind, index)?;
            // SAFETY: as above.
            let raw = unsafe { rdmsr(perfctr) };
            // The counter is 48 bits and the upper bits read as whatever the
            // part leaves there. Masking rather than sign-extending, because
            // this is a monotonically increasing count and a difference of
            // two masked reads is correct across a wrap.
            Some(raw & ((1u64 << COUNTER_WIDTH) - 1))
        }
    }

    /// Sets `CR4.PCE`, which permits `RDPMC` outside ring 0.
    ///
    /// Not required by anything here, and said plainly rather than implied:
    /// the SDM's pseudocode for `RDPMC` is
    ///
    /// ```text
    /// IF (((CR4.PCE = 1) or (CPL = 0) or (CR0.PE = 0)) and (ECX indicates a supported counter))
    /// ```
    ///
    /// — so at CPL 0, which this kernel never leaves, the flag is irrelevant.
    /// It is set anyway because it costs one `MOV` pair, because it makes the
    /// intent explicit, and because the moment anything here runs at CPL 3
    /// its absence would be a fault with no obvious cause.
    ///
    /// # Safety
    /// Writes `CR4`; requires CPL 0.
    pub(super) unsafe fn enable_rdpmc_outside_ring0() {
        // SAFETY: `CR4.PCE` is bit 8 on every x86-64 part; setting a defined
        // bit and preserving the rest cannot fault.
        unsafe {
            let mut cr4: usize;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            cr4 |= 1 << 8;
            core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
        }
    }

    /// Programs a general-purpose counter with the architectural
    /// core-cycles event, and returns its index.
    ///
    /// The fallback for a part with no usable fixed counters — some server
    /// SKUs and anything at PMU version 1. Only an *architectural* event is
    /// used, because a model-specific encoding means different things on a
    /// P-core and an E-core.
    ///
    /// # Safety
    /// Writes MSRs; requires CPL 0.
    pub(super) unsafe fn enable_general_cycles(pmu: &CorePmu) -> Option<u32> {
        if pmu.leaf.general_counters == 0 {
            return None;
        }
        // CPUID.0AH:EBX bit N set means architectural event N is *not*
        // available on this core — the one place the two core types of a
        // hybrid part genuinely can disagree about what they can count.
        if pmu.leaf.events_unavailable & EBX_BIT_UNHALTED_CORE_CYCLES != 0 {
            return None;
        }

        let (event, umask) = ARCH_EVENT_UNHALTED_CORE_CYCLES;
        // USR (bit 16) | OS (bit 17) | EN (bit 22): count in both privilege
        // levels so the number does not depend on where the caller runs, and
        // no interrupt on overflow because there is no handler for one.
        let select = (event as u64) | ((umask as u64) << 8) | (1 << 16) | (1 << 17) | (1 << 22);

        // SAFETY: caller guarantees CPL 0. Counter 0 exists whenever
        // `general_counters` is non-zero, which was just checked.
        unsafe {
            wrmsr(IA32_PMC0, 0);
            wrmsr(IA32_PERFEVTSEL0, select);
            // Only counter 0, and only bits this core implements.
            let global = rdmsr(IA32_PERF_GLOBAL_CTRL) & implemented_mask(pmu);
            wrmsr(IA32_PERF_GLOBAL_CTRL, global | 1);
        }
        Some(0)
    }

    /// Which bits of `IA32_PERF_GLOBAL_CTRL` this core actually implements.
    ///
    /// Everything else in the register is reserved, and carrying a stale
    /// reserved bit through a read-modify-write is `#GP` on the write.
    fn implemented_mask(pmu: &CorePmu) -> u64 {
        let mut mask = 0u64;
        for i in 0..pmu.leaf.general_counters.min(32) as u32 {
            mask |= 1u64 << i;
        }
        for i in 0..pmu.leaf.fixed_counters.min(3) as u32 {
            mask |= 1u64 << (32 + i);
        }
        mask
    }

    /// Reads a general-purpose counter, masked to its width.
    ///
    /// # Safety
    /// Requires CPL 0, or `CR4.PCE`.
    pub(super) unsafe fn read_general(pmu: &CorePmu, index: u32) -> Option<Reading> {
        if index >= pmu.leaf.general_counters as u32 {
            return None;
        }
        // `RDPMC` rather than `RDMSR`, and it is vendor-neutral here: on
        // Intel index `n` selects general counter `n`, and on AMD indices 0
        // upward select the core counters in the same order. The width mask
        // is what differs — 48 bits on AMD, whatever `CPUID.0AH` stated on
        // Intel — and that comes from the leaf rather than from an assumption.
        // SAFETY: caller guarantees the privilege level; the index was
        // bounds-checked against what this core reports.
        let raw = unsafe { rdpmc(index) };
        Some(Reading {
            value: mask_to_width(raw, pmu.leaf.general_width),
            core_type: pmu.core_type,
        })
    }

    /// Starts the fixed counters on this core.
    ///
    /// Must run on the core it is programming: the MSRs are per logical
    /// processor, so a configuration written on one core is simply absent on
    /// another — which on a hybrid part is the failure people meet, not the
    /// counter layout.
    ///
    /// # Safety
    /// Writes MSRs, so it requires CPL 0 — which a freestanding kernel always
    /// has. It clobbers any PMU configuration already in place.
    pub(super) unsafe fn enable_fixed(pmu: &CorePmu) {
        if pmu.leaf.fixed_counters == 0 {
            return;
        }

        // Four bits per counter: bit 0 counts in ring 0, bit 1 in ring > 0,
        // bit 2 is AnyThread, bit 3 raises a PMI on overflow. Ring 0 and ring
        // 3 are both enabled so the count does not depend on where a caller
        // ends up running; no PMI, because there is no handler for one.
        let mut ctrl: u64 = 0;
        for i in 0..pmu.leaf.fixed_counters.min(3) as u32 {
            ctrl |= 0b0011 << (i * 4);
        }
        // SAFETY: caller guarantees CPL 0. Both MSRs are architectural from
        // PMU version 2, which `detect` established before reporting any
        // fixed counters.
        unsafe {
            // Firmware can leave an overflow latched, which depending on the
            // control settings leaves the counter frozen and reading the same
            // value forever. Cleared by writing a one to each counter's own
            // bit — general counters low, fixed counters from bit 32 — and
            // nothing else, because every other bit in this register is
            // reserved and setting one is `#GP`.
            let mut overflow = 0u64;
            for i in 0..pmu.leaf.general_counters.min(32) as u32 {
                overflow |= 1u64 << i;
            }
            for i in 0..pmu.leaf.fixed_counters.min(3) as u32 {
                overflow |= 1u64 << (32 + i);
            }
            wrmsr(IA32_PERF_GLOBAL_OVF_CTRL, overflow);
            wrmsr(IA32_FIXED_CTR_CTRL, ctrl);

            // Enabling in the global control register is what actually starts
            // them; the per-counter bits above only say how to count.
            //
            // Built from what this core reports rather than OR-ed into
            // whatever was already there: the register's upper bits are
            // reserved, and preserving a stale one would be `#GP` on the
            // write for the same reason as above.
            let mut global = 0u64;
            for i in 0..pmu.leaf.general_counters.min(32) as u32 {
                global |= 1u64 << i;
            }
            for i in 0..pmu.leaf.fixed_counters.min(3) as u32 {
                global |= 1u64 << (32 + i);
            }
            wrmsr(IA32_PERF_GLOBAL_CTRL, global);
        }
    }

    /// Reads a fixed counter, masked to its architectural width.
    ///
    /// `RDPMC` returns `EDX:EAX` with the counter sign-extended above its
    /// real width, so the upper bits are not part of the count and must be
    /// discarded — otherwise a counter that has not yet passed its sign bit
    /// reads as an enormous number.
    ///
    /// # Safety
    /// `RDPMC` faults at CPL > 0 unless `CR4.PCE` is set. A freestanding
    /// kernel runs at CPL 0, where it is always permitted.
    pub(super) unsafe fn read_fixed(pmu: &CorePmu, index: u32) -> Option<Reading> {
        if index >= pmu.leaf.fixed_counters as u32 {
            return None;
        }
        // SAFETY: caller guarantees CPL 0, and the index was just bounds
        // checked against what this core reports.
        let raw = unsafe { rdpmc(RDPMC_FIXED | index) };
        Some(Reading {
            value: mask_to_width(raw, pmu.leaf.fixed_width),
            core_type: pmu.core_type,
        })
    }

    /// Allows `RDPMC` from ring 3 by setting `CR4.PCE`.
    ///
    /// Not needed by this kernel, which never leaves ring 0. It exists so a
    /// kernel built on this crate that *does* run user code can let it read
    /// the counters without a syscall — which is the whole reason `RDPMC`
    /// exists.
    ///
    /// # Safety
    /// Writes `CR4`; requires CPL 0.
    #[allow(dead_code)] // Part of the surface; this kernel never leaves ring 0.
    pub unsafe fn allow_rdpmc_from_user() {
        let mut cr4: usize;
        // SAFETY: caller guarantees CPL 0. Only bit 8 is touched, so no other
        // control-register state is disturbed.
        unsafe {
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
            cr4 |= 1 << 8;
            core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));
        }
    }
}

// ---------------------------------------------------------------------------
// AArch64
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
mod arm {
    use super::{CorePmu, CoreType, CounterRoute, PmuKind, PmuLeaf, Reading};
    use crate::arch::aarch64 as a;

    /// `PMCNTENSET_EL0` bit 31 enables the dedicated cycle counter.
    const PMCNTEN_CYCLE: u64 = 1 << 31;

    /// Whether event counter 0 was programmed with INST_RETIRED.
    static INSTRUCTIONS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    /// Event counter 0 (INST_RETIRED), if `enable_fixed` programmed it.
    pub(super) fn read_instructions(pmu: &CorePmu) -> Option<Reading> {
        if !INSTRUCTIONS.load(core::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        let value: u64;
        // SAFETY: the counter was programmed by `enable_fixed` on this core.
        unsafe {
            core::arch::asm!("mrs {v}, PMEVCNTR0_EL0", v = out(reg) value,
                             options(nomem, nostack, preserves_flags));
        }
        Some(Reading {
            value: value & 0xFFFF_FFFF,
            core_type: pmu.core_type,
        })
    }

    /// Classifies this core from `MIDR_EL1`.
    ///
    /// AArch64 has no `CPUID.1AH`. On a big.LITTLE part the clusters report
    /// different part numbers in `MIDR_EL1[15:4]`, which is the only thing
    /// available — it does not say which cluster is the big one, so the part
    /// number itself is carried and comparison is by equality.
    fn core_type() -> CoreType {
        // SAFETY: MIDR_EL1 is readable at EL1 and has no side effects.
        let midr: u64 = unsafe {
            let v: u64;
            core::arch::asm!("mrs {v}, MIDR_EL1", v = out(reg) v,
                             options(nomem, nostack, preserves_flags));
            v
        };
        // The part number does not fit in the `Unknown` byte, so it is folded
        // — different parts still compare unequal, which is all that is asked
        // of it.
        let part = ((midr >> 4) & 0xFFF) as u16;
        CoreType::Unknown((part ^ (part >> 8)) as u8)
    }

    /// `ID_AA64DFR0_EL1.PMUVer`, bits [11:8]: 0 means no PMU and 0xF an
    /// IMPLEMENTATION DEFINED one this driver does not know how to program.
    fn pmu_version() -> u64 {
        // SAFETY: ID registers are readable at EL1 and above, no side effects.
        let dfr0: u64 = unsafe {
            let v: u64;
            core::arch::asm!("mrs {v}, ID_AA64DFR0_EL1", v = out(reg) v,
                             options(nomem, nostack, preserves_flags));
            v
        };
        (dfr0 >> 8) & 0xF
    }

    pub(super) fn detect() -> CorePmu {
        // Every PMU system register is UNDEFINED on a core without the
        // architected PMU, so the ID register is asked before PMCR_EL0 is
        // touched. Without this check the first `mrs PMCR_EL0` on such a
        // core is an undefined-instruction exception.
        if matches!(pmu_version(), 0 | 0xF) {
            return CorePmu {
                leaf: PmuLeaf::default(),
                core_type: core_type(),
                route: CounterRoute::None,
                kind: PmuKind::Unknown,
                slots: [Default::default(); super::MAX_TRACKED_COUNTERS],
            };
        }
        // PMCR_EL0.N, bits [15:11]: the number of event counters. The cycle
        // counter is separate from those and always present when the PMU is.
        let pmcr = read_pmcr();
        CorePmu {
            leaf: PmuLeaf {
                version: 1,
                // PMCR_EL0.N, bits [15:11].
                general_counters: ((pmcr >> 11) & 0x1F) as u8,
                general_width: 32,
                // The cycle counter is the one fixed counter AArch64 has.
                fixed_counters: 1,
                // PMCR_EL0.LC is set in `enable_fixed`, making it 64 bits.
                fixed_width: 64,
                // AArch64 has no equivalent of the architectural-event
                // availability mask; PMCEID0/1_EL0 describe events, and the
                // cycle counter this uses is not one of them.
                events_unavailable: 0,
            },
            core_type: core_type(),
            route: CounterRoute::None,
            kind: PmuKind::ArmSystemRegister,
            slots: [Default::default(); super::MAX_TRACKED_COUNTERS],
        }
    }

    fn read_pmcr() -> u64 {
        // SAFETY: PMCR_EL0 is readable at EL1 with no side effects.
        unsafe {
            let v: u64;
            core::arch::asm!("mrs {v}, PMCR_EL0", v = out(reg) v,
                             options(nomem, nostack, preserves_flags));
            v
        }
    }

    /// Starts the cycle counter.
    ///
    /// # Safety
    /// Writes PMU control registers, which requires EL1.
    pub(super) unsafe fn enable_fixed(_pmu: &CorePmu) {
        let mut pmcr = read_pmcr();
        // E (bit 0) enables the counters at all.
        pmcr |= 1 << 0;
        // LC (bit 6) makes the cycle counter 64 bits. Without it the counter
        // is 32 bits and wraps every couple of seconds at gigahertz clocks,
        // which is useless for anything but the shortest interval.
        pmcr |= 1 << 6;
        // D (bit 3) divides the cycle count by 64. Clearing it is what makes
        // the counter report cycles rather than cycles/64 — a factor of 64
        // that would otherwise be silently wrong.
        pmcr &= !(1 << 3);

        // Which exception levels the cycle counter counts in is filtered by
        // PMCCFILTR_EL0, and by default it does not count at EL2: NSH
        // (bit 27) has to be set for that. A kernel entered at EL2 — QEMU
        // with `virtualization=on`, most real boards — otherwise sees a
        // counter that never moves. At EL2, MDCR_EL2.HPMD (bit 17) can also
        // prohibit counting there and is cleared. At EL3, MDCR_EL3.SCCD
        // (bit 23) prohibits the cycle counter in Secure state.
        let el = crate::arch::arm::current_el();
        // SAFETY: caller guarantees EL1 or above; each register is written
        // only at the level that owns it.
        unsafe {
            let filter: u64 = if el >= 2 { 1 << 27 } else { 0 };
            core::arch::asm!("msr PMCCFILTR_EL0, {v}", v = in(reg) filter,
                             options(nomem, nostack, preserves_flags));
            if el == 2 {
                core::arch::asm!(
                    "mrs {t}, MDCR_EL2",
                    "bic {t}, {t}, #(1 << 17)",
                    "msr MDCR_EL2, {t}",
                    t = out(reg) _,
                    options(nomem, nostack, preserves_flags),
                );
            }
            if el == 3 {
                core::arch::asm!(
                    "mrs {t}, MDCR_EL3",
                    "bic {t}, {t}, #(1 << 23)",
                    "msr MDCR_EL3, {t}",
                    t = out(reg) _,
                    options(nomem, nostack, preserves_flags),
                );
            }
        }

        // SAFETY: caller guarantees EL1, where all three registers are
        // writable.
        unsafe {
            core::arch::asm!("msr PMCR_EL0, {v}", v = in(reg) pmcr,
                             options(nomem, nostack, preserves_flags));
            // Event counter 0 counts INST_RETIRED (0x08) when the core says
            // it implements that event (PMCEID0_EL0 bit 8) and has a counter
            // to spare. Filtered like the cycle counter: NSH at EL2+.
            let eid0: u64;
            core::arch::asm!("mrs {v}, PMCEID0_EL0", v = out(reg) eid0,
                             options(nomem, nostack, preserves_flags));
            let instructions = _pmu.leaf.general_counters >= 1 && eid0 & (1 << 8) != 0;
            if instructions {
                let evtype: u64 = 0x08 | if el >= 2 { 1 << 27 } else { 0 };
                core::arch::asm!(
                    "msr PMSELR_EL0, xzr",
                    "isb",
                    "msr PMXEVTYPER_EL0, {t}",
                    "msr PMXEVCNTR_EL0, xzr",
                    t = in(reg) evtype,
                    options(nomem, nostack, preserves_flags),
                );
            }
            INSTRUCTIONS.store(instructions, core::sync::atomic::Ordering::Relaxed);
            let enable = PMCNTEN_CYCLE | u64::from(instructions);
            core::arch::asm!("msr PMCNTENSET_EL0, {v}", v = in(reg) enable,
                             options(nomem, nostack, preserves_flags));
            // PMUSERENR_EL0.EN (bit 0) lets EL0 read the counters without
            // trapping. This kernel stays at EL1, but a kernel built on it
            // that runs user code needs this for the same reason x86 needs
            // CR4.PCE.
            core::arch::asm!("msr PMUSERENR_EL0, {v}", v = in(reg) 1u64,
                             options(nomem, nostack, preserves_flags));
            a::isb();
        }
    }

    /// Reads `PMCCNTR_EL0`, the cycle counter.
    ///
    /// # Safety
    /// Requires EL1, or EL0 with `PMUSERENR_EL0.EN` set.
    pub(super) unsafe fn read_fixed(pmu: &CorePmu, index: u32) -> Option<Reading> {
        // AArch64 has exactly one fixed counter, and it counts cycles.
        if index != super::FIXED_CORE_CYCLES {
            return None;
        }
        // SAFETY: caller guarantees the access is permitted; the read has no
        // side effects.
        let value: u64 = unsafe {
            let v: u64;
            core::arch::asm!("mrs {v}, PMCCNTR_EL0", v = out(reg) v,
                             options(nomem, nostack, preserves_flags));
            v
        };
        Some(Reading {
            value,
            core_type: pmu.core_type,
        })
    }
}

/// POWER8 and later, 64-bit Book3S.
///
/// Only the fixed pair is used: `PMC5` (instructions completed) and `PMC6`
/// (cycles) need no event selection, which differs per generation, so the
/// same programming is right on POWER8, 9 and 10. `MMCR0` holds the freeze
/// controls; the kernel clears them all — including `FCH`, freeze in
/// hypervisor state, which is where `powernv` runs. PMC5/6 also count only
/// while the thread's run latch (`CTRL[RUN]`) is set, which an operating
/// system sets whenever it is not idle and a bare kernel has to set itself.
///
/// Under QEMU's TCG, `PMC6` is only brought up to date when `MMCR0` is
/// written, not when it is read. `enable` detects that — the counter does not
/// move on plain reads — and switches to rewriting `MMCR0` with its own value
/// before each read. On silicon that write changes nothing (no counter is
/// reset by it), so the mode is harmless where it is not needed; it is only
/// turned on where a plain read was shown not to advance.
///
/// Anything else — a 32-bit e500 with its separate "embedded" PMU, a G4 with
/// the 7450-style one, a pre-POWER8 part — is reported as having no PMU this
/// driver can program. The Time Base remains the measurement there.
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
mod power {
    use super::{CorePmu, CoreType, CounterRoute, PmuKind, PmuLeaf, Reading};


    static SYNC_ON_READ: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    pub(super) fn set_sync_on_read(on: bool) {
        SYNC_ON_READ.store(on, core::sync::atomic::Ordering::Relaxed);
    }

    /// The classic 32-bit parts whose PMU has the 7xx/74xx layout: MMCR0 at
    /// SPR 952 with 6-bit selectors for PMC1 (bits 6-11) and PMC2 (bits 0-5).
    /// Event 1 is processor cycles on every counter and event 2 instructions
    /// completed on PMC1-4 — the encoding FreeBSD's `hwpmc_mpc7xxx` uses for
    /// both the G3 and the G4.
    #[cfg(target_arch = "powerpc")]
    fn has_classic_pmu() -> bool {
        matches!(crate::arch::ppc::pvr() >> 16, 0x0008 | 0x7000 | 0x000C | 0x800C | 0x8000..=0x8004)
    }

    /// Whether this core has the Book3S v2.07+ PMU layout.
    fn has_power_pmu() -> bool {
        #[cfg(target_arch = "powerpc64")]
        {
            matches!(crate::arch::ppc::pvr() >> 16, 0x004B..=0x004E | 0x0080 | 0x0082)
        }
        #[cfg(not(target_arch = "powerpc64"))]
        {
            false
        }
    }

    pub(super) fn detect() -> CorePmu {
        #[cfg(target_arch = "powerpc")]
        if has_classic_pmu() {
            return CorePmu {
                leaf: PmuLeaf {
                    version: 1,
                    general_counters: 4,
                    general_width: 32,
                    // PMC1 (cycles) and PMC2 (instructions), programmed as a
                    // fixed pair.
                    fixed_counters: 2,
                    fixed_width: 32,
                    events_unavailable: 0,
                },
                core_type: CoreType::Uniform,
                route: CounterRoute::None,
                kind: PmuKind::Classic7xx,
                slots: [Default::default(); super::MAX_TRACKED_COUNTERS],
            };
        }
        let available = has_power_pmu();
        CorePmu {
            leaf: if available {
                PmuLeaf {
                    version: 1,
                    general_counters: 4,
                    general_width: 32,
                    fixed_counters: 2,
                    fixed_width: 32,
                    events_unavailable: 0,
                }
            } else {
                PmuLeaf::default()
            },
            // POWER parts are not hybrid; every thread has the same PMU.
            core_type: CoreType::Uniform,
            route: CounterRoute::None,
            kind: if available { PmuKind::PowerMmcr } else { PmuKind::Unknown },
            slots: [Default::default(); super::MAX_TRACKED_COUNTERS],
        }
    }

    /// Unfreezes PMC5/PMC6 in every privilege state.
    ///
    /// # Safety
    /// Supervisor or hypervisor state on a core `detect` accepted.
    pub(super) unsafe fn enable_fixed() {
        #[cfg(target_arch = "powerpc")]
        if has_classic_pmu() {
            // SAFETY: supervisor state on a 7xx/74xx: freeze (FC), zero both
            // counters, then select cycles on PMC1 and instructions completed
            // on PMC2 with every freeze bit clear.
            unsafe {
                core::arch::asm!(
                    "lis {t}, 0x8000",
                    "mtspr 952, {t}",
                    "li {t}, 0",
                    "mtspr 953, {t}",
                    "mtspr 954, {t}",
                    "isync",
                    "li {t}, (1 << 6) | 2",
                    "mtspr 952, {t}",
                    "isync",
                    t = out(reg) _,
                    options(nomem, nostack, preserves_flags),
                );
            }
            return;
        }
        #[cfg(target_arch = "powerpc64")]
        // SAFETY: forwarded from this function's contract. SPR numbers from
        // the Power ISA: MMCR0 795, MMCR1 798, MMCR2 785, MMCRA 786, PMC5
        // 775, PMC6 776, CTRL 152 (write) / 136 (read).
        unsafe {
            core::arch::asm!(
                // Freeze while reprogramming. `oris` rather than `lis`: `lis`
                // sign-extends and would set the reserved upper half too.
                "li {t}, 0",
                "oris {t}, {t}, 0x8000",
                "mtspr 795, {t}",
                "li {t}, 0",
                "mtspr 798, {t}",
                "mtspr 785, {t}",
                "mtspr 786, {t}",
                "mtspr 775, {t}",
                "mtspr 776, {t}",
                // The run latch.
                "li {t}, 1",
                "mtspr 152, {t}",
                "isync",
                // Every freeze bit clear.
                "li {t}, 0",
                "mtspr 795, {t}",
                "isync",
                t = out(reg) _,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    /// Reads PMC5 (instructions) or PMC6 (cycles).
    pub(super) fn read_fixed(pmu: &CorePmu, index: u32) -> Option<Reading> {
        #[cfg(target_arch = "powerpc")]
        if pmu.kind == PmuKind::Classic7xx {
            let value: u32;
            // SAFETY: `kind` is only `Classic7xx` on a core with these SPRs.
            unsafe {
                match index {
                    super::FIXED_CORE_CYCLES => core::arch::asm!("mfspr {v}, 953", v = out(reg) value,
                                                                 options(nomem, nostack, preserves_flags)),
                    super::FIXED_INSTRUCTIONS => core::arch::asm!("mfspr {v}, 954", v = out(reg) value,
                                                                  options(nomem, nostack, preserves_flags)),
                    _ => return None,
                }
            }
            return Some(Reading { value: value as u64, core_type: pmu.core_type });
        }
        if pmu.kind != PmuKind::PowerMmcr {
            return None;
        }
        #[cfg(target_arch = "powerpc64")]
        {
            let value: u64;
            // SAFETY: `kind` is only `PowerMmcr` on a core with these SPRs,
            // and reading them in supervisor state has no side effects.
            unsafe {
                if SYNC_ON_READ.load(core::sync::atomic::Ordering::Relaxed) {
                    core::arch::asm!("mfspr {t}, 795", "mtspr 795, {t}", "isync", t = out(reg) _,
                                     options(nomem, nostack, preserves_flags));
                }
                match index {
                    super::FIXED_INSTRUCTIONS => core::arch::asm!("mfspr {v}, 775", v = out(reg) value,
                                                                  options(nomem, nostack, preserves_flags)),
                    super::FIXED_CORE_CYCLES => core::arch::asm!("mfspr {v}, 776", v = out(reg) value,
                                                                 options(nomem, nostack, preserves_flags)),
                    _ => return None,
                }
            }
            Some(Reading {
                // The PMCs are 32 bits; the upper half of the SPR read is 0.
                value: value & 0xFFFF_FFFF,
                core_type: pmu.core_type,
            })
        }
        #[cfg(not(target_arch = "powerpc64"))]
        {
            let _ = index;
            None
        }
    }
}

/// RISC-V: `cycle` and `instret`.
///
/// Whether S-mode may read them is M-mode's decision (`mcounteren`), not
/// discoverable from S-mode except by trying — so `detect` tries, through the
/// trap-fixup probes in `arch::riscv`, and a counter that would trap is never
/// read again. Both are 64 bits (RV32 reads them as two halves). The
/// `hpmcounter`s would need the SBI PMU extension to program; not used.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
mod riscv {
    use super::{CorePmu, CoreType, CounterRoute, PmuKind, PmuLeaf, Reading};
    use core::sync::atomic::{AtomicBool, Ordering};

    static INSTRET: AtomicBool = AtomicBool::new(false);

    pub(super) fn detect() -> CorePmu {
        let cycle = crate::arch::riscv::cycle_readable();
        INSTRET.store(cycle && crate::arch::riscv::instret_readable(), Ordering::Relaxed);
        CorePmu {
            leaf: if cycle {
                PmuLeaf {
                    version: 1,
                    general_counters: 0,
                    general_width: 0,
                    fixed_counters: if INSTRET.load(Ordering::Relaxed) { 2 } else { 1 },
                    fixed_width: 64,
                    events_unavailable: 0,
                }
            } else {
                PmuLeaf::default()
            },
            core_type: CoreType::Uniform,
            route: CounterRoute::None,
            kind: if cycle { PmuKind::RiscvCounters } else { PmuKind::Unknown },
            slots: [Default::default(); super::MAX_TRACKED_COUNTERS],
        }
    }

    pub(super) fn read_fixed(pmu: &CorePmu, index: u32) -> Option<Reading> {
        if pmu.kind != PmuKind::RiscvCounters {
            return None;
        }
        // SAFETY: `detect` proved each read legal before `kind` was set.
        let value = unsafe {
            match index {
                super::FIXED_CORE_CYCLES => nanochrono_core::arch::riscv::rdcycle_raw(),
                super::FIXED_INSTRUCTIONS if INSTRET.load(Ordering::Relaxed) => {
                    nanochrono_core::arch::riscv::rdinstret_raw()
                }
                _ => return None,
            }
        };
        Some(Reading { value, core_type: pmu.core_type })
    }
}

// ---------------------------------------------------------------------------
// The neutral surface
// ---------------------------------------------------------------------------

/// Fixed counter indices, named so a caller does not pass a bare number.
#[cfg(x86_any)]
pub use x86::{FIXED_CORE_CYCLES, FIXED_INSTRUCTIONS, FIXED_REF_CYCLES};

// AArch64 has one fixed counter, the cycle counter. The other two indices
// exist so the API is the same shape on both architectures; reading them
// returns `None`.
/// Instructions retired. Not implemented as a fixed counter on AArch64.
#[cfg(target_arch = "aarch64")]
pub const FIXED_INSTRUCTIONS: u32 = 0;
/// The cycle counter, `PMCCNTR_EL0`.
#[cfg(target_arch = "aarch64")]
pub const FIXED_CORE_CYCLES: u32 = 1;
/// A reference-rate clock. Not implemented as a fixed counter on AArch64.
#[cfg(target_arch = "aarch64")]
pub const FIXED_REF_CYCLES: u32 = 2;

// RISC-V: `instret` and `cycle` are the fixed-function pair.
/// Instructions retired, `instret`.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "arm"))]
pub const FIXED_INSTRUCTIONS: u32 = 0;
/// Cycles, `cycle`.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "arm"))]
pub const FIXED_CORE_CYCLES: u32 = 1;
/// `time` is the reference clock; it is the counter, not a PMU register.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "arm"))]
pub const FIXED_REF_CYCLES: u32 = 2;

// POWER: PMC5 and PMC6 are the fixed-function pair.
/// Instructions completed, `PMC5`.
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
pub const FIXED_INSTRUCTIONS: u32 = 0;
/// Cycles, `PMC6`.
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
pub const FIXED_CORE_CYCLES: u32 = 1;
/// No reference-rate counter on POWER; the Time Base plays that role.
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
pub const FIXED_REF_CYCLES: u32 = 2;

impl CorePmu {
    /// Describes the PMU of the core this runs on.
    ///
    /// **Must be called on the core it will be used for.** On a hybrid part
    /// the answer differs between core types, and a configuration derived on
    /// one core is not valid on another.
    pub fn detect() -> CorePmu {
        #[cfg(x86_any)]
        {
            x86::detect()
        }
        #[cfg(target_arch = "aarch64")]
        {
            arm::detect()
        }
        #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
        {
            power::detect()
        }
        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        {
            riscv::detect()
        }
        // 32-bit ARM: the PMU (PMCCNTR through CP15) is not driven yet; the
        // interface reports it absent rather than guessing.
        #[cfg(target_arch = "arm")]
        {
            CorePmu {
                leaf: PmuLeaf::default(),
                core_type: CoreType::Uniform,
                route: CounterRoute::None,
                kind: PmuKind::Unknown,
                slots: [Default::default(); MAX_TRACKED_COUNTERS],
            }
        }
    }

    /// Records what a counter was programmed with.
    ///
    /// The per-core state the measurement depends on. A counter is shared
    /// hardware: something else — firmware, a hypervisor, a later call here —
    /// can reprogram it, and a read afterwards returns a number that looks
    /// entirely reasonable while answering a different question. This is the
    /// only record of what the number currently means.
    pub fn record(&mut self, index: usize, event: u64) {
        if let Some(slot) = self.slots.get_mut(index) {
            *slot = Slot { event, owned: true };
        }
    }

    /// What a counter is currently programmed with, if this programmed it.
    pub fn slot(&self, index: usize) -> Option<Slot> {
        self.slots.get(index).copied().filter(|slot| slot.owned)
    }

    /// Whether this core has a usable PMU.
    pub fn is_available(&self) -> bool {
        self.leaf.is_available()
    }

    /// Starts the counters on this core and confirms one of them counts.
    ///
    /// **This is the fix for "RDPMC does not work".** Programming the PMU can
    /// fail silently in several ways that report success: firmware may have
    /// left a counter frozen behind a latched overflow, a hypervisor may
    /// swallow the MSR writes, a general-purpose event may not exist on this
    /// core type. In every case `RDPMC` then returns a fixed value — usually
    /// zero — and a caller subtracting two of them gets a plausible-looking
    /// duration of nothing.
    ///
    /// So rather than trusting the enumeration, this runs a short known
    /// workload and checks the counter moved. If the fixed counters do not
    /// count it falls back to a general-purpose counter programmed with an
    /// *architectural* event, which is the only encoding that means the same
    /// thing on a P-core and an E-core. If neither counts it returns
    /// [`CounterRoute::None`] and nothing downstream reports a measurement.
    ///
    /// # Safety
    /// Requires ring 0 / EL1 and clobbers any existing PMU configuration.
    pub unsafe fn enable(&mut self) -> CounterRoute {
        #[cfg(x86_any)]
        {
            // Permit `RDPMC` outside ring 0. Not needed here — see the
            // function — but set before anything else so the state is
            // established rather than assumed.
            // SAFETY: forwarded from this function's own contract.
            unsafe { x86::enable_rdpmc_outside_ring0() };

            match self.kind {
                // AMD has no fixed counters: every one is programmable, so
                // there is no architectural route to try first.
                PmuKind::AmdCore | PmuKind::AmdLegacy => {
                    // SAFETY: as above; `enable_cycles` writes only the MSRs
                    // its own interface defines.
                    if let Some((index, event)) =
                        unsafe { x86::amd::enable_cycles(self.kind, self.leaf.general_counters) }
                    {
                        self.record(index as usize, event);
                        let route = CounterRoute::General(index);
                        // SAFETY: as above; reads only. The read goes through
                        // `RDMSR`, not `RDPMC` — see `read_route`.
                        if unsafe { self.counter_advances(route) } {
                            // The measurement route is settled; instructions
                            // ride a second counter when one exists. It is
                            // verified the same way the cycle counter was —
                            // a counter a virtualizer or firmware left frozen
                            // reports a fixed number, which is precisely what
                            // the report must not show — and only recorded
                            // when it moves. Failing here loses a line of the
                            // report, never the measurement.
                            // SAFETY: as above; same interface, counter 1.
                            if let Some((index, event)) = unsafe {
                                x86::amd::enable_instructions(
                                    self.kind,
                                    self.leaf.general_counters,
                                )
                            } {
                                // SAFETY: as above; reads only, via MSR.
                                if unsafe { self.counter_advances(CounterRoute::General(index)) } {
                                    self.record(index as usize, event);
                                }
                            }
                            self.route = route;
                            return route;
                        }
                    }
                    self.route = CounterRoute::None;
                    return self.route;
                }
                PmuKind::Unknown | PmuKind::ArmSystemRegister | PmuKind::PowerMmcr | PmuKind::RiscvCounters | PmuKind::Classic7xx => {
                    // Nothing is known about this part's counters, so nothing
                    // is written to them. A wrong MSR here is a triple fault,
                    // not a wrong number. (`ArmSystemRegister` cannot reach
                    // this match arm on x86-64, which is the architecture
                    // this block compiles for; it is listed so the match is
                    // total.)
                    self.route = CounterRoute::None;
                    return self.route;
                }
                PmuKind::IntelArchitectural => {}
            }

            // SAFETY: forwarded from this function's own contract.
            unsafe { x86::enable_fixed(self) };
            // SAFETY: as above; reads only.
            if unsafe { self.counter_advances(CounterRoute::Fixed) } {
                self.route = CounterRoute::Fixed;
                return self.route;
            }

            // SAFETY: as above.
            if let Some(index) = unsafe { x86::enable_general_cycles(self) } {
                let route = CounterRoute::General(index);
                // SAFETY: as above.
                if unsafe { self.counter_advances(route) } {
                    self.route = route;
                    return route;
                }
            }
            self.route = CounterRoute::None;
            self.route
        }
        #[cfg(target_arch = "aarch64")]
        {
            // No architected PMU: its registers are UNDEFINED, so nothing is
            // written. `detect` reported version 0 for exactly this case.
            if !self.is_available() {
                self.route = CounterRoute::None;
                return self.route;
            }
            // SAFETY: forwarded from this function's own contract.
            unsafe { arm::enable_fixed(self) };
            // SAFETY: as above; reads only.
            self.route = if unsafe { self.counter_advances(CounterRoute::Fixed) } {
                CounterRoute::Fixed
            } else {
                CounterRoute::None
            };
            self.route
        }
        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "arm"))]
        {
            // Nothing to program: the counters free-run unless M-mode
            // inhibited them (`mcountinhibit`), which `counter_advances`
            // detects rather than assumes.
            self.route = if self.is_available()
                // SAFETY: forwarded from this function's own contract.
                && unsafe { self.counter_advances(CounterRoute::Fixed) }
            {
                CounterRoute::Fixed
            } else {
                CounterRoute::None
            };
            self.route
        }
        #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
        {
            if !self.is_available() {
                self.route = CounterRoute::None;
                return self.route;
            }
            // SAFETY: forwarded from this function's own contract.
            unsafe { power::enable_fixed() };
            // SAFETY: as above; reads only.
            let mut advances = unsafe { self.counter_advances(CounterRoute::Fixed) };
            if !advances {
                // An emulator that updates PMC6 only on MMCR0 writes: ask for
                // a resynchronisation before each read, and check again.
                power::set_sync_on_read(true);
                // SAFETY: as above.
                advances = unsafe { self.counter_advances(CounterRoute::Fixed) };
                if !advances {
                    power::set_sync_on_read(false);
                }
            }
            self.route = if advances { CounterRoute::Fixed } else { CounterRoute::None };
            self.route
        }
    }

    /// Whether a counter actually moves over a short known workload.
    ///
    /// The workload is a dependent chain the optimiser cannot remove, long
    /// enough that even a coarse counter has to tick and short enough to cost
    /// nothing at boot.
    ///
    /// # Safety
    /// Requires ring 0 / EL1.
    unsafe fn counter_advances(&self, route: CounterRoute) -> bool {
        // SAFETY: forwarded from this function's own contract.
        let Some(before) = (unsafe { self.read_route(route) }) else {
            return false;
        };
        arch::serialize();
        let mut acc = 0x9E37_79B9_7F4A_7C15u64;
        for i in 0..4096u64 {
            acc = acc.wrapping_add(i).rotate_left(7);
        }
        core::hint::black_box(acc);
        arch::serialize();
        // SAFETY: as above.
        let Some(after) = (unsafe { self.read_route(route) }) else {
            return false;
        };
        after.value != before.value
    }

    /// Reads one fixed counter by index.
    ///
    /// # Safety
    /// Requires ring 0 / EL1, or user access explicitly enabled.
    pub unsafe fn read(&self, index: u32) -> Option<Reading> {
        #[cfg(x86_any)]
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            x86::read_fixed(self, index)
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            arm::read_fixed(self, index)
        }
        #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
        {
            power::read_fixed(self, index)
        }
        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        {
            riscv::read_fixed(self, index)
        }
        #[cfg(target_arch = "arm")]
        {
            let _ = index;
            None
        }
    }

    /// Reads whichever counter [`enable`](Self::enable) settled on.
    ///
    /// # Safety
    /// Requires ring 0 / EL1.
    pub unsafe fn read_cycles(&self) -> Option<Reading> {
        // SAFETY: forwarded from this function's own contract.
        unsafe { self.read_route(self.route) }
    }

    /// Reads the instructions-retired count, from whatever counted it.
    ///
    /// On Intel this is fixed counter 0, so it is only present on the
    /// `Fixed` route. On AMD, where every counter is programmable, it is the
    /// general-purpose counter [`enable`](Self::enable) programmed with
    /// `Retired Instructions` (`0xC0`) when a second one existed — and it is
    /// [recorded](Self::record), so a counter that another writer reprogrammed
    /// is refused here rather than misread. `None` means there is no
    /// instructions counter to read, which is a fact about the machine, not
    /// an error.
    ///
    /// # Safety
    /// Requires ring 0 / EL1.
    pub unsafe fn read_instructions(&self) -> Option<Reading> {
        #[cfg(x86_any)]
        {
            match self.kind {
                // SAFETY: as above; `read` checks the counter exists.
                PmuKind::AmdCore | PmuKind::AmdLegacy => {
                    // The pairing is fixed by `enable`: cycles on counter 0,
                    // instructions on counter 1. A slot that is not `owned`
                    // means the programming never happened (or happened and
                    // lost the MSRs to someone else), and the number it would
                    // return is not this measurement's — so refuse.
                    if self.slots[1].owned {
                        // SAFETY: forwarded from this function's own contract.
                        unsafe { x86::amd::read(self.kind, 1) }.map(|value| Reading {
                            value,
                            core_type: self.core_type,
                        })
                    } else {
                        None
                    }
                }
                _ => {
                    // SAFETY: as above.
                    unsafe { self.read(FIXED_INSTRUCTIONS) }
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            // AArch64's one fixed counter counts cycles; instructions come
            // from event counter 0, programmed with INST_RETIRED when the core
            // implements it (32 bits wide).
            if self.route == CounterRoute::Fixed {
                arm::read_instructions(self)
            } else {
                None
            }
        }
        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "arm"))]
        {
            if self.route == CounterRoute::Fixed {
                // SAFETY: forwarded from this function's own contract.
                unsafe { self.read(FIXED_INSTRUCTIONS) }
            } else {
                None
            }
        }
        #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
        {
            // PMC5 is fixed-function instructions completed, so it is
            // available whenever the fixed route is.
            if self.route == CounterRoute::Fixed {
                // SAFETY: forwarded from this function's own contract.
                unsafe { self.read(FIXED_INSTRUCTIONS) }
            } else {
                None
            }
        }
    }

    /// # Safety
    /// Requires ring 0 / EL1.
    unsafe fn read_route(&self, route: CounterRoute) -> Option<Reading> {
        match route {
            CounterRoute::None => None,
            // SAFETY: forwarded from this function's own contract.
            CounterRoute::Fixed => unsafe { self.read(FIXED_CORE_CYCLES) },
            // The read instruction depends on the interface, and the choice
            // is not an optimisation.
            //
            // `RDPMC` takes a counter index and is one instruction; `RDMSR`
            // takes an address and is slower. But `RDPMC` is *optional* in a
            // way that is invisible until it faults: QEMU's TCG raises `#UD`
            // for it unconditionally, and a hypervisor may decline it too.
            // On Intel that never surfaced because a machine without a real
            // PMU reports `CPUID.0AH` version 0 and never reaches a read. On
            // AMD the counters are enumerated from a feature bit that TCG
            // *does* advertise, so the first read was an invalid opcode and,
            // with no interrupt descriptor table, a reset.
            //
            // So AMD reads through the MSR it just wrote — which is
            // necessarily implemented wherever the write was — and Intel
            // keeps `RDPMC`, where the enumeration already proves a real PMU.
            #[cfg(x86_any)]
            CounterRoute::General(i) => match self.kind {
                // SAFETY: as above.
                PmuKind::AmdCore | PmuKind::AmdLegacy => unsafe {
                    x86::amd::read(self.kind, i).map(|value| Reading {
                        value,
                        core_type: self.core_type,
                    })
                },
                // SAFETY: as above.
                _ => unsafe { x86::read_general(self, i) },
            },
            #[cfg(not(x86_any))]
            CounterRoute::General(_) => None,
        }
    }

    /// Cycles elapsed while running `body`, from the PMU rather than the
    /// timestamp counter.
    ///
    /// `None` if the PMU is unavailable, or if the reading before and after
    /// came from different core types — which on a hybrid part means the
    /// measurement was migrated and is not a duration at all. Nothing here
    /// can prevent that migration; it can only refuse to report the result.
    ///
    /// # Safety
    /// Requires ring 0 / EL1.
    pub unsafe fn measure<T>(&self, body: impl FnOnce() -> T) -> (T, Option<u64>) {
        // SAFETY: forwarded from this function's own contract.
        let before = unsafe { self.read_cycles() };
        arch::serialize();
        let out = body();
        arch::serialize();
        // SAFETY: as above.
        let after = unsafe { self.read_cycles() };

        // The route decides the counter's width; see `delta_since_width`.
        let width = match self.route {
            CounterRoute::Fixed => self.leaf.fixed_width,
            CounterRoute::General(_) => self.leaf.general_width,
            CounterRoute::None => 64,
        };
        let delta = match (before, after) {
            (Some(a), Some(b)) => b.delta_since_width(a, width),
            _ => None,
        };
        (out, delta)
    }
}
