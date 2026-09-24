// SPDX-License-Identifier: Apache-2.0
//! Decoding the CPU's own description of its performance counters.
//!
//! Pure functions over the raw `CPUID` registers, with no privileged
//! instruction anywhere. They live here rather than beside the `RDPMC` that
//! uses them for two reasons:
//!
//! * A freestanding kernel is `no_std` with no test harness, and this is
//!   exactly the logic that has to be tested — the counter layouts differ
//!   between the two core types of a hybrid part, and **one thread can only
//!   ever observe one of them**. Driving both requires supplying the register
//!   values, which is only possible from a hosted test.
//! * The hybrid distinction is not bare-metal-specific. A hosted build meets
//!   it too, as `cpu_core` and `cpu_atom` in [`crate::perf`].
//!
//! # What actually goes wrong on a hybrid part
//!
//! Not, in general, the counter layout. On a Raptor Lake i9-14900HX both core
//! types report `CPUID.0AH` identically — version 5, six general counters of
//! 48 bits, three fixed of 48 — so code that only checks the layout sees
//! nothing wrong and proceeds to produce garbage. Two things break instead:
//!
//! * **The counters are per-logical-processor MSR state.** Programming them
//!   on one core and reading on another returns whatever that core had, which
//!   is usually zero. There is no fault and no flag; the number is simply not
//!   a measurement.
//! * **General-purpose event encodings are per core type.** A P-core is a
//!   Raptor Cove and an E-core is a Gracemont: the same event-select byte
//!   names different events, or none. Only the *fixed* counters are
//!   architectural and mean the same thing on both.
//!
//! So the layout is not the guard. [`CoreType`] travelling with every reading
//! is, and so is checking that a counter actually advanced before believing
//! it — see `CorePmu::enable` in `nanochrono-baremetal`.

/// Which kind of core a measurement came from.
///
/// From `CPUID.1AH:EAX[31:24]`, the Native Model ID enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreType {
    /// Not a hybrid part: every core is the same.
    Uniform,
    /// Intel Core, the performance core. `CPUID.1AH` reports `0x40`.
    Performance,
    /// Intel Atom, the efficiency core. `CPUID.1AH` reports `0x20`.
    Efficiency,
    /// A hybrid part reporting a type this code does not know, or a
    /// non-x86 core identified some other way.
    Unknown(u8),
}

impl CoreType {
    pub const fn name(self) -> &'static str {
        match self {
            CoreType::Uniform => "uniform",
            CoreType::Performance => "p-core",
            CoreType::Efficiency => "e-core",
            CoreType::Unknown(_) => "unknown",
        }
    }

    /// Whether two measurements may be compared.
    ///
    /// A P-core and an E-core are different microarchitectures that happen to
    /// share an instruction set: the same work takes a different number of
    /// cycles on each, by design. Aggregating across them produces a number
    /// with no meaning, so the question is asked explicitly rather than left
    /// to be forgotten.
    pub const fn comparable_with(self, other: CoreType) -> bool {
        // Derived equality would do, but writing it out keeps the rule
        // visible: same type or nothing.
        matches!(
            (self, other),
            (CoreType::Uniform, CoreType::Uniform)
                | (CoreType::Performance, CoreType::Performance)
                | (CoreType::Efficiency, CoreType::Efficiency)
        ) || matches!((self, other), (CoreType::Unknown(a), CoreType::Unknown(b)) if a == b)
    }
}

/// What one core's performance-monitoring unit offers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PmuLeaf {
    /// `CPUID.0AH:EAX[7:0]`. Zero means no architectural PMU.
    pub version: u8,
    /// General-purpose counters on this core.
    pub general_counters: u8,
    /// Their width in bits — above it, an `RDPMC` result is sign extension.
    pub general_width: u8,
    /// Fixed-function counters on this core.
    pub fixed_counters: u8,
    /// Their width in bits.
    pub fixed_width: u8,
    /// `CPUID.0AH:EBX[6:0]`: a set bit means that architectural event is
    /// **not** available here.
    ///
    /// The one field of this leaf that genuinely can differ between the two
    /// core types of a hybrid part, so it is carried rather than assumed
    /// empty. It is also the only portable way to ask "can this core count
    /// cycles with a general-purpose counter", since every model-specific
    /// event encoding means something different on each core type.
    pub events_unavailable: u32,
}

impl PmuLeaf {
    /// Whether this core has any usable counter.
    pub const fn is_available(&self) -> bool {
        self.fixed_counters > 0 || self.general_counters > 0
    }
}

/// A counter reading, tagged with the core type it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub value: u64,
    pub core_type: CoreType,
}

impl Reading {
    /// The difference between two readings from the same core type.
    ///
    /// `None` when the types differ: subtracting an E-core count from a
    /// P-core count is not a smaller number, it is a wrong one.
    pub const fn delta_since(self, earlier: Reading) -> Option<u64> {
        if self.core_type.comparable_with(earlier.core_type) {
            Some(self.value.wrapping_sub(earlier.value))
        } else {
            None
        }
    }

    /// [`delta_since`](Self::delta_since) for a counter `width` bits wide.
    ///
    /// A 48-bit counter that wraps between the two reads gives an `after`
    /// smaller than `before`, and a 64-bit subtraction turns that into a
    /// number near 2⁶⁴ — a measurement of eighteen quintillion cycles
    /// instead of a few thousand. Reducing the difference modulo 2^width is
    /// the correct answer for any interval shorter than one full wrap.
    pub const fn delta_since_width(self, earlier: Reading, width: u8) -> Option<u64> {
        match self.delta_since(earlier) {
            Some(delta) => Some(mask_to_width(delta, width)),
            None => None,
        }
    }
}

/// Classifies a core from the `CPUID` values that describe it.
///
/// The hybrid flag is `CPUID.07H.0:EDX[15]`. Without it the part is uniform
/// and leaf `0x1A` need not exist.
pub const fn classify_core(max_leaf: u32, leaf7_edx: u32, leaf1a_eax: u32) -> CoreType {
    // Leaf 7 is only valid if the maximum basic leaf reaches it.
    if max_leaf < 7 || leaf7_edx & (1 << 15) == 0 {
        return CoreType::Uniform;
    }
    if max_leaf < 0x1A {
        // Hybrid, but the enumeration leaf is missing: the type cannot be
        // established, and claiming uniformity would license comparing counts
        // across core types.
        return CoreType::Unknown(0);
    }
    match (leaf1a_eax >> 24) as u8 {
        0x40 => CoreType::Performance,
        0x20 => CoreType::Efficiency,
        other => CoreType::Unknown(other),
    }
}

/// Decodes `CPUID.0AH`, the architectural performance monitoring leaf.
pub const fn decode_pmu_leaf(eax: u32, ebx: u32, edx: u32) -> PmuLeaf {
    let version = (eax & 0xFF) as u8;
    PmuLeaf {
        version,
        general_counters: ((eax >> 8) & 0xFF) as u8,
        general_width: ((eax >> 16) & 0xFF) as u8,
        // The fixed-counter fields are only defined from version 2. Reading
        // them at version 1 would report counters that are not there, and
        // `RDPMC` on one of those faults.
        fixed_counters: if version >= 2 { (edx & 0x1F) as u8 } else { 0 },
        fixed_width: if version >= 2 {
            ((edx >> 5) & 0xFF) as u8
        } else {
            0
        },
        // EBX only describes as many events as EAX[31:24] says it
        // enumerates; beyond that the bits are reserved and must be treated
        // as available rather than as "unavailable" — the sense is inverted,
        // so a reserved 1 would silently disable a working counter.
        events_unavailable: {
            let enumerated = (eax >> 24) & 0xFF;
            if enumerated == 0 {
                0
            } else if enumerated >= 31 {
                ebx
            } else {
                ebx & ((1u32 << enumerated) - 1)
            }
        },
    }
}

impl PmuLeaf {
    /// Whether architectural event `index` can be counted on this core.
    ///
    /// Index 1 is `CPU_CLK_UNHALTED.THREAD`, the only one this toolkit uses
    /// from a general-purpose counter.
    pub const fn architectural_event_available(&self, index: u32) -> bool {
        self.events_unavailable & (1 << index) == 0
    }
}

/// Keeps the low `width` bits of a counter reading.
///
/// `RDPMC` returns `EDX:EAX` with the counter sign-extended above its real
/// width, so the upper bits are not part of the count. Keeping them turns a
/// small count into an enormous one.
pub const fn mask_to_width(raw: u64, width: u8) -> u64 {
    if width == 0 || width >= 64 {
        raw
    } else {
        raw & ((1u64 << width) - 1)
    }
}

/// Assembles an AMD core-counter event select value from an event number and
/// a unit mask.
///
/// AMD's `PerfEvtSel` register splits the event number across two fields:
/// bits 7:0 hold the low byte and bits 35:32 hold the extension — an event
/// like `0x1C0` (retired instructions on Family 15h) is encoded as `0x100`
/// shifted into bit 32, not as a byte that overflows. The unit mask sits in
/// bits 15:8. This is the `AMD_PMC_TO_EVENTMASK`/`AMD_PMC_TO_UNITMASK`
/// encoding from FreeBSD's `hwpmc_amd.h` (BSD-2-Clause; see `NOTICE`), and
/// the split fields are spelled out in AMD's BKDG, publication 32559.
///
/// The caller still ORs in the control bits (`USR`, `OS`, `EN`) — this only
/// builds the event-qualification half, so the result is safe to reuse when
/// reprogramming a counter with a different event.
#[inline]
pub const fn amd_event_select(event: u16, unit_mask: u8) -> u64 {
    (event as u64 & 0xFF)
        | ((event as u64 & 0xF00) << 24)
        | ((unit_mask as u64) << 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CPUID.0AH` on a modern P-core: version 5, 8 general counters of 48
    /// bits, 4 fixed counters of 48 bits.
    const P_CORE_EAX: u32 = 0x0000_0805 | (48 << 16);
    const P_CORE_EDX: u32 = 4 | (48 << 5);

    /// The same leaf on an E-core of the same package: fewer general
    /// counters. This is the value that makes a configuration derived on one
    /// core wrong on the other, and it is why detection has to run per core.
    const E_CORE_EAX: u32 = 0x0000_0605 | (40 << 16);
    const E_CORE_EDX: u32 = 3 | (40 << 5);

    const HYBRID: u32 = 1 << 15;

    #[test]
    fn a_non_hybrid_part_reports_uniform() {
        // Leaf 7 present, hybrid bit clear.
        assert_eq!(classify_core(0x20, 0, 0), CoreType::Uniform);
        // Leaf 7 not even reachable.
        assert_eq!(classify_core(1, 0xFFFF_FFFF, 0), CoreType::Uniform);
    }

    #[test]
    fn the_two_core_types_are_told_apart() {
        assert_eq!(
            classify_core(0x20, HYBRID, 0x40 << 24),
            CoreType::Performance
        );
        assert_eq!(
            classify_core(0x20, HYBRID, 0x20 << 24),
            CoreType::Efficiency
        );
        // A type this code does not know is carried, not guessed at.
        assert_eq!(
            classify_core(0x20, HYBRID, 0x77 << 24),
            CoreType::Unknown(0x77)
        );
    }

    /// A hybrid part whose enumeration leaf is missing must not be reported
    /// as uniform: that would license comparing counts across core types.
    #[test]
    fn hybrid_without_the_enumeration_leaf_is_not_uniform() {
        let t = classify_core(0x15, HYBRID, 0);
        assert_ne!(t, CoreType::Uniform);
        assert!(!t.comparable_with(CoreType::Uniform));
    }

    #[test]
    fn the_performance_leaf_decodes() {
        let p = decode_pmu_leaf(P_CORE_EAX, 0, P_CORE_EDX);
        assert_eq!(p.version, 5);
        assert_eq!(p.general_counters, 8);
        assert_eq!(p.general_width, 48);
        assert_eq!(p.fixed_counters, 4);
        assert_eq!(p.fixed_width, 48);
        assert!(p.is_available());
    }

    /// Some hybrid parts do report different layouts per core type, and the
    /// decoder has to carry that faithfully rather than assume one answer.
    #[test]
    fn a_differing_layout_is_decoded_faithfully() {
        let p = decode_pmu_leaf(P_CORE_EAX, 0, P_CORE_EDX);
        let e = decode_pmu_leaf(E_CORE_EAX, 0, E_CORE_EDX);
        assert_ne!(p.general_counters, e.general_counters);
        assert_ne!(p.fixed_counters, e.fixed_counters);
        assert_ne!(p.general_width, e.general_width);
    }

    /// And some do not. A Raptor Lake i9-14900HX reports `CPUID.0AH`
    /// identically on both core types — measured on one, not assumed.
    ///
    /// This is why an equal layout must never be read as "not hybrid": the
    /// hazard is that the counters are per-core state and that general-purpose
    /// event encodings differ, neither of which the layout reveals.
    #[test]
    fn an_identical_layout_does_not_mean_uniform() {
        // CPUID.0AH as both core types of an i9-14900HX report it.
        const RAPTOR_EAX: u32 = 0x0730_0605;
        const RAPTOR_EDX: u32 = 0x0000_8603;

        let p = decode_pmu_leaf(RAPTOR_EAX, 0, RAPTOR_EDX);
        let e = decode_pmu_leaf(RAPTOR_EAX, 0, RAPTOR_EDX);
        assert_eq!(p, e, "this part reports the same layout on both");
        assert_eq!(p.version, 5);
        assert_eq!(p.general_counters, 6);
        assert_eq!(p.general_width, 48);
        assert_eq!(p.fixed_counters, 3);
        assert_eq!(p.fixed_width, 48);

        // Identical layouts, and still not comparable: the core type is what
        // decides, and it is carried separately for exactly this reason.
        let on_p = Reading {
            value: 1_000,
            core_type: CoreType::Performance,
        };
        let on_e = Reading {
            value: 4_000,
            core_type: CoreType::Efficiency,
        };
        assert_eq!(on_e.delta_since(on_p), None);
    }

    /// Before version 2 the fixed-counter fields are not defined. Reading
    /// them anyway would claim counters that are not there, and `RDPMC` on
    /// one of those faults.
    #[test]
    fn version_one_reports_no_fixed_counters() {
        let v1 = decode_pmu_leaf(0x0000_0401 | (40 << 16), 0, 0xFFFF_FFFF);
        assert_eq!(v1.version, 1);
        assert_eq!(v1.fixed_counters, 0);
        assert_eq!(v1.fixed_width, 0);
        // General counters still exist at version 1.
        assert_eq!(v1.general_counters, 4);
    }

    #[test]
    fn no_pmu_is_reported_as_unavailable() {
        let none = decode_pmu_leaf(0, 0, 0);
        assert_eq!(none.version, 0);
        assert!(!none.is_available());
    }

    #[test]
    fn readings_are_masked_to_the_counter_width() {
        // A 48-bit counter holding 1000, sign-extended by the CPU.
        let sign_extended = 0xFFFF_0000_0000_03E8u64;
        assert_eq!(mask_to_width(sign_extended, 48), 1000);

        // Across a wrap, the width-aware delta is the short way round.
        let before = Reading { value: (1u64 << 48) - 10, core_type: CoreType::Uniform };
        let after = Reading { value: 5, core_type: CoreType::Uniform };
        assert_eq!(after.delta_since_width(before, 48), Some(15));
        let before32 = Reading { value: 0xFFFF_FFF0, core_type: CoreType::Uniform };
        let after32 = Reading { value: 0x10, core_type: CoreType::Uniform };
        assert_eq!(after32.delta_since_width(before32, 32), Some(0x20));

        // A width of zero or 64 means no masking is possible or needed.
        assert_eq!(mask_to_width(sign_extended, 64), sign_extended);
        assert_eq!(mask_to_width(sign_extended, 0), sign_extended);

        // The boundary: a 48-bit counter at its maximum.
        assert_eq!(mask_to_width(u64::MAX, 48), (1u64 << 48) - 1);
    }

    /// Subtracting an E-core count from a P-core count does not give a
    /// smaller number, it gives a wrong one. The types must refuse.
    #[test]
    fn readings_from_different_core_types_do_not_subtract() {
        let p = Reading {
            value: 5_000,
            core_type: CoreType::Performance,
        };
        let e = Reading {
            value: 1_000,
            core_type: CoreType::Efficiency,
        };
        assert_eq!(p.delta_since(e), None);
        assert_eq!(e.delta_since(p), None);

        let p2 = Reading {
            value: 9_000,
            core_type: CoreType::Performance,
        };
        assert_eq!(p2.delta_since(p), Some(4_000));
    }

    /// Two unknown core types are only comparable if they are the *same*
    /// unknown — on AArch64 that is what separates one cluster from another.
    #[test]
    fn unknown_core_types_compare_by_identity() {
        let a = Reading {
            value: 100,
            core_type: CoreType::Unknown(0xD4),
        };
        let b = Reading {
            value: 300,
            core_type: CoreType::Unknown(0xD4),
        };
        let other_cluster = Reading {
            value: 300,
            core_type: CoreType::Unknown(0xD0),
        };
        assert_eq!(b.delta_since(a), Some(200));
        assert_eq!(other_cluster.delta_since(a), None);
    }

    /// A counter that wrapped still yields the right delta.
    #[test]
    fn a_wrapped_counter_still_subtracts() {
        let before = Reading {
            value: u64::MAX - 10,
            core_type: CoreType::Uniform,
        };
        let after = Reading {
            value: 9,
            core_type: CoreType::Uniform,
        };
        assert_eq!(after.delta_since(before), Some(20));
    }

    /// An AMD event number below `0x100` lives entirely in bits 7:0.
    #[test]
    fn amd_events_under_256_live_in_the_low_byte() {
        // `CPU Clocks not Halted`, 76h, no unit mask.
        assert_eq!(amd_event_select(0x76, 0), 0x76);
        // `Retired Instructions`, C0h.
        assert_eq!(amd_event_select(0xC0, 0), 0xC0);
        // A unit mask lands in bits 15:8.
        assert_eq!(amd_event_select(0xCB, 0x0F), 0x0FCB);
    }

    /// An event number with bits above 7:0 moves them to bits 35:32, per
    /// FreeBSD's `AMD_PMC_TO_EVENTMASK`. Family 15h's EX/LS events start at
    /// `0x1C0`.
    #[test]
    fn amd_events_above_255_put_their_extension_in_bits_35_32() {
        // 0x1C0 & 0xFF = 0xC0; 0x1C0 & 0xF00 = 0x100, shifted to bit 32.
        assert_eq!(amd_event_select(0x1C0, 0), 0x1_0000_00C0);
        // The highest event the register encodes, 0xFFF, sets bits 32-35.
        assert_eq!(
            amd_event_select(0xFFF, 0xFF),
            0xF_0000_00FF | 0xFF00
        );
        // The low byte and the extension are independent.
        assert_eq!(amd_event_select(0xC1, 0), 0xC1);
        assert_eq!(amd_event_select(0x1D8, 0), 0x1_0000_00D8);
    }
}
