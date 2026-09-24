// SPDX-License-Identifier: Apache-2.0
//! Architecture-specific counter and probe primitives.
//!
//! Exactly one of the submodules below is compiled per target. Everything the
//! old `asm/` tree provided is expressed as `core::arch::asm!` inside them —
//! there are no `.S`/`.asm` files and no assembler in the build graph.
//!
//! Callers should prefer the neutral re-exports at the bottom of this module
//! ([`counter_raw`], [`counter_ordered`], [`read_overhead`], …) so that code
//! outside `arch` never needs a `cfg`.

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub mod x86;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
pub mod powerpc;

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub mod riscv;

#[cfg(target_arch = "arm")]
pub mod arm32;

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv32",
    target_arch = "riscv64",
    target_arch = "arm"
)))]
pub mod generic;

/// The counter family a target actually exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// x86, 32- or 64-bit: `RDTSC`/`RDTSCP`, raw units are core cycles.
    X86,
    /// AArch64: `CNTVCT_EL0`, raw units are architectural counter ticks.
    Aarch64,
    /// PowerPC, 32- or 64-bit, either byte order: the Time Base, raw units
    /// are Time Base ticks.
    PowerPc,
    /// RISC-V, RV32 or RV64: the `time` CSR, raw units are timebase ticks.
    RiscV,
    /// 32-bit ARM: the generic timer's `CNTVCT` where user space may read
    /// it, else the monotonic clock in nanoseconds.
    Arm32,
    /// No architectural counter; raw units are nanoseconds from the OS clock.
    Portable,
}

impl Arch {
    pub const fn name(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::Aarch64 => "arm64",
            Arch::PowerPc => {
                if cfg!(target_arch = "powerpc64") {
                    if cfg!(target_endian = "little") {
                        "ppc64le"
                    } else {
                        "ppc64"
                    }
                } else {
                    "ppc"
                }
            }
            Arch::Arm32 => "arm",
            Arch::RiscV => {
                if cfg!(target_arch = "riscv64") {
                    "riscv64"
                } else {
                    "riscv32"
                }
            }
            Arch::Portable => "portable",
        }
    }
}

/// The counter family this binary was built for.
pub const ARCH: Arch = {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        Arch::X86
    }
    #[cfg(target_arch = "aarch64")]
    {
        Arch::Aarch64
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        Arch::PowerPc
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        Arch::RiscV
    }
    #[cfg(target_arch = "arm")]
    {
        Arch::Arm32
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )))]
    {
        Arch::Portable
    }
};

/// Cheapest counter read, with no ordering guarantee.
#[inline(always)]
pub fn counter_raw() -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        x86::rdtsc_raw()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::counter_raw()
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        powerpc::timebase_raw()
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        riscv::rdtime_raw()
    }
    #[cfg(target_arch = "arm")]
    {
        arm32::counter_raw()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )))]
    {
        generic::counter_ns()
    }
}

/// Ordered counter read for the *start* of an interval.
#[inline(always)]
pub fn counter_start() -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        x86::rdtsc_lfence()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::counter_isb()
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        powerpc::timebase_start()
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        riscv::rdtime_start()
    }
    #[cfg(target_arch = "arm")]
    {
        arm32::counter_isb()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )))]
    {
        generic::counter_ns()
    }
}

/// Ordered counter read for the *end* of an interval.
///
/// On x86-64 this is `RDTSCP`, which additionally waits for older instructions
/// to retire — the asymmetry with [`counter_start`] is deliberate.
#[inline(always)]
pub fn counter_end() -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        // Not `rdtscp_lfence` directly: `RDTSCP` is `#UD` on anything older
        // than Nehalem or Barcelona, and this function is on the timing path
        // of every measurement the toolkit takes. See `x86::has_rdtscp`.
        x86::tsc_end_portable()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::counter_isb()
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        powerpc::timebase_end()
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        riscv::rdtime_end()
    }
    #[cfg(target_arch = "arm")]
    {
        arm32::counter_isb()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )))]
    {
        generic::counter_ns()
    }
}

/// Alias for [`counter_end`], kept for call sites that read as "now".
#[inline(always)]
pub fn counter_ordered() -> u64 {
    counter_end()
}

/// The core/socket id the last counter read came from, when the architecture
/// exposes one. Used to detect thread migration mid-measurement.
#[inline]
pub fn counter_aux() -> Option<u32> {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        // `None` where the part has no `RDTSCP`, rather than a zero that
        // would read as "core 0" and make migration look impossible.
        x86::tsc_aux_checked()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        None
    }
}

/// Cost of a back-to-back counter read pair, in raw units.
#[inline]
pub fn read_overhead() -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        x86::read_overhead_cycles()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::read_overhead_ticks()
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        powerpc::read_overhead_ticks()
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        riscv::read_overhead_ticks()
    }
    #[cfg(target_arch = "arm")]
    {
        arm32::read_overhead()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )))]
    {
        generic::read_overhead_ns()
    }
}

/// Cost of `iterations` back-to-back memory barriers, in raw units.
#[inline]
pub fn barrier_overhead(iterations: u32) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        x86::probe_barrier_cycles(iterations)
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::probe_barrier_ticks(iterations)
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        powerpc::probe_barrier_ticks(iterations)
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        riscv::probe_barrier_ticks(iterations)
    }
    #[cfg(target_arch = "arm")]
    {
        arm32::probe_barrier(iterations)
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )))]
    {
        generic::barrier_overhead_ns(iterations)
    }
}

/// Spin hint for calibration loops: `PAUSE` on x86, `YIELD` on ARM.
#[inline(always)]
pub fn cpu_relax() {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        x86::pause()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::yield_hint()
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        powerpc::yield_hint()
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        riscv::pause()
    }
    #[cfg(target_arch = "arm")]
    {
        core::hint::spin_loop()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )))]
    {
        core::hint::spin_loop()
    }
}

/// Full memory barrier.
#[inline(always)]
pub fn memory_barrier() {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        x86::mfence()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::dmb_sy()
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        powerpc::sync()
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        riscv::fence()
    }
    #[cfg(target_arch = "arm")]
    {
        arm32::dmb()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )))]
    {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Virtual or physical counter
// ---------------------------------------------------------------------------

/// Which of the architecture's fixed-rate counters the reads use.
///
/// Only AArch64 offers the choice: `CNTVCT_EL0` (virtual, the default) or
/// `CNTPCT_EL0` (physical). x86 has one TSC; RISC-V's `time` and PowerPC's
/// Time Base each have a single user-visible form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterSource {
    Virtual,
    Physical,
}

impl CounterSource {
    /// The register's name on this architecture.
    pub const fn name(self) -> &'static str {
        match self {
            CounterSource::Virtual if cfg!(target_arch = "aarch64") => "cntvct_el0",
            CounterSource::Physical if cfg!(target_arch = "aarch64") => "cntpct_el0",
            CounterSource::Virtual => "architectural counter",
            CounterSource::Physical => "physical counter (unavailable)",
        }
    }
}

/// Why the physical counter could not be selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterSourceError {
    /// This architecture has no separate physical counter.
    NoPhysicalCounter,
    /// The OS does not let this process read it (the read would fault).
    NotPermitted,
}

impl core::fmt::Display for CounterSourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CounterSourceError::NoPhysicalCounter => {
                "this architecture has no separate physical counter (only AArch64 does)"
            }
            CounterSourceError::NotPermitted => {
                "the operating system does not let this process read CNTPCT_EL0"
            }
        })
    }
}

/// The warning every interface shows next to the setting.
pub const PHYSICAL_COUNTER_WARNING: &str = "The physical counter (CNTPCT_EL0) is for timing \
on real hardware. Inside a virtual machine the hypervisor may trap every read, and under \
nested virtualization that trap passes through two hypervisors: slow and unstable. Use it \
on bare metal, not in VMs.";

/// Whether this architecture has a physical counter to choose.
pub const fn has_physical_counter() -> bool {
    cfg!(target_arch = "aarch64")
}

/// The counter the reads currently use.
pub fn counter_source() -> CounterSource {
    #[cfg(target_arch = "aarch64")]
    if aarch64::physical_selected() {
        return CounterSource::Physical;
    }
    CounterSource::Virtual
}

/// Selects the counter every architectural read uses.
///
/// Selecting the physical one first checks that this process may read it
/// (see [`aarch64::physical_permitted`]); a refusal leaves the virtual
/// counter in place. The rate is `CNTFRQ_EL0` either way, so an existing
/// calibration stays valid.
pub fn set_counter_source(source: CounterSource) -> Result<(), CounterSourceError> {
    #[cfg(target_arch = "aarch64")]
    {
        if source == CounterSource::Physical && !aarch64::physical_permitted() {
            return Err(CounterSourceError::NotPermitted);
        }
        aarch64::select_physical(source == CounterSource::Physical);
        Ok(())
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        match source {
            CounterSource::Virtual => Ok(()),
            CounterSource::Physical => Err(CounterSourceError::NoPhysicalCounter),
        }
    }
}

/// What one read of each counter costs here, and whether the physical one
/// looks trapped — the measured answer to "is a hypervisor in the way".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalCounterCheck {
    pub virtual_read_ns: u64,
    pub physical_read_ns: u64,
    /// The physical read costs an order of magnitude more than the virtual
    /// one and over 100 ns: every read is an exit to a hypervisor (or a trap
    /// into the kernel for emulation).
    pub trapped: bool,
}

/// Measures both counters, if the physical one may be read here.
pub fn physical_counter_check() -> Option<PhysicalCounterCheck> {
    #[cfg(target_arch = "aarch64")]
    {
        if !aarch64::physical_permitted() {
            return None;
        }
        let virtual_read_ns = aarch64::read_cost_ns(aarch64::cntvct_isb);
        let physical_read_ns = aarch64::read_cost_ns(aarch64::cntpct_isb);
        Some(PhysicalCounterCheck {
            virtual_read_ns,
            physical_read_ns,
            trapped: physical_read_ns > 100 && physical_read_ns > virtual_read_ns.saturating_mul(10),
        })
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        None
    }
}

/// Native tick rate of the architectural counter, when the hardware states it.
///
/// AArch64 reports `CNTFRQ_EL0` directly. PowerPC's Time Base rate comes from
/// the device tree (`/proc/cpuinfo` when hosted). x86-64 has no equivalent,
/// so its TSC frequency has to be measured — see
/// [`crate::clock::calibrate_cycles_per_ns`].
#[inline]
pub fn declared_counter_hz() -> Option<u64> {
    #[cfg(target_arch = "aarch64")]
    {
        let hz = aarch64::cntfrq();
        if hz > 0 {
            Some(hz)
        } else {
            None
        }
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        powerpc::timebase_hz()
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        riscv::timebase_hz()
    }
    #[cfg(target_arch = "arm")]
    {
        arm32::counter_hz()
    }
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )))]
    {
        None
    }
}

#[cfg(test)]
mod counter_source_tests {
    use super::*;

    /// Virtual is the default everywhere, and selecting it always works.
    #[test]
    fn virtual_is_the_default_and_always_selectable() {
        assert_eq!(counter_source(), CounterSource::Virtual);
        assert!(set_counter_source(CounterSource::Virtual).is_ok());
    }

    /// Where the physical counter exists and may be read, selecting it takes
    /// effect, the reads keep moving forward, and switching back restores the
    /// virtual counter. Being inside a VM is not a reason to refuse: that is
    /// what the warning is for.
    #[test]
    fn physical_can_be_selected_where_permitted() {
        match set_counter_source(CounterSource::Physical) {
            Ok(()) => {
                assert_eq!(counter_source(), CounterSource::Physical);
                let a = counter_start();
                let mut x = 0u64;
                for i in 0..10_000u64 {
                    x = core::hint::black_box(x.wrapping_add(i));
                }
                assert!(counter_end() >= a);
                assert!(physical_counter_check().is_some());
                set_counter_source(CounterSource::Virtual).unwrap();
                assert_eq!(counter_source(), CounterSource::Virtual);
            }
            Err(CounterSourceError::NoPhysicalCounter) => assert!(!has_physical_counter()),
            Err(CounterSourceError::NotPermitted) => {
                assert!(has_physical_counter());
                assert_eq!(counter_source(), CounterSource::Virtual);
            }
        }
    }
}
