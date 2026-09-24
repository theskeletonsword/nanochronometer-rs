// SPDX-License-Identifier: Apache-2.0
//! The instructions a freestanding build needs that a hosted one never may.
//!
//! The counters themselves — `RDTSC`, `CNTVCT_EL0`, the SIMD probes — come
//! from `nanochrono_core::arch`, unchanged, because they are the same
//! instructions either way. What lives here is the privileged half: `RDPMC`,
//! `RDMSR`/`WRMSR`, port I/O. A hosted process cannot execute any of it, so it
//! has no place in the shared crate.

#[cfg(target_arch = "aarch64")]
pub use nanochrono_core::arch::aarch64;

#[cfg(x86_any)]
pub mod x86;

#[cfg(target_arch = "aarch64")]
pub mod arm;

#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
pub use nanochrono_core::arch::powerpc;

#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
pub mod ppc;

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub use nanochrono_core::arch::riscv as rv;

/// The kernel side of RISC-V (entry, traps, SBI). Named `riscv` in this
/// crate; the shared counter layer is re-exported as [`rv`].
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub mod riscv;


/// Orders the instruction stream around a measurement.
///
/// Without this the CPU is free to hoist the work past the counter read, or
/// sink the read past the work, and the interval measured is not the interval
/// asked for.
#[inline(always)]
pub fn serialize() {
    #[cfg(x86_any)]
    // SAFETY: `LFENCE` has no operands and no memory effects beyond ordering.
    unsafe {
        core::arch::asm!("lfence", options(nostack, preserves_flags));
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    // SAFETY: `ISB` has no operands and no memory effects beyond ordering.
    unsafe {
        core::arch::asm!("isb", options(nostack, preserves_flags));
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    powerpc::isync();
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    rv::fence();
}

/// Which AArch64 counter [`counter_ordered`] reads, and why it is a choice.
///
/// Defaults to [`CounterSource::Virtual`]: the virtual counter is the safe
/// choice for any kernel that might run inside a hypervisor, because a guest
/// sees a timeline that starts when the guest did. The physical counter
/// exposes — and splices together — the host's real timeline, which is what
/// this toggle exists to opt into for bare metal only.
///
/// `core::sync::atomic` because it is shared without a lock: a kernel built
/// on [`crate::abi`] may set it from one call while the interface reads it
/// from the render loop, on one core with interrupts masked, so the atomic is
/// ordering only against itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterSource {
    /// `CNTVCT_EL0` — the virtual counter, minus `CNTVOFF_EL2`. The safe
    /// default: a timeline that starts when this guest did.
    Virtual,
    /// `CNTPCT_EL0` — the physical counter, what the hardware really ticks.
    /// Not recommended inside a VM.
    Physical,
}

impl CounterSource {
    pub const fn as_u8(self) -> u8 {
        match self {
            CounterSource::Virtual => 0,
            CounterSource::Physical => 1,
        }
    }

    pub const fn from_u8(v: u8) -> CounterSource {
        match v {
            1 => CounterSource::Physical,
            _ => CounterSource::Virtual,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            CounterSource::Virtual => "cntvct_el0",
            CounterSource::Physical => "cntpct_el0",
        }
    }

    /// The counter this architecture actually reads under this setting.
    pub const fn name_here(self) -> &'static str {
        if cfg!(target_arch = "aarch64") {
            self.name()
        } else if cfg!(target_arch = "arm") {
            "cntvct"
        } else if cfg!(x86_any) {
            "tsc"
        } else if cfg!(any(target_arch = "riscv32", target_arch = "riscv64")) {
            "time (rdtime)"
        } else {
            "time base (mftb)"
        }
    }
}

impl CounterSource {
    const fn to_core(self) -> nanochrono_core::arch::CounterSource {
        match self {
            CounterSource::Virtual => nanochrono_core::arch::CounterSource::Virtual,
            CounterSource::Physical => nanochrono_core::arch::CounterSource::Physical,
        }
    }
}

/// Selects which AArch64 counter every read uses — this kernel's and the
/// shared crate's alike, since the state lives in `nanochrono_core::arch`.
///
/// This is the backing store for the *Enable Physical Counter* setting.
/// At EL1 and above the physical counter is always readable, so the only
/// refusal is an architecture without one (x86-64, RISC-V, PowerPC), where
/// the call returns `false` and nothing changes. Inside a VM it is allowed —
/// the hypervisor may trap every read, which is what the setting's warning
/// says — and on real hardware it costs the same as the virtual one.
pub fn set_counter_source(source: CounterSource) -> bool {
    nanochrono_core::arch::set_counter_source(source.to_core()).is_ok()
}

/// Which counter source is currently selected.
pub fn counter_source() -> CounterSource {
    match nanochrono_core::arch::counter_source() {
        nanochrono_core::arch::CounterSource::Physical => CounterSource::Physical,
        nanochrono_core::arch::CounterSource::Virtual => CounterSource::Virtual,
    }
}

/// The counter a freestanding kernel should read.
///
/// On AArch64 this reads either the virtual counter, `CNTVCT_EL0` (the
/// default, safe under a hypervisor), or — when the physical counter is
/// enabled through [`set_counter_source`] — `CNTPCT_EL0`. Both are wrapped in
/// `DSB`+`ISB`; see
/// [`nanochrono_core::arch::aarch64::cntvct_ordered`] and
/// [`nanochrono_core::arch::aarch64::cntpct_ordered`] for why the memory
/// barrier is not optional.
///
/// On x86-64 the shared `RDTSCP`+`LFENCE` route already is the ordered read;
/// there is no privileged alternative to switch to.
#[inline(always)]
pub fn counter_ordered() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        match counter_source() {
            CounterSource::Virtual => aarch64::cntvct_ordered(),
            CounterSource::Physical => aarch64::cntpct_ordered(),
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        nanochrono_core::arch::counter_end()
    }
}

/// Stops this core permanently, with interrupts masked.
///
/// A freestanding `main` cannot return: there is nothing to return *to*, and
/// falling off the end would execute whatever bytes follow.
pub fn halt() -> ! {
    loop {
        #[cfg(x86_any)]
        // SAFETY: `cli` masks interrupts and `hlt` waits for one; with
        // interrupts masked this never wakes, which is the intent.
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: masks interrupts, then waits for an event that cannot
        // arrive.
        unsafe {
            core::arch::asm!("msr daifset, #0xf", "wfi", options(nomem, nostack));
        }
        #[cfg(target_arch = "arm")]
        // SAFETY: as above, in the AArch32 spelling.
        unsafe {
            core::arch::asm!("cpsid if", "wfi", options(nomem, nostack));
        }
        // External interrupts are never enabled (`MSR[EE]` stays clear), and
        // there is no wait instruction common to Book3S and Book E that is
        // safe without platform setup, so the core spins at the lowest SMT
        // priority (`or 1,1,1`) instead.
        #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
        // SAFETY: a priority hint; no architectural state changes.
        unsafe {
            core::arch::asm!("or 1, 1, 1", options(nomem, nostack, preserves_flags));
        }
        // Supervisor interrupts off, then wait for one that cannot be taken.
        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        // SAFETY: clears sstatus.SIE and waits; nothing else changes.
        unsafe {
            core::arch::asm!("csrci sstatus, 2", "wfi", options(nomem, nostack));
        }
    }
}
