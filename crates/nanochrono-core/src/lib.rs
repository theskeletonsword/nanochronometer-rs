// SPDX-License-Identifier: Apache-2.0
//! NanoChronometer timing core.
//!
//! A nanosecond-resolution chronometer, precision clock and ISA measurement
//! toolkit built directly on the architectural counters — `RDTSC`/`RDTSCP` on
//! x86-64, `CNTVCT_EL0` on AArch64 — with the calibration and drift tracking
//! that make those counters trustworthy.
//!
//! # Where the assembly went
//!
//! Every instruction sequence lives in [`arch`] as `core::arch::asm!`. There
//! are no `.S` or `.asm` files in this crate, no NASM dependency and no
//! assembler step: `cargo build` is the entire toolchain, and the ISA
//! sequences sit next to the CPUID gates that decide whether to run them.
//!
//! The whole project has exactly one loose assembly file —
//! `nanochrono-baremetal`'s `boot32.S` — because a multiboot loader enters in
//! 32-bit protected mode with no stack, before any of Rust's ABI assumptions
//! hold, and the multiboot header has to sit at a fixed offset that only a
//! linker script can place.
//!
//! # What the numbers mean
//!
//! Formatting to nanoseconds does not make the OS nanosecond-accurate.
//! Scheduling, interrupts and frequency transitions all dwarf a counter tick.
//! Direct counter reads are trustworthy for short intervals and
//! microbenchmarks; for wall-clock time over minutes, the calibrated route
//! against the monotonic clock is the honest answer, and
//! [`Chronometer::drift_ppm`] shows you when calibration has gone stale.
//!
//! # Example
//!
//! ```
//! use nanochrono_core::{Chronometer, Stopwatch, format::DetailMode};
//!
//! let chrono = Chronometer::new();
//! let mut sw = Stopwatch::new();
//! sw.start();
//! // ... work ...
//! sw.pause(&chrono);
//! println!("{}", sw.format(&chrono, DetailMode::Nano));
//! ```

//! # Running without an operating system
//!
//! The crate builds `no_std` with `default-features = false`. What survives is
//! the part that needs no kernel: [`arch`] (every counter and every inline
//! assembly sequence), [`backend`], [`simd`] and [`redundancy`]. Everything
//! else — calibration against a monotonic clock, `perf_event_open`, the
//! hypervisor's platform files, formatting — needs an OS underneath and is
//! gated behind the `std` feature, which is on by default.
//!
//! `nanochrono-baremetal` is built on that subset, so a freestanding kernel
//! executes the same instruction sequences as a hosted process rather than a
//! reimplementation of them.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

// Available with or without an OS: pure instruction sequences and the types
// that describe them.
/// Reading the firmware's ACPI Machine Language.
///
/// `no_std` and free of privilege: it is a parser over a byte slice, so the
/// freestanding kernel and a hosted test can run the same code over the same
/// table. That is deliberate — see the module docs.
pub mod aml;
pub mod arch;
pub mod backend;
pub mod cpu;
/// Checking the primary counter against an independent clock.
///
/// `no_std` and pure: the caller reads both clocks and passes the pair.
pub mod crosscheck;
/// Reading a HID report descriptor to find a pointer.
///
/// `no_std` and pure: the freestanding kernel and a hosted test run it over
/// the same bytes, which is what lets a real touchpad's descriptor be a test
/// fixture rather than a hardware dependency.
pub mod hid_report;
pub mod hypercall_hal;
/// The microbenchmark kernels per ISA family. `no_std`; shared by the
/// hosted dispatcher and the freestanding benchmark tab.
pub mod kernels;
pub mod pmu_leaf;
/// The typed code a restart or power-off waits for (BadUSB defence).
///
/// `no_std` and pure, like [`reprobe`]: the caller supplies time and entropy.
pub mod power_confirm;
pub mod redundancy;
pub mod reprobe;
/// When to scrub protected state, and when to escalate to verified reads.
///
/// `no_std` and pure: the caller supplies the clock and the outcomes.
pub mod space_mode;
/// Submersion, ingress ratings and temperature, for a phone under water.
///
/// Uses `f64` arithmetic, so it needs `std` (no `libm` in the freestanding
/// build).
#[cfg(feature = "std")]
pub mod underwater;
pub mod simd;

#[cfg(feature = "std")]
pub mod clock;
#[cfg(feature = "std")]
pub mod context;
#[cfg(feature = "std")]
pub mod dispatch;
#[cfg(feature = "std")]
pub mod format;
#[cfg(feature = "std")]
pub mod hypervisor;
/// The Linux kernel's crypto API, reached from ring 3 and timed. Compiled in
/// everywhere; reports itself unavailable off Linux.
#[cfg(feature = "std")]
pub mod kcrypto;
#[cfg(feature = "std")]
pub mod kvmclock;
#[cfg(feature = "std")]
pub mod ntp;
#[cfg(feature = "std")]
pub mod perf;
#[cfg(feature = "std")]
pub mod platform;
#[cfg(feature = "std")]
pub mod pmu;
#[cfg(feature = "std")]
pub mod probe;
#[cfg(feature = "std")]
pub mod ring0_perf;
#[cfg(feature = "std")]
pub mod stats;
#[cfg(feature = "std")]
pub mod stopwatch;

pub use backend::Backend;
#[cfg(feature = "std")]
pub use clock::{
    ClockRoute, NanoclockSnapshot, RouteCalibration, StableClockConfig, StableClockState,
    WrapperKind,
};
#[cfg(feature = "std")]
pub use context::Chronometer;
pub use cpu::CpuFeatures;
#[cfg(feature = "std")]
pub use dispatch::{CryptoKernel, Dispatcher, SelectionReason};
#[cfg(feature = "std")]
pub use format::{DetailMode, TimeZoneMode};
#[cfg(feature = "std")]
pub use hypervisor::{Hypervisor, HypervisorReport, TimingImpact};
#[cfg(feature = "std")]
pub use kvmclock::{ClockPairing, HostSync};
#[cfg(feature = "std")]
pub use pmu::{PmuBackend, PmuReading};
#[cfg(feature = "std")]
pub use ring0_perf::{Ring0Event, Ring0Perf};
#[cfg(feature = "std")]
pub use probe::{AuditConfig, CacheAudit, CacheProbe};
pub use redundancy::{Integrity, IntegrityStats, Protected};
pub use simd::{ProbeKind, SimdFamily};
#[cfg(feature = "std")]
pub use stats::{ConstantTimeVerdict, SampleStats};
#[cfg(feature = "std")]
pub use stopwatch::{Stopwatch, StopwatchState};

/// Crate version, from Cargo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Human-readable toolkit identifier for reports and log headers.
#[cfg(feature = "std")]
pub fn toolkit_version() -> String {
    format!("NanoChronometer Toolkit {VERSION} ({})", arch::ARCH.name())
}

/// Which of the three clock surfaces the UI is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockView {
    /// Elapsed time under user control.
    #[default]
    Stopwatch,
    /// Wall-clock time of day.
    Clock,
    /// Countdown.
    Timer,
}

impl ClockView {
    pub const fn name(self) -> &'static str {
        match self {
            ClockView::Stopwatch => "stopwatch",
            ClockView::Clock => "clock",
            ClockView::Timer => "timer",
        }
    }

    /// Cycles Stopwatch → Clock → Timer → Stopwatch.
    pub const fn next(self) -> ClockView {
        match self {
            ClockView::Stopwatch => ClockView::Clock,
            ClockView::Clock => ClockView::Timer,
            ClockView::Timer => ClockView::Stopwatch,
        }
    }

    pub const ALL: &'static [ClockView] =
        &[ClockView::Clock, ClockView::Stopwatch, ClockView::Timer];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chronometer_calibrates_to_a_plausible_rate() {
        let chrono = Chronometer::new();
        let hz = chrono.counter_hz();
        // Anywhere from a 1 MHz fallback clock to a 100 GHz counter is
        // plausible; zero or absurd values mean calibration broke.
        assert!(
            (1_000_000..100_000_000_000).contains(&hz),
            "counter_hz = {hz}"
        );
    }

    #[test]
    fn elapsed_tracks_a_real_sleep() {
        let mut chrono = Chronometer::new();
        chrono.start();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let ns = chrono.elapsed_ns();
        // Generous bounds: a loaded CI box can oversleep considerably, but it
        // cannot undersleep.
        assert!(
            (15_000_000..500_000_000).contains(&ns),
            "20 ms sleep measured as {ns} ns"
        );
    }

    #[test]
    fn selected_backend_is_supported_here() {
        let chrono = Chronometer::new();
        assert!(chrono.backend().is_available());
    }

    #[test]
    fn requesting_an_absent_backend_degrades() {
        // Whatever this machine is, the resolved backend must be runnable.
        for backend in Backend::ALL.iter().copied() {
            assert!(backend.resolve().is_available());
        }
    }

    #[test]
    fn backend_names_round_trip_through_parse() {
        for backend in Backend::ALL.iter().copied() {
            assert_eq!(Backend::parse(backend.name()), Some(backend));
        }
        assert_eq!(Backend::parse("nonsense"), None);
    }

    #[test]
    fn clock_view_cycles_through_all_three() {
        let mut view = ClockView::Stopwatch;
        for _ in 0..3 {
            view = view.next();
        }
        assert_eq!(view, ClockView::Stopwatch);
    }

    /// The scenario the redundancy layer exists for: a bit flips in the
    /// calibration constant, and every conversion afterwards is silently wrong
    /// until something checks.
    #[test]
    fn an_upset_in_the_calibration_is_caught_and_repaired() {
        let mut chrono = Chronometer::new();
        let good_hz = chrono.counter_hz();
        let good_ns = chrono.units_to_ns(1_000_000);

        // Bit 40 is high in the frequency: enough to change every duration by
        // orders of magnitude, while the value still looks like a plausible
        // clock rate in a log.
        chrono.inject_calibration_flip(40);
        assert_ne!(
            chrono.counter_hz(),
            good_hz,
            "the injected flip did not take"
        );
        assert_ne!(
            chrono.units_to_ns(1_000_000),
            good_ns,
            "a corrupted constant produced the same answer, so the test proves nothing"
        );

        let outcome = chrono.verify_calibration();
        assert!(
            outcome.was_repaired(),
            "the upset went undetected: {outcome:?}"
        );
        assert!(outcome.is_usable());
        assert_eq!(
            chrono.counter_hz(),
            good_hz,
            "repair restored the wrong value"
        );
        assert_eq!(chrono.units_to_ns(1_000_000), good_ns);
    }

    /// Two flips are past what the code can repair, so the emergency tier has
    /// to carry it — which is exactly the split the design calls for.
    #[test]
    fn a_double_upset_escalates_to_the_voting_tier() {
        let mut chrono = Chronometer::new();
        let good_hz = chrono.counter_hz();

        chrono.inject_calibration_flip(5);
        chrono.inject_calibration_flip(37);

        let outcome = chrono.verify_calibration();
        assert!(
            matches!(outcome, crate::Integrity::CorrectedByTmr { .. }),
            "expected the vote to run, got {outcome:?}"
        );
        assert_eq!(chrono.counter_hz(), good_hz);
        assert_eq!(chrono.verify_calibration(), crate::Integrity::Clean);
    }

    #[test]
    fn unit_conversion_is_self_consistent() {
        let chrono = Chronometer::new();
        let units = chrono.ns_to_units(1_000_000);
        let ns = chrono.units_to_ns(units);
        // Round-trip through integer division loses at most one unit.
        assert!(
            ns.abs_diff(1_000_000) < 1_000,
            "1 ms round-tripped to {ns} ns"
        );
    }
}
