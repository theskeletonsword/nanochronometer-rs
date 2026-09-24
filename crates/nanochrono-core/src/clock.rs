// SPDX-License-Identifier: Apache-2.0
//! Clock routes, snapshots and stable calibration.
//!
//! A *route* is a specific way of asking the machine what time it is, from a
//! bare `RDTSC` to a syscall. They differ by orders of magnitude in both cost
//! and ordering guarantees, and the whole point of this module is to make that
//! difference measurable rather than assumed.
//!
//! The critical-path rule from the C implementation is preserved: once
//! calibrated, reading the clock is a counter read, a subtraction and a
//! multiply. No syscall, no lock, no network.

use crate::arch;
use crate::backend::Backend;
use crate::context::Chronometer;
use crate::cpu;
use crate::platform;
use crate::redundancy::{Integrity, Protected};
use crate::simd::SimdFamily;

/// A way of reading the current time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockRoute {
    /// Pick the best route this machine offers.
    #[default]
    Auto,
    /// OS realtime clock, in nanoseconds. Steppable; the only route
    /// comparable against NTP.
    WallRealtimeNs,
    /// OS monotonic clock, in nanoseconds.
    MonotonicNs,
    /// Bare `RDTSC`. Cheapest, unordered. Available on both x86 widths.
    X86RdtscRaw,
    /// `LFENCE` + `RDTSC`.
    X86RdtscLfence,
    /// `MFENCE` + `LFENCE` + `RDTSC`.
    X86RdtscMfence,
    /// `RDTSCP` + `LFENCE`. Ordered against older instructions.
    X86RdtscpLfence,
    /// `CNTFRQ_EL0` — the counter's declared rate, not a time.
    Arm64Cntfrq,
    /// Bare `CNTVCT_EL0`.
    Arm64Cntvct,
    /// `ISB` + `CNTVCT_EL0`.
    Arm64CntvctIsb,
    /// Hardware cycle counter via `perf_event_open`.
    ///
    /// Per-thread, context-switch safe and unprivileged, unlike the raw PMU
    /// register the C build reached for. Available on Linux where
    /// `perf_event_paranoid` permits it and the host exposes a PMU.
    LinuxPerfCycles,
    /// The counter read tagged to the widest available SIMD family.
    BestSimdCounter,
    /// Bare PowerPC Time Base (`mftb`; `mftbu`/`mftb`/`mftbu` on 32-bit).
    PpcTimebase,
    /// `isync`-ordered PowerPC Time Base: the interval-boundary read.
    PpcTimebaseIsync,
    /// RISC-V `time` CSR (`rdtime`), fence-ordered.
    RiscvRdtime,
    /// 32-bit ARM: `ISB` + `CNTVCT` where user space may read the generic
    /// timer, the monotonic clock otherwise.
    Arm32Counter,
}

impl ClockRoute {
    pub const fn name(self) -> &'static str {
        match self {
            ClockRoute::Auto => "auto",
            ClockRoute::WallRealtimeNs => "wall-realtime-ns",
            ClockRoute::MonotonicNs => "monotonic-ns",
            ClockRoute::X86RdtscRaw => "x86-rdtsc-raw",
            ClockRoute::X86RdtscLfence => "x86-lfence-rdtsc",
            ClockRoute::X86RdtscMfence => "x86-mfence-lfence-rdtsc",
            ClockRoute::X86RdtscpLfence => "x86-rdtscp-lfence",
            ClockRoute::Arm64Cntfrq => "arm64-cntfrq-el0",
            ClockRoute::Arm64Cntvct => "arm64-cntvct-el0",
            ClockRoute::Arm64CntvctIsb => "arm64-isb-cntvct-el0",
            ClockRoute::LinuxPerfCycles => "linux-perf-cycles",
            ClockRoute::BestSimdCounter => "best-simd-counter",
            ClockRoute::PpcTimebase => "ppc-mftb",
            ClockRoute::PpcTimebaseIsync => "ppc-isync-mftb",
            ClockRoute::RiscvRdtime => "riscv-rdtime",
            ClockRoute::Arm32Counter => "arm32-isb-cntvct",
        }
    }

    /// Whether this route exists on the current target.
    pub fn is_available(self) -> bool {
        match self {
            ClockRoute::Auto | ClockRoute::WallRealtimeNs | ClockRoute::MonotonicNs => true,
            ClockRoute::X86RdtscRaw | ClockRoute::X86RdtscLfence | ClockRoute::X86RdtscMfence => {
                cfg!(any(target_arch = "x86_64", target_arch = "x86"))
            }
            // `RDTSCP` is an architecture *and* a feature: it is `#UD` on
            // anything older than Nehalem or Barcelona. Reporting the route
            // as available there and then executing it is `SIGILL` in a
            // process and a triple fault in this project's freestanding
            // kernel, so the CPU is asked rather than the target.
            ClockRoute::X86RdtscpLfence => {
                #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
                {
                    arch::x86::has_rdtscp()
                }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
                {
                    false
                }
            }
            ClockRoute::Arm64Cntfrq | ClockRoute::Arm64Cntvct | ClockRoute::Arm64CntvctIsb => {
                cfg!(target_arch = "aarch64")
            }
            ClockRoute::LinuxPerfCycles => {
                #[cfg(target_os = "linux")]
                {
                    crate::perf::is_available()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    false
                }
            }
            ClockRoute::BestSimdCounter => SimdFamily::best().is_some(),
            ClockRoute::PpcTimebase | ClockRoute::PpcTimebaseIsync => {
                cfg!(any(target_arch = "powerpc", target_arch = "powerpc64"))
            }
            ClockRoute::RiscvRdtime => cfg!(any(target_arch = "riscv32", target_arch = "riscv64")),
            ClockRoute::Arm32Counter => cfg!(target_arch = "arm"),
        }
    }

    /// Best route for this machine.
    ///
    /// Prefers an architectural counter over any syscall: `RDTSCP` costs tens
    /// of cycles where even a vDSO `clock_gettime` costs hundreds.
    pub fn best() -> ClockRoute {
        if SimdFamily::best().is_some() {
            return ClockRoute::BestSimdCounter;
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            ClockRoute::X86RdtscpLfence
        }
        #[cfg(target_arch = "aarch64")]
        {
            // CNTVCT_EL0 is preferred over the perf counter for interval
            // timing: it is a single unprivileged instruction, where a perf
            // read on AArch64 still costs a syscall. Perf is offered as an
            // explicit route for callers that want true cycles rather than
            // fixed-frequency ticks.
            ClockRoute::Arm64CntvctIsb
        }
        #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
        {
            // The Time Base is one unprivileged instruction at a fixed rate:
            // the PowerPC counterpart of CNTVCT_EL0, preferred over perf for
            // the same reason.
            ClockRoute::PpcTimebaseIsync
        }
        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        {
            // `rdtime` is the one counter Linux leaves readable in user space.
            ClockRoute::RiscvRdtime
        }
        #[cfg(target_arch = "arm")]
        {
            ClockRoute::Arm32Counter
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
            ClockRoute::MonotonicNs
        }
    }

    /// Resolves `Auto` and falls back when a route is unavailable.
    pub fn resolve(self) -> ClockRoute {
        match self {
            ClockRoute::Auto => ClockRoute::best(),
            other if other.is_available() => other,
            _ => ClockRoute::best(),
        }
    }

    /// Reads this route, returning `(raw_units, nanoseconds)`.
    ///
    /// `nanoseconds` is only meaningful for the wall/monotonic routes and for
    /// counter routes once `chrono` has been calibrated.
    pub fn read(self, chrono: &Chronometer) -> (u64, u64) {
        let route = self.resolve();
        match route {
            ClockRoute::WallRealtimeNs => {
                let ns = platform::unix_time_ns();
                (ns, ns)
            }
            ClockRoute::MonotonicNs => {
                let ns = platform::monotonic_ns();
                (ns, ns)
            }
            ClockRoute::X86RdtscRaw
            | ClockRoute::X86RdtscLfence
            | ClockRoute::X86RdtscMfence
            | ClockRoute::X86RdtscpLfence
            | ClockRoute::Arm64Cntvct
            | ClockRoute::Arm64CntvctIsb
            | ClockRoute::LinuxPerfCycles
            | ClockRoute::BestSimdCounter
            | ClockRoute::PpcTimebase
            | ClockRoute::PpcTimebaseIsync
            | ClockRoute::RiscvRdtime
            | ClockRoute::Arm32Counter => {
                let raw = read_counter(route);
                (raw, chrono.units_to_ns(raw))
            }
            ClockRoute::Arm64Cntfrq => {
                let hz = arch::declared_counter_hz().unwrap_or(0);
                (hz, hz)
            }
            ClockRoute::Auto => unreachable!("resolve() eliminates Auto"),
        }
    }

    /// Reads just the raw counter units for this route.
    pub fn read_raw(self, chrono: &Chronometer) -> u64 {
        self.read(chrono).0
    }

    pub const ALL: &'static [ClockRoute] = &[
        ClockRoute::WallRealtimeNs,
        ClockRoute::MonotonicNs,
        ClockRoute::X86RdtscRaw,
        ClockRoute::X86RdtscLfence,
        ClockRoute::X86RdtscMfence,
        ClockRoute::X86RdtscpLfence,
        ClockRoute::Arm64Cntfrq,
        ClockRoute::Arm64Cntvct,
        ClockRoute::Arm64CntvctIsb,
        ClockRoute::LinuxPerfCycles,
        ClockRoute::BestSimdCounter,
        // Appended, never inserted: the FFI numbers routes by their position
        // in this list.
        ClockRoute::PpcTimebase,
        ClockRoute::PpcTimebaseIsync,
        ClockRoute::RiscvRdtime,
        ClockRoute::Arm32Counter,
    ];
}

fn read_counter(route: ClockRoute) -> u64 {
    #[cfg(target_os = "linux")]
    if route == ClockRoute::LinuxPerfCycles {
        if let Some(cycles) = crate::perf::read_thread_cycles() {
            return cycles;
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        use arch::x86 as x;
        match route {
            ClockRoute::X86RdtscRaw => x::rdtsc_raw(),
            ClockRoute::X86RdtscLfence => x::rdtsc_lfence(),
            ClockRoute::X86RdtscMfence => x::rdtsc_mfence(),
            // Portable by construction: `is_available` refuses this route on
            // a part without `RDTSCP`, and a caller that names it anyway gets
            // the fenced `RDTSC` rather than an invalid opcode.
            ClockRoute::X86RdtscpLfence => x::tsc_end_portable(),
            _ => arch::counter_start(),
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use arch::aarch64 as a;
        match route {
            ClockRoute::Arm64Cntvct => a::cntvct_raw(),
            ClockRoute::Arm64CntvctIsb => a::cntvct_isb(),
            _ => arch::counter_start(),
        }
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        use arch::powerpc as p;
        match route {
            ClockRoute::PpcTimebase => p::timebase_raw(),
            ClockRoute::PpcTimebaseIsync => p::timebase_end(),
            _ => arch::counter_start(),
        }
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        let _ = route;
        arch::riscv::rdtime_end()
    }
    #[cfg(target_arch = "arm")]
    {
        let _ = route;
        arch::arm32::counter_isb()
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
        let _ = route;
        arch::counter_start()
    }
}

/// Which language binding's call overhead to estimate.
///
/// The native figures are real measurements. The interpreted ones are
/// *baselines*: this process cannot measure another runtime's marshalling
/// cost, so a Python or Node wrapper must run its own loop and add its own
/// overhead on top of the number reported here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperKind {
    CApi,
    DllBoundary,
    PythonCtypes,
    PythonCffi,
    NodeFfi,
    LuaFfi,
    JavaJna,
    CsharpPinvoke,
    GoCgo,
    RustFfi,
    ZigFfi,
}

impl WrapperKind {
    pub const fn name(self) -> &'static str {
        match self {
            WrapperKind::CApi => "c-api",
            WrapperKind::DllBoundary => "dll-boundary",
            WrapperKind::PythonCtypes => "python-ctypes",
            WrapperKind::PythonCffi => "python-cffi",
            WrapperKind::NodeFfi => "node-ffi",
            WrapperKind::LuaFfi => "lua-ffi",
            WrapperKind::JavaJna => "java-jna",
            WrapperKind::CsharpPinvoke => "csharp-pinvoke",
            WrapperKind::GoCgo => "go-cgo",
            WrapperKind::RustFfi => "rust-ffi",
            WrapperKind::ZigFfi => "zig-ffi",
        }
    }

    /// True when the number is a real measurement rather than a baseline.
    pub const fn is_measured_natively(self) -> bool {
        matches!(
            self,
            WrapperKind::CApi | WrapperKind::DllBoundary | WrapperKind::RustFfi
        )
    }

    pub const ALL: &'static [WrapperKind] = &[
        WrapperKind::CApi,
        WrapperKind::DllBoundary,
        WrapperKind::PythonCtypes,
        WrapperKind::PythonCffi,
        WrapperKind::NodeFfi,
        WrapperKind::LuaFfi,
        WrapperKind::JavaJna,
        WrapperKind::CsharpPinvoke,
        WrapperKind::GoCgo,
        WrapperKind::RustFfi,
        WrapperKind::ZigFfi,
    ];
}

/// Native call-overhead baseline for `kind`, in counter units.
pub fn measure_wrapper_overhead(chrono: &Chronometer, kind: WrapperKind, iterations: u32) -> u64 {
    let _ = kind;
    chrono.measure_ffi_overhead(iterations.max(1))
}

/// Everything the clock views display, captured in one pass.
#[derive(Debug, Clone, Default)]
pub struct NanoclockSnapshot {
    pub arch: &'static str,
    pub route: ClockRoute,
    pub backend: Backend,
    pub best_simd: Option<SimdFamily>,

    pub unix_time_ns: u64,
    pub monotonic_ns: u64,
    pub process_time_ns: u64,
    pub thread_time_ns: u64,

    /// Raw units from the selected route.
    pub selected_raw_units: u64,
    /// Those units converted to nanoseconds.
    pub selected_ns: u64,
    /// Barrier cost on the selected route.
    pub selected_overhead_units: u64,

    // x86-64 counter routes, all four read back to back for comparison.
    pub rdtsc_raw: u64,
    pub rdtsc_lfence: u64,
    pub rdtsc_mfence: u64,
    pub rdtscp_lfence: u64,
    pub rdtscp_aux: u32,

    // AArch64 counters.
    pub cntfrq_el0: u64,
    pub cntvct_el0: u64,
    pub cntvct_isb: u64,
    pub cntvct_ns: u64,

    /// Thread cycle count from `perf_event_open`, where the host allows it.
    ///
    /// `None` means no PMU is exposed — routine in containers and VMs.
    pub perf_cycles: Option<u64>,
    /// How many CPU PMUs the perf counter spans. Two on a hybrid CPU.
    pub perf_pmu_count: usize,

    pub simd_counter: u64,
    pub simd_counter_ns: u64,

    pub native_overhead_units: u64,
    pub ffi_overhead_units: u64,
    pub cpu_index: u32,

    /// What the platform is, and what that means for these numbers.
    ///
    /// Copied from the cached detection rather than re-derived: the answer
    /// cannot change mid-process, and the trap probe is too expensive to
    /// repeat on every snapshot.
    pub hypervisor: crate::hypervisor::Hypervisor,
    pub timing_impact: crate::hypervisor::TimingImpact,
}

impl NanoclockSnapshot {
    /// Captures the current state of every clock route.
    pub fn capture(chrono: &Chronometer) -> NanoclockSnapshot {
        let route = ClockRoute::best();
        let best_simd = SimdFamily::best();
        let (selected_raw_units, selected_ns) = route.read(chrono);

        let mut snap = NanoclockSnapshot {
            arch: arch::ARCH.name(),
            route,
            backend: chrono.backend(),
            best_simd,
            unix_time_ns: platform::unix_time_ns(),
            monotonic_ns: platform::monotonic_ns(),
            process_time_ns: platform::process_time_ns(),
            thread_time_ns: platform::thread_time_ns(),
            selected_raw_units,
            selected_ns,
            selected_overhead_units: arch::barrier_overhead(64),
            native_overhead_units: chrono.overhead_units(),
            ffi_overhead_units: chrono.measure_ffi_overhead(256),
            cpu_index: platform::current_cpu(),
            hypervisor: crate::hypervisor::cached().hypervisor.clone(),
            timing_impact: crate::hypervisor::cached().timing_impact,
            ..Default::default()
        };

        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            use arch::x86 as x;
            snap.rdtsc_raw = x::rdtsc_raw();
            snap.rdtsc_lfence = x::rdtsc_lfence();
            snap.rdtsc_mfence = x::rdtsc_mfence();
            // Left at zero on a part with no `RDTSCP`. A snapshot is a
            // record of what this machine can do, and "cannot" is one of the
            // things it can record — executing the instruction to find out
            // would end the process.
            if let Some(aux) = x::tsc_aux_checked() {
                snap.rdtscp_lfence = x::tsc_end_portable();
                snap.rdtscp_aux = aux;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            use arch::aarch64 as a;
            snap.cntfrq_el0 = a::cntfrq();
            snap.cntvct_el0 = a::cntvct_raw();
            snap.cntvct_isb = a::cntvct_isb();
            snap.cntvct_ns = chrono.units_to_ns(snap.cntvct_isb);
        }

        #[cfg(target_os = "linux")]
        {
            snap.perf_cycles = crate::perf::read_thread_cycles();
            snap.perf_pmu_count = crate::perf::pmu_count();
        }

        snap.simd_counter = arch::counter_start();
        snap.simd_counter_ns = chrono.units_to_ns(snap.simd_counter);
        snap
    }

    /// Whether these readings came from a virtualized platform.
    pub fn is_virtualized(&self) -> bool {
        self.timing_impact != crate::hypervisor::TimingImpact::Native
    }

    /// Name of the widest available SIMD family, for status lines.
    pub fn simd_name(&self) -> &'static str {
        self.best_simd.map(SimdFamily::name).unwrap_or("none")
    }
}

/// Inputs to a stable-clock calibration.
#[derive(Debug, Clone, Copy)]
pub struct StableClockConfig {
    pub route: ClockRoute,
    /// Pin the thread before calibrating. Strongly recommended.
    pub pin_cpu: bool,
    pub cpu_index: u32,
    /// Untimed settle time before the window opens.
    pub warmup_ms: u32,
    /// Length of the measurement window. Longer is more precise.
    pub calibration_ms: u32,
    /// Treat a thread migration during the window as a failure.
    pub require_no_migration: bool,
}

impl Default for StableClockConfig {
    fn default() -> Self {
        StableClockConfig {
            route: ClockRoute::Auto,
            pin_cpu: true,
            cpu_index: 0,
            warmup_ms: 50,
            calibration_ms: 500,
            require_no_migration: true,
        }
    }
}

/// Result of a stable-clock calibration.
#[derive(Debug, Clone, Copy, Default)]
pub struct StableClockState {
    pub route: ClockRoute,
    pub pinned: bool,
    pub cpu_before: u32,
    pub cpu_after: u32,
    /// The thread moved cores during the window; the result is suspect.
    pub migrated: bool,
    /// The counter is documented as invariant.
    pub invariant: bool,
    pub raw_start: u64,
    pub raw_end: u64,
    pub elapsed_units: u64,
    pub elapsed_ns: u64,
    /// The conversion factor, under an error-correcting code.
    ///
    /// Private, and the only stored form: the reciprocal is derived rather
    /// than stored so the two cannot disagree. A calibration is held for the
    /// life of a session and divides every duration derived from it, so a
    /// single flipped bit in this exponent would rescale every reading — the
    /// exact failure the code exists to catch. Read it through
    /// [`cycles_per_ns`](Self::cycles_per_ns).
    factor: Protected,
    pub read_overhead_units: u64,
    pub kernel_timecall_overhead_units: u64,
    pub api_call_overhead_units: u64,
}

impl StableClockState {
    /// The conversion factor: `ns = units / cycles_per_ns`.
    ///
    /// Verified on the way out, so a damaged calibration never reaches a
    /// conversion. Repairing the stored copy needs [`verify`](Self::verify).
    pub fn cycles_per_ns(&self) -> f64 {
        self.factor.get_f64_checked().0
    }

    /// The reciprocal, `units / ns`. Derived, never stored.
    pub fn ns_per_cycle(&self) -> f64 {
        let factor = self.cycles_per_ns();
        if factor > 0.0 {
            1.0 / factor
        } else {
            0.0
        }
    }

    /// Checks the stored factor without repairing it.
    pub fn integrity(&self) -> Integrity {
        self.factor.get_f64_checked().1
    }

    /// Verifies and repairs the stored factor.
    pub fn verify(&mut self) -> Integrity {
        self.factor.verify()
    }

    /// Whether this calibration is safe to convert with.
    pub fn is_usable(&self) -> bool {
        self.cycles_per_ns() > 0.0 && !(self.migrated && !self.pinned)
    }

    /// Flips bit `bit` of the stored factor, for drills and tests.
    #[doc(hidden)]
    pub fn inject_factor_flip(&mut self, bit: u32) {
        self.factor.inject_flip(bit);
    }
}

/// Measures how many counter units elapse per nanosecond.
///
/// This is the number that turns a raw `RDTSC` delta into a duration on the
/// hot path, so it is worth spending half a second on: sleep for a known wall
/// interval, read the counter at both ends, divide.
pub fn calibrate_cycles_per_ns(
    chrono: &Chronometer,
    config: &StableClockConfig,
) -> StableClockState {
    let route = config.route.resolve();
    let mut state = StableClockState {
        route,
        invariant: cpu::features().invariant_counter,
        ..Default::default()
    };

    state.cpu_before = platform::current_cpu();
    if config.pin_cpu {
        state.pinned = platform::pin_thread_to_cpu(config.cpu_index);
    }
    platform::sleep_ms(config.warmup_ms);

    let wall0 = platform::monotonic_ns();
    let raw0 = route.read_raw(chrono);
    platform::sleep_ms(config.calibration_ms.max(1));
    let raw1 = route.read_raw(chrono);
    let wall1 = platform::monotonic_ns();
    state.cpu_after = platform::current_cpu();

    state.migrated = state.cpu_before != platform::CPU_UNKNOWN
        && state.cpu_after != platform::CPU_UNKNOWN
        && state.cpu_before != state.cpu_after;

    state.raw_start = raw0;
    state.raw_end = raw1;
    state.elapsed_units = raw1.saturating_sub(raw0);
    state.elapsed_ns = wall1.saturating_sub(wall0);
    if state.elapsed_ns > 0 {
        state.factor = Protected::from_f64(state.elapsed_units as f64 / state.elapsed_ns as f64);
    }

    state.read_overhead_units = arch::read_overhead();
    state.kernel_timecall_overhead_units = measure_kernel_timecall_overhead(chrono, 256);
    state.api_call_overhead_units = measure_api_call_overhead(chrono, 256);
    state
}

/// Converts counter units to nanoseconds using a calibrated factor.
pub fn units_to_ns_calibrated(units: u64, cycles_per_ns: f64) -> u64 {
    // Rejects zero, negatives and NaN in one check: an uncalibrated
    // factor must never silently produce a plausible-looking duration.
    if !cycles_per_ns.is_finite() || cycles_per_ns <= 0.0 {
        return 0;
    }
    let ns = units as f64 / cycles_per_ns;
    if ns < 0.0 {
        0
    } else if ns >= u64::MAX as f64 {
        u64::MAX
    } else {
        ns.round() as u64
    }
}

/// Converts a raw counter delta to nanoseconds using a calibrated factor.
pub fn raw_delta_to_ns(raw_start: u64, raw_end: u64, cycles_per_ns: f64) -> u64 {
    units_to_ns_calibrated(raw_end.saturating_sub(raw_start), cycles_per_ns)
}

/// Best-case cost of one OS time syscall, in counter units.
///
/// The gap between this and [`measure_api_call_overhead`] is the argument for
/// counter routes: it is typically an order of magnitude.
pub fn measure_kernel_timecall_overhead(chrono: &Chronometer, iterations: u32) -> u64 {
    let route = ClockRoute::best();
    let mut best = u64::MAX;
    for _ in 0..iterations.max(1) {
        let a = route.read_raw(chrono);
        core::hint::black_box(platform::unix_time_ns());
        let b = route.read_raw(chrono);
        let d = b.saturating_sub(a);
        if d > 0 {
            best = best.min(d);
        }
    }
    if best == u64::MAX {
        0
    } else {
        best
    }
}

/// Best-case cost of one library clock read, in counter units.
pub fn measure_api_call_overhead(chrono: &Chronometer, iterations: u32) -> u64 {
    let route = ClockRoute::best();
    let mut best = u64::MAX;
    for _ in 0..iterations.max(1) {
        let a = route.read_raw(chrono);
        core::hint::black_box(route.read(chrono));
        let b = route.read_raw(chrono);
        let d = b.saturating_sub(a);
        if d > 0 {
            best = best.min(d);
        }
    }
    if best == u64::MAX {
        0
    } else {
        best
    }
}

/// Result of calibrating one route against wall time.
#[derive(Debug, Clone, Copy, Default)]
pub struct RouteCalibration {
    pub route: ClockRoute,
    pub samples: u64,
    pub pinned: bool,
    pub cpu_before: u32,
    pub cpu_after: u32,
    pub migrated: bool,
    pub elapsed_raw_units: u64,
    pub elapsed_ns: u64,
    pub units_per_second: f64,
    pub ns_per_unit: f64,
    pub read_overhead_units: u64,
    pub kernel_timecall_overhead_units: u64,
    pub api_call_overhead_units: u64,
}

/// Calibrates a route by reading it `samples` times and dividing by wall time.
///
/// Complements [`calibrate_cycles_per_ns`], which sleeps: this one keeps the
/// core busy, so it also exposes what a tight read loop costs.
pub fn calibrate_route(
    chrono: &Chronometer,
    route: ClockRoute,
    samples: u32,
    pin_cpu: bool,
    cpu_index: u32,
) -> RouteCalibration {
    let route = route.resolve();
    let samples = if samples == 0 { 100_000 } else { samples };
    let mut out = RouteCalibration {
        route,
        samples: samples as u64,
        ..Default::default()
    };

    if pin_cpu {
        out.pinned = platform::pin_thread_to_cpu(cpu_index);
    }
    out.cpu_before = platform::current_cpu();

    let t0 = platform::monotonic_ns();
    let r0 = route.read_raw(chrono);
    for _ in 0..samples {
        core::hint::black_box(route.read_raw(chrono));
    }
    let r1 = route.read_raw(chrono);
    let t1 = platform::monotonic_ns();

    out.cpu_after = platform::current_cpu();
    out.migrated = out.cpu_before != platform::CPU_UNKNOWN
        && out.cpu_after != platform::CPU_UNKNOWN
        && out.cpu_before != out.cpu_after;
    out.elapsed_raw_units = r1.saturating_sub(r0);
    out.elapsed_ns = t1.saturating_sub(t0);
    if out.elapsed_ns > 0 && out.elapsed_raw_units > 0 {
        out.units_per_second = out.elapsed_raw_units as f64 * 1e9 / out.elapsed_ns as f64;
        out.ns_per_unit = out.elapsed_ns as f64 / out.elapsed_raw_units as f64;
    }
    out.read_overhead_units = arch::read_overhead();
    out.kernel_timecall_overhead_units = measure_kernel_timecall_overhead(chrono, 256);
    out.api_call_overhead_units = measure_api_call_overhead(chrono, 256);
    out
}

/// Operator advice for getting a stable calibration, shown by the CLI.
pub const STABILITY_ADVICE: &str = "Best precision: disable turbo/boost, lock the performance \
governor, pin CPU affinity, avoid core migration, prefer an invariant TSC or CNTVCT_EL0, isolate \
benchmark cores, and consider disabling deep C-states when latency matters.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn best_route_is_available() {
        assert!(ClockRoute::best().is_available());
    }

    #[test]
    fn auto_never_survives_resolution() {
        assert_ne!(ClockRoute::Auto.resolve(), ClockRoute::Auto);
    }

    #[test]
    fn unavailable_routes_fall_back() {
        for route in ClockRoute::ALL.iter().copied() {
            let resolved = route.resolve();
            assert!(
                resolved.is_available(),
                "{} resolved to unavailable {}",
                route.name(),
                resolved.name()
            );
        }
    }

    #[test]
    fn counter_routes_advance() {
        let chrono = Chronometer::new();
        let route = ClockRoute::best();
        let a = route.read_raw(&chrono);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = route.read_raw(&chrono);
        assert!(b > a, "{} did not advance", route.name());
    }

    #[test]
    fn snapshot_fills_wall_and_monotonic() {
        let chrono = Chronometer::new();
        let snap = NanoclockSnapshot::capture(&chrono);
        assert!(snap.unix_time_ns > 1_600_000_000_000_000_000);
        assert!(snap.monotonic_ns > 0);
    }

    #[test]
    fn calibrated_conversion_round_trips() {
        // 3 GHz: 3000 cycles is 1000 ns.
        assert_eq!(units_to_ns_calibrated(3000, 3.0), 1000);
        assert_eq!(units_to_ns_calibrated(3000, 0.0), 0);
        assert_eq!(raw_delta_to_ns(100, 400, 3.0), 100);
        // A backwards delta is clamped, not wrapped.
        assert_eq!(raw_delta_to_ns(400, 100, 3.0), 0);
    }

    #[test]
    fn short_calibration_produces_a_usable_factor() {
        let chrono = Chronometer::new();
        let config = StableClockConfig {
            pin_cpu: false,
            warmup_ms: 0,
            calibration_ms: 20,
            require_no_migration: false,
            ..Default::default()
        };
        let state = calibrate_cycles_per_ns(&chrono, &config);
        assert!(
            state.cycles_per_ns() > 0.0,
            "calibration produced no factor"
        );
    }
}
