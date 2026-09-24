// SPDX-License-Identifier: Apache-2.0
//! Hardware cycle counting through `perf_event_open`.
//!
//! This replaces the direct `PMCCNTR_EL0` read the C build used on AArch64,
//! and adds the same capability on x86-64. Reading the PMU register directly
//! was never viable:
//!
//! * `PMCCNTR_EL0` traps to EL1 unless `PMUSERENR_EL0.EN` is set, which needs
//!   a privileged write and cannot be probed without taking the trap. The C
//!   code punted on this with a `NANOCHRONO_USE_PMCCNTR_EL0` environment
//!   variable — an opt-in that told the library to try an instruction that
//!   might kill the process.
//! * A raw PMU register is not virtualised. It counts whatever the core has
//!   been doing, including an SMT sibling's work, and it is not saved across
//!   context switches, so a preempted thread reads someone else's cycles.
//!
//! `perf_event_open` fixes both: the kernel schedules the counter per thread,
//! saves and restores it across context switches, and exposes it unprivileged
//! (subject to `perf_event_paranoid`).
//!
//! # Hybrid CPUs
//!
//! On Intel P-core/E-core parts there is no single `cpu` PMU — there are
//! `cpu_core` and `cpu_atom`, with separate counters. A plain
//! `PERF_TYPE_HARDWARE` event binds to one of them and then silently reads
//! **zero** whenever the thread is scheduled on the other core type. That is
//! not hypothetical: it is what this module did on an i9-14900HX until it
//! opened one event per PMU and summed them, which is what
//! [`PerfCycleCounter`] does now. Each event accumulates only while the thread
//! is on its own core type, so the sum is the thread's true cycle count across
//! migrations.
//!
//! # perf is the only PMU interface here
//!
//! Reads go through `read(2)` on the perf file descriptor. There is
//! deliberately no `RDPMC` fast path and no `PMCCNTR_EL0` read, even though
//! the kernel offers `cap_user_rdpmc` and would permit one:
//!
//! * A raw counter read bypasses the kernel's accounting. It cannot see
//!   multiplexing, so a descheduled event silently under-reports, and it has
//!   no idea which PMU it landed on — on a hybrid CPU that means reading the
//!   wrong core type's counter and getting zero.
//! * The userspace path needs a seqlock protocol, architecture-specific
//!   inline assembly and a sign-extension dance against `pmc_width`. That is
//!   a lot of subtle machinery to maintain for a saving that only shows up if
//!   you read the PMU inside a hot loop — which is not what this counter is
//!   for. The TSC and `CNTVCT_EL0` are the hot-path counters; see
//!   [`crate::arch`].
//!
//! A `read` costs roughly a microsecond. That is the honest price of a
//! counter the kernel owns, schedules and corrects.

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// --- perf_event ABI --------------------------------------------------------
// `libc` exposes the syscall number but not these types, so they are declared
// here against `linux/perf_event.h`. All are stable kernel ABI.

const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;

/// Extended hardware-event encoding: the PMU type goes in the top 32 bits of
/// `config`, which is how a hybrid CPU's `cpu_core` or `cpu_atom` is selected.
const PERF_PMU_TYPE_SHIFT: u32 = 32;

const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;

/// `exclude_kernel` (bit 5) and `exclude_hv` (bit 6) of the attribute bitfield.
///
/// Counting only user cycles is both more meaningful for a benchmark — kernel
/// time mid-measurement is noise — and more permissive: it is the mode allowed
/// at `perf_event_paranoid = 2`, the common default.
const ATTR_EXCLUDE_KERNEL_HV: u64 = (1 << 5) | (1 << 6);

/// `struct perf_event_attr`, zero-initialised and version-tagged by `size`.
///
/// The kernel uses `size` to negotiate: a struct smaller than it knows is
/// zero-filled, a larger one is accepted if the trailing bytes are zero. Since
/// this is always constructed zeroed, both directions are safe.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    reserved_2: u16,
    aux_sample_size: u32,
    reserved_3: u32,
    sig_data: u64,
    config3: u64,
}

impl Default for PerfEventAttr {
    fn default() -> Self {
        // SAFETY: every field is a plain integer, so all-zero is valid.
        let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr
    }
}

/// What a `read` returns with time totals enabled.
#[derive(Debug, Clone, Copy, Default)]
struct ReadFormat {
    value: u64,
    /// Nanoseconds the event was enabled.
    time_enabled: u64,
    /// Nanoseconds it was actually on hardware. Zero means it never ran.
    time_running: u64,
}

/// Why the counter could not be opened.
#[derive(Debug)]
pub enum PerfError {
    /// `perf_event_open` failed on every PMU. Usually `EACCES` from
    /// `perf_event_paranoid`, or `ENOENT` where no PMU is exposed — routine in
    /// containers and VMs.
    Open(io::Error),
    /// The counter opened but could not be read, or never ran.
    Read(io::Error),
}

impl std::fmt::Display for PerfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PerfError::Open(e) => write!(
                f,
                "perf_event_open failed: {e} \
                 (check /proc/sys/kernel/perf_event_paranoid, or run on a host with a PMU)"
            ),
            PerfError::Read(e) => write!(f, "could not read the perf counter: {e}"),
        }
    }
}

impl std::error::Error for PerfError {}

/// A per-thread hardware cycle counter.
///
/// Holds one event per CPU PMU, so a thread that migrates between P-cores and
/// E-cores is still counted correctly. Closed on drop.
#[derive(Debug)]
pub struct PerfCycleCounter {
    events: Vec<Event>,
    /// The largest total handed out so far. A multiplexed event's count is
    /// an estimate — raw × enabled / running — and two estimates taken a
    /// moment apart can go *down*: the second window ran a larger share of
    /// the time and extrapolates less. A cycle counter that runs backwards
    /// turns every interval measured across that moment negative, so every
    /// read is clamped to never fall below the last one.
    high_water: std::sync::atomic::AtomicU64,
}

#[derive(Debug)]
struct Event {
    fd: OwnedFd,
}

impl PerfCycleCounter {
    /// Opens a cycle counter for the calling thread.
    ///
    /// On a hybrid CPU this opens one event per core type. Fails only when no
    /// PMU accepts an event at all.
    pub fn open() -> Result<PerfCycleCounter, PerfError> {
        let mut events = Vec::new();
        let mut last_error = None;

        for config in cycle_event_configs() {
            match Event::open(config) {
                Ok(event) => events.push(event),
                Err(e) => last_error = Some(e),
            }
        }

        if events.is_empty() {
            return Err(PerfError::Open(last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "no CPU PMU available")
            })));
        }
        Ok(PerfCycleCounter {
            events,
            high_water: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// How many PMUs this counter spans. Two on a hybrid CPU, one elsewhere.
    pub fn pmu_count(&self) -> usize {
        self.events.len()
    }

    /// The calling thread's cycle count, summed across PMUs.
    ///
    /// Returns `None` if no event has ever been scheduled onto hardware —
    /// which is how a counter that exists but cannot count reports itself,
    /// instead of quietly returning zero forever.
    #[inline]
    pub fn read(&self) -> Option<u64> {
        let mut total = 0u64;
        let mut ran = false;
        for event in &self.events {
            if let Some(value) = event.read() {
                ran = true;
                total = total.saturating_add(value);
            }
        }
        ran.then(|| self.monotonic(total))
    }

    /// `total`, or the largest total already returned if that is larger.
    fn monotonic(&self, total: u64) -> u64 {
        let previous = self
            .high_water
            .fetch_max(total, std::sync::atomic::Ordering::Relaxed);
        previous.max(total)
    }

    /// Sums every event through the `read` syscall, returning an error when
    /// none of them was ever scheduled onto hardware.
    pub fn read_syscall(&self) -> Result<u64, PerfError> {
        let mut total = 0u64;
        let mut ran = false;
        for event in &self.events {
            let raw = event.read_syscall()?;
            if raw.time_running > 0 {
                ran = true;
                total = total.saturating_add(scale(raw));
            }
        }
        if ran {
            Ok(self.monotonic(total))
        } else {
            Err(PerfError::Read(io::Error::other(
                "no event was scheduled onto hardware",
            )))
        }
    }
}

impl Event {
    fn open(config: u64) -> Result<Event, io::Error> {
        let mut attr = PerfEventAttr {
            type_: PERF_TYPE_HARDWARE,
            config,
            flags: ATTR_EXCLUDE_KERNEL_HV,
            // Time totals turn "the counter read zero" into a distinguishable
            // "the counter never ran", which is the difference between a real
            // measurement and a silently broken one.
            read_format: PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
            ..PerfEventAttr::default()
        };
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;

        // pid = 0: this thread. cpu = -1: wherever it runs, so the count
        // follows the thread rather than measuring one core.
        //
        // Every argument is widened to `c_long` explicitly: `syscall` is
        // variadic and reads its arguments as `long`, so passing a `c_int`
        // leaves the upper 32 bits of the register undefined.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const PerfEventAttr as libc::c_long,
                0 as libc::c_long,
                -1 as libc::c_long,
                -1 as libc::c_long,
                PERF_FLAG_FD_CLOEXEC as libc::c_long,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the syscall returned a fresh, owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        Ok(Event { fd })
    }

    /// This event's contribution, or `None` if it never ran.
    #[inline]
    fn read(&self) -> Option<u64> {
        let raw = self.read_syscall().ok()?;
        (raw.time_running > 0).then(|| scale(raw))
    }

    fn read_syscall(&self) -> Result<ReadFormat, PerfError> {
        let mut buffer = [0u64; 3];
        // SAFETY: `read_format` was set to value + enabled + running, which is
        // exactly three u64s, and `buffer` is that size.
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                std::mem::size_of_val(&buffer),
            )
        };
        if n != std::mem::size_of_val(&buffer) as isize {
            return Err(PerfError::Read(io::Error::last_os_error()));
        }
        Ok(ReadFormat {
            value: buffer[0],
            time_enabled: buffer[1],
            time_running: buffer[2],
        })
    }
}

/// Corrects for PMU multiplexing.
///
/// When more events are open than there are hardware counters, the kernel
/// time-slices them and `time_running < time_enabled`. Scaling by that ratio
/// is the kernel's documented way to estimate the full count; without it a
/// multiplexed counter under-reports by whatever fraction it was descheduled.
fn scale(raw: ReadFormat) -> u64 {
    if raw.time_running == 0 {
        return 0;
    }
    if raw.time_running >= raw.time_enabled {
        return raw.value;
    }
    ((raw.value as u128 * raw.time_enabled as u128) / raw.time_running as u128) as u64
}

/// One `config` value per CPU PMU that can count cycles.
///
/// A hybrid CPU exposes `cpu_core` and `cpu_atom` instead of a single `cpu`,
/// and an event must name which one it wants; the PMU type goes in the top 32
/// bits of `config`. Falls back to the plain generic event on non-hybrid
/// hardware, where there is only one CPU PMU.
fn cycle_event_configs() -> Vec<u64> {
    let mut configs = Vec::new();
    for pmu in ["cpu_core", "cpu_atom"] {
        if let Some(type_id) = read_pmu_type(pmu) {
            configs.push(((type_id as u64) << PERF_PMU_TYPE_SHIFT) | PERF_COUNT_HW_CPU_CYCLES);
        }
    }
    if configs.is_empty() {
        configs.push(PERF_COUNT_HW_CPU_CYCLES);
    }
    configs
}

fn read_pmu_type(name: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/bus/event_source/devices/{name}/type"))
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

// --- per-thread handle -----------------------------------------------------

use std::sync::OnceLock;

thread_local! {
    /// One counter per thread, opened on first use.
    ///
    /// Per-thread because that is what the counter *means*: `perf_event_open`
    /// with `pid = 0` measures the thread that opened it. A shared handle
    /// would have every thread reading some other thread's cycles, which looks
    /// like a counter that stops whenever the owner is parked.
    static THREAD_COUNTER: Option<PerfCycleCounter> = PerfCycleCounter::open().ok();
}

/// Reads the calling thread's cycle count.
///
/// `None` where no PMU is exposed, or where the counter exists but has never
/// been scheduled onto hardware.
#[inline]
pub fn read_thread_cycles() -> Option<u64> {
    THREAD_COUNTER.with(|counter| counter.as_ref()?.read())
}

/// How many CPU PMUs the calling thread's counter spans.
pub fn pmu_count() -> usize {
    THREAD_COUNTER.with(|counter| counter.as_ref().map_or(0, PerfCycleCounter::pmu_count))
}

/// Whether this host exposes a usable hardware cycle counter.
///
/// Probed once per process: a counter is opened, exercised, and required to
/// actually count. Opening alone is not enough — an event that never gets
/// scheduled opens fine and reads zero forever, which is the failure mode a
/// plain "did open succeed" check would miss.
pub fn is_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let Ok(counter) = PerfCycleCounter::open() else {
            return false;
        };
        let before = counter.read();
        let mut acc = 0u64;
        for i in 0..50_000u64 {
            acc = acc.wrapping_add(i).rotate_left(3);
        }
        std::hint::black_box(acc);
        matches!((before, counter.read()), (Some(a), Some(b)) if b > a)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_opens_or_explains_itself() {
        match PerfCycleCounter::open() {
            Ok(counter) => {
                assert!(counter.pmu_count() >= 1);
                eprintln!("perf: {} PMU event(s)", counter.pmu_count());
            }
            Err(e) => {
                // Not a failure: containers and VMs routinely deny this.
                eprintln!("perf unavailable on this host: {e}");
            }
        }
    }

    #[test]
    fn counter_advances_over_real_work() {
        let Some(before) = read_thread_cycles() else {
            return;
        };
        let mut acc = 0u64;
        for i in 0..200_000u64 {
            acc = acc.wrapping_add(i).rotate_left(3);
        }
        std::hint::black_box(acc);
        let after = read_thread_cycles().expect("counter was available a moment ago");
        assert!(
            after > before,
            "200k iterations produced no cycles: {before} -> {after}"
        );
    }

    /// The regression this module was rewritten for: on a hybrid CPU a single
    /// generic event reads zero whenever the thread runs on the other core
    /// type, so every exposed CPU PMU must get its own event.
    #[test]
    fn every_cpu_pmu_gets_an_event() {
        let expected = ["cpu_core", "cpu_atom"]
            .iter()
            .filter(|pmu| read_pmu_type(pmu).is_some())
            .count()
            .max(1);
        let Ok(counter) = PerfCycleCounter::open() else {
            return;
        };
        assert_eq!(
            counter.pmu_count(),
            expected,
            "a hybrid CPU needs one event per core type or it reads zero on half of them"
        );
    }

    /// Reads must survive the thread bouncing between core types.
    #[test]
    fn counter_survives_migration_across_core_types() {
        if !is_available() {
            return;
        }
        let mut last = read_thread_cycles().expect("counter available");
        for _ in 0..20 {
            let mut acc = 0u64;
            for i in 0..100_000u64 {
                acc = acc.wrapping_add(i).rotate_left(3);
            }
            std::hint::black_box(acc);
            // Yield so the scheduler is free to move us between P and E cores.
            std::thread::yield_now();
            let now = read_thread_cycles().expect("counter available");
            assert!(
                now >= last,
                "cycle count went backwards across a migration: {last} -> {now}"
            );
            last = now;
        }
        assert!(last > 0);
    }

    /// Multiplexing correction has to survive a real read: a counter that
    /// was descheduled must be scaled up, never reported raw.
    #[test]
    fn reads_are_scaled_and_monotonic() {
        let Ok(counter) = PerfCycleCounter::open() else {
            return;
        };
        let Some(first) = counter.read() else {
            return;
        };
        let mut acc = 0u64;
        for i in 0..200_000u64 {
            acc = acc.wrapping_add(i).rotate_left(3);
        }
        std::hint::black_box(acc);
        let second = counter.read().expect("counter stayed available");
        assert!(
            second > first,
            "counter did not advance: {first} -> {second}"
        );

        // The syscall path is the only path; both accessors must agree.
        let direct = counter.read_syscall().expect("syscall read");
        assert!(direct >= second, "read_syscall {direct} < read {second}");
    }

    /// Each thread must get its own counter, or readings cross-contaminate.
    #[test]
    fn each_thread_counts_its_own_cycles() {
        if !is_available() {
            return;
        }
        // Open this thread's counter *before* doing the work it is meant to
        // measure. `THREAD_COUNTER` is a lazily-initialised thread-local, so
        // the first read is what creates the event — and an earlier version
        // of this test burned two million iterations first, which the counter
        // therefore did not exist for. Both threads then reported a few
        // thousand cycles of scheduling noise and the assertion below became
        // a coin flip: it failed about one run in five and, worse, told the
        // truth about nothing on the other four.
        read_thread_cycles().expect("counter available");

        let mut acc = 0u64;
        for i in 0..40_000_000u64 {
            acc = acc.wrapping_add(i).rotate_left(3);
        }
        std::hint::black_box(acc);
        let this_thread = read_thread_cycles().expect("counter available");
        assert!(
            this_thread > 1_000_000,
            "the counter reported {this_thread} cycles for forty million \
             iterations; it is not counting"
        );

        let other_thread = std::thread::spawn(|| read_thread_cycles().unwrap_or(0))
            .join()
            .expect("counter thread");

        // An order of magnitude. If the counter were shared the two would be
        // within a hair of each other, so this separates the two outcomes
        // with room to spare in either direction.
        assert!(
            other_thread.saturating_mul(8) < this_thread,
            "a fresh thread reported {other_thread} against this thread's {this_thread}; \
             the counter is shared when it should be per-thread"
        );
    }

    #[test]
    fn availability_is_resolved_once() {
        assert_eq!(is_available(), is_available());
    }

    #[test]
    fn multiplexing_is_scaled_out() {
        // Ran for half the time it was enabled: the true count is double.
        assert_eq!(
            scale(ReadFormat {
                value: 500,
                time_enabled: 1000,
                time_running: 500,
            }),
            1000
        );
        // Never ran: no estimate is possible.
        assert_eq!(
            scale(ReadFormat {
                value: 0,
                time_enabled: 1000,
                time_running: 0,
            }),
            0
        );
        // Ran the whole time: reported as-is, with no rounding drift.
        assert_eq!(
            scale(ReadFormat {
                value: 1234,
                time_enabled: 1000,
                time_running: 1000,
            }),
            1234
        );
    }

    #[test]
    fn attr_is_the_size_the_kernel_expects() {
        let attr = PerfEventAttr::default();
        assert_eq!(attr.size as usize, std::mem::size_of::<PerfEventAttr>());
        // PERF_ATTR_SIZE_VER0 is 64; anything smaller is rejected outright.
        assert!(attr.size >= 64);
        assert_eq!(attr.flags, 0);
    }

    #[test]
    fn hybrid_configs_encode_the_pmu_type() {
        for config in cycle_event_configs() {
            assert_eq!(config & 0xFFFF_FFFF, PERF_COUNT_HW_CPU_CYCLES);
            let pmu = (config >> PERF_PMU_TYPE_SHIFT) as u32;
            if pmu != 0 {
                assert!(
                    read_pmu_type("cpu_core") == Some(pmu)
                        || read_pmu_type("cpu_atom") == Some(pmu),
                    "config names PMU type {pmu}, which is neither cpu_core nor cpu_atom"
                );
            }
        }
    }
}
