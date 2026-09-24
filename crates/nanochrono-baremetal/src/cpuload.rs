// SPDX-License-Identifier: Apache-2.0
//! CPU load and effective frequency, the way a task manager shows them —
//! from the hardware's own activity counters rather than from guesses.
//!
//! # What "load" means with no operating system
//!
//! One core runs this kernel and nothing else, so there is no run queue to
//! sample. What there is:
//!
//! * **Active time** — how much of an interval the core spent executing
//!   rather than stopped in a low-power wait. The architectures count this
//!   themselves:
//!   - x86: `MPERF` (MSR `0xE7`) ticks at the TSC rate only in C0, so
//!     ΔMPERF / ΔTSC is the C0 residency.
//!   - AArch64: the Activity Monitors' constant-frequency counter
//!     (`AMEVCNTR01_EL0`, `CNT_CYCLES`) ticks at the system-counter rate only
//!     while the core is not in WFI/WFE, so ΔAMEVCNTR01 / ΔCNTVCT is the
//!     same ratio.
//!   - POWER: `PURR` (SPR 309) accumulates at the Time Base rate in
//!     proportion to the dispatch share this thread received, so ΔPURR / ΔTB
//!     is this thread's utilization.
//! * **Effective frequency** — core cycles per reference tick: ΔAPERF/ΔMPERF
//!   on x86, ΔAMEVCNTR00/ΔAMEVCNTR01 on AArch64 (both scaled by the reference
//!   rate), or, lacking those, the PMU's cycle counter (or RISC-V `cycle`)
//!   against the fixed-rate counter.
//! * **IPC** — instructions per cycle, from AMU `INST_RETIRED`, RISC-V
//!   `instret`, or the PMU when the caller has one running.
//! * **Where the time went** — the kernel's own loop, split into named
//!   [`Task`]s. That is the process list of this task manager: the only
//!   "processes" on the machine are the phases of its one loop.
//!
//! # Idle has to be real for any of this to mean something
//!
//! A busy-poll loop is 100% active by every counter above, correctly. So the
//! wait between frames uses the architecture's low-power wait where one can
//! wake without interrupts (this kernel runs with them masked): `TPAUSE` with
//! a TSC deadline on x86 (WAITPKG), and `WFE` woken by the generic timer's
//! event stream on AArch64. Elsewhere it is a low-priority spin, and the
//! active figure says 100% — which is then the truth.

use core::sync::atomic::{AtomicU8, Ordering};

/// Per-task tick accumulators. 64-bit where the target has 64-bit atomics;
/// 32-bit PowerPC and RV32 do not, and there the accumulators (and the
/// timestamp they subtract from) keep the low 32 bits — ample for a refresh
/// window, which is a second or so of ticks at a few hundred MHz.
#[cfg(target_has_atomic = "64")]
type TickCell = core::sync::atomic::AtomicU64;
#[cfg(target_has_atomic = "64")]
type Tick = u64;
#[cfg(not(target_has_atomic = "64"))]
type TickCell = core::sync::atomic::AtomicU32;
#[cfg(not(target_has_atomic = "64"))]
type Tick = u32;

/// Where the active-time and frequency figures come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// x86 `APERF`/`MPERF`.
    AperfMperf,
    /// AArch64 Activity Monitors (AMU).
    Amu,
    /// POWER `PURR` (utilization), with the PMU for frequency if present.
    Purr,
    /// RISC-V `cycle`/`instret` against `time`: frequency and IPC, no
    /// active-time figure (whether `cycle` stops in a wait is up to the
    /// implementation).
    Cycles,
    /// No activity counters: frequency and IPC from the PMU if it runs, plus
    /// the loop's own accounting.
    None,
}

impl Source {
    pub const fn name(self) -> &'static str {
        match self {
            Source::AperfMperf => "APERF/MPERF",
            Source::Amu => "AMU (activity monitors)",
            Source::Purr => "PURR",
            Source::Cycles => "cycle/instret CSRs",
            Source::None => "PMU and loop accounting",
        }
    }
}

static SOURCE: AtomicU8 = AtomicU8::new(u8::MAX);

fn source_from_u8(v: u8) -> Source {
    match v {
        0 => Source::AperfMperf,
        1 => Source::Amu,
        2 => Source::Purr,
        3 => Source::Cycles,
        _ => Source::None,
    }
}

const fn source_to_u8(s: Source) -> u8 {
    match s {
        Source::AperfMperf => 0,
        Source::Amu => 1,
        Source::Purr => 2,
        Source::Cycles => 3,
        Source::None => 4,
    }
}

/// The source [`init`] settled on.
pub fn source() -> Source {
    source_from_u8(SOURCE.load(Ordering::Relaxed))
}

/// Detects (and where this level owns it, enables) the activity counters.
///
/// # Safety
/// Ring 0 / EL1+ / supervisor, once, before [`sample`].
pub unsafe fn init() -> Source {
    // SAFETY: forwarded from this function's contract.
    let s = unsafe { arch::init() };
    SOURCE.store(source_to_u8(s), Ordering::Relaxed);
    s
}

/// One reading of every counter involved.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sample {
    /// The fixed-rate reference: TSC, CNTVCT/CNTPCT, Time Base, `time`.
    pub reference: u64,
    /// Active time, in reference ticks (MPERF, AMU constant cycles, PURR).
    pub active: Option<u64>,
    /// Core cycles (APERF, AMU core cycles, PMU cycles, `cycle`).
    pub cycles: Option<u64>,
    /// Instructions retired.
    pub instructions: Option<u64>,
    /// Width in bits of the cycle and instruction counters, so a wrap
    /// between two samples is a short interval rather than 2⁶⁴ of one. PMU
    /// counters are often 32 or 48 bits; the architectural activity
    /// counters are 64.
    pub cycles_width: u8,
    pub instructions_width: u8,
}

/// Reads every counter the source provides, filling cycles and instructions
/// from `pmu` where the activity counters have none (x86 without APERF,
/// AArch64 without AMU, POWER, e500): the PMU's cycle counter against the
/// fixed-rate reference still gives the effective frequency, and with an
/// instruction counter the IPC.
///
/// # Safety
/// After [`init`], at the same privilege level; `pmu` enabled on this core.
pub unsafe fn sample(pmu: Option<&crate::pmu::CorePmu>) -> Sample {
    // SAFETY: forwarded from this function's contract.
    let mut s = unsafe { arch::sample(source()) };
    s.cycles_width = 64;
    s.instructions_width = 64;
    if let Some(pmu) = pmu {
        if s.cycles.is_none() {
            // SAFETY: forwarded; the PMU was enabled by the caller.
            s.cycles = unsafe { pmu.read_cycles() }.map(|r| r.value);
            s.cycles_width = match pmu.route {
                crate::pmu::CounterRoute::General(_) => pmu.leaf.general_width,
                _ => pmu.leaf.fixed_width,
            };
        }
        if s.instructions.is_none() {
            // SAFETY: as above.
            s.instructions = unsafe { pmu.read_instructions() }.map(|r| r.value);
            s.instructions_width = if cfg!(target_arch = "aarch64") { 32 } else { pmu.leaf.fixed_width };
        }
    }
    s
}

/// What happened between two samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Load {
    /// Active time as a share of the interval, in tenths of a percent.
    pub active_permille: Option<u32>,
    /// Effective core frequency, in kHz.
    pub frequency_khz: Option<u64>,
    /// Instructions per cycle, in hundredths.
    pub ipc_x100: Option<u32>,
}

/// Compares two samples. `reference_hz` is the reference counter's rate.
pub fn between(earlier: &Sample, later: &Sample, reference_hz: u64) -> Load {
    let reference = later.reference.wrapping_sub(earlier.reference);
    if reference == 0 {
        return Load::default();
    }
    let delta = |a: Option<u64>, b: Option<u64>, width: u8| {
        Some(nanochrono_core::pmu_leaf::mask_to_width(b?.wrapping_sub(a?), width))
    };
    let active = delta(earlier.active, later.active, 64);
    let cycles = delta(earlier.cycles, later.cycles, later.cycles_width);
    let instructions = delta(earlier.instructions, later.instructions, later.instructions_width);

    let active_permille = active.map(|a| ((a.min(reference) as u128 * 1000) / reference as u128) as u32);
    // Frequency: cycles per *active* reference tick where the active count
    // exists (APERF/MPERF, AMU) — the frequency while running, which is what
    // "effective frequency" means — else per wall-clock tick.
    let frequency_khz = cycles.and_then(|c| {
        let base = active.filter(|&a| a > 0).unwrap_or(reference);
        (reference_hz > 0).then(|| ((c as u128 * reference_hz as u128) / base as u128 / 1000) as u64)
    });
    let ipc_x100 = match (instructions, cycles) {
        (Some(i), Some(c)) if c > 0 => Some(((i as u128 * 100) / c as u128) as u32),
        _ => None,
    };
    Load {
        active_permille,
        frequency_khz,
        ipc_x100,
    }
}

// ---------------------------------------------------------------------------
// The loop's own accounting: the "process list"
// ---------------------------------------------------------------------------

/// The phases of the kernel's one loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Task {
    /// Drawing into the back buffer (or formatting the text screen).
    Render = 0,
    /// Copying to the framebuffer / writing to the console.
    Present = 1,
    /// Polling keyboard, pointer, USB, I2C, the UART.
    Input = 2,
    /// Measurement work: counters, PMU, probes.
    Measure = 3,
    /// Waiting for the next frame (a real low-power wait where available).
    Idle = 4,
}

impl Task {
    pub const ALL: [Task; 5] = [Task::Render, Task::Present, Task::Input, Task::Measure, Task::Idle];

    pub const fn name(self) -> &'static str {
        match self {
            Task::Render => "render",
            Task::Present => "present",
            Task::Input => "input",
            Task::Measure => "measure",
            Task::Idle => "idle",
        }
    }
}

static TASK_TICKS: [TickCell; 5] = [const { TickCell::new(0) }; 5];
static CURRENT: AtomicU8 = AtomicU8::new(Task::Measure as u8);
static SINCE: TickCell = TickCell::new(0);

/// Charges the time since the last switch to the task that was running, and
/// makes `task` current. Cheap: one counter read and two relaxed stores.
pub fn switch_to(task: Task) {
    let now = crate::arch::counter_ordered() as Tick;
    let since = SINCE.swap(now, Ordering::Relaxed);
    let current = CURRENT.swap(task as u8, Ordering::Relaxed) as usize;
    if since != 0 {
        if let Some(slot) = TASK_TICKS.get(current) {
            slot.fetch_add(now.wrapping_sub(since), Ordering::Relaxed);
        }
    }
}

/// The accumulated ticks per task since the last call, and the reset.
pub fn take_task_ticks() -> [u64; 5] {
    // Charge the running task up to now first, so the window is complete.
    switch_to(source_task());
    let mut out = [0u64; 5];
    for (i, slot) in TASK_TICKS.iter().enumerate() {
        out[i] = u64::from(slot.swap(0, Ordering::Relaxed));
    }
    out
}

fn source_task() -> Task {
    match CURRENT.load(Ordering::Relaxed) {
        0 => Task::Render,
        1 => Task::Present,
        2 => Task::Input,
        4 => Task::Idle,
        _ => Task::Measure,
    }
}

/// Waits until the reference counter reaches `deadline`, as idle as this
/// architecture can manage without interrupts; charged to [`Task::Idle`].
pub fn idle_until(deadline: u64) {
    let previous = source_task();
    switch_to(Task::Idle);
    arch::idle_until(deadline);
    switch_to(previous);
}

/// How [`idle_until`] waits here.
pub fn idle_method() -> &'static str {
    arch::idle_method()
}

// ---------------------------------------------------------------------------
// Per-architecture halves
// ---------------------------------------------------------------------------

#[cfg(x86_any)]
mod arch {
    use super::{Sample, Source};
    use crate::arch::x86::{cpuid, rdmsr};
    use core::sync::atomic::{AtomicBool, Ordering};

    const IA32_MPERF: u32 = 0xE7;
    const IA32_APERF: u32 = 0xE8;

    static WAITPKG: AtomicBool = AtomicBool::new(false);

    pub(super) unsafe fn init() -> Source {
        // CPUID.07H:ECX[5]: TPAUSE/UMWAIT.
        WAITPKG.store(cpuid(0, 0)[0] >= 7 && cpuid(7, 0)[2] & (1 << 5) != 0, Ordering::Relaxed);
        // CPUID.06H:ECX[0]: the APERF/MPERF pair exists. Read only then: an
        // absent MSR is #GP, not zero (KVM, for one, may not expose them).
        if cpuid(0, 0)[0] >= 6 && cpuid(6, 0)[2] & 1 != 0 {
            Source::AperfMperf
        } else {
            Source::None
        }
    }

    pub(super) unsafe fn sample(source: Source) -> Sample {
        let reference = crate::arch::counter_ordered();
        if source != Source::AperfMperf {
            return Sample { reference, ..Default::default() };
        }
        // SAFETY: `init` confirmed both MSRs through CPUID; ring 0.
        let (mperf, aperf) = unsafe { (rdmsr(IA32_MPERF), rdmsr(IA32_APERF)) };
        Sample {
            reference,
            active: Some(mperf),
            cycles: Some(aperf),
            instructions: None,
            ..Default::default()
        }
    }

    pub(super) fn idle_until(deadline: u64) {
        if WAITPKG.load(Ordering::Relaxed) {
            // TPAUSE: sleep in C0.2 (EDX:EAX = TSC deadline, ECX bit 0 = 0
            // selects the deeper C0.2) until the deadline or an event. The
            // OS-imposed cap (IA32_UMWAIT_CONTROL) may cut each wait short,
            // hence the loop.
            while crate::arch::counter_ordered() < deadline {
                // SAFETY: WAITPKG is present; TPAUSE has no memory effects.
                unsafe {
                    core::arch::asm!(
                        "tpause ecx",
                        in("ecx") 0u32,
                        in("eax") deadline as u32,
                        in("edx") (deadline >> 32) as u32,
                        options(nomem, nostack),
                    );
                }
            }
        } else {
            while crate::arch::counter_ordered() < deadline {
                core::hint::spin_loop();
            }
        }
    }

    pub(super) fn idle_method() -> &'static str {
        if WAITPKG.load(Ordering::Relaxed) {
            "TPAUSE (C0.2) to a TSC deadline"
        } else {
            "PAUSE spin (no WAITPKG): the core stays active"
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arch {
    use super::{Sample, Source};
    use core::arch::asm;
    use core::sync::atomic::{AtomicBool, Ordering};

    static EVENT_STREAM: AtomicBool = AtomicBool::new(false);

    /// `ID_AA64PFR0_EL1.AMU`, bits [47:44]: 0 = none, 1 = AMUv1, 2 = AMUv1p1.
    fn amu_version() -> u64 {
        let v: u64;
        // SAFETY: ID registers are readable at EL1 and above.
        unsafe { asm!("mrs {v}, ID_AA64PFR0_EL1", v = out(reg) v, options(nomem, nostack, preserves_flags)) };
        (v >> 44) & 0xF
    }

    fn el3_implemented() -> bool {
        let v: u64;
        // SAFETY: as above.
        unsafe { asm!("mrs {v}, ID_AA64PFR0_EL1", v = out(reg) v, options(nomem, nostack, preserves_flags)) };
        (v >> 12) & 0xF != 0
    }

    pub(super) unsafe fn init() -> Source {
        let el = crate::arch::arm::current_el();

        // The event stream: CNTKCTL_EL1.EVNTEN (bit 2) with EVNTI (bits 7:4)
        // choosing which counter bit's transition raises an event — bit 10
        // of CNTVCT is ~1 µs at 1 GHz, ~40 µs at 24 MHz. That is what wakes
        // WFE with interrupts masked, and it is what makes idle real.
        // SAFETY: CNTKCTL_EL1 is readable and writable at EL1 and above.
        unsafe {
            let mut v: u64;
            asm!("mrs {v}, CNTKCTL_EL1", v = out(reg) v, options(nomem, nostack, preserves_flags));
            v = (v & !0xF0) | (10 << 4) | (1 << 2);
            asm!("msr CNTKCTL_EL1, {v}", "isb", v = in(reg) v, options(nomem, nostack, preserves_flags));
        }
        EVENT_STREAM.store(true, Ordering::Relaxed);

        if amu_version() == 0 {
            return Source::None;
        }
        // Untrap the AMU at the levels this kernel owns (CPTR_ELx.TAM, bit
        // 30). A lower level cannot, and does not need to: firmware that
        // enabled the counters also left them reachable, or reading faults
        // and the entry stub's vectors say so.
        // SAFETY: each register is touched only at its own level.
        unsafe {
            if el == 2 {
                asm!("mrs {t}, CPTR_EL2", "bic {t}, {t}, #(1 << 30)", "msr CPTR_EL2, {t}", "isb",
                     t = out(reg) _, options(nomem, nostack, preserves_flags));
            }
            if el == 3 {
                asm!("mrs {t}, CPTR_EL3", "bic {t}, {t}, #(1 << 30)", "msr CPTR_EL3, {t}", "isb",
                     t = out(reg) _, options(nomem, nostack, preserves_flags));
            }
        }
        // Enabling the architected group 0 is reserved to the highest
        // implemented EL (the write is UNDEFINED anywhere else). This kernel
        // is that level at EL3, or at EL2 on a part without EL3.
        let highest = el == 3 || (el == 2 && !el3_implemented());
        if highest {
            // SAFETY: highest EL: AMCNTENSET0_EL0 (S3_3_C13_C2_5) is writable.
            // Bits 0-3: core cycles, constant cycles, instructions, stalls.
            unsafe {
                asm!("msr S3_3_C13_C2_5, {v}", "isb", v = in(reg) 0xFu64,
                     options(nomem, nostack, preserves_flags));
            }
        }
        let enabled: u64;
        // SAFETY: AMCNTENSET0_EL0 is readable at EL1+ once untrapped.
        unsafe { asm!("mrs {v}, S3_3_C13_C2_5", v = out(reg) enabled, options(nomem, nostack, preserves_flags)) };
        if enabled & 0b111 == 0b111 {
            Source::Amu
        } else {
            // Firmware left the architected counters off, and this level may
            // not turn them on.
            Source::None
        }
    }

    pub(super) unsafe fn sample(source: Source) -> Sample {
        let reference = crate::arch::counter_ordered();
        match source {
            Source::Amu => {
                let (core, constant, inst): (u64, u64, u64);
                // SAFETY: `init` confirmed counters 0-2 are enabled and
                // reachable. AMEVCNTR0<n>_EL0 = S3_3_C13_C4_<n>.
                unsafe {
                    asm!(
                        "mrs {a}, S3_3_C13_C4_0",
                        "mrs {b}, S3_3_C13_C4_1",
                        "mrs {c}, S3_3_C13_C4_2",
                        a = out(reg) core,
                        b = out(reg) constant,
                        c = out(reg) inst,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                Sample {
                    reference,
                    active: Some(constant),
                    cycles: Some(core),
                    instructions: Some(inst),
                    ..Default::default()
                }
            }
            _ => Sample { reference, ..Default::default() },
        }
    }

    pub(super) fn idle_until(deadline: u64) {
        if EVENT_STREAM.load(Ordering::Relaxed) {
            while crate::arch::counter_ordered() < deadline {
                // SAFETY: WFE waits for an event; the event stream supplies
                // one within microseconds, with interrupts masked or not.
                unsafe { asm!("wfe", options(nomem, nostack, preserves_flags)) };
            }
        } else {
            while crate::arch::counter_ordered() < deadline {
                core::hint::spin_loop();
            }
        }
    }

    pub(super) fn idle_method() -> &'static str {
        "WFE, woken by the generic timer's event stream"
    }
}

#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
mod arch {
    use super::{Sample, Source};

    /// PURR exists on 64-bit Book3S from POWER5 on.
    fn has_purr() -> bool {
        #[cfg(target_arch = "powerpc64")]
        {
            matches!(crate::arch::ppc::pvr() >> 16, 0x003A..=0x003B | 0x003E | 0x003F | 0x004A..=0x004E | 0x0080 | 0x0082)
        }
        #[cfg(not(target_arch = "powerpc64"))]
        {
            false
        }
    }

    pub(super) unsafe fn init() -> Source {
        if has_purr() {
            Source::Purr
        } else {
            Source::None
        }
    }

    pub(super) unsafe fn sample(source: Source) -> Sample {
        let reference = crate::arch::counter_ordered();
        #[cfg(target_arch = "powerpc64")]
        if source == Source::Purr {
            let purr: u64;
            // SAFETY: `init` confirmed PURR (SPR 309) on this core;
            // supervisor/hypervisor read.
            unsafe {
                core::arch::asm!("mfspr {v}, 309", v = out(reg) purr, options(nomem, nostack, preserves_flags));
            }
            return Sample { reference, active: Some(purr), ..Default::default() };
        }
        let _ = source;
        Sample { reference, ..Default::default() }
    }

    pub(super) fn idle_until(deadline: u64) {
        while crate::arch::counter_ordered() < deadline {
            // Lowest SMT priority while spinning: the sibling threads get
            // the core, and PURR charges this thread less of it.
            // SAFETY: a priority hint.
            unsafe { core::arch::asm!("or 1, 1, 1", options(nomem, nostack, preserves_flags)) };
        }
        // SAFETY: back to medium priority.
        unsafe { core::arch::asm!("or 2, 2, 2", options(nomem, nostack, preserves_flags)) };
    }

    pub(super) fn idle_method() -> &'static str {
        "low-priority spin (no wait instruction without interrupts)"
    }
}

/// 32-bit ARM: no PMU driven yet, so load is the reference counter's
/// busy/idle split alone.
#[cfg(target_arch = "arm")]
mod arch {
    use super::{Sample, Source};

    pub(super) unsafe fn init() -> Source {
        Source::None
    }

    pub(super) unsafe fn sample(_source: Source) -> Sample {
        Sample { reference: crate::arch::counter_ordered(), ..Default::default() }
    }

    pub(super) fn idle_until(deadline: u64) {
        // WFI would never wake with interrupts off; YIELD is the hint.
        while crate::arch::counter_ordered() < deadline {
            // SAFETY: YIELD is a hint with no architectural effect.
            unsafe { core::arch::asm!("yield", options(nomem, nostack, preserves_flags)) };
        }
    }

    pub(super) fn idle_method() -> &'static str {
        "YIELD spin (WFI cannot wake with interrupts off)"
    }
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
mod arch {
    use super::{Sample, Source};

    pub(super) unsafe fn init() -> Source {
        if crate::arch::riscv::cycle_readable() {
            Source::Cycles
        } else {
            Source::None
        }
    }

    pub(super) unsafe fn sample(source: Source) -> Sample {
        let reference = crate::arch::counter_ordered();
        if source != Source::Cycles {
            return Sample { reference, ..Default::default() };
        }
        use nanochrono_core::arch::riscv as rv;
        // SAFETY: `init` proved `cycle` readable; `instret` is asked
        // separately because firmware may allow one and not the other.
        let cycles = unsafe { rv::rdcycle_raw() };
        let instructions = crate::arch::riscv::instret_readable()
            // SAFETY: just proved readable.
            .then(|| unsafe { rv::rdinstret_raw() });
        Sample {
            reference,
            active: None,
            cycles: Some(cycles),
            instructions,
            ..Default::default()
        }
    }

    pub(super) fn idle_until(deadline: u64) {
        // WFI would never wake with interrupts off; PAUSE is the hint.
        while crate::arch::counter_ordered() < deadline {
            nanochrono_core::arch::riscv::pause();
        }
    }

    pub(super) fn idle_method() -> &'static str {
        "PAUSE spin (WFI cannot wake with interrupts off)"
    }
}
