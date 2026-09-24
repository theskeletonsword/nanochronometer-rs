// SPDX-License-Identifier: Apache-2.0
//! Time, with no timer interrupt and no kernel to ask.
//!
//! A hosted build asks the operating system what time it is and how fast the
//! counter runs. Neither question has an answer here, and the usual way a
//! kernel answers them — programme a timer, take an interrupt, count ticks —
//! is exactly what this project must not do: an interrupt handler running
//! between two counter reads is part of what the chronometer would then be
//! measuring, and there is no IDT anyway.
//!
//! So everything is derived from the counter itself, and read by polling:
//!
//! * **How fast the counter runs.** `CPUID.15H` states it exactly, as a ratio
//!   against the core crystal, on every part since Skylake. Where that leaf
//!   is absent or incomplete the PIT is used as a reference — gated by hand
//!   through port 0x61 and polled, never through IRQ 0.
//! * **What time it is.** The CMOS real-time clock, read once at startup.
//!   It has one-second resolution, so it fixes the offset and the counter
//!   supplies everything below a second.
//!
//! The result is a clock with nanosecond resolution whose only moving part is
//! `RDTSC`, which is the same instruction the measurements use. That is the
//! point: the displayed time and the measured interval come from one source,
//! so they cannot disagree.

#[cfg(x86_any)]
use crate::arch::x86::{cpuid, inb, outb};
#[cfg(x86_any)]
use nanochrono_core::cpu::vendor;

/// Nanoseconds per second, and the rest of the ladder.
pub const NS_PER_US: u64 = 1_000;
pub const NS_PER_MS: u64 = 1_000_000;
pub const NS_PER_S: u64 = 1_000_000_000;

/// The counter's rate, and how it was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Calibration {
    /// Counter ticks per second.
    pub hz: u64,
    pub source: Source,
}

/// Where the frequency came from. Reported rather than hidden: an exact
/// figure from `CPUID.15H` and a measured one from a 1.19 MHz timer are not
/// the same quality of answer, and a reading is only as good as its rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `CPUID.15H`: crystal frequency times a ratio the part states. Exact.
    CrystalRatio,
    /// `CPUID.40000010H`, the KVM leaf. Exact, and what the host is using.
    Hypervisor,
    /// `CPUID.16H`, the nominal base frequency in MHz. Rounded to a whole
    /// megahertz by the leaf itself, so good to about one part in a thousand.
    ///
    /// Intel only, for the same reason as [`Source::CrystalRatio`].
    BaseFrequency,
    /// Measured against the 8254 PIT.
    Pit,
    /// Stated by the architecture: `CNTFRQ_EL0` on ARM, the devicetree's
    /// `timebase-frequency` on POWER and RISC-V. No calibration to do.
    Architectural,
    /// Nothing worked; the rate is a guess and times are not shown.
    Unknown,
}

impl Source {
    pub const fn name(self) -> &'static str {
        match self {
            Source::CrystalRatio => "cpuid 15h",
            Source::Hypervisor => "kvm leaf",
            Source::BaseFrequency => "cpuid 16h",
            Source::Pit => "8254 pit",
            Source::Architectural => "architectural",
            Source::Unknown => "unknown",
        }
    }

    /// Whether times derived from this rate are worth displaying.
    pub const fn trustworthy(self) -> bool {
        !matches!(self, Source::Unknown)
    }
}

/// A rate that is obviously wrong is worse than no rate: it turns every
/// duration on screen into a confident fiction. Anything outside this band is
/// rejected and the next method tried.
#[cfg(x86_any)]
const PLAUSIBLE: core::ops::RangeInclusive<u64> = 100_000_000..=100_000_000_000;

impl Calibration {
    /// Establishes the counter's rate, trying the exact methods first.
    ///
    /// # Safety
    /// Drives the PIT through I/O ports in the fallback path; requires ring 0
    /// and that nothing else is using timer channel 2.
    pub unsafe fn measure() -> Calibration {
        // Everywhere but x86 the counter's rate is part of the architecture:
        // there is nothing to measure, only something to read.
        #[cfg(not(x86_any))]
        {
            match nanochrono_core::arch::declared_counter_hz() {
                Some(hz) if hz > 0 => Calibration { hz, source: Source::Architectural },
                _ => Calibration { hz: 1_000_000_000, source: Source::Unknown },
            }
        }
        // SAFETY: forwarded from this function's own contract.
        #[cfg(x86_any)]
        unsafe {
            Self::measure_x86()
        }
    }

    /// The x86 search: exact leaves first, the PIT as the fallback.
    ///
    /// # Safety
    /// As [`measure`](Self::measure).
    #[cfg(x86_any)]
    unsafe fn measure_x86() -> Calibration {
        if let Some(hz) = hypervisor_tsc_hz() {
            return Calibration {
                hz,
                source: Source::Hypervisor,
            };
        }
        if let Some(hz) = crystal_tsc_hz() {
            return Calibration {
                hz,
                source: Source::CrystalRatio,
            };
        }
        // SAFETY: forwarded from this function's own contract.
        if let Some(hz) = unsafe { pit_tsc_hz() } {
            return Calibration {
                hz,
                source: Source::Pit,
            };
        }
        if let Some(hz) = base_frequency_tsc_hz() {
            return Calibration {
                hz,
                source: Source::BaseFrequency,
            };
        }
        Calibration {
            // A rate that makes the arithmetic below harmless rather than
            // dividing by zero. Nothing derived from it is displayed.
            hz: 1_000_000_000,
            source: Source::Unknown,
        }
    }

    /// Converts a counter interval to nanoseconds.
    ///
    /// The multiply is done in 128 bits. At 3 GHz a `u64` product overflows
    /// after about six seconds of elapsed time, which a stopwatch reaches
    /// immediately — this is the difference between a stopwatch and a
    /// stopwatch that wraps to zero while you watch it.
    pub fn ticks_to_ns(&self, ticks: u64) -> u64 {
        if self.hz == 0 {
            return 0;
        }
        ((ticks as u128 * NS_PER_S as u128) / self.hz as u128) as u64
    }

    /// The inverse, for turning a duration into a deadline.
    pub fn ns_to_ticks(&self, ns: u64) -> u64 {
        ((ns as u128 * self.hz as u128) / NS_PER_S as u128) as u64
    }

    /// The rate in megahertz, for display.
    pub fn mhz(&self) -> u64 {
        self.hz / 1_000_000
    }
}

#[cfg(x86_any)]
/// `CPUID.15H`: TSC = crystal * numerator / denominator.
fn crystal_tsc_hz() -> Option<u64> {
    // Intel only, and this is not caution for its own sake — it is the rule
    // Linux applies in `native_calibrate_tsc`, which returns zero for every
    // other vendor before it looks at the leaf at all. Zhaoxin parts are the
    // reason it matters here: they are x86-64 with Intel-style architectural
    // leaves, they may well answer `15H`, and code that treats "not AMD" as
    // "Intel" takes the answer. If it is wrong, it is wrong in the one number
    // every later measurement is divided by — so a part outside the rule
    // falls through to the PIT, which measures rather than asks.
    if !vendor().states_a_trustworthy_tsc_rate() {
        return None;
    }
    if cpuid(0, 0)[0] < 0x15 {
        return None;
    }
    let [denominator, numerator, crystal, _] = cpuid(0x15, 0);
    if denominator == 0 || numerator == 0 {
        return None;
    }
    // Some parts report the ratio but leave the crystal frequency zero. The
    // values below are the documented defaults for those families; anything
    // else is left to the PIT rather than guessed at.
    let crystal = if crystal != 0 {
        crystal as u64
    } else {
        match cpuid(0x16, 0)[0] {
            // Only used to tell a family apart, not as a frequency.
            0 => return None,
            _ => 24_000_000,
        }
    };
    let hz = crystal * numerator as u64 / denominator as u64;
    PLAUSIBLE.contains(&hz).then_some(hz)
}

#[cfg(x86_any)]
/// `CPUID.16H`: the nominal base frequency, in megahertz.
///
/// Not the TSC rate in general — the TSC runs at the *base* frequency while
/// the core boosts above it, which is precisely why it is invariant — but on
/// the parts that reach here the two are the same number.
fn base_frequency_tsc_hz() -> Option<u64> {
    // Intel only: Linux's `cpu_khz_from_cpuid` refuses every other vendor
    // before reading the leaf. See `crystal_tsc_hz`.
    if !vendor().states_a_trustworthy_tsc_rate() {
        return None;
    }
    if cpuid(0, 0)[0] < 0x16 {
        return None;
    }
    let mhz = cpuid(0x16, 0)[0] as u64;
    let hz = mhz * 1_000_000;
    PLAUSIBLE.contains(&hz).then_some(hz)
}

#[cfg(x86_any)]
/// `CPUID.40000010H:EAX`: the TSC frequency in kHz, as the hypervisor set it.
///
/// Exact by construction under KVM, because the host chose the number this
/// leaf reports. Checked against the signature first: the hypervisor leaf
/// range is a convention, and a range of leaves that exists proves nothing
/// about what any individual one returns.
fn hypervisor_tsc_hz() -> Option<u64> {
    // Bit 31 of `CPUID.1H:ECX` is the hypervisor-present flag. Without it the
    // 0x4000_0000 range is not architecturally defined at all.
    if cpuid(1, 0)[2] & (1 << 31) == 0 {
        return None;
    }
    let [max, ..] = cpuid(0x4000_0000, 0);
    if max < 0x4000_0010 {
        return None;
    }
    let khz = cpuid(0x4000_0010, 0)[0] as u64;
    let hz = khz * 1_000;
    PLAUSIBLE.contains(&hz).then_some(hz)
}

#[cfg(x86_any)]
/// The 8254's input clock: 1.193182 MHz, the NTSC colourburst over three.
const PIT_HZ: u64 = 1_193_182;
#[cfg(x86_any)]
/// Channel 2 data port. The only channel wired to something a kernel can poll
/// without an interrupt controller.
const PIT_CH2: u16 = 0x42;
#[cfg(x86_any)]
const PIT_COMMAND: u16 = 0x43;
#[cfg(x86_any)]
/// The port whose bit 0 gates channel 2 and whose bit 5 mirrors its output.
const PIT_GATE: u16 = 0x61;

#[cfg(x86_any)]
/// Measures the counter against the PIT.
///
/// Channel 2 is used rather than 0 because its gate is under software control
/// and its output is readable from a port — so the whole measurement is
/// polling, with no interrupt controller, no IDT and no handler. Channel 0
/// would need IRQ 0, which is the thing this kernel must not have.
///
/// # Safety
/// Drives the PIT and the speaker gate; requires ring 0 and exclusive use of
/// timer channel 2.
unsafe fn pit_tsc_hz() -> Option<u64> {
    // 50 ms. Long enough that the counter's own read overhead is noise, short
    // enough not to be a visible pause at boot.
    const INTERVAL_TICKS: u16 = (PIT_HZ / 20) as u16;

    // SAFETY: caller guarantees ring 0 and exclusive use of channel 2.
    unsafe {
        // Bit 0 gates the counter, bit 1 routes it to the speaker. The
        // speaker bit is cleared so the measurement is silent.
        let gate = inb(PIT_GATE);
        outb(PIT_GATE, (gate & !0x02) | 0x01);

        // Channel 2, access lo/hi, mode 0 (interrupt on terminal count),
        // binary. Mode 0 drives the output line low until the count expires,
        // which is the edge polled for below.
        outb(PIT_COMMAND, 0b1011_0000);
        outb(PIT_CH2, INTERVAL_TICKS as u8);
        outb(PIT_CH2, (INTERVAL_TICKS >> 8) as u8);

        // Restarting the gate makes the counter load and begin.
        let restart = inb(PIT_GATE) & !0x01;
        outb(PIT_GATE, restart);
        outb(PIT_GATE, restart | 0x01);

        let start = crate::arch::counter_ordered();

        // Bounded: on a machine with no working PIT this bit never sets, and
        // an unbounded wait would hang the boot rather than fall through to
        // the next method. The bound is generous — several times the interval
        // even on a slow part — because a *short* one would report a wrong
        // frequency, which is worse than reporting none.
        let mut spins: u64 = 0;
        const SPIN_LIMIT: u64 = 1_000_000_000;
        while inb(PIT_GATE) & 0x20 == 0 {
            spins += 1;
            if spins > SPIN_LIMIT {
                outb(PIT_GATE, gate);
                return None;
            }
            core::hint::spin_loop();
        }

        let end = crate::arch::counter_ordered();
        outb(PIT_GATE, gate);

        let elapsed = end.wrapping_sub(start);
        if elapsed == 0 {
            return None;
        }
        let hz = elapsed * PIT_HZ / INTERVAL_TICKS as u64;
        PLAUSIBLE.contains(&hz).then_some(hz)
    }
}

// ---------------------------------------------------------------------------
// Wall clock
// ---------------------------------------------------------------------------

#[cfg(x86_any)]
const CMOS_ADDRESS: u16 = 0x70;
#[cfg(x86_any)]
const CMOS_DATA: u16 = 0x71;

/// A date and time as the RTC reports it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl DateTime {
    /// Seconds since midnight, which is all the display needs.
    pub fn seconds_of_day(&self) -> u64 {
        self.hour as u64 * 3600 + self.minute as u64 * 60 + self.second as u64
    }
}

/// Reads the CMOS real-time clock.
///
/// The RTC updates itself once a second and sets a flag while it does. Reading
/// through an update gives a mix of old and new fields — 12:59:59 becoming
/// 12:00:59 rather than 13:00:00 — so this waits for the flag to clear, reads
/// the whole set, and reads it again: if the two agree, no update happened in
/// between.
///
/// # Safety
/// Drives the CMOS index and data ports; requires ring 0.
#[cfg(x86_any)]
pub unsafe fn read_rtc() -> Option<DateTime> {
    // SAFETY: caller guarantees ring 0.
    unsafe {
        for _ in 0..8 {
            wait_for_rtc()?;
            let first = raw_rtc();
            wait_for_rtc()?;
            let second = raw_rtc();
            if first != second {
                continue;
            }

            // Register B says how the fields are encoded. Bit 2 clear means
            // BCD, which is the default on essentially every machine; bit 1
            // clear means 12-hour, where bit 7 of the hour is the PM flag.
            let format = cmos(0x0B);
            let bcd = format & 0x04 == 0;
            let twelve_hour = format & 0x02 == 0;

            let decode = |v: u8| if bcd { (v >> 4) * 10 + (v & 0x0F) } else { v };

            let raw_hour = first.3;
            let pm = twelve_hour && raw_hour & 0x80 != 0;
            let mut hour = decode(raw_hour & 0x7F);
            if twelve_hour {
                hour %= 12;
                if pm {
                    hour += 12;
                }
            }

            let year = decode(first.0) as u16;
            let dt = DateTime {
                // The register holds two digits. The century register is
                // optional and its index is only knowable from the FADT, so
                // the window is assumed instead: a machine booting this is
                // not in 1999.
                year: if year < 70 { 2000 + year } else { 1900 + year },
                month: decode(first.1),
                day: decode(first.2),
                hour,
                minute: decode(first.4),
                second: decode(first.5),
            };
            if dt.hour < 24 && dt.minute < 60 && dt.second < 60 {
                return Some(dt);
            }
        }
        None
    }
}

#[cfg(x86_any)]
/// The six fields, undecoded.
///
/// # Safety
/// Requires ring 0.
unsafe fn raw_rtc() -> (u8, u8, u8, u8, u8, u8) {
    // SAFETY: caller guarantees ring 0; CMOS reads have no side effects
    // beyond selecting the index.
    unsafe {
        (
            cmos(0x09), // year
            cmos(0x08), // month
            cmos(0x07), // day
            cmos(0x04), // hour
            cmos(0x02), // minute
            cmos(0x00), // second
        )
    }
}

#[cfg(x86_any)]
/// Waits for the update-in-progress flag to clear.
///
/// # Safety
/// Requires ring 0.
unsafe fn wait_for_rtc() -> Option<()> {
    // An update takes under 2 ms; this bound is far past that, and exists so
    // a machine with no RTC falls through instead of hanging.
    for _ in 0..10_000_000u32 {
        // SAFETY: caller guarantees ring 0.
        if unsafe { cmos(0x0A) } & 0x80 == 0 {
            return Some(());
        }
        core::hint::spin_loop();
    }
    None
}

/// The RTC's seconds register, raw (BCD or binary as the RTC is set), or
/// `None` while an update is in progress and the value may be torn. For
/// seeing the second change, not for telling the time.
///
/// # Safety
/// Drives the CMOS ports; requires ring 0.
#[cfg(x86_any)]
pub unsafe fn rtc_second_raw() -> Option<u8> {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        if cmos(0x0A) & 0x80 != 0 {
            return None;
        }
        Some(cmos(0x00))
    }
}

#[cfg(x86_any)]
/// Reads one CMOS register.
///
/// # Safety
/// Requires ring 0.
unsafe fn cmos(index: u8) -> u8 {
    // SAFETY: caller guarantees ring 0. Bit 7 of the index port masks NMI;
    // it is left clear, which is what firmware expects to find.
    unsafe {
        outb(CMOS_ADDRESS, index);
        inb(CMOS_DATA)
    }
}

// ---------------------------------------------------------------------------
// The clock the interface reads
// ---------------------------------------------------------------------------

/// A monotonic nanosecond clock, plus the wall time it was started at.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    pub calibration: Calibration,
    /// The counter when the clock was started.
    origin: u64,
    /// Seconds since midnight at that instant, when the RTC could be read.
    wall_origin: Option<u64>,
    pub date: Option<DateTime>,
}

impl Clock {
    /// Calibrates the counter and anchors it to the RTC.
    ///
    /// # Safety
    /// Drives the PIT and the CMOS; requires ring 0.
    pub unsafe fn start() -> Clock {
        // SAFETY: forwarded from this function's own contract.
        let calibration = unsafe { Calibration::measure() };
        // SAFETY: as above.
        let date = unsafe { read_rtc() };
        Clock {
            calibration,
            origin: crate::arch::counter_ordered(),
            wall_origin: date.map(|d| d.seconds_of_day()),
            date,
        }
    }

    /// Nanoseconds since [`start`](Self::start).
    pub fn elapsed_ns(&self) -> u64 {
        let ticks = crate::arch::counter_ordered().wrapping_sub(self.origin);
        self.calibration.ticks_to_ns(ticks)
    }

    /// Raw counter ticks since start, for anything that wants the counter
    /// rather than a duration.
    pub fn elapsed_ticks(&self) -> u64 {
        crate::arch::counter_ordered().wrapping_sub(self.origin)
    }

    /// Nanoseconds since midnight, or `None` with no readable RTC.
    ///
    /// The RTC supplies the second and the counter supplies everything below
    /// it, so this advances smoothly rather than in one-second steps — the
    /// display shows nanoseconds and a clock that jumps by a second is not
    /// showing them.
    pub fn wall_ns(&self) -> Option<u64> {
        let base = self.wall_origin?;
        let total = base * NS_PER_S + self.elapsed_ns();
        // Past midnight the count would exceed a day; wrapping is correct and
        // the alternative is a clock that reads 24:xx.
        Some(total % (86_400 * NS_PER_S))
    }
}

/// No CMOS RTC off x86. A PL031 (ARM) or Goldfish RTC (RISC-V `virt`) would
/// be the equivalent; until one is read the wall clock is simply unknown.
///
/// # Safety
/// None; the signature matches the x86 one.
#[cfg(not(x86_any))]
pub unsafe fn read_rtc() -> Option<DateTime> {
    None
}

/// See [`read_rtc`]: no RTC to watch off x86.
///
/// # Safety
/// None; the signature matches the x86 one.
#[cfg(not(x86_any))]
pub unsafe fn rtc_second_raw() -> Option<u8> {
    None
}
