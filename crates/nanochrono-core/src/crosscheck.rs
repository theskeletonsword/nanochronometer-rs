// SPDX-License-Identifier: Apache-2.0
//! Checking one clock against another that does not share its failure modes.
//!
//! The stopwatch counts one counter — the TSC, `CNTVCT_EL0`, the time base.
//! Anything that disturbs that counter disturbs the measurement with nothing
//! to show for it: a hypervisor that rescales or offsets the guest's TSC, a
//! crystal pulled by temperature or by interference, a glitch in the PLL. A
//! second clock with its own counter (the ACPI PM timer) or its own crystal
//! (the RTC's 32.768 kHz) is what makes those visible.
//!
//! Two things are looked for, because they mean different things:
//!
//! - a **step**: between two consecutive samples the clocks disagree about
//!   how much time passed by more than the sampling can explain. Something
//!   moved one of them — an offset written, a counter reset, a VM migrated.
//! - a **drift**: over the whole baseline the rates disagree by more than
//!   [`CrossCheck::tolerance_ppm`]. Ordinary crystals agree within ~100 ppm;
//!   more than that is a rescaled counter or a clock being pulled.
//!
//! After a step the baseline restarts, so one event is reported once and the
//! rate is then judged afresh. The policy is pure: the caller reads both
//! clocks back to back and passes the pair in, with the reference already
//! unwrapped to a monotonic count.

/// What the comparison says now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not enough baseline yet to judge the rate.
    Warming,
    /// The rates agree; the measured difference in parts per million.
    Agree { ppm: i64 },
    /// The rates disagree by more than the tolerance.
    Drift { ppm: i64 },
    /// One clock jumped relative to the other between two samples, by this
    /// many nanoseconds (primary minus reference).
    Step { ns: i64 },
}

impl Verdict {
    pub const fn is_alarm(self) -> bool {
        matches!(self, Verdict::Drift { .. } | Verdict::Step { .. })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Verdict::Warming => "warming up",
            Verdict::Agree { .. } => "agree",
            Verdict::Drift { .. } => "DRIFT",
            Verdict::Step { .. } => "STEP",
        }
    }
}

/// One primary-versus-reference comparison.
#[derive(Debug, Clone, Copy)]
pub struct CrossCheck {
    primary_hz: u64,
    reference_hz: u64,
    /// Rate disagreement that counts as drift.
    pub tolerance_ppm: u32,
    /// How uncertain one sample's pairing is, in nanoseconds: the time
    /// between the two reads, or for an edge-sampled reference the polling
    /// period. Sets the step threshold and the baseline a rate needs.
    pub sample_uncertainty_ns: u64,
    origin: Option<(u64, u64)>,
    last: Option<(u64, u64)>,
    steps: u32,
    verdict: Verdict,
}

impl CrossCheck {
    pub const fn new(primary_hz: u64, reference_hz: u64, tolerance_ppm: u32, sample_uncertainty_ns: u64) -> CrossCheck {
        CrossCheck {
            primary_hz,
            reference_hz,
            tolerance_ppm,
            sample_uncertainty_ns,
            origin: None,
            last: None,
            steps: 0,
            verdict: Verdict::Warming,
        }
    }

    /// The latest verdict. A step stays reported until the next sample.
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// Steps seen since power-on.
    pub const fn steps(&self) -> u32 {
        self.steps
    }

    fn ns(ticks: u64, hz: u64) -> i128 {
        ticks as i128 * 1_000_000_000 / hz.max(1) as i128
    }

    /// The baseline a rate judgement needs: long enough that two samples'
    /// worth of uncertainty is a tenth of the tolerance.
    pub fn min_baseline_ns(&self) -> u64 {
        let tolerance = self.tolerance_ppm.max(1) as u64;
        (self.sample_uncertainty_ns.saturating_mul(2) * 10).saturating_mul(1_000_000) / tolerance
    }

    /// Adds one paired sample.
    pub fn sample(&mut self, primary: u64, reference: u64) -> Verdict {
        let Some(origin) = self.origin else {
            self.origin = Some((primary, reference));
            self.last = Some((primary, reference));
            self.verdict = Verdict::Warming;
            return self.verdict;
        };
        let (last_p, last_r) = self.last.unwrap_or(origin);
        self.last = Some((primary, reference));

        // Step: this interval against the rate the baseline so far has
        // established — not against a perfect 0 ppm, or a counter that is
        // steadily off would read as a step every interval and never as the
        // drift it is. The first interval after the origin only establishes
        // that rate. Slack is the sampling uncertainty on both ends plus the
        // tolerated rate wander over the interval.
        let dp = Self::ns(primary.wrapping_sub(last_p), self.primary_hz);
        let dr = Self::ns(reference.wrapping_sub(last_r), self.reference_hz);
        let base_p = Self::ns(last_p.wrapping_sub(origin.0), self.primary_hz);
        let base_r = Self::ns(last_r.wrapping_sub(origin.1), self.reference_hz);
        let expected = if base_r > 0 { dr * base_p / base_r } else { dp };
        let slack = 2 * self.sample_uncertainty_ns as i128 + dr.abs() * self.tolerance_ppm as i128 / 1_000_000;
        if (dp - expected).abs() > slack {
            self.steps = self.steps.saturating_add(1);
            self.origin = Some((primary, reference));
            self.verdict = Verdict::Step {
                ns: (dp - expected).clamp(i64::MIN as i128, i64::MAX as i128) as i64,
            };
            return self.verdict;
        }

        // Drift: the whole baseline.
        let bp = Self::ns(primary.wrapping_sub(origin.0), self.primary_hz);
        let br = Self::ns(reference.wrapping_sub(origin.1), self.reference_hz);
        if br < self.min_baseline_ns() as i128 || br <= 0 {
            self.verdict = Verdict::Warming;
            return self.verdict;
        }
        let ppm = ((bp - br) * 1_000_000 / br) as i64;
        self.verdict = if ppm.unsigned_abs() > self.tolerance_ppm as u64 {
            Verdict::Drift { ppm }
        } else {
            Verdict::Agree { ppm }
        };
        self.verdict
    }
}

/// Unwraps a counter narrower than 64 bits (the PM timer's 24 or 32) into a
/// monotonic count. Sample it more often than it wraps.
#[derive(Debug, Clone, Copy)]
pub struct Unwrap {
    bits: u32,
    last: Option<u64>,
    total: u64,
}

impl Unwrap {
    pub const fn new(bits: u32) -> Unwrap {
        Unwrap { bits, last: None, total: 0 }
    }

    pub fn feed(&mut self, raw: u64) -> u64 {
        let mask = if self.bits >= 64 { u64::MAX } else { (1u64 << self.bits) - 1 };
        let raw = raw & mask;
        if let Some(last) = self.last {
            self.total = self.total.wrapping_add(raw.wrapping_sub(last) & mask);
        }
        self.last = Some(raw);
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GHZ: u64 = 1_000_000_000;
    const PM: u64 = 3_579_545;

    /// A PM-timer pairing: reads a microsecond apart.
    fn pm_check() -> CrossCheck {
        CrossCheck::new(GHZ, PM, 200, 1_000)
    }

    fn pm_ticks(ns: u64) -> u64 {
        (ns as u128 * PM as u128 / 1_000_000_000) as u64
    }

    #[test]
    fn matching_clocks_agree_once_warmed() {
        let mut c = pm_check();
        let mut last = Verdict::Warming;
        for s in 0..=30u64 {
            let ns = s * 1_000_000_000;
            last = c.sample(ns, pm_ticks(ns));
        }
        assert!(matches!(last, Verdict::Agree { ppm } if ppm.abs() <= 1), "{last:?}");
    }

    #[test]
    fn a_rescaled_primary_is_drift() {
        let mut c = pm_check();
        let mut last = Verdict::Warming;
        for s in 0..=30u64 {
            let ns = s * 1_000_000_000;
            // Primary runs 0.1 % fast: 1000 ppm.
            last = c.sample(ns + ns / 1000, pm_ticks(ns));
        }
        assert!(matches!(last, Verdict::Drift { ppm } if (990..=1010).contains(&ppm)), "{last:?}");
    }

    #[test]
    fn a_jump_is_a_step_and_rebases() {
        let mut c = pm_check();
        for s in 0..10u64 {
            let ns = s * 1_000_000_000;
            c.sample(ns, pm_ticks(ns));
        }
        // The primary jumps 5 ms forward between two samples.
        let v = c.sample(10 * GHZ + 5_000_000, pm_ticks(10 * GHZ));
        assert!(matches!(v, Verdict::Step { ns } if (4_990_000..=5_010_000).contains(&ns)), "{v:?}");
        assert_eq!(c.steps(), 1);
        // Rebased: the offset alone is not drift afterwards.
        let mut last = v;
        for s in 11..=40u64 {
            let ns = s * GHZ;
            last = c.sample(ns + 5_000_000, pm_ticks(ns));
        }
        assert!(matches!(last, Verdict::Agree { .. }), "{last:?}");
    }

    #[test]
    fn sampling_noise_is_not_a_step() {
        let mut c = pm_check();
        for s in 0..20u64 {
            let ns = s * GHZ;
            let jitter = if s % 2 == 0 { 900 } else { 0 };
            let v = c.sample(ns + jitter, pm_ticks(ns));
            assert!(!matches!(v, Verdict::Step { .. }), "sample {s}: {v:?}");
        }
    }

    #[test]
    fn unwrap_24_bits() {
        let mut u = Unwrap::new(24);
        assert_eq!(u.feed(0xFF_FFF0), 0);
        assert_eq!(u.feed(0x00_0010), 0x20);
        assert_eq!(u.feed(0x00_0020), 0x30);
    }
}
