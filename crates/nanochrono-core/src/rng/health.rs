// SPDX-License-Identifier: Apache-2.0
//! Continuous health tests on the jitter samples (NIST SP 800-90B §4.4).
//!
//! Three tests watch every sample the collector takes, stuck or not:
//!
//! * **Repetition count (RCT)** counts consecutive *stuck* samples (see
//!   [`super::jitter`]). The cutoff is `C = ⌈−log2(α) / H⌉` with
//!   `H = 1/OSR`, which is `30·OSR` for the intermittent `α = 2⁻³⁰` and
//!   `60·OSR` for the permanent `α = 2⁻⁶⁰`.
//! * **Adaptive proportion (APT)** takes the first sample of a 512-sample
//!   window as reference and counts how often that exact value comes back.
//!   The cutoff is `2 + Qbinom(1−α, 511, 2^(−1/OSR))`, capped at the window.
//! * **Lag predictor** keeps the last 8 samples and predicts each new one as
//!   the value `k` samples back, for whichever `k` has predicted best so far
//!   (ties go to the shorter lag). Over a 131072-sample window it fails on
//!   too many correct predictions in total, or too long a run of them.
//!
//! A tripped test latches a bit; what that means for the block being
//! collected is the pool's decision, not this module's.
//!
//! # Where the numbers come from
//!
//! The intermittent tables are the manual's (sections 7.3 and 7.4). The
//! permanent lag-predictor cutoffs (`α = 2⁻⁴⁴`) are not tabulated there; they
//! were computed with the same formulas — the inverse binomial for the global
//! count, the Kelsey–McKay–Turan run-length bound for the local one — by a
//! script that first reproduces every intermittent entry of the manual
//! exactly, so both columns come from one verified method.

/// The repetition count test tripped at the intermittent cutoff.
pub const FAIL_RCT: u32 = 1 << 0;
/// The adaptive proportion test tripped at the intermittent cutoff.
pub const FAIL_APT: u32 = 1 << 1;
/// The lag predictor tripped at the intermittent cutoff.
pub const FAIL_LAG: u32 = 1 << 2;
/// The repetition count test tripped at the permanent cutoff.
pub const FAIL_RCT_PERMANENT: u32 = 1 << 3;
/// The adaptive proportion test tripped at the permanent cutoff.
pub const FAIL_APT_PERMANENT: u32 = 1 << 4;
/// The lag predictor tripped at the permanent cutoff.
pub const FAIL_LAG_PERMANENT: u32 = 1 << 5;

/// Every intermittent failure bit.
pub const FAIL_INTERMITTENT: u32 = FAIL_RCT | FAIL_APT | FAIL_LAG;
/// Every permanent failure bit.
pub const FAIL_PERMANENT: u32 = FAIL_RCT_PERMANENT | FAIL_APT_PERMANENT | FAIL_LAG_PERMANENT;

/// Lowest oversampling rate: one bit of entropy credited per sample.
pub const OSR_MIN: u32 = 1;
/// The default: a third of a bit per sample.
pub const OSR_DEFAULT: u32 = 3;
/// Past this, the source is too poor to use; asking for more is an error.
pub const OSR_MAX: u32 = 20;

/// Samples per APT window.
pub const APT_WINDOW: u32 = 512;
/// APT cutoffs for OSR 1..=20, `α = 2⁻³⁰` (manual §7.3).
const APT_INTERMITTENT: [u32; 20] = [
    325, 422, 459, 477, 488, 494, 499, 502, 505, 507, 508, 509, 510, 511, 512, 512, 512, 512, 512,
    512,
];
/// APT cutoffs for OSR 1..=20, `α = 2⁻⁶⁰` (manual §7.3).
const APT_PERMANENT: [u32; 20] = [
    355, 447, 479, 494, 502, 507, 510, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512,
    512,
];

/// Samples the lag predictor remembers.
pub const LAG_HISTORY: usize = 8;
/// Samples per lag-predictor window.
pub const LAG_WINDOW: u32 = 131_072;
/// Correct predictions per window, `α = 2⁻²²` (manual §7.4).
const LAG_GLOBAL_INTERMITTENT: [u32; 20] = [
    66443, 93504, 104761, 110875, 114707, 117330, 119237, 120686, 121823, 122739, 123493, 124124,
    124660, 125120, 125520, 125871, 126181, 126457, 126704, 126926,
];
/// Longest run of correct predictions, `α = 2⁻²²` (manual §7.4).
const LAG_LOCAL_INTERMITTENT: [u32; 20] = [
    38, 75, 111, 146, 181, 215, 250, 284, 318, 351, 385, 419, 452, 485, 518, 551, 584, 617, 650,
    683,
];
/// Correct predictions per window, `α = 2⁻⁴⁴` (computed; see the module docs).
const LAG_GLOBAL_PERMANENT: [u32; 20] = [
    66876, 93896, 105108, 111188, 114993, 117596, 119486, 120920, 122045, 122951, 123696, 124318,
    124847, 125301, 125695, 126041, 126346, 126617, 126860, 127079,
];
/// Longest run of correct predictions, `α = 2⁻⁴⁴` (computed; see above).
const LAG_LOCAL_PERMANENT: [u32; 20] = [
    60, 119, 177, 234, 291, 347, 404, 460, 516, 571, 627, 683, 738, 793, 848, 903, 958, 1013,
    1068, 1123,
];

/// `osr` clamped into the tables' range.
pub const fn clamp_osr(osr: u32) -> u32 {
    if osr < OSR_MIN {
        OSR_MIN
    } else if osr > OSR_MAX {
        OSR_MAX
    } else {
        osr
    }
}

/// The RCT cutoff: `30·OSR` intermittent, `60·OSR` permanent (manual §7.2).
pub const fn rct_cutoff(osr: u32, permanent: bool) -> u32 {
    (if permanent { 60 } else { 30 }) * clamp_osr(osr)
}

/// The three tests' state for one source.
#[derive(Debug, Clone)]
pub struct Health {
    osr: u32,
    // Repetition count.
    rct_run: u32,
    // Adaptive proportion.
    apt_reference: u64,
    apt_count: u32,
    apt_seen: u32,
    // Lag predictor.
    lag_history: [u64; LAG_HISTORY],
    lag_scores: [u32; LAG_HISTORY],
    lag_best: usize,
    lag_observed: u32,
    lag_hits: u32,
    lag_run: u32,
}

impl Health {
    pub const fn new(osr: u32) -> Self {
        Health {
            osr: clamp_osr(osr),
            rct_run: 0,
            apt_reference: 0,
            apt_count: 0,
            apt_seen: 0,
            lag_history: [0; LAG_HISTORY],
            lag_scores: [0; LAG_HISTORY],
            lag_best: 0,
            lag_observed: 0,
            lag_hits: 0,
            lag_run: 0,
        }
    }

    pub const fn osr(&self) -> u32 {
        self.osr
    }

    /// Moves to a new oversampling rate, keeping every counter. The manual's
    /// rule after a resilient reallocation is to carry the state over so a
    /// source that keeps failing escalates rather than starting clean.
    pub fn retune(&mut self, osr: u32) {
        self.osr = clamp_osr(osr);
    }

    /// Feeds one sample: its normalised delta and whether it was stuck.
    /// Returns the failure bits it raised, 0 if none.
    pub fn observe(&mut self, delta: u64, stuck: bool) -> u32 {
        self.rct(stuck) | self.apt(delta) | self.lag(delta)
    }

    /// The current run of stuck samples, for the dispersion loop to absorb.
    pub const fn rct_run(&self) -> u32 {
        self.rct_run
    }

    /// The APT window's reference count and position, likewise.
    pub const fn apt_state(&self) -> (u32, u32) {
        (self.apt_count, self.apt_seen)
    }

    /// Correct predictions in the current lag window, likewise.
    pub const fn lag_hits(&self) -> u32 {
        self.lag_hits
    }

    fn rct(&mut self, stuck: bool) -> u32 {
        if !stuck {
            self.rct_run = 0;
            return 0;
        }
        self.rct_run = self.rct_run.saturating_add(1);
        if self.rct_run >= rct_cutoff(self.osr, true) {
            FAIL_RCT_PERMANENT
        } else if self.rct_run >= rct_cutoff(self.osr, false) {
            FAIL_RCT
        } else {
            0
        }
    }

    fn apt(&mut self, delta: u64) -> u32 {
        if self.apt_seen == 0 {
            // First sample of a window: the reference, counted once.
            self.apt_reference = delta;
            self.apt_count = 1;
            self.apt_seen = 1;
            return 0;
        }
        if delta == self.apt_reference {
            self.apt_count += 1;
        }
        self.apt_seen += 1;
        let index = (self.osr - 1) as usize;
        let fail = if self.apt_count >= APT_PERMANENT[index] {
            FAIL_APT_PERMANENT
        } else if self.apt_count >= APT_INTERMITTENT[index] {
            FAIL_APT
        } else {
            0
        };
        if self.apt_seen >= APT_WINDOW {
            // Window complete; the next sample is the new reference.
            self.apt_seen = 0;
        }
        fail
    }

    fn lag(&mut self, delta: u64) -> u32 {
        let n = self.lag_observed as usize;
        if n < LAG_HISTORY {
            // Filling the history: nothing to predict from yet.
            self.lag_history[n] = delta;
            self.lag_observed += 1;
            return 0;
        }

        // Sample `n - k - 1` is `k + 1` back, and sits at that index mod 8.
        let back = |k: usize| (n - k - 1) % LAG_HISTORY;
        let index = (self.osr - 1) as usize;
        let mut fail = 0;
        if self.lag_history[back(self.lag_best)] == delta {
            self.lag_hits += 1;
            self.lag_run += 1;
            if self.lag_run >= LAG_LOCAL_PERMANENT[index] || self.lag_hits >= LAG_GLOBAL_PERMANENT[index] {
                fail = FAIL_LAG_PERMANENT;
            } else if self.lag_run >= LAG_LOCAL_INTERMITTENT[index]
                || self.lag_hits >= LAG_GLOBAL_INTERMITTENT[index]
            {
                fail = FAIL_LAG;
            }
        } else {
            self.lag_run = 0;
        }

        // Score every lag on this sample; the best predicts the next one.
        for k in 0..LAG_HISTORY {
            if self.lag_history[back(k)] == delta {
                self.lag_scores[k] += 1;
                let best = self.lag_scores[self.lag_best];
                if self.lag_scores[k] > best || (self.lag_scores[k] == best && k < self.lag_best) {
                    self.lag_best = k;
                }
            }
        }

        self.lag_history[n % LAG_HISTORY] = delta;
        self.lag_observed += 1;
        if self.lag_observed >= LAG_WINDOW {
            self.lag_history = [0; LAG_HISTORY];
            self.lag_scores = [0; LAG_HISTORY];
            self.lag_best = 0;
            self.lag_observed = 0;
            self.lag_hits = 0;
            self.lag_run = 0;
        }
        fail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rct_cutoffs_match_the_manual() {
        // §7.2's table, first and last rows and the default.
        assert_eq!((rct_cutoff(1, false), rct_cutoff(1, true)), (30, 60));
        assert_eq!((rct_cutoff(3, false), rct_cutoff(3, true)), (90, 180));
        assert_eq!((rct_cutoff(20, false), rct_cutoff(20, true)), (600, 1200));
    }

    #[test]
    fn rct_trips_at_the_cutoff_and_a_healthy_sample_resets_it() {
        let mut h = Health::new(3);
        for _ in 0..89 {
            assert_eq!(h.rct(true), 0);
        }
        assert_eq!(h.rct(true), FAIL_RCT);
        assert_eq!(h.rct(false), 0);
        assert_eq!(h.rct_run(), 0);
        for _ in 0..179 {
            h.rct(true);
        }
        assert_eq!(h.rct(true), FAIL_RCT_PERMANENT);
    }

    #[test]
    fn apt_trips_on_a_value_that_keeps_coming_back() {
        let mut h = Health::new(3);
        let mut worst = 0;
        // Reference 7, then 7 on every other sample: 256 of 512, under 459.
        for i in 0..512u64 {
            worst |= h.apt(if i % 2 == 0 { 7 } else { 1000 + i });
        }
        assert_eq!(worst, 0);
        // A window that is nearly all one value trips.
        for i in 0..512u64 {
            worst |= h.apt(if i % 50 == 49 { 1000 + i } else { 7 });
        }
        assert_ne!(worst & (FAIL_APT | FAIL_APT_PERMANENT), 0);
    }

    #[test]
    fn lag_predictor_catches_a_period() {
        let mut h = Health::new(3);
        let mut worst = 0;
        // Period 5: once the history holds a period, every prediction hits,
        // and the run reaches the local cutoff (111 at OSR 3) quickly.
        for i in 0..400u64 {
            worst |= h.lag(i % 5);
        }
        assert_ne!(worst & (FAIL_LAG | FAIL_LAG_PERMANENT), 0);
    }

    #[test]
    fn lag_predictor_passes_a_source_that_does_not_repeat() {
        let mut h = Health::new(3);
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..10_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            assert_eq!(h.lag(x), 0);
        }
    }
}
