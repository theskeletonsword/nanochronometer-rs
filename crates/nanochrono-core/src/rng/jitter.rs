// SPDX-License-Identifier: Apache-2.0
//! The CPU-timing jitter source: how long the same work takes, twice.
//!
//! One measurement reads the counter, walks a memory region with a fixed
//! stride, runs a short hash loop, and reads the counter again. The work is
//! identical every time; the time it takes is not, because it depends on the
//! caches, the TLB, the branch predictors, DRAM refresh, SMM and everything
//! else sharing the core — none of which the instruction set controls or
//! exposes. That variation is the entropy. The manual's sections 3.1–3.3,
//! 3.8 and 7.1 specify it; this follows them:
//!
//! * The counter is the cheapest one, **not** serialised
//!   ([`crate::arch::counter_raw`]): a fence would only add a constant.
//! * The **memory walk** increments one byte and steps [`STRIDE`] (127)
//!   bytes, masked to a power-of-two region. The stride is odd and longer
//!   than a cache line, so the walk touches a new line every step and, in
//!   time, every byte. The position carries over between measurements, so
//!   successive ones reach different lines rather than the same warm ones.
//! * The **dispersion loop** hashes the previous digest together with the
//!   health counters, and its digest travels with the sample into the pool
//!   as additional (uncredited) input. It keeps the pipeline busy and
//!   stops the measured region from being optimised away.
//! * A sample is **stuck** when its delta, or its first or second
//!   difference, is zero: a timer that did not move, or moved exactly as
//!   before. A stuck sample updates the health tests but is not absorbed or
//!   counted.
//! * **Start-up** runs 100 warm-up measurements, then 1024 with three times
//!   the work. It fails if the timer reads zero, stands still, runs
//!   backwards more than three times, if 90 % of the samples are stuck, if
//!   a health test trips, or if the deltas' common divisor (the counter's
//!   granularity) is useless. That divisor then normalises every delta.
//! * Every non-stuck sample is credited `1/OSR` bits, so a seed of
//!   `256 + F` bits takes `(256 + F)·OSR` of them.

use core::sync::atomic::{compiler_fence, Ordering};

use super::health::{self, Health};
use super::keccak::{wipe_bytes, Sponge, DOMAIN_SHA3, RATE};
use super::RngError;

/// Bytes between consecutive accesses of the memory walk.
pub const STRIDE: usize = 127;
/// The region the manual falls back to when the cache size is not known.
pub const DEFAULT_REGION_LEN: usize = 1 << 18;
/// Smallest and largest regions the manual allows.
pub const MIN_REGION_LEN: usize = 1 << 10;
pub const MAX_REGION_LEN: usize = 1 << 29;
/// Memory accesses per measurement.
pub const DEFAULT_MEM_STEPS: u32 = 128;
/// Hash-loop iterations per measurement.
pub const DEFAULT_HASH_LOOPS: u32 = 1;
/// Start-up measurements do this many times the work.
pub const STARTUP_FACTOR: u32 = 3;
/// Start-up: measurements discarded, then measurements judged.
pub const STARTUP_WARMUP: u32 = 100;
pub const STARTUP_SAMPLES: u32 = 1024;
/// Backward steps of the counter tolerated during start-up (a migration, a
/// VM being moved), after which the timer is declared non-monotonic.
pub const STARTUP_BACKWARDS: u32 = 3;
/// A granularity at or above half of `i32::MAX` is too coarse to use.
const GRANULARITY_LIMIT: u64 = 0x7FFF_FFFF / 2;

/// Domain byte of a jitter block in the pool (the manual's separator).
pub const DOMAIN_JITTER: u8 = 0x01;

/// A counter the embedder can read around each measurement — a PMU event,
/// say — whose difference rides along as additional input. Never credited.
pub type Sampler = fn() -> u64;

/// One classified measurement.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// The measurement's duration divided by the counter's granularity.
    pub delta: u64,
    /// Zero delta, or zero first or second difference.
    pub stuck: bool,
    /// Health bits this sample tripped.
    pub fail: u32,
    /// The sampler's difference across the measurement, 0 without one.
    pub side: u64,
}

/// What start-up found.
#[derive(Debug, Clone, Copy, Default)]
pub struct StartupReport {
    /// The counter's granularity: the common divisor of every delta.
    pub granularity: u64,
    /// Stuck samples among the 1024, and backward steps of the counter.
    pub stuck: u32,
    pub backwards: u32,
    /// Sum of absolute differences between adjacent deltas.
    pub variation: u64,
}

/// The collector: a memory region, the stuck-test history and the health
/// tests.
pub struct Jitter<'r> {
    region: &'r mut [u8],
    pos: usize,
    mem_steps: u32,
    hash_loops: u32,
    granularity: u64,
    prev_delta: u64,
    prev_d1: u64,
    digest: [u8; 32],
    health: Health,
    sampler: Option<Sampler>,
    /// Every sample taken, and the stuck ones among them, since creation.
    samples: u64,
    stuck: u64,
}

impl core::fmt::Debug for Jitter<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Jitter")
            .field("region_len", &self.region.len())
            .field("osr", &self.health.osr())
            .field("granularity", &self.granularity)
            .field("samples", &self.samples)
            .field("stuck", &self.stuck)
            .finish_non_exhaustive()
    }
}

impl<'r> Jitter<'r> {
    /// A collector over `region`, whose length must be a power of two between
    /// 1 KiB and 512 MiB. Takes no measurement; [`startup`](Self::startup)
    /// must pass before samples are used.
    pub fn new(region: &'r mut [u8], osr: u32, mem_steps: u32, hash_loops: u32) -> Result<Self, RngError> {
        let len = region.len();
        if !len.is_power_of_two() || !(MIN_REGION_LEN..=MAX_REGION_LEN).contains(&len) {
            return Err(RngError::Misuse);
        }
        if osr > health::OSR_MAX {
            return Err(RngError::Misuse);
        }
        let osr = if osr == 0 { health::OSR_DEFAULT } else { osr };
        Ok(Jitter {
            region,
            pos: 0,
            mem_steps: mem_steps.max(1),
            hash_loops: hash_loops.max(1),
            granularity: 1,
            prev_delta: 0,
            prev_d1: 0,
            digest: [0; 32],
            health: Health::new(osr),
            sampler: None,
            samples: 0,
            stuck: 0,
        })
    }

    pub fn set_sampler(&mut self, sampler: Option<Sampler>) {
        self.sampler = sampler;
    }

    pub fn has_sampler(&self) -> bool {
        self.sampler.is_some()
    }

    pub fn osr(&self) -> u32 {
        self.health.osr()
    }

    pub fn granularity(&self) -> u64 {
        self.granularity
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    pub fn stuck(&self) -> u64 {
        self.stuck
    }

    /// The resilient step after an intermittent failure: a higher OSR (less
    /// entropy assumed per sample, so more samples per seed) and one more
    /// hash loop. The region is the embedder's and does not grow. Start-up
    /// must pass again before the collector is used.
    pub fn retune(&mut self, osr: u32) {
        self.health.retune(osr);
        self.hash_loops = self.hash_loops.saturating_add(1);
    }

    /// Reads the counter around one walk and one hash loop.
    ///
    /// Not inlined, per the manual: the measured code must stay one piece
    /// the optimiser cannot interleave with its caller.
    #[inline(never)]
    fn measure(&mut self, steps: u32, loops: u32) -> (u64, u64, u64) {
        let side0 = self.sampler.map_or(0, |read| read());
        let t0 = crate::arch::counter_raw();
        self.walk(steps);
        self.disperse(loops);
        let t1 = crate::arch::counter_raw();
        let side1 = self.sampler.map_or(0, |read| read());
        (t0, t1, side1.wrapping_sub(side0))
    }

    fn walk(&mut self, steps: u32) {
        let mask = self.region.len() - 1;
        let base = self.region.as_mut_ptr();
        let mut pos = self.pos;
        for _ in 0..steps {
            // SAFETY: `pos` is masked to the region, whose length is a power
            // of two, so it is always in bounds. Volatile, so the read and
            // the write both happen: that memory traffic is what is timed.
            unsafe {
                let byte = base.add(pos);
                byte.write_volatile(byte.read_volatile().wrapping_add(1));
            }
            compiler_fence(Ordering::SeqCst);
            pos = (pos + STRIDE) & mask;
        }
        self.pos = pos;
    }

    fn disperse(&mut self, loops: u32) {
        let (apt_count, apt_seen) = self.health.apt_state();
        for j in 0..loops {
            let mut sponge = Sponge::new();
            sponge.absorb(&self.digest);
            sponge.absorb(&self.health.rct_run().to_le_bytes());
            sponge.absorb(&apt_count.to_le_bytes());
            sponge.absorb(&apt_seen.to_le_bytes());
            sponge.absorb(&self.health.lag_hits().to_le_bytes());
            sponge.absorb(&self.samples.to_le_bytes());
            sponge.absorb(&(self.pos as u64).to_le_bytes());
            sponge.absorb(&j.to_le_bytes());
            sponge.finish(DOMAIN_SHA3);
            sponge.squeeze(&mut self.digest);
            sponge.wipe();
        }
    }

    /// Normalises a raw duration, runs the stuck test and the health tests.
    fn classify(&mut self, raw: u64, side: u64) -> Sample {
        let delta = raw / self.granularity.max(1);
        let d1 = delta.abs_diff(self.prev_delta);
        let d2 = d1.abs_diff(self.prev_d1);
        let stuck = delta == 0 || d1 == 0 || d2 == 0;
        self.prev_d1 = d1;
        self.prev_delta = delta;
        let fail = self.health.observe(delta, stuck);
        self.samples += 1;
        if stuck {
            self.stuck += 1;
        }
        Sample { delta, stuck, fail, side }
    }

    /// One measurement at the running work level.
    pub fn sample(&mut self) -> Sample {
        let (t0, t1, side) = self.measure(self.mem_steps, self.hash_loops);
        self.classify(t1.wrapping_sub(t0), side)
    }

    /// The manual's start-up validation (100 + 1024, work ×3), which also
    /// learns the granularity. On success the health windows start clean.
    ///
    /// The stuck test and the health tests run on raw deltas here, before
    /// the divisor is known. That changes none of their verdicts: every raw
    /// delta is a multiple of the divisor, so dividing preserves which
    /// deltas are zero and which are equal — all the tests look at.
    pub fn startup(&mut self) -> Result<StartupReport, RngError> {
        let steps = self.mem_steps.saturating_mul(STARTUP_FACTOR);
        let loops = self.hash_loops.saturating_mul(STARTUP_FACTOR);
        let osr = self.health.osr();
        self.granularity = 1;
        self.health = Health::new(osr);

        // Warm-up: caches, predictors and the stuck test's history.
        for _ in 0..STARTUP_WARMUP {
            let (t0, t1, _) = self.measure(steps, loops);
            let delta = t1.wrapping_sub(t0);
            self.prev_d1 = delta.abs_diff(self.prev_delta);
            self.prev_delta = delta;
        }

        let mut report = StartupReport::default();
        let mut divisor = 0u64;
        let mut previous: Option<u64> = None;
        let mut judged = 0u32;
        let mut fail = 0u32;
        for _ in 0..STARTUP_SAMPLES {
            let (t0, t1, side) = self.measure(steps, loops);
            if t0 == 0 || t1 == 0 {
                return Err(RngError::Timer);
            }
            let raw = t1.wrapping_sub(t0);
            if raw > u64::MAX / 2 {
                // Read earlier than the read before it.
                report.backwards += 1;
                if report.backwards > STARTUP_BACKWARDS {
                    return Err(RngError::Timer);
                }
                continue;
            }
            if raw == 0 {
                // The whole measurement fit inside one tick: no resolution.
                return Err(RngError::Timer);
            }
            divisor = gcd(divisor, raw);
            if let Some(prev) = previous {
                report.variation = report.variation.saturating_add(raw.abs_diff(prev));
            }
            previous = Some(raw);
            let sample = self.classify(raw, side);
            report.stuck += sample.stuck as u32;
            fail |= sample.fail;
            judged += 1;
        }

        if let Some(error) = RngError::from_health(fail) {
            return Err(error);
        }
        if report.stuck as u64 * 10 >= judged as u64 * 9 {
            return Err(RngError::Timer);
        }
        if report.variation.saturating_mul(osr as u64) < judged as u64 {
            return Err(RngError::Timer);
        }
        if divisor == 0 || divisor >= GRANULARITY_LIMIT {
            return Err(RngError::Timer);
        }

        report.granularity = divisor;
        self.granularity = divisor;
        self.prev_delta /= divisor;
        self.prev_d1 /= divisor;
        self.health = Health::new(osr);
        Ok(report)
    }

    /// Absorbs `bits · OSR` non-stuck samples into `sponge`, one full
    /// permutation per sample, and credits them `bits` bits. Stuck samples
    /// are measured again without counting.
    ///
    /// A health failure discards nothing by itself — the samples already
    /// absorbed are in the caller's sponge — so the caller must throw the
    /// sponge away, which is the manual's "the block is discarded, with no
    /// partial delivery".
    pub fn collect(&mut self, sponge: &mut Sponge, bits: u32) -> Result<u32, RngError> {
        let need = bits.saturating_mul(self.health.osr());
        let mut block = [0u8; RATE];
        let mut got = 0;
        while got < need {
            let sample = self.sample();
            if let Some(error) = RngError::from_health(sample.fail) {
                wipe_bytes(&mut block);
                return Err(error);
            }
            if sample.stuck {
                continue;
            }
            // delta(8) | domain(1) | digest(32), as the manual lays it out,
            // then the side counter; the rest of the rate stays zero.
            block[..8].copy_from_slice(&sample.delta.to_le_bytes());
            block[8] = DOMAIN_JITTER;
            block[9..41].copy_from_slice(&self.digest);
            block[41..49].copy_from_slice(&sample.side.to_le_bytes());
            sponge.absorb_block(&block);
            got += 1;
        }
        wipe_bytes(&mut block);
        Ok(got)
    }
}

/// Euclid's greatest common divisor, with `gcd(0, x) = x`.
pub fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcd_of_the_manuals_example() {
        // §10.3: deltas 0, 3, 6, …, 27 have divisor 3 and variation 27.
        let history = [0u64, 3, 6, 9, 12, 15, 18, 21, 24, 27];
        let divisor = history.iter().fold(0, |g, &d| gcd(g, d));
        let variation: u64 = history.windows(2).map(|w| w[1].abs_diff(w[0])).sum();
        assert_eq!(divisor, 3);
        assert_eq!(variation, 27);
        assert!(variation * 3 >= history.len() as u64);
    }

    #[test]
    fn region_must_be_a_power_of_two_in_range() {
        let mut small = [0u8; 512];
        assert!(Jitter::new(&mut small, 3, 128, 1).is_err());
        let mut odd = [0u8; 3000];
        assert!(Jitter::new(&mut odd, 3, 128, 1).is_err());
        let mut ok = [0u8; 4096];
        assert!(Jitter::new(&mut ok, 3, 128, 1).is_ok());
        let mut ok2 = [0u8; 4096];
        assert!(Jitter::new(&mut ok2, 21, 128, 1).is_err());
    }

    #[test]
    fn stuck_test_is_the_triple_derivative() {
        let mut region = [0u8; 4096];
        let mut j = Jitter::new(&mut region, 3, 128, 1).unwrap();
        // 100, 110, 130: differences 10 then 20, second difference 10.
        j.classify(100, 0);
        j.classify(110, 0);
        assert!(!j.classify(130, 0).stuck);
        // Same delta again: first difference zero.
        assert!(j.classify(130, 0).stuck);
        // Zero delta.
        assert!(j.classify(0, 0).stuck);
    }

    #[test]
    fn the_host_counter_passes_startup_and_collects() {
        let mut region = vec![0u8; DEFAULT_REGION_LEN];
        let mut j = Jitter::new(&mut region, 3, DEFAULT_MEM_STEPS, DEFAULT_HASH_LOOPS).unwrap();
        let report = j.startup().expect("start-up on the host counter");
        assert!(report.granularity >= 1);
        let mut sponge = Sponge::new();
        let got = j.collect(&mut sponge, 16).expect("collect");
        assert_eq!(got, 16 * 3);
    }
}
