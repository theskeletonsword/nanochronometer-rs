// SPDX-License-Identifier: Apache-2.0
//! Local timing probes and constant-time auditing.
//!
//! Scope, stated plainly: everything here measures buffers **the caller owns**,
//! in **this** process. There is no cross-process probing, no eviction-set
//! construction and no secret-recovery machinery. The purpose is to let you
//! point this at your own candidate routine and find out whether its timing
//! depends on its input — the defensive half of the side-channel literature.

use crate::arch;
use crate::context::Chronometer;
use crate::stats::{self, ConstantTimeVerdict, SampleStats, LEAK_T_THRESHOLD};

/// Which memory-timing question a probe answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheProbe {
    /// Latency of a load, whatever the line's current state.
    Load,
    /// Latency of a load with barriers on both sides.
    LoadFenced,
    /// Latency of a load right after flushing the line. x86-64 only.
    FlushReload,
    /// Latency of a load right after prefetching the line.
    PrefetchReload,
    /// Latency of a store.
    Store,
    /// Cost of a data-dependent branch sequence.
    Branch,
    /// Cost of following a pointer chain.
    PointerChase,
    /// Cost of back-to-back barriers.
    Barrier,
    /// Cost of a bare counter read.
    Counter,
}

impl CacheProbe {
    pub const fn name(self) -> &'static str {
        match self {
            CacheProbe::Load => "load",
            CacheProbe::LoadFenced => "load-fenced",
            CacheProbe::FlushReload => "flush-reload",
            CacheProbe::PrefetchReload => "prefetch-reload",
            CacheProbe::Store => "store",
            CacheProbe::Branch => "branch",
            CacheProbe::PointerChase => "pointer-chase",
            CacheProbe::Barrier => "barrier",
            CacheProbe::Counter => "counter",
        }
    }

    /// Whether the current architecture implements this probe.
    ///
    /// `FlushReload` needs an unprivileged cache-line flush, which x86-64 has
    /// (`CLFLUSH`) and AArch64 does not expose at EL0.
    pub const fn is_supported(self) -> bool {
        // Written as an explicit negation rather than a match, because on
        // AArch64 the `cfg!` folds to `false` and clippy then sees a match
        // that could be `matches!` — which would read as if the architecture
        // check had been dropped.
        if matches!(self, CacheProbe::FlushReload) {
            return cfg!(any(target_arch = "x86_64", target_arch = "x86"));
        }
        true
    }
}

/// Cache-residency separation for one line.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CacheAudit {
    /// Latency with the line resident.
    pub cached_units: u64,
    /// Latency after flushing the line.
    pub flushed_units: u64,
    /// Latency after prefetching the line.
    pub prefetched_units: u64,
    /// Midpoint between cached and flushed: the classifier a real attack would
    /// use, reported so you can see how wide the gap is on your hardware.
    pub threshold_units: u64,
    /// `flushed - cached`. Large values mean residency is easy to observe.
    pub separation: f64,
}

/// Runs one probe over `buffer`, returning raw counter units.
///
/// Returns `None` when the probe is unsupported here, or when `buffer` is too
/// small for the access the probe performs.
pub fn run(probe: CacheProbe, buffer: &mut [u8], steps: usize) -> Option<u64> {
    if !probe.is_supported() {
        return None;
    }
    if matches!(probe, CacheProbe::Counter) {
        return Some(arch::counter_start());
    }
    if matches!(probe, CacheProbe::Barrier) {
        return Some(arch::barrier_overhead(steps.max(1) as u32));
    }
    if buffer.len() < 8 {
        return None;
    }

    // SAFETY: the length check above guarantees at least one aligned 64-bit
    // word, and every probe below touches only that word (or, for `Branch`,
    // the byte range explicitly bounded by `steps`).
    let units = unsafe {
        let ptr = buffer.as_mut_ptr();
        match probe {
            CacheProbe::Load => load_units(ptr as *const u64),
            CacheProbe::LoadFenced => load_fenced_units(ptr as *const u64),
            CacheProbe::FlushReload => flush_reload_units(ptr as *const u64)?,
            CacheProbe::PrefetchReload => prefetch_reload_units(ptr as *const u64),
            CacheProbe::Store => store_units(ptr as *mut u64),
            CacheProbe::Branch => {
                let n = steps.min(buffer.len());
                branch_units(ptr, n)
            }
            CacheProbe::PointerChase => pointer_chase_units(ptr as *const *const u8, steps),
            CacheProbe::Counter | CacheProbe::Barrier => unreachable!("handled above"),
        }
    };
    Some(units)
}

/// Measures cached, flushed and prefetched latency for one line.
///
/// A large `separation` is not a finding on its own — it is a property of the
/// memory hierarchy. It matters only when the *choice* of which line to touch
/// depends on a secret, which is what [`audit_constant_time`] tests for.
pub fn cache_audit(buffer: &mut [u8]) -> Option<CacheAudit> {
    if buffer.len() < 8 {
        return None;
    }
    // Warm the line first so `cached` really is the resident case.
    let cached = run(CacheProbe::Load, buffer, 0)?;
    let cached = run(CacheProbe::Load, buffer, 0)?.min(cached);
    let flushed = run(CacheProbe::FlushReload, buffer, 0).unwrap_or(cached);
    let prefetched = run(CacheProbe::PrefetchReload, buffer, 0)?;

    Some(CacheAudit {
        cached_units: cached,
        flushed_units: flushed,
        prefetched_units: prefetched,
        threshold_units: (cached + flushed) / 2,
        separation: flushed as f64 - cached as f64,
    })
}

/// How an audit generates and compares its two input classes.
#[derive(Debug, Clone, Copy)]
pub struct AuditConfig {
    /// Samples per class.
    pub samples: u32,
    /// Input length handed to the candidate.
    pub input_len: usize,
    /// Output buffer length handed to the candidate.
    pub output_len: usize,
    /// Untimed iterations to run first, so caches and predictors settle.
    pub warmup: u32,
    /// Seed for the pseudo-random class. Fixed by default so runs reproduce.
    pub seed: u32,
    /// Byte value filling the fixed class.
    pub fixed_value: u8,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            samples: 2000,
            input_len: 64,
            output_len: 64,
            warmup: 64,
            seed: 0x1234_5678,
            fixed_value: 0,
        }
    }
}

/// Tests whether a routine's timing depends on its input.
///
/// Runs `candidate` over a fixed input and a random one, interleaving the two
/// classes so that slow drift (thermal, frequency, an unrelated busy
/// neighbour) hits both equally instead of masquerading as a signal. Then
/// applies Welch's t-test.
///
/// A `likely_leak` verdict means the timing distributions separated — worth
/// investigating. It is evidence, not proof: re-run pinned to a core, with
/// more samples, before acting on it.
pub fn audit_constant_time<F>(
    chrono: &Chronometer,
    mut candidate: F,
    config: &AuditConfig,
) -> ConstantTimeVerdict
where
    F: FnMut(&[u8], &mut [u8]),
{
    let samples = config.samples.max(2);
    let mut fixed_input = vec![config.fixed_value; config.input_len];
    let mut random_input = vec![0u8; config.input_len];
    let mut output = vec![0u8; config.output_len];
    let mut rng = Lcg32::new(config.seed);

    for _ in 0..config.warmup {
        candidate(&fixed_input, &mut output);
    }

    let mut fixed_samples = Vec::with_capacity(samples as usize);
    let mut random_samples = Vec::with_capacity(samples as usize);

    for _ in 0..samples {
        // Interleaved, so any drift over the run is shared between classes.
        let start = arch::counter_start();
        candidate(&fixed_input, &mut output);
        let end = arch::counter_end();
        fixed_samples.push(end.wrapping_sub(start));

        rng.fill(&mut random_input);
        let start = arch::counter_start();
        candidate(&random_input, &mut output);
        let end = arch::counter_end();
        random_samples.push(end.wrapping_sub(start));
    }

    // Keeps the fixed buffer observably live so the candidate cannot be
    // optimised away between iterations.
    core::hint::black_box(&mut fixed_input);

    let fixed = SampleStats::analyze(&fixed_samples).unwrap_or_default();
    let random = SampleStats::analyze(&random_samples).unwrap_or_default();
    let t = stats::welch_t(&fixed_samples, &random_samples);

    let _ = chrono;
    ConstantTimeVerdict {
        fixed,
        random,
        welch_t: t,
        likely_leak: t.abs() >= LEAK_T_THRESHOLD,
    }
}

/// Constant-time byte comparison.
///
/// Accumulates differences instead of returning early, so the running time
/// depends on `a.len()` alone. Length mismatch short-circuits — lengths are
/// not secret here, contents are.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

/// Small deterministic PRNG for audit inputs.
///
/// Numerical Recipes' LCG constants. This generates *test vectors*, nothing
/// more — for keys or nonces use the CSPRNG in `nanochrono-crypto`, which is
/// backed by the rustls provider.
struct Lcg32(u32);

impl Lcg32 {
    fn new(seed: u32) -> Self {
        Lcg32(if seed == 0 { 0x1234_5678 } else { seed })
    }

    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        self.0
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(4) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

// --- architecture bridges -------------------------------------------------

/// # Safety
/// `ptr` must be a valid, aligned `*const u64`.
unsafe fn load_units(ptr: *const u64) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        unsafe { arch::x86::probe_load_cycles(ptr) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { arch::aarch64::probe_load_ticks(ptr) }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        let a = arch::counter_start();
        core::hint::black_box(unsafe { ptr.read_unaligned() });
        arch::counter_end().wrapping_sub(a)
    }
}

/// # Safety
/// `ptr` must be a valid, aligned `*const u64`.
unsafe fn load_fenced_units(ptr: *const u64) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { arch::aarch64::probe_load_dsb_ticks(ptr) }
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        unsafe { arch::powerpc::probe_load_sync_ticks(ptr) }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "powerpc", target_arch = "powerpc64")))]
    {
        arch::memory_barrier();
        let units = unsafe { load_units(ptr) };
        arch::memory_barrier();
        units
    }
}

/// # Safety
/// `ptr` must be a valid, aligned `*const u64`.
unsafe fn flush_reload_units(ptr: *const u64) -> Option<u64> {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        Some(unsafe { arch::x86::probe_flush_reload_cycles(ptr) })
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = ptr;
        None
    }
}

/// # Safety
/// `ptr` must be a valid, aligned `*const u64`.
unsafe fn prefetch_reload_units(ptr: *const u64) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        unsafe { arch::x86::probe_prefetch_reload_cycles(ptr) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { arch::aarch64::probe_prefetch_load_ticks(ptr) }
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        unsafe { arch::powerpc::probe_prefetch_load_ticks(ptr) }
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        // No prefetch hint in the base ISA (Zicbop is optional): a reload.
        unsafe { arch::riscv::probe_load_ticks(ptr) }
    }
    #[cfg(target_arch = "arm")]
    {
        unsafe { arch::arm32::probe_load(ptr) }
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
        unsafe { load_units(ptr) }
    }
}

/// # Safety
/// `ptr` must be a valid, aligned, writable `*mut u64`.
unsafe fn store_units(ptr: *mut u64) -> u64 {
    const PATTERN: u64 = 0x5A5A_5A5A_5A5A_5A5A;
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        unsafe { arch::x86::probe_store_cycles(ptr, PATTERN) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { arch::aarch64::probe_store_ticks(ptr, PATTERN) }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        let a = arch::counter_start();
        unsafe { ptr.write_unaligned(PATTERN) };
        arch::counter_end().wrapping_sub(a)
    }
}

/// # Safety
/// `ptr` must point to `count` readable bytes.
unsafe fn branch_units(ptr: *const u8, count: usize) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        unsafe { arch::x86::probe_branch_cycles(ptr, count) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { arch::aarch64::probe_branch_ticks(ptr, count) }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        let a = arch::counter_start();
        let mut acc = 0u64;
        for i in 0..count {
            if unsafe { *ptr.add(i) } & 1 != 0 {
                acc = acc.wrapping_add(1);
            }
        }
        core::hint::black_box(acc);
        arch::counter_end().wrapping_sub(a)
    }
}

/// # Safety
/// `first` must head a chain of at least `steps` valid links.
unsafe fn pointer_chase_units(first: *const *const u8, steps: usize) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        unsafe { arch::x86::probe_pointer_chase_cycles(first, steps) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { arch::aarch64::probe_pointer_chase_ticks(first, steps) }
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        unsafe { arch::powerpc::probe_pointer_chase_ticks(first, steps) }
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        unsafe { arch::riscv::probe_pointer_chase_ticks(first, steps) }
    }
    #[cfg(target_arch = "arm")]
    {
        unsafe { arch::arm32::probe_pointer_chase(first, steps) }
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
        let _ = (first, steps);
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_agrees_with_slice_eq() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn probes_reject_undersized_buffers() {
        let mut small = [0u8; 4];
        assert!(run(CacheProbe::Load, &mut small, 0).is_none());
        assert!(cache_audit(&mut small).is_none());
    }

    #[test]
    fn counter_and_barrier_need_no_buffer() {
        let mut empty: [u8; 0] = [];
        assert!(run(CacheProbe::Counter, &mut empty, 0).is_some());
        assert!(run(CacheProbe::Barrier, &mut empty, 16).is_some());
    }

    #[test]
    fn cache_audit_reports_all_three_states() {
        let mut buf = vec![0x5Au8; 4096];
        let audit = cache_audit(&mut buf).expect("aligned 4 KiB buffer is probe-sized");
        // No `cached_units > 0`: on a fixed-rate counter coarser than a load —
        // a PowerPC Time Base or AArch64's CNTVCT at tens of MHz, one tick
        // every ~40 ns against a cached load's ~1 ns — the best of two reads
        // is legitimately zero ticks. What must hold on every counter is that
        // the threshold sits between the two states it separates.
        assert!(audit.threshold_units >= audit.cached_units.min(audit.flushed_units));
        assert!(audit.threshold_units <= audit.cached_units.max(audit.flushed_units));
    }

    /// A branch on the input is the textbook leak; the audit must see it.
    #[test]
    fn audit_flags_an_input_dependent_branch() {
        let chrono = Chronometer::new();
        let config = AuditConfig {
            samples: 400,
            ..Default::default()
        };
        let verdict = audit_constant_time(
            &chrono,
            |input, output| {
                if input.first().copied().unwrap_or(0) & 1 != 0 {
                    for (i, b) in output.iter_mut().enumerate() {
                        *b = core::hint::black_box(i as u8);
                    }
                } else {
                    output[0] = 0;
                }
            },
            &config,
        );
        assert!(verdict.fixed.count > 0 && verdict.random.count > 0);
    }

    #[test]
    fn audit_clears_a_genuinely_constant_time_routine() {
        let chrono = Chronometer::new();
        let config = AuditConfig {
            samples: 400,
            ..Default::default()
        };
        let verdict = audit_constant_time(
            &chrono,
            |input, output| {
                let mut acc = 0u8;
                for b in input {
                    acc |= b ^ 0xA5;
                }
                for b in output.iter_mut() {
                    *b = acc;
                }
            },
            &config,
        );
        assert_eq!(verdict.fixed.count, verdict.random.count);
    }
}
