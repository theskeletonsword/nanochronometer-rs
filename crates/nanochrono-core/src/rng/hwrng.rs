// SPDX-License-Identifier: Apache-2.0
//! The CPU's own generators, where it has them: `RDSEED` and `RDRAND` on x86.
//!
//! Neither is trusted alone, and neither can be audited from here. `RDSEED`
//! reads the conditioned noise source; `RDRAND` reads the DRBG seeded from
//! it. The pool mixes both, and credits `RDSEED` only when the jitter source
//! cannot run (see [`super::pool`]).
//!
//! A word is refused, and the instruction dropped for the rest of the
//! session, when it is all zeros, all ones, or the same as the word before:
//! the first two are how known-broken parts fail (a generator that reports
//! success and returns a constant), and a healthy 64-bit source repeats with
//! probability 2⁻⁶⁴. On 32-bit x86 a word is two reads, and each half is
//! checked. Other architectures report no hardware generator: ARMv8.5 `RNDR`
//! and POWER9 `darn` are optional, and absent on the parts this runs on.

/// Whether an instruction can be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwState {
    /// The CPU does not implement it.
    Absent,
    /// Implemented, and every word so far looked healthy.
    Healthy,
    /// It returned a word that failed the checks; not used again.
    Failed,
}

/// The two x86 generators and their health.
#[derive(Debug, Clone)]
pub struct HwRng {
    rdseed: HwState,
    rdrand: HwState,
    // The previous word of each, for the repeat check. Only x86 has words.
    #[cfg_attr(not(any(target_arch = "x86_64", target_arch = "x86")), allow(dead_code))]
    last_seed: u64,
    #[cfg_attr(not(any(target_arch = "x86_64", target_arch = "x86")), allow(dead_code))]
    last_rand: u64,
    /// Healthy words delivered, both instructions together.
    pub words: u64,
}

/// `RDSEED` may be momentarily empty; it is retried this many times with a
/// pause between tries before a read is given up (not failed).
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const RDSEED_TRIES: u32 = 128;
/// `RDRAND` underflows far less; Intel suggests ten tries.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const RDRAND_TRIES: u32 = 10;

impl HwRng {
    /// No hardware generator.
    pub const fn absent() -> Self {
        HwRng { rdseed: HwState::Absent, rdrand: HwState::Absent, last_seed: 0, last_rand: 0, words: 0 }
    }

    /// Asks CPUID, then takes one word from each instruction so a part that
    /// is broken from the start is caught before anything is mixed.
    pub fn detect() -> Self {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            use crate::arch::x86::{cpuid, cpuid_max_leaf};
            let mut hw = Self::absent();
            if cpuid(1, 0)[2] & (1 << 30) != 0 {
                hw.rdrand = HwState::Healthy;
            }
            if cpuid_max_leaf() >= 7 && cpuid(7, 0)[1] & (1 << 18) != 0 {
                hw.rdseed = HwState::Healthy;
            }
            let _ = hw.rdseed();
            let _ = hw.rdrand();
            hw
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        Self::absent()
    }

    pub fn rdseed_state(&self) -> HwState {
        self.rdseed
    }

    pub fn rdrand_state(&self) -> HwState {
        self.rdrand
    }

    /// One `RDSEED` word, or `None` if absent, failed, or empty right now.
    pub fn rdseed(&mut self) -> Option<u64> {
        if self.rdseed != HwState::Healthy {
            return None;
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: CPUID reported RDSEED (the state is only Healthy then).
            let word = unsafe { x86::read_word(x86::Insn::Rdseed, RDSEED_TRIES) }?;
            if !plausible(word, self.last_seed) {
                self.rdseed = HwState::Failed;
                return None;
            }
            self.last_seed = word;
            self.words += 1;
            Some(word)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        None
    }

    /// One `RDRAND` word, or `None` if absent, failed, or empty right now.
    pub fn rdrand(&mut self) -> Option<u64> {
        if self.rdrand != HwState::Healthy {
            return None;
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: CPUID reported RDRAND.
            let word = unsafe { x86::read_word(x86::Insn::Rdrand, RDRAND_TRIES) }?;
            if !plausible(word, self.last_rand) {
                self.rdrand = HwState::Failed;
                return None;
            }
            self.last_rand = word;
            self.words += 1;
            Some(word)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        None
    }
}

/// Neither 32-bit half is all zeros or all ones, and the word is not the
/// previous one again.
#[cfg_attr(not(any(target_arch = "x86_64", target_arch = "x86")), allow(dead_code))]
fn plausible(word: u64, previous: u64) -> bool {
    let halves = [word as u32, (word >> 32) as u32];
    halves.iter().all(|&h| h != 0 && h != u32::MAX) && word != previous
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod x86 {
    #[derive(Clone, Copy)]
    pub(super) enum Insn {
        Rdseed,
        Rdrand,
    }

    /// One register-width read: `Some` when the carry flag reported success.
    ///
    /// # Safety
    /// The CPU must implement the instruction.
    unsafe fn read_register(insn: Insn) -> Option<usize> {
        let (value, ok): (usize, u8);
        // SAFETY: the caller's CPUID check; writes only the named registers
        // (and the flags, which is why `preserves_flags` is absent).
        unsafe {
            match insn {
                Insn::Rdseed => core::arch::asm!(
                    "rdseed {v}", "setc {ok}",
                    v = out(reg) value, ok = out(reg_byte) ok,
                    options(nomem, nostack),
                ),
                Insn::Rdrand => core::arch::asm!(
                    "rdrand {v}", "setc {ok}",
                    v = out(reg) value, ok = out(reg_byte) ok,
                    options(nomem, nostack),
                ),
            }
        }
        (ok != 0).then_some(value)
    }

    /// A 64-bit word: one read on x86-64, two on i386. Each read is retried
    /// up to `tries` times, pausing between tries.
    ///
    /// # Safety
    /// As [`read_register`].
    pub(super) unsafe fn read_word(insn: Insn, tries: u32) -> Option<u64> {
        let mut word = 0u64;
        for _ in 0..(8 / core::mem::size_of::<usize>()) {
            let mut got = None;
            for _ in 0..tries {
                // SAFETY: forwarded from this function's own contract.
                got = unsafe { read_register(insn) };
                if got.is_some() {
                    break;
                }
                core::hint::spin_loop();
            }
            // One pass on x86-64; on i386 the first read becomes the high half.
            word = (word << 32) | got? as u64;
        }
        Some(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_failure_signatures_are_refused() {
        assert!(!plausible(0, 1));
        assert!(!plausible(u64::MAX, 1));
        // The Zen 5 RDSEED erratum: success reported, low half zero.
        assert!(!plausible(0x1234_5678_0000_0000, 1));
        assert!(!plausible(0xFFFF_FFFF_1234_5678, 1));
        assert!(!plausible(0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF));
        assert!(plausible(0x0123_4567_89AB_CDEF, 7));
    }

    #[test]
    fn detection_never_reports_a_failed_part_as_healthy() {
        let mut hw = HwRng::detect();
        for _ in 0..16 {
            if let Some(w) = hw.rdrand() {
                assert!(plausible(w, 0));
            }
            if let Some(w) = hw.rdseed() {
                assert!(plausible(w, 0));
            }
        }
    }
}
