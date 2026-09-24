// SPDX-License-Identifier: Apache-2.0
//! When to check stored state for flipped bits: rarely, until one is found.
//!
//! [`crate::redundancy`] supplies the tiers — a plain read, a Hamming
//! SECDED check, a TMR vote — and says nothing about *when* to use them. This
//! is that policy.
//!
//! Checking on every read is wasted work almost always: a single-event upset
//! is rare at sea level and rare enough in orbit that a stopwatch spends
//! nearly all of its life with nothing to find. The check never sits inside a
//! measurement — the counter is read first, the check comes after — so it
//! costs CPU time and cache, not precision; but there is no reason to pay
//! that per frame for an event that has not happened.
//!
//! So there are two modes:
//!
//! - [`Mode::Normal`]: reads are plain loads. Everything protected is
//!   scrubbed (checked and repaired) once per [`SCRUB_INTERVAL_NS`], and at
//!   every transition that *stores* a value — a pause, a lap — since that is
//!   where a flipped bit would otherwise be written back as good.
//! - [`Mode::Emergency`]: entered the moment a scrub finds anything. Every
//!   read is verified, TMR included, until [`EMERGENCY_HOLD_NS`] pass with
//!   nothing found; one upset is evidence that more may follow (a solar
//!   particle event, a failing DIMM), and that is when checking is worth it.
//!
//! An [`Integrity::Unrecoverable`] result latches: the value cannot be
//! trusted, the mode stays Emergency and [`SpaceMode::unrecoverable`] stays
//! set until the owner resets the state it describes.

use crate::redundancy::Integrity;

/// How often a Normal-mode scrub runs.
pub const SCRUB_INTERVAL_NS: u64 = 1_000_000_000;

/// How long Emergency lasts after the last detection.
pub const EMERGENCY_HOLD_NS: u64 = 300_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Plain reads; a scrub every [`SCRUB_INTERVAL_NS`].
    Normal,
    /// Verified reads, since the last detection at `since_ns`.
    Emergency { since_ns: u64 },
}

/// The policy state. The caller owns the protected values and the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceMode {
    mode: Mode,
    last_scrub_ns: Option<u64>,
    unrecoverable: bool,
    /// Upsets found (repaired or not) since power-on, for a status line.
    detections: u32,
}

impl Default for SpaceMode {
    fn default() -> Self {
        SpaceMode::new()
    }
}

impl SpaceMode {
    pub const fn new() -> SpaceMode {
        SpaceMode {
            mode: Mode::Normal,
            last_scrub_ns: None,
            unrecoverable: false,
            detections: 0,
        }
    }

    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether reads should be verified right now.
    pub const fn verify_reads(&self) -> bool {
        matches!(self.mode, Mode::Emergency { .. })
    }

    /// Whether a scrub is due. In Emergency every read is already verified,
    /// so a scrub only covers what is not being read.
    pub fn scrub_due(&self, now_ns: u64) -> bool {
        match self.last_scrub_ns {
            None => true,
            Some(last) => now_ns.saturating_sub(last) >= SCRUB_INTERVAL_NS,
        }
    }

    /// Records the worst outcome of a scrub, or of any verified read.
    /// Returns the mode that now applies.
    pub fn record(&mut self, outcome: Integrity, now_ns: u64, was_scrub: bool) -> Mode {
        if was_scrub {
            self.last_scrub_ns = Some(now_ns);
        }
        if outcome != Integrity::Clean {
            self.detections = self.detections.saturating_add(1);
            self.mode = Mode::Emergency { since_ns: now_ns };
            if outcome == Integrity::Unrecoverable {
                self.unrecoverable = true;
            }
            return self.mode;
        }
        if let Mode::Emergency { since_ns } = self.mode {
            if !self.unrecoverable && now_ns.saturating_sub(since_ns) >= EMERGENCY_HOLD_NS {
                self.mode = Mode::Normal;
            }
        }
        self.mode
    }

    /// Whether an unrecoverable value was seen and not yet cleared.
    pub const fn unrecoverable(&self) -> bool {
        self.unrecoverable
    }

    /// Upsets found since power-on.
    pub const fn detections(&self) -> u32 {
        self.detections
    }

    /// The owner replaced the damaged state (a reset): the latch clears, and
    /// Emergency then runs out its hold like any other.
    pub fn clear_unrecoverable(&mut self) {
        self.unrecoverable = false;
    }

    /// For a status line.
    pub const fn name(&self) -> &'static str {
        match (self.mode, self.unrecoverable) {
            (_, true) => "EMERGENCY: value lost",
            (Mode::Emergency { .. }, false) => "EMERGENCY: verifying",
            (Mode::Normal, false) => "normal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn normal_until_a_scrub_finds_something() {
        let mut m = SpaceMode::new();
        assert!(m.scrub_due(0));
        assert_eq!(m.record(Integrity::Clean, 0, true), Mode::Normal);
        assert!(!m.verify_reads());
        assert!(!m.scrub_due(S - 1));
        assert!(m.scrub_due(S));
    }

    #[test]
    fn a_detection_escalates_and_holds() {
        let mut m = SpaceMode::new();
        m.record(Integrity::CorrectedByEcc { bit: 3 }, 10 * S, true);
        assert!(m.verify_reads());
        m.record(Integrity::Clean, 10 * S + EMERGENCY_HOLD_NS - 1, true);
        assert!(m.verify_reads());
        m.record(Integrity::Clean, 10 * S + EMERGENCY_HOLD_NS, true);
        assert_eq!(m.mode(), Mode::Normal);
        assert_eq!(m.detections(), 1);
    }

    #[test]
    fn a_second_detection_restarts_the_hold() {
        let mut m = SpaceMode::new();
        m.record(Integrity::CorrectedByEcc { bit: 3 }, 0, true);
        m.record(Integrity::CorrectedByTmr { outvoted: 1 }, 100 * S, false);
        m.record(Integrity::Clean, EMERGENCY_HOLD_NS, true);
        assert!(m.verify_reads(), "hold counts from the latest detection");
    }

    #[test]
    fn unrecoverable_latches_until_cleared() {
        let mut m = SpaceMode::new();
        m.record(Integrity::Unrecoverable, 0, true);
        m.record(Integrity::Clean, 10 * EMERGENCY_HOLD_NS, true);
        assert!(m.unrecoverable() && m.verify_reads());
        m.clear_unrecoverable();
        m.record(Integrity::Clean, 11 * EMERGENCY_HOLD_NS, true);
        assert_eq!(m.mode(), Mode::Normal);
    }
}
