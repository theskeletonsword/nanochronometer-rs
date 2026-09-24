// SPDX-License-Identifier: Apache-2.0
//! Detection and repair of corrupted state, for environments where a bit can
//! flip on its own.
//!
//! # What this is for
//!
//! A single-event upset — a cosmic ray secondary, an alpha particle from
//! package decay — flips one bit. In most programs that shows up as a crash or
//! a wrong answer somebody notices. In *this* program it can be much quieter:
//! flip one bit in the exponent of `cycles_per_ns` and every subsequent
//! conversion is wrong by a factor of two, silently, for as long as the process
//! runs. A stopwatch that has been running for a week is exactly the workload
//! where that matters and exactly the workload where nobody re-checks the
//! constant.
//!
//! So the calibration state carries a code, and the code is checked at
//! defined points.
//!
//! # Three tiers, in cost order
//!
//! | Tier | When | Cost |
//! |---|---|---|
//! | Nothing | The hot path — [`Protected::get`] | one load |
//! | **ECC** | At checkpoints — [`Protected::verify`] | a few dozen XORs |
//! | **TMR** | Only when ECC cannot repair | three loads and a vote |
//!
//! The code is Hamming(72,64) SECDED, the same construction ECC DRAM uses:
//! it *corrects* any single-bit flip and *detects* any double-bit flip. TMR is
//! never consulted while the code still verifies, which is the overwhelmingly
//! common case — it exists for the double-bit flip the code can detect but not
//! repair, and for a strike that lands in the check byte itself.
//!
//! # What this does not do
//!
//! Being precise about the limits, because "radiation hardened" is a claim
//! that gets overused:
//!
//! * It protects **stored state**, not registers. A bit that flips inside the
//!   ALU mid-computation is gone before anything here can see it.
//! * It is **not a substitute for ECC memory**. Hardware ECC covers every
//!   byte of DRAM on every access; this covers a handful of values at
//!   checkpoints.
//! * The replicas are placed on separate cache lines, which usually means
//!   separate DRAM rows, but software cannot guarantee physical separation. A
//!   strike energetic enough to corrupt all three copies defeats the vote.
//! * Nothing here makes the *measurements* radiation-tolerant. It makes a
//!   corrupted measurement **detectable** instead of silent, which is the
//!   honest and achievable goal.

use core::sync::atomic::Ordering;

/// The event counters' storage. 64-bit where the target has 64-bit atomics;
/// 32-bit PowerPC (and other 32-bit targets) have none, and there the
/// counters are 32 bits wide. Reaching 2³² integrity checks on such a
/// machine is not a realistic concern, and the alternative — a lock — is
/// not available in a freestanding build.
#[cfg(target_has_atomic = "64")]
type EventCounter = core::sync::atomic::AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
type EventCounter = core::sync::atomic::AtomicU32;

/// Outcome of an integrity check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Integrity {
    /// The code verified. Nothing was touched.
    #[default]
    Clean,
    /// A single-bit flip, repaired from the Hamming syndrome.
    ///
    /// `bit` is the position in the 72-bit codeword, so a value above 63 means
    /// the flip landed in the check byte and the data was never wrong.
    CorrectedByEcc { bit: u32 },
    /// The code could not repair it, so the replicas were consulted and a
    /// majority agreed. `outvoted` is how many copies disagreed.
    CorrectedByTmr { outvoted: u8 },
    /// Neither tier could recover: the code failed *and* the three copies
    /// disagree with each other. The value must not be trusted.
    Unrecoverable,
}

impl Integrity {
    /// How bad this outcome is, for folding several into one report.
    ///
    /// Ordered by what it says about the hardware, not by whether the value
    /// survived: a TMR repair outranks an ECC repair because reaching the
    /// emergency tier at all means the code was overwhelmed.
    pub const fn severity(self) -> u8 {
        match self {
            Integrity::Clean => 0,
            Integrity::CorrectedByEcc { .. } => 1,
            Integrity::CorrectedByTmr { .. } => 2,
            Integrity::Unrecoverable => 3,
        }
    }

    /// The worse of two outcomes.
    pub const fn max(self, other: Integrity) -> Integrity {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }

    /// Whether the value is safe to use afterwards.
    pub const fn is_usable(self) -> bool {
        !matches!(self, Integrity::Unrecoverable)
    }

    /// Whether anything had to be repaired.
    pub const fn was_repaired(self) -> bool {
        matches!(
            self,
            Integrity::CorrectedByEcc { .. } | Integrity::CorrectedByTmr { .. }
        )
    }

    pub const fn name(self) -> &'static str {
        match self {
            Integrity::Clean => "clean",
            Integrity::CorrectedByEcc { .. } => "corrected-by-ecc",
            Integrity::CorrectedByTmr { .. } => "corrected-by-tmr",
            Integrity::Unrecoverable => "unrecoverable",
        }
    }
}

// --- process-wide counters -------------------------------------------------

static CHECKS: EventCounter = EventCounter::new(0);
static ECC_CORRECTIONS: EventCounter = EventCounter::new(0);
static TMR_CORRECTIONS: EventCounter = EventCounter::new(0);
static UNRECOVERABLE: EventCounter = EventCounter::new(0);

/// How often the tiers have fired since the process started.
///
/// Worth surfacing: a non-zero correction count on a machine at sea level
/// usually means failing DRAM rather than cosmic rays, and either way it is
/// something the operator should know before trusting a long run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IntegrityStats {
    pub checks: u64,
    pub ecc_corrections: u64,
    pub tmr_corrections: u64,
    pub unrecoverable: u64,
}

impl IntegrityStats {
    /// Whether anything has ever needed repair.
    pub const fn is_clean(&self) -> bool {
        self.ecc_corrections == 0 && self.tmr_corrections == 0 && self.unrecoverable == 0
    }

    /// A one-line summary for a status bar.
    #[cfg(feature = "std")]
    pub fn summary(&self) -> String {
        if self.is_clean() {
            format!("{} checks, no corrections", self.checks)
        } else {
            format!(
                "{} checks, {} ECC, {} TMR, {} unrecoverable",
                self.checks, self.ecc_corrections, self.tmr_corrections, self.unrecoverable
            )
        }
    }
}

/// Reads the process-wide counters.
// `u64::from` is a no-op where the counters are 64-bit and a widening where
// they are 32-bit (no 64-bit atomics), which is why it stays.
#[allow(clippy::useless_conversion)]
pub fn stats() -> IntegrityStats {
    IntegrityStats {
        checks: u64::from(CHECKS.load(Ordering::Relaxed)),
        ecc_corrections: u64::from(ECC_CORRECTIONS.load(Ordering::Relaxed)),
        tmr_corrections: u64::from(TMR_CORRECTIONS.load(Ordering::Relaxed)),
        unrecoverable: u64::from(UNRECOVERABLE.load(Ordering::Relaxed)),
    }
}

fn record(outcome: Integrity) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    match outcome {
        Integrity::CorrectedByEcc { .. } => ECC_CORRECTIONS.fetch_add(1, Ordering::Relaxed),
        Integrity::CorrectedByTmr { .. } => TMR_CORRECTIONS.fetch_add(1, Ordering::Relaxed),
        Integrity::Unrecoverable => UNRECOVERABLE.fetch_add(1, Ordering::Relaxed),
        Integrity::Clean => 0,
    };
}

// --- Hamming(72,64) SECDED -------------------------------------------------

/// Codeword positions, 1-indexed. Powers of two hold parity, the rest data.
///
/// 71 positions minus the 7 powers of two leaves exactly 64 for the payload.
const CODEWORD_LEN: u32 = 71;

/// Whether a codeword position holds a parity bit.
const fn is_parity_position(position: u32) -> bool {
    position.is_power_of_two()
}

/// The codeword position holding data bit `index`.
const fn data_position(index: u32) -> u32 {
    let mut seen = 0;
    let mut position = 1;
    while position <= CODEWORD_LEN {
        if !is_parity_position(position) {
            if seen == index {
                return position;
            }
            seen += 1;
        }
        position += 1;
    }
    // Unreachable: 71 positions minus 7 powers of two is exactly 64.
    0
}

/// For each of the seven Hamming parities, which data bits feed it.
///
/// Built at compile time so a verification is seven ANDs and seven popcounts
/// rather than a nested scan over codeword positions. That difference is what
/// makes the check cheap enough to run on every stopwatch read instead of only
/// at a once-a-second checkpoint.
const PARITY_MASKS: [u64; 7] = build_parity_masks();

const fn build_parity_masks() -> [u64; 7] {
    let mut masks = [0u64; 7];
    let mut index = 0;
    while index < 64 {
        let position = data_position(index);
        let mut k = 0;
        while k < 7 {
            if position & (1 << k) != 0 {
                masks[k] |= 1u64 << index;
            }
            k += 1;
        }
        index += 1;
    }
    masks
}

/// The data bit index at codeword `position`, or `None` for a parity position.
fn position_to_data_index(position: u32) -> Option<u32> {
    if position == 0 || position > CODEWORD_LEN || is_parity_position(position) {
        return None;
    }
    let mut index = 0;
    for p in 1..position {
        if !is_parity_position(p) {
            index += 1;
        }
    }
    Some(index)
}

/// The seven Hamming parities P1, P2, P4, ... P64.
#[inline]
fn hamming_parities(data: u64) -> u8 {
    let mut parity = 0u8;
    let mut k = 0;
    while k < 7 {
        parity |= (((data & PARITY_MASKS[k]).count_ones() & 1) as u8) << k;
        k += 1;
    }
    parity
}

/// Computes the 8 check bits: seven Hamming parities plus one overall parity.
///
/// Bits 0..6 are P1, P2, P4, ... P64; bit 7 is the parity of the whole
/// codeword — data bits *and* parity bits — which is what turns
/// single-error-correcting into single-error-correcting **double-error-
/// detecting**.
fn check_bits(data: u64) -> u8 {
    let parity = hamming_parities(data);
    let overall = (data.count_ones() + parity.count_ones()) % 2;
    parity | ((overall as u8) << 7)
}

/// What a decode found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoded {
    Clean,
    /// Repaired; carries the corrected data and the codeword position.
    Corrected {
        data: u64,
        bit: u32,
    },
    /// Two or more bits flipped: detected, not correctable.
    DoubleError,
}

fn decode(data: u64, stored: u8) -> Decoded {
    let stored_parities = stored & 0x7F;
    let stored_overall = stored >> 7 & 1;

    let syndrome = (hamming_parities(data) ^ stored_parities) as u32;

    // The received word's parity is computed over the *stored* parity bits,
    // not freshly recomputed ones. Recomputing them would make a data flip
    // change both terms, which cancels out and turns every single-bit error
    // into an apparent double error.
    let received_overall = ((data.count_ones() + stored_parities.count_ones()) % 2) as u8;
    let overall_differs = received_overall != stored_overall;

    match (syndrome, overall_differs) {
        // Nothing to do.
        (0, false) => Decoded::Clean,
        // Only the overall parity bit flipped. The data is intact; position 72
        // names that bit, which is outside the 64 data bits by construction.
        (0, true) => Decoded::Corrected { data, bit: 72 },
        // A single flip, at the codeword position the syndrome names.
        (position, true) => match position_to_data_index(position) {
            Some(index) => Decoded::Corrected {
                data: data ^ (1u64 << index),
                bit: index,
            },
            // A parity bit flipped; the data was never wrong.
            None => Decoded::Corrected {
                data,
                bit: 64 + position,
            },
        },
        // Syndrome set but overall parity agrees: an even number of bits
        // flipped. Detectable, not correctable — this is where TMR earns its
        // keep.
        (_, false) => Decoded::DoubleError,
    }
}

// --- the protected container ----------------------------------------------

/// One TMR replica, on its own cache line.
///
/// Separation is the whole point: two copies sharing a line usually share a
/// DRAM row, and a strike that corrupts one would corrupt the other. Software
/// cannot guarantee physical separation, but a cache line is the coarsest
/// granularity it can ask for.
#[repr(align(64))]
#[derive(Debug, Clone, Copy)]
struct Replica {
    value: u64,
    /// The replica's own code.
    ///
    /// Without one a replica is just an unverifiable number, and the vote
    /// cannot tell a good copy from a damaged one — it would count a
    /// corrupted replica as a vote and, if two happened to agree, hand back a
    /// wrong value with a majority behind it. Its own code makes each copy
    /// independently checkable, and single-bit damage to a replica is
    /// repaired rather than merely outvoted.
    check: u8,
}

impl Replica {
    fn new(value: u64) -> Replica {
        Replica {
            value,
            check: check_bits(value),
        }
    }

    /// The value this copy stands behind, or `None` if it is too damaged to
    /// speak for itself.
    fn candidate(&self) -> Option<u64> {
        match decode(self.value, self.check) {
            Decoded::Clean => Some(self.value),
            Decoded::Corrected { data, .. } => Some(data),
            Decoded::DoubleError => None,
        }
    }
}

/// A `u64` carrying its own error-correcting code and two spare copies.
///
/// Reads on the hot path go through [`get`](Self::get) and cost one load. The
/// code is verified only when [`verify`](Self::verify) or
/// [`get_verified`](Self::get_verified) is called, which is where the caller
/// decides the checkpoint should be.
#[derive(Debug, Clone, Copy)]
pub struct Protected {
    value: u64,
    check: u8,
    replicas: [Replica; 2],
}

impl Default for Protected {
    fn default() -> Self {
        Protected::new(0)
    }
}

impl Protected {
    /// Stores `value` with its code and replicas.
    pub fn new(value: u64) -> Protected {
        Protected {
            value,
            check: check_bits(value),
            replicas: [Replica::new(value), Replica::new(value)],
        }
    }

    /// Reads without checking. One load; use on the hot path.
    ///
    /// This is deliberately the cheap default: a nanosecond-resolution library
    /// cannot afford a code verification inside every conversion, and running
    /// one would not help — a flip that happens after the check is not caught
    /// by it either. Verification belongs at checkpoints, which is what
    /// [`verify`](Self::verify) is for.
    #[inline(always)]
    pub fn get(&self) -> u64 {
        self.value
    }

    /// Reads with verification, returning the repaired value.
    ///
    /// Cannot fix the stored copy — that needs [`verify`](Self::verify) and a
    /// `&mut` — but it never hands back a value the code says is wrong. Use it
    /// on read paths that only have a shared borrow, such as rendering a
    /// stopwatch face.
    ///
    /// The outcome is still counted, so a display path that keeps finding
    /// corruption shows up in the process counters even though it cannot
    /// repair the storage itself.
    #[inline]
    pub fn get_checked(&self) -> (u64, Integrity) {
        let outcome = match decode(self.value, self.check) {
            Decoded::Clean => return (self.value, Integrity::Clean),
            Decoded::Corrected { data, bit } => {
                record(Integrity::CorrectedByEcc { bit });
                return (data, Integrity::CorrectedByEcc { bit });
            }
            Decoded::DoubleError => self.vote(),
        };
        record(outcome.1);
        outcome
    }

    /// The emergency tier, without mutating: returns the majority value.
    ///
    /// Only copies that satisfy their own code get a vote. A copy damaged
    /// past repair is silent rather than wrong, so two independently
    /// corrupted replicas cannot outvote a good one.
    fn vote(&self) -> (u64, Integrity) {
        let mut ballots = [None; 3];
        // The primary reached this path because its own code failed, so it
        // does not vote: including it would let the damage vote for itself.
        ballots[1] = self.replicas[0].candidate();
        ballots[2] = self.replicas[1].candidate();

        for candidate in ballots.into_iter().flatten() {
            let agreeing = ballots.iter().filter(|&&c| c == Some(candidate)).count();
            if agreeing < 2 {
                continue;
            }
            return (
                candidate,
                Integrity::CorrectedByTmr {
                    outvoted: (3 - agreeing) as u8,
                },
            );
        }
        (self.value, Integrity::Unrecoverable)
    }

    /// Replaces the value and regenerates the code and replicas.
    pub fn set(&mut self, value: u64) {
        self.value = value;
        self.check = check_bits(value);
        self.replicas = [Replica::new(value), Replica::new(value)];
    }

    /// Verifies, repairing in place if it can.
    ///
    /// ECC first, because it is cheap and handles the single-bit flip that is
    /// by far the most likely event. TMR only when ECC reports a double error
    /// it cannot repair.
    pub fn verify(&mut self) -> Integrity {
        let outcome = match decode(self.value, self.check) {
            Decoded::Clean => {
                // The code is satisfied. The replicas are not consulted: that
                // is the point of doing this in tiers.
                Integrity::Clean
            }
            Decoded::Corrected { data, bit } => {
                self.value = data;
                self.check = check_bits(data);
                self.replicas = [Replica::new(data), Replica::new(data)];
                Integrity::CorrectedByEcc { bit }
            }
            Decoded::DoubleError => self.repair_by_vote(),
        };
        record(outcome);
        outcome
    }

    /// Verifies and returns the value, so a caller can do both in one step.
    pub fn get_verified(&mut self) -> (u64, Integrity) {
        let integrity = self.verify();
        (self.value, integrity)
    }

    /// The emergency tier: majority vote across the three copies, writing the
    /// winner back.
    ///
    /// Reached only when the code detected damage it could not repair. A
    /// majority is two matching copies out of three, and the winner must also
    /// satisfy the code — so a vote never resurrects a value ECC knows is bad.
    /// Without such a majority nothing here can tell which copy is right, and
    /// the value is declared unrecoverable rather than guessed at.
    fn repair_by_vote(&mut self) -> Integrity {
        let (value, outcome) = self.vote();
        if outcome.is_usable() {
            self.value = value;
            self.check = check_bits(value);
            self.replicas = [Replica::new(value), Replica::new(value)];
        }
        outcome
    }

    /// Flips one bit of the stored value, for tests and fault-injection drills.
    ///
    /// This is the only way to exercise the repair paths without a particle
    /// accelerator, and a system that claims to tolerate upsets should be
    /// tested against injected ones.
    ///
    /// `bit` 0..63 hits the working copy; 64..71 hits the check byte; 72..135
    /// and 136..199 hit the first and second replica.
    pub fn inject_flip(&mut self, bit: u32) {
        match bit {
            0..=63 => self.value ^= 1u64 << bit,
            64..=71 => self.check ^= 1u8 << (bit - 64),
            72..=135 => self.replicas[0].value ^= 1u64 << (bit - 72),
            136..=199 => self.replicas[1].value ^= 1u64 << (bit - 136),
            200..=207 => self.replicas[0].check ^= 1u8 << (bit - 200),
            208..=215 => self.replicas[1].check ^= 1u8 << (bit - 208),
            _ => {}
        }
    }
}

/// Stores an `f64` by its bit pattern.
///
/// Floating-point calibration constants are the values most worth protecting:
/// a flip in the exponent changes the result by a power of two, which is large
/// enough to matter and small enough to look plausible in a log.
impl Protected {
    pub fn from_f64(value: f64) -> Protected {
        Protected::new(value.to_bits())
    }

    #[inline(always)]
    pub fn get_f64(&self) -> f64 {
        f64::from_bits(self.value)
    }

    /// Reads with verification, returning the repaired value.
    ///
    /// The `f64` counterpart of [`get_checked`](Self::get_checked): use it
    /// wherever the number is about to be converted with rather than merely
    /// displayed.
    #[inline]
    pub fn get_f64_checked(&self) -> (f64, Integrity) {
        let (bits, outcome) = self.get_checked();
        (f64::from_bits(bits), outcome)
    }

    pub fn set_f64(&mut self, value: f64) {
        self.set(value.to_bits());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_value_verifies_without_touching_the_replicas() {
        let mut p = Protected::new(0x0123_4567_89AB_CDEF);
        assert_eq!(p.verify(), Integrity::Clean);
        assert_eq!(p.get(), 0x0123_4567_89AB_CDEF);
    }

    /// The core ECC guarantee: every single-bit flip in the payload is
    /// repaired, not merely noticed.
    #[test]
    fn ecc_repairs_every_single_data_bit_flip() {
        const VALUE: u64 = 0xDEAD_BEEF_CAFE_F00D;
        for bit in 0..64 {
            let mut p = Protected::new(VALUE);
            p.inject_flip(bit);
            let outcome = p.verify();
            assert_eq!(
                outcome,
                Integrity::CorrectedByEcc { bit },
                "bit {bit} was not repaired by ECC"
            );
            assert_eq!(p.get(), VALUE, "bit {bit} repaired to the wrong value");
        }
    }

    /// A flip in the check byte must be recognised as such: the data was never
    /// wrong, and rewriting it would be the bug.
    #[test]
    fn ecc_repairs_a_flip_in_its_own_check_byte() {
        const VALUE: u64 = 0x5555_AAAA_5555_AAAA;
        for bit in 64..72 {
            let mut p = Protected::new(VALUE);
            p.inject_flip(bit);
            let outcome = p.verify();
            assert!(
                matches!(outcome, Integrity::CorrectedByEcc { .. }),
                "check-byte bit {bit} gave {outcome:?}"
            );
            assert_eq!(p.get(), VALUE);
            assert_eq!(p.verify(), Integrity::Clean, "repair did not stick");
        }
    }

    /// Two flips are beyond the code, so the emergency tier has to take over.
    #[test]
    fn tmr_recovers_what_ecc_cannot() {
        const VALUE: u64 = 0x1234_5678_9ABC_DEF0;
        let mut p = Protected::new(VALUE);
        p.inject_flip(3);
        p.inject_flip(40);

        let outcome = p.verify();
        assert_eq!(
            outcome,
            Integrity::CorrectedByTmr { outvoted: 1 },
            "a double flip should have escalated to the vote"
        );
        assert_eq!(p.get(), VALUE);
        assert_eq!(p.verify(), Integrity::Clean);
    }

    /// TMR is a fallback, not a routine step: a clean value must never consult
    /// the replicas, so corrupting them alone must go unnoticed.
    #[test]
    fn a_clean_code_never_consults_the_replicas() {
        let mut p = Protected::new(42);
        p.inject_flip(72); // first replica
        p.inject_flip(136); // second replica
        assert_eq!(
            p.verify(),
            Integrity::Clean,
            "the vote ran even though the code verified"
        );
        assert_eq!(p.get(), 42);
    }

    /// Each replica carries its own code, so single-bit damage to a replica
    /// is repaired by that replica rather than merely outvoted. Five separate
    /// flips across all three copies still come back with the right answer.
    #[test]
    fn replicas_repair_themselves_before_voting() {
        const VALUE: u64 = 0xFFFF_0000_FFFF_0000;
        let mut p = Protected::new(VALUE);
        p.inject_flip(1);
        p.inject_flip(2);
        p.inject_flip(72 + 5);
        p.inject_flip(136 + 9);
        assert_eq!(p.verify(), Integrity::CorrectedByTmr { outvoted: 1 });
        assert_eq!(p.get(), VALUE);
        assert_eq!(p.verify(), Integrity::Clean, "the repair did not stick");
    }

    /// Two replicas damaged at the same bit position used to agree with each
    /// other and carry a wrong value to a 2-of-3 majority. Their own codes
    /// now repair them instead, so the agreement is on the true value.
    #[test]
    fn matching_damage_to_both_replicas_does_not_win_the_vote() {
        const VALUE: u64 = 0x1234_5678_9ABC_DEF0;
        let mut p = Protected::new(VALUE);
        p.inject_flip(4);
        p.inject_flip(20);
        p.inject_flip(72);
        p.inject_flip(136);
        assert!(p.verify().is_usable());
        assert_eq!(p.get(), VALUE, "the vote returned corrupted agreement");
    }

    /// Past what every copy can repair there is no majority and no honest
    /// answer, and saying so beats a confident wrong number.
    #[test]
    fn no_majority_is_reported_rather_than_guessed() {
        let mut p = Protected::new(0xFFFF_0000_FFFF_0000);
        // Two flips in the working copy defeat its code, and two in each
        // replica defeat theirs, leaving nothing that can speak for itself.
        p.inject_flip(1);
        p.inject_flip(2);
        p.inject_flip(72 + 5);
        p.inject_flip(72 + 33);
        p.inject_flip(136 + 9);
        p.inject_flip(136 + 41);
        assert_eq!(p.verify(), Integrity::Unrecoverable);
    }

    /// The replica check bytes are injectable too, so a drill can damage
    /// every part of the structure.
    #[test]
    fn replica_check_bytes_are_reachable_and_repairable() {
        const VALUE: u64 = 0xA5A5_5A5A_A5A5_5A5A;
        for bit in 200..216 {
            let mut p = Protected::new(VALUE);
            p.inject_flip(bit);
            // Damage confined to a replica's code never reaches the primary.
            assert_eq!(p.verify(), Integrity::Clean);
            assert_eq!(p.get(), VALUE);
        }
    }

    #[test]
    fn every_double_flip_is_at_least_detected() {
        const VALUE: u64 = 0x0F0F_F0F0_0F0F_F0F0;
        // A representative sweep rather than all 2016 pairs: enough to catch a
        // systematic hole, fast enough to stay in the unit suite.
        for a in (0..64).step_by(7) {
            for b in (0..64).step_by(5) {
                if a == b {
                    continue;
                }
                let mut bare = Protected::new(VALUE);
                bare.inject_flip(a);
                bare.inject_flip(b);
                // Damage the replicas past their own codes too, so TMR
                // cannot rescue it and the detection itself is under test.
                bare.replicas[0] = Replica {
                    value: 0,
                    check: 0xFF,
                };
                bare.replicas[1] = Replica {
                    value: 1,
                    check: 0xFF,
                };
                assert_eq!(
                    bare.verify(),
                    Integrity::Unrecoverable,
                    "flips at {a} and {b} were not detected"
                );
            }
        }
    }

    #[test]
    fn f64_round_trips_and_repairs() {
        let mut p = Protected::from_f64(2.418105195);
        assert_eq!(p.get_f64(), 2.418105195);
        // Bit 62 is high in the exponent: exactly the flip that changes a
        // calibration constant by a power of two while still looking sane.
        p.inject_flip(62);
        assert!(p.verify().was_repaired());
        assert_eq!(p.get_f64(), 2.418105195);
    }

    /// The counters are process-wide by design, so this asserts lower bounds
    /// rather than exact deltas: other tests in the same binary run
    /// chronometers, and those verify their own calibration on a timer.
    #[test]
    fn counters_track_each_tier() {
        let before = stats();
        let mut p = Protected::new(7);
        p.verify(); // clean
        p.inject_flip(0);
        p.verify(); // ecc
        p.inject_flip(1);
        p.inject_flip(2);
        p.verify(); // tmr
        let after = stats();

        assert!(after.checks > before.checks + 2);
        assert!(after.ecc_corrections > before.ecc_corrections);
        assert!(after.tmr_corrections > before.tmr_corrections);
        // A lower bound, not an equality: the counters are process-wide and
        // the unrecoverable-damage tests run in parallel with this one.
        assert!(after.unrecoverable >= before.unrecoverable);
        assert!(!after.is_clean(), "a repaired process cannot report clean");
    }

    #[test]
    fn integrity_reports_usability_honestly() {
        assert!(Integrity::Clean.is_usable());
        assert!(Integrity::CorrectedByEcc { bit: 0 }.is_usable());
        assert!(Integrity::CorrectedByTmr { outvoted: 1 }.is_usable());
        assert!(!Integrity::Unrecoverable.is_usable());
        assert!(!Integrity::Clean.was_repaired());
        assert!(Integrity::CorrectedByEcc { bit: 0 }.was_repaired());
    }

    /// The codeword layout has to be exactly 64 data positions in 71 slots, or
    /// the whole construction is off by one somewhere.
    #[test]
    fn the_codeword_layout_is_well_formed() {
        let data_positions: Vec<u32> = (1..=CODEWORD_LEN)
            .filter(|p| !is_parity_position(*p))
            .collect();
        assert_eq!(data_positions.len(), 64);
        for index in 0..64u32 {
            let position = data_position(index);
            assert!(!is_parity_position(position));
            assert_eq!(position_to_data_index(position), Some(index));
        }
        for power in 0..7 {
            assert_eq!(position_to_data_index(1 << power), None);
        }
    }
}
