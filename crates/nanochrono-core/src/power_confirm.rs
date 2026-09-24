// SPDX-License-Identifier: Apache-2.0
//! The confirmation standing between a keypress and a restart or power-off.
//!
//! A single key that restarts the machine is a single key a BadUSB can press.
//! Such a device enumerates as a keyboard and types a script; so does a
//! firmware's legacy USB emulation, which delivers a USB keyboard's keys
//! through the 8042 where even a raw-port reader sees them. Asking for the
//! same key twice stops nothing — the script presses it twice.
//!
//! What the script cannot do is read the screen. So the request shows a code
//! drawn at the moment it is made, and only typing that code carries it out:
//!
//! - [`CODE_DIGITS`] decimal digits, typed within [`CONFIRM_WINDOW_NS`];
//! - a wrong digit cancels, and the next request is refused for a lockout
//!   that doubles with each consecutive miss (from [`LOCKOUT_BASE_NS`] up to
//!   [`LOCKOUT_MAX_NS`]), so walking through the 100 codes blind takes hours
//!   rather than seconds;
//! - cancelling (Esc, timing out) is not a miss: nobody is punished for
//!   changing their mind.
//!
//! A person at the keyboard pays two keystrokes. Nothing here is a
//! cryptographic secret — the attacker it answers is blind, not patient.
//!
//! This module is only the policy. Time is any monotonic nanosecond clock the
//! caller has, and randomness is whatever the caller can [`Confirm::stir`] in:
//! counter values at input events, counter jitter, hardware generators. No
//! single source is trusted: each is folded through a non-linear mix, so one
//! that is broken or hostile cannot cancel the others without knowing the
//! pool.

/// Digits in a confirmation code.
pub const CODE_DIGITS: usize = 2;

/// How long a shown code stays valid.
pub const CONFIRM_WINDOW_NS: u64 = 10_000_000_000;

/// Lockout after the first miss; doubled per consecutive miss.
pub const LOCKOUT_BASE_NS: u64 = 5_000_000_000;

/// The ceiling the doubling stops at.
pub const LOCKOUT_MAX_NS: u64 = 600_000_000_000;

/// What the confirmation guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Restart,
    Shutdown,
}

impl Action {
    /// For a prompt: "restart", "shut down".
    pub const fn verb(self) -> &'static str {
        match self {
            Action::Restart => "restart",
            Action::Shutdown => "shut down",
        }
    }
}

/// Why [`Confirm::request`] did not show a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Locked out after a miss; this many nanoseconds remain.
    LockedOut { remaining_ns: u64 },
}

/// What one typed digit did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Right so far; more digits to go.
    Pending,
    /// The whole code was typed: the caller must carry the action out.
    Confirmed(Action),
    /// Wrong digit: cancelled, and the lockout has started.
    Rejected,
    /// Nothing was pending, or it had expired; the digit meant nothing here.
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pending {
    action: Action,
    code: [u8; CODE_DIGITS],
    typed: usize,
    since_ns: u64,
}

/// The confirmation state. One per screen that offers restart/shut down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confirm {
    pool: u64,
    pending: Option<Pending>,
    misses: u32,
    locked_until_ns: u64,
}

impl Default for Confirm {
    fn default() -> Self {
        Confirm::new()
    }
}

/// SplitMix64's finaliser: every input bit reaches every output bit, so a
/// counter whose low bits alone vary still yields an even digit.
const fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Confirm {
    pub const fn new() -> Confirm {
        Confirm {
            pool: 0x9E37_79B9_7F4A_7C15,
            pending: None,
            misses: 0,
            locked_until_ns: 0,
        }
    }

    /// Folds unpredictable bits into the pool. Call it with the counter at
    /// every input event and with any hardware randomness available: the
    /// code is drawn from everything stirred in before it is requested.
    pub fn stir(&mut self, entropy: u64) {
        self.pool = mix(self.pool ^ entropy).wrapping_add(0x9E37_79B9_7F4A_7C15);
    }

    /// Nanoseconds until a request is allowed again; 0 = now.
    pub fn lockout_remaining_ns(&self, now_ns: u64) -> u64 {
        self.locked_until_ns.saturating_sub(now_ns)
    }

    /// Asks for `action`. On `Ok` the code to show is returned (and is also
    /// available from [`Confirm::shown`]); the action itself waits for it.
    ///
    /// A request while another is pending replaces it with a fresh code.
    pub fn request(
        &mut self,
        action: Action,
        now_ns: u64,
        entropy: u64,
    ) -> Result<[u8; CODE_DIGITS], Refused> {
        let remaining_ns = self.lockout_remaining_ns(now_ns);
        if remaining_ns > 0 {
            self.pending = None;
            return Err(Refused::LockedOut { remaining_ns });
        }
        self.stir(entropy ^ now_ns.rotate_left(32));
        let mut r = mix(self.pool);
        let mut code = [0u8; CODE_DIGITS];
        for d in code.iter_mut() {
            *d = (r % 10) as u8;
            r /= 10;
        }
        // Advance the pool so the next code is not this one's neighbour.
        self.stir(r);
        self.pending = Some(Pending {
            action,
            code,
            typed: 0,
            since_ns: now_ns,
        });
        Ok(code)
    }

    /// The pending request, if it has not expired: the action, its code and
    /// how many digits have been typed. For drawing the prompt.
    pub fn shown(&self, now_ns: u64) -> Option<(Action, [u8; CODE_DIGITS], usize)> {
        self.live(now_ns).map(|p| (p.action, p.code, p.typed))
    }

    /// Nanoseconds before the pending code expires, if one is pending.
    pub fn remaining_ns(&self, now_ns: u64) -> Option<u64> {
        self.live(now_ns)
            .map(|p| CONFIRM_WINDOW_NS - now_ns.saturating_sub(p.since_ns))
    }

    /// Whether a code is on screen, so the caller routes digits here rather
    /// than to their usual bindings.
    pub fn is_pending(&self, now_ns: u64) -> bool {
        self.live(now_ns).is_some()
    }

    /// Drops the pending request without penalty (Esc, a click elsewhere).
    pub fn cancel(&mut self) {
        self.pending = None;
    }

    /// Feeds one typed digit (0–9). Anything above 9 counts as a wrong digit.
    pub fn digit(&mut self, d: u8, now_ns: u64) -> Outcome {
        let Some(mut p) = self.live(now_ns) else {
            self.pending = None;
            return Outcome::Idle;
        };
        if p.code[p.typed] != d {
            self.pending = None;
            let shift = self.misses.min(16);
            let lockout = LOCKOUT_BASE_NS.saturating_mul(1u64 << shift).min(LOCKOUT_MAX_NS);
            self.misses = self.misses.saturating_add(1);
            self.locked_until_ns = now_ns.saturating_add(lockout);
            return Outcome::Rejected;
        }
        p.typed += 1;
        if p.typed == CODE_DIGITS {
            self.pending = None;
            self.misses = 0;
            return Outcome::Confirmed(p.action);
        }
        self.pending = Some(p);
        Outcome::Pending
    }

    fn live(&self, now_ns: u64) -> Option<Pending> {
        self.pending
            .filter(|p| now_ns.saturating_sub(p.since_ns) < CONFIRM_WINDOW_NS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    fn type_code(c: &mut Confirm, code: [u8; CODE_DIGITS], now: u64) -> Outcome {
        let mut last = Outcome::Idle;
        for d in code {
            last = c.digit(d, now);
        }
        last
    }

    #[test]
    fn right_code_confirms() {
        let mut c = Confirm::new();
        let code = c.request(Action::Restart, S, 1234).unwrap();
        assert_eq!(type_code(&mut c, code, 2 * S), Outcome::Confirmed(Action::Restart));
        assert!(!c.is_pending(2 * S));
    }

    #[test]
    fn repeating_the_key_confirms_nothing() {
        // What a blind script does: ask again instead of answering.
        let mut c = Confirm::new();
        for i in 0..50 {
            c.request(Action::Shutdown, S + i, i).unwrap();
        }
        assert!(c.is_pending(S + 50));
    }

    #[test]
    fn wrong_digit_rejects_and_locks_out() {
        let mut c = Confirm::new();
        let code = c.request(Action::Shutdown, S, 7).unwrap();
        let wrong = (code[0] + 1) % 10;
        assert_eq!(c.digit(wrong, S), Outcome::Rejected);
        assert_eq!(c.digit(code[1], S), Outcome::Idle);
        assert!(matches!(
            c.request(Action::Shutdown, S + 1, 8),
            Err(Refused::LockedOut { .. })
        ));
        assert!(c.request(Action::Shutdown, S + LOCKOUT_BASE_NS, 8).is_ok());
    }

    #[test]
    fn lockout_doubles_and_caps() {
        let mut c = Confirm::new();
        let mut now = S;
        let mut last = 0;
        for _ in 0..40 {
            let code = c.request(Action::Restart, now, now).unwrap();
            c.digit((code[0] + 1) % 10, now);
            let lock = c.lockout_remaining_ns(now);
            assert!(lock >= last && lock <= LOCKOUT_MAX_NS);
            last = lock;
            now += lock;
        }
        assert_eq!(last, LOCKOUT_MAX_NS);
    }

    #[test]
    fn success_resets_the_doubling() {
        let mut c = Confirm::new();
        let code = c.request(Action::Restart, S, 1).unwrap();
        c.digit((code[0] + 1) % 10, S);
        let now = S + LOCKOUT_BASE_NS;
        let code = c.request(Action::Restart, now, 2).unwrap();
        type_code(&mut c, code, now);
        let code = c.request(Action::Restart, now, 3).unwrap();
        c.digit((code[0] + 1) % 10, now);
        assert_eq!(c.lockout_remaining_ns(now), LOCKOUT_BASE_NS);
    }

    #[test]
    fn code_expires() {
        let mut c = Confirm::new();
        let code = c.request(Action::Restart, S, 5).unwrap();
        let late = S + CONFIRM_WINDOW_NS;
        assert!(!c.is_pending(late));
        assert_eq!(c.remaining_ns(S + 1), Some(CONFIRM_WINDOW_NS - 1));
        assert_eq!(c.remaining_ns(late), None);
        assert_eq!(c.digit(code[0], late), Outcome::Idle);
        // Expiry is not a miss.
        assert_eq!(c.lockout_remaining_ns(late), 0);
    }

    #[test]
    fn cancel_is_not_a_miss() {
        let mut c = Confirm::new();
        c.request(Action::Shutdown, S, 5).unwrap();
        c.cancel();
        assert!(c.request(Action::Shutdown, S, 6).is_ok());
    }

    #[test]
    fn digits_cover_all_values() {
        // Low-entropy input (consecutive counters) still spreads the codes.
        let mut seen = [false; 100];
        let mut c = Confirm::new();
        for i in 0..2000u64 {
            let code = c.request(Action::Restart, S + i, i).unwrap();
            seen[code[0] as usize * 10 + code[1] as usize] = true;
            c.cancel();
        }
        assert!(seen.iter().all(|&s| s));
    }
}
