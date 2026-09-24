// SPDX-License-Identifier: Apache-2.0
//! The once-per-boot hypervisor probe, and the cooldown on repeating it.
//!
//! Every hypervisor probe that makes the guest exit — a `VMCALL`/`VMMCALL`,
//! an `HVC`, an SBI call into a hypervisor, a `CPUID` exit-cost loop, a
//! trapped counter read — runs **once**: when the kernel module loads, when
//! the Windows driver starts, when the bare-metal kernel boots. The result is
//! cached and every later reader gets the cache.
//!
//! The reason is the cloud: on Azure, GCP, AWS, Vultr and the like a guest
//! that fires exits in a loop looks like an attack on the shared host, and
//! providers throttle or ban it. A GUI refreshing a panel, or a
//! `watch cat /proc/nanochrono`, must not be able to do that.
//!
//! A deliberate re-probe — a button, a key, `echo reprobe` — is allowed at
//! most once per [`DEFAULT_COOLDOWN_S`] seconds. The wait can be switched off
//! in Settings; whoever does that assumes the provider's reaction, which is
//! what [`COOLDOWN_OFF_WARNING`] says wherever the switch is offered.
//!
//! This module is only the policy: the timestamps come from the caller, so
//! the same gate serves the kernel-less bare metal, the hosted GUI and CLI.

/// Seconds between re-probes unless the user turns the wait off.
pub const DEFAULT_COOLDOWN_S: u32 = 10;

/// Shown next to every control that disables the wait.
pub const COOLDOWN_OFF_WARNING: &str = "Re-probe cooldown OFF: every re-probe makes the guest \
exit to its hypervisor. Repeated exits on a cloud VM (Azure, GCP, AWS, Vultr...) can look \
like an attack and get the instance throttled or banned. YOU assume that risk.";

/// Shown next to the re-probe control while the wait is on.
pub const COOLDOWN_NOTE: &str = "The hypervisor is probed once at start. A re-probe is \
allowed every 10 s so a cloud provider does not read it as abuse.";

/// Why a re-probe was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Still cooling down; this many nanoseconds remain.
    CoolingDown { remaining_ns: u64 },
}

/// The cooldown gate. Time is any monotonic nanosecond clock the caller has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    cooldown_s: u32,
    last_ns: Option<u64>,
    probes: u32,
}

impl Default for Gate {
    fn default() -> Self {
        Gate::new()
    }
}

impl Gate {
    /// A gate with the default cooldown and no probe yet.
    pub const fn new() -> Gate {
        Gate {
            cooldown_s: DEFAULT_COOLDOWN_S,
            last_ns: None,
            probes: 0,
        }
    }

    /// Seconds between re-probes; 0 = no limit.
    pub const fn cooldown_s(&self) -> u32 {
        self.cooldown_s
    }

    /// Whether the wait is on.
    pub const fn cooldown_enabled(&self) -> bool {
        self.cooldown_s != 0
    }

    /// Sets the wait; 0 disables it (see [`COOLDOWN_OFF_WARNING`]).
    pub fn set_cooldown_s(&mut self, seconds: u32) {
        self.cooldown_s = seconds;
    }

    /// Turns the wait on (default length) or off.
    pub fn set_cooldown_enabled(&mut self, on: bool) {
        self.cooldown_s = if on { DEFAULT_COOLDOWN_S } else { 0 };
    }

    /// How many probes have been recorded.
    pub const fn probes(&self) -> u32 {
        self.probes
    }

    /// Nanoseconds until the next probe is allowed; 0 = now.
    pub fn remaining_ns(&self, now_ns: u64) -> u64 {
        match self.last_ns {
            None => 0,
            Some(_) if self.cooldown_s == 0 => 0,
            Some(last) => {
                let window = self.cooldown_s as u64 * 1_000_000_000;
                window.saturating_sub(now_ns.saturating_sub(last))
            }
        }
    }

    /// Whole seconds until the next probe, rounded up (for a label).
    pub fn remaining_s(&self, now_ns: u64) -> u32 {
        self.remaining_ns(now_ns).div_ceil(1_000_000_000) as u32
    }

    /// Asks to probe now. On `Ok` the probe is recorded as done at `now_ns`
    /// and the caller must run it; on `Err` it must not.
    pub fn try_begin(&mut self, now_ns: u64) -> Result<(), Refused> {
        let remaining_ns = self.remaining_ns(now_ns);
        if remaining_ns > 0 {
            return Err(Refused::CoolingDown { remaining_ns });
        }
        self.last_ns = Some(now_ns);
        self.probes = self.probes.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn the_first_probe_is_free_and_the_next_waits() {
        let mut g = Gate::new();
        assert!(g.try_begin(5 * S).is_ok());
        assert_eq!(g.probes(), 1);
        assert_eq!(
            g.try_begin(9 * S),
            Err(Refused::CoolingDown { remaining_ns: 6 * S })
        );
        assert_eq!(g.remaining_s(9 * S + 1), 6);
        assert_eq!(g.probes(), 1);
        assert!(g.try_begin(15 * S).is_ok());
        assert_eq!(g.probes(), 2);
    }

    #[test]
    fn disabling_the_wait_removes_it() {
        let mut g = Gate::new();
        g.try_begin(0).unwrap();
        g.set_cooldown_enabled(false);
        assert!(!g.cooldown_enabled());
        assert!(g.try_begin(1).is_ok());
        assert!(g.try_begin(2).is_ok());
        g.set_cooldown_enabled(true);
        assert_eq!(g.cooldown_s(), DEFAULT_COOLDOWN_S);
        assert!(g.try_begin(3).is_err());
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_unlock() {
        let mut g = Gate::new();
        g.try_begin(100 * S).unwrap();
        assert!(g.try_begin(50 * S).is_err());
    }
}
