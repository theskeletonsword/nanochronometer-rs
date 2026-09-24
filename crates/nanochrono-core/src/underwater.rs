// SPDX-License-Identifier: Apache-2.0
//! Keeping a phone's stopwatch honest under water.
//!
//! Depth does not change how a counter counts: the counter runs off the
//! SoC's crystal, and pressure does not reach it. What water does change:
//!
//! - **the touchscreen**: a wet capacitive panel reports touches nobody made,
//!   and one of them lands on Start or Reset. [`SubmersionGuard`] says when
//!   the device is submerged, so the interface can ignore the panel and take
//!   only hardware keys until it is out.
//! - **the device itself**: every ingress rating has a depth it was tested
//!   to, and some have none. [`IpRating`] turns a declared rating into a
//!   warning while there is still time to surface.
//! - **the temperature**: cold water moves a crystal's frequency. How much
//!   depends on the crystal, and a generic correction applied to a specific
//!   phone can make it worse, so [`thermal_uncertainty_ppm`] reports a bound
//!   to show next to the reading rather than a correction to apply.
//!
//! The barometer is only a sensor here: nothing about the measurement is
//! corrected by pressure. Pure policy; the caller feeds it sensor readings
//! and a monotonic clock.

/// Water adds about this much pressure per metre (fresh water, 9.81 m/s²).
pub const HPA_PER_METRE: f64 = 98.1;

/// Rise above the surface baseline that counts as submerged (~0.5 m).
pub const ENTER_HPA: f64 = 50.0;
/// Rise below which the device counts as out again (~0.2 m)...
pub const EXIT_HPA: f64 = 20.0;
/// ...held for this long, so a wave or a splash does not unlock the screen.
pub const EXIT_HOLD_NS: u64 = 5_000_000_000;
/// How quickly the surface baseline follows the weather. Weather moves a few
/// hPa per hour; a dive moves tens per second. A ten-minute time constant
/// tracks the first and ignores the second.
pub const BASELINE_TAU_NS: u64 = 600_000_000_000;

/// Whether the device is in the water, from its barometer.
#[derive(Debug, Clone, Copy)]
pub struct SubmersionGuard {
    baseline_hpa: Option<f64>,
    last_ns: u64,
    submerged: bool,
    below_exit_since: Option<u64>,
    max_depth_m: f64,
}

impl Default for SubmersionGuard {
    fn default() -> Self {
        SubmersionGuard::new()
    }
}

impl SubmersionGuard {
    pub const fn new() -> SubmersionGuard {
        SubmersionGuard {
            baseline_hpa: None,
            last_ns: 0,
            submerged: false,
            below_exit_since: None,
            max_depth_m: 0.0,
        }
    }

    /// Feeds one barometer reading. Returns whether the device is submerged.
    pub fn sample(&mut self, hpa: f64, now_ns: u64) -> bool {
        if !hpa.is_finite() || hpa <= 0.0 {
            return self.submerged;
        }
        let Some(baseline) = self.baseline_hpa else {
            self.baseline_hpa = Some(hpa);
            self.last_ns = now_ns;
            return false;
        };
        let rise = hpa - baseline;

        if self.submerged {
            self.max_depth_m = self.max_depth_m.max(rise / HPA_PER_METRE);
            if rise <= EXIT_HPA {
                let since = *self.below_exit_since.get_or_insert(now_ns);
                if now_ns.saturating_sub(since) >= EXIT_HOLD_NS {
                    self.submerged = false;
                    self.below_exit_since = None;
                }
            } else {
                self.below_exit_since = None;
            }
        } else if rise >= ENTER_HPA {
            self.submerged = true;
            self.below_exit_since = None;
            self.max_depth_m = self.max_depth_m.max(rise / HPA_PER_METRE);
        } else {
            // Out of the water: follow the weather. Frozen while submerged,
            // or the baseline would sink towards the depth it measures.
            let dt = now_ns.saturating_sub(self.last_ns) as f64;
            let alpha = (dt / BASELINE_TAU_NS as f64).min(1.0);
            self.baseline_hpa = Some(baseline + (hpa - baseline) * alpha);
        }
        self.last_ns = now_ns;
        self.submerged
    }

    pub const fn submerged(&self) -> bool {
        self.submerged
    }

    /// Whether touch input should be ignored: while submerged. Hardware keys
    /// stay live — they are the one input water cannot fake.
    pub const fn touch_locked(&self) -> bool {
        self.submerged
    }

    /// Estimated depth now, in metres, from the last reading's rise.
    pub fn depth_m(&self, hpa: f64) -> f64 {
        self.baseline_hpa
            .map_or(0.0, |b| ((hpa - b) / HPA_PER_METRE).max(0.0))
    }

    /// The deepest point since power-on, for comparing against the rating.
    pub const fn max_depth_m(&self) -> f64 {
        self.max_depth_m
    }
}

/// An ingress-protection rating's water digit, as the manufacturer declares
/// it (IEC 60529; IP69K is ISO 20653).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpRating {
    /// IPx5/IPx6 (IP56, IP65, IP66...): jets, not immersion.
    Jets,
    /// IPx7 (IP57, IP67): immersion to 1 m for 30 minutes.
    Immersion1m,
    /// IPx8 (IP58, IP68): immersion beyond 1 m, to the depth and time the
    /// manufacturer states — commonly 1.5 m to 6 m for 30 minutes.
    ImmersionDeclared { depth_m: f64, minutes: u32 },
    /// IPx9 / IP69K: high-pressure, high-temperature jets. Says nothing
    /// about immersion; a phone rated only IP69K is not rated to go under.
    HighPressureJets,
    /// No water rating, or none declared.
    None,
}

/// What the rating says about the current dive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// Inside the rating.
    Within,
    /// Past 80 % of the rated depth or time: surface soon.
    Near,
    /// Past the rated depth or time, or under water with no immersion
    /// rating at all.
    Beyond,
}

impl IpRating {
    /// Rated immersion depth and duration, if the rating has one.
    pub fn immersion(self) -> Option<(f64, u32)> {
        match self {
            IpRating::Immersion1m => Some((1.0, 30)),
            IpRating::ImmersionDeclared { depth_m, minutes } => Some((depth_m, minutes)),
            IpRating::Jets | IpRating::HighPressureJets | IpRating::None => None,
        }
    }

    /// Judges a dive: current depth and time submerged.
    pub fn exposure(self, depth_m: f64, submerged_ns: u64) -> Exposure {
        let Some((rated_m, rated_min)) = self.immersion() else {
            return if submerged_ns > 0 { Exposure::Beyond } else { Exposure::Within };
        };
        let minutes = submerged_ns as f64 / 60e9;
        let fraction = (depth_m / rated_m).max(minutes / rated_min as f64);
        if fraction > 1.0 {
            Exposure::Beyond
        } else if fraction > 0.8 {
            Exposure::Near
        } else {
            Exposure::Within
        }
    }
}

/// The crystal behind a counter, for [`thermal_uncertainty_ppm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crystal {
    /// A 32.768 kHz tuning fork (RTCs): a parabola turning over at 25 °C,
    /// −0.034 ppm/°C², so cold water costs tens of ppm.
    TuningFork,
    /// An AT-cut MHz crystal (a phone SoC's reference): a flat cubic, a few
    /// ppm across ordinary temperatures, ±10 ppm to its datasheet's limits.
    AtCut,
}

/// A bound on how far `crystal`'s frequency may sit from nominal at
/// `celsius`, in ppm: temperature only, on top of the part's tolerance at
/// room temperature. For a "± N ppm" beside the reading, not a correction.
pub fn thermal_uncertainty_ppm(crystal: Crystal, celsius: f64) -> f64 {
    let dt = celsius - 25.0;
    match crystal {
        Crystal::TuningFork => 0.034 * dt * dt,
        // A conservative envelope of the AT-cut cubic: ~1 ppm near room
        // temperature, growing to ~10 ppm at −20 °C and +70 °C.
        Crystal::AtCut => 1.0 + 9.0 * (dt.abs() / 45.0).powi(3).min(1.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn a_dive_locks_touch_and_surfacing_unlocks_after_the_hold() {
        let mut g = SubmersionGuard::new();
        g.sample(1013.0, 0);
        assert!(!g.sample(1013.5, S));
        // 1 m down.
        assert!(g.sample(1013.0 + HPA_PER_METRE, 2 * S));
        assert!(g.touch_locked());
        assert!((g.depth_m(1013.0 + HPA_PER_METRE) - 1.0).abs() < 0.01);
        // Surfaced: still locked until the hold passes.
        assert!(g.sample(1013.0, 3 * S));
        assert!(g.sample(1013.0, 3 * S + EXIT_HOLD_NS - 1));
        assert!(!g.sample(1013.0, 3 * S + EXIT_HOLD_NS));
    }

    #[test]
    fn a_splash_at_the_surface_does_not_unlock() {
        let mut g = SubmersionGuard::new();
        g.sample(1013.0, 0);
        g.sample(1013.0 + 2.0 * HPA_PER_METRE, S);
        g.sample(1013.0, 2 * S); // bobbing up
        g.sample(1013.0 + 60.0, 4 * S); // back under before the hold
        assert!(g.sample(1013.0, 5 * S));
        assert!(g.sample(1013.0, 5 * S + EXIT_HOLD_NS - 1));
    }

    #[test]
    fn weather_moves_the_baseline_without_triggering() {
        let mut g = SubmersionGuard::new();
        // A storm front: -30 hPa over three hours, sampled each minute.
        let mut hpa = 1013.0;
        for minute in 0..180u64 {
            hpa -= 30.0 / 180.0;
            assert!(!g.sample(hpa, minute * 60 * S));
        }
        // And back up faster than weather ever does is still not a dive
        // unless it clears ENTER_HPA over the tracked baseline.
        assert!(!g.sample(hpa + 20.0, 181 * 60 * S));
    }

    #[test]
    fn garbage_readings_are_ignored() {
        let mut g = SubmersionGuard::new();
        g.sample(1013.0, 0);
        assert!(!g.sample(f64::NAN, S));
        assert!(!g.sample(-1.0, 2 * S));
        assert!(!g.sample(0.0, 3 * S));
    }

    #[test]
    fn ratings() {
        assert_eq!(IpRating::HighPressureJets.exposure(0.3, S), Exposure::Beyond);
        assert_eq!(IpRating::Jets.exposure(0.0, 0), Exposure::Within);
        assert_eq!(IpRating::Immersion1m.exposure(0.5, 60 * S), Exposure::Within);
        assert_eq!(IpRating::Immersion1m.exposure(0.9, 60 * S), Exposure::Near);
        assert_eq!(IpRating::Immersion1m.exposure(1.2, 60 * S), Exposure::Beyond);
        assert_eq!(IpRating::Immersion1m.exposure(0.2, 31 * 60 * S), Exposure::Beyond);
        let ip68 = IpRating::ImmersionDeclared { depth_m: 6.0, minutes: 30 };
        assert_eq!(ip68.exposure(4.0, 60 * S), Exposure::Within);
    }

    #[test]
    fn thermal_bounds() {
        assert!(thermal_uncertainty_ppm(Crystal::TuningFork, 25.0).abs() < 1e-9);
        // 4 °C water: 0.034 * 21² ≈ 15 ppm.
        assert!((thermal_uncertainty_ppm(Crystal::TuningFork, 4.0) - 14.994).abs() < 0.01);
        assert!(thermal_uncertainty_ppm(Crystal::AtCut, 25.0) <= 1.0 + 1e-9);
        assert!(thermal_uncertainty_ppm(Crystal::AtCut, -20.0) <= 10.0 + 1e-9);
    }
}
