// SPDX-License-Identifier: Apache-2.0
//! Perf counters from ring 0, via `kernel/linux/nanochrono_perf.rs`.
//!
//! Ring 3 (`[`crate::perf`]`) opens per-thread events with `perf_event_open`:
//! the count follows the calling thread across migrations and context
//! switches. Ring 0 opens system-wide per-CPU events with
//! `perf_event_create_kernel_counter` and publishes the summed, multiplexing-
//! corrected total at `/proc/nanochrono`, next to the hypervisor report of
//! the same (single) module, under `perf_*` keys:
//!
//! ```text
//! version=4
//! ...hypervisor and counter keys...
//! perf_event=cycles
//! perf_enabled=1
//! perf_npmu=8
//! perf_raw=123456
//! perf_enabled_ns=1000
//! perf_running_ns=1000
//! perf_scaled=123456
//! ```
//!
//! The two numbers answer different questions — "what did *this thread* cost"
//! versus "what did *every CPU* count" — so neither replaces the other. The
//! CLI (`nanochrono perf`) and the GUI hypervisor panel show both side by
//! side. There is deliberately no `RDPMC` anywhere in this path: the kernel
//! owns the counters, schedules them and corrects for multiplexing.
//!
//! Reading the perf keys never re-runs the module's hypervisor probes: those
//! run once per load (see [`crate::reprobe`]). The older standalone perf
//! module's format (`source=perf` and unprefixed keys) still parses.
//! Unknown keys are ignored so the report can grow.

/// Where the module publishes.
pub const PROC_PATH: &str = "/proc/nanochrono";

/// What the module is currently counting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ring0Event {
    #[default]
    Cycles,
    Instructions,
}

impl Ring0Event {
    pub const fn name(self) -> &'static str {
        match self {
            Ring0Event::Cycles => "cycles",
            Ring0Event::Instructions => "instructions",
        }
    }

    pub fn parse(s: &str) -> Option<Ring0Event> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cycles" | "cycle" | "cpu-cycles" => Some(Ring0Event::Cycles),
            "instr" | "instructions" | "instruction" => Some(Ring0Event::Instructions),
            _ => None,
        }
    }
}

/// One snapshot of the ring-0 counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ring0Perf {
    pub event: Ring0Event,
    /// Whether the kernel events are currently enabled.
    pub enabled: bool,
    /// How many per-CPU events were summed. >1 on multi-CPU machines.
    pub npmu: usize,
    /// Summed raw count, uncorrected.
    pub raw: u64,
    /// Nanoseconds the events were enabled.
    pub enabled_ns: u64,
    /// Nanoseconds they were actually on hardware. Zero means opened but
    /// never scheduled — report as unavailable, never as zero.
    pub running_ns: u64,
    /// Multiplexing-corrected count. **This is the number to use.**
    pub scaled: u64,
}

impl Ring0Perf {
    /// Whether the counters were ever scheduled onto hardware.
    pub fn ran(&self) -> bool {
        self.running_ns > 0
    }

    /// Reads `/proc/nanochrono`. `None` when the perf module is not loaded
    /// (or the hypervisor module is loaded instead — different format).
    pub fn read() -> Option<Ring0Perf> {
        let text = std::fs::read_to_string(PROC_PATH).ok()?;
        parse_report(&text)
    }

    /// Reads from an explicit path (tests, containers with a bind mount).
    pub fn read_from(path: &str) -> Option<Ring0Perf> {
        let text = std::fs::read_to_string(path).ok()?;
        parse_report(&text)
    }

    /// Whether a usable ring-0 counter is present right now.
    pub fn is_available() -> bool {
        Self::read().is_some_and(|r| r.ran())
    }

    /// Selects what the module counts (`cycles` or `instr`).
    /// Needs write access to `/proc/nanochrono` (usually root).
    pub fn select(event: Ring0Event) -> std::io::Result<()> {
        std::fs::write(PROC_PATH, event.name())
    }

    /// Enables or disables counting without dropping the events.
    pub fn set_enabled(on: bool) -> std::io::Result<()> {
        std::fs::write(PROC_PATH, if on { "enable" } else { "disable" })
    }
}

/// Parses a `/proc/nanochrono` report. Returns `None` unless it carries
/// perf keys — `perf_*` (the merged module) or the legacy `source=perf`
/// format — with a counter that was scheduled.
fn parse_report(text: &str) -> Option<Ring0Perf> {
    let mut perf = Ring0Perf::default();
    let legacy = text.lines().any(|l| l.trim() == "source=perf");
    let mut is_perf = legacy;
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let key = key.trim();
        let field = match key.strip_prefix("perf_") {
            Some(field) => {
                is_perf = true;
                field
            }
            // Unprefixed keys only mean perf in the legacy format; in the
            // merged report they belong to the hypervisor section.
            None if legacy => key,
            None => continue,
        };
        let value = value.trim();
        match field {
            "event" => perf.event = Ring0Event::parse(value).unwrap_or(Ring0Event::Cycles),
            "enabled" => perf.enabled = value == "1",
            "npmu" => perf.npmu = value.parse().unwrap_or(0),
            "raw" => perf.raw = value.parse().unwrap_or(0),
            "enabled_ns" => perf.enabled_ns = value.parse().unwrap_or(0),
            "running_ns" => perf.running_ns = value.parse().unwrap_or(0),
            "scaled" => perf.scaled = value.parse().unwrap_or(0),
            _ => {}
        }
    }
    if !is_perf || !perf.ran() {
        return None;
    }
    Some(perf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
source=perf
event=cycles
enabled=1
npmu=8
raw=123456
enabled_ns=2000
running_ns=1000
scaled=246912
";

    #[test]
    fn perf_report_parses_and_scales() {
        let r = parse_report(SAMPLE).expect("sample is a valid perf report");
        assert_eq!(r.event, Ring0Event::Cycles);
        assert!(r.enabled);
        assert_eq!(r.npmu, 8);
        assert_eq!(r.raw, 123456);
        assert_eq!(r.scaled, 246912);
        assert!(r.ran());
    }

    #[test]
    fn merged_report_parses_its_perf_keys() {
        let text = "version=4\narch=x86\nvmcall_ok=0\nenabled=0\nhypercall_probes=1\n\
                    perf_event=instructions\nperf_enabled=1\nperf_npmu=4\nperf_raw=10\n\
                    perf_enabled_ns=4\nperf_running_ns=2\nperf_scaled=20\n";
        let r = parse_report(text).expect("merged report");
        assert_eq!(r.event, Ring0Event::Instructions);
        assert!(r.enabled, "an unprefixed key must not override perf_enabled");
        assert_eq!((r.npmu, r.raw, r.scaled), (4, 10, 20));
    }

    #[test]
    fn merged_report_without_a_pmu_has_no_perf() {
        let text = "version=4\nperf_available=0\nperf_npmu=0\nperf_running_ns=0\n";
        assert_eq!(parse_report(text), None);
    }

    #[test]
    fn hypervisor_report_is_not_a_perf_report() {
        let hv = "version=2\narch=x86\nvmcall_ok=0\nexit_cycles=58\n";
        assert_eq!(parse_report(hv), None);
    }

    #[test]
    fn never_scheduled_counts_as_unavailable() {
        let text = SAMPLE.replace("running_ns=1000", "running_ns=0");
        assert_eq!(parse_report(&text), None);
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let text = format!("{SAMPLE}future_field=1\n");
        assert!(parse_report(&text).is_some());
    }

    #[test]
    fn event_names_parse() {
        assert_eq!(Ring0Event::parse("cycles"), Some(Ring0Event::Cycles));
        assert_eq!(Ring0Event::parse("INSTR"), Some(Ring0Event::Instructions));
        assert_eq!(Ring0Event::parse("bogus"), None);
    }

    #[test]
    fn missing_proc_is_not_an_error() {
        assert_eq!(Ring0Perf::read_from("/nonexistent/nanochrono-test"), None);
    }
}
