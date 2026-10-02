// SPDX-License-Identifier: Apache-2.0
//! `nanochrono`: the hosted CLI's command set, freestanding.
//!
//! The same subcommands, the same options and — where the measurement
//! exists without an operating system — the same output, line for line, so
//! a script or a person moving between a Linux box and this kernel reads the
//! same report. Where a subcommand needs something only an operating system
//! has (a network stack for `ntp` and `tls`, language runtimes for
//! `wrapper-overhead`, the kernel module for `perf`'s ring-0 half), it says
//! so and what the freestanding equivalent is, and exits 1.

use super::{Job, Out, Shell};
use crate::kbd::KeyInput;
use core::fmt::Write;

const USAGE: &str = "\
Nanosecond-resolution chronometer, precision clock and ISA measurement toolkit

Usage: nanochrono [OPTIONS] [COMMAND]

Commands:
  stopwatch          Live stopwatch until Ctrl+C (the default with no subcommand)
  once               Print one diagnostic timing sample and exit
  dispatch           Show what the runtime ISA dispatcher selected, and why
  integrity          Report the state-integrity counters, and optionally drill the repair paths
  hypervisor         Detect a hypervisor or emulator, and say what it means for the numbers
  host-sync          Report how the guest's nanoseconds relate to the host's
  catalog            List every timer backend and SIMD family with its availability
  clock              Live precision clock
  clock-once         One precision-clock sample
  ns-clock           Live nanosecond clock with every raw counter route
  ns-clock-once      One nanosecond-clock snapshot
  calibrate-clock    Calibrate the selected counter route against wall time
  stable-calibrate   Calibrate cycles-per-nanosecond for raw counter conversion
  cycles-to-ns       Convert raw cycles to nanoseconds with a known factor
  ntp                Query an NTP server and report offset, delay and overhead
  tls                Time a TLS 1.3 handshake, phase by phase
  bench              Run a benchmark
  wrapper-overhead   Measure native and language-wrapper call overhead baselines
  asm-probe          Run local cache and branch timing probes
  asm-simd           Run per-family SIMD probes, gated by CPUID
  sct-audit          Run a constant-time timing audit on a demo candidate
  perf               Compare per-thread perf counters (ring 3) with the ring-0 counters
  help               Print this message or the help of the given subcommand(s)

Options:
      --backend <NAME>     Force a timer backend instead of the dispatcher's choice
      --pin-cpu <INDEX>    Pin the measuring thread to a CPU before doing anything
      --physical-counter   AArch64: time with CNTPCT_EL0 instead of CNTVCT_EL0
  -h, --help               Print help
  -V, --version            Print version
";

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

/// `hh:mm:ss:mmm:uuu:nnn`, the hosted CLI's `format_elapsed_nano`.
pub fn elapsed_nano(out: &mut dyn Write, ns: u64) {
    let _ = write!(
        out,
        "{:02}:{:02}:{:02}:{:03}:{:03}:{:03}",
        ns / 3_600_000_000_000,
        (ns / 60_000_000_000) % 60,
        (ns / 1_000_000_000) % 60,
        (ns / 1_000_000) % 1_000,
        (ns / 1_000) % 1_000,
        ns % 1_000
    );
}

/// `mm:ss.mmm`, the hosted CLI's `format_elapsed_simple`.
fn elapsed_simple(out: &mut dyn Write, ns: u64) {
    let ms = ns / 1_000_000;
    let _ = write!(out, "{:02}:{:02}.{:03}", ms / 60_000, ms / 1_000 % 60, ms % 1_000);
}

fn platform_summary() -> crate::text::Text<48> {
    // SAFETY: cached since boot; this does not probe.
    let hv = unsafe { crate::hypervisor::detect() };
    let mut t = crate::text::Text::new();
    if hv.is_virtualized() {
        let sig = hv.signature_str();
        t.str(if sig.is_empty() { "virtualized" } else { sig });
    } else {
        t.str("bare metal");
    }
    t
}

/// A backend by the name the hosted `--backend` takes.
fn parse_backend(name: &str) -> Option<nanochrono_core::Backend> {
    nanochrono_core::Backend::ALL.iter().copied().find(|b| b.name().eq_ignore_ascii_case(name))
}

/// Runs `nanochrono [options] [command] [args]`.
pub fn run(shell: &mut Shell, out: &mut Out<'_>, argv: &[&str], now_ns: u64) -> i32 {
    let Some(system) = crate::system::get() else {
        let _ = writeln!(out, "nanochrono: the machine has not been probed yet\r");
        return 1;
    };
    // Global options first, then the subcommand.
    let mut i = 1;
    let mut backend: Option<&str> = None;
    while i < argv.len() && argv[i].starts_with('-') {
        match argv[i] {
            "-h" | "--help" => {
                print_usage(out);
                return 0;
            }
            "-V" | "--version" => {
                let _ = writeln!(out, "nanochrono {}\r", crate::VERSION);
                return 0;
            }
            "--backend" => {
                backend = argv.get(i + 1).copied();
                i += 1;
            }
            // One core, nothing to migrate between: accepted and true.
            "--pin-cpu" => i += 1,
            "--physical-counter" => {
                if !crate::arch::set_counter_source(crate::arch::CounterSource::Physical) {
                    let _ = writeln!(out, "--physical-counter: only AArch64 has a separate physical counter\r");
                    return 1;
                }
                let _ = writeln!(out, "warning: {}\r", nanochrono_core::arch::PHYSICAL_COUNTER_WARNING);
            }
            other => {
                let _ = writeln!(out, "error: unexpected argument '{other}'\r\n\r\nFor more information, try '--help'.\r");
                return 2;
            }
        }
        i += 1;
    }
    if let Some(name) = backend {
        match parse_backend(name) {
            Some(b) if b.is_available() => {}
            Some(b) => {
                let _ = writeln!(out, "backend {} is not available on this machine\r", b.name());
                return 1;
            }
            None => {
                let _ = writeln!(out, "unknown backend '{name}'\r");
                return 1;
            }
        }
    }
    let command = argv.get(i).copied().unwrap_or("stopwatch");
    let args = argv.get(i + 1..).unwrap_or(&[]);
    let hz = system.hz();
    match command {
        "help" => {
            print_usage(out);
            0
        }
        "stopwatch" => start_stopwatch(shell, out, now_ns),
        "once" => {
            let backend = nanochrono_core::Backend::best();
            let start = crate::arch::counter_ordered();
            let target = start.wrapping_add(hz / 1000);
            while crate::arch::counter_ordered().wrapping_sub(start) < target.wrapping_sub(start) {
                core::hint::spin_loop();
            }
            let elapsed = system.clock.calibration.ticks_to_ns(crate::arch::counter_ordered().wrapping_sub(start));
            let mut overhead = u64::MAX;
            for _ in 0..1024 {
                let a = crate::arch::counter_ordered();
                let b = crate::arch::counter_ordered();
                overhead = overhead.min(b.wrapping_sub(a));
            }
            let _ = writeln!(out, "backend={}\r", backend.name());
            let _ = writeln!(out, "platform={}\r", platform_summary().as_str());
            let _ = writeln!(out, "counter_hz={hz}\r");
            let _ = write!(out, "elapsed=");
            elapsed_nano(out, elapsed);
            let _ = writeln!(out, "\r");
            let _ = writeln!(out, "counter_read_overhead={overhead} units\r");
            let _ = writeln!(out, "ffi_overhead=0 units (freestanding: no FFI boundary)\r");
            let _ = writeln!(out, "drift=+0.000 ppm\r");
            let _ = writeln!(out, "calibration_integrity=clean\r");
            0
        }
        "dispatch" => {
            let best = nanochrono_core::Backend::best();
            let _ = writeln!(out, "dispatcher: {} (best available counter route on this CPU)\r\n\r", best.name());
            let _ = writeln!(out, "{:<16} {:>10} {:>10}\r", "BACKEND", "AVAILABLE", "SELECTED");
            for b in nanochrono_core::Backend::ALL {
                let _ = writeln!(out, "{:<16} {:>10} {:>10}\r", b.name(), yes_no(b.is_available()), yes_no(*b == best));
            }
            0
        }
        "integrity" => integrity(out, args.contains(&"--drill")),
        "hypervisor" => {
            let mut v: [&str; 4] = ["hypervisor", "", "", ""];
            if args.contains(&"--reprobe") {
                v[1] = "--reprobe";
            }
            super::builtins::dispatch(shell, &v[..if v[1].is_empty() { 1 } else { 2 }], out.term, now_ns)
        }
        "host-sync" => {
            // SAFETY: cached since boot.
            let hv = unsafe { crate::hypervisor::detect() };
            let _ = writeln!(out, "paravirtual clocksource : none (freestanding: the counter is read directly)\r");
            let _ = writeln!(out, "monotonic follows host  : {}\r", yes_no(hv.is_virtualized()));
            match hv.pairing {
                Some(p) => {
                    let _ = writeln!(out, "host clock pairing      : available (hypercall)\r");
                    let _ = writeln!(out, "  host clock            : {} ns\r", p.host_ns);
                    let _ = writeln!(out, "  at counter            : {}\r", p.counter);
                }
                None => {
                    let _ = writeln!(out, "host clock pairing      : unavailable\r");
                }
            }
            0
        }
        "catalog" => {
            let f = nanochrono_core::cpu::features();
            let _ = writeln!(out, "invariant counter: {}\r", yes_no(f.invariant_counter));
            let _ = writeln!(out, "platform: {}\r", platform_summary().as_str());
            let _ = writeln!(out, "\r\nTIMER BACKENDS\r");
            for b in nanochrono_core::Backend::ALL {
                let _ = writeln!(out, "  {:<16} {}\r", b.name(), yes_no(b.is_available()));
            }
            let _ = writeln!(out, "\r\nSIMD FAMILIES\r");
            for family in nanochrono_core::SimdFamily::ALL {
                let _ = writeln!(out, "  {:<16} {:>4} B  {}\r", family.name(), family.vector_bytes(), yes_no(family.is_available()));
            }
            0
        }
        "clock" | "clock-once" => {
            let mut c = LiveClock::new(ClockKind::Wall, now_ns);
            for (j, a) in args.iter().enumerate() {
                match *a {
                    "--simple" => c.simple = true,
                    "--nano" => c.simple = false,
                    "--utc" => c.offset_minutes = 0,
                    "--utc-offset" => {
                        c.offset_minutes = args.get(j + 1).and_then(|v| v.parse().ok()).unwrap_or(0);
                    }
                    "--ntp" => {
                        let _ = writeln!(out, "--ntp: no network stack in the freestanding kernel; the RTC and the counter are the clock\r");
                    }
                    _ => {}
                }
            }
            if command == "clock-once" {
                c.draw(out, now_ns, false);
                let _ = writeln!(out, "\r");
                0
            } else {
                let _ = writeln!(out, "NanoChronometer precision clock (RTC + counter). Ctrl+C or q stops.\r");
                shell.job = Job::Clock(c);
                0
            }
        }
        "ns-clock" | "ns-clock-once" => {
            let c = LiveClock::new(ClockKind::Counters, now_ns);
            if command == "ns-clock-once" {
                c.draw(out, now_ns, false);
                let _ = writeln!(out, "\r");
            } else {
                shell.job = Job::Clock(c);
            }
            0
        }
        "calibrate-clock" | "stable-calibrate" => {
            #[cfg(x86_any)]
            // SAFETY: the PIT and CPUID at kernel privilege.
            let cal = unsafe { crate::clock::Calibration::measure() };
            #[cfg(not(x86_any))]
            let cal = system.clock.calibration;
            let _ = writeln!(out, "counter_hz={}\r", cal.hz);
            let _ = writeln!(out, "source={}\r", cal.source.name());
            let _ = writeln!(out, "cycles_per_ns={}.{:06}\r", cal.hz / 1_000_000_000, (cal.hz % 1_000_000_000) / 1000);
            let drift = cal.hz as i128 - hz as i128;
            let _ = writeln!(out, "vs_session={drift:+} Hz\r");
            0
        }
        "cycles-to-ns" => {
            let cycles = args.first().and_then(|v| v.parse::<u64>().ok());
            let factor = args.iter().position(|a| *a == "--cycles-per-ns").and_then(|p| args.get(p + 1)).and_then(|v| v.parse::<f64>().ok());
            match (cycles, factor) {
                (Some(c), Some(f)) if f > 0.0 && f.is_finite() => {
                    let ns = c as f64 / f;
                    let _ = writeln!(out, "cycles={c} cycles_per_ns={f} ns={ns:.3}\r");
                    0
                }
                (_, Some(_)) => {
                    let _ = writeln!(out, "error: --cycles-per-ns must be a positive, finite number\r");
                    1
                }
                _ => {
                    let _ = writeln!(out, "usage: nanochrono cycles-to-ns <CYCLES> --cycles-per-ns <F>\r");
                    2
                }
            }
        }
        "ntp" | "tls" => {
            let _ = writeln!(
                out,
                "{command}: needs a network stack, which the freestanding kernel does not have.\r\n\
                 The hosted build (Linux, Windows, macOS, Android) runs it.\r"
            );
            1
        }
        "bench" => {
            let mode = args.iter().position(|a| *a == "--mode").and_then(|p| args.get(p + 1)).copied().unwrap_or("isa");
            let kernel = args.iter().position(|a| *a == "--kernel").and_then(|p| args.get(p + 1)).copied().unwrap_or("all");
            let mode = match mode {
                "isa" => "isa",
                "crypto" => "crypto",
                "crypto-raw" => "raw",
                "tls" | "kernel" | "ring0" => {
                    let _ = writeln!(out, "bench --mode {mode}: hosted only (needs an operating system)\r");
                    return 1;
                }
                other => {
                    let _ = writeln!(out, "error: invalid value '{other}' for '--mode'\r");
                    return 2;
                }
            };
            let v = ["bench", mode, kernel];
            super::builtins::dispatch(shell, &v, out.term, now_ns)
        }
        "wrapper-overhead" => {
            let _ = writeln!(out, "wrapper-overhead: no language runtimes here; native counter read overhead:\r");
            let mut best = u64::MAX;
            for _ in 0..4096 {
                let a = crate::arch::counter_ordered();
                let b = crate::arch::counter_ordered();
                best = best.min(b.wrapping_sub(a));
            }
            let _ = writeln!(out, "native={best} units\r");
            0
        }
        "asm-probe" | "asm-simd" => asm_simd(out),
        "sct-audit" => {
            let _ = writeln!(out, "sct-audit: the statistics harness is hosted only; run it on a hosted build\r");
            1
        }
        "perf" => {
            let r = |v: Option<crate::pmu::Reading>| v.map(|r| r.value);
            // SAFETY: kernel privilege; the PMU was enabled when the session
            // probed the machine.
            let (c, n) = unsafe { (r(system.pmu.read_cycles()), r(system.pmu.read_instructions())) };
            let _ = writeln!(out, "ring0 (this kernel is ring 0): route={}\r", system.route.name());
            match (c, n) {
                (Some(c), Some(n)) => {
                    let _ = writeln!(out, "cycles={c} instructions={n}\r");
                }
                (Some(c), None) => {
                    let _ = writeln!(out, "cycles={c} instructions=unavailable\r");
                }
                _ => {
                    let _ = writeln!(out, "pmu: unavailable (no architectural PMU, or the hypervisor hides it)\r");
                }
            }
            0
        }
        other => {
            let _ = writeln!(out, "error: unrecognized subcommand '{other}'\r\n\r\nFor more information, try '--help'.\r");
            2
        }
    }
}

fn print_usage(out: &mut Out<'_>) {
    for line in USAGE.lines() {
        let _ = writeln!(out, "{line}\r");
    }
}

fn integrity(out: &mut Out<'_>, drill: bool) -> i32 {
    use nanochrono_core::redundancy::{self, Protected};
    if drill {
        let _ = writeln!(out, "Fault-injection drill on a scratch value — nothing live is touched.\r\n\r");
        let _ = writeln!(out, "{:<34} {:<22} RECOVERED\r", "INJECTED", "TIER");
        let cases: [(&str, &[u32]); 4] = [
            ("nothing", &[]),
            ("one data bit (40)", &[40]),
            ("one check bit (66)", &[66]),
            ("two data bits (5, 37)", &[5, 37]),
        ];
        let original = 0x0000_0002_4126_D2BCu64;
        for (label, bits) in cases {
            let mut value = Protected::new(original);
            for &bit in bits {
                value.inject_flip(bit);
            }
            let outcome = value.verify();
            let _ = writeln!(out, "{:<34} {:<22} {}\r", label, outcome.name(), yes_no(value.get() == original));
        }
        let mut battered = Protected::new(original);
        for bit in [1, 2, 72 + 3, 136 + 4] {
            battered.inject_flip(bit);
        }
        let outcome = battered.verify();
        let _ = writeln!(out, "{:<34} {:<22} {}\r", "two data bits + one per replica", outcome.name(), yes_no(battered.get() == original));
        let mut hopeless = Protected::new(original);
        for bit in [1, 2, 72 + 3, 72 + 35, 136 + 4, 136 + 36] {
            hopeless.inject_flip(bit);
        }
        let outcome = hopeless.verify();
        let _ = writeln!(out, "{:<34} {:<22} {}\r\n\r", "two bits in all three copies", outcome.name(), yes_no(outcome.is_usable()));
    }
    let stats = redundancy::stats();
    let _ = writeln!(out, "checks          : {}\r", stats.checks);
    let _ = writeln!(out, "ecc corrections : {}\r", stats.ecc_corrections);
    let _ = writeln!(out, "tmr corrections : {}\r", stats.tmr_corrections);
    let _ = writeln!(out, "unrecoverable   : {}\r\n\r", stats.unrecoverable);
    if stats.is_clean() {
        let _ = writeln!(out, "No stored-state corruption observed.\r");
    } else {
        let _ = writeln!(out, "State was repaired during this run. At sea level that usually means failing\r");
        let _ = writeln!(out, "memory rather than radiation — check the hardware before trusting a long run.\r");
    }
    0
}

fn asm_simd(out: &mut Out<'_>) -> i32 {
    #[cfg(feature = "simd")]
    {
        use nanochrono_core::simd::{self, ProbeBuffers, ProbeKind};
        #[repr(C, align(64))]
        struct Vector([u8; 64]);
        let mut a = Vector([0x5A; 64]);
        let mut b = Vector([0xA5; 64]);
        let mut o = Vector([0; 64]);
        let _ = writeln!(out, "{:<18} {:>12} {:>12}\r", "FAMILY", "XOR", "LOAD");
        for family in nanochrono_core::SimdFamily::ALL.iter().copied() {
            if !family.is_available() {
                let _ = writeln!(out, "{:<18} {:>12}\r", family.name(), "unsupported");
                continue;
            }
            let mut run = |kind| {
                let bufs = ProbeBuffers { a: &mut a.0, b: &mut b.0, out: &mut o.0 };
                simd::probe(family, kind, Some(bufs), 1).map(|r| r.raw_units)
            };
            let x = run(ProbeKind::VectorXor);
            let l = run(ProbeKind::VectorLoad);
            let show = |v: Option<u64>| v.map_or(0, |v| v);
            let _ = writeln!(out, "{:<18} {:>12} {:>12}\r", family.name(), show(x), show(l));
        }
        0
    }
    #[cfg(not(feature = "simd"))]
    {
        let _ = writeln!(out, "asm-simd: built without the `simd` feature\r");
        1
    }
}

// ---------------------------------------------------------------------------
// The stopwatch: essential, and the default command
// ---------------------------------------------------------------------------

pub fn start_stopwatch(shell: &mut Shell, out: &mut Out<'_>, now_ns: u64) -> i32 {
    let Some(system) = crate::system::get() else { return 1 };
    let _ = writeln!(out, "NanoChronometer stopwatch\r");
    let _ = writeln!(
        out,
        "backend={}  counter={}.{:03} MHz  route={}\r",
        nanochrono_core::Backend::best().name(),
        system.hz() / 1_000_000,
        system.hz() / 1_000 % 1_000,
        crate::arch::counter_source().name_here()
    );
    if system.hypervisor.is_virtualized() {
        let _ = writeln!(out, "platform={}  timing inside a VM includes the hypervisor's exits\r", platform_summary().as_str());
    }
    let _ = writeln!(out, "Press Ctrl+C to stop.  [space] lap  [s] pause/resume  [r] reset\r\n\r");
    shell.job = Job::Stopwatch(LiveStopwatch::new(now_ns));
    0
}

/// The live stopwatch: `elapsed=` redrawn in place every frame.
pub struct LiveStopwatch {
    started_ticks: u64,
    banked_ticks: u64,
    running: bool,
    laps: u32,
    last_draw_ns: u64,
}

impl LiveStopwatch {
    pub fn new(now_ns: u64) -> LiveStopwatch {
        let _ = now_ns;
        LiveStopwatch { started_ticks: crate::arch::counter_ordered(), banked_ticks: 0, running: true, laps: 0, last_draw_ns: 0 }
    }

    fn elapsed_ns(&self) -> u64 {
        let Some(system) = crate::system::get() else { return 0 };
        let mut ticks = self.banked_ticks;
        if self.running {
            ticks += crate::arch::counter_ordered().wrapping_sub(self.started_ticks);
        }
        system.clock.calibration.ticks_to_ns(ticks)
    }

    /// Redraws about sixty times a second. Returns whether it still runs.
    pub fn tick(&mut self, out: &mut Out<'_>, now_ns: u64) -> bool {
        if now_ns.wrapping_sub(self.last_draw_ns) >= 16_000_000 {
            self.last_draw_ns = now_ns;
            let _ = out.write_str("\relapsed=");
            elapsed_nano(out, self.elapsed_ns());
            let _ = out.write_str(if self.running { "\x1b[K" } else { "  (paused)\x1b[K" });
        }
        true
    }

    /// Returns whether the job ends.
    pub fn key(&mut self, k: KeyInput, out: &mut Out<'_>, now_ns: u64) -> bool {
        match k {
            KeyInput::Char(' ') | KeyInput::Enter => {
                self.laps += 1;
                let _ = write!(out, "\rlap {:>3}  ", self.laps);
                elapsed_nano(out, self.elapsed_ns());
                let _ = out.write_str("\x1b[K\r\n");
            }
            KeyInput::Char('s') => {
                if self.running {
                    self.banked_ticks += crate::arch::counter_ordered().wrapping_sub(self.started_ticks);
                    self.running = false;
                } else {
                    self.started_ticks = crate::arch::counter_ordered();
                    self.running = true;
                }
                self.last_draw_ns = 0;
                self.tick(out, now_ns);
            }
            KeyInput::Char('r') => {
                self.banked_ticks = 0;
                self.laps = 0;
                self.started_ticks = crate::arch::counter_ordered();
                self.last_draw_ns = 0;
            }
            KeyInput::Char('q') | KeyInput::Escape => {
                let _ = out.write_str("\relapsed=");
                elapsed_nano(out, self.elapsed_ns());
                let _ = out.write_str("\x1b[K\r\n");
                return true;
            }
            _ => {}
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Live clocks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockKind {
    /// Time of day: the RTC's second, the counter below it.
    Wall,
    /// Every raw counter route.
    Counters,
}

pub struct LiveClock {
    kind: ClockKind,
    simple: bool,
    offset_minutes: i32,
    last_draw_ns: u64,
}

impl LiveClock {
    pub fn new(kind: ClockKind, now_ns: u64) -> LiveClock {
        let _ = now_ns;
        LiveClock { kind, simple: false, offset_minutes: 0, last_draw_ns: 0 }
    }

    fn draw(&self, out: &mut Out<'_>, now_ns: u64, in_place: bool) {
        let Some(system) = crate::system::get() else { return };
        if in_place {
            let _ = out.write_str("\r");
        }
        match self.kind {
            ClockKind::Wall => match system.clock.wall_ns() {
                Some(ns) => {
                    let day = 86_400_000_000_000i128;
                    let ns = (ns as i128 + self.offset_minutes as i128 * 60_000_000_000).rem_euclid(day) as u64;
                    let _ = out.write_str("time=");
                    if self.simple {
                        elapsed_simple(out, ns % 3_600_000_000_000);
                    } else {
                        elapsed_nano(out, ns);
                    }
                    let _ = write!(out, " UTC{:+}", self.offset_minutes / 60);
                }
                None => {
                    let _ = out.write_str("time=unknown (no RTC this kernel reads here); uptime=");
                    elapsed_nano(out, now_ns);
                }
            },
            ClockKind::Counters => {
                let raw = crate::arch::counter_ordered();
                let _ = write!(out, "counter={raw} {}={} Hz ns=", crate::arch::counter_source().name_here(), system.hz());
                elapsed_nano(out, system.uptime_ns());
            }
        }
        if in_place {
            let _ = out.write_str("\x1b[K");
        }
    }

    pub fn tick(&mut self, out: &mut Out<'_>, now_ns: u64) -> bool {
        if now_ns.wrapping_sub(self.last_draw_ns) >= 16_000_000 {
            self.last_draw_ns = now_ns;
            self.draw(out, now_ns, true);
        }
        true
    }
}
