// SPDX-License-Identifier: Apache-2.0
//! The interactive serial console: a menu, a task manager and settings.
//!
//! The graphical interface exists only on x86 (a multiboot framebuffer).
//! Everywhere else — AArch64, RISC-V, PowerPC, and x86 booted in text mode —
//! the machine's console is a UART, so the same three things are drawn with
//! ANSI escapes instead of pixels:
//!
//! * **Task manager** — the htop of a machine with one program: CPU active
//!   time from the architecture's activity counters, effective frequency,
//!   IPC, and the time spent in each phase of this very loop. See
//!   [`crate::cpuload`] for where each figure comes from.
//! * **Hypervisor** — the report the boot-time negotiation produced, and a
//!   re-probe key behind a 10-second cooldown (see [`crate::hypervisor`]).
//! * **Settings** — *Enable Physical Counter* (AArch64: `CNTPCT_EL0` instead
//!   of the default `CNTVCT_EL0`) and the re-probe cooldown, each with its
//!   warning always on screen.
//! * **Self-test** — the boot report, again.

use crate::cpuload::{self, Load, Sample, Task};
use crate::pmu::{CorePmu, CounterRoute};
use crate::{arch, println, serial};
use core::fmt::Write as _;

const CLEAR: &str = "\x1b[H\x1b[2J";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

/// Refresh period of the task manager.
const REFRESH_NS: u64 = 500_000_000;
/// How often a wait looks at the UART. Short enough that a key feels
/// immediate; each slice is otherwise spent in the idle wait.
const POLL_NS: u64 = 10_000_000;

struct Console {
    hz: u64,
    pmu: CorePmu,
    pmu_route: CounterRoute,
    virtualized: bool,
    hypervisor: &'static str,
    started: u64,
    /// The CNTPCT/CNTVCT read-cost comparison, taken when the physical
    /// counter is switched on — not on every redraw: in a VM each trapped
    /// read is an exit, and exits are what the cooldown rules ration.
    counter_check: Option<nanochrono_core::arch::PhysicalCounterCheck>,
    /// The outcome of the last re-probe request.
    reprobe_status: Str32,
}

/// Runs the console forever.
///
/// # Safety
/// Ring 0 / EL1+ / supervisor, after `Serial::init` and the self-test, on the
/// only running core.
pub unsafe fn run() -> ! {
    // SAFETY: forwarded from this function's contract.
    unsafe { cpuload::init() };
    let mut pmu = CorePmu::detect();
    // SAFETY: as above; the PMU belongs to this core and nothing else.
    let pmu_route = if pmu.is_available() { unsafe { pmu.enable() } } else { CounterRoute::None };
    // SAFETY: as above.
    let hv = unsafe { crate::hypervisor::detect() };
    let mut console = Console {
        hz: reference_hz(),
        pmu,
        pmu_route,
        virtualized: hv.is_virtualized(),
        hypervisor: if hv.is_virtualized() { "hypervisor detected" } else { "none detected" },
        started: arch::counter_ordered(),
        counter_check: None,
        reprobe_status: Str32::new(),
    };
    loop {
        console.menu();
        match console.wait_key(u64::MAX) {
            Some(b't') | Some(b'T') => console.task_manager(),
            Some(b's') | Some(b'S') => console.settings(),
            Some(b'v') | Some(b'V') => console.hypervisor_screen(),
            Some(b'r') | Some(b'R') => {
                print!("{CLEAR}");
                // SAFETY: forwarded from this function's contract.
                unsafe { crate::selftest::run() };
                println!("{DIM}press any key{RESET}");
                console.wait_key(u64::MAX);
            }
            Some(b'h') | Some(b'H') => {
                println!("{CLEAR}halted.");
                arch::halt();
            }
            _ => {}
        }
    }
}

/// `print!` without the newline `println!` adds.
macro_rules! print {
    ($($arg:tt)*) => { $crate::serial::_print(format_args!($($arg)*)) };
}
use print;

/// The reference counter's rate: stated by the architecture where it is
/// (CNTFRQ, the device tree), measured on x86.
fn reference_hz() -> u64 {
    #[cfg(x86_any)]
    {
        // SAFETY: the PIT/CPUID calibration reads ports and CPUID at CPL 0.
        unsafe { crate::clock::Calibration::measure() }.hz
    }
    #[cfg(not(x86_any))]
    {
        nanochrono_core::arch::declared_counter_hz().unwrap_or(1_000_000_000)
    }
}

impl Console {
    fn ns_to_ticks(&self, ns: u64) -> u64 {
        ((ns as u128 * self.hz as u128) / 1_000_000_000) as u64
    }

    /// Waits up to `deadline` (reference ticks; `u64::MAX` = forever) for a
    /// key, idling between polls. Polling is charged to `Input`, waiting to
    /// `Idle`.
    fn wait_key(&self, deadline: u64) -> Option<u8> {
        loop {
            cpuload::switch_to(Task::Input);
            if let Some(b) = serial::read_byte() {
                cpuload::switch_to(Task::Measure);
                return Some(b);
            }
            let now = arch::counter_ordered();
            if now >= deadline {
                cpuload::switch_to(Task::Measure);
                return None;
            }
            let slice = now.saturating_add(self.ns_to_ticks(POLL_NS)).min(deadline);
            cpuload::idle_until(slice);
        }
    }

    fn menu(&self) {
        cpuload::switch_to(Task::Render);
        print!("{CLEAR}");
        println!("{BOLD}NanoChronometer {} — freestanding ({}){RESET}", crate::VERSION, arch_line());
        println!();
        println!("  [t] task manager");
        println!("  [v] hypervisor (re-probe)");
        println!("  [s] settings");
        println!("  [r] run the self-test again");
        println!("  [h] halt");
        println!();
        println!(
            "{DIM}counter: {}   activity counters: {}{RESET}",
            arch::counter_source().name_here(),
            cpuload::source().name()
        );
        cpuload::switch_to(Task::Measure);
    }

    // -- task manager --------------------------------------------------------

    fn task_manager(&mut self) {
        let _ = cpuload::take_task_ticks();
        // SAFETY: after `cpuload::init`, same privilege level; PMU enabled.
        let mut previous = unsafe { cpuload::sample(self.pmu_for_sampling()) };
        let mut last = arch::counter_ordered();
        loop {
            let deadline = last.wrapping_add(self.ns_to_ticks(REFRESH_NS));
            if let Some(key) = self.wait_key(deadline) {
                if matches!(key, b'q' | b'Q' | 0x1b) {
                    return;
                }
                if matches!(key, b's' | b'S') {
                    self.settings();
                }
            }
            cpuload::switch_to(Task::Measure);
            // SAFETY: as above.
            let now_sample = unsafe { cpuload::sample(self.pmu_for_sampling()) };
            let load = cpuload::between(&previous, &now_sample, self.hz);
            let ticks = cpuload::take_task_ticks();
            previous = now_sample;
            last = arch::counter_ordered();
            self.draw_tasks(&load, &ticks, &now_sample);
        }
    }

    fn pmu_for_sampling(&self) -> Option<&CorePmu> {
        (self.pmu_route != CounterRoute::None).then_some(&self.pmu)
    }

    fn draw_tasks(&self, load: &Load, ticks: &[u64; 5], _sample: &Sample) {
        cpuload::switch_to(Task::Render);
        let mut screen = ScreenBuffer::new();
        let total: u64 = ticks.iter().sum::<u64>().max(1);
        let idle = ticks[Task::Idle as usize];
        let busy_permille = ((total - idle.min(total)) as u128 * 1000 / total as u128) as u32;

        let _ = write!(screen, "{CLEAR}");
        let _ = writeln!(screen, "{BOLD}NanoChronometer task manager{RESET}  {}   {DIM}[q] back  [s] settings{RESET}\r", arch_line());
        let uptime_s = arch::counter_ordered().wrapping_sub(self.started) / self.hz.max(1);
        let _ = writeln!(screen, "uptime {}:{:02}:{:02}   hypervisor: {}\r", uptime_s / 3600, uptime_s / 60 % 60, uptime_s % 60, self.hypervisor);
        let _ = writeln!(screen, "\r");

        match load.active_permille {
            Some(p) => {
                let _ = writeln!(screen, "CPU  {}  {}  active ({}, hardware)\r", bar(p, 40), pct(p), cpuload::source().name());
            }
            None => {
                let _ = writeln!(screen, "CPU  {}  {}  active (loop accounting: this core has no active-time counter)\r", bar(busy_permille, 40), pct(busy_permille));
            }
        }
        let _ = writeln!(screen, "loop {}  {}  not idle\r", bar(busy_permille, 40), pct(busy_permille));
        let freq = match load.frequency_khz {
            Some(k) => format_mhz(k),
            None => Str32::from("n/a"),
        };
        let ipc = match load.ipc_x100 {
            Some(i) => {
                let mut s = Str32::new();
                let _ = write!(s, "{}.{:02}", i / 100, i % 100);
                s
            }
            None => Str32::from("n/a"),
        };
        let _ = writeln!(screen, "freq {} MHz   IPC {}   PMU route {}\r", freq.as_str(), ipc.as_str(), self.pmu_route.name());
        let _ = writeln!(screen, "counter {} at {} Hz   idle: {}\r", arch::counter_source().name_here(), self.hz, cpuload::idle_method());
        let _ = writeln!(screen, "\r");
        let _ = writeln!(screen, "{BOLD}  TASK        TIME%   ms/window{RESET}\r");
        for task in Task::ALL {
            let t = ticks[task as usize];
            let permille = (t as u128 * 1000 / total as u128) as u32;
            let ms = (t as u128 * 1000 / self.hz.max(1) as u128) as u64;
            let _ = writeln!(screen, "  {:<10} {:>6}  {:>6}   {}\r", task.name(), pct(permille).as_str(), ms, bar(permille, 30));
        }
        let _ = writeln!(screen, "\r");
        let _ = writeln!(screen, "MEM  kernel image {} KiB\r", crate::multiboot::kernel_footprint() / 1024);
        cpuload::switch_to(Task::Present);
        serial::_print(format_args!("{}", screen.as_str()));
        cpuload::switch_to(Task::Measure);
    }

    // -- hypervisor ----------------------------------------------------------

    fn hypervisor_screen(&mut self) {
        loop {
            cpuload::switch_to(Task::Render);
            // SAFETY: cached since the self-test; this does not probe.
            let hv = unsafe { crate::hypervisor::detect() };
            let wait = crate::hypervisor::reprobe_wait_s(self.hz);
            print!("{CLEAR}");
            println!("{BOLD}Hypervisor{RESET}   {DIM}[p] re-probe  [q] back{RESET}");
            println!();
            println!("  virtualized    : {}", if hv.is_virtualized() { "yes" } else { "no" });
            let sig = hv.signature_str();
            println!("  signature      : {}", if sig.is_empty() { "none" } else { sig });
            println!("  hypercall      : {}", if hv.hypercall_ok { "answered" } else { "none" });
            #[cfg(x86_any)]
            println!(
                "  hypercall HAL  : {} ({})",
                hv.hypercall_insn.map_or("none", |i| i.name()),
                nanochrono_core::cpu::vendor().name()
            );
            if let Some(p) = hv.pairing {
                println!("  host clock     : {} ns at counter {}", p.host_ns, p.counter);
            }
            println!("  probes run     : {} (1 = the boot negotiation only)", hv.probes);
            println!("  hypercalls     : {} since power-on", crate::hypervisor::hypercalls());
            println!();
            if crate::hypervisor::cooldown_enabled() {
                println!("  {DIM}{}{RESET}", nanochrono_core::reprobe::COOLDOWN_NOTE);
            } else {
                println!("  {RED}Re-probe cooldown OFF (settings): the provider-ban risk is yours.{RESET}");
            }
            if wait > 0 {
                println!("  [p] re-probe ....................... {YELLOW}wait {wait} s{RESET}");
            } else {
                println!("  [p] re-probe ....................... {GREEN}ready{RESET}");
            }
            if !self.reprobe_status.as_str().is_empty() {
                println!("  {}", self.reprobe_status.as_str());
            }
            cpuload::switch_to(Task::Measure);
            // Redraw once a second while counting down; otherwise wait.
            let deadline = if wait > 0 {
                arch::counter_ordered().wrapping_add(self.ns_to_ticks(1_000_000_000))
            } else {
                u64::MAX
            };
            match self.wait_key(deadline) {
                Some(b'p') | Some(b'P') => {
                    // SAFETY: ring 0 / EL1 / supervisor, per `run`.
                    self.reprobe_status = match unsafe { crate::hypervisor::reprobe(self.hz) } {
                        Ok(r) => {
                            self.virtualized = r.is_virtualized();
                            self.hypervisor =
                                if r.is_virtualized() { "hypervisor detected" } else { "none detected" };
                            Str32::from("re-probed")
                        }
                        Err(left) => {
                            let mut m = Str32::new();
                            let _ = write!(m, "refused: {left} s of cooldown left");
                            m
                        }
                    };
                }
                Some(b'q') | Some(b'Q') | Some(0x1b) => return,
                _ => {}
            }
        }
    }

    // -- settings ------------------------------------------------------------

    fn settings(&mut self) {
        loop {
            cpuload::switch_to(Task::Render);
            print!("{CLEAR}");
            println!("{BOLD}Settings{RESET}   {DIM}[q] back{RESET}");
            println!();
            let physical = arch::counter_source() == arch::CounterSource::Physical;
            if nanochrono_core::arch::has_physical_counter() {
                println!(
                    "  [p] Enable Physical Counter ........ {}{}{RESET}",
                    if physical { GREEN } else { DIM },
                    if physical { "ON " } else { "OFF" }
                );
                println!("      in use: {}   default: cntvct_el0", arch::counter_source().name_here());
                println!();
                println!(
                    "  {}WARNING:{RESET} {}",
                    if self.virtualized { RED } else { YELLOW },
                    nanochrono_core::arch::PHYSICAL_COUNTER_WARNING
                );
                if self.virtualized {
                    println!(
                        "  {RED}This machine is virtualized ({}). It can still be enabled; \
                         expect trapped, jittery reads — worse under nested virtualization.{RESET}",
                        self.hypervisor
                    );
                }
                if let Some(check) = &self.counter_check {
                    println!(
                        "  one read: {} ns physical vs {} ns virtual{}",
                        check.physical_read_ns,
                        check.virtual_read_ns,
                        if check.trapped { "  — the physical read is being trapped" } else { "" }
                    );
                }
            } else {
                println!("  Enable Physical Counter ............ n/a");
                println!(
                    "  {DIM}Only AArch64 has a separate physical counter. This machine reads {}.{RESET}",
                    arch::counter_source().name_here()
                );
            }
            println!();
            let cooldown = crate::hypervisor::cooldown_enabled();
            println!(
                "  [c] Re-probe cooldown ({} s) ........ {}{}{RESET}",
                nanochrono_core::reprobe::DEFAULT_COOLDOWN_S,
                if cooldown { GREEN } else { RED },
                if cooldown { "ON " } else { "OFF" }
            );
            println!(
                "  {}WARNING:{RESET} {}",
                if cooldown { YELLOW } else { RED },
                nanochrono_core::reprobe::COOLDOWN_OFF_WARNING
            );
            cpuload::switch_to(Task::Measure);
            match self.wait_key(u64::MAX) {
                Some(b'p') | Some(b'P') if nanochrono_core::arch::has_physical_counter() => {
                    let next = if physical { arch::CounterSource::Virtual } else { arch::CounterSource::Physical };
                    let _ = arch::set_counter_source(next);
                    self.counter_check = if physical {
                        None
                    } else {
                        nanochrono_core::arch::physical_counter_check()
                    };
                    // The reference changed timeline (in a VM they differ by
                    // CNTVOFF_EL2): uptime restarts from the new one.
                    self.started = arch::counter_ordered();
                }
                Some(b'c') | Some(b'C') => {
                    crate::hypervisor::set_cooldown_enabled(!crate::hypervisor::cooldown_enabled());
                }
                Some(b'q') | Some(b'Q') | Some(0x1b) => return,
                _ => {}
            }
        }
    }
}

fn arch_line() -> Str32 {
    let mut s = Str32::new();
    let _ = write!(s, "{}", nanochrono_core::arch::ARCH.name());
    #[cfg(target_arch = "aarch64")]
    let _ = write!(s, ", EL{}", crate::arch::arm::current_el());
    s
}

fn pct(permille: u32) -> Str32 {
    let mut s = Str32::new();
    let _ = write!(s, "{:>3}.{}%", permille / 10, permille % 10);
    s
}

fn format_mhz(khz: u64) -> Str32 {
    let mut s = Str32::new();
    let _ = write!(s, "{}", khz / 1000);
    s
}

/// An htop-style bar, green to yellow to red as it fills.
fn bar(permille: u32, width: usize) -> Bar {
    Bar { permille: permille.min(1000), width }
}

struct Bar {
    permille: u32,
    width: usize,
}

impl core::fmt::Display for Bar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let filled = (self.permille as usize * self.width).div_ceil(1000).min(self.width);
        let colour = match self.permille {
            0..=499 => GREEN,
            500..=849 => YELLOW,
            _ => RED,
        };
        f.write_str("[")?;
        f.write_str(colour)?;
        for _ in 0..filled {
            f.write_str("|")?;
        }
        f.write_str(RESET)?;
        for _ in filled..self.width {
            f.write_str(" ")?;
        }
        f.write_str("]")
    }
}

/// A small fixed string, for formatting without an allocator.
struct Str32 {
    bytes: [u8; 64],
    len: usize,
}

impl Str32 {
    const fn new() -> Str32 {
        Str32 { bytes: [0; 64], len: 0 }
    }

    fn from(s: &str) -> Str32 {
        let mut out = Str32::new();
        let _ = out.write_str(s);
        out
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

impl core::fmt::Write for Str32 {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.bytes.len() {
                break;
            }
            self.bytes[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

impl core::fmt::Display for Str32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The whole task-manager screen, formatted first and written in one go so
/// the terminal repaints without flicker (and so "present" is one phase).
struct ScreenBuffer {
    bytes: [u8; 4096],
    len: usize,
}

impl ScreenBuffer {
    const fn new() -> ScreenBuffer {
        ScreenBuffer { bytes: [0; 4096], len: 0 }
    }

    fn as_str(&self) -> &str {
        // Truncation can only split at a byte the formatter wrote; fall back
        // to the valid prefix rather than nothing.
        match core::str::from_utf8(&self.bytes[..self.len]) {
            Ok(s) => s,
            Err(e) => core::str::from_utf8(&self.bytes[..e.valid_up_to()]).unwrap_or(""),
        }
    }
}

impl core::fmt::Write for ScreenBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.bytes.len() {
                break;
            }
            self.bytes[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}
