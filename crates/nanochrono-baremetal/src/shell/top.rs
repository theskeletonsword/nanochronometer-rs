// SPDX-License-Identifier: Apache-2.0
//! `top`: what the machine is doing, redrawn twice a second.
//!
//! The figures are the task manager's (`crate::cpuload`): active time from
//! the architecture's activity counters (APERF/MPERF, AMU, PURR) where it has
//! them, the effective frequency and IPC from the same counters or the PMU,
//! and the time the kernel's one loop spent in each of its phases — the
//! nearest thing to a process list a machine with one program has. On the
//! desktop the apps get rows of their own, with the time each spent; and
//! underneath, where the memory is: the image, and in it every static pool.

use super::Out;
use crate::cpuload::{self, Load, Sample, Task};
use crate::kbd::KeyInput;
use core::fmt::Write;

const REFRESH_NS: u64 = 500_000_000;

pub struct Top {
    previous: Sample,
    last_ns: u64,
    load: Load,
    ticks: [u64; 5],
    started_ns: u64,
}

impl Top {
    pub fn start(out: &mut Out<'_>, now_ns: u64) -> Option<Top> {
        let system = crate::system::get()?;
        let _ = cpuload::take_task_ticks();
        // SAFETY: after `cpuload::init` (the session ran it), at the
        // kernel's privilege, with the PMU the session enabled.
        let previous = unsafe { cpuload::sample(system.pmu_for_load()) };
        let _ = out.write_str("\x1b[?25l\x1b[H\x1b[2J");
        let top = Top { previous, last_ns: now_ns, load: Load::default(), ticks: [0; 5], started_ns: now_ns };
        top.draw(out, now_ns);
        Some(top)
    }

    /// Redraws on its period. Returns whether it still runs.
    pub fn tick(&mut self, out: &mut Out<'_>, now_ns: u64) -> bool {
        if now_ns.wrapping_sub(self.last_ns) < REFRESH_NS {
            return true;
        }
        let Some(system) = crate::system::get() else { return false };
        // SAFETY: as in `start`.
        let sample = unsafe { cpuload::sample(system.pmu_for_load()) };
        self.load = cpuload::between(&self.previous, &sample, system.hz());
        self.ticks = cpuload::take_task_ticks();
        self.previous = sample;
        self.last_ns = now_ns;
        self.draw(out, now_ns);
        true
    }

    /// Returns whether `top` ends.
    pub fn key(&mut self, k: KeyInput, out: &mut Out<'_>) -> bool {
        if matches!(k, KeyInput::Char('q') | KeyInput::Escape) {
            let _ = out.write_str("\x1b[?25h\x1b[H\x1b[2J");
            return true;
        }
        false
    }

    fn draw(&self, out: &mut Out<'_>, now_ns: u64) {
        let Some(system) = crate::system::get() else { return };
        let cols = out.term.cols;
        let width = cols.saturating_sub(40).clamp(10, 60);
        let total: u64 = self.ticks.iter().sum::<u64>().max(1);
        let idle = self.ticks[Task::Idle as usize];
        let busy = ((total - idle.min(total)) as u128 * 1000 / total as u128) as u32;
        let up = now_ns / 1_000_000_000;
        let _ = out.write_str("\x1b[H");
        let _ = writeln!(
            out,
            "\x1b[1mtop\x1b[0m - up {}:{:02}:{:02}  NanoChronometer {} ({})  \x1b[2m[q] quit\x1b[0m\x1b[K\r",
            up / 3600,
            up / 60 % 60,
            up % 60,
            crate::VERSION,
            crate::system::MACHINE
        );
        let hv = if system.hypervisor.is_virtualized() { system.hypervisor.signature_str() } else { "none" };
        let _ = writeln!(out, "hypervisor: {hv}   counter: {} at {} Hz\x1b[K\r", crate::arch::counter_source().name_here(), system.hz());
        let _ = writeln!(out, "\x1b[K\r");
        match self.load.active_permille {
            Some(p) => {
                let _ = write!(out, "CPU  ");
                bar(out, p, width);
                let _ = writeln!(out, " {:>3}.{}% active ({})\x1b[K\r", p / 10, p % 10, cpuload::source().name());
            }
            None => {
                let _ = write!(out, "CPU  ");
                bar(out, busy, width);
                let _ = writeln!(out, " {:>3}.{}% busy (loop accounting)\x1b[K\r", busy / 10, busy % 10);
            }
        }
        let _ = write!(out, "loop ");
        bar(out, busy, width);
        let _ = writeln!(out, " {:>3}.{}% not idle\x1b[K\r", busy / 10, busy % 10);
        let mut freq = crate::text::Text::<24>::new();
        match self.load.frequency_khz {
            Some(k) => {
                let _ = write!(freq, "{} MHz", k / 1000);
            }
            None => {
                freq.str("n/a");
            }
        }
        let mut ipc = crate::text::Text::<16>::new();
        match self.load.ipc_x100 {
            Some(i) => {
                let _ = write!(ipc, "{}.{:02}", i / 100, i % 100);
            }
            None => {
                ipc.str("n/a");
            }
        }
        let _ = writeln!(out, "freq {}   IPC {}   PMU {}   idle: {}\x1b[K\r", freq.as_str(), ipc.as_str(), system.route.name(), cpuload::idle_method());
        let _ = writeln!(out, "\x1b[K\r");

        let _ = writeln!(out, "\x1b[7m  PID TASK          CPU%      ms  TIME BAR{}\x1b[0m\r", Pad(cols.saturating_sub(43)));
        let mut pid = 1;
        let ms = |t: u64| (t as u128 * 1000 / system.hz().max(1) as u128) as u64;
        for task in Task::ALL {
            let t = self.ticks[task as usize];
            let permille = (t as u128 * 1000 / total as u128) as u32;
            let _ = write!(out, "  {pid:>3} {:<11} {:>3}.{}% {:>7}  ", task.name(), permille / 10, permille % 10, ms(t));
            bar(out, permille, width.min(30));
            let _ = writeln!(out, "\x1b[K\r");
            pid += 1;
        }
        for (name, permille) in crate::desktop::app_load() {
            let _ = write!(out, "  {pid:>3} {:<11} {:>3}.{}%          ", name, permille / 10, permille % 10);
            bar(out, permille, width.min(30));
            let _ = writeln!(out, "\x1b[K\r");
            pid += 1;
        }
        let _ = writeln!(out, "\x1b[K\r");

        let image = crate::multiboot::kernel_footprint();
        let installed = system.memory.total;
        if installed > 0 {
            let permille = (image as u128 * 1000 / installed as u128) as u32;
            let _ = write!(out, "MEM  ");
            bar(out, permille, width);
            let _ = writeln!(out, " {} MiB of {} MiB (the kernel image)\x1b[K\r", image >> 20, installed >> 20);
        } else {
            let _ = writeln!(out, "MEM  kernel image {} MiB (installed: not reported by the loader)\x1b[K\r", image >> 20);
        }
        let mut line = 0;
        for (name, bytes) in crate::memstat::pools() {
            let _ = write!(out, "  {:<13}{:>7} KiB", name, bytes >> 10);
            line += 1;
            if line % 3 == 0 {
                let _ = out.write_str("\x1b[K\r\n");
            } else {
                let _ = out.write_str("   ");
            }
        }
        let _ = writeln!(out, "\x1b[K\r");
        let _ = writeln!(out, "  heap: none — there is no allocator; every byte above is a static of the image\x1b[K\r");
        let _ = out.write_str("\x1b[J");
        let _ = self.started_ns;
    }
}

struct Pad(usize);

impl core::fmt::Display for Pad {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for _ in 0..self.0 {
            f.write_str(" ")?;
        }
        Ok(())
    }
}

/// An htop-style bar in eighth blocks, green to yellow to red as it fills.
fn bar(out: &mut Out<'_>, permille: u32, width: usize) {
    let permille = permille.min(1000) as usize;
    let eighths = permille * width * 8 / 1000;
    let colour = match permille {
        0..=499 => "32",
        500..=849 => "33",
        _ => "31",
    };
    let _ = write!(out, "\x1b[{colour}m");
    for i in 0..width {
        let fill = eighths.saturating_sub(i * 8).min(8);
        let c = match fill {
            0 => '·',
            8 => '█',
            n => char::from_u32(0x2590 - n as u32).unwrap_or('█'),
        };
        let _ = out.write_char(c);
    }
    let _ = out.write_str("\x1b[0m");
}
