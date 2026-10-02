// SPDX-License-Identifier: Apache-2.0
//! Task Manager: what the machine is doing, as `top` shows it, in a window.
//!
//! Three tabs. Performance: CPU activity over the last two minutes, from the
//! architecture's activity counters where it has them (APERF/MPERF, AMU,
//! PURR) or the loop's own accounting, with the effective frequency and IPC.
//! Apps: every window's share of the last second and the memory its surface
//! takes, and End Task. Memory: the kernel image and its static pools.

use super::{Ctx, Event, Hits, Response};
use crate::cpuload::{self, Load, Sample, Task};
use crate::desktop::surface::Rect;
use crate::desktop::theme::{self, Style};
use crate::fonts::{UI13, UI15, UI15_SEMIBOLD, UI20_SEMIBOLD, UI28_LIGHT};
use crate::framebuffer::Framebuffer;
use crate::text::Text;
use core::fmt::Write;

const HISTORY: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Performance,
    Apps,
    Memory,
}

pub struct Tasks {
    tab: Tab,
    history: [u16; HISTORY],
    filled: usize,
    previous: Option<Sample>,
    load: Load,
    busy_permille: u32,
    last_ns: u64,
    hits: Hits<24>,
    hover: Option<u16>,
    selected: Option<usize>,
}

const T_PERF: u16 = 1;
const T_APPS: u16 = 2;
const T_MEM: u16 = 3;
const B_END: u16 = 4;
const ROW: u16 = 100;

impl Tasks {
    pub fn new(ctx: &Ctx) -> Tasks {
        Tasks {
            tab: Tab::Performance,
            history: [0; HISTORY],
            filled: 0,
            previous: None,
            load: Load::default(),
            busy_permille: 0,
            last_ns: ctx.now_ns,
            hits: Hits::new(),
            hover: None,
            selected: None,
        }
    }

    fn sample(&mut self) {
        let Some(system) = crate::system::get() else { return };
        // SAFETY: after `cpuload::init`, at the kernel's privilege, with the
        // PMU the session enabled.
        let now = unsafe { cpuload::sample(system.pmu_for_load()) };
        if let Some(prev) = self.previous {
            self.load = cpuload::between(&prev, &now, system.hz());
        }
        self.previous = Some(now);
        let ticks = crate::desktop::phase_ticks();
        let total: u64 = ticks.iter().sum::<u64>().max(1);
        let idle = ticks[Task::Idle as usize];
        self.busy_permille = ((total - idle.min(total)) as u128 * 1000 / total as u128) as u32;
        let value = self.load.active_permille.unwrap_or(self.busy_permille).min(1000) as u16;
        self.history.rotate_left(1);
        self.history[HISTORY - 1] = value;
        self.filled = (self.filled + 1).min(HISTORY);
    }

    pub fn tick(&mut self, _fb: &Framebuffer, _w: i32, _h: i32, ctx: &Ctx) -> Response {
        if ctx.now_ns.wrapping_sub(self.last_ns) < 1_000_000_000 {
            return Response::default();
        }
        self.last_ns = ctx.now_ns;
        self.sample();
        Response::repaint()
    }

    pub fn paint(&mut self, fb: &Framebuffer, w: i32, h: i32, _ctx: &Ctx) {
        theme::fill(fb, Rect::new(0, 0, w, h), theme::WINDOW);
        self.hits.clear();
        // Tabs.
        let mut x = 16;
        for (id, tab, label) in [(T_PERF, Tab::Performance, "Performance"), (T_APPS, Tab::Apps, "Apps"), (T_MEM, Tab::Memory, "Memory")] {
            let tw = UI15_SEMIBOLD.width_of(label) as i32 + 28;
            let r = Rect::new(x, 12, tw, 34);
            let selected = self.tab == tab;
            if selected {
                theme::rounded(fb, r, 8, theme::CARD);
            } else if self.hover == Some(id) {
                theme::rounded(fb, r, 8, theme::HOVER);
            }
            UI15_SEMIBOLD.draw_centred(fb, r.x, r.w as u32, r.y + 8, label, if selected { theme::TEXT } else { theme::TEXT_DIM });
            if selected {
                theme::fill(fb, Rect::new(r.x + 12, r.bottom() - 3, r.w - 24, 3), theme::ACCENT);
            }
            self.hits.add(r, id);
            x += tw + 6;
        }
        let body = Rect::new(16, 60, w - 32, h - 76);
        match self.tab {
            Tab::Performance => self.paint_performance(fb, body),
            Tab::Apps => self.paint_apps(fb, body),
            Tab::Memory => paint_memory(fb, body),
        }
    }

    fn paint_performance(&mut self, fb: &Framebuffer, r: Rect) {
        let Some(system) = crate::system::get() else { return };
        let current = self.history[HISTORY - 1];
        let mut big = Text::<16>::new();
        let _ = write!(big, "{}.{}%", current / 10, current % 10);
        UI13.draw(fb, r.x, r.y, "CPU", theme::TEXT_DIM, u32::MAX);
        UI28_LIGHT.draw(fb, r.x, r.y + 18, big.as_str(), theme::TEXT, u32::MAX);
        let source = if self.load.active_permille.is_some() { cpuload::source().name() } else { "loop accounting" };
        UI13.draw_right(fb, r.right(), r.y + 4, source, theme::TEXT_FAINT);

        // The chart: two minutes, one sample a second.
        let chart = Rect::new(r.x, r.y + 64, r.w, (r.h - 190).max(80));
        theme::rounded(fb, chart, 8, theme::WINDOW_ALT);
        for i in 1..4 {
            let y = chart.y + chart.h * i / 4;
            theme::fill(fb, Rect::new(chart.x + 8, y, chart.w - 16, 1), 0x2E3239);
        }
        let n = self.filled.max(1);
        let step = (chart.w - 16) as i64;
        let mut prev: Option<(i32, i32)> = None;
        for (k, &v) in self.history[HISTORY - n..].iter().enumerate() {
            let x = chart.x + 8 + (step * k as i64 / (HISTORY - 1) as i64) as i32;
            let y = chart.bottom() - 8 - ((chart.h - 16) as i64 * v as i64 / 1000) as i32;
            // Area under the line, then the line.
            theme::fill(fb, Rect::new(x, y, 3, chart.bottom() - 8 - y), 0x1D4A26);
            if let Some((px, py)) = prev {
                let (y0, y1) = (py.min(y), py.max(y));
                theme::fill(fb, Rect::new(px, y0, (x - px).max(2), (y1 - y0).max(2)), theme::ACCENT);
            }
            prev = Some((x, y));
        }

        // Figures underneath.
        let mut y = chart.bottom() + 16;
        let col = r.w / 3;
        let stat = |i: i32, label: &str, value: &str| {
            let x = r.x + i * col;
            UI13.draw(fb, x, y, label, theme::TEXT_DIM, u32::MAX);
            UI20_SEMIBOLD.draw(fb, x, y + 18, value, theme::TEXT, col as u32 - 8);
        };
        let mut freq = Text::<24>::new();
        match self.load.frequency_khz {
            Some(k) => {
                let _ = write!(freq, "{}.{:02} GHz", k / 1_000_000, k / 10_000 % 100);
            }
            None => {
                freq.str("n/a");
            }
        }
        let mut ipc = Text::<16>::new();
        match self.load.ipc_x100 {
            Some(i) => {
                let _ = write!(ipc, "{}.{:02}", i / 100, i % 100);
            }
            None => {
                ipc.str("n/a");
            }
        }
        let up = system.uptime_ns() / 1_000_000_000;
        let mut uptime = Text::<24>::new();
        let _ = write!(uptime, "{}:{:02}:{:02}", up / 3600, up / 60 % 60, up % 60);
        stat(0, "Effective frequency", freq.as_str());
        stat(1, "Instructions per cycle", ipc.as_str());
        stat(2, "Up time", uptime.as_str());
        y += 64;
        let stat2 = |i: i32, label: &str, value: &str| {
            let x = r.x + i * col;
            UI13.draw(fb, x, y, label, theme::TEXT_DIM, u32::MAX);
            UI15.draw(fb, x, y + 18, value, theme::TEXT, col as u32 - 8);
        };
        let mut hz = Text::<24>::new();
        let _ = write!(hz, "{} MHz", system.hz() / 1_000_000);
        stat2(0, "Counter", hz.as_str());
        stat2(1, "PMU", system.route.name());
        stat2(2, "Idle", cpuload::idle_method());
    }

    fn paint_apps(&mut self, fb: &Framebuffer, r: Rect) {
        let header = Rect::new(r.x, r.y, r.w, 30);
        theme::rounded(fb, header, 6, theme::WINDOW_ALT);
        UI13.draw(fb, r.x + 14, r.y + 8, "Name", theme::TEXT_DIM, u32::MAX);
        UI13.draw_right(fb, r.right() - 220, r.y + 8, "CPU", theme::TEXT_DIM);
        UI13.draw_right(fb, r.right() - 110, r.y + 8, "Memory", theme::TEXT_DIM);
        UI13.draw_right(fb, r.right() - 14, r.y + 8, "Status", theme::TEXT_DIM);
        let mut y = r.y + 38;
        for (i, info) in crate::desktop::app_infos().enumerate() {
            let row = Rect::new(r.x, y, r.w, 34);
            if self.selected == Some(i) {
                theme::rounded(fb, row, 6, 0x1D4A26);
            } else if self.hover == Some(ROW + i as u16) {
                theme::rounded(fb, row, 6, theme::HOVER);
            }
            theme::icon(fb, info.icon, 24, r.x + 10, y + 5);
            UI15.draw(fb, r.x + 44, y + 8, info.name, theme::TEXT, (r.w - 330).max(40) as u32);
            let mut cpu = Text::<16>::new();
            let _ = write!(cpu, "{}.{}%", info.load_permille / 10, info.load_permille % 10);
            UI15.draw_right(fb, r.right() - 220, y + 8, cpu.as_str(), theme::TEXT);
            let mut mem = Text::<16>::new();
            let _ = write!(mem, "{:.1} MiB", info.memory_bytes as f32 / 1048576.0);
            UI15.draw_right(fb, r.right() - 110, y + 8, mem.as_str(), theme::TEXT);
            UI13.draw_right(fb, r.right() - 14, y + 10, if info.essential { "essential" } else { "running" }, theme::TEXT_FAINT);
            self.hits.add(row, ROW + i as u16);
            y += 38;
        }
        let end = Rect::new(r.right() - 120, r.bottom() - 40, 120, 36);
        theme::button(fb, end, "End task", Style::Danger, self.hover == Some(B_END));
        self.hits.add(end, B_END);
        UI13.draw(fb, r.x, r.bottom() - 30, "Phases of the kernel's loop are in the terminal's `top`.", theme::TEXT_FAINT, (r.w - 140) as u32);
    }

    pub fn event(&mut self, ev: Event, _ctx: &Ctx) -> Response {
        match ev {
            Event::PointerDown { x, y } => match self.hits.at(x, y) {
                Some(T_PERF) => self.tab = Tab::Performance,
                Some(T_APPS) => self.tab = Tab::Apps,
                Some(T_MEM) => self.tab = Tab::Memory,
                Some(B_END) => {
                    if let Some(i) = self.selected.take() {
                        crate::desktop::request_close(i);
                    }
                }
                Some(id) if id >= ROW => self.selected = Some((id - ROW) as usize),
                _ => return Response::default(),
            },
            Event::PointerMove { x, y } => {
                let hover = self.hits.at(x, y);
                if hover == self.hover {
                    return Response::default();
                }
                self.hover = hover;
            }
            _ => return Response::default(),
        }
        Response::repaint()
    }
}

fn paint_memory(fb: &Framebuffer, r: Rect) {
    let image = crate::multiboot::kernel_footprint();
    let installed = crate::system::get().map_or(0, |s| s.memory.total);
    UI13.draw(fb, r.x, r.y, "In use", theme::TEXT_DIM, u32::MAX);
    let mut t = Text::<48>::new();
    if installed > 0 {
        let _ = write!(t, "{} MiB of {} MiB", image >> 20, installed >> 20);
    } else {
        let _ = write!(t, "{} MiB (installed: not reported)", image >> 20);
    }
    UI28_LIGHT.draw(fb, r.x, r.y + 18, t.as_str(), theme::TEXT, r.w as u32);
    if installed > 0 {
        theme::meter(fb, Rect::new(r.x, r.y + 62, r.w, 12), (image as u128 * 1000 / installed as u128) as u32, theme::ACCENT);
    }
    let mut y = r.y + 92;
    let biggest = crate::memstat::pools().map(|(_, b)| b).max().unwrap_or(1).max(1);
    for (name, bytes) in crate::memstat::pools() {
        UI15.draw(fb, r.x, y, name, theme::TEXT, 160);
        let mut v = Text::<24>::new();
        let _ = write!(v, "{} KiB", bytes >> 10);
        UI15.draw_right(fb, r.right(), y, v.as_str(), theme::TEXT_DIM);
        theme::meter(fb, Rect::new(r.x + 170, y + 6, r.w - 300, 8), (bytes as u128 * 1000 / biggest as u128) as u32, theme::ACCENT_DIM);
        y += 28;
        if y > r.bottom() - 40 {
            break;
        }
    }
    UI13.draw(fb, r.x, r.bottom() - 18, "No heap: there is no allocator. Every pool above is a static of the kernel image.", theme::TEXT_FAINT, r.w as u32);
}
