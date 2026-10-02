// SPDX-License-Identifier: Apache-2.0
//! Stopwatch — essential: built in, pinned to the taskbar, never removable.
//!
//! The desktop's face of the instrument: the elapsed time to the nanosecond
//! in a large tabular readout, laps with their split from the previous one,
//! and — where the machine has a PMU — the cycles and instructions the core
//! ran while the stopwatch did. The stored counter values carry a Hamming
//! code and three replicas (`nanochrono_core::Protected`), as the classic
//! instrument's do: a flipped bit in a running total is corrected on read,
//! not believed.

use super::{Ctx, Event, Hits, Response};
use crate::desktop::surface::Rect;
use crate::desktop::theme::{self, Style};
use crate::fonts::{UI13, UI15, UI15_SEMIBOLD, UI20_SEMIBOLD, UI56_DIGITS};
use crate::framebuffer::Framebuffer;
use crate::kbd::KeyInput;
use crate::text::Text;
use core::fmt::Write;
use nanochrono_core::Protected;

const MAX_LAPS: usize = 64;

const B_START: u16 = 1;
const B_LAP: u16 = 2;
const B_RESET: u16 = 3;

pub struct Stopwatch {
    running: bool,
    banked: Protected,
    started_at: Protected,
    laps: [u64; MAX_LAPS],
    lap_count: usize,
    hits: Hits<8>,
    hover: Option<u16>,
    readout: Rect,
    /// Cycles and instructions while running, from the PMU.
    cycles: u64,
    instructions: u64,
    last_pmu: Option<(u64, u64)>,
    last_text: Text<24>,
}

impl Stopwatch {
    pub fn new(_ctx: &Ctx) -> Stopwatch {
        Stopwatch {
            running: false,
            banked: Protected::new(0),
            started_at: Protected::new(0),
            laps: [0; MAX_LAPS],
            lap_count: 0,
            hits: Hits::new(),
            hover: None,
            readout: Rect::default(),
            cycles: 0,
            instructions: 0,
            last_pmu: None,
            last_text: Text::new(),
        }
    }

    fn ticks(&mut self) -> u64 {
        let banked = self.banked.get();
        if self.running {
            banked + crate::arch::counter_ordered().wrapping_sub(self.started_at.get())
        } else {
            banked
        }
    }

    fn elapsed_ns(&mut self) -> u64 {
        let ticks = self.ticks();
        crate::system::get().map_or(0, |s| s.clock.calibration.ticks_to_ns(ticks))
    }

    fn pmu_read() -> Option<(u64, u64)> {
        let system = crate::system::get()?;
        system.pmu_for_load()?;
        // SAFETY: kernel privilege; the session enabled the PMU.
        let (c, i) = unsafe { (system.pmu.read_cycles(), system.pmu.read_instructions()) };
        Some((c?.value, i.map_or(0, |r| r.value)))
    }

    fn fold_pmu(&mut self) {
        if let (Some((c0, i0)), Some((c1, i1))) = (self.last_pmu, Self::pmu_read()) {
            self.cycles += c1.wrapping_sub(c0) & 0xFFFF_FFFF_FFFF;
            self.instructions += i1.wrapping_sub(i0) & 0xFFFF_FFFF;
        }
        self.last_pmu = if self.running { Self::pmu_read() } else { None };
    }

    fn toggle(&mut self) {
        if self.running {
            // Verified before it is banked: a flipped bit stored here would
            // be re-encoded as good.
            let _ = self.banked.verify().max(self.started_at.verify());
            let t = self.ticks();
            self.banked.set(t);
            self.running = false;
            self.fold_pmu();
        } else {
            self.started_at.set(crate::arch::counter_ordered());
            self.running = true;
            self.last_pmu = Self::pmu_read();
        }
    }

    fn lap(&mut self) {
        let ns = self.elapsed_ns();
        if self.lap_count == MAX_LAPS {
            self.laps.rotate_left(1);
            self.laps[MAX_LAPS - 1] = ns;
        } else {
            self.laps[self.lap_count] = ns;
            self.lap_count += 1;
        }
    }

    fn reset(&mut self) {
        self.running = false;
        self.banked.set(0);
        self.started_at.set(0);
        self.lap_count = 0;
        self.cycles = 0;
        self.instructions = 0;
        self.last_pmu = None;
    }

    fn format(ns: u64) -> Text<24> {
        let mut t = Text::new();
        crate::shell::nanochrono::elapsed_nano(&mut t, ns);
        t
    }

    /// The readout alone, for the frame-by-frame update.
    fn paint_readout(&mut self, fb: &Framebuffer) {
        let r = self.readout;
        theme::fill(fb, r, theme::WINDOW);
        let ns = self.elapsed_ns();
        let text = Self::format(ns);
        let colour = if self.running { theme::ACCENT } else { theme::TEXT };
        UI56_DIGITS.draw_centred(fb, r.x, r.w as u32, r.y, text.as_str(), colour);
        self.last_text = text;
    }

    pub fn paint(&mut self, fb: &Framebuffer, w: i32, h: i32, _ctx: &Ctx) {
        theme::fill(fb, Rect::new(0, 0, w, h), theme::WINDOW);
        self.hits.clear();
        let state = if self.running { "running" } else if self.ticks() > 0 { "paused" } else { "ready" };
        UI13.draw(fb, 24, 18, "ELAPSED", theme::TEXT_FAINT, u32::MAX);
        UI13.draw_right(fb, w - 24, 18, state, if self.running { theme::ACCENT } else { theme::TEXT_DIM });
        self.readout = Rect::new(16, 40, w - 32, UI56_DIGITS.line_height as i32 + 8);
        self.paint_readout(fb);
        UI13.draw_centred(fb, 0, w as u32, self.readout.bottom() + 2, "hh : mm : ss : ms : µs : ns", theme::TEXT_FAINT);

        // The buttons.
        let by = self.readout.bottom() + 34;
        let bw = 132;
        let gap = 14;
        let x0 = (w - (3 * bw + 2 * gap)) / 2;
        let start = Rect::new(x0, by, bw, 40);
        let lap = Rect::new(x0 + bw + gap, by, bw, 40);
        let reset = Rect::new(x0 + 2 * (bw + gap), by, bw, 40);
        theme::button(fb, start, if self.running { "Stop" } else { "Start" }, if self.running { Style::Danger } else { Style::Accent }, self.hover == Some(B_START));
        theme::button(fb, lap, "Lap", Style::Normal, self.hover == Some(B_LAP));
        theme::button(fb, reset, "Reset", Style::Normal, self.hover == Some(B_RESET));
        self.hits.add(start, B_START);
        self.hits.add(lap, B_LAP);
        self.hits.add(reset, B_RESET);

        // Laps, newest first, and the PMU on the right.
        let top = by + 60;
        let split = w * 3 / 5;
        theme::rounded(fb, Rect::new(16, top, split - 24, h - top - 16), 10, theme::WINDOW_ALT);
        UI15_SEMIBOLD.draw(fb, 30, top + 10, "Laps", theme::TEXT, u32::MAX);
        let line = UI15.line_height as i32 + 6;
        let rows = ((h - top - 56) / line).max(0) as usize;
        if self.lap_count == 0 {
            UI13.draw(fb, 30, top + 40, "Space starts and stops; L or Enter takes a lap.", theme::TEXT_FAINT, (split - 60) as u32);
        }
        for (k, i) in (0..self.lap_count).rev().take(rows).enumerate() {
            let y = top + 40 + k as i32 * line;
            let mut label = Text::<16>::new();
            let _ = write!(label, "Lap {}", i + 1);
            UI15.draw(fb, 30, y, label.as_str(), theme::TEXT_DIM, u32::MAX);
            let total = Self::format(self.laps[i]);
            UI15.draw(fb, 110, y, total.as_str(), theme::TEXT, u32::MAX);
            let delta = self.laps[i] - if i > 0 { self.laps[i - 1] } else { 0 };
            let mut d = Text::<28>::new();
            d.str("+");
            crate::shell::nanochrono::elapsed_nano(&mut d, delta);
            UI13.draw_right(fb, split - 24, y + 2, d.as_str(), theme::TEXT_FAINT);
        }

        let px = split + 8;
        let pw = w - px - 16;
        theme::rounded(fb, Rect::new(px, top, pw, h - top - 16), 10, theme::WINDOW_ALT);
        UI15_SEMIBOLD.draw(fb, px + 14, top + 10, "Core", theme::TEXT, u32::MAX);
        let mut y = top + 40;
        let mut row = |label: &str, value: &str| {
            UI13.draw(fb, px + 14, y, label, theme::TEXT_DIM, u32::MAX);
            UI13.draw_right(fb, px + pw - 14, y, value, theme::TEXT);
            y += UI13.line_height as i32 + 8;
        };
        match Self::pmu_read() {
            Some(_) => {
                let mut c = Text::<24>::new();
                let _ = write!(c, "{}", self.cycles);
                row("cycles", c.as_str());
                let mut n = Text::<24>::new();
                let _ = write!(n, "{}", self.instructions);
                row("instructions", n.as_str());
                if self.cycles > 0 {
                    let ipc = self.instructions * 100 / self.cycles.max(1);
                    let mut t = Text::<16>::new();
                    let _ = write!(t, "{}.{:02}", ipc / 100, ipc % 100);
                    row("IPC", t.as_str());
                }
            }
            None => row("PMU", "not available"),
        }
        if let Some(system) = crate::system::get() {
            let mut hz = Text::<24>::new();
            let _ = write!(hz, "{}.{:03} MHz", system.hz() / 1_000_000, system.hz() / 1000 % 1000);
            row("counter", hz.as_str());
            row("source", crate::arch::counter_source().name_here());
        }
        let _ = UI20_SEMIBOLD.line_height;
    }

    pub fn tick(&mut self, fb: &Framebuffer, _w: i32, _h: i32, _ctx: &Ctx) -> Response {
        if !self.running {
            return Response::default();
        }
        self.paint_readout(fb);
        Response::dirty(self.readout)
    }

    pub fn event(&mut self, ev: Event, fb: &Framebuffer, w: i32, h: i32, ctx: &Ctx) -> Response {
        let act = |s: &mut Stopwatch, id: u16| match id {
            B_START => s.toggle(),
            B_LAP => s.lap(),
            _ => s.reset(),
        };
        match ev {
            Event::Key(KeyInput::Char(' ')) => act(self, B_START),
            Event::Key(KeyInput::Char('l' | 'L') | KeyInput::Enter) => act(self, B_LAP),
            Event::Key(KeyInput::Char('r' | 'R' | 'z' | 'Z')) => act(self, B_RESET),
            Event::PointerDown { x, y } => match self.hits.at(x, y) {
                Some(id) => act(self, id),
                None => return Response::default(),
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
        let _ = (fb, w, h, ctx);
        Response::repaint()
    }
}
