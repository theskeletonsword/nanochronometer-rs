// SPDX-License-Identifier: Apache-2.0
//! Files: the session's file tree (`crate::vfs`), browsed.
//!
//! A path bar, the directory's entries, and a preview of the selected file:
//! its text, or its first bytes in hex when it is not text.

use super::{Ctx, Event, Hits, Response};
use crate::desktop::surface::Rect;
use crate::desktop::theme::{self, Style};
use crate::fonts::{UI13, UI15, UI15_SEMIBOLD};
use crate::framebuffer::Framebuffer;
use crate::kbd::KeyInput;
use crate::text::Text;
use core::fmt::Write;

const MAX_ENTRIES: usize = 96;

#[derive(Clone, Copy)]
struct Entry {
    name: Text<64>,
    dir: bool,
    size: Option<usize>,
}

pub struct Files {
    cwd: Text<128>,
    entries: [Option<Entry>; MAX_ENTRIES],
    count: usize,
    selected: Option<usize>,
    scroll: usize,
    hits: Hits<120>,
    hover: Option<u16>,
    last_click: (Option<usize>, u64),
}

const B_UP: u16 = 1;
const ROW: u16 = 1000;

impl Files {
    pub fn new() -> Files {
        let mut cwd = Text::new();
        cwd.str("/");
        let mut f = Files {
            cwd,
            entries: [None; MAX_ENTRIES],
            count: 0,
            selected: None,
            scroll: 0,
            hits: Hits::new(),
            hover: None,
            last_click: (None, 0),
        };
        f.load();
        f
    }

    fn load(&mut self) {
        self.entries = [None; MAX_ENTRIES];
        self.count = 0;
        self.selected = None;
        self.scroll = 0;
        let mut dirs_first: [Option<Entry>; MAX_ENTRIES] = [None; MAX_ENTRIES];
        let mut n = 0;
        crate::vfs::list(self.cwd.as_str(), |name, node| {
            if n < MAX_ENTRIES {
                let mut t = Text::<64>::new();
                t.str(name);
                dirs_first[n] = Some(Entry { name: t, dir: node.is_dir(), size: node.size() });
                n += 1;
            }
        });
        // Directories first, each group in table order.
        for want_dir in [true, false] {
            for e in dirs_first[..n].iter().flatten() {
                if e.dir == want_dir {
                    self.entries[self.count] = Some(*e);
                    self.count += 1;
                }
            }
        }
    }

    fn open(&mut self, i: usize) {
        let Some(e) = self.entries[i] else { return };
        if e.dir {
            self.cwd = crate::vfs::resolve(self.cwd.as_str(), e.name.as_str());
            self.load();
        }
    }

    fn up(&mut self) {
        self.cwd = crate::vfs::resolve(self.cwd.as_str(), "..");
        self.load();
    }

    pub fn paint(&mut self, fb: &Framebuffer, w: i32, h: i32, _ctx: &Ctx) {
        theme::fill(fb, Rect::new(0, 0, w, h), theme::WINDOW);
        self.hits.clear();
        // Path bar.
        let up = Rect::new(12, 10, 36, 32);
        theme::button(fb, up, "↑", Style::Normal, self.hover == Some(B_UP));
        self.hits.add(up, B_UP);
        let bar = Rect::new(56, 10, w - 68, 32);
        theme::rounded(fb, bar, 8, theme::WINDOW_ALT);
        UI15.draw(fb, bar.x + 12, bar.y + 8, self.cwd.as_str(), theme::TEXT, (bar.w - 24) as u32);

        // Entries.
        let list_w = (w * 11 / 20).max(260);
        let line = 30;
        let top = 54;
        let visible = ((h - top - 8) / line).max(1) as usize;
        if let Some(sel) = self.selected {
            if sel < self.scroll {
                self.scroll = sel;
            } else if sel >= self.scroll + visible {
                self.scroll = sel + 1 - visible;
            }
        }
        for (k, i) in (self.scroll..self.count).take(visible).enumerate() {
            let Some(e) = self.entries[i] else { continue };
            let row = Rect::new(8, top + k as i32 * line, list_w - 16, line - 2);
            if self.selected == Some(i) {
                theme::rounded(fb, row, 6, 0x1D4A26);
            } else if self.hover == Some(ROW + i as u16) {
                theme::rounded(fb, row, 6, theme::HOVER);
            }
            let icon = if e.dir {
                "files"
            } else if ends_with(e.name.as_str(), ".ncplu") || ends_with(e.name.as_str(), ".ncdri") {
                "apps"
            } else {
                "about"
            };
            theme::icon(fb, icon, 16, row.x + 8, row.y + 6);
            UI15.draw(fb, row.x + 34, row.y + 6, e.name.as_str(), theme::TEXT, (row.w - 130) as u32);
            let mut size = Text::<24>::new();
            match (e.dir, e.size) {
                (true, _) => {
                    size.str("folder");
                }
                (false, Some(s)) if s >= 1 << 20 => {
                    let _ = write!(size, "{:.1} MiB", s as f32 / 1048576.0);
                }
                (false, Some(s)) if s >= 1024 => {
                    let _ = write!(size, "{:.1} KiB", s as f32 / 1024.0);
                }
                (false, Some(s)) => {
                    let _ = write!(size, "{s} B");
                }
                (false, None) => {
                    size.str("generated");
                }
            }
            UI13.draw_right(fb, row.right() - 8, row.y + 8, size.as_str(), theme::TEXT_FAINT);
            self.hits.add(row, ROW + i as u16);
        }
        if self.count == 0 {
            UI13.draw(fb, 20, top + 8, "This folder is empty.", theme::TEXT_FAINT, u32::MAX);
        }

        // Preview.
        let pv = Rect::new(list_w, top, w - list_w - 12, h - top - 12);
        theme::rounded(fb, pv, 10, theme::WINDOW_ALT);
        let Some(e) = self.selected.and_then(|i| self.entries[i]) else {
            UI13.draw_centred(fb, pv.x, pv.w as u32, pv.y + pv.h / 2, "Select a file to preview it.", theme::TEXT_FAINT);
            return;
        };
        UI15_SEMIBOLD.draw(fb, pv.x + 14, pv.y + 12, e.name.as_str(), theme::TEXT, (pv.w - 28) as u32);
        if e.dir {
            UI13.draw(fb, pv.x + 14, pv.y + 40, "Folder — double-click or Enter opens it.", theme::TEXT_DIM, (pv.w - 28) as u32);
            return;
        }
        let path = crate::vfs::resolve(self.cwd.as_str(), e.name.as_str());
        let Some(node) = crate::vfs::lookup(path.as_str()) else { return };
        let mut buf = Text::<4096>::new();
        crate::vfs::read(&node, &mut buf);
        let text = buf.as_str();
        let binary = text.chars().take(512).filter(|c| *c == '·').count() > 8;
        let mono = &crate::fonts::TERM14;
        let cols = ((pv.w - 28) / mono.cell_w as i32).max(8) as usize;
        let rows = ((pv.h - 52) / mono.cell_h as i32).max(1) as usize;
        let mut y = pv.y + 42;
        if binary {
            if let crate::vfs::Content::Bytes(bytes) = node.content {
                for chunk in bytes.chunks(8).take(rows) {
                    let mut line = Text::<64>::new();
                    for b in chunk {
                        let _ = write!(line, "{b:02x} ");
                    }
                    draw_mono(fb, mono, pv.x + 14, y, line.as_str(), theme::TEXT_DIM, cols);
                    y += mono.cell_h as i32;
                }
            }
            return;
        }
        for line in text.lines().take(rows) {
            draw_mono(fb, mono, pv.x + 14, y, line, theme::TEXT, cols);
            y += mono.cell_h as i32;
        }
    }

    pub fn event(&mut self, ev: Event, _w: i32, _h: i32, ctx: &Ctx) -> Response {
        match ev {
            Event::PointerDown { x, y } => match self.hits.at(x, y) {
                Some(B_UP) => self.up(),
                Some(id) if id >= ROW => {
                    let i = (id - ROW) as usize;
                    let double = self.last_click.0 == Some(i) && ctx.now_ns.wrapping_sub(self.last_click.1) < 450_000_000;
                    self.last_click = (Some(i), ctx.now_ns);
                    self.selected = Some(i);
                    if double {
                        self.open(i);
                    }
                }
                _ => return Response::default(),
            },
            Event::PointerMove { x, y } => {
                let hover = self.hits.at(x, y);
                if hover == self.hover {
                    return Response::default();
                }
                self.hover = hover;
            }
            Event::Wheel { delta, .. } => {
                self.scroll = if delta > 0 { self.scroll.saturating_sub(3) } else { (self.scroll + 3).min(self.count.saturating_sub(1)) };
            }
            Event::Key(KeyInput::Down) => self.selected = Some(self.selected.map_or(0, |s| (s + 1).min(self.count.saturating_sub(1)))),
            Event::Key(KeyInput::Up) => self.selected = Some(self.selected.map_or(0, |s| s.saturating_sub(1))),
            Event::Key(KeyInput::Enter) => {
                if let Some(i) = self.selected {
                    self.open(i);
                }
            }
            Event::Key(KeyInput::Backspace) => self.up(),
            _ => return Response::default(),
        }
        Response::repaint()
    }
}

fn ends_with(name: &str, suffix: &str) -> bool {
    let (n, s) = (name.as_bytes(), suffix.as_bytes());
    n.len() >= s.len() && n[n.len() - s.len()..].eq_ignore_ascii_case(s)
}

/// One line of text in the monospaced face, cut to `cols`.
fn draw_mono(fb: &Framebuffer, face: &crate::fonts::MonoFace, x: i32, y: i32, s: &str, colour: u32, cols: usize) {
    for (i, c) in s.chars().take(cols).enumerate() {
        if c == ' ' {
            continue;
        }
        let px = x + i as i32 * face.cell_w as i32;
        if let Some(cov) = face.glyph(c) {
            fb.draw_coverage(px as u32, y as u32, face.cell_w, face.cell_h, cov, colour, None);
        }
    }
}
