// SPDX-License-Identifier: Apache-2.0
//! Apps & Drivers: the packages, libraries and drivers on this system.
//!
//! Lists every `.ncplu`, `.ncapp`, `.nsdyn` and `.ncdri` in the file tree —
//! the ISO's, loaded by GRUB as modules, and an initrd's — with what each
//! file type is. A package runs from here: full screen, through the plugin
//! loader, after its launch card shows its signature tier.

use super::{Ctx, Event, Hits, Response};
use crate::desktop::surface::Rect;
use crate::desktop::theme::{self, Style};
use crate::fonts::{UI13, UI15, UI15_SEMIBOLD, UI20_SEMIBOLD};
use crate::framebuffer::Framebuffer;
use crate::text::Text;
use core::fmt::Write;

const MAX: usize = 32;

pub struct Packages {
    paths: [Option<(Text<128>, usize)>; MAX],
    count: usize,
    hits: Hits<40>,
    hover: Option<u16>,
}

const RUN: u16 = 100;

fn kind_of(path: &str) -> (&'static str, &'static str) {
    let lower = |s: &str| {
        let b = path.as_bytes();
        b.len() >= s.len() && b[b.len() - s.len()..].eq_ignore_ascii_case(s.as_bytes())
    };
    if lower(".ncplu") {
        ("package", "apps")
    } else if lower(".ncapp") {
        ("app (one architecture)", "apps")
    } else if lower(".nsdyn") {
        ("shared library", "drivers")
    } else if lower(".ncdri") {
        ("driver", "drivers")
    } else {
        ("file", "about")
    }
}

impl Packages {
    pub fn new() -> Packages {
        let mut p = Packages { paths: [None; MAX], count: 0, hits: Hits::new(), hover: None };
        for suffix in [".ncplu", ".ncapp", ".nsdyn", ".ncdri"] {
            crate::vfs::find_suffix(suffix, |node| {
                if p.count < MAX {
                    p.paths[p.count] = Some((node.path, node.size().unwrap_or(0)));
                    p.count += 1;
                }
            });
        }
        p
    }

    pub fn paint(&mut self, fb: &Framebuffer, w: i32, h: i32, _ctx: &Ctx) {
        theme::fill(fb, Rect::new(0, 0, w, h), theme::WINDOW);
        self.hits.clear();
        UI20_SEMIBOLD.draw(fb, 20, 16, "Apps & Drivers", theme::TEXT, u32::MAX);
        UI13.draw(fb, 20, 46, "Packages (.ncplu), apps (.ncapp), libraries (.nsdyn) and drivers (.ncdri) on this system.", theme::TEXT_DIM, (w - 40) as u32);
        let mut y = 78;
        if self.count == 0 {
            UI15.draw(fb, 20, y, "None yet. GRUB loads them from the ISO as modules; an initrd brings more.", theme::TEXT_FAINT, (w - 40) as u32);
            y += 30;
        }
        for i in 0..self.count {
            let Some((path, size)) = self.paths[i] else { continue };
            let row = Rect::new(16, y, w - 32, 58);
            theme::rounded(fb, row, 10, if self.hover == Some(RUN + i as u16) { theme::CARD_HOVER } else { theme::CARD });
            let (kind, icon) = kind_of(path.as_str());
            theme::icon(fb, icon, 32, row.x + 12, row.y + 13);
            let name = path.as_str().rsplit('/').next().unwrap_or(path.as_str());
            UI15_SEMIBOLD.draw(fb, row.x + 56, row.y + 10, name, theme::TEXT, (row.w - 220) as u32);
            let mut detail = Text::<160>::new();
            let _ = write!(detail, "{kind} · {} · {:.1} KiB", path.as_str(), size as f32 / 1024.0);
            UI13.draw(fb, row.x + 56, row.y + 33, detail.as_str(), theme::TEXT_DIM, (row.w - 220) as u32);
            if kind == "package" {
                let b = Rect::new(row.right() - 110, row.y + 12, 96, 34);
                let runnable = cfg!(target_arch = "x86_64");
                theme::button(fb, b, if runnable { "Run" } else { "x86_64 only" }, if runnable { Style::Accent } else { Style::Normal }, false);
                if runnable {
                    self.hits.add(b, RUN + i as u16);
                }
            }
            y += 66;
            if y > h - 140 {
                break;
            }
        }
        let legend = Rect::new(16, h - 120, w - 32, 104);
        theme::rounded(fb, legend, 10, theme::WINDOW_ALT);
        UI15_SEMIBOLD.draw(fb, legend.x + 14, legend.y + 10, "Trust", theme::TEXT, u32::MAX);
        UI13.draw(fb, legend.x + 14, legend.y + 34, "✓ green: made by the creator (ring 3) · tree root: made by the creator, ring 0", theme::TEXT_DIM, (legend.w - 28) as u32);
        UI13.draw(fb, legend.x + 14, legend.y + 54, "blue ✓: a third party certified by the creator (ring 3, or ring 0 with its ring-0 check)", theme::TEXT_DIM, (legend.w - 28) as u32);
        UI13.draw(fb, legend.x + 14, legend.y + 74, "No badge: community code — ring 3, isolated; ring 0 only with Settings ▸ Security.", theme::TEXT_DIM, (legend.w - 28) as u32);
    }

    pub fn event(&mut self, ev: Event, _w: i32, _h: i32, _ctx: &Ctx) -> Response {
        match ev {
            Event::PointerDown { x, y } => {
                if let Some(id) = self.hits.at(x, y) {
                    if let Some(Some((path, _))) = self.paths.get((id - RUN) as usize) {
                        return Response { run_package: Some(*path), ..Response::default() };
                    }
                }
                Response::default()
            }
            Event::PointerMove { x, y } => {
                let hover = self.hits.at(x, y);
                if hover == self.hover {
                    return Response::default();
                }
                self.hover = hover;
                Response::repaint()
            }
            _ => Response::default(),
        }
    }
}
