// SPDX-License-Identifier: Apache-2.0
//! Apps & Drivers: the packages, apps, libraries, plugins and drivers on
//! this system.
//!
//! Lists every `.ncpkg`, `.ncapp`, `.ncdyn`, `.ncplu` and `.ncdri` in the
//! file tree — the ISO's, loaded by GRUB as modules, and an initrd's. A
//! package shows what its manifest says (name, version, type, the
//! architectures it carries, the signatures it declares); a package with an
//! app for this machine, or a bare `.ncapp`, runs from here: full screen,
//! through the loader, after its launch card shows its signature tier.

use super::{Ctx, Event, Hits, Response};
use crate::desktop::surface::Rect;
use crate::desktop::theme::{self, Style};
use crate::fonts::{UI13, UI15, UI15_SEMIBOLD, UI20_SEMIBOLD};
use crate::framebuffer::Framebuffer;
use crate::text::Text;
use core::fmt::Write;

const MAX: usize = 32;

#[derive(Clone, Copy)]
struct Row {
    path: Text<128>,
    title: Text<96>,
    detail: Text<192>,
    icon: &'static str,
    runnable: bool,
}

pub struct Packages {
    rows: [Option<Row>; MAX],
    count: usize,
    hits: Hits<40>,
    hover: Option<u16>,
}

const RUN: u16 = 100;

fn ends_with(path: &str, ext: &str) -> bool {
    let b = path.as_bytes();
    b.len() >= ext.len() && b[b.len() - ext.len()..].eq_ignore_ascii_case(ext.as_bytes())
}

/// A row for one file: what it is, and for a package what its manifest says.
fn describe(path: Text<128>, bytes: &[u8]) -> Row {
    use nanochrono_core::ncpkg::{self, meta::Meta};
    let name = path.as_str().rsplit('/').next().unwrap_or(path.as_str());
    let kib = bytes.len() as f32 / 1024.0;
    let mut row = Row { path, title: Text::new(), detail: Text::new(), icon: "about", runnable: false };
    let _ = write!(row.title, "{name}");
    let p = path.as_str();
    let x86_64 = cfg!(target_arch = "x86_64");
    if ends_with(p, ".ncpkg") {
        row.icon = "apps";
        let parsed = ncpkg::Package::parse(bytes).ok().and_then(|pkg| Meta::parse(pkg.meta()).ok().filter(|m| m.check_container(&pkg).is_ok()));
        match parsed {
            Some(m) => {
                row.title.clear();
                let _ = write!(row.title, "{} {}", m.name(), m.version());
                let _ = write!(row.detail, "package · {} ·", m.kind().name());
                for a in m.arches() {
                    let _ = write!(row.detail, " {}", a.name());
                }
                let mut sigs = m.signatures().peekable();
                if sigs.peek().is_none() {
                    let _ = write!(row.detail, " · unsigned");
                } else {
                    let _ = write!(row.detail, " · signed:");
                    for s in sigs {
                        let _ = write!(row.detail, " {}", s.role.name());
                    }
                }
                let _ = write!(row.detail, " · {kib:.1} KiB");
                row.runnable = x86_64 && m.app().is_some() && nanochrono_core::ncplu::Arch::native().is_some_and(|a| m.supports(a));
            }
            None => {
                let _ = write!(row.detail, "package · malformed: `ncpkg verify {p}` says why");
            }
        }
    } else if ends_with(p, ".ncapp") {
        row.icon = "apps";
        let _ = write!(row.detail, "app (one architecture) · {p} · {kib:.1} KiB");
        row.runnable = x86_64;
    } else {
        let kind = if ends_with(p, ".ncdyn") {
            "shared library"
        } else if ends_with(p, ".ncplu") {
            "plugin (loaded by its app)"
        } else {
            "driver"
        };
        row.icon = "drivers";
        let _ = write!(row.detail, "{kind} · {p} · {kib:.1} KiB");
    }
    row
}

impl Packages {
    pub fn new() -> Packages {
        let mut p = Packages { rows: [None; MAX], count: 0, hits: Hits::new(), hover: None };
        for suffix in [".ncpkg", ".ncapp", ".ncdyn", ".ncplu", ".ncdri"] {
            crate::vfs::find_suffix(suffix, |node| {
                if p.count < MAX {
                    if let crate::vfs::Content::Bytes(bytes) = node.content {
                        p.rows[p.count] = Some(describe(node.path, bytes));
                        p.count += 1;
                    }
                }
            });
        }
        p
    }

    pub fn paint(&mut self, fb: &Framebuffer, w: i32, h: i32, _ctx: &Ctx) {
        theme::fill(fb, Rect::new(0, 0, w, h), theme::WINDOW);
        self.hits.clear();
        UI20_SEMIBOLD.draw(fb, 20, 16, "Apps & Drivers", theme::TEXT, u32::MAX);
        UI13.draw(fb, 20, 46, "Packages (.ncpkg), apps (.ncapp), libraries (.ncdyn), plugins (.ncplu) and drivers (.ncdri).", theme::TEXT_DIM, (w - 40) as u32);
        let mut y = 78;
        if self.count == 0 {
            UI15.draw(fb, 20, y, "None yet. GRUB loads them from the ISO as modules; an initrd brings more.", theme::TEXT_FAINT, (w - 40) as u32);
            y += 30;
        }
        for i in 0..self.count {
            let Some(r) = self.rows[i] else { continue };
            let row = Rect::new(16, y, w - 32, 58);
            theme::rounded(fb, row, 10, if self.hover == Some(RUN + i as u16) { theme::CARD_HOVER } else { theme::CARD });
            theme::icon(fb, r.icon, 32, row.x + 12, row.y + 13);
            UI15_SEMIBOLD.draw(fb, row.x + 56, row.y + 10, r.title.as_str(), theme::TEXT, (row.w - 220) as u32);
            UI13.draw(fb, row.x + 56, row.y + 33, r.detail.as_str(), theme::TEXT_DIM, (row.w - 220) as u32);
            if ends_with(r.path.as_str(), ".ncpkg") || ends_with(r.path.as_str(), ".ncapp") {
                let b = Rect::new(row.right() - 110, row.y + 12, 96, 34);
                let label = if r.runnable { "Run" } else if cfg!(target_arch = "x86_64") { "Not here" } else { "x86_64 only" };
                theme::button(fb, b, label, if r.runnable { Style::Accent } else { Style::Normal }, false);
                if r.runnable {
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
        UI13.draw(fb, legend.x + 14, legend.y + 74, "No badge: community code, ring 3; ring 0 only with Settings ▸ Security. A ring-3 signature never grants ring 0.", theme::TEXT_DIM, (legend.w - 28) as u32);
    }

    pub fn event(&mut self, ev: Event, _w: i32, _h: i32, _ctx: &Ctx) -> Response {
        match ev {
            Event::PointerDown { x, y } => {
                if let Some(id) = self.hits.at(x, y) {
                    if let Some(Some(r)) = self.rows.get((id - RUN) as usize) {
                        return Response { run_package: Some(r.path), ..Response::default() };
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
