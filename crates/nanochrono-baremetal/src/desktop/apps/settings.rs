// SPDX-License-Identifier: Apache-2.0
//! Settings: the wallpaper, the keyboard, security, and the system.

use super::{Ctx, Event, Hits, Response};
use crate::desktop::surface::Rect;
use crate::desktop::theme::{self, Style};
use crate::fonts::{UI13, UI15, UI15_SEMIBOLD, UI20_SEMIBOLD};
use crate::framebuffer::Framebuffer;
use crate::kbd::{KeyInput, Layout};
use crate::text::Text;
use core::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Appearance,
    Keyboard,
    Security,
    System,
}

const PAGES: [(Page, &str, &str); 4] = [
    (Page::Appearance, "Appearance", "images"),
    (Page::Keyboard, "Keyboard", "terminal"),
    (Page::Security, "Security", "hypervisor"),
    (Page::System, "System", "about"),
];

const NAV: u16 = 10;
const THUMB: u16 = 100;
const KBD: u16 = 200;
const T_NCVBS: u16 = 300;
const T_RING0: u16 = 301;
const B_CLI: u16 = 400;
const B_CLASSIC: u16 = 401;
const B_RESTART: u16 = 402;
const B_SHUTDOWN: u16 = 403;

pub struct Settings {
    page: Page,
    hits: Hits<48>,
    hover: Option<u16>,
}

impl Settings {
    pub fn new() -> Settings {
        Settings { page: Page::Appearance, hits: Hits::new(), hover: None }
    }

    pub fn paint(&mut self, fb: &Framebuffer, w: i32, h: i32, _ctx: &Ctx) {
        theme::fill(fb, Rect::new(0, 0, w, h), theme::WINDOW);
        self.hits.clear();
        // The navigation column.
        let nav_w = 200;
        theme::fill(fb, Rect::new(0, 0, nav_w, h), theme::WINDOW_ALT);
        for (i, (page, label, icon)) in PAGES.iter().enumerate() {
            let r = Rect::new(10, 12 + i as i32 * 44, nav_w - 20, 38);
            let id = NAV + i as u16;
            if self.page == *page {
                theme::rounded(fb, r, 8, theme::CARD_HOVER);
            } else if self.hover == Some(id) {
                theme::rounded(fb, r, 8, theme::HOVER);
            }
            theme::icon(fb, icon, 24, r.x + 10, r.y + 7);
            UI15.draw(fb, r.x + 44, r.y + 10, label, theme::TEXT, (r.w - 50) as u32);
            self.hits.add(r, id);
        }
        let body = Rect::new(nav_w + 24, 20, w - nav_w - 48, h - 40);
        match self.page {
            Page::Appearance => self.appearance(fb, body),
            Page::Keyboard => self.keyboard(fb, body),
            Page::Security => self.security(fb, body),
            Page::System => self.system(fb, body),
        }
    }

    fn heading(fb: &Framebuffer, r: Rect, title: &str, sub: &str) -> i32 {
        UI20_SEMIBOLD.draw(fb, r.x, r.y, title, theme::TEXT, r.w as u32);
        UI13.draw(fb, r.x, r.y + 30, sub, theme::TEXT_DIM, r.w as u32);
        r.y + 62
    }

    fn appearance(&mut self, fb: &Framebuffer, r: Rect) {
        let mut y = Self::heading(fb, r, "Wallpaper", "Click a picture to use it.");
        let current = crate::config::wallpaper();
        let (tw, th, gap) = (176, 99, 16);
        let per_row = ((r.w + gap) / (tw + gap)).max(1);
        for (i, thumb) in crate::assets::THUMBNAILS.iter().enumerate() {
            let col = i as i32 % per_row;
            let row = i as i32 / per_row;
            let x = r.x + col * (tw + gap);
            let ty = y + row * (th + 40);
            let frame = Rect::new(x - 3, ty - 3, tw + 6, th + 6);
            if i == current {
                theme::rounded(fb, frame, 10, theme::ACCENT);
            } else if self.hover == Some(THUMB + i as u16) {
                theme::rounded(fb, frame, 10, theme::TEXT_FAINT);
            }
            crate::logo::draw(fb, thumb, x as u32, ty as u32);
            if let Some(wp) = crate::assets::WALLPAPERS.get(i) {
                UI13.draw(fb, x, ty + th + 8, wp.name, if i == current { theme::TEXT } else { theme::TEXT_DIM }, tw as u32);
            }
            self.hits.add(frame, THUMB + i as u16);
        }
        let rows = (crate::assets::THUMBNAILS.len() as i32 + per_row - 1) / per_row;
        y += rows * (th + 40) + 8;
        theme::rounded(fb, Rect::new(r.x, y, r.w, 92), 10, theme::WINDOW_ALT);
        UI15_SEMIBOLD.draw(fb, r.x + 16, y + 12, "Your own pictures", theme::TEXT, r.w as u32);
        UI13.draw(fb, r.x + 16, y + 38, "Build with NC_WALLPAPERS=<folder> (PNG or JPEG): they are embedded", theme::TEXT_DIM, (r.w - 32) as u32);
        UI13.draw(fb, r.x + 16, y + 58, "in the kernel and listed here, without entering the source tree.", theme::TEXT_DIM, (r.w - 32) as u32);
    }

    fn keyboard(&mut self, fb: &Framebuffer, r: Rect) {
        let y = Self::heading(fb, r, "Keyboard layout", "Used by the terminal and every text field; loadkeys sets it too.");
        let current = crate::kbd::default_layout();
        for (i, (layout, label)) in [(Layout::Us, "English (US)"), (Layout::Es, "Español (España)")].iter().enumerate() {
            let row = Rect::new(r.x, y + i as i32 * 52, r.w.min(420), 44);
            let id = KBD + i as u16;
            theme::rounded(fb, row, 8, if self.hover == Some(id) { theme::CARD_HOVER } else { theme::CARD });
            let dot = Rect::new(row.x + 14, row.y + 13, 18, 18);
            theme::rounded(fb, dot, 9, if current == *layout { theme::ACCENT } else { 0x4A4F58 });
            if current == *layout {
                theme::rounded(fb, dot.inset(5), 4, theme::ON_ACCENT);
            }
            UI15.draw(fb, row.x + 46, row.y + 13, label, theme::TEXT, (row.w - 60) as u32);
            self.hits.add(row, id);
        }
    }

    fn security(&mut self, fb: &Framebuffer, r: Rect) {
        let mut y = Self::heading(fb, r, "Security", "The safe side of each switch is the default.");
        let card = |fb: &Framebuffer, y: i32, h: i32| theme::rounded(fb, Rect::new(r.x, y, r.w, h), 10, theme::WINDOW_ALT);

        card(fb, y, 110);
        UI15_SEMIBOLD.draw(fb, r.x + 16, y + 14, "Disable NCVBS", theme::TEXT, (r.w - 100) as u32);
        let t = theme::toggle(fb, r.right() - 60, y + 14, !crate::config::ncvbs_enabled());
        self.hits.add(t.inset(-4), T_NCVBS);
        UI13.draw(fb, r.x + 16, y + 42, "NanoChronometer Virtualization-Based Security keeps the kernel's", theme::TEXT_DIM, (r.w - 32) as u32);
        UI13.draw(fb, r.x + 16, y + 60, "code unwritable and its data unexecutable. On by default; disabling", theme::TEXT_DIM, (r.w - 32) as u32);
        UI13.draw(fb, r.x + 16, y + 78, "it takes effect at the next boot.", theme::TEXT_DIM, (r.w - 32) as u32);
        y += 126;

        card(fb, y, 128);
        UI15_SEMIBOLD.draw(fb, r.x + 16, y + 14, "Enable Ring0 Community Modules and Drivers", theme::TEXT, (r.w - 100) as u32);
        let t = theme::toggle(fb, r.right() - 60, y + 14, crate::config::ring0_community());
        self.hits.add(t.inset(-4), T_RING0);
        let warn = if crate::config::ring0_community() { theme::WARNING } else { theme::TEXT_DIM };
        UI13.draw(fb, r.x + 16, y + 42, "Off: only plugins and drivers signed for ring 0 (the tree root or the", theme::TEXT_DIM, (r.w - 32) as u32);
        UI13.draw(fb, r.x + 16, y + 60, "blue ring-0 check) run in the kernel. On: unsigned and self-signed", warn, (r.w - 32) as u32);
        UI13.draw(fb, r.x + 16, y + 78, "ones do too — full control of the machine for code nobody vouched for.", warn, (r.w - 32) as u32);
        UI13.draw(fb, r.x + 16, y + 100, "Badges: ✓ creator · tree root (creator, ring 0) · blue check: certified third party", theme::TEXT_FAINT, (r.w - 32) as u32);
    }

    fn system(&mut self, fb: &Framebuffer, r: Rect) {
        let mut y = Self::heading(fb, r, "System", "The processor controls the dispatcher chose, and the session.");
        if let Some(report) = crate::cpu_control::report() {
            for d in report.decisions().take(14) {
                let mut place = Text::<24>::new();
                place.str(d.register);
                if d.bit != 0xFF {
                    let _ = write!(place, ".{}", d.bit);
                }
                UI13.draw(fb, r.x, y, place.as_str(), theme::TEXT_FAINT, 90);
                UI13.draw(fb, r.x + 96, y, d.name, theme::TEXT, 110);
                UI13.draw(fb, r.x + 210, y, if d.on { "on" } else { "off" }, if d.on { theme::ACCENT } else { theme::TEXT_FAINT }, 40);
                UI13.draw(fb, r.x + 250, y, d.reason, theme::TEXT_DIM, (r.w - 250).max(0) as u32);
                y += 20;
            }
        }
        y += 16;
        let bw = 170;
        let buttons = [
            (B_CLI, "Switch to the CLI", Style::Normal),
            (B_CLASSIC, "Classic instrument", Style::Normal),
            (B_RESTART, "Restart…", Style::Normal),
            (B_SHUTDOWN, "Shut down…", Style::Danger),
        ];
        for (i, (id, label, style)) in buttons.iter().enumerate() {
            let col = i as i32 % 2;
            let row = i as i32 / 2;
            let b = Rect::new(r.x + col * (bw + 12), y + row * 48, bw, 38);
            theme::button(fb, b, label, *style, self.hover == Some(*id));
            self.hits.add(b, *id);
        }
    }

    pub fn event(&mut self, ev: Event, _w: i32, _h: i32, _ctx: &Ctx) -> Response {
        match ev {
            Event::PointerDown { x, y } => {
                let Some(id) = self.hits.at(x, y) else { return Response::default() };
                match id {
                    _ if (NAV..NAV + PAGES.len() as u16).contains(&id) => self.page = PAGES[(id - NAV) as usize].0,
                    _ if (THUMB..THUMB + 64).contains(&id) => {
                        let n = (id - THUMB) as usize;
                        crate::config::set_wallpaper(n);
                        return Response { repaint: true, wallpaper: Some(n), ..Response::default() };
                    }
                    KBD => crate::kbd::set_default_layout(Layout::Us),
                    _ if id == KBD + 1 => crate::kbd::set_default_layout(Layout::Es),
                    T_NCVBS => crate::config::set_ncvbs_disabled(crate::config::ncvbs_enabled()),
                    T_RING0 => crate::config::set_ring0_community(!crate::config::ring0_community()),
                    B_CLI => return Response { session: Some(crate::boot::Mode::Cli), ..Response::default() },
                    B_CLASSIC => return Response { session: Some(crate::boot::Mode::Classic), ..Response::default() },
                    B_RESTART => return Response { power: Some(nanochrono_core::power_confirm::Action::Restart), ..Response::default() },
                    B_SHUTDOWN => return Response { power: Some(nanochrono_core::power_confirm::Action::Shutdown), ..Response::default() },
                    _ => return Response::default(),
                }
                Response::repaint()
            }
            Event::PointerMove { x, y } => {
                let hover = self.hits.at(x, y);
                if hover == self.hover {
                    return Response::default();
                }
                self.hover = hover;
                Response::repaint()
            }
            Event::Key(KeyInput::Tab) => {
                let i = PAGES.iter().position(|p| p.0 == self.page).unwrap_or(0);
                self.page = PAGES[(i + 1) % PAGES.len()].0;
                Response::repaint()
            }
            _ => Response::default(),
        }
    }
}
