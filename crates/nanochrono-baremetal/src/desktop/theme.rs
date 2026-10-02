// SPDX-License-Identifier: Apache-2.0
//! The desktop's colours, sizes, and the widgets apps draw with.
//!
//! A dark theme in the spirit of GNOME's — flat surfaces, soft rounded
//! corners, quiet borders — with NanoChronometer green as the one accent,
//! and the Windows layout the session is modelled on: a taskbar along the
//! bottom, a start menu, icons on the desktop.

use super::surface::Rect;
use crate::draw;
use crate::fonts::UiFace;
use crate::framebuffer::{Colour, Framebuffer};

pub const ACCENT: Colour = 0x39E84A;
pub const ACCENT_DIM: Colour = 0x2A9E38;
pub const ON_ACCENT: Colour = 0x0B0D10;
pub const WINDOW: Colour = 0x22252B;
pub const WINDOW_ALT: Colour = 0x1C1F24;
pub const CARD: Colour = 0x2A2E35;
pub const CARD_HOVER: Colour = 0x333840;
pub const TITLE_FOCUSED: Colour = 0x2C3037;
pub const TITLE_UNFOCUSED: Colour = 0x24272D;
pub const BORDER: Colour = 0x3A3F48;
pub const BORDER_FOCUSED: Colour = 0x4A505B;
pub const TEXT: Colour = 0xE8EAED;
pub const TEXT_DIM: Colour = 0xA3A9B1;
pub const TEXT_FAINT: Colour = 0x6E747D;
pub const HOVER: Colour = 0x3A3F48;
pub const PRESSED: Colour = 0x474D57;
pub const DANGER: Colour = 0xE5534B;
pub const WARNING: Colour = 0xE5C07B;
pub const TASKBAR: Colour = 0x111318;
pub const MENU: Colour = 0x1A1D22;

/// Title bar height, window corner radius, the frame's border.
pub const TITLE_H: i32 = 38;
pub const RADIUS: i32 = 10;
pub const TASKBAR_H: i32 = 52;

pub fn rounded(fb: &Framebuffer, r: Rect, radius: i32, colour: Colour) {
    if r.is_empty() || r.x < 0 || r.y < 0 {
        return;
    }
    let radius = radius.min(r.w / 2).min(r.h / 2).max(0) as u32;
    draw::rounded(fb, r.x as u32, r.y as u32, r.w as u32, r.h as u32, radius, colour);
}

pub fn rounded_outline(fb: &Framebuffer, r: Rect, radius: i32, colour: Colour) {
    if r.is_empty() || r.x < 0 || r.y < 0 {
        return;
    }
    let radius = radius.min(r.w / 2).min(r.h / 2).max(0) as u32;
    draw::rounded_outline(fb, r.x as u32, r.y as u32, r.w as u32, r.h as u32, radius, colour);
}

pub fn fill(fb: &Framebuffer, r: Rect, colour: Colour) {
    if r.is_empty() {
        return;
    }
    let x = r.x.max(0);
    let y = r.y.max(0);
    let w = (r.right() - x).max(0) as u32;
    let h = (r.bottom() - y).max(0) as u32;
    fb.fill(x as u32, y as u32, w, h, colour);
}

/// Text in `face`, top-left at `(x, y)`, clipped to `max_w` with an ellipsis.
pub fn text(fb: &Framebuffer, face: &UiFace, x: i32, y: i32, s: &str, colour: Colour, max_w: u32) -> i32 {
    face.draw(fb, x, y, s, colour, max_w)
}

/// How a button looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Normal,
    Accent,
    Danger,
    Flat,
}

/// A button: a rounded box and a centred label.
pub fn button(fb: &Framebuffer, r: Rect, label: &str, style: Style, hovered: bool) {
    let (bg, fg) = match (style, hovered) {
        (Style::Accent, false) => (ACCENT, ON_ACCENT),
        (Style::Accent, true) => (0x5CF06A, ON_ACCENT),
        (Style::Danger, false) => (0x4A2326, 0xFF8A80),
        (Style::Danger, true) => (DANGER, 0xFFFFFF),
        (Style::Normal, false) => (CARD, TEXT),
        (Style::Normal, true) => (CARD_HOVER, TEXT),
        (Style::Flat, false) => (0, TEXT),
        (Style::Flat, true) => (HOVER, TEXT),
    };
    if !(style == Style::Flat && !hovered) {
        rounded(fb, r, 8, bg);
    }
    let face = &crate::fonts::UI15_SEMIBOLD;
    face.draw_centred(fb, r.x, r.w as u32, r.y + (r.h - face.line_height as i32) / 2 + 1, label, fg);
}

/// A switch, on or off, `44 x 24` at `(x, y)`.
pub fn toggle(fb: &Framebuffer, x: i32, y: i32, on: bool) -> Rect {
    let r = Rect::new(x, y, 44, 24);
    rounded(fb, r, 12, if on { ACCENT } else { 0x4A4F58 });
    let knob = Rect::new(if on { x + 22 } else { x + 2 }, y + 2, 20, 20);
    rounded(fb, knob, 10, if on { 0xFFFFFF } else { 0xD0D3D8 });
    r
}

/// A horizontal meter: `permille` of the width in `colour`.
pub fn meter(fb: &Framebuffer, r: Rect, permille: u32, colour: Colour) {
    rounded(fb, r, r.h / 2, 0x3A3F48);
    let w = (r.w as i64 * permille.min(1000) as i64 / 1000) as i32;
    if w > 0 {
        rounded(fb, Rect::new(r.x, r.y, w.max(r.h), r.h), r.h / 2, colour);
    }
}

/// An embedded icon, alpha-blended, at the size nearest `size`.
pub fn icon(fb: &Framebuffer, name: &str, size: u32, x: i32, y: i32) {
    if x < 0 || y < 0 {
        return;
    }
    let image = if name == "nanochronometer" {
        crate::assets::stopwatch_icon(size)
    } else {
        crate::assets::icon(name, size)
    };
    if let Some(img) = image {
        // Centred in the box when the nearest size is smaller.
        let dx = (size as i32 - img.width as i32).max(0) / 2;
        let dy = (size as i32 - img.height as i32).max(0) / 2;
        crate::logo::draw(fb, img, (x + dx) as u32, (y + dy) as u32);
    }
}

/// A soft drop shadow around `r`, drawn on `fb` within `clip`: rings of
/// darkening, strongest at the window's edge.
pub fn shadow(fb: &Framebuffer, r: Rect, clip: Rect, depth: i32) {
    for ring in 1..=depth {
        let alpha = (70 * (depth - ring + 1) / depth / 2) as u8;
        let outer = Rect::new(r.x - ring, r.y - ring + depth / 3, r.w + 2 * ring, r.h + 2 * ring);
        for edge in [
            Rect::new(outer.x, outer.y, outer.w, 1),
            Rect::new(outer.x, outer.bottom() - 1, outer.w, 1),
            Rect::new(outer.x, outer.y + 1, 1, outer.h - 2),
            Rect::new(outer.right() - 1, outer.y + 1, 1, outer.h - 2),
        ] {
            let Some(e) = edge.intersect(&clip) else { continue };
            for py in e.y.max(0)..e.bottom() {
                for px in e.x.max(0)..e.right() {
                    let under = fb.get(px as u32, py as u32);
                    fb.set(px as u32, py as u32, draw::blend(under, 0x000000, alpha));
                }
            }
        }
    }
}
