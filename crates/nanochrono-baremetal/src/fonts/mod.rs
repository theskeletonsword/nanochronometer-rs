// SPDX-License-Identifier: Apache-2.0
//! "NC Terminal", the monospaced face the shell and the desktop's terminal
//! draw with: Source Code Pro Medium (Adobe, SIL Open Font License 1.1 — see
//! `assets/font/OFL-SourceCodePro.txt`) rasterised into fixed cells on the
//! host by `tools/rasterise-mono.py`. The OFL lets the glyphs ship inside
//! software of any licence; a derivative may not use the Reserved Font Name
//! "Source", hence the name here.
//!
//! Box-drawing and block characters are not in the tables: [`draw_cell`]
//! draws them to fill the cell exactly, so a frame's lines join and a meter's
//! eighth-blocks stack with no gap — which a glyph from an outline font,
//! sized for its own line height, does not guarantee.

use crate::framebuffer::{Colour, Framebuffer};

/// One rasterised size: `count` cells of `cell_w x cell_h` 8-bit coverage,
/// with the code point each covers.
pub struct MonoFace {
    pub cell_w: u32,
    pub cell_h: u32,
    pub baseline: u32,
    count: usize,
    codes: &'static [u8],
    coverage: &'static [u8],
}

impl MonoFace {
    /// Parses a table `rasterise-mono.py` wrote. `const`, so a malformed one
    /// fails the build, not the boot.
    pub const fn parse(bytes: &'static [u8]) -> MonoFace {
        assert!(bytes.len() >= 12, "terminal face: no header");
        assert!(bytes[0] == b'N' && bytes[1] == b'C' && bytes[2] == b'T' && bytes[3] == b'F', "terminal face: magic");
        let cell_w = bytes[4] as u32;
        let cell_h = bytes[5] as u32;
        let baseline = bytes[6] as u32;
        let count = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
        let (_, rest) = bytes.split_at(12);
        assert!(rest.len() >= count * 4, "terminal face: code table");
        let (codes, coverage) = rest.split_at(count * 4);
        assert!(coverage.len() == count * (cell_w * cell_h) as usize, "terminal face: coverage size");
        MonoFace { cell_w, cell_h, baseline, count, codes, coverage }
    }

    fn code(&self, i: usize) -> u32 {
        let b = &self.codes[i * 4..i * 4 + 4];
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// The coverage cell for `c`, if the face has it.
    pub fn glyph(&self, c: char) -> Option<&'static [u8]> {
        let want = c as u32;
        let (mut lo, mut hi) = (0usize, self.count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.code(mid).cmp(&want) {
                core::cmp::Ordering::Equal => {
                    let size = (self.cell_w * self.cell_h) as usize;
                    return self.coverage.get(mid * size..(mid + 1) * size);
                }
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }
}

pub static TERM14: MonoFace = MonoFace::parse(include_bytes!("term14.bin"));
pub static TERM18: MonoFace = MonoFace::parse(include_bytes!("term18.bin"));

/// The larger face when the screen has room for `min_cols x min_rows` cells
/// of it, the smaller otherwise.
pub fn face_for(width: u32, height: u32, min_cols: u32, min_rows: u32) -> &'static MonoFace {
    if width / TERM18.cell_w >= min_cols && height / TERM18.cell_h >= min_rows {
        &TERM18
    } else {
        &TERM14
    }
}

/// Draws `c` in the cell whose top-left corner is `(x, y)`: the background,
/// then the glyph — from the face, or drawn here for box-drawing and block
/// characters — then an underline if asked. A character the face lacks is
/// drawn as a hollow box, so it is seen to be missing rather than skipped.
#[allow(clippy::too_many_arguments)]
pub fn draw_cell(fb: &Framebuffer, face: &MonoFace, x: u32, y: u32, c: char, fg: Colour, bg: Colour, underline: bool) {
    let (w, h) = (face.cell_w, face.cell_h);
    if c == ' ' || c == '\0' {
        fb.fill(x, y, w, h, bg);
    } else if !draw_shape(fb, x, y, w, h, c, fg, bg) {
        match face.glyph(c) {
            Some(cov) => fb.draw_coverage(x, y, w, h, cov, fg, Some(bg)),
            None => {
                fb.fill(x, y, w, h, bg);
                fb.outline(x + 1, y + h / 4, w.saturating_sub(2), h / 2, fg);
            }
        }
    }
    if underline {
        fb.fill(x, y + face.baseline + 1, w, 1, fg);
    }
}

/// The arms of a box-drawing character: up, down, left, right, each 0
/// (none), 1 (light), 2 (heavy) or 3 (double).
fn box_arms(c: char) -> Option<[u8; 4]> {
    Some(match c {
        '─' => [0, 0, 1, 1],
        '━' => [0, 0, 2, 2],
        '│' => [1, 1, 0, 0],
        '┃' => [2, 2, 0, 0],
        '┌' | '╭' => [0, 1, 0, 1],
        '┐' | '╮' => [0, 1, 1, 0],
        '└' | '╰' => [1, 0, 0, 1],
        '┘' | '╯' => [1, 0, 1, 0],
        '├' => [1, 1, 0, 1],
        '┤' => [1, 1, 1, 0],
        '┬' => [0, 1, 1, 1],
        '┴' => [1, 0, 1, 1],
        '┼' => [1, 1, 1, 1],
        '┏' => [0, 2, 0, 2],
        '┓' => [0, 2, 2, 0],
        '┗' => [2, 0, 0, 2],
        '┛' => [2, 0, 2, 0],
        '═' => [0, 0, 3, 3],
        '║' => [3, 3, 0, 0],
        '╔' => [0, 3, 0, 3],
        '╗' => [0, 3, 3, 0],
        '╚' => [3, 0, 0, 3],
        '╝' => [3, 0, 3, 0],
        '╠' => [3, 3, 0, 3],
        '╣' => [3, 3, 3, 0],
        '╦' => [0, 3, 3, 3],
        '╩' => [3, 0, 3, 3],
        '╬' => [3, 3, 3, 3],
        _ => return None,
    })
}

/// Box drawing and block elements, drawn to the cell. Returns whether `c`
/// was one of them.
#[allow(clippy::too_many_arguments)]
fn draw_shape(fb: &Framebuffer, x: u32, y: u32, w: u32, h: u32, c: char, fg: Colour, bg: Colour) -> bool {
    let code = c as u32;
    // Block elements, U+2580..U+259F.
    if (0x2580..=0x259F).contains(&code) {
        fb.fill(x, y, w, h, bg);
        match code {
            0x2580 => fb.fill(x, y, w, h / 2, fg),                       // ▀
            0x2581..=0x2588 => {
                // ▁..█: the lower n eighths.
                let n = code - 0x2580;
                let bar = h * n / 8;
                fb.fill(x, y + h - bar, w, bar, fg);
            }
            0x2589..=0x258F => {
                // ▉..▏: the left n eighths, n = 7 down to 1.
                let n = 0x2590 - code;
                fb.fill(x, y, (w * n / 8).max(1), h, fg);
            }
            0x2590 => fb.fill(x + w / 2, y, w - w / 2, h, fg),            // ▐
            0x2591..=0x2593 => {
                // ░ ▒ ▓: a quarter, half, three quarters of the ink.
                let alpha = ((code - 0x2590) * 64) as u8;
                fb.fill(x, y, w, h, crate::draw::blend(bg, fg, alpha));
            }
            0x2594 => fb.fill(x, y, w, (h / 8).max(1), fg),               // ▔
            0x2595 => fb.fill(x + w - (w / 8).max(1), y, (w / 8).max(1), h, fg), // ▕
            _ => {
                // The quadrants: whole cell, dimmed, as an approximation.
                fb.fill(x, y, w, h, crate::draw::blend(bg, fg, 160));
            }
        }
        return true;
    }
    let Some([up, down, left, right]) = box_arms(c) else { return false };
    fb.fill(x, y, w, h, bg);
    let (cx, cy) = (x + w / 2, y + h / 2);
    let thick = |kind: u8| if kind == 2 { 3 } else { 1 };
    let vertical = |from: u32, to: u32, kind: u8| {
        if kind == 3 {
            fb.fill(cx.saturating_sub(2), from, 1, to - from, fg);
            fb.fill(cx + 1, from, 1, to - from, fg);
        } else if kind != 0 {
            let t = thick(kind);
            fb.fill(cx.saturating_sub(t / 2), from, t, to - from, fg);
        }
    };
    let horizontal = |from: u32, to: u32, kind: u8| {
        if kind == 3 {
            fb.fill(from, cy.saturating_sub(2), to - from, 1, fg);
            fb.fill(from, cy + 1, to - from, 1, fg);
        } else if kind != 0 {
            let t = thick(kind);
            fb.fill(from, cy.saturating_sub(t / 2), to - from, t, fg);
        }
    };
    // Each arm runs from the cell's edge past the centre, so arms meet.
    vertical(y, cy + 2, up);
    vertical(cy.saturating_sub(1), y + h, down);
    horizontal(x, cx + 2, left);
    horizontal(cx.saturating_sub(1), x + w, right);
    true
}

// ---------------------------------------------------------------------------
// "NC UI": the desktop's proportional interface face
// ---------------------------------------------------------------------------
//
// Adwaita Sans (GNOME's interface face, derived from Inter; SIL Open Font
// License 1.1 — `assets/font/OFL-AdwaitaSans.txt`), rasterised by
// `tools/rasterise-ui.py`. The instrument keeps Nanoplex, the brand's pixel
// face; the desktop's windows and menus read in this.

/// One rasterised size and weight of the interface face.
pub struct UiFace {
    pub px: u32,
    pub ascent: u32,
    pub line_height: u32,
    count: usize,
    table: &'static [u8],
    coverage: &'static [u8],
}

/// One glyph's box and advance.
#[derive(Debug, Clone, Copy)]
pub struct UiGlyph {
    pub w: u32,
    pub h: u32,
    pub left: i32,
    pub top: i32,
    pub advance: u32,
    offset: usize,
}

impl UiFace {
    pub const fn parse(bytes: &'static [u8]) -> UiFace {
        assert!(bytes.len() >= 12, "ui face: no header");
        assert!(bytes[0] == b'N' && bytes[1] == b'C' && bytes[2] == b'U' && bytes[3] == b'F', "ui face: magic");
        let count = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
        let (_, rest) = bytes.split_at(12);
        assert!(rest.len() >= count * 16, "ui face: table");
        let (table, coverage) = rest.split_at(count * 16);
        UiFace { px: bytes[5] as u32, ascent: bytes[6] as u32, line_height: bytes[7] as u32, count, table, coverage }
    }

    fn entry(&self, i: usize) -> (u32, UiGlyph) {
        let e = &self.table[i * 16..i * 16 + 16];
        let cp = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let offset = u32::from_le_bytes([e[4], e[5], e[6], e[7]]) as usize;
        (cp, UiGlyph { w: e[8] as u32, h: e[9] as u32, left: e[10] as i8 as i32, top: e[11] as i8 as i32, advance: e[12] as u32, offset })
    }

    /// The glyph for `c`, or `None` if the face lacks it.
    pub fn glyph(&self, c: char) -> Option<UiGlyph> {
        let want = c as u32;
        let (mut lo, mut hi) = (0usize, self.count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (cp, g) = self.entry(mid);
            match cp.cmp(&want) {
                core::cmp::Ordering::Equal => return Some(g),
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    fn glyph_or_fallback(&self, c: char) -> Option<UiGlyph> {
        self.glyph(c).or_else(|| self.glyph('?'))
    }

    /// The width of `s`, by advance.
    pub fn width_of(&self, s: &str) -> u32 {
        s.chars().map(|c| self.glyph_or_fallback(c).map_or(0, |g| g.advance)).sum()
    }

    /// Draws `s` with its top-left at `(x, y)` (the line box's top), blended
    /// over what is there, clipped to `max_w` pixels of width (`u32::MAX`:
    /// no limit) with an ellipsis when it would overflow. Returns the pen's
    /// end.
    pub fn draw(&self, fb: &Framebuffer, x: i32, y: i32, s: &str, colour: Colour, max_w: u32) -> i32 {
        let ellipsis_w = self.width_of("…");
        let fits = self.width_of(s) <= max_w;
        let mut pen = x;
        for c in s.chars() {
            let Some(g) = self.glyph_or_fallback(c) else { continue };
            if !fits && (pen - x) as u32 + g.advance + ellipsis_w > max_w {
                if let Some(e) = self.glyph('…') {
                    self.blit(fb, pen, y, e, colour);
                    pen += e.advance as i32;
                }
                break;
            }
            self.blit(fb, pen, y, g, colour);
            pen += g.advance as i32;
        }
        pen
    }

    fn blit(&self, fb: &Framebuffer, pen: i32, y: i32, g: UiGlyph, colour: Colour) {
        if g.w == 0 || g.h == 0 {
            return;
        }
        let gx = pen + g.left;
        let gy = y + self.ascent as i32 - g.top;
        if gx < 0 || gy < 0 {
            return;
        }
        let Some(cov) = self.coverage.get(g.offset..g.offset + (g.w * g.h) as usize) else { return };
        fb.draw_coverage(gx as u32, gy as u32, g.w, g.h, cov, colour, None);
    }

    /// Draws `s` centred in `[x, x + w)`.
    pub fn draw_centred(&self, fb: &Framebuffer, x: i32, w: u32, y: i32, s: &str, colour: Colour) {
        let tw = self.width_of(s).min(w);
        self.draw(fb, x + (w - tw) as i32 / 2, y, s, colour, w);
    }

    /// Draws `s` ending at `right`.
    pub fn draw_right(&self, fb: &Framebuffer, right: i32, y: i32, s: &str, colour: Colour) {
        self.draw(fb, right - self.width_of(s) as i32, y, s, colour, u32::MAX);
    }
}

pub static UI13: UiFace = UiFace::parse(include_bytes!("ui13regular.bin"));
pub static UI15: UiFace = UiFace::parse(include_bytes!("ui15regular.bin"));
pub static UI15_SEMIBOLD: UiFace = UiFace::parse(include_bytes!("ui15semibold.bin"));
pub static UI20_SEMIBOLD: UiFace = UiFace::parse(include_bytes!("ui20semibold.bin"));
pub static UI28_LIGHT: UiFace = UiFace::parse(include_bytes!("ui28light.bin"));
/// Digits and separators only, tabular: the stopwatch's readout.
pub static UI56_DIGITS: UiFace = UiFace::parse(include_bytes!("ui56light.bin"));
