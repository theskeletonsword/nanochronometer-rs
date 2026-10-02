// SPDX-License-Identifier: Apache-2.0
//! A terminal: a grid of character cells, the ANSI escape sequences the
//! kernel's own output uses, and the renderer that puts it on a framebuffer.
//!
//! Everything the kernel prints already speaks ANSI — the serial console's
//! task manager is drawn with `ESC[2J`, `ESC[1m` and coloured bars — so the
//! shell and its commands write ANSI here too, and the same bytes work on a
//! UART and on the screen. Understood: the C0 controls (`\r \n \t \b`), SGR
//! (bold, dim, underline, inverse; the 16 colours, the 256-colour palette and
//! 24-bit colour, mapped to the palette), cursor movement and positioning,
//! erase in display and line, save and restore, and showing or hiding the
//! cursor. Anything else is consumed and ignored rather than printed.
//!
//! No allocator: the cells live in a slice the owner provides — a static for
//! the full-screen shell, a slot of the desktop's pool for a terminal window.
//! Rendering is incremental: only rows marked dirty are redrawn, and a scroll
//! moves the pixels already drawn instead of redrawing every line.

use crate::fonts::{draw_cell, MonoFace};
use crate::framebuffer::{Colour, Framebuffer};

/// The widest and tallest grid any terminal has: 1920 pixels of the small
/// face's 8-pixel cells, and the rows of a 1200-line screen at 14.
pub const MAX_COLS: usize = 240;
pub const MAX_ROWS: usize = 90;

const FLAG_BOLD: u8 = 1;
const FLAG_DIM: u8 = 2;
const FLAG_UNDERLINE: u8 = 4;
const FLAG_INVERSE: u8 = 8;

/// The default colour: 0 in a cell's `fg` or `bg`. A palette index `n` is
/// stored as `n + 1`, so a blank cell — NUL on the defaults — is all zero
/// bits, and the big cell pools are `.bss`, not megabytes of image.
const DEFAULT: u16 = 0;

/// One character cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    /// NUL draws as a space.
    pub ch: char,
    pub fg: u16,
    pub bg: u16,
    pub flags: u8,
}

impl Cell {
    pub const BLANK: Cell = Cell { ch: '\0', fg: DEFAULT, bg: DEFAULT, flags: 0 };
}

/// A palette index as a cell stores it.
const fn ink(index: u16) -> u16 {
    index + 1
}

/// The colours a terminal is drawn in.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub ansi: [Colour; 16],
    pub foreground: Colour,
    pub background: Colour,
    pub cursor: Colour,
}

impl Theme {
    /// A dark theme in the interface's own colours: NanoChronometer green for
    /// green, cool greys, and a near-black ground.
    pub const DARK: Theme = Theme {
        ansi: [
            0x1C1F24, 0xE5534B, 0x39E84A, 0xE5C07B, 0x61AFEF, 0xC678DD, 0x56B6C2, 0xD5D9E0,
            0x5C6370, 0xFF6B6B, 0x7CF08A, 0xF2D27C, 0x8CC8FF, 0xDDA6F2, 0x84DCE6, 0xFFFFFF,
        ],
        foreground: 0xD8DEE9,
        background: 0x0D0F12,
        cursor: 0x39E84A,
    };

    /// The CLI's: a plain text console. Light grey on black, every colour
    /// the same grey, so even a colour escape that reaches it (a kernel
    /// message) changes nothing; bold is white.
    pub const MONO: Theme = Theme {
        ansi: [
            0x000000, 0xC0C0C0, 0xC0C0C0, 0xC0C0C0, 0xC0C0C0, 0xC0C0C0, 0xC0C0C0, 0xC0C0C0,
            0x808080, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF,
        ],
        foreground: 0xC0C0C0,
        background: 0x000000,
        cursor: 0xC0C0C0,
    };

    /// A cell's colour: `stored` is 0 for the default, else index + 1.
    fn colour(&self, stored: u16, background: bool) -> Colour {
        if stored == DEFAULT {
            return if background { self.background } else { self.foreground };
        }
        let index = stored - 1;
        match index {
            0..=15 => self.ansi[index as usize],
            16..=231 if self.ansi[2] != self.ansi[7] => {
                // The 6x6x6 cube.
                let i = index as u32 - 16;
                let level = |v: u32| if v == 0 { 0 } else { 55 + v * 40 };
                level(i / 36) << 16 | level(i / 6 % 6) << 8 | level(i % 6)
            }
            232..=255 if self.ansi[2] != self.ansi[7] => {
                let v = 8 + (index as u32 - 232) * 10;
                v << 16 | v << 8 | v
            }
            _ => {
                if background {
                    self.background
                } else {
                    self.foreground
                }
            }
        }
    }
}

/// The 256-colour palette entry nearest an RGB colour (the cube, or the
/// grey ramp for greys).
fn nearest_256(r: u8, g: u8, b: u8) -> u16 {
    let to_level = |v: u8| -> u16 {
        if v < 48 {
            0
        } else if v < 115 {
            1
        } else {
            ((v as u16 - 35) / 40).min(5)
        }
    };
    if r.abs_diff(g) < 8 && g.abs_diff(b) < 8 {
        let avg = (r as u16 + g as u16 + b as u16) / 3;
        if avg < 8 {
            return 16;
        }
        if avg > 238 {
            return 231;
        }
        return 232 + ((avg - 8) / 10).min(23);
    }
    16 + 36 * to_level(r) + 6 * to_level(g) + to_level(b)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parse {
    Ground,
    Escape,
    Csi,
    /// An OSC string (`ESC ]`), skipped to its terminator.
    Osc,
}

/// A terminal over cells it was given.
pub struct Term {
    cells: &'static mut [Cell],
    pub cols: usize,
    pub rows: usize,
    pub cx: usize,
    pub cy: usize,
    fg: u16,
    bg: u16,
    flags: u8,
    saved: (usize, usize),
    state: Parse,
    params: [u16; 16],
    nparams: usize,
    private: bool,
    /// A character was written into the last column: the next one wraps
    /// first (the "pending wrap" every VT100 descendant has).
    wrap_pending: bool,
    pub cursor_visible: bool,
    /// Rows to redraw, one bit each.
    dirty: [u64; 2],
    /// Rows scrolled since the last render, for the pixel scroll.
    scrolled: usize,
    /// Where the cursor was last drawn, so moving it repaints that cell.
    drawn_cursor: Option<(usize, usize)>,
    /// Bytes of a UTF-8 sequence arriving byte by byte (a serial line).
    utf8: [u8; 4],
    utf8_len: usize,
}

impl Term {
    /// A terminal of `cols x rows` over `cells`, clamped to what the slice
    /// and [`MAX_COLS`]/[`MAX_ROWS`] hold.
    pub fn new(cells: &'static mut [Cell], cols: usize, rows: usize) -> Term {
        let mut t = Term {
            cells,
            cols: 1,
            rows: 1,
            cx: 0,
            cy: 0,
            fg: DEFAULT,
            bg: DEFAULT,
            flags: 0,
            saved: (0, 0),
            state: Parse::Ground,
            params: [0; 16],
            nparams: 0,
            private: false,
            wrap_pending: false,
            cursor_visible: true,
            dirty: [!0; 2],
            scrolled: 0,
            drawn_cursor: None,
            utf8: [0; 4],
            utf8_len: 0,
        };
        t.resize(cols, rows);
        t
    }

    /// Changes the grid's size, keeping what fits and clearing the rest.
    pub fn resize(&mut self, cols: usize, rows: usize) {
        let cap = self.cells.len();
        let cols = cols.clamp(1, MAX_COLS);
        let rows = rows.clamp(1, MAX_ROWS).min(cap / cols).max(1);
        if cols != self.cols || rows != self.rows {
            // Keep the bottom of the old contents, which is where the prompt
            // is: copy row by row into a fresh layout.
            let (old_cols, old_rows) = (self.cols, self.rows);
            let keep = old_rows.min(rows);
            let first_old = old_rows - keep;
            let mut line = [Cell::BLANK; MAX_COLS];
            for r in 0..keep {
                let src = (first_old + r) * old_cols;
                for (c, slot) in line.iter_mut().enumerate().take(cols) {
                    *slot = if c < old_cols { self.cells[src + c] } else { Cell::BLANK };
                }
                let dst = r * cols;
                self.cells[dst..dst + cols].copy_from_slice(&line[..cols]);
            }
            for cell in self.cells[keep * cols..rows * cols].iter_mut() {
                *cell = Cell::BLANK;
            }
            self.cy = (self.cy + keep).saturating_sub(old_rows).min(rows - 1);
            self.cols = cols;
            self.rows = rows;
        }
        self.cx = self.cx.min(self.cols - 1);
        self.cy = self.cy.min(self.rows - 1);
        self.dirty = [!0; 2];
        self.scrolled = 0;
        self.drawn_cursor = None;
    }

    fn mark(&mut self, row: usize) {
        if row < 128 {
            self.dirty[row / 64] |= 1 << (row % 64);
        }
    }

    fn is_dirty(&self, row: usize) -> bool {
        row < 128 && self.dirty[row / 64] & (1 << (row % 64)) != 0
    }

    /// Redraw everything at the next render.
    pub fn invalidate(&mut self) {
        self.dirty = [!0; 2];
        self.scrolled = 0;
    }

    pub fn cell(&self, col: usize, row: usize) -> Cell {
        self.cells.get(row * self.cols + col).copied().unwrap_or(Cell::BLANK)
    }

    fn put(&mut self, col: usize, row: usize, cell: Cell) {
        if col < self.cols && row < self.rows {
            self.cells[row * self.cols + col] = cell;
            self.mark(row);
        }
    }

    fn blank(&self) -> Cell {
        // Erasing paints the current background, as terminals do.
        Cell { ch: ' ', fg: self.fg, bg: self.bg, flags: 0 }
    }

    /// Clears the screen and homes the cursor.
    pub fn clear(&mut self) {
        let b = Cell::BLANK;
        for c in self.cells[..self.cols * self.rows].iter_mut() {
            *c = b;
        }
        self.cx = 0;
        self.cy = 0;
        self.wrap_pending = false;
        self.invalidate();
    }

    fn scroll_up(&mut self, n: usize) {
        let n = n.min(self.rows);
        let cols = self.cols;
        self.cells.copy_within(n * cols..self.rows * cols, 0);
        let blank = self.blank();
        for c in self.cells[(self.rows - n) * cols..self.rows * cols].iter_mut() {
            *c = blank;
        }
        // The rows that moved are already drawn, one band higher: the render
        // moves the pixels; only the new bottom rows need drawing. A dirty
        // row moves with its content.
        let mut moved = [0u64; 2];
        for r in n..self.rows {
            if self.is_dirty(r) {
                let d = r - n;
                moved[d / 64] |= 1 << (d % 64);
            }
        }
        self.dirty = moved;
        for r in self.rows - n..self.rows {
            self.mark(r);
        }
        self.scrolled = (self.scrolled + n).min(self.rows);
        if let Some((x, y)) = self.drawn_cursor {
            self.drawn_cursor = y.checked_sub(n).map(|y| (x, y));
        }
    }

    fn newline(&mut self) {
        if self.cy + 1 >= self.rows {
            self.scroll_up(1);
        } else {
            self.cy += 1;
        }
    }

    fn print(&mut self, ch: char) {
        if self.wrap_pending {
            self.wrap_pending = false;
            self.cx = 0;
            self.newline();
        }
        let cell = Cell { ch, fg: self.fg, bg: self.bg, flags: self.flags };
        self.put(self.cx, self.cy, cell);
        if self.cx + 1 >= self.cols {
            self.wrap_pending = true;
        } else {
            self.cx += 1;
        }
    }

    /// Feeds one byte (from a byte stream, a serial line): UTF-8 is
    /// assembled here.
    pub fn write_byte(&mut self, byte: u8) {
        if byte < 0x80 {
            self.utf8_len = 0;
            self.feed(byte as char);
            return;
        }
        if byte & 0xC0 != 0x80 {
            self.utf8_len = 0;
        }
        if self.utf8_len < 4 {
            self.utf8[self.utf8_len] = byte;
            self.utf8_len += 1;
        }
        let need = match self.utf8[0] {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => {
                self.utf8_len = 0;
                return;
            }
        };
        if self.utf8_len == need {
            let ch = core::str::from_utf8(&self.utf8[..need]).ok().and_then(|s| s.chars().next());
            self.utf8_len = 0;
            self.feed(ch.unwrap_or('?'));
        }
    }

    /// Feeds one character through the escape-sequence parser.
    pub fn feed(&mut self, ch: char) {
        match self.state {
            Parse::Ground => match ch {
                '\x1b' => self.state = Parse::Escape,
                '\r' => {
                    self.cx = 0;
                    self.wrap_pending = false;
                }
                '\n' => {
                    self.wrap_pending = false;
                    self.newline();
                }
                '\t' => {
                    let next = ((self.cx / 8) + 1) * 8;
                    self.cx = next.min(self.cols - 1);
                }
                '\x08' => {
                    self.wrap_pending = false;
                    self.cx = self.cx.saturating_sub(1);
                }
                '\x07' | '\0' => {}
                c if (c as u32) < 0x20 => {}
                c => self.print(c),
            },
            Parse::Escape => {
                self.state = Parse::Ground;
                match ch {
                    '[' => {
                        self.state = Parse::Csi;
                        self.params = [0; 16];
                        self.nparams = 0;
                        self.private = false;
                    }
                    ']' => self.state = Parse::Osc,
                    '7' => self.saved = (self.cx, self.cy),
                    '8' => (self.cx, self.cy) = self.saved,
                    'c' => {
                        self.fg = DEFAULT;
                        self.bg = DEFAULT;
                        self.flags = 0;
                        self.clear();
                    }
                    _ => {}
                }
            }
            Parse::Osc => {
                // To BEL, or to ST (ESC \), whose backslash lands in Ground.
                if ch == '\x07' || ch == '\x1b' {
                    self.state = Parse::Ground;
                }
            }
            Parse::Csi => match ch {
                '0'..='9' => {
                    if self.nparams == 0 {
                        self.nparams = 1;
                    }
                    let p = &mut self.params[self.nparams - 1];
                    *p = p.saturating_mul(10).saturating_add(ch as u16 - b'0' as u16);
                }
                ';' => {
                    if self.nparams == 0 {
                        self.nparams = 1;
                    }
                    if self.nparams < self.params.len() {
                        self.nparams += 1;
                    }
                }
                '?' | '>' | '=' => self.private = true,
                c if ('\x40'..='\x7e').contains(&c) => {
                    self.state = Parse::Ground;
                    self.csi(c);
                }
                _ => {}
            },
        }
    }

    fn param(&self, i: usize, default: u16) -> u16 {
        if i < self.nparams && self.params[i] != 0 {
            self.params[i]
        } else {
            default
        }
    }

    fn csi(&mut self, final_byte: char) {
        let n = self.param(0, 1) as usize;
        match (final_byte, self.private) {
            ('m', false) => self.sgr(),
            ('H' | 'f', false) => {
                self.cy = (self.param(0, 1) as usize - 1).min(self.rows - 1);
                self.cx = (self.param(1, 1) as usize - 1).min(self.cols - 1);
                self.wrap_pending = false;
            }
            ('A', false) => self.cy = self.cy.saturating_sub(n),
            ('B', false) => self.cy = (self.cy + n).min(self.rows - 1),
            ('C', false) => self.cx = (self.cx + n).min(self.cols - 1),
            ('D', false) => {
                self.cx = self.cx.saturating_sub(n);
                self.wrap_pending = false;
            }
            ('G', false) => self.cx = (n - 1).min(self.cols - 1),
            ('d', false) => self.cy = (n - 1).min(self.rows - 1),
            ('J', false) => {
                let blank = self.blank();
                let (from, to) = match self.param(0, 0) {
                    0 => (self.cy * self.cols + self.cx, self.rows * self.cols),
                    1 => (0, self.cy * self.cols + self.cx + 1),
                    _ => (0, self.rows * self.cols),
                };
                for i in from..to.min(self.cells.len()) {
                    self.cells[i] = blank;
                }
                for r in from / self.cols..to.div_ceil(self.cols).min(self.rows) {
                    self.mark(r);
                }
            }
            ('K', false) => {
                let blank = self.blank();
                let (from, to) = match self.param(0, 0) {
                    0 => (self.cx, self.cols),
                    1 => (0, self.cx + 1),
                    _ => (0, self.cols),
                };
                for c in from..to.min(self.cols) {
                    self.put(c, self.cy, blank);
                }
            }
            ('X', false) => {
                let blank = self.blank();
                for c in self.cx..(self.cx + n).min(self.cols) {
                    self.put(c, self.cy, blank);
                }
            }
            ('P', false) => {
                // Delete n characters: the rest of the line moves left.
                let row = self.cy * self.cols;
                let n = n.min(self.cols - self.cx);
                self.cells.copy_within(row + self.cx + n..row + self.cols, row + self.cx);
                let blank = self.blank();
                for c in self.cols - n..self.cols {
                    self.cells[row + c] = blank;
                }
                self.mark(self.cy);
            }
            ('@', false) => {
                let row = self.cy * self.cols;
                let n = n.min(self.cols - self.cx);
                self.cells.copy_within(row + self.cx..row + self.cols - n, row + self.cx + n);
                let blank = self.blank();
                for c in self.cx..self.cx + n {
                    self.cells[row + c] = blank;
                }
                self.mark(self.cy);
            }
            ('s', false) => self.saved = (self.cx, self.cy),
            ('u', false) => (self.cx, self.cy) = self.saved,
            ('h' | 'l', true) => {
                if self.param(0, 0) == 25 {
                    self.cursor_visible = final_byte == 'h';
                    self.mark(self.cy);
                }
            }
            _ => {}
        }
    }

    fn sgr(&mut self) {
        if self.nparams == 0 {
            self.fg = DEFAULT;
            self.bg = DEFAULT;
            self.flags = 0;
            return;
        }
        let mut i = 0;
        while i < self.nparams {
            let p = self.params[i];
            match p {
                0 => {
                    self.fg = DEFAULT;
                    self.bg = DEFAULT;
                    self.flags = 0;
                }
                1 => self.flags |= FLAG_BOLD,
                2 => self.flags |= FLAG_DIM,
                4 => self.flags |= FLAG_UNDERLINE,
                7 => self.flags |= FLAG_INVERSE,
                22 => self.flags &= !(FLAG_BOLD | FLAG_DIM),
                24 => self.flags &= !FLAG_UNDERLINE,
                27 => self.flags &= !FLAG_INVERSE,
                30..=37 => self.fg = ink(p - 30),
                39 => self.fg = DEFAULT,
                40..=47 => self.bg = ink(p - 40),
                49 => self.bg = DEFAULT,
                90..=97 => self.fg = ink(p - 90 + 8),
                100..=107 => self.bg = ink(p - 100 + 8),
                38 | 48 => {
                    // 38;5;n or 38;2;r;g;b (and 48 for the background).
                    let colour = match self.params.get(i + 1).copied() {
                        Some(5) => {
                            let n = self.params.get(i + 2).copied().unwrap_or(0).min(255);
                            i += 2;
                            n
                        }
                        Some(2) => {
                            let c = |k: usize| self.params.get(i + k).copied().unwrap_or(0).min(255) as u8;
                            let n = nearest_256(c(2), c(3), c(4));
                            i += 4;
                            n
                        }
                        _ => {
                            i += 1;
                            continue;
                        }
                    };
                    if p == 38 {
                        self.fg = ink(colour);
                    } else {
                        self.bg = ink(colour);
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    /// Draws what changed since the last call at `(x, y)` on `fb`.
    /// `focused` draws the cursor as a block; unfocused, as an outline.
    pub fn render(&mut self, fb: &Framebuffer, x: u32, y: u32, face: &MonoFace, theme: &Theme, focused: bool) {
        let (cw, ch) = (face.cell_w, face.cell_h);
        // Move what is already drawn up by the rows scrolled, then draw the
        // rows that came in. Without a back buffer, everything is redrawn.
        if self.scrolled > 0 {
            let s = self.scrolled.min(self.rows) as u32;
            let band = self.rows as u32 - s;
            if band == 0 || !fb.copy_within(x, y + s * ch, self.cols as u32 * cw, band * ch, x, y) {
                self.dirty = [!0; 2];
            }
            self.scrolled = 0;
        }
        // The cell the cursor was drawn over, and the one it is in now.
        let cursor_now = (self.cursor_visible).then_some((self.cx.min(self.cols - 1), self.cy));
        if self.drawn_cursor != cursor_now {
            if let Some((_, r)) = self.drawn_cursor {
                self.mark(r);
            }
            if let Some((_, r)) = cursor_now {
                self.mark(r);
            }
        }
        for row in 0..self.rows {
            if !self.is_dirty(row) {
                continue;
            }
            for col in 0..self.cols {
                let cell = self.cells[row * self.cols + col];
                let mut fg = theme.colour(cell.fg, false);
                let mut bg = theme.colour(cell.bg, true);
                if cell.flags & FLAG_BOLD != 0 && (1..=8).contains(&cell.fg) {
                    fg = theme.ansi[cell.fg as usize - 1 + 8];
                }
                if cell.flags & FLAG_DIM != 0 {
                    fg = crate::draw::mix_colour(bg, fg, 550);
                }
                if cell.flags & FLAG_INVERSE != 0 {
                    core::mem::swap(&mut fg, &mut bg);
                }
                let is_cursor = cursor_now == Some((col, row));
                if is_cursor && focused {
                    bg = theme.cursor;
                    fg = theme.background;
                }
                let (px, py) = (x + col as u32 * cw, y + row as u32 * ch);
                draw_cell(fb, face, px, py, cell.ch, fg, bg, cell.flags & FLAG_UNDERLINE != 0);
                if is_cursor && !focused {
                    fb.outline(px, py, cw, ch, theme.cursor);
                }
            }
        }
        self.dirty = [0; 2];
        self.drawn_cursor = cursor_now;
    }
}

impl core::fmt::Write for Term {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for ch in s.chars() {
            self.feed(ch);
        }
        Ok(())
    }
}
