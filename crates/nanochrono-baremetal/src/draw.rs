// SPDX-License-Identifier: Apache-2.0
//! Text and widgets on a raw framebuffer.
//!
//! Everything is a loop over pixels: there is no renderer, no glyph cache and
//! no allocator. The palette matches the desktop GUI's so the two look like
//! the same product, which is as close as they can get — see
//! [`crate::framebuffer`] for why the actual `iced` code cannot run here.

use crate::framebuffer::{Colour, Framebuffer};
use crate::typeface::Face;

/// The colours one screen uses.
///
/// Values taken from `nanochrono-gui`'s `style` module so the freestanding
/// build is recognisably the same application.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub background: Colour,
    pub panel: Colour,
    /// One step darker than the panel, offset by a pixel to read as a shadow.
    pub shadow: Colour,
    pub title: Colour,
    pub text: Colour,
    pub muted: Colour,
    pub accent: Colour,
    /// For the control that ends the session, which should not look like the
    /// one that restarts it.
    pub danger: Colour,
    pub button: Colour,
    pub button_edge: Colour,
    pub divider: Colour,
    /// The header runs between these two.
    pub header_from: Colour,
    pub header_to: Colour,
    /// A control the pointer is over, and one being pressed.
    pub hover: Colour,
    pub active: Colour,
    /// The unfilled part of a meter.
    pub track: Colour,
    /// A second accent, for the readout's halo and for values that are
    /// counting rather than settled.
    pub glow: Colour,
    /// A meter that has gone past what is comfortable.
    pub warn: Colour,
}

impl Palette {
    /// The stop screen: green, and deliberately not the blue every other
    /// system uses for the same situation.
    pub const STOP: Palette = Palette {
        background: 0x000E_2A1E,
        panel: 0x0014_3B2A,
        shadow: 0x000A_1F16,
        title: 0x00E4_FFF1,
        text: 0x00E6_FFF0,
        muted: 0x008F_CFA8,
        accent: 0x004C_E894,
        danger: 0x00FF_9A7A,
        button: 0x001B_5A3F,
        button_edge: 0x004C_E894,
        divider: 0x0022_5C43,
        header_from: 0x0017_4A33,
        header_to: 0x000F_3324,
        hover: 0x0023_6E4E,
        active: 0x002F_8A62,
        track: 0x0012_3225,
        glow: 0x0030_9C68,
        warn: 0x00FF_C36B,
    };

    /// The measurement interface: black, with the logo's two inks for the
    /// lettering — white for what is read, the logo green for labels and
    /// accents. No grey anywhere, so the embedded logo sits on its own
    /// background.
    pub const APP: Palette = Palette {
        background: 0x0000_0000,
        panel: 0x000A_0C0A,
        shadow: 0x0000_0000,
        title: 0x00FF_FFFF,
        text: 0x00F4_F7F4,
        muted: 0x002F_B83C,
        accent: 0x0039_E84A,
        danger: 0x00FF_7A66,
        button: 0x0010_1410,
        button_edge: 0x001F_4A26,
        divider: 0x0014_2A18,
        header_from: 0x0000_0000,
        header_to: 0x0000_0000,
        hover: 0x0016_2E1A,
        active: 0x001F_4A26,
        track: 0x0012_1812,
        glow: 0x0014_5C22,
        warn: 0x00FF_C36B,
    };
}

/// Blends `fg` over `bg` at `alpha`, 0 to 255.
///
/// The whole reason glyph coverage is eight bits: at one bit a diagonal stem
/// is a staircase, and at eight it is a line. Each channel is interpolated
/// separately, which is wrong in a strict colour-space sense and right in the
/// way every framebuffer in existence does it.
#[inline]
pub fn blend(bg: Colour, fg: Colour, alpha: u8) -> Colour {
    if alpha == 0 {
        return bg;
    }
    if alpha == 255 {
        return fg;
    }
    let a = alpha as u32;
    let inv = 255 - a;
    let mix = |shift: u32| {
        let b = (bg >> shift) & 0xFF;
        let f = (fg >> shift) & 0xFF;
        ((f * a + b * inv) / 255) << shift
    };
    mix(16) | mix(8) | mix(0)
}

/// Draws one line of text in `face`, antialiased against what is already
/// there.
///
/// `y` is the *top* of the line, not the baseline: callers lay out in boxes,
/// and asking each one to know the ascent is how a layout ends up with every
/// label a pixel off from its neighbour.
pub fn text(fb: &Framebuffer, face: &Face, x: u32, y: u32, s: &str, colour: Colour) {
    let baseline = y + face.ascent as u32;
    let mut pen = x as i32;

    for ch in s.chars() {
        let g = face.glyph(ascii_fallback(ch));

        for row in 0..g.height as u32 {
            for col in 0..g.width as u32 {
                let alpha = face.coverage[(g.offset + row * g.width as u32 + col) as usize];
                if alpha == 0 {
                    continue;
                }
                let px = pen + g.left as i32 + col as i32;
                let py = baseline as i32 - g.top as i32 + row as i32;
                if px < 0 || py < 0 {
                    continue;
                }
                let (px, py) = (px as u32, py as u32);
                fb.set(px, py, blend(fb.get(px, py), colour, alpha));
            }
        }

        pen += g.advance as i32;
        if pen >= fb.width as i32 {
            return;
        }
    }
}

/// The byte a character is drawn as.
///
/// The faces are ASCII tables, and iterating a `&str` by *byte* would draw one
/// substitute per byte of a multi-byte character — a single em dash coming out
/// as `???`, which is how "none — press L" reached the screen as
/// "none ??? press L". Iterating by character fixes the count; this fixes what
/// the substitute is, transliterating the few typographic characters an
/// interface actually reaches for rather than replacing them all with a
/// question mark.
fn ascii_fallback(ch: char) -> u8 {
    match ch {
        c if c.is_ascii() => c as u8,
        '·' | '—' | '–' | '‑' => b'-',
        '×' => b'x',
        '≈' => b'~',
        '°' => b'o',
        'µ' | 'μ' => b'u',
        '“' | '”' => b'"',
        '‘' | '’' => b'\'',
        '…' => b'.',
        _ => b'?',
    }
}

/// Draws text right-aligned so its last pixel lands on `right`.
pub fn text_right(fb: &Framebuffer, face: &Face, right: u32, y: u32, s: &str, colour: Colour) {
    let w = face.width_of(s);
    text(fb, face, right.saturating_sub(w), y, s, colour);
}

/// Draws text centred in `[x, x + w)`.
pub fn text_centred(fb: &Framebuffer, face: &Face, x: u32, w: u32, y: u32, s: &str, c: Colour) {
    let tw = face.width_of(s);
    text(fb, face, x + w.saturating_sub(tw) / 2, y, s, c);
}

/// Draws a labelled button with rounded corners.
pub fn button(fb: &Framebuffer, x: u32, y: u32, w: u32, h: u32, label: &str, p: &Palette) {
    rounded(fb, x, y, w, h, 8, p.button);
    rounded_outline(fb, x, y, w, h, 8, p.button_edge);

    let face = &crate::typeface::BODY;
    let ty = y + h.saturating_sub(face.line_height as u32) / 2;
    text_centred(fb, face, x, w, ty, label, p.title);
}

/// A filled rectangle with its corners cut back by `r`.
///
/// Square corners are the single thing that most makes an interface look like
/// a debugger. The corner is a quarter circle tested per pixel — slow in
/// principle, and irrelevant for a few hundred pixels drawn once.
pub fn rounded(fb: &Framebuffer, x: u32, y: u32, w: u32, h: u32, r: u32, colour: Colour) {
    let r = r.min(w / 2).min(h / 2);
    for row in 0..h {
        for col in 0..w {
            if !inside_rounded(col, row, w, h, r) {
                continue;
            }
            fb.set(x + col, y + row, colour);
        }
    }
}

/// The same shape as an outline.
pub fn rounded_outline(fb: &Framebuffer, x: u32, y: u32, w: u32, h: u32, r: u32, colour: Colour) {
    let r = r.min(w / 2).min(h / 2);
    for row in 0..h {
        for col in 0..w {
            // On the edge if this pixel is inside and at least one
            // four-neighbour is not.
            if !inside_rounded(col, row, w, h, r) {
                continue;
            }
            let edge = col == 0
                || row == 0
                || col + 1 == w
                || row + 1 == h
                || !inside_rounded(col.wrapping_sub(1), row, w, h, r)
                || !inside_rounded(col + 1, row, w, h, r)
                || !inside_rounded(col, row.wrapping_sub(1), w, h, r)
                || !inside_rounded(col, row + 1, w, h, r);
            if edge {
                fb.set(x + col, y + row, colour);
            }
        }
    }
}

fn inside_rounded(col: u32, row: u32, w: u32, h: u32, r: u32) -> bool {
    if col >= w || row >= h {
        return false;
    }
    if r == 0 {
        return true;
    }
    // Which corner, if any, this pixel is in the square of.
    let (cx, cy) = (
        if col < r {
            Some(r)
        } else if col >= w - r {
            Some(w - r - 1)
        } else {
            None
        },
        if row < r {
            Some(r)
        } else if row >= h - r {
            Some(h - r - 1)
        } else {
            None
        },
    );
    match (cx, cy) {
        (Some(cx), Some(cy)) => {
            let dx = col as i32 - cx as i32;
            let dy = row as i32 - cy as i32;
            dx * dx + dy * dy <= (r * r) as i32
        }
        _ => true,
    }
}

/// A horizontal gradient between two colours.
///
/// Used for the header. A flat panel and a graded one differ by about fifteen
/// lines of code and rather more than that in how finished the result looks.
pub fn gradient(fb: &Framebuffer, x: u32, y: u32, w: u32, h: u32, from: Colour, to: Colour) {
    for col in 0..w {
        let t = if w > 1 {
            (col * 255 / (w - 1)) as u8
        } else {
            0
        };
        let colour = blend(from, to, t);
        fb.fill(x + col, y, 1, h, colour);
    }
}

/// Splits `s` into chunks of at most `columns` characters, at spaces where
/// there are any.
///
/// Returns an iterator rather than a `Vec`: there is no allocator.
pub fn wrap(s: &str, columns: usize) -> impl Iterator<Item = &str> {
    let mut rest = s;
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        if rest.len() <= columns {
            let out = rest;
            rest = "";
            return Some(out);
        }
        // Break at the last space inside the budget; if the word is longer
        // than a line, break it rather than overflow.
        let split = rest[..columns].rfind(' ').map(|i| i + 1).unwrap_or(columns);
        let (line, remainder) = rest.split_at(split);
        rest = remainder;
        Some(line.trim_end())
    })
}

// ---------------------------------------------------------------------------
// Motion
// ---------------------------------------------------------------------------

/// Eases `0..=1` so a movement starts fast and settles.
///
/// Expressed in thousandths rather than floats: this is called several times a
/// frame and the freestanding build has no `libm`, so a cubic in integers is
/// both cheaper and exactly reproducible. `1 - (1 - t)^3`, the curve every
/// desktop environment uses for a control that snaps into place.
pub fn ease_out(t_permille: u32) -> u32 {
    let t = t_permille.min(1000);
    let inv = 1000 - t;
    1000 - (inv * inv / 1000) * inv / 1000
}

/// The same curve, run backwards: slow to leave, fast to arrive.
pub fn ease_in(t_permille: u32) -> u32 {
    let t = t_permille.min(1000);
    t * t / 1000 * t / 1000
}

/// Interpolates between two numbers by a thousandth-scaled fraction.
pub fn mix(from: i32, to: i32, permille: u32) -> i32 {
    from + (to - from) * permille.min(1000) as i32 / 1000
}

/// The same for a colour.
pub fn mix_colour(from: Colour, to: Colour, permille: u32) -> Colour {
    blend(from, to, (permille.min(1000) * 255 / 1000) as u8)
}

/// A value that chases a target instead of jumping to it.
///
/// This is the whole animation system. Every moving thing in the interface —
/// a tab underline sliding, a meter filling, a control lighting up under the
/// pointer — is one of these, stepped once a frame. There is no timeline and
/// no scheduler, because a target that can change mid-flight is exactly what
/// an interface needs and exactly what a timeline handles badly.
#[derive(Debug, Clone, Copy, Default)]
pub struct Tween {
    /// Where the value started when the target last changed.
    from: i32,
    to: i32,
    /// How far along, in thousandths.
    progress: u32,
    /// How much of the remaining distance to cover each frame, in thousandths.
    rate: u32,
}

impl Tween {
    /// A tween already settled on `value`.
    pub const fn at(value: i32) -> Tween {
        Tween {
            from: value,
            to: value,
            progress: 1000,
            rate: 140,
        }
    }

    /// The same, with a different speed. Higher is faster; 1000 is instant.
    pub const fn with_rate(value: i32, rate: u32) -> Tween {
        Tween {
            from: value,
            to: value,
            progress: 1000,
            rate,
        }
    }

    /// Points the tween at a new target, from wherever it currently is.
    pub fn retarget(&mut self, to: i32) {
        if self.to == to {
            return;
        }
        self.from = self.value();
        self.to = to;
        self.progress = 0;
    }

    /// Advances one frame. Returns whether anything moved, which is what
    /// tells the caller whether this region has to be redrawn.
    pub fn step(&mut self) -> bool {
        if self.progress >= 1000 {
            return false;
        }
        self.progress = (self.progress + self.rate).min(1000);
        true
    }

    /// The current value.
    pub fn value(&self) -> i32 {
        mix(self.from, self.to, ease_out(self.progress))
    }

    /// Whether it has arrived.
    pub fn settled(&self) -> bool {
        self.progress >= 1000
    }

    pub fn target(&self) -> i32 {
        self.to
    }
}

// ---------------------------------------------------------------------------
// Widgets
// ---------------------------------------------------------------------------

/// A vertical gradient, for panels and the header.
pub fn gradient_v(fb: &Framebuffer, x: u32, y: u32, w: u32, h: u32, from: Colour, to: Colour) {
    for row in 0..h {
        let t = if h > 1 {
            (row * 255 / (h - 1)) as u8
        } else {
            0
        };
        fb.fill(x, y + row, w, 1, blend(from, to, t));
    }
}

/// A pill-shaped control with a label, as a tab or a mode chip.
///
/// The background is passed in rather than derived from a state enum so the
/// caller can hand in a colour part-way between two — which is what makes a
/// chip light up gradually under the pointer instead of switching.
#[allow(clippy::too_many_arguments)]
pub fn chip(
    fb: &Framebuffer,
    face: &Face,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    label: &str,
    background: Colour,
    foreground: Colour,
) {
    rounded(fb, x, y, w, h, h / 2, background);
    let ty = y + h.saturating_sub(face.line_height as u32) / 2;
    text_centred(fb, face, x, w, ty, label, foreground);
}

/// A segmented bar, filled to `permille` of its width.
///
/// Segments rather than a continuous fill: at the height a status bar can
/// spare, a solid bar an eighth full is three pixels and reads as empty,
/// while one lit segment out of twelve reads as "a little". The desktop GUI's
/// meters are drawn the same way.
#[allow(clippy::too_many_arguments)]
pub fn meter(
    fb: &Framebuffer,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    permille: u32,
    track: Colour,
    fill: Colour,
) {
    const SEGMENTS: u32 = 12;
    let gap = 2;
    if w < SEGMENTS * 2 {
        // Too narrow to segment; a plain bar says the same thing.
        fb.fill(x, y, w, h, track);
        fb.fill(x, y, w * permille.min(1000) / 1000, h, fill);
        return;
    }
    let segment = (w - gap * (SEGMENTS - 1)) / SEGMENTS;
    // Rounded up, so any non-zero reading lights at least one segment: a
    // meter that reads empty while something is using memory is a bug the
    // user has to discover for themselves.
    let lit = (permille.min(1000) * SEGMENTS).div_ceil(1000);
    for i in 0..SEGMENTS {
        let colour = if i < lit { fill } else { track };
        fb.fill(x + i * (segment + gap), y, segment, h, colour);
    }
}

/// Draws text with a soft halo behind it.
///
/// The readout is the one thing on screen that has to read at a glance from
/// across a desk, and a halo is what separates a large number from a large
/// number that looks pasted on. Four offset passes at low alpha, then the
/// glyphs themselves — cheap because it all lands in the back buffer, where a
/// blend is a cached read and write rather than an uncached one.
#[allow(clippy::too_many_arguments)]
pub fn text_glow(
    fb: &Framebuffer,
    face: &Face,
    x: u32,
    y: u32,
    s: &str,
    colour: Colour,
    halo: Colour,
    spread: u32,
) {
    if spread > 0 {
        for (dx, dy) in [(spread, 0), (0, spread), (0, 0), (spread * 2, spread)] {
            let (ox, oy) = (x + dx, y + dy);
            if ox >= spread && oy >= spread {
                text(fb, face, ox - spread, oy - spread, s, halo);
            }
        }
    }
    text(fb, face, x, y, s, colour);
}

/// An underline that can sit anywhere, used for the selected tab.
///
/// Two pixels with a one-pixel dimmer edge above: a bare rectangle reads as a
/// border, and this reads as a highlight.
pub fn underline(fb: &Framebuffer, x: u32, y: u32, w: u32, accent: Colour, dim: Colour) {
    if w == 0 {
        return;
    }
    fb.fill(x, y, w, 1, dim);
    fb.fill(x, y + 1, w, 2, accent);
}

/// Blends a rectangle of what is already drawn towards `towards`.
///
/// This is how a panel fades in. The element is drawn normally and then this
/// runs over it, which is far cheaper than compositing every primitive
/// through an alpha — the whole rectangle is one pass instead of every glyph
/// and every rounded corner carrying an opacity argument.
///
/// `alpha` is how much of the drawn content survives: 255 leaves it alone,
/// 0 replaces it entirely with `towards`.
pub fn fade_region(fb: &Framebuffer, x: u32, y: u32, w: u32, h: u32, towards: Colour, alpha: u8) {
    if alpha == 255 {
        return;
    }
    for row in y..y.saturating_add(h).min(fb.height) {
        for col in x..x.saturating_add(w).min(fb.width) {
            fb.set(col, row, blend(towards, fb.get(col, row), alpha));
        }
    }
}
