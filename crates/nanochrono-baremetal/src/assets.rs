// SPDX-License-Identifier: Apache-2.0
//! The desktop's embedded pictures: wallpapers and icons.
//!
//! `build.rs` (`desktop_assets`) finds them and writes the tables included
//! below: every wallpaper in `assets/wallpapers/` (and in `NC_WALLPAPERS`,
//! when the build sets it) as QOI, and every icon — the apps' and
//! NanoChronometer's own stopwatch — as raw RGBA in the logo's format. So
//! nothing here reads a filesystem, and the only decoder is QOI's, a single
//! pass over six opcodes (`nanochrono_core::qoi`).
//!
//! A wallpaper is never decoded whole: [`render_cover`] streams it through a
//! two-row window straight into the screen-sized copy the desktop keeps,
//! scaling as it goes, so the source never needs a buffer of its own.

use crate::logo::Image;
use nanochrono_core::qoi;

/// One embedded wallpaper.
pub struct Wallpaper {
    pub name: &'static str,
    pub width: u32,
    pub height: u32,
    pub qoi: &'static [u8],
}

/// One icon at every size it was drawn at, smallest first.
pub struct IconSet {
    pub name: &'static str,
    pub sizes: &'static [Image],
}

include!(concat!(env!("OUT_DIR"), "/desktop_assets.rs"));

/// The icon `name` at the largest embedded size no larger than `size`, or
/// the smallest it has when every size is larger.
pub fn icon(name: &str, size: u32) -> Option<&'static Image> {
    let set = ICONS.iter().find(|s| s.name == name)?;
    set.sizes.iter().rev().find(|i| i.height <= size).or_else(|| set.sizes.first())
}

/// NanoChronometer's own icon, the stopwatch, at `size` (see [`icon`]).
pub fn stopwatch_icon(size: u32) -> Option<&'static Image> {
    icon("nanochronometer", size)
}

/// The widest source row [`render_cover`] streams: build.rs reduces every
/// wallpaper to fit 1920x1200 before it is embedded.
const MAX_SOURCE_W: usize = 1920;
/// The widest destination row the column tables cover: the back buffer's.
const MAX_DEST_W: usize = 1920;

/// Two decoded source rows, and per destination column its left source
/// column and the weight of the one to its right. Static rather than on the
/// stack — 30 KiB — and used by one render at a time, on the one core.
struct Scratch {
    rows: [[u32; MAX_SOURCE_W]; 2],
    xs: [u16; MAX_DEST_W],
    fx: [u8; MAX_DEST_W],
}

static mut SCRATCH: Scratch = Scratch {
    rows: [[0; MAX_SOURCE_W]; 2],
    xs: [0; MAX_DEST_W],
    fx: [0; MAX_DEST_W],
};

/// The size `(sw, sh)` the source is scaled to so it covers `w x h`, and the
/// offset `(ox, oy)` of the visible window into it: the scale that fills the
/// screen in both directions, centred, the overflow cropped — the way every
/// desktop lays a wallpaper by default.
fn cover_geometry(iw: u32, ih: u32, w: u32, h: u32) -> (u64, u64, u64, u64) {
    let (iw, ih, w, h) = (iw as u64, ih as u64, w as u64, h as u64);
    let (sw, sh) = if w * ih >= h * iw { (w, (ih * w).div_ceil(iw)) } else { ((iw * h).div_ceil(ih), h) };
    (sw, sh, (sw - w) / 2, (sh - h) / 2)
}

/// Source coordinate, in 1/256ths, sampled for destination coordinate `d`:
/// the centre of the destination pixel mapped back, minus half a pixel.
fn sample_at(d: u64, offset: u64, source: u64, scaled: u64) -> u64 {
    ((d + offset) * 2 + 1)
        .saturating_mul(source * 256)
        .checked_div(2 * scaled)
        .unwrap_or(0)
        .saturating_sub(128)
}

fn rgb(p: [u8; 4]) -> u32 {
    (p[0] as u32) << 16 | (p[1] as u32) << 8 | p[2] as u32
}

/// Draws `wallpaper` into `dst` — `w x h` pixels, `0x00RRGGBB`, rows `w`
/// apart — scaled to cover it ([`cover_geometry`]) with bilinear filtering.
/// Returns `false`, leaving `dst` alone, when the picture will not decode or
/// the sizes are out of range.
pub fn render_cover(wallpaper: &Wallpaper, dst: &mut [u32], w: u32, h: u32) -> bool {
    let Ok(mut decoder) = qoi::Decoder::new(wallpaper.qoi) else { return false };
    let header = decoder.header();
    let (iw, ih) = (header.width, header.height);
    if w == 0 || h == 0 || iw as usize > MAX_SOURCE_W || w as usize > MAX_DEST_W {
        return false;
    }
    if dst.len() < (w as usize) * (h as usize) {
        return false;
    }
    let (sw, sh, ox, oy) = cover_geometry(iw, ih, w, h);
    // SAFETY: one render at a time on the one core; nothing else touches the
    // scratch rows, and the reference does not outlive this call.
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) };
    for x in 0..w as usize {
        let s = sample_at(x as u64, ox, iw as u64, sw);
        scratch.xs[x] = (s >> 8).min(iw as u64 - 1) as u16;
        scratch.fx[x] = if (s >> 8) + 1 < iw as u64 { (s & 255) as u8 } else { 0 };
    }
    let mut have: i64 = -1;
    for y in 0..h as u64 {
        let s = sample_at(y, oy, ih as u64, sh);
        let y0 = (s >> 8).min(ih as u64 - 1);
        let y1 = (y0 + 1).min(ih as u64 - 1);
        let fy = if y1 > y0 { (s & 255) as u32 } else { 0 };
        while have < y1 as i64 {
            have += 1;
            let row = &mut scratch.rows[(have & 1) as usize];
            for px in row.iter_mut().take(iw as usize) {
                *px = rgb(decoder.next_pixel().unwrap_or([0, 0, 0, 255]));
            }
        }
        let top = &scratch.rows[(y0 & 1) as usize];
        let bottom = &scratch.rows[(y1 & 1) as usize];
        let out = &mut dst[(y as usize) * (w as usize)..][..w as usize];
        for (x, slot) in out.iter_mut().enumerate() {
            let x0 = scratch.xs[x] as usize;
            let fx = scratch.fx[x] as u32;
            let x1 = if fx > 0 { x0 + 1 } else { x0 };
            *slot = bilinear(top[x0], top[x1], bottom[x0], bottom[x1], fx, fy);
        }
    }
    true
}

/// Mixes four `0x00RRGGBB` pixels with 8-bit weights.
#[inline]
fn bilinear(p00: u32, p01: u32, p10: u32, p11: u32, fx: u32, fy: u32) -> u32 {
    if fx == 0 && fy == 0 {
        return p00;
    }
    let mut out = 0;
    for shift in [16u32, 8, 0] {
        let c = |p: u32| (p >> shift) & 0xFF;
        let top = c(p00) * (256 - fx) + c(p01) * fx;
        let bottom = c(p10) * (256 - fx) + c(p11) * fx;
        out |= ((top * (256 - fy) + bottom * fy) >> 16) << shift;
    }
    out
}

/// Draws `wallpaper` reduced to `w x h` into `dst`, by averaging every
/// source pixel into the destination pixel it lands in — the picture as a
/// thumbnail, without the sparkle a bilinear reduction of ten to one gives
/// a sky of stars. Cropped to the same window [`render_cover`] shows.
pub fn render_thumbnail(wallpaper: &Wallpaper, dst: &mut [u32], w: u32, h: u32) -> bool {
    const MAX_THUMB_W: usize = 256;
    let Ok(mut decoder) = qoi::Decoder::new(wallpaper.qoi) else { return false };
    let header = decoder.header();
    let (iw, ih) = (header.width as u64, header.height as u64);
    if w == 0 || h == 0 || w as usize > MAX_THUMB_W || dst.len() < (w as usize) * (h as usize) {
        return false;
    }
    let (sw, sh, ox, oy) = cover_geometry(header.width, header.height, w, h);
    let mut sums = [[0u32; 4]; MAX_THUMB_W];
    let mut row_of_sums: Option<u64> = None;
    let flush = |sums: &mut [[u32; 4]; MAX_THUMB_W], ty: u64, dst: &mut [u32]| {
        for (tx, s) in sums.iter_mut().enumerate().take(w as usize) {
            if s[3] > 0 {
                dst[ty as usize * w as usize + tx] = (s[0] / s[3]) << 16 | (s[1] / s[3]) << 8 | s[2] / s[3];
            }
            *s = [0; 4];
        }
    };
    for sy in 0..ih {
        // Where this source row lands in the scaled picture, then on screen.
        let ty = (sy * sh / ih).checked_sub(oy).filter(|&t| t < h as u64);
        if ty != row_of_sums {
            if let Some(done) = row_of_sums {
                flush(&mut sums, done, dst);
            }
            row_of_sums = ty;
        }
        for sx in 0..iw {
            let p = decoder.next_pixel().unwrap_or([0, 0, 0, 255]);
            let (Some(ty), Some(tx)) = (ty, (sx * sw / iw).checked_sub(ox).filter(|&t| t < w as u64)) else {
                continue;
            };
            let _ = ty;
            let s = &mut sums[tx as usize];
            s[0] += p[0] as u32;
            s[1] += p[1] as u32;
            s[2] += p[2] as u32;
            s[3] += 1;
        }
    }
    if let Some(done) = row_of_sums {
        flush(&mut sums, done, dst);
    }
    true
}
