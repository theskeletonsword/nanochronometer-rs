// SPDX-License-Identifier: Apache-2.0
//! QOI ("Quite OK Image"): the format the freestanding kernel embeds its
//! wallpapers in, decoded a pixel at a time.
//!
//! # Why QOI and not PNG
//!
//! The logo and icons are embedded as raw RGBA, decoded on the host, so the
//! kernel carries no image decoder at all. A screen-sized picture is too big
//! for that — 1920x1080 is eight megabytes of RGBA — and PNG's answer is
//! DEFLATE, an inflate implementation in ring 0: a lot of code and attack
//! surface for a picture. QOI compresses the smooth artwork wallpapers are
//! made of to a tenth of that with six opcodes and a 64-entry table, and
//! decodes in one pass with no allocation and no back-references into the
//! output — so the kernel can stream it through a two-row window and scale
//! it to the screen without ever holding the whole source.
//!
//! The decoder is written for untrusted input all the same (a user can embed
//! any picture): every read is checked, the pixel count is bounded by the
//! header, and a malformed stream ends the image early rather than reading
//! past it. It never panics.
//!
//! The encoder is for the build script (`std` only); the two are tested
//! against each other here.
//!
//! Format: <https://qoiformat.org/qoi-specification.pdf>, implemented from
//! the specification.

/// `qoif`, then width and height as big-endian `u32`, channels, colour space.
pub const MAGIC: [u8; 4] = *b"qoif";
pub const HEADER_LEN: usize = 14;
/// Seven zero bytes and a one.
pub const END_MARKER: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];
/// The largest image this decodes: past it the header is refused, whatever
/// the file says, so no caller's buffer arithmetic can overflow.
pub const MAX_PIXELS: u64 = 64 * 1024 * 1024;

const OP_INDEX: u8 = 0x00;
const OP_DIFF: u8 = 0x40;
const OP_LUMA: u8 = 0x80;
const OP_RUN: u8 = 0xC0;
const OP_RGB: u8 = 0xFE;
const OP_RGBA: u8 = 0xFF;
const MASK_2: u8 = 0xC0;

/// Why a picture was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Shorter than a header, or not `qoif`.
    NotQoi,
    /// Zero-sized, larger than [`MAX_PIXELS`], or an unknown channel count.
    BadHeader,
}

/// The header's fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub width: u32,
    pub height: u32,
    /// 3 (RGB) or 4 (RGBA). Informational: every pixel decodes to RGBA.
    pub channels: u8,
    /// 0: sRGB with linear alpha, 1: all linear. Informational.
    pub colorspace: u8,
}

impl Header {
    pub fn pixels(&self) -> u64 {
        self.width as u64 * self.height as u64
    }
}

/// Reads and checks the header.
pub fn header(data: &[u8]) -> Result<Header, Error> {
    let h = data.get(..HEADER_LEN).ok_or(Error::NotQoi)?;
    if h[..4] != MAGIC {
        return Err(Error::NotQoi);
    }
    let width = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
    let height = u32::from_be_bytes([h[8], h[9], h[10], h[11]]);
    let header = Header { width, height, channels: h[12], colorspace: h[13] };
    if width == 0 || height == 0 || header.pixels() > MAX_PIXELS || !(3..=4).contains(&h[12]) {
        return Err(Error::BadHeader);
    }
    Ok(header)
}

#[inline]
fn hash(p: [u8; 4]) -> usize {
    (p[0] as usize * 3 + p[1] as usize * 5 + p[2] as usize * 7 + p[3] as usize * 11) % 64
}

/// A pixel-at-a-time decoder over a borrowed QOI stream.
///
/// `next` hands out exactly `width * height` pixels, row by row, as
/// `[r, g, b, a]`. A stream that ends early — truncated or malformed — keeps
/// repeating its last pixel rather than stopping, so a consumer that reads
/// whole rows always gets whole rows; [`Decoder::damaged`] says whether that
/// happened.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    /// The end of the opcode stream: the end marker's start, or the data's
    /// end when the marker is missing.
    end: usize,
    header: Header,
    index: [[u8; 4]; 64],
    previous: [u8; 4],
    run: u32,
    remaining: u64,
    damaged: bool,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Result<Decoder<'a>, Error> {
        let header = header(data)?;
        let end = if data.len() >= HEADER_LEN + END_MARKER.len() && data[data.len() - 8..] == END_MARKER {
            data.len() - 8
        } else {
            data.len()
        };
        Ok(Decoder {
            data,
            pos: HEADER_LEN,
            end,
            header,
            index: [[0; 4]; 64],
            previous: [0, 0, 0, 255],
            run: 0,
            remaining: header.pixels(),
            damaged: false,
        })
    }

    pub fn header(&self) -> Header {
        self.header
    }

    /// Whether the stream ran out before the image did.
    pub fn damaged(&self) -> bool {
        self.damaged
    }

    fn byte(&mut self) -> Option<u8> {
        if self.pos < self.end {
            let b = self.data[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    /// The next pixel, or `None` once all of them have been handed out.
    pub fn next_pixel(&mut self) -> Option<[u8; 4]> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        if self.run > 0 {
            self.run -= 1;
            return Some(self.previous);
        }
        let Some(op) = self.byte() else {
            self.damaged = true;
            return Some(self.previous);
        };
        let mut p = self.previous;
        let ok = match op {
            OP_RGB => match (self.byte(), self.byte(), self.byte()) {
                (Some(r), Some(g), Some(b)) => {
                    p[0] = r;
                    p[1] = g;
                    p[2] = b;
                    true
                }
                _ => false,
            },
            OP_RGBA => match (self.byte(), self.byte(), self.byte(), self.byte()) {
                (Some(r), Some(g), Some(b), Some(a)) => {
                    p = [r, g, b, a];
                    true
                }
                _ => false,
            },
            _ => match op & MASK_2 {
                OP_INDEX => {
                    p = self.index[(op & 0x3F) as usize];
                    true
                }
                OP_DIFF => {
                    p[0] = p[0].wrapping_add(((op >> 4) & 3).wrapping_sub(2));
                    p[1] = p[1].wrapping_add(((op >> 2) & 3).wrapping_sub(2));
                    p[2] = p[2].wrapping_add((op & 3).wrapping_sub(2));
                    true
                }
                OP_LUMA => match self.byte() {
                    Some(b) => {
                        let dg = (op & 0x3F).wrapping_sub(32);
                        let dr_dg = (b >> 4).wrapping_sub(8);
                        let db_dg = (b & 0x0F).wrapping_sub(8);
                        p[0] = p[0].wrapping_add(dg.wrapping_add(dr_dg));
                        p[1] = p[1].wrapping_add(dg);
                        p[2] = p[2].wrapping_add(dg.wrapping_add(db_dg));
                        true
                    }
                    None => false,
                },
                // OP_RUN: this pixel and `run` more like it. (0xFE and 0xFF,
                // which share the tag, were matched above.)
                _ => {
                    debug_assert_eq!(op & MASK_2, OP_RUN);
                    self.run = (op & 0x3F) as u32;
                    true
                }
            },
        };
        if !ok {
            self.damaged = true;
            self.pos = self.end;
            return Some(self.previous);
        }
        self.index[hash(p)] = p;
        self.previous = p;
        Some(p)
    }
}

/// Encodes RGBA (or RGB, `channels` 3) pixels. For the build script; the
/// kernel never encodes.
#[cfg(any(test, feature = "std"))]
pub fn encode(pixels: &[u8], width: u32, height: u32, channels: u8) -> std::vec::Vec<u8> {
    let n = width as usize * height as usize;
    let step = channels as usize;
    assert!(channels == 3 || channels == 4, "channels must be 3 or 4");
    assert_eq!(pixels.len(), n * step, "pixel buffer does not match the size");
    let mut out = std::vec::Vec::with_capacity(HEADER_LEN + n + END_MARKER.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.push(channels);
    out.push(0);
    let mut index = [[0u8; 4]; 64];
    let mut previous = [0u8, 0, 0, 255];
    let mut run = 0u8;
    for i in 0..n {
        let s = &pixels[i * step..i * step + step];
        let p = [s[0], s[1], s[2], if step == 4 { s[3] } else { 255 }];
        if p == previous {
            run += 1;
            if run == 62 || i == n - 1 {
                out.push(OP_RUN | (run - 1));
                run = 0;
            }
            continue;
        }
        if run > 0 {
            out.push(OP_RUN | (run - 1));
            run = 0;
        }
        let h = hash(p);
        if index[h] == p {
            out.push(OP_INDEX | h as u8);
        } else {
            index[h] = p;
            if p[3] == previous[3] {
                let dr = p[0].wrapping_sub(previous[0]) as i8;
                let dg = p[1].wrapping_sub(previous[1]) as i8;
                let db = p[2].wrapping_sub(previous[2]) as i8;
                let dr_dg = dr.wrapping_sub(dg);
                let db_dg = db.wrapping_sub(dg);
                if (-2..=1).contains(&dr) && (-2..=1).contains(&dg) && (-2..=1).contains(&db) {
                    out.push(OP_DIFF | ((dr + 2) as u8) << 4 | ((dg + 2) as u8) << 2 | (db + 2) as u8);
                } else if (-32..=31).contains(&dg) && (-8..=7).contains(&dr_dg) && (-8..=7).contains(&db_dg) {
                    out.push(OP_LUMA | (dg + 32) as u8);
                    out.push(((dr_dg + 8) as u8) << 4 | (db_dg + 8) as u8);
                } else {
                    out.extend_from_slice(&[OP_RGB, p[0], p[1], p[2]]);
                }
            } else {
                out.extend_from_slice(&[OP_RGBA, p[0], p[1], p[2], p[3]]);
            }
        }
        previous = p;
    }
    out.extend_from_slice(&END_MARKER);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn decode_all(data: &[u8]) -> (Vec<u8>, bool) {
        let mut d = Decoder::new(data).unwrap();
        let mut out = Vec::new();
        while let Some(p) = d.next_pixel() {
            out.extend_from_slice(&p);
        }
        (out, d.damaged())
    }

    fn picture(w: u32, h: u32, seed: u64) -> Vec<u8> {
        // Gradients, flat runs, noise and alpha: every opcode gets used.
        let mut x = seed | 1;
        let mut px = Vec::new();
        for y in 0..h {
            for c in 0..w {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let noisy = (c / 7 + y / 5) % 3 == 0;
                let r = if noisy { x as u8 } else { (c * 255 / w.max(1)) as u8 };
                let g = if c % 40 < 20 { 80 } else { (y * 3) as u8 };
                let b = ((c + y) / 3) as u8;
                let a = if y % 9 == 0 { (x >> 8) as u8 } else { 255 };
                px.extend_from_slice(&[r, g, b, a]);
            }
        }
        px
    }

    #[test]
    fn round_trips() {
        for (w, h) in [(1, 1), (3, 2), (64, 64), (257, 31), (1000, 3)] {
            let px = picture(w, h, w as u64 * 31 + h as u64);
            let q = encode(&px, w, h, 4);
            let (back, damaged) = decode_all(&q);
            assert!(!damaged);
            assert_eq!(back, px, "{w}x{h}");
        }
    }

    #[test]
    fn rgb_round_trips_with_opaque_alpha() {
        let rgba = picture(50, 20, 9);
        let rgb: Vec<u8> = rgba.chunks(4).flat_map(|p| [p[0], p[1], p[2]]).collect();
        let q = encode(&rgb, 50, 20, 3);
        let (back, _) = decode_all(&q);
        let want: Vec<u8> = rgb.chunks(3).flat_map(|p| [p[0], p[1], p[2], 255]).collect();
        assert_eq!(back, want);
    }

    #[test]
    fn headers_are_checked() {
        assert_eq!(header(b"qoi").err(), Some(Error::NotQoi));
        assert_eq!(header(b"xoif\0\0\0\x01\0\0\0\x01\x04\0").err(), Some(Error::NotQoi));
        assert_eq!(header(b"qoif\0\0\0\0\0\0\0\x01\x04\0").err(), Some(Error::BadHeader));
        assert_eq!(header(b"qoif\xff\xff\xff\xff\xff\xff\xff\xff\x04\0").err(), Some(Error::BadHeader));
        assert_eq!(header(b"qoif\0\0\0\x01\0\0\0\x01\x05\0").err(), Some(Error::BadHeader));
    }

    #[test]
    fn truncated_and_corrupted_streams_never_panic() {
        let px = picture(40, 30, 77);
        let q = encode(&px, 40, 30, 4);
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for cut in [HEADER_LEN, HEADER_LEN + 1, q.len() / 2, q.len() - 9, q.len() - 1] {
            let (back, damaged) = decode_all(&q[..cut]);
            assert_eq!(back.len(), px.len(), "always the full pixel count");
            assert!(damaged || cut >= q.len() - 8);
        }
        for _ in 0..20_000 {
            let mut b = q.clone();
            for _ in 0..4 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let at = HEADER_LEN + (x as usize % (b.len() - HEADER_LEN));
                b[at] = (x >> 32) as u8;
            }
            let (back, _) = decode_all(&b);
            assert_eq!(back.len(), px.len());
        }
    }
}
