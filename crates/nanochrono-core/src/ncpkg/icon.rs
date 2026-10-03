// SPDX-License-Identifier: Apache-2.0
//! Package icons: `icon.png` at the root of a `.ncpkg`.
//!
//! The icon is a file of the package like any other — listed in the
//! manifest with its SHA-512, so the signatures cover it — and the installer
//! copies it to [`CACHE_DIR`]`/<id>.png`, where the desktop, the dock and
//! the package app find every installed package's icon without opening the
//! package again.
//!
//! What an icon may be: a PNG ([`crate::png`]), square, [`MIN_SIDE`] to
//! [`MAX_SIDE`] pixels (256 × 256 is the size to draw it at; it is scaled
//! down for the taskbar and the lists), not interlaced, at most
//! [`MAX_BYTES`]. Any colour type and bit depth decodes; transparency is
//! kept. Checked when the package is built and again when it is installed.

use crate::png::{self, Header, Png};

/// Where installed icons live, one `<id>.png` per package.
pub const CACHE_DIR: &str = "/var/cache/ncpkg/icons";
pub const MIN_SIDE: u32 = 16;
pub const MAX_SIDE: u32 = 512;
pub const MAX_BYTES: usize = 1 << 20;

/// Why an icon was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconError {
    Png(png::Error),
    TooLarge,
    NotSquare,
    BadSize,
    Interlaced,
}

impl IconError {
    pub const fn message(self) -> &'static str {
        match self {
            IconError::Png(e) => e.message(),
            IconError::TooLarge => "icon.png is larger than 1 MiB",
            IconError::NotSquare => "icon.png is not square",
            IconError::BadSize => "icon.png must be 16 to 512 pixels on a side (256 recommended)",
            IconError::Interlaced => "icon.png is interlaced; save it without Adam7",
        }
    }
}

impl core::fmt::Display for IconError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

/// Checks an icon's structure and the rules above, without decoding it.
pub fn check(bytes: &[u8]) -> Result<Header, IconError> {
    if bytes.len() > MAX_BYTES {
        return Err(IconError::TooLarge);
    }
    let h = Png::parse(bytes).map_err(IconError::Png)?.header();
    if h.width != h.height {
        return Err(IconError::NotSquare);
    }
    if !(MIN_SIDE..=MAX_SIDE).contains(&h.width) {
        return Err(IconError::BadSize);
    }
    if h.interlaced {
        return Err(IconError::Interlaced);
    }
    Ok(h)
}

/// Checks an icon and decodes it completely: what the installer runs, so an
/// icon that parses but does not decode is refused before it is installed.
#[cfg(feature = "alloc")]
pub fn check_decodes(bytes: &[u8]) -> Result<Header, IconError> {
    let h = check(bytes)?;
    Png::parse(bytes).and_then(|p| p.decode_rgba()).map_err(IconError::Png)?;
    Ok(h)
}

/// The cache path of package `id`'s icon.
#[cfg(feature = "alloc")]
pub fn cache_path(id: &str) -> alloc::string::String {
    alloc::format!("{CACHE_DIR}/{id}.png")
}

/// Scales a decoded icon to `size` × `size` RGBA8 by averaging the source
/// pixels each destination pixel covers (premultiplied, so a transparent
/// edge does not darken), streaming: feed it rows with [`Thumb::row`].
#[derive(Debug, Clone)]
pub struct Thumb<const N: usize> {
    src: u32,
    size: u32,
    /// Per destination pixel: premultiplied R, G, B, then A, and the weight.
    acc: [[u32; 5]; N],
}

impl<const N: usize> Thumb<N> {
    /// A thumbnail of `size` × `size` (`size * size <= N`) from a square
    /// source of `src` pixels a side.
    pub fn new(src: u32, size: u32) -> Option<Thumb<N>> {
        if size == 0 || (size * size) as usize > N || src == 0 {
            return None;
        }
        Some(Thumb { src, size, acc: [[0; 5]; N] })
    }

    /// One source row (RGBA8).
    pub fn row(&mut self, y: u32, rgba: &[u8]) {
        let dy = (u64::from(y) * u64::from(self.size) / u64::from(self.src)) as u32;
        for (x, px) in rgba.chunks_exact(4).enumerate() {
            let dx = (x as u64 * u64::from(self.size) / u64::from(self.src)) as u32;
            let Some(a) = self.acc.get_mut((dy * self.size + dx) as usize) else { continue };
            let alpha = u32::from(px[3]);
            a[0] += u32::from(px[0]) * alpha;
            a[1] += u32::from(px[1]) * alpha;
            a[2] += u32::from(px[2]) * alpha;
            a[3] += alpha;
            a[4] += 1;
        }
    }

    /// The thumbnail as RGBA8, `size * size * 4` bytes into `out`.
    pub fn finish(&self, out: &mut [u8]) {
        for (i, a) in self.acc.iter().take((self.size * self.size) as usize).enumerate() {
            let Some(px) = out.get_mut(4 * i..4 * i + 4) else { return };
            if a[4] == 0 || a[3] == 0 {
                px.copy_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            px[0] = (a[0] / a[3]) as u8;
            px[1] = (a[1] / a[3]) as u8;
            px[2] = (a[2] / a[3]) as u8;
            px[3] = (a[3] / a[4]) as u8;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::vec::Vec;

    /// A valid square RGBA PNG of `side` pixels (stored DEFLATE blocks), for
    /// the package tests.
    pub(crate) fn png(side: u32, rgba: [u8; 4]) -> Vec<u8> {
        let mut raw = Vec::new();
        for _ in 0..side {
            raw.push(0);
            for _ in 0..side {
                raw.extend_from_slice(&rgba);
            }
        }
        encode(side, side, 6, 8, &raw)
    }

    /// A 1-bit grayscale PNG: big in pixels, small in bytes.
    fn png_gray1(w: u32, h: u32) -> Vec<u8> {
        let stride = w.div_ceil(8) as usize;
        let mut raw = Vec::new();
        for _ in 0..h {
            raw.push(0);
            raw.extend(std::iter::repeat_n(0xAAu8, stride));
        }
        encode(w, h, 0, 1, &raw)
    }

    fn encode(w: u32, h: u32, color: u8, depth: u8, raw: &[u8]) -> Vec<u8> {
        let mut z = std::vec![0x78, 0x01];
        let mut rest: &[u8] = raw;
        loop {
            let take = rest.len().min(65535);
            let last = take == rest.len();
            z.push(u8::from(last));
            z.extend_from_slice(&(take as u16).to_le_bytes());
            z.extend_from_slice(&(!(take as u16)).to_le_bytes());
            z.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if last {
                break;
            }
        }
        let (mut a, mut b) = (1u32, 0u32);
        for &x in raw {
            a = (a + u32::from(x)) % 65521;
            b = (b + a) % 65521;
        }
        z.extend_from_slice(&((b << 16) | a).to_be_bytes());
        let chunk = |out: &mut Vec<u8>, kind: &[u8], data: &[u8]| {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(kind);
            out.extend_from_slice(data);
            out.extend_from_slice(&png::crc32(&[kind, data]).to_be_bytes());
        };
        let mut out = png::SIGNATURE.to_vec();
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&w.to_be_bytes());
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[depth, color, 0, 0, 0]);
        chunk(&mut out, b"IHDR", &ihdr);
        chunk(&mut out, b"IDAT", &z);
        chunk(&mut out, b"IEND", &[]);
        out
    }

    #[test]
    fn the_rules() {
        assert_eq!(check_decodes(&png(64, [1, 2, 3, 255])).unwrap().width, 64);
        assert_eq!(check(&png(8, [0; 4])).err(), Some(IconError::BadSize));
        assert_eq!(check(&png_gray1(520, 520)).err(), Some(IconError::BadSize));
        assert_eq!(check(&png_gray1(64, 32)).err(), Some(IconError::NotSquare));
        assert_eq!(check_decodes(&png_gray1(512, 512)).unwrap().width, 512);
        assert_eq!(check(&png(513, [0; 4])).err(), Some(IconError::TooLarge));
        assert_eq!(check(b"not a png").err(), Some(IconError::Png(png::Error::NotPng)));
        assert_eq!(cache_path("org.a.b"), "/var/cache/ncpkg/icons/org.a.b.png");
    }

    #[test]
    fn thumbnails_average_with_alpha() {
        // A 4x4 icon: left half opaque red, right half transparent.
        let mut t = Thumb::<4>::new(4, 2).unwrap();
        for y in 0..4 {
            let mut row = Vec::new();
            for x in 0..4 {
                row.extend_from_slice(if x < 2 { &[255, 0, 0, 255] } else { &[0, 0, 0, 0] });
            }
            t.row(y, &row);
        }
        let mut out = [0u8; 16];
        t.finish(&mut out);
        assert_eq!(&out[..4], &[255, 0, 0, 255]);
        assert_eq!(&out[4..8], &[0, 0, 0, 0]);
        assert!(Thumb::<4>::new(4, 3).is_none());
    }
}
