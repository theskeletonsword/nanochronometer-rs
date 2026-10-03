// SPDX-License-Identifier: Apache-2.0
//! PNG (ISO/IEC 15948, W3C PNG 3rd ed.), decoded with this crate's own
//! inflate: package icons (`icon.png` in a `.ncpkg`) and the Gallery.
//!
//! Untrusted input, so written the way [`crate::inflate`] and
//! [`crate::ncpkg`] are: every chunk's length and CRC-32 checked before its
//! contents are believed, the chunk order enforced (IHDR first, PLTE before
//! the image data, the IDATs contiguous, IEND last and nothing after it), the
//! zlib header and its Adler-32 checked, the image bounded ([`MAX_PIXELS`])
//! before a byte is inflated, and the inflated size exactly what the header
//! implies. It never panics and never allocates: the caller lends
//! [`Png::scratch_len`] bytes, and rows arrive one at a time as RGBA8 — so
//! the kernel can scale an icon to the screen without holding the image.
//!
//! Supported: every colour type, bit depths 1–16 (16-bit samples are reduced
//! to their high byte), palettes with `tRNS` alpha, `tRNS` colour keys.
//! Not supported: Adam7 interlacing ([`Error::Unsupported`]); ancillary
//! chunks are skipped after their CRC is checked.

use crate::inflate;

/// The eight bytes every PNG starts with.
pub const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
/// Width or height beyond this is refused.
pub const MAX_SIDE: u32 = 16_384;
/// So is an image of more pixels than this, whatever its shape.
pub const MAX_PIXELS: u64 = 64 * 1024 * 1024;

/// Why a PNG was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No PNG signature.
    NotPng,
    /// A chunk runs past the end, fails its CRC, comes out of order, or
    /// something follows IEND.
    BadChunk,
    /// IHDR is malformed or names an impossible combination.
    BadHeader,
    /// Interlaced: not decoded here.
    Unsupported,
    /// Larger than [`MAX_SIDE`] or [`MAX_PIXELS`].
    TooBig,
    /// The zlib wrapper is wrong, or its Adler-32 does not match.
    BadZlib,
    /// The compressed data does not decode, or to the wrong size.
    BadData(inflate::Error),
    /// A scanline names an unknown filter.
    BadFilter,
    /// A palette index past the palette.
    BadPalette,
    /// The scratch buffer is smaller than [`Png::scratch_len`].
    BufferTooSmall,
}

impl Error {
    pub const fn message(self) -> &'static str {
        match self {
            Error::NotPng => "not a PNG file",
            Error::BadChunk => "a PNG chunk is truncated, fails its CRC, or is out of order",
            Error::BadHeader => "bad PNG header",
            Error::Unsupported => "interlaced PNG (not supported)",
            Error::TooBig => "image too large",
            Error::BadZlib => "bad zlib stream in the image data",
            Error::BadData(e) => e.message(),
            Error::BadFilter => "unknown PNG filter type",
            Error::BadPalette => "palette index out of range",
            Error::BufferTooSmall => "scratch buffer too small for this image",
        }
    }
}

/// The colour types of IHDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorType {
    Gray = 0,
    Rgb = 2,
    Palette = 3,
    GrayAlpha = 4,
    Rgba = 6,
}

impl ColorType {
    fn from_u8(v: u8) -> Option<ColorType> {
        Some(match v {
            0 => ColorType::Gray,
            2 => ColorType::Rgb,
            3 => ColorType::Palette,
            4 => ColorType::GrayAlpha,
            6 => ColorType::Rgba,
            _ => return None,
        })
    }

    const fn channels(self) -> u32 {
        match self {
            ColorType::Gray | ColorType::Palette => 1,
            ColorType::GrayAlpha => 2,
            ColorType::Rgb => 3,
            ColorType::Rgba => 4,
        }
    }
}

/// What IHDR says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub color: ColorType,
    pub interlaced: bool,
}

impl Header {
    /// Bytes per scanline, without the filter byte.
    pub fn stride(&self) -> usize {
        (self.width as usize * self.color.channels() as usize * self.bit_depth as usize).div_ceil(8)
    }

    /// Bytes per complete pixel, at least one: the filters' "bpp".
    fn filter_bpp(&self) -> usize {
        ((self.color.channels() as usize * self.bit_depth as usize) / 8).max(1)
    }
}

/// CRC-32 (ISO 3309, as PNG and zlib use it), table built at compile time.
const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[n] = c;
        n += 1;
    }
    t
};

pub fn crc32(parts: &[&[u8]]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for p in parts {
        for &b in *p {
            c = CRC_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
        }
    }
    c ^ 0xFFFF_FFFF
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= 65_521;
        b %= 65_521;
    }
    (b << 16) | a
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// One chunk: its type and data, CRC already checked.
struct Chunk<'a> {
    kind: [u8; 4],
    data: &'a [u8],
}

/// The chunks after the signature, each checked as it is read.
struct Chunks<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Iterator for Chunks<'a> {
    type Item = Result<Chunk<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.at >= self.b.len() {
            return None;
        }
        let bad = || {
            Some(Err(Error::BadChunk))
        };
        let Some(len) = be32(self.b, self.at) else { return bad() };
        let len = len as usize;
        if len > 0x7FFF_FFFF {
            return bad();
        }
        let kind_at = self.at + 4;
        let Some(kind) = self.b.get(kind_at..kind_at + 4) else { return bad() };
        let Some(data) = self.b.get(kind_at + 4..kind_at + 4 + len) else { return bad() };
        let Some(crc) = be32(self.b, kind_at + 4 + len) else { return bad() };
        if crc32(&[kind, data]) != crc || !kind.iter().all(u8::is_ascii_alphabetic) {
            return bad();
        }
        self.at = kind_at + 8 + len;
        Some(Ok(Chunk { kind: [kind[0], kind[1], kind[2], kind[3]], data }))
    }
}

/// A PNG that passed every structural check.
#[derive(Debug, Clone, Copy)]
pub struct Png<'a> {
    bytes: &'a [u8],
    header: Header,
    palette: Option<&'a [u8]>,
    trns: Option<&'a [u8]>,
    idat_len: usize,
}

impl<'a> Png<'a> {
    /// Checks the signature, IHDR and every chunk; inflates nothing.
    pub fn parse(bytes: &'a [u8]) -> Result<Png<'a>, Error> {
        if bytes.get(..8) != Some(&SIGNATURE[..]) {
            return Err(Error::NotPng);
        }
        let mut chunks = Chunks { b: bytes, at: 8 };
        let ihdr = match chunks.next() {
            Some(Ok(c)) if &c.kind == b"IHDR" && c.data.len() == 13 => c,
            Some(Err(e)) => return Err(e),
            _ => return Err(Error::BadChunk),
        };
        let d = ihdr.data;
        let width = be32(d, 0).ok_or(Error::BadHeader)?;
        let height = be32(d, 4).ok_or(Error::BadHeader)?;
        let bit_depth = d[8];
        let color = ColorType::from_u8(d[9]).ok_or(Error::BadHeader)?;
        if d[10] != 0 || d[11] != 0 || d[12] > 1 {
            return Err(Error::BadHeader);
        }
        let depth_ok = match color {
            ColorType::Gray => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
            ColorType::Palette => matches!(bit_depth, 1 | 2 | 4 | 8),
            _ => matches!(bit_depth, 8 | 16),
        };
        if width == 0 || height == 0 || !depth_ok {
            return Err(Error::BadHeader);
        }
        if width > MAX_SIDE || height > MAX_SIDE || u64::from(width) * u64::from(height) > MAX_PIXELS {
            return Err(Error::TooBig);
        }
        let header = Header { width, height, bit_depth, color, interlaced: d[12] == 1 };
        let (mut palette, mut trns) = (None, None);
        let (mut idat_len, mut idat_state, mut ended) = (0usize, 0u8, false);
        for c in chunks.by_ref() {
            let c = c?;
            if ended {
                return Err(Error::BadChunk);
            }
            match &c.kind {
                b"IHDR" => return Err(Error::BadChunk),
                b"PLTE" => {
                    if palette.is_some() || idat_state != 0 || c.data.is_empty() || c.data.len() % 3 != 0 || c.data.len() > 768 {
                        return Err(Error::BadChunk);
                    }
                    palette = Some(c.data);
                }
                b"tRNS" => {
                    if trns.is_some() || idat_state != 0 {
                        return Err(Error::BadChunk);
                    }
                    trns = Some(c.data);
                }
                b"IDAT" => {
                    // The image data is one run of IDATs.
                    if idat_state == 2 {
                        return Err(Error::BadChunk);
                    }
                    idat_state = 1;
                    idat_len = idat_len.checked_add(c.data.len()).ok_or(Error::TooBig)?;
                }
                b"IEND" => {
                    if !c.data.is_empty() {
                        return Err(Error::BadChunk);
                    }
                    ended = true;
                }
                kind => {
                    if idat_state == 1 {
                        idat_state = 2;
                    }
                    // An unknown critical chunk (upper-case first letter)
                    // means an image this cannot render correctly.
                    if kind[0].is_ascii_uppercase() {
                        return Err(Error::BadChunk);
                    }
                }
            }
        }
        if !ended || idat_len == 0 {
            return Err(Error::BadChunk);
        }
        match (color, palette) {
            (ColorType::Palette, None) => return Err(Error::BadChunk),
            (ColorType::Gray | ColorType::GrayAlpha, Some(_)) => return Err(Error::BadChunk),
            _ => {}
        }
        if let Some(t) = trns {
            let ok = match color {
                ColorType::Gray => t.len() == 2,
                ColorType::Rgb => t.len() == 6,
                ColorType::Palette => palette.is_some_and(|p| t.len() <= p.len() / 3),
                _ => false,
            };
            if !ok {
                return Err(Error::BadChunk);
            }
        }
        Ok(Png { bytes, header, palette, trns, idat_len })
    }

    pub fn header(&self) -> Header {
        self.header
    }

    /// The scratch [`decode`](Self::decode) needs: the compressed image
    /// data, the inflated scanlines, and one RGBA row.
    pub fn scratch_len(&self) -> usize {
        let h = &self.header;
        self.idat_len + h.height as usize * (h.stride() + 1) + h.width as usize * 4
    }

    /// Decodes the image, handing each row to `row` as RGBA8 (`width × 4`
    /// bytes), top to bottom.
    pub fn decode(&self, scratch: &mut [u8], row: &mut dyn FnMut(u32, &[u8])) -> Result<(), Error> {
        let h = self.header;
        if h.interlaced {
            return Err(Error::Unsupported);
        }
        let need = self.scratch_len();
        let scratch = scratch.get_mut(..need).ok_or(Error::BufferTooSmall)?;
        let (idat, rest) = scratch.split_at_mut(self.idat_len);
        let stride = h.stride();
        let raw_len = h.height as usize * (stride + 1);
        let (raw, rgba) = rest.split_at_mut(raw_len);

        // The IDATs, in one piece.
        let mut at = 0;
        for c in (Chunks { b: self.bytes, at: 8 }).flatten() {
            if &c.kind == b"IDAT" {
                idat[at..at + c.data.len()].copy_from_slice(c.data);
                at += c.data.len();
            }
        }

        // zlib: CM 8, a window no larger than 32 KiB, no preset dictionary,
        // the check bits right; then DEFLATE; then Adler-32 and nothing more.
        let (cmf, flg) = (*idat.first().ok_or(Error::BadZlib)?, *idat.get(1).ok_or(Error::BadZlib)?);
        if cmf & 0x0F != 8 || cmf >> 4 > 7 || flg & 0x20 != 0 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
            return Err(Error::BadZlib);
        }
        let (n, used) = inflate::inflate_into_prefix(&idat[2..], raw).map_err(Error::BadData)?;
        if n != raw_len {
            return Err(Error::BadData(inflate::Error::Truncated));
        }
        let trailer = 2 + used;
        if be32(idat, trailer) != Some(adler32(raw)) || trailer + 4 != idat.len() {
            return Err(Error::BadZlib);
        }

        // Unfilter in place, a row at a time, and hand it on.
        let bpp = h.filter_bpp();
        for y in 0..h.height as usize {
            let (done, here) = raw.split_at_mut(y * (stride + 1));
            let prev = if y == 0 { None } else { Some(&done[(y - 1) * (stride + 1) + 1..]) };
            let (filter, line) = here.split_first_mut().ok_or(Error::BadFilter)?;
            let line = &mut line[..stride];
            unfilter(*filter, line, prev, bpp)?;
            self.to_rgba(line, rgba)?;
            row(y as u32, rgba);
        }
        Ok(())
    }

    /// One unfiltered scanline to RGBA8.
    fn to_rgba(&self, line: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let h = &self.header;
        let depth = usize::from(h.bit_depth);
        let sample = |i: usize| -> u16 {
            // The i-th sample of the line at the header's bit depth.
            match depth {
                16 => u16::from_be_bytes([line[2 * i], line[2 * i + 1]]),
                8 => u16::from(line[i]),
                _ => {
                    let bit = i * depth;
                    let byte = line[bit / 8];
                    let shift = 8 - depth - bit % 8;
                    u16::from((byte >> shift) & ((1u8 << depth) - 1))
                }
            }
        };
        // A sample scaled to 8 bits.
        let to8 = |v: u16| -> u8 {
            match depth {
                16 => (v >> 8) as u8,
                8 => v as u8,
                _ => ((u32::from(v) * 255) / ((1u32 << depth) - 1)) as u8,
            }
        };
        let key = |i: usize| self.trns.and_then(|t| t.get(2 * i..2 * i + 2)).map(|k| u16::from_be_bytes([k[0], k[1]]));
        for x in 0..h.width as usize {
            let px = &mut out[4 * x..4 * x + 4];
            match h.color {
                ColorType::Gray => {
                    let v = sample(x);
                    let g = to8(v);
                    let a = if key(0) == Some(v) { 0 } else { 255 };
                    px.copy_from_slice(&[g, g, g, a]);
                }
                ColorType::GrayAlpha => {
                    let (g, a) = (to8(sample(2 * x)), to8(sample(2 * x + 1)));
                    px.copy_from_slice(&[g, g, g, a]);
                }
                ColorType::Rgb => {
                    let (r, g, b) = (sample(3 * x), sample(3 * x + 1), sample(3 * x + 2));
                    let a = if key(0) == Some(r) && key(1) == Some(g) && key(2) == Some(b) { 0 } else { 255 };
                    px.copy_from_slice(&[to8(r), to8(g), to8(b), a]);
                }
                ColorType::Rgba => {
                    px.copy_from_slice(&[to8(sample(4 * x)), to8(sample(4 * x + 1)), to8(sample(4 * x + 2)), to8(sample(4 * x + 3))]);
                }
                ColorType::Palette => {
                    let i = usize::from(sample(x));
                    let rgb = self.palette.and_then(|p| p.get(3 * i..3 * i + 3)).ok_or(Error::BadPalette)?;
                    let a = self.trns.and_then(|t| t.get(i)).copied().unwrap_or(255);
                    px.copy_from_slice(&[rgb[0], rgb[1], rgb[2], a]);
                }
            }
        }
        Ok(())
    }

    /// The whole image as RGBA8.
    #[cfg(feature = "alloc")]
    pub fn decode_rgba(&self) -> Result<alloc::vec::Vec<u8>, Error> {
        let mut scratch = alloc::vec![0u8; self.scratch_len()];
        let w = self.header.width as usize * 4;
        let mut out = alloc::vec![0u8; w * self.header.height as usize];
        self.decode(&mut scratch, &mut |y, row| out[y as usize * w..(y as usize + 1) * w].copy_from_slice(row))?;
        Ok(out)
    }
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let (pa, pb, pc) = ((p - i16::from(a)).abs(), (p - i16::from(b)).abs(), (p - i16::from(c)).abs());
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

fn unfilter(filter: u8, line: &mut [u8], prev: Option<&[u8]>, bpp: usize) -> Result<(), Error> {
    let up = |i: usize| prev.map_or(0, |p| p[i]);
    match filter {
        0 => {}
        1 => {
            for i in bpp..line.len() {
                line[i] = line[i].wrapping_add(line[i - bpp]);
            }
        }
        2 => {
            for i in 0..line.len() {
                line[i] = line[i].wrapping_add(up(i));
            }
        }
        3 => {
            for i in 0..line.len() {
                let a = if i >= bpp { u16::from(line[i - bpp]) } else { 0 };
                line[i] = line[i].wrapping_add(((a + u16::from(up(i))) / 2) as u8);
            }
        }
        4 => {
            for i in 0..line.len() {
                let a = if i >= bpp { line[i - bpp] } else { 0 };
                let c = if i >= bpp { up(i - bpp) } else { 0 };
                line[i] = line[i].wrapping_add(paeth(a, up(i), c));
            }
        }
        _ => return Err(Error::BadFilter),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // PNGs written by a small Python encoder (zlib, hand-applied filters,
    // the IDAT split in two), with the RGBA the source pixels give.
    const FIXTURES: &[(&str, &str, u32, u32, &str)] = &[
    ("rgba8_all_filters", "89504e470d0a1a0a0000000d49484452000000050000000508060000008d6f26e50000003a4944415478da01690096ff00a54dca182530bb1d6d132cded6237b2ed91e3f72011fcb1971f8797b6532f80986eb2421d5ecbeabcd02bbd5d577a255eb86903edcfe0000003a4944415433edfca17b85d5f41cb8ebb103e0aa60a0a4d7037bad858057b40bc6f53b00575e04641115a1a530256971f394605c35bcab8a1dcfc9393732d27665d09a0000000049454e44ae426082", 5, 5, "a54dca182530bb1d6d132cded6237b2ed91e3f721fcb1971174494d6493c9d5c3460be31201e69fedaa0eee8b9997f5c7c2999fdafe593253cd654af4dfad71427a0aeb3fee9232f8af2211f9ee491c5b10becb5563bfc1e6f93427ecbc8fe2955e5cd8e"),
    ("rgb8_paeth", "89504e470d0a1a0a0000000d49484452000000040000000308020000003b963991000000194944415478da012700d8ff0446dc8e8edb34a29668e4004c04312a6a89c901e15300000019494441548098a5fdacbb596a04a4e3d0b0e339d870f7626be2762b146d02ddd4d70000000049454e44ae426082", 4, 3, "46dc8effd4b7c2ff764d2aff5a4d76ff7706f8ff5d8690ff024ad6ffbda340ff1be9c8ffcbccc9ff35f6cdff1f6122ff"),
    ("palette4_trns", "89504e470d0a1a0a0000000d49484452000000060000000204030000008973b06d0000000c504c54450a141ec8643200ff00ffffff5a0e83110000000274524e5300809b2b4e18000000084944415478da6314fe2bc0c889aa924600000008494441542020000007070143b6d5091a0000000049454e44ae426082", 6, 2, "c8643280ffffffffc86432800a141e0000ff00ff0a141e000a141e000a141e00c86432800a141e0000ff00ff0a141e00"),
    ("gray1", "89504e470d0a1a0a0000000d4948445200000009000000020100000000a22dcb7e000000074944415478da63d06760a82dda53fd000000074944415461000001e900aca578fffc0000000049454e44ae426082", 9, 2, "000000ff000000ffffffffff000000ffffffffffffffffffffffffffffffffff000000ff000000ffffffffffffffffffffffffffffffffffffffffff000000ff000000ff000000ff"),
    ("graya8_up", "89504e470d0a1a0a0000000d4948445200000003000000020804000000377dae910000000b4944415478da635adffe35883b938914fa8ad00000000b49444154eb88849bb20c0026790461943403b50000000049454e44ae426082", 3, 2, "afafaf87f5f5f5520b0b0b69b9b9b94b0d0d0d982e2e2e85"),
    ("rgba16_avg", "89504e470d0a1a0a0000000d49484452000000020000000210060000002226d167000000164944415478da012200ddff03bbc05586b61d72114b6948ef08dc17460ce8000000174944415441890370c64ad40b4dc345fc959bb2aaabd4a0063010a73ed31db90000000049454e44ae426082", 2, 2, "bb55b672a872637acd7466fcb60e0e8f"),
    ("gray8_key", "89504e470d0a1a0a0000000d49484452000000030000000108000000003e8b4b680000000274524e5300106b24dd5c000000064944415478da6310681091e4fbc200000006494441540000014400a15e08c8c70000000049454e44ae426082", 3, 1, "10101000808080ff10101000"),
    ];

    #[test]
    fn every_colour_type_and_filter_decodes() {
        for (name, png, w, h, want) in FIXTURES {
            let bytes = unhex(png);
            let p = Png::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!((p.header().width, p.header().height), (*w, *h), "{name}");
            assert_eq!(p.decode_rgba().unwrap_or_else(|e| panic!("{name}: {e:?}")), unhex(want), "{name}");
        }
    }

    #[test]
    fn crc_and_adler_known_answers() {
        assert_eq!(crc32(&[b"123456789"]), 0xCBF4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn structure_is_checked() {
        let good = unhex(FIXTURES[0].1);
        assert!(Png::parse(&good).is_ok());
        assert_eq!(Png::parse(b"GIF89a").err(), Some(Error::NotPng));
        // A flipped bit anywhere in a chunk fails its CRC.
        let mut b = good.clone();
        b[20] ^= 1;
        assert_eq!(Png::parse(&b).err(), Some(Error::BadChunk));
        // Anything after IEND.
        let mut b = good.clone();
        b.push(0);
        assert_eq!(Png::parse(&b).err(), Some(Error::BadChunk));
        // Truncated.
        assert_eq!(Png::parse(&good[..good.len() - 5]).err(), Some(Error::BadChunk));
        // Interlaced parses, and is refused at decode.
        let inter = unhex("89504e470d0a1a0a0000000d494844520000000200000002080600000105b13db2000000054944415478da6360409577f474000000064944415407000012000145566ef00000000049454e44ae426082");
        let p = Png::parse(&inter).unwrap();
        assert!(p.header().interlaced);
        assert_eq!(p.decode_rgba().err(), Some(Error::Unsupported));
        // Too small a scratch buffer.
        let p = Png::parse(&good).unwrap();
        let mut small = [0u8; 8];
        assert_eq!(p.decode(&mut small, &mut |_, _| {}).err(), Some(Error::BufferTooSmall));
    }

    #[test]
    fn corrupted_images_never_panic() {
        let bases: Vec<Vec<u8>> = FIXTURES.iter().map(|f| unhex(f.1)).collect();
        let mut x = 0x0123_4567_89AB_CDEFu64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..20_000 {
            let mut b = bases[round % bases.len()].clone();
            let r = next();
            let at = (r >> 8) as usize % b.len();
            match r % 3 {
                0 => b[at] ^= 1 << ((r >> 32) % 8),
                1 => b[at] = (r >> 40) as u8,
                _ => b.truncate(at),
            }
            // A mutation that keeps the CRCs valid needs the chunk data and
            // its CRC changed together; recompute them half the time so the
            // decoder, not only the CRC check, sees damaged data.
            if round % 2 == 0 {
                fix_crcs(&mut b);
            }
            if let Ok(p) = Png::parse(&b) {
                let _ = p.decode_rgba();
            }
        }
    }

    /// Recomputes every chunk's CRC in place, as far as the chunks parse.
    fn fix_crcs(b: &mut [u8]) {
        let mut at = 8;
        while let Some(len) = be32(b, at) {
            let len = len as usize;
            let end = at + 8 + len;
            if end + 4 > b.len() {
                return;
            }
            let crc = crc32(&[&b[at + 4..end]]);
            b[end..end + 4].copy_from_slice(&crc.to_be_bytes());
            at = end + 4;
        }
    }
}
