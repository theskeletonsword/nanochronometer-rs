// SPDX-License-Identifier: Apache-2.0
//! EDID: what a monitor says about itself — who made it, what it is called,
//! and above all its native mode.
//!
//! The base block of VESA's Extended Display Identification Data, versions
//! 1.3 and 1.4: 128 bytes behind a fixed header and a checksum, read from
//! the monitor over DDC by whatever drives the connector (a display driver,
//! the firmware). A display driver hands the bytes to the kernel, which
//! parses them here: the driver gets the native mode to set, and the boot
//! log names the monitor.
//!
//! `no_std`, allocation-free, and written for bytes that are not to be
//! trusted: a monitor, a KVM switch or a cheap adapter can send anything.
//! Every field is read through the validated block, never by an index the
//! data chose.
//!
//! The native mode is the first detailed timing descriptor: EDID 1.3 and
//! later require it to be the preferred one ("the display's native format",
//! in 1.4). A mode whose pixel clock does not fit a descriptor's 16 bits —
//! past 655.35 MHz: 4K above 60 Hz, 5K, 8K — is described in a DisplayID
//! extension block instead, as a timing marked preferred (DisplayID 1.x
//! type I, 2.0 type VII), and the base block may then hold no timing at all.
//! So the native mode is the largest preferred timing of the two, read from
//! every extension block that came with the base one and passed its
//! checksum.

/// The base block's length.
pub const BLOCK_LEN: usize = 128;

/// Every EDID starts with these eight bytes.
pub const HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// Why bytes are not an EDID this can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Fewer than 128 bytes.
    Short,
    /// The fixed header is not there.
    Header,
    /// The block's bytes do not sum to zero (mod 256).
    Checksum,
    /// Not EDID version 1.
    Version,
}

impl Error {
    pub const fn message(self) -> &'static str {
        match self {
            Error::Short => "shorter than an EDID block",
            Error::Header => "no EDID header",
            Error::Checksum => "the EDID checksum does not match",
            Error::Version => "not EDID version 1",
        }
    }
}

/// One detailed timing: a mode the monitor accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub width: u32,
    pub height: u32,
    pub pixel_clock_khz: u32,
    /// Refresh rate in millihertz (59 940 for 59.94 Hz).
    pub refresh_mhz: u32,
    pub interlaced: bool,
    /// The image size this mode shows, in millimetres; zero when unstated.
    pub size_mm: (u16, u16),
    /// Marked as the display's preferred (native) mode: the base block's
    /// first descriptor from EDID 1.3 on, or a DisplayID timing's flag.
    pub preferred: bool,
}

/// A validated base block, and the extension blocks that followed it.
#[derive(Debug, Clone, Copy)]
pub struct Edid<'a> {
    block: &'a [u8; BLOCK_LEN],
    /// Everything after the base block that the caller passed: extension
    /// blocks, each checked on its own before it is read.
    rest: &'a [u8],
}

/// Extension block tags.
const EXT_DISPLAYID: u8 = 0x70;
/// DisplayID data blocks: 1.x type I and 2.0 type VII detailed timings,
/// 20 bytes each, the same layout but for the pixel clock's unit.
const DID_TYPE_I: u8 = 0x03;
const DID_TYPE_VII: u8 = 0x22;
const DID_TIMING_LEN: usize = 20;

/// The four 18-byte descriptors' offsets.
const DESCRIPTORS: [usize; 4] = [54, 72, 90, 108];

impl<'a> Edid<'a> {
    /// Checks the header, the checksum and the version of the first block of
    /// `bytes` (extension blocks may follow; they are not read).
    pub fn parse(bytes: &'a [u8]) -> Result<Edid<'a>, Error> {
        let block: &[u8; BLOCK_LEN] = bytes.get(..BLOCK_LEN).and_then(|b| b.try_into().ok()).ok_or(Error::Short)?;
        if block[..8] != HEADER {
            return Err(Error::Header);
        }
        if block.iter().fold(0u8, |sum, &b| sum.wrapping_add(b)) != 0 {
            return Err(Error::Checksum);
        }
        if block[18] != 1 {
            return Err(Error::Version);
        }
        Ok(Edid { block, rest: &bytes[BLOCK_LEN..] })
    }

    /// The manufacturer's three-letter PNP ID ("DEL", "SAM", "RHT"), from
    /// three 5-bit letters; `?` for a code outside A–Z.
    pub fn manufacturer(&self) -> [u8; 3] {
        let id = u16::from_be_bytes([self.block[8], self.block[9]]);
        let letter = |v: u16| if (1..=26).contains(&v) { b'A' + v as u8 - 1 } else { b'?' };
        [letter((id >> 10) & 0x1F), letter((id >> 5) & 0x1F), letter(id & 0x1F)]
    }

    /// The manufacturer's product code.
    pub fn product(&self) -> u16 {
        u16::from_le_bytes([self.block[10], self.block[11]])
    }

    /// The numeric serial number (zero when unused).
    pub fn serial(&self) -> u32 {
        u32::from_le_bytes([self.block[12], self.block[13], self.block[14], self.block[15]])
    }

    /// The year of manufacture (or of the model, in 1.4).
    pub fn year(&self) -> u16 {
        1990 + self.block[17] as u16
    }

    /// EDID version and revision: (1, 3) or (1, 4).
    pub fn version(&self) -> (u8, u8) {
        (self.block[18], self.block[19])
    }

    /// Whether the input is digital (HDMI, DisplayPort, DVI) rather than
    /// analogue (VGA).
    pub fn digital(&self) -> bool {
        self.block[20] & 0x80 != 0
    }

    /// The screen's size in centimetres, when stated.
    pub fn size_cm(&self) -> Option<(u8, u8)> {
        let (w, h) = (self.block[21], self.block[22]);
        (w != 0 && h != 0).then_some((w, h))
    }

    /// How many extension blocks follow this one.
    pub fn extensions(&self) -> u8 {
        self.block[126]
    }

    /// The monitor's name (descriptor 0xFC), when it gives one.
    pub fn name(&self) -> Option<&'a str> {
        self.text(0xFC)
    }

    /// The serial number as text (descriptor 0xFF), when it gives one.
    pub fn serial_text(&self) -> Option<&'a str> {
        self.text(0xFF)
    }

    /// The detailed timings in the base block, in order; the first is
    /// marked preferred from EDID 1.3 on (and in 1.0–1.2 by feature bit 1).
    pub fn timings(&self) -> impl Iterator<Item = Timing> + 'a {
        let block = self.block;
        let first_preferred = block[24] & 0x02 != 0 || block[19] >= 3;
        DESCRIPTORS.into_iter().enumerate().filter_map(move |(i, at)| {
            timing(&block[at..at + 18]).map(|t| Timing { preferred: i == 0 && first_preferred, ..t })
        })
    }

    /// The extension blocks that came with the base block, as many as it
    /// announces and the caller passed, each with a valid checksum.
    fn extension_blocks(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        let rest = self.rest;
        rest.chunks_exact(BLOCK_LEN)
            .take(self.extensions() as usize)
            .filter(|b| b.iter().fold(0u8, |sum, &x| sum.wrapping_add(x)) == 0)
    }

    /// The detailed timings of every DisplayID extension block (1.x type I,
    /// 2.0 type VII), in order.
    pub fn displayid_timings(&self) -> impl Iterator<Item = Timing> + 'a {
        self.extension_blocks()
            .filter(|b| b[0] == EXT_DISPLAYID)
            .flat_map(DisplayIdTimings::new)
    }

    /// The native mode: the largest timing marked preferred, in the base
    /// block or a DisplayID extension (see the module docs).
    pub fn preferred(&self) -> Option<Timing> {
        self.timings()
            .chain(self.displayid_timings())
            .filter(|t| t.preferred)
            .max_by_key(|t| (t.width as u64 * t.height as u64, t.refresh_mhz))
    }

    /// The text of the first display descriptor tagged `tag`: printable
    /// ASCII up to its line feed, trailing spaces trimmed.
    fn text(&self, tag: u8) -> Option<&'a str> {
        let block: &'a [u8; BLOCK_LEN] = self.block;
        DESCRIPTORS.into_iter().find_map(|at| {
            let d = &block[at..at + 18];
            if d[0] != 0 || d[1] != 0 || d[3] != tag {
                return None;
            }
            let body = &d[5..18];
            let end = body.iter().position(|&b| b == 0x0A).unwrap_or(body.len());
            let mut text = &body[..end];
            while let [rest @ .., b' '] = text {
                text = rest;
            }
            if text.is_empty() || !text.iter().all(|b| (0x20..=0x7E).contains(b)) {
                return None;
            }
            core::str::from_utf8(text).ok()
        })
    }
}

/// The timings in one DisplayID extension block: its section header (the
/// version, the payload's length), then data blocks of a tag, a revision and
/// a length, every one bounded by the section and the block.
struct DisplayIdTimings<'a> {
    block: &'a [u8],
    /// Where the next data block starts.
    at: usize,
    /// Where the section's payload ends.
    end: usize,
    /// The data block being read: its tag, and its remaining payload.
    current: Option<(u8, usize, usize)>,
}

impl<'a> DisplayIdTimings<'a> {
    fn new(block: &'a [u8]) -> Self {
        // byte 0: the extension tag; 1: DisplayID version; 2: payload bytes;
        // 3: product type or use case; 4: extension count; data from 5. The
        // section ends before its own checksum, inside the 128-byte block
        // whose last byte is the EDID checksum.
        let end = (5 + block[2] as usize).min(BLOCK_LEN - 2);
        DisplayIdTimings { block, at: 5, end, current: None }
    }
}

impl Iterator for DisplayIdTimings<'_> {
    type Item = Timing;

    fn next(&mut self) -> Option<Timing> {
        loop {
            if let Some((tag, at, end)) = self.current {
                if at + DID_TIMING_LEN <= end {
                    self.current = Some((tag, at + DID_TIMING_LEN, end));
                    let unit_khz = if tag == DID_TYPE_I { 10 } else { 1 };
                    if let Some(t) = displayid_timing(&self.block[at..at + DID_TIMING_LEN], unit_khz) {
                        return Some(t);
                    }
                    continue;
                }
                self.current = None;
            }
            if self.at + 3 > self.end {
                return None;
            }
            let (tag, len) = (self.block[self.at], self.block[self.at + 2] as usize);
            let start = self.at + 3;
            let stop = start + len;
            if stop > self.end {
                return None;
            }
            self.at = stop;
            if tag == DID_TYPE_I || tag == DID_TYPE_VII {
                self.current = Some((tag, start, stop));
            }
        }
    }
}

/// A 20-byte DisplayID detailed timing: every field stored as its value
/// minus one, the pixel clock in `unit_khz` (10 kHz for type I, 1 kHz for
/// type VII), the preferred flag in bit 7 of the options byte.
fn displayid_timing(d: &[u8], unit_khz: u64) -> Option<Timing> {
    let le16 = |at: usize| u16::from_le_bytes([d[at], d[at + 1]]) as u32;
    let clock_khz = (u32::from_le_bytes([d[0], d[1], d[2], 0]) as u64 + 1) * unit_khz;
    let options = d[3];
    let width = le16(4) + 1;
    let hblank = le16(6) + 1;
    let height = le16(12) + 1;
    let vblank = le16(14) + 1;
    let interlaced = options & 0x10 != 0;
    let total = (width + hblank) as u64 * (height + vblank) as u64;
    let mut refresh = clock_khz * 1_000_000 / total;
    if interlaced {
        refresh /= 2;
    }
    Some(Timing {
        width,
        height,
        pixel_clock_khz: u32::try_from(clock_khz).ok()?,
        refresh_mhz: u32::try_from(refresh).ok()?,
        interlaced,
        size_mm: (0, 0),
        preferred: options & 0x80 != 0,
    })
}

/// An 18-byte detailed timing descriptor, or `None` for a display
/// descriptor (pixel clock zero) or a timing with no picture.
fn timing(d: &[u8]) -> Option<Timing> {
    let clock = u16::from_le_bytes([d[0], d[1]]) as u32 * 10;
    if clock == 0 {
        return None;
    }
    let width = d[2] as u32 | ((d[4] as u32 & 0xF0) << 4);
    let hblank = d[3] as u32 | ((d[4] as u32 & 0x0F) << 8);
    let height = d[5] as u32 | ((d[7] as u32 & 0xF0) << 4);
    let vblank = d[6] as u32 | ((d[7] as u32 & 0x0F) << 8);
    if width == 0 || height == 0 {
        return None;
    }
    let interlaced = d[17] & 0x80 != 0;
    let total = (width + hblank) as u64 * (height + vblank) as u64;
    // Millihertz: kHz · 10⁶ over pixels per frame. An interlaced mode's
    // timing describes a field, so its frame rate is half of that.
    let mut refresh = (clock as u64 * 1_000_000) / total;
    if interlaced {
        refresh /= 2;
    }
    let size_mm = (
        d[12] as u16 | ((d[14] as u16 & 0xF0) << 4),
        d[13] as u16 | ((d[14] as u16 & 0x0F) << 8),
    );
    Some(Timing { width, height, pixel_clock_khz: clock, refresh_mhz: refresh as u32, interlaced, size_mm, preferred: false })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A detailed timing descriptor.
    fn dtd(clock_khz: u32, w: u32, h: u32, hblank: u32, vblank: u32, mm: (u16, u16)) -> [u8; 18] {
        let c = (clock_khz / 10) as u16;
        let mut d = [0u8; 18];
        d[0..2].copy_from_slice(&c.to_le_bytes());
        d[2] = w as u8;
        d[3] = hblank as u8;
        d[4] = (((w >> 8) & 0xF) << 4) as u8 | ((hblank >> 8) & 0xF) as u8;
        d[5] = h as u8;
        d[6] = vblank as u8;
        d[7] = (((h >> 8) & 0xF) << 4) as u8 | ((vblank >> 8) & 0xF) as u8;
        d[12] = mm.0 as u8;
        d[13] = mm.1 as u8;
        d[14] = (((mm.0 >> 8) & 0xF) << 4) as u8 | ((mm.1 >> 8) & 0xF) as u8;
        d
    }

    /// A display descriptor carrying text.
    fn text(tag: u8, s: &str) -> [u8; 18] {
        let mut d = [0u8; 18];
        d[3] = tag;
        let mut body = [0x20u8; 13];
        body[..s.len()].copy_from_slice(s.as_bytes());
        if s.len() < 13 {
            body[s.len()] = 0x0A;
        }
        d[5..18].copy_from_slice(&body);
        d
    }

    /// A base block: "NCH" product 0x1234, 2024, 60 x 34 cm, digital, with
    /// the given descriptors, checksummed.
    fn block(descriptors: [[u8; 18]; 4], revision: u8) -> [u8; 128] {
        let mut b = [0u8; 128];
        b[..8].copy_from_slice(&HEADER);
        // N=14, C=3, H=8
        let id: u16 = (14 << 10) | (3 << 5) | 8;
        b[8..10].copy_from_slice(&id.to_be_bytes());
        b[10..12].copy_from_slice(&0x1234u16.to_le_bytes());
        b[12..16].copy_from_slice(&7u32.to_le_bytes());
        b[17] = 34;
        b[18] = 1;
        b[19] = revision;
        b[20] = 0x80;
        b[21] = 60;
        b[22] = 34;
        for (i, d) in descriptors.iter().enumerate() {
            b[54 + i * 18..72 + i * 18].copy_from_slice(d);
        }
        let sum = b[..127].iter().fold(0u8, |s, &x| s.wrapping_add(x));
        b[127] = 0u8.wrapping_sub(sum);
        b
    }

    fn uhd() -> [u8; 128] {
        // 3840x2160 at 60 Hz, CTA timing: 594 MHz, 4400 x 2250 total.
        block(
            [
                dtd(594_000, 3840, 2160, 560, 90, (597, 336)),
                dtd(148_500, 1920, 1080, 280, 45, (597, 336)),
                text(0xFC, "NC Monitor 4K"),
                text(0xFF, "SN-0042"),
            ],
            4,
        )
    }

    #[test]
    fn reads_who_made_it_and_what_it_is() {
        let b = uhd();
        let e = Edid::parse(&b).unwrap();
        assert_eq!(&e.manufacturer(), b"NCH");
        assert_eq!(e.product(), 0x1234);
        assert_eq!(e.serial(), 7);
        assert_eq!(e.year(), 2024);
        assert_eq!(e.version(), (1, 4));
        assert!(e.digital());
        assert_eq!(e.size_cm(), Some((60, 34)));
        assert_eq!(e.name(), Some("NC Monitor 4K"));
        assert_eq!(e.serial_text(), Some("SN-0042"));
        assert_eq!(e.extensions(), 0);
    }

    #[test]
    fn the_first_timing_is_the_native_mode() {
        let b = uhd();
        let e = Edid::parse(&b).unwrap();
        let p = e.preferred().unwrap();
        assert_eq!((p.width, p.height), (3840, 2160));
        assert_eq!(p.pixel_clock_khz, 594_000);
        assert_eq!(p.refresh_mhz, 60_000);
        assert_eq!(p.size_mm, (597, 336));
        assert!(!p.interlaced);
        assert!(p.preferred);
        let all: Vec<_> = e.timings().map(|t| (t.width, t.height, t.refresh_mhz, t.preferred)).collect();
        assert_eq!(all, [(3840, 2160, 60_000, true), (1920, 1080, 60_000, false)]);
    }

    /// A DisplayID extension block holding one detailed timing.
    #[allow(clippy::too_many_arguments)]
    fn displayid(version: u8, tag: u8, clock_units: u32, w: u32, h: u32, hblank: u32, vblank: u32, preferred: bool) -> [u8; 128] {
        let mut b = [0u8; 128];
        b[0] = EXT_DISPLAYID;
        b[1] = version;
        b[2] = 3 + 20; // one data block
        b[3] = 0x03;
        b[4] = 0;
        b[5] = tag;
        b[6] = 0;
        b[7] = 20;
        let t = &mut b[8..28];
        let c = clock_units - 1;
        t[0..3].copy_from_slice(&c.to_le_bytes()[..3]);
        t[3] = if preferred { 0x80 } else { 0 } | 0x04;
        t[4..6].copy_from_slice(&((w - 1) as u16).to_le_bytes());
        t[6..8].copy_from_slice(&((hblank - 1) as u16).to_le_bytes());
        t[12..14].copy_from_slice(&((h - 1) as u16).to_le_bytes());
        t[14..16].copy_from_slice(&((vblank - 1) as u16).to_le_bytes());
        // The DisplayID section's checksum, then the EDID block's.
        let sec = b[1..28].iter().fold(0u8, |s, &x| s.wrapping_add(x));
        b[28] = 0u8.wrapping_sub(sec);
        let sum = b[..127].iter().fold(0u8, |s, &x| s.wrapping_add(x));
        b[127] = 0u8.wrapping_sub(sum);
        b
    }

    /// A base block announcing `ext` extensions, with no timing of its own:
    /// the shape a monitor whose native mode needs DisplayID sends.
    fn base_without_timings(ext: u8) -> [u8; 128] {
        let mut b = block([[0; 18], [0; 18], text(0xFC, "NC 4K75"), [0; 18]], 4);
        b[126] = ext;
        b[127] = 0;
        let sum = b[..127].iter().fold(0u8, |s, &x| s.wrapping_add(x));
        b[127] = 0u8.wrapping_sub(sum);
        b
    }

    #[test]
    fn a_native_mode_past_a_descriptor_comes_from_displayid() {
        // 3840x2160 at 75 Hz: 868.97 MHz, more than a descriptor holds.
        let mut bytes = [0u8; 256];
        bytes[..128].copy_from_slice(&base_without_timings(1));
        bytes[128..].copy_from_slice(&displayid(0x13, DID_TYPE_I, 86_897, 3840, 2160, 1344, 75, true));
        let e = Edid::parse(&bytes).unwrap();
        assert_eq!(e.timings().count(), 0);
        let p = e.preferred().unwrap();
        assert_eq!((p.width, p.height, p.pixel_clock_khz), (3840, 2160, 868_970));
        assert_eq!(p.refresh_mhz, 75_000);
        // Not passed: no extension, no mode.
        assert_eq!(Edid::parse(&bytes[..128]).unwrap().preferred(), None);
        // A damaged extension is skipped.
        let mut bad = bytes;
        bad[140] ^= 0x40;
        assert_eq!(Edid::parse(&bad).unwrap().preferred(), None);
    }

    #[test]
    fn the_largest_preferred_timing_wins() {
        // 5K: the base block's first descriptor is a mode it also takes
        // (2560x1440), DisplayID 2.0 marks 5120x2880 preferred (1 kHz units).
        let mut bytes = [0u8; 256];
        let mut base = block([dtd(241_500, 2560, 1440, 160, 41, (0, 0)), [0; 18], [0; 18], [0; 18]], 4);
        base[126] = 1;
        base[127] = 0;
        let sum = base[..127].iter().fold(0u8, |s, &x| s.wrapping_add(x));
        base[127] = 0u8.wrapping_sub(sum);
        bytes[..128].copy_from_slice(&base);
        bytes[128..].copy_from_slice(&displayid(0x20, DID_TYPE_VII, 938_250, 5120, 2880, 160, 62, true));
        let e = Edid::parse(&bytes).unwrap();
        let p = e.preferred().unwrap();
        assert_eq!((p.width, p.height), (5120, 2880));
        assert_eq!(p.pixel_clock_khz, 938_250);
        assert_eq!(e.displayid_timings().count(), 1);
        // The same timing without the flag is listed but not chosen.
        bytes[128..].copy_from_slice(&displayid(0x20, DID_TYPE_VII, 938_250, 5120, 2880, 160, 62, false));
        let e = Edid::parse(&bytes).unwrap();
        assert_eq!(e.preferred().map(|t| (t.width, t.height)), Some((2560, 1440)));
    }

    #[test]
    fn a_fractional_refresh_is_kept() {
        // 1920x1080 at 59.94 Hz: 148.35 MHz over the same totals.
        let b = block([dtd(148_350, 1920, 1080, 280, 45, (0, 0)), [0; 18], [0; 18], [0; 18]], 3);
        let p = Edid::parse(&b).unwrap().preferred().unwrap();
        assert_eq!(p.refresh_mhz, 59_939);
    }

    #[test]
    fn bad_bytes_are_refused() {
        let b = uhd();
        assert_eq!(Edid::parse(&b[..127]).unwrap_err(), Error::Short);
        let mut h = b;
        h[0] = 1;
        assert_eq!(Edid::parse(&h).unwrap_err(), Error::Header);
        let mut c = b;
        c[60] ^= 1;
        assert_eq!(Edid::parse(&c).unwrap_err(), Error::Checksum);
        let mut v = b;
        v[18] = 2;
        v[127] = v[127].wrapping_sub(1);
        assert_eq!(Edid::parse(&v).unwrap_err(), Error::Version);
        // Extension blocks after the base block are allowed (and ignored).
        let mut long = [0u8; 256];
        long[..128].copy_from_slice(&b);
        assert!(Edid::parse(&long).is_ok());
    }

    #[test]
    fn old_blocks_need_the_preferred_bit_and_text_must_be_printable() {
        // EDID 1.2 without feature bit 1: no preferred mode.
        let b = block([dtd(65_000, 1024, 768, 320, 38, (0, 0)), text(0xFC, "Old\u{1}"), [0; 18], [0; 18]], 2);
        let e = Edid::parse(&b).unwrap();
        assert_eq!(e.preferred(), None);
        assert_eq!(e.timings().count(), 1);
        assert_eq!(e.name(), None, "a control character is not a name");
        // Display descriptors and zero-sized timings are not modes.
        let z = block([dtd(65_000, 0, 768, 320, 38, (0, 0)), [0; 18], [0; 18], [0; 18]], 4);
        assert_eq!(Edid::parse(&z).unwrap().preferred(), None);
    }

    #[test]
    fn any_bytes_parse_or_fail_without_panicking() {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..20_000 {
            let mut b = uhd();
            for _ in 0..1 + (x % 6) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                b[(x % 128) as usize] = (x >> 32) as u8;
            }
            // Fix the checksum half the time, so the descriptors are read.
            if x & 1 == 0 {
                let sum = b[..127].iter().fold(0u8, |s, &v| s.wrapping_add(v));
                b[127] = 0u8.wrapping_sub(sum);
            }
            if let Ok(e) = Edid::parse(&b) {
                let _ = (e.manufacturer(), e.name(), e.serial_text(), e.size_cm(), e.preferred());
                for t in e.timings() {
                    assert!(t.width > 0 && t.height > 0 && t.width < 4096 && t.height < 4096);
                }
            }
            // And DisplayID blocks of any content behind a valid base block.
            let mut two = [0u8; 256];
            two[..128].copy_from_slice(&base_without_timings(1));
            two[128..].copy_from_slice(&displayid(0x13, DID_TYPE_I, 86_897, 3840, 2160, 1344, 75, true));
            for _ in 0..1 + (x % 8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                two[128 + (x % 127) as usize] = (x >> 40) as u8;
            }
            let sum = two[128..255].iter().fold(0u8, |s, &v| s.wrapping_add(v));
            two[255] = 0u8.wrapping_sub(sum);
            let e = Edid::parse(&two).unwrap();
            for t in e.displayid_timings() {
                assert!(t.width >= 1 && t.height >= 1 && t.width <= 65_536 && t.height <= 65_536);
            }
            let _ = e.preferred();
        }
    }
}
