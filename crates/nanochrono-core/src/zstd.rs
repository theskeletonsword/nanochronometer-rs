// SPDX-License-Identifier: Apache-2.0
//! Zstandard decoding (RFC 8878): NCFS extents and `ncinitramdisk` images
//! compressed on a host.
//!
//! NCFS has two codecs. LZ4 ([`crate::lz4`]) is what the system writes with,
//! because it costs less than the disk time it saves; ZSTD is what a host
//! writes with when it builds an image once and the system reads it many
//! times — the boot image above all, where every byte saved is a byte the
//! loader does not have to read. Only the reading half is here: a host has
//! the reference library to compress with, and the kernel never needs to.
//!
//! # For untrusted input
//!
//! Written from the format specification (RFC 8878, and the format
//! document it was taken from), not from any implementation, in safe Rust
//! with every read and write checked. It never panics, never allocates, and
//! never writes past the buffer it is given: a frame decodes into exactly
//! the extent's declared size or is refused. What a frame says about itself
//! — its content size, its window, its checksum — is checked, not trusted.
//! The tests decode frames the reference library made, check the predefined
//! decoding tables against the specification's appendix, and throw mutated
//! frames at it; the host tool's tests decode the reference library's output
//! at every level.
//!
//! # Memory
//!
//! A [`Workspace`] holds the Huffman and FSE tables, about 10 KiB; a kernel
//! keeps one in static memory, a hosted caller lets [`decompress_into`] put
//! one on its stack. The output buffer is the window: a match may reach
//! anywhere back to the start of its frame. Huffman-coded literals are
//! decoded into the unused end of the output buffer and consumed from there
//! — the write position never overtakes the literals still to be read
//! while the block fits — so there is no 128 KiB literal buffer either.
//! Dictionaries are not supported (NCFS never makes frames that need one);
//! a frame that names one is refused with [`Error::Dictionary`].

/// A Zstandard frame's magic number.
pub const MAGIC: u32 = 0xFD2F_B528;
/// Skippable frames: any magic from `0x184D2A50` to `0x184D2A5F`.
const SKIPPABLE: u32 = 0x184D_2A50;
/// The largest block, compressed or not.
pub const BLOCK_MAX: usize = 128 * 1024;
/// The longest Huffman code.
const HUF_LOG_MAX: u32 = 11;
/// The largest offset code this decoder takes (the reference's limit too).
const OFFSET_CODE_MAX: u8 = 31;

/// Why a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input ends inside a frame.
    Truncated,
    /// Not a Zstandard (or skippable) frame.
    BadMagic,
    /// A reserved bit or a reserved block type is set.
    Reserved,
    /// The frame needs a dictionary.
    Dictionary,
    /// A block larger than the frame allows.
    BadBlock,
    /// An inconsistent literals section.
    BadLiterals,
    /// An invalid Huffman tree description or stream.
    BadHuffman,
    /// An invalid FSE table description.
    BadFse,
    /// A sequences section that does not decode exactly.
    BadSequences,
    /// A match reaching before the frame's start or beyond its window.
    BadOffset,
    /// More output than the buffer holds: more than the extent declared.
    Overflow,
    /// Less output than declared (the frame's content size, or the extent).
    Short,
    /// The content checksum does not match.
    Checksum,
}

impl Error {
    pub const fn message(self) -> &'static str {
        match self {
            Error::Truncated => "zstd frame ends early",
            Error::BadMagic => "not a zstd frame",
            Error::Reserved => "zstd frame uses a reserved field",
            Error::Dictionary => "zstd frame needs a dictionary",
            Error::BadBlock => "zstd block larger than allowed",
            Error::BadLiterals => "bad zstd literals section",
            Error::BadHuffman => "bad zstd Huffman table or stream",
            Error::BadFse => "bad zstd FSE table",
            Error::BadSequences => "bad zstd sequences section",
            Error::BadOffset => "zstd match reaches outside its window",
            Error::Overflow => "zstd frame decodes to more than declared",
            Error::Short => "zstd frame decodes to less than declared",
            Error::Checksum => "zstd content checksum mismatch",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

type Result<T> = core::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// The codes for literal lengths, match lengths and offsets (RFC 8878
// §3.1.1.3.2.1) and their default distributions.

const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
    8192, 16384, 32768, 65536,
];
const LL_BITS: [u8; 36] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37,
    39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539,
];
const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7,
    8, 9, 10, 11, 12, 13, 14, 15, 16,
];

const LL_DEFAULT: [i16; 36] = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1];
const ML_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT: [i16; 29] = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1];

// ---------------------------------------------------------------------------
// Bit readers.

/// Forward, least significant bit first: FSE table descriptions.
struct Fwd<'a> {
    data: &'a [u8],
    bit: usize,
}

impl Fwd<'_> {
    /// `n` (≤ 32) bits from the current position; bits past the end read
    /// as zero, and [`Fwd::bytes_used`] then exceeds the data.
    fn peek(&self, n: u32) -> u32 {
        let (byte, shift) = (self.bit / 8, self.bit % 8);
        let mut w = 0u64;
        for i in 0..5 {
            if let Some(&b) = self.data.get(byte + i) {
                w |= u64::from(b) << (8 * i);
            }
        }
        ((w >> shift) & ((1u64 << n) - 1)) as u32
    }

    fn skip(&mut self, n: u32) {
        self.bit += n as usize;
    }

    fn bytes_used(&self) -> usize {
        self.bit.div_ceil(8)
    }
}

/// Backward: the FSE and Huffman streams, read from the last bit written
/// (just below the end marker) toward the first.
struct Back<'a> {
    data: &'a [u8],
    /// Unread bits: positions `0..pos`, bit `i` being bit `i % 8` of byte
    /// `i / 8`.
    pos: usize,
    /// A read wanted more bits than remained.
    overflow: bool,
}

impl<'a> Back<'a> {
    fn new(data: &'a [u8]) -> Result<Back<'a>> {
        let last = *data.last().ok_or(Error::Truncated)?;
        if last == 0 {
            // No end marker.
            return Err(Error::BadSequences);
        }
        let marker = 7 - last.leading_zeros() as usize;
        Ok(Back { data, pos: (data.len() - 1) * 8 + marker, overflow: false })
    }

    /// The `n` bits at positions `start..start + n` as a little-endian
    /// field (`n` ≤ 32).
    fn field(&self, start: usize, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        let (byte, shift) = (start / 8, start % 8);
        let mut w = 0u64;
        for i in 0..5 {
            if let Some(&b) = self.data.get(byte + i) {
                w |= u64::from(b) << (8 * i);
            }
        }
        (w >> shift) & ((1u64 << n) - 1)
    }

    /// The next `n` bits without consuming them; past the stream's start,
    /// zeros fill the low end.
    fn peek(&self, n: u32) -> u64 {
        let n_us = n as usize;
        if self.pos >= n_us {
            self.field(self.pos - n_us, n)
        } else {
            self.field(0, self.pos as u32) << (n_us - self.pos)
        }
    }

    fn consume(&mut self, n: u32) {
        let n = n as usize;
        if n > self.pos {
            self.overflow = true;
            self.pos = 0;
        } else {
            self.pos -= n;
        }
    }

    fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.consume(n);
        v
    }

    /// Every bit read, and never one more.
    fn exhausted_exactly(&self) -> bool {
        self.pos == 0 && !self.overflow
    }
}

// ---------------------------------------------------------------------------
// FSE.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FseEntry {
    symbol: u8,
    bits: u8,
    base: u16,
}

/// A decoding table of up to `N` states.
#[derive(Clone, Copy)]
struct Fse<const N: usize> {
    e: [FseEntry; N],
    log: u8,
    /// Set this frame: what `Repeat_Mode` may reuse.
    valid: bool,
}

impl<const N: usize> Fse<N> {
    const fn new() -> Fse<N> {
        Fse { e: [FseEntry { symbol: 0, bits: 0, base: 0 }; N], log: 0, valid: false }
    }

    /// The table for a normalised distribution (RFC 8878 §4.1.1).
    fn build(&mut self, norm: &[i16], log: u32) -> Result<()> {
        let size = 1usize << log;
        if size > N || norm.len() > 256 {
            return Err(Error::BadFse);
        }
        let mut next = [0u16; 256];
        let mut high = size - 1;
        let mut low_prob = 0usize;
        for (s, &p) in norm.iter().enumerate() {
            if p == -1 {
                // "Less than one": a row of its own from the end, a full
                // state reset.
                if low_prob >= size {
                    return Err(Error::BadFse);
                }
                self.e[high].symbol = s as u8;
                high = high.wrapping_sub(1);
                low_prob += 1;
                next[s] = 1;
            } else if p < -1 {
                return Err(Error::BadFse);
            } else {
                next[s] = p as u16;
            }
        }
        let high = size - 1 - low_prob;
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut pos = 0usize;
        for (s, &p) in norm.iter().enumerate() {
            for _ in 0..p.max(0) {
                self.e[pos].symbol = s as u8;
                loop {
                    pos = (pos + step) & mask;
                    if pos <= high || low_prob == size {
                        break;
                    }
                }
            }
        }
        if pos != 0 {
            // The probabilities did not fill the table exactly.
            return Err(Error::BadFse);
        }
        for u in 0..size {
            let s = usize::from(self.e[u].symbol);
            let x = next[s];
            if x == 0 {
                return Err(Error::BadFse);
            }
            next[s] = x + 1;
            // Lower states of a symbol take one bit more than higher ones.
            let bits = log.checked_sub(15 - x.leading_zeros()).ok_or(Error::BadFse)?;
            self.e[u].bits = bits as u8;
            self.e[u].base = ((u32::from(x) << bits) - size as u32) as u16;
        }
        self.log = log as u8;
        self.valid = true;
        Ok(())
    }

    /// One symbol forever: `RLE_Mode`.
    fn rle(&mut self, symbol: u8) {
        self.e[0] = FseEntry { symbol, bits: 0, base: 0 };
        self.log = 0;
        self.valid = true;
    }

    fn init(&self, br: &mut Back) -> usize {
        br.read(u32::from(self.log)) as usize
    }

    fn symbol(&self, state: usize) -> u8 {
        self.e[state & (N - 1)].symbol
    }

    fn update(&self, state: usize, br: &mut Back) -> usize {
        let e = self.e[state & (N - 1)];
        usize::from(e.base) + br.read(u32::from(e.bits)) as usize
    }
}

/// Reads an FSE table description (RFC 8878 §4.1.1): fills `norm`, returns
/// (accuracy log, symbols described, bytes consumed).
fn read_distribution(data: &[u8], max_symbol: usize, max_log: u32, norm: &mut [i16; 256]) -> Result<(u32, usize, usize)> {
    let mut r = Fwd { data, bit: 0 };
    let log = r.peek(4) + 5;
    r.skip(4);
    if log > max_log {
        return Err(Error::BadFse);
    }
    let mut remaining: i32 = (1 << log) + 1;
    let mut threshold: i32 = 1 << log;
    let mut bits = log + 1;
    let mut symbol = 0usize;
    let mut previous_zero = false;
    while remaining > 1 {
        if previous_zero {
            // Two-bit repeat flags: how many more zero probabilities follow.
            let mut run = 0usize;
            loop {
                let flag = r.peek(2) as usize;
                r.skip(2);
                run += flag;
                if flag != 3 {
                    break;
                }
                if r.bytes_used() > data.len() {
                    return Err(Error::BadFse);
                }
            }
            if symbol + run > max_symbol + 1 {
                return Err(Error::BadFse);
            }
            for _ in 0..run {
                norm[symbol] = 0;
                symbol += 1;
            }
        }
        if symbol > max_symbol {
            return Err(Error::BadFse);
        }
        // Values below `max` take one bit less.
        let max = (2 * threshold - 1) - remaining;
        let low = r.peek(bits - 1) as i32;
        let value = if low < max {
            r.skip(bits - 1);
            low
        } else {
            let v = r.peek(bits) as i32;
            r.skip(bits);
            if v >= threshold {
                v - max
            } else {
                v
            }
        };
        let p = value - 1;
        remaining -= p.abs();
        norm[symbol] = p as i16;
        symbol += 1;
        previous_zero = p == 0;
        if remaining < 1 {
            return Err(Error::BadFse);
        }
        while remaining < threshold {
            bits -= 1;
            threshold >>= 1;
        }
        if r.bytes_used() > data.len() {
            return Err(Error::BadFse);
        }
    }
    if remaining != 1 {
        return Err(Error::BadFse);
    }
    Ok((log, symbol, r.bytes_used()))
}

// ---------------------------------------------------------------------------
// Huffman.

#[derive(Debug, Clone, Copy, Default)]
struct HufEntry {
    symbol: u8,
    bits: u8,
}

/// The Huffman weights of a tree description: returns (weights described,
/// bytes consumed). The last symbol's weight is not among them.
fn read_weights(data: &[u8], weights: &mut [u8; 256], scratch: &mut Fse<64>) -> Result<(usize, usize)> {
    let header = usize::from(*data.first().ok_or(Error::Truncated)?);
    if header >= 128 {
        // Direct: four bits a weight.
        let n = header - 127;
        let bytes = n.div_ceil(2);
        let src = data.get(1..1 + bytes).ok_or(Error::Truncated)?;
        for i in 0..n {
            let b = src[i / 2];
            weights[i] = if i % 2 == 0 { b >> 4 } else { b & 15 };
        }
        return Ok((n, 1 + bytes));
    }
    // FSE-compressed: two interleaved states over one table.
    let src = data.get(1..1 + header).ok_or(Error::Truncated)?;
    let mut norm = [0i16; 256];
    let (log, symbols, used) = read_distribution(src, 12, 6, &mut norm)?;
    scratch.build(&norm[..symbols], log)?;
    let mut br = Back::new(src.get(used..).ok_or(Error::BadHuffman)?).map_err(|_| Error::BadHuffman)?;
    let mut s1 = scratch.init(&mut br);
    let mut s2 = scratch.init(&mut br);
    if br.overflow {
        return Err(Error::BadHuffman);
    }
    let mut n = 0usize;
    loop {
        if n + 2 > 255 {
            return Err(Error::BadHuffman);
        }
        weights[n] = scratch.symbol(s1);
        n += 1;
        s1 = scratch.update(s1, &mut br);
        if br.overflow {
            weights[n] = scratch.symbol(s2);
            n += 1;
            break;
        }
        weights[n] = scratch.symbol(s2);
        n += 1;
        s2 = scratch.update(s2, &mut br);
        if br.overflow {
            weights[n] = scratch.symbol(s1);
            n += 1;
            break;
        }
    }
    Ok((n, 1 + header))
}

/// Builds the decoding table from the described weights; returns the
/// table's log (the longest code).
fn build_huffman(weights: &mut [u8; 256], described: usize, table: &mut [HufEntry; 1 << HUF_LOG_MAX]) -> Result<u32> {
    if described == 0 || described > 255 {
        return Err(Error::BadHuffman);
    }
    let mut total = 0u32;
    for &w in &weights[..described] {
        if u32::from(w) > HUF_LOG_MAX {
            return Err(Error::BadHuffman);
        }
        if w > 0 {
            total += 1 << (w - 1);
        }
    }
    if total == 0 {
        return Err(Error::BadHuffman);
    }
    // The last weight completes the total to the next power of two.
    let log = 32 - total.leading_zeros();
    if log > HUF_LOG_MAX {
        return Err(Error::BadHuffman);
    }
    let rest = (1u32 << log) - total;
    if !rest.is_power_of_two() {
        return Err(Error::BadHuffman);
    }
    weights[described] = (rest.trailing_zeros() + 1) as u8;
    let symbols = described + 1;
    let mut count = [0u32; 13];
    for &w in &weights[..symbols] {
        count[usize::from(w)] += 1;
    }
    // At least two symbols, and the weight-1 codes pair up.
    if count[1] < 2 || count[1] % 2 != 0 {
        return Err(Error::BadHuffman);
    }
    let mut start = [0u32; 13];
    let mut next = 0u32;
    for w in 1..=log as usize {
        start[w] = next;
        next += count[w] << (w - 1);
    }
    if next != 1 << log {
        return Err(Error::BadHuffman);
    }
    for (s, &w) in weights[..symbols].iter().enumerate() {
        if w == 0 {
            continue;
        }
        let w = usize::from(w);
        let len = 1u32 << (w - 1);
        let at = start[w] as usize;
        for e in &mut table[at..at + len as usize] {
            *e = HufEntry { symbol: s as u8, bits: (log + 1 - w as u32) as u8 };
        }
        start[w] += len;
    }
    Ok(log)
}

fn huffman_stream(table: &[HufEntry; 1 << HUF_LOG_MAX], log: u32, src: &[u8], out: &mut [u8]) -> Result<()> {
    let mut br = Back::new(src).map_err(|_| Error::BadHuffman)?;
    for o in out.iter_mut() {
        let e = table[br.peek(log) as usize];
        *o = e.symbol;
        br.consume(u32::from(e.bits));
        if br.overflow {
            return Err(Error::BadHuffman);
        }
    }
    if !br.exhausted_exactly() {
        return Err(Error::BadHuffman);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// XXH64, for the content checksum.

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

fn le64(b: &[u8]) -> u64 {
    let mut w = 0u64;
    for (i, &x) in b.iter().take(8).enumerate() {
        w |= u64::from(x) << (8 * i);
    }
    w
}

fn xxh_round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1)
}

fn xxh_merge(acc: u64, v: u64) -> u64 {
    (acc ^ xxh_round(0, v)).wrapping_mul(P1).wrapping_add(P4)
}

/// XXH64 with seed 0.
pub fn xxh64(data: &[u8]) -> u64 {
    let mut rest = data;
    let mut h = if data.len() >= 32 {
        let mut v = [P1.wrapping_add(P2), P2, 0, 0u64.wrapping_sub(P1)];
        while rest.len() >= 32 {
            for (i, lane) in v.iter_mut().enumerate() {
                *lane = xxh_round(*lane, le64(&rest[8 * i..]));
            }
            rest = &rest[32..];
        }
        let mut h = v[0].rotate_left(1).wrapping_add(v[1].rotate_left(7)).wrapping_add(v[2].rotate_left(12)).wrapping_add(v[3].rotate_left(18));
        for lane in v {
            h = xxh_merge(h, lane);
        }
        h
    } else {
        P5
    };
    h = h.wrapping_add(data.len() as u64);
    while rest.len() >= 8 {
        h ^= xxh_round(0, le64(rest));
        h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        rest = &rest[8..];
    }
    if rest.len() >= 4 {
        let k = u64::from(u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]));
        h ^= k.wrapping_mul(P1);
        h = h.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
        rest = &rest[4..];
    }
    for &b in rest {
        h ^= u64::from(b).wrapping_mul(P5);
        h = h.rotate_left(11).wrapping_mul(P1);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^ (h >> 32)
}

// ---------------------------------------------------------------------------
// Frames and blocks.

/// What a frame header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// The decompressed size, when the frame states it.
    pub content_size: Option<u64>,
    /// The farthest back a match may reach.
    pub window: u64,
    pub checksum: bool,
    /// The header's length, magic number included.
    pub header_len: usize,
}

/// Parses the header of the frame at the start of `input`.
pub fn frame_header(input: &[u8]) -> Result<FrameHeader> {
    let magic = input.get(..4).ok_or(Error::Truncated)?;
    if u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]]) != MAGIC {
        return Err(Error::BadMagic);
    }
    let fhd = *input.get(4).ok_or(Error::Truncated)?;
    let single = fhd & 0x20 != 0;
    if fhd & 0x08 != 0 {
        return Err(Error::Reserved);
    }
    let mut at = 5;
    let mut window = 0u64;
    if !single {
        let wd = *input.get(at).ok_or(Error::Truncated)?;
        at += 1;
        let log = 10 + u32::from(wd >> 3);
        let base = 1u64 << log;
        window = base + (base / 8) * u64::from(wd & 7);
    }
    let did_len = [0usize, 1, 2, 4][usize::from(fhd & 3)];
    let did = input.get(at..at + did_len).ok_or(Error::Truncated)?;
    if did.iter().any(|&b| b != 0) {
        return Err(Error::Dictionary);
    }
    at += did_len;
    let fcs_len = match fhd >> 6 {
        0 if single => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let content_size = if fcs_len == 0 {
        None
    } else {
        let f = input.get(at..at + fcs_len).ok_or(Error::Truncated)?;
        at += fcs_len;
        let v = le64(f);
        Some(if fcs_len == 2 { v + 256 } else { v })
    };
    if single {
        window = content_size.unwrap_or(0);
    }
    Ok(FrameHeader { content_size, window, checksum: fhd & 0x04 != 0, header_len: at })
}

/// Where a block's literals are.
#[derive(Clone, Copy)]
enum Lit<'a> {
    Slice(&'a [u8]),
    Rle(u8, usize),
    /// Decoded into `out[start..start + len]`.
    Tail(usize, usize),
}

/// The decoder's tables: about 10 KiB, kept between blocks of a frame.
#[derive(Clone)]
pub struct Workspace {
    huf: [HufEntry; 1 << HUF_LOG_MAX],
    huf_log: u32,
    ll: Fse<512>,
    of: Fse<256>,
    ml: Fse<512>,
    scratch: Fse<64>,
    rep: [usize; 3],
}

impl core::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("zstd::Workspace")
    }
}

impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}

impl Workspace {
    pub const fn new() -> Workspace {
        Workspace {
            huf: [HufEntry { symbol: 0, bits: 0 }; 1 << HUF_LOG_MAX],
            huf_log: 0,
            ll: Fse::new(),
            of: Fse::new(),
            ml: Fse::new(),
            scratch: Fse::new(),
            rep: [1, 4, 8],
        }
    }

    fn reset(&mut self) {
        self.huf_log = 0;
        self.ll.valid = false;
        self.of.valid = false;
        self.ml.valid = false;
        self.rep = [1, 4, 8];
    }

    /// Decompresses every frame in `input` (skippable frames skipped) into
    /// `out`; returns the bytes written.
    pub fn decompress_into(&mut self, input: &[u8], out: &mut [u8]) -> Result<usize> {
        if input.is_empty() {
            return Err(Error::Truncated);
        }
        let (mut ip, mut op) = (0usize, 0usize);
        while ip < input.len() {
            let m = input.get(ip..ip + 4).ok_or(Error::Truncated)?;
            let magic = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
            if magic & 0xFFFF_FFF0 == SKIPPABLE {
                let s = input.get(ip + 4..ip + 8).ok_or(Error::Truncated)?;
                let size = u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize;
                ip = (ip + 8).checked_add(size).filter(|&e| e <= input.len()).ok_or(Error::Truncated)?;
                continue;
            }
            let (used, written) = self.frame(&input[ip..], out, op)?;
            ip += used;
            op += written;
        }
        Ok(op)
    }

    /// One frame at the start of `input`, written from `out[base..]`;
    /// returns (input used, bytes written).
    fn frame(&mut self, input: &[u8], out: &mut [u8], base: usize) -> Result<(usize, usize)> {
        let h = frame_header(input)?;
        self.reset();
        let block_max = (h.window.min(BLOCK_MAX as u64)) as usize;
        let mut ip = h.header_len;
        let mut op = base;
        loop {
            let bh = input.get(ip..ip + 3).ok_or(Error::Truncated)?;
            let bh = u32::from(bh[0]) | u32::from(bh[1]) << 8 | u32::from(bh[2]) << 16;
            ip += 3;
            let last = bh & 1 != 0;
            let size = (bh >> 3) as usize;
            if size > block_max {
                return Err(Error::BadBlock);
            }
            match (bh >> 1) & 3 {
                0 => {
                    let src = input.get(ip..ip + size).ok_or(Error::Truncated)?;
                    out.get_mut(op..op + size).ok_or(Error::Overflow)?.copy_from_slice(src);
                    ip += size;
                    op += size;
                }
                1 => {
                    let b = *input.get(ip).ok_or(Error::Truncated)?;
                    out.get_mut(op..op + size).ok_or(Error::Overflow)?.fill(b);
                    ip += 1;
                    op += size;
                }
                2 => {
                    let src = input.get(ip..ip + size).ok_or(Error::Truncated)?;
                    let written = self.block(src, out, base, op, h.window)?;
                    if written > block_max {
                        return Err(Error::BadBlock);
                    }
                    ip += size;
                    op += written;
                }
                _ => return Err(Error::Reserved),
            }
            if last {
                break;
            }
        }
        let produced = op - base;
        if let Some(size) = h.content_size {
            if produced as u64 != size {
                return Err(if (produced as u64) < size { Error::Short } else { Error::Overflow });
            }
        }
        if h.checksum {
            let c = input.get(ip..ip + 4).ok_or(Error::Truncated)?;
            let want = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            if xxh64(&out[base..op]) as u32 != want {
                return Err(Error::Checksum);
            }
            ip += 4;
        }
        Ok((ip, produced))
    }

    /// The literals section: where the literals are, and its length.
    fn literals<'a>(&mut self, blk: &'a [u8], out: &mut [u8], op: usize) -> Result<(Lit<'a>, usize)> {
        let b = |i: usize| blk.get(i).copied().map(u32::from).ok_or(Error::Truncated);
        let b0 = b(0)?;
        let kind = b0 & 3;
        let format = (b0 >> 2) & 3;
        if kind < 2 {
            let (size, hlen) = match format {
                0 | 2 => (b0 >> 3, 1),
                1 => ((b0 >> 4) | b(1)? << 4, 2),
                _ => ((b0 >> 4) | b(1)? << 4 | b(2)? << 12, 3),
            };
            let size = size as usize;
            if size > BLOCK_MAX {
                return Err(Error::BadLiterals);
            }
            return if kind == 0 {
                let s = blk.get(hlen..hlen + size).ok_or(Error::Truncated)?;
                Ok((Lit::Slice(s), hlen + size))
            } else {
                let v = *blk.get(hlen).ok_or(Error::Truncated)?;
                Ok((Lit::Rle(v, size), hlen + 1))
            };
        }
        let (regen, csize, hlen, four) = match format {
            0 | 1 => {
                let h = b0 | b(1)? << 8 | b(2)? << 16;
                ((h >> 4) & 0x3FF, (h >> 14) & 0x3FF, 3, format == 1)
            }
            2 => {
                let h = b0 | b(1)? << 8 | b(2)? << 16 | b(3)? << 24;
                ((h >> 4) & 0x3FFF, (h >> 18) & 0x3FFF, 4, true)
            }
            _ => {
                let h = u64::from(b0) | u64::from(b(1)?) << 8 | u64::from(b(2)?) << 16 | u64::from(b(3)?) << 24 | u64::from(b(4)?) << 32;
                (((h >> 4) & 0x3FFFF) as u32, ((h >> 22) & 0x3FFFF) as u32, 5, true)
            }
        };
        let (regen, csize) = (regen as usize, csize as usize);
        if regen > BLOCK_MAX || csize == 0 || (four && regen < 6) {
            return Err(Error::BadLiterals);
        }
        let data = blk.get(hlen..hlen + csize).ok_or(Error::Truncated)?;
        let mut at = 0;
        if kind == 2 {
            let mut weights = [0u8; 256];
            let (described, used) = read_weights(data, &mut weights, &mut self.scratch)?;
            self.huf_log = build_huffman(&mut weights, described, &mut self.huf)?;
            at = used;
        } else if self.huf_log == 0 {
            // Treeless, with no tree yet in this frame.
            return Err(Error::BadLiterals);
        }
        // The literals go to the unused end of the output.
        let start = out.len().checked_sub(regen).filter(|&s| s >= op).ok_or(Error::Overflow)?;
        let dst = &mut out[start..];
        let streams = &data[at..];
        if !four {
            huffman_stream(&self.huf, self.huf_log, streams, dst)?;
        } else {
            let jt = streams.get(..6).ok_or(Error::Truncated)?;
            let s1 = usize::from(u16::from_le_bytes([jt[0], jt[1]]));
            let s2 = usize::from(u16::from_le_bytes([jt[2], jt[3]]));
            let s3 = usize::from(u16::from_le_bytes([jt[4], jt[5]]));
            let total = streams.len().checked_sub(6).ok_or(Error::BadLiterals)?;
            let s4 = total.checked_sub(s1 + s2 + s3).filter(|&s| s >= 1).ok_or(Error::BadLiterals)?;
            let seg = regen.div_ceil(4);
            let mut src_at = 6;
            let mut dst_at = 0;
            for (i, len) in [s1, s2, s3, s4].into_iter().enumerate() {
                let n = if i < 3 { seg } else { regen - 3 * seg };
                huffman_stream(&self.huf, self.huf_log, &streams[src_at..src_at + len], &mut dst[dst_at..dst_at + n])?;
                src_at += len;
                dst_at += n;
            }
        }
        Ok((Lit::Tail(start, regen), hlen + csize))
    }

    /// One table of the sequences section; returns the bytes it used.
    fn table(&mut self, which: u8, mode: u8, data: &[u8]) -> Result<usize> {
        let (max_symbol, max_log, default, default_log): (usize, u32, &[i16], u32) = match which {
            0 => (35, 9, &LL_DEFAULT, 6),
            1 => (usize::from(OFFSET_CODE_MAX), 8, &OF_DEFAULT, 5),
            _ => (52, 9, &ML_DEFAULT, 6),
        };
        let mut norm = [0i16; 256];
        let (used, built): (usize, Option<(usize, u32)>) = match mode {
            0 => {
                norm[..default.len()].copy_from_slice(default);
                (0, Some((default.len(), default_log)))
            }
            1 => {
                let s = *data.first().ok_or(Error::Truncated)?;
                if usize::from(s) > max_symbol {
                    return Err(Error::BadSequences);
                }
                match which {
                    0 => self.ll.rle(s),
                    1 => self.of.rle(s),
                    _ => self.ml.rle(s),
                }
                (1, None)
            }
            2 => {
                let (log, symbols, used) = read_distribution(data, max_symbol, max_log, &mut norm)?;
                (used, Some((symbols, log)))
            }
            _ => {
                let valid = match which {
                    0 => self.ll.valid,
                    1 => self.of.valid,
                    _ => self.ml.valid,
                };
                if !valid {
                    return Err(Error::BadSequences);
                }
                (0, None)
            }
        };
        if let Some((symbols, log)) = built {
            match which {
                0 => self.ll.build(&norm[..symbols], log)?,
                1 => self.of.build(&norm[..symbols], log)?,
                _ => self.ml.build(&norm[..symbols], log)?,
            }
        }
        Ok(used)
    }

    /// One compressed block, written at `out[op..]` (the frame began at
    /// `base`); returns the bytes written.
    fn block(&mut self, blk: &[u8], out: &mut [u8], base: usize, op: usize, window: u64) -> Result<usize> {
        let (lit, lit_len) = self.literals(blk, out, op)?;
        let seq = &blk[lit_len..];
        let b0 = usize::from(*seq.first().ok_or(Error::Truncated)?);
        let (count, mut at) = match b0 {
            0..=127 => (b0, 1),
            128..=254 => (((b0 - 128) << 8) + usize::from(*seq.get(1).ok_or(Error::Truncated)?), 2),
            _ => (usize::from(*seq.get(1).ok_or(Error::Truncated)?) + (usize::from(*seq.get(2).ok_or(Error::Truncated)?) << 8) + 0x7F00, 3),
        };
        let mut w = Exec { out, op, base, window, lit, lit_at: 0 };
        if count == 0 {
            if at != seq.len() {
                return Err(Error::BadSequences);
            }
        } else {
            let modes = *seq.get(at).ok_or(Error::Truncated)?;
            at += 1;
            if modes & 3 != 0 {
                return Err(Error::Reserved);
            }
            for (which, shift) in [(0u8, 6u8), (1, 4), (2, 2)] {
                at += self.table(which, (modes >> shift) & 3, &seq[at..])?;
            }
            let mut br = Back::new(seq.get(at..).filter(|s| !s.is_empty()).ok_or(Error::Truncated)?)?;
            let mut lls = self.ll.init(&mut br);
            let mut ofs = self.of.init(&mut br);
            let mut mls = self.ml.init(&mut br);
            for i in 0..count {
                let ofc = self.of.symbol(ofs);
                let llc = usize::from(self.ll.symbol(lls));
                let mlc = usize::from(self.ml.symbol(mls));
                if ofc > OFFSET_CODE_MAX || llc >= LL_BASE.len() || mlc >= ML_BASE.len() {
                    return Err(Error::BadSequences);
                }
                let offset_value = (1usize << ofc) + br.read(u32::from(ofc)) as usize;
                let ml = ML_BASE[mlc] as usize + br.read(u32::from(ML_BITS[mlc])) as usize;
                let ll = LL_BASE[llc] as usize + br.read(u32::from(LL_BITS[llc])) as usize;
                if i + 1 < count {
                    lls = self.ll.update(lls, &mut br);
                    mls = self.ml.update(mls, &mut br);
                    ofs = self.of.update(ofs, &mut br);
                }
                if br.overflow {
                    return Err(Error::BadSequences);
                }
                let offset = self.offset(offset_value, ll)?;
                w.literals(ll)?;
                w.copy_match(offset, ml)?;
            }
            if !br.exhausted_exactly() {
                return Err(Error::BadSequences);
            }
        }
        let left = w.lit_len() - w.lit_at;
        w.literals(left)?;
        Ok(w.op - op)
    }

    /// Resolves an offset value against the repeat offsets (RFC 8878
    /// §3.1.2.5) and updates them.
    fn offset(&mut self, value: usize, ll: usize) -> Result<usize> {
        let r = &mut self.rep;
        if value > 3 {
            let o = value - 3;
            *r = [o, r[0], r[1]];
            return Ok(o);
        }
        // With no literals before the match, the codes shift by one.
        let index = if ll == 0 { value } else { value - 1 };
        let o = match index {
            0 => r[0],
            1 => {
                let o = r[1];
                *r = [o, r[0], r[2]];
                o
            }
            2 => {
                let o = r[2];
                *r = [o, r[0], r[1]];
                o
            }
            _ => {
                let o = r[0].checked_sub(1).filter(|&o| o > 0).ok_or(Error::BadOffset)?;
                *r = [o, r[0], r[1]];
                o
            }
        };
        Ok(o)
    }
}

/// Sequence execution over the output buffer.
struct Exec<'a, 'b> {
    out: &'b mut [u8],
    op: usize,
    base: usize,
    window: u64,
    lit: Lit<'a>,
    lit_at: usize,
}

impl Exec<'_, '_> {
    fn lit_len(&self) -> usize {
        match self.lit {
            Lit::Slice(s) => s.len(),
            Lit::Rle(_, n) => n,
            Lit::Tail(_, n) => n,
        }
    }

    fn literals(&mut self, n: usize) -> Result<()> {
        if n > self.lit_len() - self.lit_at {
            return Err(Error::BadSequences);
        }
        let end = self.op.checked_add(n).filter(|&e| e <= self.out.len()).ok_or(Error::Overflow)?;
        match self.lit {
            Lit::Slice(s) => self.out[self.op..end].copy_from_slice(&s[self.lit_at..self.lit_at + n]),
            Lit::Rle(v, _) => self.out[self.op..end].fill(v),
            // A memmove: the literals sit at or after where they land.
            Lit::Tail(start, _) => self.out.copy_within(start + self.lit_at..start + self.lit_at + n, self.op),
        }
        self.lit_at += n;
        self.op = end;
        Ok(())
    }

    fn copy_match(&mut self, offset: usize, n: usize) -> Result<()> {
        if offset > self.op - self.base || offset as u64 > self.window {
            return Err(Error::BadOffset);
        }
        let end = self.op.checked_add(n).filter(|&e| e <= self.out.len()).ok_or(Error::Overflow)?;
        // Matches must not run into literals not yet copied.
        if let Lit::Tail(start, _) = self.lit {
            if end > start + self.lit_at {
                return Err(Error::Overflow);
            }
        }
        let from = self.op - offset;
        if offset >= n {
            self.out.copy_within(from..from + n, self.op);
        } else {
            for i in 0..n {
                self.out[self.op + i] = self.out[from + i];
            }
        }
        self.op = end;
        Ok(())
    }
}

/// Decompresses every frame in `input` into `out` with a workspace on the
/// stack; returns the bytes written.
pub fn decompress_into(input: &[u8], out: &mut [u8]) -> Result<usize> {
    Workspace::new().decompress_into(input, out)
}

/// Decompresses into a buffer that must be filled exactly: an extent of a
/// known size.
pub fn decompress_exact(input: &[u8], out: &mut [u8]) -> Result<()> {
    match decompress_into(input, out)? {
        n if n == out.len() => Ok(()),
        _ => Err(Error::Short),
    }
}

#[cfg(test)]
mod tests;
