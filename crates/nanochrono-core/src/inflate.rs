// SPDX-License-Identifier: Apache-2.0
//! DEFLATE decoding (RFC 1951), for the compressed files inside a `.ncpkg`.
//!
//! # Why the kernel carries an inflater after all
//!
//! The wallpapers chose QOI precisely to keep DEFLATE out of ring 0
//! ([`crate::qoi`]): for a picture there was a choice. A package has none —
//! it carries code for nine architectures, and code is what DEFLATE was made
//! for. So this decoder is written the way that module asked for: from the
//! RFC, for untrusted input, in safe Rust with every read checked, never
//! panicking, with its output bounded by the caller — a buffer of exactly
//! the size the manifest declares, or a byte budget — so a "zip bomb" ends
//! with [`Error::Overflow`] the moment it exceeds what was promised. The
//! hosted test build throws tens of thousands of corrupted streams at it.
//!
//! Two ways out, sharing one decoder:
//!
//! * [`inflate_into`]: into a flat buffer, which doubles as the window.
//! * [`inflate_to`]: through a 32 KiB window the caller lends, flushed to a
//!   sink as it fills — for files larger than any buffer the caller has,
//!   hashed or written as they decode.
//!
//! Both are strict about the end: the final block must end in the last
//! input byte. Data after the stream is an error, not ignored.
//!
//! Huffman codes decode through a 10-bit lookup table, with the canonical
//! code walk (RFC 1951 §3.2.2) for the rare longer codes.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// The largest distance a DEFLATE stream may reach back.
pub const WINDOW: usize = 32 * 1024;

/// Why a stream was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input ended inside the stream.
    Truncated,
    /// Block type 3, or a stored block whose length check fails.
    BadBlock,
    /// A code table that is over-subscribed, incomplete where that is not
    /// allowed, has too many lengths, or has no end-of-block code.
    BadCode,
    /// Bits that decode to no symbol, or a length/distance symbol out of
    /// range.
    BadSymbol,
    /// A distance reaching back before the start of the output.
    TooFar,
    /// More output than the caller allowed.
    Overflow,
    /// The sink refused the output.
    Sink,
    /// Input after the end of the final block.
    Trailing,
}

impl Error {
    pub const fn message(self) -> &'static str {
        match self {
            Error::Truncated => "compressed data ends early",
            Error::BadBlock => "bad DEFLATE block",
            Error::BadCode => "bad Huffman code table",
            Error::BadSymbol => "bad Huffman symbol",
            Error::TooFar => "a back-reference reaches before the start",
            Error::Overflow => "decompresses to more than declared",
            Error::Sink => "the output was refused",
            Error::Trailing => "data after the end of the compressed stream",
        }
    }
}

/// Decompresses `input` into `out` and returns the number of bytes written.
/// The stream must end exactly at the end of `input`.
pub fn inflate_into(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let (n, used) = inflate_into_prefix(input, out)?;
    if used != input.len() {
        return Err(Error::Trailing);
    }
    Ok(n)
}

/// Decompresses the DEFLATE stream at the start of `input` into `out`, and
/// returns the bytes written and the bytes of `input` the stream occupied —
/// for formats that carry something after it (zlib's Adler-32, in PNG).
pub fn inflate_into_prefix(input: &[u8], out: &mut [u8]) -> Result<(usize, usize), Error> {
    let mut flat = Flat { buf: out, n: 0 };
    let used = decode_prefix(input, &mut flat)?;
    Ok((flat.n, used))
}

/// Decompresses `input` through `window`, handing the output to `sink` in
/// pieces of up to [`WINDOW`] bytes, and returns the total. More than
/// `max_out` bytes is [`Error::Overflow`]; `sink` returning `false` stops
/// with [`Error::Sink`].
pub fn inflate_to(
    input: &[u8],
    window: &mut [u8; WINDOW],
    max_out: u64,
    sink: &mut dyn FnMut(&[u8]) -> bool,
) -> Result<u64, Error> {
    let mut ring = Ring { win: window, n: 0, max: max_out, sink };
    decode(input, &mut ring)?;
    ring.flush_tail()?;
    Ok(ring.n)
}

/// Decompresses `input` into a new buffer that must come out exactly `size`
/// bytes long.
#[cfg(feature = "alloc")]
pub fn inflate_vec(input: &[u8], size: usize) -> Result<Vec<u8>, Error> {
    let mut out = alloc::vec![0u8; size];
    let n = inflate_into(input, &mut out)?;
    if n != size {
        return Err(Error::Truncated);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

trait Output {
    fn put(&mut self, b: u8) -> Result<(), Error>;
    fn put_slice(&mut self, s: &[u8]) -> Result<(), Error> {
        for &b in s {
            self.put(b)?;
        }
        Ok(())
    }
    /// Copies `len` bytes from `dist` back; `dist` may be shorter than
    /// `len` (the copy then repeats itself, as DEFLATE intends).
    fn copy(&mut self, dist: usize, len: usize) -> Result<(), Error>;
}

struct Flat<'a> {
    buf: &'a mut [u8],
    n: usize,
}

impl Output for Flat<'_> {
    fn put(&mut self, b: u8) -> Result<(), Error> {
        *self.buf.get_mut(self.n).ok_or(Error::Overflow)? = b;
        self.n += 1;
        Ok(())
    }

    fn put_slice(&mut self, s: &[u8]) -> Result<(), Error> {
        let end = self.n.checked_add(s.len()).ok_or(Error::Overflow)?;
        self.buf.get_mut(self.n..end).ok_or(Error::Overflow)?.copy_from_slice(s);
        self.n = end;
        Ok(())
    }

    fn copy(&mut self, dist: usize, len: usize) -> Result<(), Error> {
        if dist == 0 || dist > self.n {
            return Err(Error::TooFar);
        }
        let end = self.n.checked_add(len).ok_or(Error::Overflow)?;
        if end > self.buf.len() {
            return Err(Error::Overflow);
        }
        if dist >= len {
            let from = self.n - dist;
            self.buf.copy_within(from..from + len, self.n);
        } else {
            for i in self.n..end {
                self.buf[i] = self.buf[i - dist];
            }
        }
        self.n = end;
        Ok(())
    }
}

struct Ring<'a, 's> {
    win: &'a mut [u8; WINDOW],
    /// Bytes produced so far.
    n: u64,
    max: u64,
    sink: &'s mut dyn FnMut(&[u8]) -> bool,
}

impl Ring<'_, '_> {
    fn flush_tail(&mut self) -> Result<(), Error> {
        let fill = (self.n % WINDOW as u64) as usize;
        if fill > 0 && !(self.sink)(&self.win[..fill]) {
            return Err(Error::Sink);
        }
        Ok(())
    }
}

impl Output for Ring<'_, '_> {
    fn put(&mut self, b: u8) -> Result<(), Error> {
        if self.n >= self.max {
            return Err(Error::Overflow);
        }
        let at = (self.n % WINDOW as u64) as usize;
        self.win[at] = b;
        self.n += 1;
        if self.n % WINDOW as u64 == 0 && !(self.sink)(&self.win[..]) {
            return Err(Error::Sink);
        }
        Ok(())
    }

    fn copy(&mut self, dist: usize, len: usize) -> Result<(), Error> {
        if dist == 0 || dist > WINDOW || dist as u64 > self.n {
            return Err(Error::TooFar);
        }
        for _ in 0..len {
            // Read before the write: at `dist == WINDOW` the source is the
            // very slot this byte replaces.
            let at = ((self.n - dist as u64) % WINDOW as u64) as usize;
            let b = self.win[at];
            self.put(b)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bits
// ---------------------------------------------------------------------------

struct Bits<'a> {
    input: &'a [u8],
    /// Next input byte not yet in `buf`.
    pos: usize,
    buf: u64,
    count: u32,
}

impl<'a> Bits<'a> {
    fn new(input: &'a [u8]) -> Self {
        Bits { input, pos: 0, buf: 0, count: 0 }
    }

    /// Tops the buffer up to at least 56 bits, or with all remaining input.
    fn refill(&mut self) {
        while self.count <= 56 {
            let Some(&b) = self.input.get(self.pos) else { break };
            self.buf |= u64::from(b) << self.count;
            self.pos += 1;
            self.count += 8;
        }
    }

    fn bits(&mut self, n: u32) -> Result<u32, Error> {
        if n == 0 {
            return Ok(0);
        }
        if self.count < n {
            self.refill();
            if self.count < n {
                return Err(Error::Truncated);
            }
        }
        let v = (self.buf & ((1u64 << n) - 1)) as u32;
        self.buf >>= n;
        self.count -= n;
        Ok(v)
    }

    /// Up to 15 bits without consuming them, and how many are real.
    fn peek15(&mut self) -> (u32, u32) {
        if self.count < 15 {
            self.refill();
        }
        ((self.buf & 0x7FFF) as u32, self.count.min(15))
    }

    fn consume(&mut self, n: u32) {
        self.buf >>= n;
        self.count -= n;
    }

    /// Drops the rest of the current byte and hands back whole bytes the
    /// buffer read ahead, so `pos` is the next byte of the stream.
    fn align(&mut self) {
        let partial = self.count % 8;
        self.buf >>= partial;
        self.count -= partial;
        self.pos -= (self.count / 8) as usize;
        self.buf = 0;
        self.count = 0;
    }
}

// ---------------------------------------------------------------------------
// Huffman codes
// ---------------------------------------------------------------------------

const MAX_BITS: usize = 15;
const FAST_BITS: u32 = 10;
const MAX_LIT: usize = 288;

struct Huffman {
    /// Codes of each length.
    count: [u16; MAX_BITS + 1],
    /// Symbols in canonical code order.
    symbol: [u16; MAX_LIT],
    /// Indexed by the next `FAST_BITS` stream bits: `(len << 9) | symbol`
    /// for a code of at most `FAST_BITS` bits, 0 for "walk the code".
    fast: [u16; 1 << FAST_BITS],
}

/// How a code table turned out.
#[derive(PartialEq, Eq)]
enum Fill {
    Complete,
    /// Some codes unused. Fine for a single code of length one.
    Incomplete,
    OverSubscribed,
}

impl Huffman {
    fn new() -> Self {
        Huffman { count: [0; MAX_BITS + 1], symbol: [0; MAX_LIT], fast: [0; 1 << FAST_BITS] }
    }

    /// Builds the canonical code for `lengths` (one per symbol, 0 = unused).
    fn build(&mut self, lengths: &[u8]) -> Fill {
        self.count = [0; MAX_BITS + 1];
        self.fast = [0; 1 << FAST_BITS];
        for &l in lengths {
            self.count[usize::from(l)] += 1;
        }
        if usize::from(self.count[0]) == lengths.len() {
            // No codes at all: complete, and any decode fails.
            return Fill::Complete;
        }
        let mut left: i32 = 1;
        for len in 1..=MAX_BITS {
            left <<= 1;
            left -= i32::from(self.count[len]);
            if left < 0 {
                return Fill::OverSubscribed;
            }
        }
        let mut offs = [0u16; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            offs[len + 1] = offs[len] + self.count[len];
        }
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                let slot = &mut offs[usize::from(l)];
                self.symbol[usize::from(*slot)] = sym as u16;
                *slot += 1;
            }
        }
        // The fast table: each code of at most FAST_BITS bits, bit-reversed
        // (codes are sent most significant bit first, the stream is read
        // least significant first), repeated under every longer suffix.
        let mut code: u32 = 0;
        let mut index = 0usize;
        for len in 1..=MAX_BITS as u32 {
            for _ in 0..self.count[len as usize] {
                if len <= FAST_BITS {
                    let rev = code.reverse_bits() >> (32 - len);
                    let entry = ((len as u16) << 9) | self.symbol[index];
                    let mut i = rev as usize;
                    while i < self.fast.len() {
                        self.fast[i] = entry;
                        i += 1 << len;
                    }
                }
                code += 1;
                index += 1;
            }
            code <<= 1;
        }
        if left > 0 {
            Fill::Incomplete
        } else {
            Fill::Complete
        }
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, Error> {
        let (peek, avail) = bits.peek15();
        let entry = self.fast[(peek & ((1 << FAST_BITS) - 1)) as usize];
        if entry != 0 {
            let len = u32::from(entry >> 9);
            if len > avail {
                return Err(Error::Truncated);
            }
            bits.consume(len);
            return Ok(entry & 0x1FF);
        }
        // The canonical walk, one bit at a time.
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=MAX_BITS as u32 {
            if len > avail {
                return Err(Error::Truncated);
            }
            code |= ((peek >> (len - 1)) & 1) as i32;
            let count = i32::from(self.count[len as usize]);
            if code - first < count {
                bits.consume(len);
                let at = usize::try_from(index + code - first).map_err(|_| Error::BadSymbol)?;
                return self.symbol.get(at).copied().ok_or(Error::BadSymbol);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(Error::BadSymbol)
    }
}

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
/// The order the code-length code's lengths are sent in.
const CLEN_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

fn decode(input: &[u8], out: &mut dyn Output) -> Result<(), Error> {
    if decode_prefix(input, out)? != input.len() {
        return Err(Error::Trailing);
    }
    Ok(())
}

/// Decodes one stream and returns how many input bytes it occupied.
fn decode_prefix(input: &[u8], out: &mut dyn Output) -> Result<usize, Error> {
    let mut bits = Bits::new(input);
    let mut lit = Huffman::new();
    let mut dist = Huffman::new();
    loop {
        let last = bits.bits(1)? == 1;
        match bits.bits(2)? {
            0 => stored(&mut bits, out)?,
            1 => {
                fixed_tables(&mut lit, &mut dist);
                codes(&mut bits, out, &lit, &dist)?;
            }
            2 => {
                dynamic_tables(&mut bits, &mut lit, &mut dist)?;
                codes(&mut bits, out, &lit, &dist)?;
            }
            _ => return Err(Error::BadBlock),
        }
        if last {
            break;
        }
    }
    // The final block ends in its last byte: whatever bits remain belong to
    // that byte's padding.
    bits.align();
    Ok(bits.pos)
}

fn stored(bits: &mut Bits<'_>, out: &mut dyn Output) -> Result<(), Error> {
    bits.align();
    let at = bits.pos;
    let head = bits.input.get(at..at + 4).ok_or(Error::Truncated)?;
    let len = u16::from_le_bytes([head[0], head[1]]);
    let nlen = u16::from_le_bytes([head[2], head[3]]);
    if len != !nlen {
        return Err(Error::BadBlock);
    }
    let body = bits.input.get(at + 4..at + 4 + usize::from(len)).ok_or(Error::Truncated)?;
    out.put_slice(body)?;
    bits.pos = at + 4 + usize::from(len);
    Ok(())
}

fn fixed_tables(lit: &mut Huffman, dist: &mut Huffman) {
    let mut lengths = [0u8; MAX_LIT];
    lengths[..144].fill(8);
    lengths[144..256].fill(9);
    lengths[256..280].fill(7);
    lengths[280..].fill(8);
    lit.build(&lengths);
    dist.build(&[5u8; 30]);
}

fn dynamic_tables(bits: &mut Bits<'_>, lit: &mut Huffman, dist: &mut Huffman) -> Result<(), Error> {
    let nlen = bits.bits(5)? as usize + 257;
    let ndist = bits.bits(5)? as usize + 1;
    let ncode = bits.bits(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Err(Error::BadCode);
    }
    let mut lengths = [0u8; 286 + 30];
    for &slot in CLEN_ORDER.iter().take(ncode) {
        lengths[slot] = bits.bits(3)? as u8;
    }
    let mut clen = Huffman::new();
    // The code-length code must be complete.
    if clen.build(&lengths[..19]) != Fill::Complete {
        return Err(Error::BadCode);
    }
    let total = nlen + ndist;
    let mut index = 0;
    lengths = [0u8; 286 + 30];
    while index < total {
        let sym = clen.decode(bits)?;
        if sym < 16 {
            lengths[index] = sym as u8;
            index += 1;
            continue;
        }
        let (value, repeat) = match sym {
            16 => {
                let prev = *lengths.get(index.wrapping_sub(1)).ok_or(Error::BadCode)?;
                if index == 0 {
                    return Err(Error::BadCode);
                }
                (prev, 3 + bits.bits(2)? as usize)
            }
            17 => (0, 3 + bits.bits(3)? as usize),
            18 => (0, 11 + bits.bits(7)? as usize),
            _ => return Err(Error::BadSymbol),
        };
        if index + repeat > total {
            return Err(Error::BadCode);
        }
        lengths[index..index + repeat].fill(value);
        index += repeat;
    }
    // Without an end-of-block code no block can end.
    if lengths[256] == 0 {
        return Err(Error::BadCode);
    }
    // An incomplete code is allowed only when it is a single code of length
    // one (RFC 1951 §3.2.7 permits one distance code; zlib extends that to
    // the literal/length code).
    let usable = |h: &Huffman, n: usize, fill: Fill| match fill {
        Fill::Complete => true,
        Fill::Incomplete => usize::from(h.count[0]) + usize::from(h.count[1]) == n,
        Fill::OverSubscribed => false,
    };
    let fill = lit.build(&lengths[..nlen]);
    if !usable(lit, nlen, fill) {
        return Err(Error::BadCode);
    }
    let fill = dist.build(&lengths[nlen..total]);
    if !usable(dist, ndist, fill) {
        return Err(Error::BadCode);
    }
    Ok(())
}

fn codes(bits: &mut Bits<'_>, out: &mut dyn Output, lit: &Huffman, dist: &Huffman) -> Result<(), Error> {
    loop {
        let sym = usize::from(lit.decode(bits)?);
        match sym {
            0..=255 => out.put(sym as u8)?,
            256 => return Ok(()),
            _ => {
                let s = sym - 257;
                let base = *LEN_BASE.get(s).ok_or(Error::BadSymbol)?;
                let len = usize::from(base) + bits.bits(u32::from(LEN_EXTRA[s]))? as usize;
                let d = usize::from(dist.decode(bits)?);
                let dbase = *DIST_BASE.get(d).ok_or(Error::BadSymbol)?;
                let distance = usize::from(dbase) + bits.bits(u32::from(DIST_EXTRA[d]))? as usize;
                out.copy(distance, len)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The input `tests` fixtures were compressed from, rebuilt the way the
    /// Python generator built it.
    fn gen(n: usize) -> Vec<u8> {
        let words: [&[u8]; 7] = [b"nano", b"chrono", b"meter ", b"package ", b"ncpkg ", b"\n", b"0123456789"];
        let mut out = Vec::new();
        let mut x: u64 = 0x1234_5678;
        while out.len() < n {
            x = (x * 1_103_515_245 + 12_345) & 0x7fff_ffff;
            if x % 5 == 0 {
                out.push(((x >> 16) & 0xff) as u8);
            } else {
                out.extend_from_slice(words[((x >> 8) % 7) as usize]);
            }
        }
        out.truncate(n);
        out
    }

    // Raw DEFLATE from zlib (Python's zlib module, wbits = -15).
    const FIXED: &str = "f348cdc9c9d751f04bcccb77ce28cacfcbcf4d2d492d5254f0c02e0e00";
    const STORE_PREFIX: &str = "012c01d3fe";
    const RLE: &str = "edc13101000000c2a06ceb5fca129e4001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f03";
    const DYN: &str = "85584b485651102682a229d3455060918884bda0b27c14f420c8079448f42030f8fb1505f1d74c2b5a5448282d9216d9b61606d2a6a25ab8098b425a0422066e7a19e24648844288a8ee9d73fe799cb9bf0bfdcf3d3377ce3cbf99732fb63777377715eddabda76cefbef28aca2a98834c2ad301b89f6eedeac874441b9974675b4b11ee721afe6f15ec312b74a6d26da996e622388044dc8e64dd261a1d7c02e99e42dcbdf83a638d76bbf9f17544abaaa5b5b68d491067bd027c6e705647f24b25cb71bfd03222decfd1bf057dda6ae0decada95f24a03709f46fb7701299e779885853b98b69d24ee8ba7a4970b040462e210477f8b74b854139fde7f3cc845939c3a71e4d175b1c0fb781e710d52fab873bdf8bfc4f4c7890219f951967ae4327e2aa94e0c56accb55e6a07ce9699eb8110fbd312019a189074d27838b80949a9c8f972c9f674fe25503dab591929eb382ec77dcfac81f9eb516e09c5f576b75f2c8a35925b20be0dbd17a4bae8ae0eeb06242c1d53ccafcb3321aa565c87f4156274b70a437724d850ba5b343543390c9f63a5fef1ed3f1e122ad286bb3117467650d4c146e146e0f92ee3fed16b29e4281fd546b02748dec417a1b538121e714cc237dc1d7978e5de87a5e9bbc4225bff2bf939e64a176d3312bd9827417f810b3d5457c052e1152d2cb0e5abe304f78863b41c69ac5ff61b99428eb1f434b2e9fc0ed47c8fbcc0658b0920696ce44ff9b6f219b9582b8eee94b6a01e4e6e46a8624b77b519b9cfece21f85419801a92a77538ab6307c61e2c042a686efe38a9bf9da73cbcd36884eb5e99d2f0dce93299edf7f87c8f80eaeb5280106676ae5297f1397c4dd19dc92cdd58069594701bb785de0fe154b7085d47f85e313ef421e7906672fa1cb142ec670d0801633dc0373a9f6b71c6bf5d6abcc6612cc9f7a960148210d8c19e9ad259a81f52b34732fe40be682c0a6c91fbe6e9fd28663ec4483fc1446f9eb44a944386a7f7ace287ca229dc2c711132f6c5c7c083c555c4c2bf06720eb133b9dc2b666fbd61e6972f57bd90fac78df50f057c37c65746d18098f9d7e10adeb07d95544a39ccbe3b08da9c10449bf7e93de4abd373393e6600bd2621705fcf914db6242aca197d5cfed8994e8b1a24f90f6faaa52fb3b76aa9838de78885bbfc89d793e79a4b331466a0a053013367d581bd350c056b7d7acc1352ca9728e855ccbdc39a9dd35abd96ba4d2f23af298254c90b20b4913920727305bc20a8a520b336f43836d942a2da10f8ce9aba5b3c91a04b5329bc3e20c5056a7d9ce70def63b97c5dd2a479406f429ee0e4a2289e185d5785712bdd2ef0da1903c7b087de9e231c79317349720eaee2e227a458727e25b160ec34dc9df24282243a344dbc1ab591cdc9fd4f1cb68eb7abb31db063948190ef6d89b54cf1c4287d56015de421c90cd6b5741e21df0a775f01a7be42e96e6cdbdad0f3e7025dea69491d62d215bf06a4f7c9e58ba9505df4532ff00";

    fn stored_stream(data: &[u8]) -> Vec<u8> {
        let mut s = std::vec![0x01u8];
        s.extend_from_slice(&(data.len() as u16).to_le_bytes());
        s.extend_from_slice(&(!(data.len() as u16)).to_le_bytes());
        s.extend_from_slice(data);
        s
    }

    fn through_ring(input: &[u8], max: u64) -> Result<Vec<u8>, Error> {
        let mut window = [0u8; WINDOW];
        let mut out = Vec::new();
        let mut sink = |piece: &[u8]| {
            out.extend_from_slice(piece);
            true
        };
        let n = inflate_to(input, &mut window, max, &mut sink)?;
        assert_eq!(n as usize, out.len());
        Ok(out)
    }

    #[test]
    fn fixed_huffman() {
        let want = b"Hello, NanoChronometer! Hello, NanoChronometer!";
        assert_eq!(inflate_vec(&unhex(FIXED), want.len()).unwrap(), want);
        assert_eq!(through_ring(&unhex(FIXED), u64::MAX).unwrap(), want);
    }

    #[test]
    fn dynamic_huffman() {
        let want = gen(5000);
        assert_eq!(inflate_vec(&unhex(DYN), 5000).unwrap(), want);
        assert_eq!(through_ring(&unhex(DYN), u64::MAX).unwrap(), want);
    }

    #[test]
    fn stored_blocks() {
        let want = gen(300);
        let s = stored_stream(&want);
        assert_eq!(&s[..5], &unhex(STORE_PREFIX)[..]);
        assert_eq!(inflate_vec(&s, 300).unwrap(), want);
        assert_eq!(through_ring(&s, u64::MAX).unwrap(), want);
        // Empty stored block.
        assert_eq!(inflate_vec(&stored_stream(&[]), 0).unwrap(), Vec::<u8>::new());
    }

    /// 70 000 bytes from 86: long matches, a distance of one, and a ring
    /// that wraps twice.
    #[test]
    fn long_runs_cross_the_window() {
        let want = std::vec![b'A'; 70_000];
        assert_eq!(inflate_vec(&unhex(RLE), 70_000).unwrap(), want);
        assert_eq!(through_ring(&unhex(RLE), u64::MAX).unwrap(), want);
    }

    #[test]
    fn output_is_bounded() {
        assert_eq!(inflate_into(&unhex(RLE), &mut [0u8; 69_999]), Err(Error::Overflow));
        assert_eq!(through_ring(&unhex(RLE), 69_999), Err(Error::Overflow));
        assert_eq!(inflate_vec(&unhex(DYN), 5001), Err(Error::Truncated));
        let mut window = [0u8; WINDOW];
        let mut refuse = |_: &[u8]| false;
        assert_eq!(inflate_to(&unhex(RLE), &mut window, u64::MAX, &mut refuse), Err(Error::Sink));
    }

    #[test]
    fn malformed_streams_have_their_errors() {
        let mut out = [0u8; 1024];
        // Block type 3.
        assert_eq!(inflate_into(&[0x07], &mut out), Err(Error::BadBlock));
        // Stored with LEN != ~NLEN.
        assert_eq!(inflate_into(&[0x01, 4, 0, 0, 0, 1, 2, 3, 4], &mut out), Err(Error::BadBlock));
        // Stored, cut short.
        assert_eq!(inflate_into(&[0x01, 4, 0, 0xfb, 0xff, 1, 2], &mut out), Err(Error::Truncated));
        // Nothing at all.
        assert_eq!(inflate_into(&[], &mut out), Err(Error::Truncated));
        // Data after the final block.
        let mut s = unhex(FIXED);
        s.push(0);
        assert_eq!(inflate_into(&s, &mut out), Err(Error::Trailing));
        // Truncated anywhere inside the stream.
        let dynamic = unhex(DYN);
        for cut in [1, 2, 10, 100, 1000, dynamic.len() - 1] {
            assert!(inflate_into(&dynamic[..cut], &mut [0u8; 8192]).is_err(), "cut at {cut}");
        }
        // A fixed block whose first symbol is a match: nothing to copy from.
        // Bits: final=1, type=01, then length symbol 257 (7-bit code
        // 0000001), then distance code 0 (00000).
        let too_far = [0b0000_0011u8, 0b0000_0010, 0, 0];
        assert_eq!(inflate_into(&too_far, &mut out), Err(Error::TooFar));
    }

    /// Mutated streams: never a panic, never more output than the buffer.
    #[test]
    fn corrupted_streams_never_panic() {
        let bases = [unhex(DYN), unhex(FIXED), unhex(RLE), stored_stream(&gen(200))];
        let mut x = 0xDEAD_BEEF_CAFE_F00Du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut out = std::vec![0u8; 80_000];
        let mut window = [0u8; WINDOW];
        let mut decoded = 0;
        for round in 0..30_000 {
            let mut b = bases[round % bases.len()].clone();
            for _ in 0..(next() % 3 + 1) {
                let r = next();
                let at = (r >> 8) as usize % b.len().max(1);
                match r % 3 {
                    0 if !b.is_empty() => b[at] ^= 1 << ((r >> 32) % 8),
                    1 if !b.is_empty() => b[at] = (r >> 40) as u8,
                    _ => b.truncate(at),
                }
            }
            if inflate_into(&b, &mut out).is_ok() {
                decoded += 1;
            }
            let mut sink = |_: &[u8]| true;
            let _ = inflate_to(&b, &mut window, 80_000, &mut sink);
        }
        // Some flips land in literals and still decode: those must be fine.
        assert!(decoded > 0);
    }
}
