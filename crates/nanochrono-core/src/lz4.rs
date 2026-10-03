// SPDX-License-Identifier: Apache-2.0
//! LZ4 blocks: NCFS's fast transparent compression.
//!
//! NCFS compresses each file extent on its own and stores the result only
//! when it saves space; LZ4 is the codec for data written on the system
//! itself, where compression must cost less than the disk time it saves
//! (ZSTD, decoded by [`crate::zstd`], is for images built on a host). The
//! block format here is the one `lz4`'s `LZ4_compress_default` and
//! `LZ4_decompress_safe` exchange — a block either side writes, the other
//! reads — written from the format's description, not from that code.
//!
//! A block is a run of sequences: a token (literal count in the high
//! nibble, match length minus four in the low one, 15 meaning "more bytes
//! follow"), the literals, a two-byte little-endian distance, and the
//! match. The last sequence is literals only.
//!
//! # For untrusted input
//!
//! The decoder is the one the kernel runs on blocks read from a disk: safe
//! Rust, every read and write checked, never panicking, its output bounded
//! by the buffer the caller passes — an extent decodes into exactly its
//! declared size or is refused ([`decompress_exact`]). The tests throw
//! mutated blocks at it, and decode blocks the reference library made.
//!
//! The compressor is greedy, one hash probe per position, with its table
//! lent by the caller so a kernel with a small stack can keep it in static
//! memory. It finds less than `lz4 -9`, never writes a block the format
//! forbids, and says when the output would not fit — which is how NCFS
//! decides an extent is not worth compressing.

/// The shortest match a block can encode.
pub const MIN_MATCH: usize = 4;
/// The farthest back a match may reach.
pub const MAX_DISTANCE: usize = 65_535;
/// The last five bytes of a block are always literals.
const LAST_LITERALS: usize = 5;
/// No match starts in the last twelve bytes.
const MF_LIMIT: usize = 12;
const HASH_LOG: u32 = 12;
/// Entries in the compressor's table.
pub const TABLE_LEN: usize = 1 << HASH_LOG;

/// The largest block `n` input bytes can compress to: every byte a
/// literal, plus the length bytes that many literals need.
pub const fn bound(n: usize) -> usize {
    n + n / 255 + 16
}

/// Why a block was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The block ends inside a sequence.
    Truncated,
    /// A distance of zero, or one reaching before the start of the output.
    BadDistance,
    /// More output than the buffer holds: more than the extent declared.
    Overflow,
    /// Less output than the extent declared.
    Short,
}

impl Error {
    pub const fn message(self) -> &'static str {
        match self {
            Error::Truncated => "LZ4 block ends early",
            Error::BadDistance => "LZ4 match reaches before the start",
            Error::Overflow => "LZ4 block decodes to more than declared",
            Error::Short => "LZ4 block decodes to less than declared",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

/// The compressor's hash table: 16 KiB, positions of recent four-byte
/// sequences.
#[derive(Clone)]
pub struct Table {
    slots: [u32; TABLE_LEN],
}

impl core::fmt::Debug for Table {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("lz4::Table")
    }
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    pub const fn new() -> Table {
        Table { slots: [0; TABLE_LEN] }
    }
}

fn read32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn hash(v: u32) -> usize {
    (v.wrapping_mul(2_654_435_761) >> (32 - HASH_LOG)) as usize
}

struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn byte(&mut self, b: u8) -> Option<()> {
        *self.out.get_mut(self.at)? = b;
        self.at += 1;
        Some(())
    }

    fn bytes(&mut self, b: &[u8]) -> Option<()> {
        self.out.get_mut(self.at..self.at + b.len())?.copy_from_slice(b);
        self.at += b.len();
        Some(())
    }

    /// The bytes past a nibble's 15: 255s, then the remainder.
    fn length(&mut self, mut n: usize) -> Option<()> {
        while n >= 255 {
            self.byte(255)?;
            n -= 255;
        }
        self.byte(n as u8)
    }

    fn sequence(&mut self, literals: &[u8], distance: usize, matched: Option<usize>) -> Option<()> {
        let lit = literals.len();
        let ml = matched.map_or(0, |m| m - MIN_MATCH);
        self.byte(((lit.min(15) as u8) << 4) | ml.min(15) as u8)?;
        if lit >= 15 {
            self.length(lit - 15)?;
        }
        self.bytes(literals)?;
        if matched.is_some() {
            self.bytes(&(distance as u16).to_le_bytes())?;
            if ml >= 15 {
                self.length(ml - 15)?;
            }
        }
        Some(())
    }
}

/// Compresses `input` into `out` and returns the block's length, or `None`
/// when it does not fit — pass an `out` shorter than the input to learn
/// that compressing would not save anything. [`bound`] bytes always fit.
/// Inputs are at most 4 GiB.
pub fn compress(input: &[u8], out: &mut [u8], table: &mut Table) -> Option<usize> {
    let n = input.len();
    if u32::try_from(n).is_err() {
        return None;
    }
    let mut w = Writer { out, at: 0 };
    let mut anchor = 0;
    if n > MF_LIMIT {
        table.slots.fill(0);
        let match_limit = n - LAST_LITERALS;
        let last_start = n - MF_LIMIT;
        let mut ip = 0;
        let mut misses = 0usize;
        while ip <= last_start {
            let v = read32(input, ip);
            let h = hash(v);
            // Any slot is only a guess, checked against the bytes: a stale or
            // zeroed entry cannot produce a wrong match.
            let cand = table.slots[h] as usize;
            table.slots[h] = ip as u32;
            if cand < ip && ip - cand <= MAX_DISTANCE && read32(input, cand) == v {
                // Back over literals not yet written, then forward up to the
                // last literals.
                let (mut s, mut c) = (ip, cand);
                while s > anchor && c > 0 && input[s - 1] == input[c - 1] {
                    s -= 1;
                    c -= 1;
                }
                let (mut e, mut ce) = (ip + MIN_MATCH, cand + MIN_MATCH);
                while e < match_limit && input[e] == input[ce] {
                    e += 1;
                    ce += 1;
                }
                w.sequence(&input[anchor..s], s - c, Some(e - s))?;
                // Remember a position near the match's end: runs that repeat
                // are found again sooner.
                let p = e - 2;
                table.slots[hash(read32(input, p))] = p as u32;
                ip = e;
                anchor = e;
                misses = 0;
            } else {
                // Step faster through data that does not compress.
                misses += 1;
                ip += 1 + (misses >> 6);
            }
        }
    }
    w.sequence(&input[anchor..], 0, None)?;
    Some(w.at)
}

/// The bytes past a nibble's 15.
fn read_length(input: &[u8], ip: &mut usize) -> Result<usize, Error> {
    let mut n = 0usize;
    loop {
        let b = *input.get(*ip).ok_or(Error::Truncated)?;
        *ip += 1;
        n = n.checked_add(usize::from(b)).ok_or(Error::Overflow)?;
        if b != 255 {
            return Ok(n);
        }
    }
}

/// Decompresses one block into `out` and returns the bytes written. The
/// block must end exactly at the end of `input`, with a literals-only
/// sequence.
pub fn decompress(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let (mut ip, mut op) = (0usize, 0usize);
    loop {
        let token = *input.get(ip).ok_or(Error::Truncated)?;
        ip += 1;
        let mut lit = usize::from(token >> 4);
        if lit == 15 {
            lit += read_length(input, &mut ip)?;
        }
        let lit_end = ip.checked_add(lit).ok_or(Error::Truncated)?;
        let src = input.get(ip..lit_end).ok_or(Error::Truncated)?;
        let op_end = op.checked_add(lit).ok_or(Error::Overflow)?;
        out.get_mut(op..op_end).ok_or(Error::Overflow)?.copy_from_slice(src);
        ip = lit_end;
        op = op_end;
        if ip == input.len() {
            return Ok(op);
        }
        let d = input.get(ip..ip + 2).ok_or(Error::Truncated)?;
        let distance = usize::from(u16::from_le_bytes([d[0], d[1]]));
        ip += 2;
        if distance == 0 || distance > op {
            return Err(Error::BadDistance);
        }
        let mut ml = usize::from(token & 15);
        if ml == 15 {
            ml += read_length(input, &mut ip)?;
        }
        ml += MIN_MATCH;
        let end = op.checked_add(ml).filter(|&e| e <= out.len()).ok_or(Error::Overflow)?;
        if distance >= ml {
            out.copy_within(op - distance..op - distance + ml, op);
        } else {
            // Overlapping: the match repeats bytes it is itself writing.
            for i in op..end {
                out[i] = out[i - distance];
            }
        }
        op = end;
    }
}

/// Decompresses a block that must fill `out` exactly: an extent of a known
/// size.
pub fn decompress_exact(input: &[u8], out: &mut [u8]) -> Result<(), Error> {
    match decompress(input, out)? {
        n if n == out.len() => Ok(()),
        _ => Err(Error::Short),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Text-like data with repeats (the generator the reference vectors
    /// were made from, in Python, with the same constants).
    fn gen(n: usize) -> Vec<u8> {
        let words: [&[u8]; 9] = [b"nano", b"chronometer", b"ncfs", b"blake3", b"snapshot", b"extent", b"  ", b"\n", b"0123456789"];
        let mut out = Vec::new();
        let mut x: u32 = 0x9E37_79B9;
        while out.len() < n {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            out.extend_from_slice(words[(x >> 16) as usize % words.len()]);
        }
        out.truncate(n);
        out
    }

    fn noise(n: usize, mut x: u64) -> Vec<u8> {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn round_trip(data: &[u8]) -> usize {
        let mut table = Table::new();
        let mut c = std::vec![0u8; bound(data.len())];
        let n = compress(data, &mut c, &mut table).expect("bound always fits");
        let mut d = std::vec![0u8; data.len()];
        decompress_exact(&c[..n], &mut d).unwrap();
        assert_eq!(d, data);
        n
    }

    // Made by the reference library (lz4 4.4, through Python): the text
    // above at its highest level, and 70 000 'a's at its default.
    const HC_TEXT: &str = "fd046368726f6e6f6d65746572626c616b653320201300af30313233343536373839100003a7657874656e746e616e6f3b000f150008d80a20202020736e617073686f744300020c00406e63667338000008000218000f920008060a000451000037000ca200074100001f00380a20202e00080c000271000905010b3d0008ab002620206a000159000db000062000202020d50002380002e900001000140a7d000734003c0a202010012820203900020600043a00036a010126000f1901010cf200035b010bd700041f000638001b0abd010831000044000a1e000c990103eb010d22000f1c01020f15000208960008a301024800130a07000f3b000207c500064401075e02012c010ef200088401040902020800040e0001b3010727000ebe010513000c0b01080a020eaa000016001a0ae60108740002b2000a0a00049c0006ca000532000224000909030c4a010683020a7201025a000bec010e66030b42020ec6030421030608040e4500042400089b0224202086000ad600042c000afc020c48041e0aba030a96010ad101056a030731020735001e200c050c2f0008a5020c1c000df9043a20200a95010fa3010b0b85010cec000f9b03070ea20206f7030c20000aae0106e1040d4303110ab7051e0adf000edb03041100071305047b000c5d000b8f02039d030460040fee05130d7800180a330208f0010a7a010a67030ac6010e84010f0102080e730606aa020f5a02050c30001c0a88000e51000be60108ee03063f010770000e38010e64020bc6050e10040e1d070142020856010a350007fb010c2f070d10000ada04030400292020eb000f5e03100436000ef101061c010664000c99050e48030cee0109b9010549030d970705c50003c2020f15060a0718031e0aeb01071d00063b010ff402040a2101077501041900160a2e020858050ad60003d2000e7b06033f0807ba000558000ec005086800041d010fc80902066c000e1f0a130a08000c41030ff506030f2d02080623000fd402030b90000e5c020efe090ed7030117050efa060f1f09020a66010f87000408d0092e0a73d10050686f743031";

    /// One literal, a match of 69 994 at distance one (15 + 274 × 255 +
    /// 105), five literals: 285 bytes.
    fn rle_a() -> Vec<u8> {
        let mut v = unhex("1f610100");
        v.extend(std::iter::repeat_n(0xffu8, 274));
        v.extend_from_slice(&unhex("69506161616161"));
        assert_eq!(v.len(), 285);
        v
    }

    #[test]
    fn reads_what_the_reference_library_writes() {
        let mut out = std::vec![0u8; 3000];
        decompress_exact(&unhex(HC_TEXT), &mut out).unwrap();
        assert_eq!(out, gen(3000));
        let mut out = std::vec![0u8; 70_000];
        decompress_exact(&rle_a(), &mut out).unwrap();
        assert!(out.iter().all(|&b| b == b'a'));
    }

    #[test]
    fn round_trips() {
        for n in 0..40 {
            round_trip(&gen(n));
            round_trip(&std::vec![7u8; n]);
        }
        assert!(round_trip(&gen(64 * 1024)) < 64 * 1024 / 2, "text compresses");
        assert!(round_trip(&std::vec![0u8; 128 * 1024]) < 600, "zeros compress");
        round_trip(&noise(100_000, 0x1234_5678_9ABC_DEF0));
        // Matches far apart, beyond the reach of a distance.
        let mut far = gen(1000);
        far.extend(noise(70_000, 99));
        far.extend(gen(1000));
        round_trip(&far);
    }

    #[test]
    fn says_when_compressing_does_not_pay() {
        let data = noise(4096, 7);
        let mut out = std::vec![0u8; data.len() - 1];
        assert_eq!(compress(&data, &mut out, &mut Table::new()), None);
        let text = gen(4096);
        let mut out = std::vec![0u8; text.len() - 1];
        assert!(compress(&text, &mut out, &mut Table::new()).is_some());
    }

    #[test]
    fn output_is_bounded_and_exact() {
        let mut short = std::vec![0u8; 69_999];
        assert_eq!(decompress(&rle_a(), &mut short), Err(Error::Overflow));
        let mut long = std::vec![0u8; 70_001];
        assert_eq!(decompress_exact(&rle_a(), &mut long), Err(Error::Short));
        let mut out = [0u8; 64];
        assert_eq!(decompress(&[], &mut out), Err(Error::Truncated));
        // A match before any output.
        assert_eq!(decompress(&[0x00, 0x01, 0x00, 0x00], &mut out), Err(Error::BadDistance));
        // Distance zero.
        assert_eq!(decompress(&[0x10, b'x', 0x00, 0x00, 0x00], &mut out), Err(Error::BadDistance));
        // Literals cut short.
        assert_eq!(decompress(&[0x50, 1, 2], &mut out), Err(Error::Truncated));
    }

    /// Mutated blocks: never a panic, never more output than the buffer.
    #[test]
    fn corrupted_blocks_never_panic() {
        let mut table = Table::new();
        let text = gen(5000);
        let mut c = std::vec![0u8; bound(text.len())];
        let n = compress(&text, &mut c, &mut table).unwrap();
        c.truncate(n);
        let bases = [unhex(HC_TEXT), rle_a(), c];
        let mut x = 0xDEAD_BEEF_CAFE_F00Du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut out = std::vec![0u8; 80_000];
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
            let _ = decompress(&b, &mut out);
            let _ = decompress(&b, &mut out[..100]);
        }
    }
}
