// SPDX-License-Identifier: Apache-2.0
//! Keccak-f[1600] and the sponge built on it (FIPS 202).
//!
//! Everything NC_RNG conditions goes through this one primitive: the jitter
//! samples, the hardware generators' words, the event timings and the
//! XDRBG-256 state. It is written here rather than taken from a crate because
//! the pool has to run in the freestanding kernel with no allocator, and
//! because 24 rounds of five steps is short enough to read in one sitting.
//!
//! The sponge has the 136-byte rate that SHA3-256 and SHAKE256 use (1088
//! bits, capacity 512), which is what the manual specifies for 256-bit output.
//!
//! Lanes are filled and read a byte at a time by shifting, never by viewing
//! the state as bytes, so the same code is right on the big-endian PowerPC
//! targets. [`selftest`] checks it against vectors produced by an unrelated
//! implementation (`tools/nc_rng_kat.py`, i.e. OpenSSL via hashlib).

use core::sync::atomic::{compiler_fence, Ordering};

/// Bytes absorbed or squeezed per permutation: 1088 bits of rate, 512 of
/// capacity.
pub const RATE: usize = 136;

/// Domain-separation suffix of the SHA3 hash functions.
pub const DOMAIN_SHA3: u8 = 0x06;
/// Domain-separation suffix of the SHAKE extendable-output functions.
pub const DOMAIN_SHAKE: u8 = 0x1F;

/// Iota's round constants, one per round.
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rho and pi fused: walking the lanes in [`PI_LANES`] order, lane `i`
/// receives the previous lane rotated by `RHO_OFFSETS[i]`.
const RHO_OFFSETS: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const PI_LANES: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Keccak-f[1600]: 24 rounds over 25 lanes, lane `(x, y)` at `x + 5y`.
pub fn permute(a: &mut [u64; 25]) {
    for &rc in &ROUND_CONSTANTS {
        // Theta: every lane absorbs the parity of two neighbouring columns.
        let mut column = [0u64; 5];
        for x in 0..5 {
            column[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = column[(x + 4) % 5] ^ column[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }

        // Rho and pi: rotate each lane and move it to its new position.
        let mut carried = a[1];
        for i in 0..24 {
            let lane = PI_LANES[i];
            let displaced = a[lane];
            a[lane] = carried.rotate_left(RHO_OFFSETS[i]);
            carried = displaced;
        }

        // Chi: the only non-linear step, row by row.
        for y in 0..5 {
            let row = [a[5 * y], a[5 * y + 1], a[5 * y + 2], a[5 * y + 3], a[5 * y + 4]];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }

        // Iota: break the symmetry between rounds.
        a[0] ^= rc;
    }
}

/// A Keccak sponge with a 136-byte rate.
///
/// Absorb any number of times, then squeeze; the first squeeze pads with the
/// domain given to [`finish`](Self::finish), or SHAKE's if none was.
#[derive(Clone)]
pub struct Sponge {
    lanes: [u64; 25],
    /// Byte offset into the current rate block.
    pos: usize,
    squeezing: bool,
}

impl core::fmt::Debug for Sponge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The state is secret; show only where the sponge is.
        f.debug_struct("Sponge")
            .field("pos", &self.pos)
            .field("squeezing", &self.squeezing)
            .finish_non_exhaustive()
    }
}

impl Default for Sponge {
    fn default() -> Self {
        Self::new()
    }
}

impl Sponge {
    pub const fn new() -> Self {
        Sponge { lanes: [0; 25], pos: 0, squeezing: false }
    }

    /// XORs `data` into the rate, permuting at every full block.
    pub fn absorb(&mut self, data: &[u8]) {
        debug_assert!(!self.squeezing, "absorb after squeeze");
        for &byte in data {
            self.lanes[self.pos / 8] ^= (byte as u64) << (8 * (self.pos % 8));
            self.pos += 1;
            if self.pos == RATE {
                permute(&mut self.lanes);
                self.pos = 0;
            }
        }
    }

    /// Absorbs a whole rate-sized block. From a block boundary — which is
    /// where the pool always is — that is exactly one permutation, which is
    /// the point: the manual mixes each measurement through a full
    /// compression, whatever its length.
    pub fn absorb_block(&mut self, block: &[u8; RATE]) {
        self.absorb(block);
    }

    /// Pads with `domain` and the final bit, and switches to squeezing.
    pub fn finish(&mut self, domain: u8) {
        if self.squeezing {
            return;
        }
        self.lanes[self.pos / 8] ^= (domain as u64) << (8 * (self.pos % 8));
        self.lanes[(RATE - 1) / 8] ^= 0x80u64 << (8 * ((RATE - 1) % 8));
        permute(&mut self.lanes);
        self.pos = 0;
        self.squeezing = true;
    }

    /// Fills `out` with output, permuting whenever the rate runs out.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.finish(DOMAIN_SHAKE);
        for byte in out {
            if self.pos == RATE {
                permute(&mut self.lanes);
                self.pos = 0;
            }
            *byte = (self.lanes[self.pos / 8] >> (8 * (self.pos % 8))) as u8;
            self.pos += 1;
        }
    }

    /// Overwrites the state with zeros in a way the optimiser may not drop,
    /// and returns the sponge to its initial, absorbing state.
    pub fn wipe(&mut self) {
        for lane in self.lanes.iter_mut() {
            // SAFETY: `lane` is a valid, aligned `&mut u64`.
            unsafe { core::ptr::write_volatile(lane, 0) };
        }
        self.pos = 0;
        self.squeezing = false;
        compiler_fence(Ordering::SeqCst);
    }
}

/// Zeroes a byte buffer so the write survives optimisation. For secrets that
/// only ever lived on the stack: seeds, blocks, measurements.
pub fn wipe_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid `&mut u8`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// SHA3-256 of the concatenation of `parts`.
pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut sponge = Sponge::new();
    for part in parts {
        sponge.absorb(part);
    }
    sponge.finish(DOMAIN_SHA3);
    let mut digest = [0u8; 32];
    sponge.squeeze(&mut digest);
    sponge.wipe();
    digest
}

/// SHAKE256 of the concatenation of `parts`, as much output as `out` holds.
pub fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut sponge = Sponge::new();
    for part in parts {
        sponge.absorb(part);
    }
    sponge.finish(DOMAIN_SHAKE);
    sponge.squeeze(out);
    sponge.wipe();
}

// Known answers, from tools/nc_rng_kat.py (OpenSSL's SHA-3 via hashlib). The
// first three are also the FIPS 202 example values.
const SHA3_256_EMPTY: [u8; 32] = [
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
    0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
];
const SHA3_256_ABC: [u8; 32] = [
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
    0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
];
const SHA3_256_A3X200: [u8; 32] = [
    0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07, 0xa9, 0x8e, 0xf7, 0x6e, 0x83, 0x24, 0xaf, 0xbf,
    0xd4, 0x6c, 0xfd, 0x81, 0xb2, 0x2e, 0x39, 0x73, 0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3, 0x17, 0x87,
];
const SHAKE256_EMPTY: [u8; 32] = [
    0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
    0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
];
/// SHA3-256 of the first 300 bytes of SHAKE256("abc"): the squeeze crosses
/// two rate boundaries, and the digest keeps the constant short.
const SHAKE256_ABC_300_SHA3: [u8; 32] = [
    0xd4, 0x89, 0x24, 0xbe, 0x33, 0x19, 0xfe, 0x23, 0xc1, 0x55, 0x50, 0x4a, 0x2a, 0x92, 0x3f, 0xd7,
    0xfe, 0x65, 0xee, 0x16, 0x88, 0xbe, 0x80, 0xed, 0xac, 0xf6, 0x58, 0x41, 0xbf, 0x48, 0x76, 0xd7,
];

/// Checks the permutation and both paddings against known answers. A
/// failure here means every output of the pool would be wrong, so the pool
/// latches it as permanent.
pub fn selftest() -> bool {
    let a3 = [0xA3u8; 200];
    let mut shake = [0u8; 32];
    shake256(&[], &mut shake);
    let mut long = [0u8; 300];
    shake256(&[b"abc"], &mut long);

    sha3_256(&[]) == SHA3_256_EMPTY
        && sha3_256(&[b"abc"]) == SHA3_256_ABC
        // Split across calls, so absorbing in pieces is covered too.
        && sha3_256(&[&a3[..7], &a3[7..150], &a3[150..]]) == SHA3_256_A3X200
        && shake == SHAKE256_EMPTY
        && sha3_256(&[&long]) == SHAKE256_ABC_300_SHA3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert!(selftest());
    }

    #[test]
    fn absorbing_in_pieces_matches_one_call() {
        let data: [u8; 700] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let whole = sha3_256(&[&data]);
        for split in [0, 1, 135, 136, 137, 272, 699, 700] {
            assert_eq!(sha3_256(&[&data[..split], &data[split..]]), whole, "split at {split}");
        }
    }

    #[test]
    fn wipe_resets_to_initial_state() {
        let mut s = Sponge::new();
        s.absorb(b"secret");
        s.wipe();
        s.absorb(b"abc");
        s.finish(DOMAIN_SHA3);
        let mut out = [0u8; 32];
        s.squeeze(&mut out);
        assert_eq!(out, SHA3_256_ABC);
    }
}
