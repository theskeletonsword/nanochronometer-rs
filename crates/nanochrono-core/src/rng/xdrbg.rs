// SPDX-License-Identifier: Apache-2.0
//! XDRBG-256: the deterministic generator every NC_RNG output byte comes from.
//!
//! The construction is Kelsey, Lucks and Müller's ("XDRBG: A Proposed
//! Deterministic Random Bit Generator Based on Any XOF", ToSC 2024), over
//! SHAKE256, as the manual's section 7.5 specifies: a 64-byte state `V`, and
//! a one-byte encoding that keeps the three operations' XOF inputs apart:
//!
//! ```text
//! instantiate(seed, α):  V ← SHAKE256(seed ‖ α ‖ enc(0, α), 64)
//! reseed(seed, α):       V ← SHAKE256(V ‖ seed ‖ α ‖ enc(1, α), 64)
//! generate(ℓ, α):        T ← SHAKE256(V ‖ α ‖ enc(2, α), 64 + ℓ)
//!                        V ← T[..64]; output ← T[64..]
//! enc(n, α) = n·85 + |α|, one byte, |α| ≤ 84
//! ```
//!
//! `generate` keeps only the successor state and overwrites the one it came
//! from, so reading `V` now reveals nothing about output already handed out.
//! A call produces at most [`BLOCK_LEN`] bytes, per the manual; the pool
//! loops for longer requests.

use super::keccak::{shake256, wipe_bytes};

/// The state, in bytes: twice the security level, as XDRBG-256 requires.
pub const STATE_LEN: usize = 64;
/// Output per generate call.
pub const BLOCK_LEN: usize = 32;
/// Longest additional input the encoding can tell apart.
pub const MAX_ALPHA: usize = 84;

/// Which operation an XOF input belongs to.
#[derive(Clone, Copy)]
enum Op {
    Instantiate = 0,
    Reseed = 1,
    Generate = 2,
}

fn encoding(op: Op, alpha: &[u8]) -> [u8; 1] {
    debug_assert!(alpha.len() <= MAX_ALPHA);
    [(op as u8) * 85 + alpha.len().min(MAX_ALPHA) as u8]
}

/// An XDRBG-256 instance.
pub struct Xdrbg {
    v: [u8; STATE_LEN],
    seeded: bool,
}

impl core::fmt::Debug for Xdrbg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Xdrbg").field("seeded", &self.seeded).finish_non_exhaustive()
    }
}

impl Default for Xdrbg {
    fn default() -> Self {
        Self::new()
    }
}

impl Xdrbg {
    pub const fn new() -> Self {
        Xdrbg { v: [0; STATE_LEN], seeded: false }
    }

    pub fn is_seeded(&self) -> bool {
        self.seeded
    }

    /// First seeding. `alpha` is a personalisation string, at most 84 bytes.
    pub fn instantiate(&mut self, seed: &[u8], alpha: &[u8]) {
        let alpha = &alpha[..alpha.len().min(MAX_ALPHA)];
        shake256(&[seed, alpha, &encoding(Op::Instantiate, alpha)], &mut self.v);
        self.seeded = true;
    }

    /// Folds fresh seed material into the state.
    pub fn reseed(&mut self, seed: &[u8], alpha: &[u8]) {
        let alpha = &alpha[..alpha.len().min(MAX_ALPHA)];
        let mut next = [0u8; STATE_LEN];
        shake256(&[&self.v, seed, alpha, &encoding(Op::Reseed, alpha)], &mut next);
        self.v = next;
        wipe_bytes(&mut next);
        self.seeded = true;
    }

    /// Fills `out` (at most [`BLOCK_LEN`] bytes) and steps the state.
    ///
    /// # Panics
    /// If `out` is longer than a block, or the generator was never seeded —
    /// both caller bugs the pool rules out before it gets here.
    pub fn generate(&mut self, out: &mut [u8], alpha: &[u8]) {
        assert!(self.seeded, "XDRBG used before it was seeded");
        assert!(out.len() <= BLOCK_LEN, "XDRBG block is at most 32 bytes");
        let alpha = &alpha[..alpha.len().min(MAX_ALPHA)];
        let mut t = [0u8; STATE_LEN + BLOCK_LEN];
        let t = &mut t[..STATE_LEN + out.len()];
        shake256(&[&self.v, alpha, &encoding(Op::Generate, alpha)], t);
        self.v.copy_from_slice(&t[..STATE_LEN]);
        out.copy_from_slice(&t[STATE_LEN..]);
        wipe_bytes(t);
    }

    /// Erases the state; the instance must be instantiated again.
    pub fn wipe(&mut self) {
        wipe_bytes(&mut self.v);
        self.seeded = false;
    }
}

// Known answers from tools/nc_rng_kat.py, which builds XDRBG-256 on hashlib's
// SHAKE256 and shares no code with this file.
const KAT_FIRST: [u8; 32] = [
    0x6f, 0x65, 0x1d, 0xe8, 0x3e, 0x34, 0x95, 0x47, 0xb7, 0xda, 0xdb, 0x94, 0x06, 0x86, 0x67, 0x00,
    0x9c, 0xb7, 0x5a, 0x95, 0x13, 0x2e, 0xf8, 0x9d, 0xf9, 0x4b, 0x5a, 0x16, 0x31, 0x6d, 0x60, 0x47,
];
const KAT_SECOND: [u8; 32] = [
    0xf3, 0x7e, 0x74, 0x4a, 0xf9, 0xce, 0x81, 0x8d, 0xe7, 0x49, 0x3f, 0x84, 0x16, 0x9b, 0x79, 0x57,
    0x20, 0x9e, 0xee, 0xb6, 0x31, 0x64, 0xee, 0x35, 0x09, 0xed, 0x19, 0x89, 0xc0, 0x0a, 0x81, 0x92,
];
const KAT_AFTER_RESEED: [u8; 32] = [
    0x92, 0x1a, 0x10, 0xa2, 0x20, 0xf4, 0x46, 0x9a, 0xbb, 0xbd, 0x3d, 0xee, 0x3a, 0x39, 0xcd, 0xf8,
    0xbf, 0x48, 0xa2, 0x26, 0x71, 0xb8, 0xcf, 0xb4, 0x51, 0x0c, 0x67, 0x66, 0x45, 0x7c, 0x3e, 0x49,
];

/// Instantiates from a public seed, generates twice, reseeds and generates
/// again, comparing each block with the reference. The manual's "doble
/// generación determinista": a failure takes the pool out of service.
pub fn selftest() -> bool {
    let mut seed = [0u8; 64];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut drbg = Xdrbg::new();
    drbg.instantiate(&seed, b"NanoChronometer");
    let mut first = [0u8; BLOCK_LEN];
    let mut second = [0u8; BLOCK_LEN];
    drbg.generate(&mut first, &[]);
    drbg.generate(&mut second, &[]);
    for (i, b) in seed.iter_mut().enumerate() {
        *b = 64 + i as u8;
    }
    drbg.reseed(&seed, b"NC_RNG");
    let mut third = [0u8; BLOCK_LEN];
    drbg.generate(&mut third, b"alpha");
    drbg.wipe();
    first == KAT_FIRST && second == KAT_SECOND && third == KAT_AFTER_RESEED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert!(selftest());
    }

    #[test]
    fn short_generate_is_a_prefix_of_the_same_step() {
        // The output is T[64..64+ℓ]; a shorter request is a prefix of a
        // longer one from the same state, and leaves the same successor.
        let mut a = Xdrbg::new();
        let mut b = Xdrbg::new();
        a.instantiate(&[7; 48], &[]);
        b.instantiate(&[7; 48], &[]);
        let mut long = [0u8; 32];
        let mut short = [0u8; 5];
        a.generate(&mut long, &[]);
        b.generate(&mut short, &[]);
        assert_eq!(&long[..5], &short);
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        a.generate(&mut x, &[]);
        b.generate(&mut y, &[]);
        assert_eq!(x, y);
    }

    #[test]
    fn encodings_keep_operations_apart() {
        assert_ne!(encoding(Op::Instantiate, &[0; 84]), encoding(Op::Reseed, &[]));
        assert_ne!(encoding(Op::Reseed, &[0; 84]), encoding(Op::Generate, &[]));
        assert_eq!(encoding(Op::Generate, &[0; 84]), [254]);
    }
}
