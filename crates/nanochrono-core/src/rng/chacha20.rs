// SPDX-License-Identifier: Apache-2.0
//! ChaCha20 (RFC 8439) in plain 32-bit arithmetic: the output stage's
//! software path.
//!
//! Used when the CPU has no AES instructions — or when the embedder picks it
//! on purpose. Additions, rotations and XORs on `u32` only, so it is the same
//! code, and runs in constant time, on every target this project builds for,
//! 32-bit and 64-bit alike; no table lookups for a cache to leak through.

use super::keccak::wipe_bytes;

/// "expand 32-byte k", as four little-endian words.
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574];

/// Bytes per ChaCha20 block.
pub const BLOCK_LEN: usize = 64;

/// The last word of the 96-bit nonce the output stage uses; the first two
/// are its 64-bit request counter. "NCRN" read little-endian.
pub const DOMAIN: u32 = 0x4E43_524E;

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// One 64-byte block: 20 rounds over the constants, key, block counter and
/// nonce, added back to the input.
pub fn block(key: &[u32; 8], counter: u32, nonce: &[u32; 3], out: &mut [u8; BLOCK_LEN]) {
    let mut input = [0u32; 16];
    input[..4].copy_from_slice(&SIGMA);
    input[4..12].copy_from_slice(key);
    input[12] = counter;
    input[13..].copy_from_slice(nonce);

    let mut s = input;
    for _ in 0..10 {
        // Column round.
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        // Diagonal round.
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(input[i]).to_le_bytes());
    }
    wipe_words(&mut s);
    wipe_words(&mut input);
}

/// Keystream for `key` under the output stage's nonce layout — the 64-bit
/// `nonce`, then [`DOMAIN`] — starting at block `first`.
///
/// The caller keeps `first` plus the block count below 2³²: the block
/// counter is 32 bits, and a wrap would repeat keystream.
pub fn keystream(key: &[u8; 32], nonce: u64, first: u32, out: &mut [u8]) {
    let mut words = [0u32; 8];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    let nonce = [nonce as u32, (nonce >> 32) as u32, DOMAIN];
    let mut buf = [0u8; BLOCK_LEN];
    for (i, chunk) in out.chunks_mut(BLOCK_LEN).enumerate() {
        debug_assert!(first as u64 + i as u64 <= u32::MAX as u64, "ChaCha20 block counter wrap");
        block(&words, first.wrapping_add(i as u32), &nonce, &mut buf);
        chunk.copy_from_slice(&buf[..chunk.len()]);
    }
    wipe_bytes(&mut buf);
    wipe_words(&mut words);
}

fn wipe_words(words: &mut [u32]) {
    for word in words.iter_mut() {
        // SAFETY: `word` is a valid `&mut u32`.
        unsafe { core::ptr::write_volatile(word, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// RFC 8439 §2.3.2: key 00..1f, counter 1, nonce 00000009 0000004a 00000000.
const RFC8439_BLOCK: [u8; 64] = [
    0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
];

/// The RFC's block test vector.
pub fn selftest() -> bool {
    let mut key = [0u32; 8];
    for (i, word) in key.iter_mut().enumerate() {
        let b = 4 * i as u32;
        *word = u32::from_le_bytes([b as u8, (b + 1) as u8, (b + 2) as u8, (b + 3) as u8]);
    }
    let nonce = [0x0900_0000, 0x4A00_0000, 0];
    let mut out = [0u8; 64];
    block(&key, 1, &nonce, &mut out);
    out == RFC8439_BLOCK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_block() {
        assert!(selftest());
    }

    #[test]
    fn keystream_is_consecutive_blocks() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let mut whole = [0u8; 200];
        keystream(&key, 5, 0, &mut whole);
        let mut tail = [0u8; 72];
        keystream(&key, 5, 2, &mut tail);
        assert_eq!(&whole[128..], &tail);
    }
}
