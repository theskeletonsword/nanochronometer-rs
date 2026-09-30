// SPDX-License-Identifier: Apache-2.0
//! AES-256 in counter mode, on the CPU's AES instructions: the output
//! stage's hardware paths.
//!
//! | Path | Instructions | Blocks per instruction |
//! |---|---|---|
//! | [`vaes512`] | `VAESENC` on ZMM (VAES + AVX-512F) | 4 |
//! | [`vaes256`] | `VAESENC` on YMM (VAES + AVX2) | 2 |
//! | [`aesni`] | `AESENC` on XMM (AES-NI) | 1, four interleaved |
//! | [`armv8`] | `AESE` + `AESMC` (ARMv8 Cryptography Extension) | 1 |
//!
//! There is deliberately no software AES. A table-driven AES leaks its key
//! through the cache, and a constant-time one is slower than ChaCha20, which
//! is the software path instead. The key schedule is computed with the AES
//! instructions too (`AESKEYGENASSIST` on x86; on ARM, `AESE` with a zero
//! round key applied to a word broadcast to all four columns, where
//! `ShiftRows` is the identity and only `SubBytes` remains), so no path ever
//! indexes a table with key material.
//!
//! The counter block is the 64-bit nonce then the 64-bit block index, both
//! little-endian: `nonce ‖ index`. Every function here is `unsafe` and must
//! only be called once [`crate::cpu`] has reported the instructions it uses.

/// Round keys in AES-256: 14 rounds plus the initial whitening key.
pub const ROUND_KEYS: usize = 15;

/// AES-NI, and the AES-NI key schedule the VAES path reuses.
#[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), feature = "simd"))]
pub mod aesni {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    use super::ROUND_KEYS;

    pub(super) type Schedule = [__m128i; ROUND_KEYS];

    /// Each word XORed with every word below it: the running XOR a key
    /// schedule step needs, three byte shifts deep.
    #[inline]
    #[target_feature(enable = "sse2")]
    fn prefix_xor(mut a: __m128i) -> __m128i {
        let mut shifted = _mm_slli_si128(a, 4);
        a = _mm_xor_si128(a, shifted);
        shifted = _mm_slli_si128(shifted, 4);
        a = _mm_xor_si128(a, shifted);
        shifted = _mm_slli_si128(shifted, 4);
        _mm_xor_si128(a, shifted)
    }

    /// The even round keys: `RotWord`, `SubWord` and the round constant come
    /// from `AESKEYGENASSIST`'s top word.
    #[inline]
    #[target_feature(enable = "aes,sse2")]
    fn even(previous: __m128i, assist: __m128i) -> __m128i {
        _mm_xor_si128(prefix_xor(previous), _mm_shuffle_epi32(assist, 0xFF))
    }

    /// The odd round keys: `SubWord` alone, from the assist's third word.
    #[inline]
    #[target_feature(enable = "aes,sse2")]
    fn odd(previous: __m128i, latest: __m128i) -> __m128i {
        let assist = _mm_aeskeygenassist_si128(latest, 0x00);
        _mm_xor_si128(prefix_xor(previous), _mm_shuffle_epi32(assist, 0xAA))
    }

    /// The AES-256 key schedule (FIPS 197 §5.2), two round keys per step.
    #[target_feature(enable = "aes,sse2")]
    pub(super) fn expand(key: &[u8; 32]) -> Schedule {
        let mut rk = [_mm_setzero_si128(); ROUND_KEYS];
        // SAFETY: both halves of `key` are 16 readable bytes; unaligned loads.
        unsafe {
            rk[0] = _mm_loadu_si128(key.as_ptr().cast());
            rk[1] = _mm_loadu_si128(key[16..].as_ptr().cast());
        }
        // The round constant is an immediate, so the steps are spelled out.
        macro_rules! step {
            ($i:literal, $rcon:literal) => {
                rk[$i] = even(rk[$i - 2], _mm_aeskeygenassist_si128(rk[$i - 1], $rcon));
                rk[$i + 1] = odd(rk[$i - 1], rk[$i]);
            };
        }
        step!(2, 0x01);
        step!(4, 0x02);
        step!(6, 0x04);
        step!(8, 0x08);
        step!(10, 0x10);
        step!(12, 0x20);
        rk[14] = even(rk[12], _mm_aeskeygenassist_si128(rk[13], 0x40));
        rk
    }

    /// Overwrites a schedule so it does not outlive its use on the stack.
    #[target_feature(enable = "sse2")]
    pub(super) fn wipe(rk: &mut Schedule) {
        for key in rk.iter_mut() {
            // SAFETY: `key` is a valid, aligned `&mut __m128i`.
            unsafe { core::ptr::write_volatile(key, _mm_setzero_si128()) };
        }
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    fn counter(nonce: u64, index: u64) -> __m128i {
        _mm_set_epi64x(index as i64, nonce as i64)
    }

    #[inline]
    #[target_feature(enable = "aes,sse2")]
    fn encrypt(rk: &Schedule, block: __m128i) -> __m128i {
        let mut b = _mm_xor_si128(block, rk[0]);
        for key in &rk[1..14] {
            b = _mm_aesenc_si128(b, *key);
        }
        _mm_aesenclast_si128(b, rk[14])
    }

    /// AES-256-CTR keystream from block `first` into `out`.
    ///
    /// Four blocks at a time in the main loop: `AESENC` has a latency of
    /// several cycles and a throughput of one or two per cycle, so four
    /// independent chains keep the unit busy where one would idle.
    ///
    /// # Safety
    /// Requires AES-NI.
    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn ctr(key: &[u8; 32], nonce: u64, first: u64, out: &mut [u8]) {
        let mut rk = expand(key);
        let mut index = first;
        let (groups, tail) = out.as_chunks_mut::<64>();
        for chunk in groups {
            let mut b = [
                _mm_xor_si128(counter(nonce, index), rk[0]),
                _mm_xor_si128(counter(nonce, index.wrapping_add(1)), rk[0]),
                _mm_xor_si128(counter(nonce, index.wrapping_add(2)), rk[0]),
                _mm_xor_si128(counter(nonce, index.wrapping_add(3)), rk[0]),
            ];
            for key in &rk[1..14] {
                for state in b.iter_mut() {
                    *state = _mm_aesenc_si128(*state, *key);
                }
            }
            for (j, state) in b.iter().enumerate() {
                let block = _mm_aesenclast_si128(*state, rk[14]);
                // SAFETY: `chunk` is 64 bytes, so 16 * j + 16 <= 64.
                unsafe { _mm_storeu_si128(chunk[16 * j..].as_mut_ptr().cast(), block) };
            }
            index = index.wrapping_add(4);
        }
        let mut last = [0u8; 16];
        for chunk in tail.chunks_mut(16) {
            let block = encrypt(&rk, counter(nonce, index));
            // SAFETY: `last` is 16 writable bytes.
            unsafe { _mm_storeu_si128(last.as_mut_ptr().cast(), block) };
            chunk.copy_from_slice(&last[..chunk.len()]);
            index = index.wrapping_add(1);
        }
        crate::rng::keccak::wipe_bytes(&mut last);
        wipe(&mut rk);
    }
}

/// VAES on ZMM: four AES blocks per instruction.
#[cfg(all(target_arch = "x86_64", feature = "simd"))]
pub mod vaes512 {
    use core::arch::x86_64::*;

    use super::{aesni, ROUND_KEYS};

    #[inline]
    #[target_feature(enable = "avx512f,vaes")]
    fn encrypt4(rk: &[__m512i; ROUND_KEYS], counters: __m512i) -> __m512i {
        let mut b = _mm512_xor_si512(counters, rk[0]);
        for key in &rk[1..14] {
            b = _mm512_aesenc_epi128(b, *key);
        }
        _mm512_aesenclast_epi128(b, rk[14])
    }

    /// AES-256-CTR keystream from block `first` into `out`, 64 bytes (four
    /// counter blocks, one per 128-bit lane) per instruction. A short tail
    /// still encrypts a whole group and keeps what it needs; the rest is
    /// never handed out.
    ///
    /// # Safety
    /// Requires VAES and AVX-512F with the ZMM state enabled in XCR0 (which
    /// [`crate::cpu`]'s `avx512f` includes), and AES-NI for the schedule —
    /// every VAES part has it.
    #[target_feature(enable = "avx512f,vaes,aes,sse2")]
    pub unsafe fn ctr(key: &[u8; 32], nonce: u64, first: u64, out: &mut [u8]) {
        let mut narrow = aesni::expand(key);
        let mut rk = [_mm512_setzero_si512(); ROUND_KEYS];
        for (wide, key) in rk.iter_mut().zip(narrow.iter()) {
            *wide = _mm512_broadcast_i32x4(*key);
        }
        aesni::wipe(&mut narrow);

        // Lane j holds block `first + j`: the nonce in its low quadword, the
        // index in its high one. `_mm512_set_epi64` lists quadwords high to
        // low.
        let n = nonce as i64;
        let f = first as i64;
        let mut counters =
            _mm512_set_epi64(f.wrapping_add(3), n, f.wrapping_add(2), n, f.wrapping_add(1), n, f, n);
        let step = _mm512_set_epi64(4, 0, 4, 0, 4, 0, 4, 0);

        let (groups, rest) = out.as_chunks_mut::<64>();
        for chunk in groups {
            let block = encrypt4(&rk, counters);
            // SAFETY: `chunk` is exactly 64 writable bytes.
            unsafe { _mm512_storeu_si512(chunk.as_mut_ptr().cast(), block) };
            counters = _mm512_add_epi64(counters, step);
        }
        if !rest.is_empty() {
            let mut last = [0u8; 64];
            let block = encrypt4(&rk, counters);
            // SAFETY: `last` is 64 writable bytes.
            unsafe { _mm512_storeu_si512(last.as_mut_ptr().cast(), block) };
            rest.copy_from_slice(&last[..rest.len()]);
            crate::rng::keccak::wipe_bytes(&mut last);
        }
        for key in rk.iter_mut() {
            // SAFETY: `key` is a valid, aligned `&mut __m512i`.
            unsafe { core::ptr::write_volatile(key, _mm512_setzero_si512()) };
        }
    }
}

/// VAES on YMM: two AES blocks per instruction. The VAES parts without
/// AVX-512 — Alder Lake, Raptor Lake, Zen 3 — land here rather than on
/// AES-NI.
#[cfg(all(target_arch = "x86_64", feature = "simd"))]
pub mod vaes256 {
    use core::arch::x86_64::*;

    use super::{aesni, ROUND_KEYS};

    #[inline]
    #[target_feature(enable = "avx2,vaes")]
    fn encrypt2(rk: &[__m256i; ROUND_KEYS], counters: __m256i) -> __m256i {
        let mut b = _mm256_xor_si256(counters, rk[0]);
        for key in &rk[1..14] {
            b = _mm256_aesenc_epi128(b, *key);
        }
        _mm256_aesenclast_epi128(b, rk[14])
    }

    /// AES-256-CTR keystream from block `first` into `out`, 32 bytes (two
    /// counter blocks, one per 128-bit lane) per instruction; a short tail
    /// encrypts a whole pair and keeps what it needs.
    ///
    /// # Safety
    /// Requires VAES and AVX2 with the YMM state enabled in XCR0, and AES-NI
    /// for the schedule.
    #[target_feature(enable = "avx2,vaes,aes,sse2")]
    pub unsafe fn ctr(key: &[u8; 32], nonce: u64, first: u64, out: &mut [u8]) {
        let mut narrow = aesni::expand(key);
        let mut rk = [_mm256_setzero_si256(); ROUND_KEYS];
        for (wide, key) in rk.iter_mut().zip(narrow.iter()) {
            *wide = _mm256_broadcastsi128_si256(*key);
        }
        aesni::wipe(&mut narrow);

        // Lane j holds block `first + j`: nonce low, index high.
        let n = nonce as i64;
        let f = first as i64;
        let mut counters = _mm256_set_epi64x(f.wrapping_add(1), n, f, n);
        let step = _mm256_set_epi64x(2, 0, 2, 0);

        let (pairs, rest) = out.as_chunks_mut::<32>();
        for chunk in pairs {
            let block = encrypt2(&rk, counters);
            // SAFETY: `chunk` is exactly 32 writable bytes.
            unsafe { _mm256_storeu_si256(chunk.as_mut_ptr().cast(), block) };
            counters = _mm256_add_epi64(counters, step);
        }
        if !rest.is_empty() {
            let mut last = [0u8; 32];
            let block = encrypt2(&rk, counters);
            // SAFETY: `last` is 32 writable bytes.
            unsafe { _mm256_storeu_si256(last.as_mut_ptr().cast(), block) };
            rest.copy_from_slice(&last[..rest.len()]);
            crate::rng::keccak::wipe_bytes(&mut last);
        }
        for key in rk.iter_mut() {
            // SAFETY: `key` is a valid, aligned `&mut __m256i`.
            unsafe { core::ptr::write_volatile(key, _mm256_setzero_si256()) };
        }
    }
}

/// The ARMv8 Cryptography Extension.
#[cfg(all(target_arch = "aarch64", feature = "simd"))]
pub mod armv8 {
    use core::arch::aarch64::*;

    use super::ROUND_KEYS;

    /// `SubWord` through the AES unit: broadcast the word to all four
    /// columns, where `ShiftRows` moves nothing, and `AESE` with a zero key
    /// leaves `SubBytes` alone in every lane.
    #[inline]
    #[target_feature(enable = "aes")]
    fn sub_word(word: u32) -> u32 {
        let state = vreinterpretq_u8_u32(vdupq_n_u32(word));
        let substituted = vaeseq_u8(state, vdupq_n_u8(0));
        vgetq_lane_u32::<0>(vreinterpretq_u32_u8(substituted))
    }

    /// The AES-256 key schedule over 32-bit words (FIPS 197 §5.2). Words are
    /// little-endian, so `RotWord` is a right rotation by eight bits and the
    /// round constant lands in the low byte.
    #[target_feature(enable = "aes")]
    fn expand(key: &[u8; 32]) -> [uint8x16_t; ROUND_KEYS] {
        let mut w = [0u32; 4 * ROUND_KEYS];
        for (i, word) in w.iter_mut().take(8).enumerate() {
            *word = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        let mut rcon = 1u32;
        for i in 8..4 * ROUND_KEYS {
            let mut t = w[i - 1];
            if i % 8 == 0 {
                t = sub_word(t.rotate_right(8)) ^ rcon;
                rcon <<= 1;
            } else if i % 8 == 4 {
                t = sub_word(t);
            }
            w[i] = w[i - 8] ^ t;
        }
        let mut rk = [vdupq_n_u8(0); ROUND_KEYS];
        for (r, key) in rk.iter_mut().enumerate() {
            // SAFETY: `w` has 4 * ROUND_KEYS words, so four are readable here.
            *key = vreinterpretq_u8_u32(unsafe { vld1q_u32(w[4 * r..].as_ptr()) });
        }
        for word in w.iter_mut() {
            // SAFETY: `word` is a valid `&mut u32`.
            unsafe { core::ptr::write_volatile(word, 0) };
        }
        rk
    }

    /// AES-256-CTR keystream from block `first` into `out`.
    ///
    /// `AESE` is AddRoundKey, SubBytes and ShiftRows; `AESMC` is MixColumns.
    /// Thirteen of each, then a last `AESE` and the final key XOR.
    ///
    /// # Safety
    /// Requires the ARMv8 AES instructions, and FP/SIMD enabled at this EL.
    #[target_feature(enable = "aes")]
    pub unsafe fn ctr(key: &[u8; 32], nonce: u64, first: u64, out: &mut [u8]) {
        let mut rk = expand(key);
        let mut block = [0u8; 16];
        for (i, chunk) in out.chunks_mut(16).enumerate() {
            block[..8].copy_from_slice(&nonce.to_le_bytes());
            block[8..].copy_from_slice(&first.wrapping_add(i as u64).to_le_bytes());
            // SAFETY: `block` is 16 readable and writable bytes.
            let mut state = unsafe { vld1q_u8(block.as_ptr()) };
            for key in &rk[..13] {
                state = vaesmcq_u8(vaeseq_u8(state, *key));
            }
            state = veorq_u8(vaeseq_u8(state, rk[13]), rk[14]);
            // SAFETY: as above.
            unsafe { vst1q_u8(block.as_mut_ptr(), state) };
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        crate::rng::keccak::wipe_bytes(&mut block);
        for key in rk.iter_mut() {
            // SAFETY: `key` is a valid `&mut uint8x16_t`.
            unsafe { core::ptr::write_volatile(key, vdupq_n_u8(0)) };
        }
    }
}
