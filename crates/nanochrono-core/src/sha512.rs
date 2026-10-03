// SPDX-License-Identifier: Apache-2.0
//! SHA-512 (FIPS 180-4), for package integrity.
//!
//! A `.ncpkg` names every file it carries with its SHA-512 in the signed
//! manifest, and the signatures cover the SHA-512 of the manifest — so the
//! hash is what ties every byte of a package to its signature. The kernel
//! checks those hashes before it runs anything out of a package, with or
//! without the `plugin-verify` feature, so the hash lives here, `no_std` and
//! allocation-free, rather than behind the crypto crates. It is written from
//! the standard like [`crate::rng::keccak`]: eighty rounds of one formula.
//!
//! Words are read and written big-endian by shifting, never by viewing
//! memory, so the same code is right on the big-endian PowerPC targets. The
//! tests check it against vectors from an unrelated implementation (OpenSSL,
//! through Python's `hashlib`).

/// Digest length in bytes.
pub const DIGEST_LEN: usize = 64;
/// Block length in bytes.
pub const BLOCK_LEN: usize = 128;

/// The first 64 bits of the fractional parts of the square roots of the
/// first eight primes.
const H0: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// The first 64 bits of the fractional parts of the cube roots of the first
/// eighty primes.
const K: [u64; 80] = [
    0x428a_2f98_d728_ae22, 0x7137_4491_23ef_65cd, 0xb5c0_fbcf_ec4d_3b2f, 0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538, 0x59f1_11f1_b605_d019, 0x923f_82a4_af19_4f9b, 0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242, 0x1283_5b01_4570_6fbe, 0x2431_85be_4ee4_b28c, 0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f, 0x80de_b1fe_3b16_96b1, 0x9bdc_06a7_25c7_1235, 0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2, 0xefbe_4786_384f_25e3, 0x0fc1_9dc6_8b8c_d5b5, 0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275, 0x4a74_84aa_6ea6_e483, 0x5cb0_a9dc_bd41_fbd4, 0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab, 0xa831_c66d_2db4_3210, 0xb003_27c8_98fb_213f, 0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2, 0xd5a7_9147_930a_a725, 0x06ca_6351_e003_826f, 0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc, 0x2e1b_2138_5c26_c926, 0x4d2c_6dfc_5ac4_2aed, 0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de, 0x766a_0abb_3c77_b2a8, 0x81c2_c92e_47ed_aee6, 0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364, 0xa81a_664b_bc42_3001, 0xc24b_8b70_d0f8_9791, 0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218, 0xd699_0624_5565_a910, 0xf40e_3585_5771_202a, 0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8, 0x1e37_6c08_5141_ab53, 0x2748_774c_df8e_eb99, 0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63, 0x4ed8_aa4a_e341_8acb, 0x5b9c_ca4f_7763_e373, 0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc, 0x78a5_636f_4317_2f60, 0x84c8_7814_a1f0_ab72, 0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28, 0xa450_6ceb_de82_bde9, 0xbef9_a3f7_b2c6_7915, 0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c, 0xd186_b8c7_21c0_c207, 0xeada_7dd6_cde0_eb1e, 0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba, 0x0a63_7dc5_a2c8_98a6, 0x113f_9804_bef9_0dae, 0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84, 0x32ca_ab7b_40c7_2493, 0x3c9e_be0a_15c9_bebc, 0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6, 0x597f_299c_fc65_7e2a, 0x5fcb_6fab_3ad6_faec, 0x6c44_198c_4a47_5817,
];

/// An incremental SHA-512: feed it with [`update`](Self::update), read the
/// digest with [`finalize`](Self::finalize).
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    block: [u8; BLOCK_LEN],
    /// Bytes waiting in `block`.
    fill: usize,
    /// Message length so far, in bytes. A 128-bit count in bits is what the
    /// standard pads with; `u128` bytes cannot overflow it in practice and
    /// the shift below keeps the low 128 bits exactly as the standard does.
    len: u128,
}

impl core::fmt::Debug for Sha512 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sha512").field("len", &self.len).finish_non_exhaustive()
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    pub const fn new() -> Sha512 {
        Sha512 { state: H0, block: [0; BLOCK_LEN], fill: 0, len: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u128);
        if self.fill > 0 {
            let take = (BLOCK_LEN - self.fill).min(data.len());
            self.block[self.fill..self.fill + take].copy_from_slice(&data[..take]);
            self.fill += take;
            data = &data[take..];
            if self.fill < BLOCK_LEN {
                return;
            }
            let block = self.block;
            compress(&mut self.state, &block);
            self.fill = 0;
        }
        let mut blocks = data.chunks_exact(BLOCK_LEN);
        for block in &mut blocks {
            // `chunks_exact` hands out exactly BLOCK_LEN bytes.
            let mut b = [0u8; BLOCK_LEN];
            b.copy_from_slice(block);
            compress(&mut self.state, &b);
        }
        let rest = blocks.remainder();
        self.block[..rest.len()].copy_from_slice(rest);
        self.fill = rest.len();
    }

    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.len.wrapping_shl(3);
        let fill = self.fill;
        self.block[fill] = 0x80;
        self.block[fill + 1..].fill(0);
        // No room for the 16-byte length after the 0x80: one more block.
        if fill + 1 > BLOCK_LEN - 16 {
            let block = self.block;
            compress(&mut self.state, &block);
            self.block = [0; BLOCK_LEN];
        }
        for i in 0..16 {
            self.block[BLOCK_LEN - 1 - i] = (bits >> (8 * i)) as u8;
        }
        let block = self.block;
        compress(&mut self.state, &block);
        let mut out = [0u8; DIGEST_LEN];
        for (i, word) in self.state.iter().enumerate() {
            for j in 0..8 {
                out[i * 8 + j] = (word >> (56 - 8 * j)) as u8;
            }
        }
        out
    }
}

/// SHA-512 of `data` in one call.
pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

/// Constant-time equality of two digests: the comparison takes as long
/// whether the first or the last byte differs.
pub fn ct_eq(a: &[u8; DIGEST_LEN], b: &[u8; DIGEST_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..DIGEST_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn compress(state: &mut [u64; 8], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u64; 80];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        let mut v = 0u64;
        for j in 0..8 {
            v = (v << 8) | u64::from(block[i * 8 + j]);
        }
        *word = v;
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..80 {
        let big_s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(big_s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let big_s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

/// Lower-case hex of a digest, into a caller's buffer (no allocation).
pub fn to_hex(digest: &[u8; DIGEST_LEN], out: &mut [u8; DIGEST_LEN * 2]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in digest.iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 15)];
    }
}

/// Parses 128 lower-case hex digits — the only spelling the manifest and the
/// database use, so a digest has exactly one textual form.
pub fn from_hex(text: &[u8]) -> Option<[u8; DIGEST_LEN]> {
    if text.len() != DIGEST_LEN * 2 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; DIGEST_LEN];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nibble(text[2 * i])? << 4) | nibble(text[2 * i + 1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8; DIGEST_LEN]) -> std::string::String {
        let mut out = [0u8; DIGEST_LEN * 2];
        to_hex(d, &mut out);
        std::string::String::from_utf8(out.to_vec()).unwrap()
    }

    // Vectors from OpenSSL through Python's hashlib.
    #[test]
    fn known_answers() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            (b"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(hex(&digest(input)), *want);
        }
    }

    #[test]
    fn a_million_a() {
        let mut h = Sha512::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            hex(&h.finalize()),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        );
    }

    /// Every padding boundary (0..=300 bytes) and every split of the input
    /// gives the one-shot digest.
    #[test]
    fn incremental_matches_one_shot_at_every_boundary() {
        let data: std::vec::Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in 0..data.len() {
            let whole = digest(&data[..len]);
            for split in [0, 1, len / 3, len / 2, len.saturating_sub(1), len] {
                let split = split.min(len);
                let mut h = Sha512::new();
                h.update(&data[..split]);
                h.update(&data[split..len]);
                assert_eq!(h.finalize(), whole, "len {len} split {split}");
            }
        }
        // 111 and 112 bytes straddle the length field: one block, then two.
        assert_eq!(
            hex(&digest(&[0u8; 111])),
            "77ddd3a542e530fd047b8977c657ba6ce72f1492e360b2b2212cd264e75ec03882e4ff0525517ab4207d14c70c2259ba88d4d335ee0e7e20543d22102ab1788c"
        );
        assert_eq!(
            hex(&digest(&[0u8; 112])),
            "2be2e788c8a8adeaa9c89a7f78904cacea6e39297d75e0573a73c756234534d6627ab4156b48a6657b29ab8beb73334040ad39ead81446bb09c70704ec707952"
        );
    }

    #[test]
    fn hex_round_trips_and_refuses_other_spellings() {
        let d = digest(b"abc");
        let mut h = [0u8; 128];
        to_hex(&d, &mut h);
        assert_eq!(from_hex(&h), Some(d));
        h[0] = b'D';
        assert_eq!(from_hex(&h), None, "upper case is not the canonical spelling");
        assert_eq!(from_hex(&h[..126]), None);
        assert!(ct_eq(&d, &d));
        assert!(!ct_eq(&d, &digest(b"abd")));
    }
}
