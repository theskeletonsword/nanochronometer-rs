// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::vec::Vec;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Text-like data with repeats (the generator the reference frames were
/// made from, in Python, with the same constants).
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

// Frames from the reference library (zstd through Python's `zstandard`).
const SHORT: &str = "28b52ffd2017b9000048656c6c6f2c204e616e6f4368726f6e6f6d6574657221";
const ZEROS_300K: &str = "28b52ffda4e09304005400001000000100fbff39c00202001000039f04002d28de26";
const TEXT_L1: &str = "28b52ffd60b80a0d1400a288171790391d60ad0e24f99a083b12ecce69c03ffaf173bd2eab87719e9c423eb225d9f2a69bcc963c2bdec4f6ac5af226dfe4b63d2bf3ac7c563e2bdfe4b3f279720af9da9637f9d89c85311408034100011c468b1804250e8b3946717f492a8134a8618f2429159a0321041d08e3149e071120108d49821d1a9a141432ac0138e1ade1fe7834055115e00e07384e0091ec1ca39b460c32bed6ca1d33894f883f337524345e60a078e051d2c01345acf098fa80c84ba825a506695a4f5b3b8fc3d9a21f67756f0094301724ca08e3561024639ee11cde77d5e75b3e72ac092c19804c342648a849b779f44748f9ada115570f6336bf2a400915fd106c62f840869eaf8f2bc9e6ba9390d2644dce8d96fae1c6114b72370f97c64fc2de9ce0c18e616c63023c8aa41d84c135ac1e3eb9ef64c8f5ed6ab2d0c3788b3b5980a449f282f72696bfe42ef8f6b5027a52399eb902ecb50ef01430568f1428879cf739330b5cf0a272abb2e31593accd89ab75113c4c6c5e5aec432bdde5c63db16da56e34a3d50c79a17f38ebd360743f3c2935f55c4c878a77473084164f3963040e45f43790f131a83c29dc497aa18a70cc81816d7576ca4479ec677d6ec15f7a32f354a14b28f1fc0930ffa143fed399e363b0231b450621d2583a02111fdc0e01edb4fb486778c4f0bc66f441af185eefa0ed9cf448aafe3180d41e5af388bc16e362328df90cc50341e1b2bfdc0a633b41b1ee8a2f79a9b40c03f267b4a38147e2853a38655430e9248a0044017775b1cd102a3af65ad4f13968850c12f4786f865b3e514359c88bed802a5fd97a106a0a55ceadeddc2a0bc92111321db2bc4e820c3167cdb2a1e2de056b404dfb163e8f37b33cc016f0cf874743966a7e5b05";
const TEXT_L19_CHECKSUM: &str = "28b52ffd648812ad180022c81316804d3a802db36d19af39ee0cac92160018ee4467d503dfb66dbfdfb66dbfdfffb67ffbdff6ffdbefb7ffedff7731cb25362b52b7fe8ba72ecf72b204398c82188400f8c11cf52892a5417828354b8156a851d3a65259e61120084481a0e4d479128030480c8bd028cdb014cf218294931991a450e94bc208a92c0ec53302997eba29342b5a765f5f4230666cce4863ab45166d2f1208a9549916af18290421c2b3c1ce597fe25805750056bdb59c62222df15d84a89d0a07589046c6d320b65efe5f430a828e2cfe0c00b4bc923cd1b266257414c3bc58f44a2aaa4b3bab284e2ddc787095135a7f0296b961bc670884cdd7062bcb8bb08c1e88982cdad341293f541a6a3f206da17361b1eb9d749af4f05046fbb873223d22acf24c55606c5ad82026bf1a0755645fcc7aa3e62e36e5bd110b3b71bdb8deed64c58084d2604a6d065867541d86f194a7c2e082c5e2183d9ad048cef62c23d2e96bd0c4f0bc7b1cb5a459e9ffc29481c87068e9ee655423fdb8c0411dee75a7c416f740254ee7af0a421a45ca35845f60d2a5fde684bf101346d70ce31f4615be3aa200dbf88a48f315ae75ce475963c38db47179afe7a7af4a989dd96abf1810f8c4ab4702394a191c58dedd63a3a93194d5c2a66f4572a630c51e6fcd58393bcee8073fbd207b206cafddde7b378d7c2e652efc8b38c882b008319045c00735e0bcb39da3be19693acc098973519ae2bb645a41cafb22401a00d2e891d8f56bb9dfbb3be8c7371da300ad61258226ff6bd145c221b0deb68d96c9f1c42ec3d15f508acf76de29c46399120553921fd1ff4785d8310bc20b0045a9eb4ce1f6a62ea1fa8779a96ce1261a9ec22780a04f7bc7a9368ff6b4bbde8bdd54e718f235e50cf5cfd01136e14fba02da925b8ee9b02a66ea1d166607fbeddbd87ac267cf001daeaa0b2ff75a1eb9c8605fa5966fc1a65f994158f9b15d72dd1127f630658b590fc075c1080a2d2bafa86ee7b84ff38fde49b10a27f589c12d2e009f1118c70eced8da1098f5e480796b73e101af0816dac08d24460819012f4dd51beab0762b5a2b7836f1ce791260088495c03ff907e96faeab0a9ec02377";

fn decode(frame: &str, size: usize) -> Result<Vec<u8>> {
    let mut out = std::vec![0u8; size];
    decompress_exact(&unhex(frame), &mut out)?;
    Ok(out)
}

#[test]
fn reads_what_the_reference_library_writes() {
    assert_eq!(decode(SHORT, 23).unwrap(), b"Hello, NanoChronometer!");
    assert_eq!(decode(ZEROS_300K, 300_000).unwrap(), std::vec![0u8; 300_000]);
    assert_eq!(decode(TEXT_L1, 3000).unwrap(), gen(3000));
    assert_eq!(decode(TEXT_L19_CHECKSUM, 5000).unwrap(), gen(5000));
    // Frames back to back, a skippable frame between them.
    let mut two = unhex(SHORT);
    two.extend_from_slice(&[0x5A, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3]);
    two.extend_from_slice(&unhex(TEXT_L1));
    let mut out = std::vec![0u8; 3023];
    assert_eq!(decompress_into(&two, &mut out), Ok(3023));
    assert_eq!(&out[..23], b"Hello, NanoChronometer!");
    assert_eq!(&out[23..], &gen(3000)[..]);
}

#[test]
fn frame_headers() {
    let h = frame_header(&unhex(SHORT)).unwrap();
    assert_eq!(h.content_size, Some(23));
    assert!(!h.checksum);
    let h = frame_header(&unhex(TEXT_L19_CHECKSUM)).unwrap();
    assert_eq!(h.content_size, Some(5000));
    assert!(h.checksum);
    let h = frame_header(&unhex(ZEROS_300K)).unwrap();
    assert_eq!(h.content_size, Some(300_000));
}

/// The specification's Appendix A: the predefined tables, state by state.
#[test]
fn predefined_tables_match_the_specification() {
    let mut ll = Fse::<512>::new();
    ll.build(&LL_DEFAULT, 6).unwrap();
    let want_ll: [(u8, u8, u16); 64] = [
        (0, 4, 0), (0, 4, 16), (1, 5, 32), (3, 5, 0), (4, 5, 0), (6, 5, 0), (7, 5, 0), (9, 5, 0),
        (10, 5, 0), (12, 5, 0), (14, 6, 0), (16, 5, 0), (18, 5, 0), (19, 5, 0), (21, 5, 0), (22, 5, 0),
        (24, 5, 0), (25, 5, 32), (26, 5, 0), (27, 6, 0), (29, 6, 0), (31, 6, 0), (0, 4, 32), (1, 4, 0),
        (2, 5, 0), (4, 5, 32), (5, 5, 0), (7, 5, 32), (8, 5, 0), (10, 5, 32), (11, 5, 0), (13, 6, 0),
        (16, 5, 32), (17, 5, 0), (19, 5, 32), (20, 5, 0), (22, 5, 32), (23, 5, 0), (25, 4, 0), (25, 4, 16),
        (26, 5, 32), (28, 6, 0), (30, 6, 0), (0, 4, 48), (1, 4, 16), (2, 5, 32), (3, 5, 32), (5, 5, 32),
        (6, 5, 32), (8, 5, 32), (9, 5, 32), (11, 5, 32), (12, 5, 32), (15, 6, 0), (17, 5, 32), (18, 5, 32),
        (20, 5, 32), (21, 5, 32), (23, 5, 32), (24, 5, 32), (35, 6, 0), (34, 6, 0), (33, 6, 0), (32, 6, 0),
    ];
    for (i, &(s, b, base)) in want_ll.iter().enumerate() {
        assert_eq!(ll.e[i], FseEntry { symbol: s, bits: b, base }, "LL state {i}");
    }
    let mut ml = Fse::<512>::new();
    ml.build(&ML_DEFAULT, 6).unwrap();
    let want_ml: [(u8, u8, u16); 64] = [
        (0, 6, 0), (1, 4, 0), (2, 5, 32), (3, 5, 0), (5, 5, 0), (6, 5, 0), (8, 5, 0), (10, 6, 0),
        (13, 6, 0), (16, 6, 0), (19, 6, 0), (22, 6, 0), (25, 6, 0), (28, 6, 0), (31, 6, 0), (33, 6, 0),
        (35, 6, 0), (37, 6, 0), (39, 6, 0), (41, 6, 0), (43, 6, 0), (45, 6, 0), (1, 4, 16), (2, 4, 0),
        (3, 5, 32), (4, 5, 0), (6, 5, 32), (7, 5, 0), (9, 6, 0), (12, 6, 0), (15, 6, 0), (18, 6, 0),
        (21, 6, 0), (24, 6, 0), (27, 6, 0), (30, 6, 0), (32, 6, 0), (34, 6, 0), (36, 6, 0), (38, 6, 0),
        (40, 6, 0), (42, 6, 0), (44, 6, 0), (1, 4, 32), (1, 4, 48), (2, 4, 16), (4, 5, 32), (5, 5, 32),
        (7, 5, 32), (8, 5, 32), (11, 6, 0), (14, 6, 0), (17, 6, 0), (20, 6, 0), (23, 6, 0), (26, 6, 0),
        (29, 6, 0), (52, 6, 0), (51, 6, 0), (50, 6, 0), (49, 6, 0), (48, 6, 0), (47, 6, 0), (46, 6, 0),
    ];
    for (i, &(s, b, base)) in want_ml.iter().enumerate() {
        assert_eq!(ml.e[i], FseEntry { symbol: s, bits: b, base }, "ML state {i}");
    }
    let mut of = Fse::<256>::new();
    of.build(&OF_DEFAULT, 5).unwrap();
    let want_of: [(u8, u8, u16); 32] = [
        (0, 5, 0), (6, 4, 0), (9, 5, 0), (15, 5, 0), (21, 5, 0), (3, 5, 0), (7, 4, 0), (12, 5, 0),
        (18, 5, 0), (23, 5, 0), (5, 5, 0), (8, 4, 0), (14, 5, 0), (20, 5, 0), (2, 5, 0), (7, 4, 16),
        (11, 5, 0), (17, 5, 0), (22, 5, 0), (4, 5, 0), (8, 4, 16), (13, 5, 0), (19, 5, 0), (1, 5, 0),
        (6, 4, 16), (10, 5, 0), (16, 5, 0), (28, 5, 0), (27, 5, 0), (26, 5, 0), (25, 5, 0), (24, 5, 0),
    ];
    for (i, &(s, b, base)) in want_of.iter().enumerate() {
        assert_eq!(of.e[i], FseEntry { symbol: s, bits: b, base }, "OF state {i}");
    }
}

// XXH64 (seed 0) from the reference `xxhash` package.
#[test]
fn xxh64_known_answers() {
    assert_eq!(xxh64(b""), 0xef46_db37_51d8_e999);
    assert_eq!(xxh64(b"a"), 0xd24e_c4f1_a98c_6e5b);
    assert_eq!(xxh64(b"abc"), 0x44bc_2cf5_ad77_0999);
    assert_eq!(xxh64(b"0123456789abcdef0123456789abcdef"), 0x642a_9495_8e71_e6c5);
    let ramp: Vec<u8> = (0..100u8).collect();
    assert_eq!(xxh64(&ramp), 0x6ac1_e580_3216_6597);
}

#[test]
fn malformed_frames_have_their_errors() {
    let mut out = [0u8; 64];
    assert_eq!(decompress_into(&[], &mut out), Err(Error::Truncated));
    assert_eq!(decompress_into(b"\x28\xb5\x2f", &mut out), Err(Error::Truncated));
    assert_eq!(decompress_into(b"PK\x03\x04", &mut out), Err(Error::BadMagic));
    // The reserved bit.
    let mut f = unhex(SHORT);
    f[4] |= 0x08;
    assert_eq!(decompress_into(&f, &mut out), Err(Error::Reserved));
    // A dictionary id: one byte, non-zero.
    let mut f = unhex(SHORT);
    f[4] |= 0x01;
    f.insert(5, 7);
    assert_eq!(decompress_into(&f, &mut out), Err(Error::Dictionary));
    // Too little room, too much room.
    assert_eq!(decompress_into(&unhex(SHORT), &mut out[..22]), Err(Error::Overflow));
    assert_eq!(decompress_exact(&unhex(SHORT), &mut out[..24]), Err(Error::Short));
    // A content size the blocks do not deliver.
    let mut f = unhex(SHORT);
    f[5] = 24;
    assert_eq!(decompress_into(&f, &mut out), Err(Error::Short));
    // A checksum that does not match.
    let mut f = unhex(TEXT_L19_CHECKSUM);
    let n = f.len();
    f[n - 1] ^= 1;
    let mut big = std::vec![0u8; 5000];
    assert_eq!(decompress_into(&f, &mut big), Err(Error::Checksum));
    // Reserved block type.
    let mut f = unhex(SHORT);
    f[6] |= 0x06;
    assert_eq!(decompress_into(&f, &mut out), Err(Error::Reserved));
}

/// Mutated frames: never a panic, never more output than the buffer.
#[test]
fn corrupted_frames_never_panic() {
    let bases = [unhex(TEXT_L1), unhex(TEXT_L19_CHECKSUM), unhex(ZEROS_300K), unhex(SHORT)];
    let mut x = 0xDEAD_BEEF_CAFE_F00Du64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut out = std::vec![0u8; 300_000];
    let mut ws = Workspace::new();
    for round in 0..20_000 {
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
        let _ = ws.decompress_into(&b, &mut out);
        let _ = ws.decompress_into(&b, &mut out[..1000]);
    }
}
