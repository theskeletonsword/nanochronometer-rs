// SPDX-License-Identifier: Apache-2.0
//! BLAKE3: the checksum in every NCFS block pointer.
//!
//! NCFS keeps the BLAKE3 hash of every block it points at beside the
//! pointer, so a tree of pointers is a Merkle tree: the superblock's root
//! hash covers every byte of the volume, and signing it (an
//! `ncinitramdisk`) signs all of them. That makes the hash part of the
//! filesystem's format, read by the kernel before it trusts a block — so it
//! lives here, `no_std` and allocation-free, beside [`crate::sha512`].
//!
//! Written from the BLAKE3 specification (O'Connor, Aumasson, Neves,
//! Wilcox-O'Hearn, 2020): seven rounds of ChaCha's quarter-round over a
//! 64-byte block, 1 KiB chunks, chunks joined as a binary tree. Keyed
//! hashing, key derivation and output of any length are the same function
//! with different flags, and all three are here. Words are read and written
//! little-endian by shifting, never by viewing memory, so the big-endian
//! PowerPC targets compute the same digests. The tests check it against an
//! unrelated implementation (the reference `blake3` package, through
//! Python).
//!
//! This is the portable form — about a gigabyte a second on a current core,
//! far more than a disk delivers per core; the vector forms buy throughput
//! the filesystem does not need.

/// Digest length in bytes (any length can be read: [`Hasher::finalize_xof`]).
pub const OUT_LEN: usize = 32;
/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Block length in bytes.
pub const BLOCK_LEN: usize = 64;
/// Chunk length in bytes: the leaves of the tree.
pub const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

/// SHA-256's initial hash value, which BLAKE3 takes as its IV.
const IV: [u32; 8] = [0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A, 0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19];

/// How the message words are reordered between rounds.
const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// The quarter-round: mixes column or diagonal `a b c d` with two message
/// words.
#[inline(always)]
fn g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(x);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(y);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

#[inline(always)]
fn round(s: &mut [u32; 16], m: &[u32; 16]) {
    // The columns.
    g(s, 0, 4, 8, 12, m[0], m[1]);
    g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);
    g(s, 3, 7, 11, 15, m[6], m[7]);
    // The diagonals.
    g(s, 0, 5, 10, 15, m[8], m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]);
    g(s, 3, 4, 9, 14, m[14], m[15]);
}

/// The compression function: a chaining value and one block in, sixteen
/// words out (the first eight are the next chaining value; all sixteen are
/// output bytes for a root).
fn compress(cv: &[u32; 8], block: &[u32; 16], counter: u64, block_len: u32, flags: u32) -> [u32; 16] {
    let mut s = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut m = *block;
    for r in 0..7 {
        round(&mut s, &m);
        if r < 6 {
            let p = m;
            for (dst, &src) in m.iter_mut().zip(PERMUTATION.iter()) {
                *dst = p[src];
            }
        }
    }
    for i in 0..8 {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    s
}

fn first8(w: [u32; 16]) -> [u32; 8] {
    let mut out = [0u32; 8];
    out.copy_from_slice(&w[..8]);
    out
}

/// Little-endian words from up to 64 bytes; the rest of the block is zero.
fn words(bytes: &[u8]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for (i, b) in bytes.iter().take(BLOCK_LEN).enumerate() {
        w[i / 4] |= u32::from(*b) << (8 * (i % 4));
    }
    w
}

fn key_words(key: &[u8; KEY_LEN]) -> [u32; 8] {
    first8(words(key))
}

/// What one more compression would produce: kept unevaluated so the last
/// node can still become the root.
#[derive(Clone, Copy)]
struct Output {
    cv: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first8(compress(&self.cv, &self.block, self.counter, self.block_len, self.flags))
    }

    /// The root's output: 64 bytes per output block, counted from `seek / 64`.
    fn root_bytes(&self, seek: u64, out: &mut [u8]) {
        let mut counter = seek / (2 * OUT_LEN as u64);
        let mut skip = (seek % (2 * OUT_LEN as u64)) as usize;
        let mut out = out;
        while !out.is_empty() {
            let w = compress(&self.cv, &self.block, counter, self.block_len, self.flags | ROOT);
            let mut bytes = [0u8; 2 * OUT_LEN];
            for (chunk, word) in bytes.chunks_exact_mut(4).zip(w.iter()) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            let take = (bytes.len() - skip).min(out.len());
            out[..take].copy_from_slice(&bytes[skip..skip + take]);
            out = &mut out[take..];
            skip = 0;
            counter += 1;
        }
    }
}

/// The chunk being filled: up to sixteen blocks.
#[derive(Clone, Copy)]
struct Chunk {
    cv: [u32; 8],
    counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_done: u8,
    flags: u32,
}

impl Chunk {
    fn new(key: [u32; 8], counter: u64, flags: u32) -> Chunk {
        Chunk { cv: key, counter, block: [0; BLOCK_LEN], block_len: 0, blocks_done: 0, flags }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * usize::from(self.blocks_done) + usize::from(self.block_len)
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_done == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // A full buffer with more input to come is not the chunk's end.
            if usize::from(self.block_len) == BLOCK_LEN {
                let w = words(&self.block);
                self.cv = first8(compress(&self.cv, &w, self.counter, BLOCK_LEN as u32, self.flags | self.start_flag()));
                self.blocks_done += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let at = usize::from(self.block_len);
            let take = (BLOCK_LEN - at).min(input.len());
            self.block[at..at + take].copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            cv: self.cv,
            block: words(&self.block[..usize::from(self.block_len)]),
            counter: self.counter,
            block_len: u32::from(self.block_len),
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent(left: [u32; 8], right: [u32; 8], key: [u32; 8], flags: u32) -> Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(&left);
    block[8..].copy_from_slice(&right);
    Output { cv: key, block, counter: 0, block_len: BLOCK_LEN as u32, flags: PARENT | flags }
}

/// An incremental BLAKE3: plain, keyed or deriving a key.
#[derive(Clone)]
pub struct Hasher {
    chunk: Chunk,
    key: [u32; 8],
    /// One chaining value per completed subtree on the tree's left edge:
    /// 54 of them reach 2^54 chunks, 2^64 bytes.
    stack: [[u32; 8]; 54],
    depth: u8,
    flags: u32,
}

impl core::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never the state: a keyed hasher's state is derived from its key.
        f.debug_struct("Hasher").field("chunks", &self.chunk.counter).finish_non_exhaustive()
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    fn with(key: [u32; 8], flags: u32) -> Hasher {
        Hasher { chunk: Chunk::new(key, 0, flags), key, stack: [[0; 8]; 54], depth: 0, flags }
    }

    /// Plain hashing.
    pub fn new() -> Hasher {
        Hasher::with(IV, 0)
    }

    /// Keyed hashing: a MAC, or a hash only the holder of `key` can match.
    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Hasher {
        Hasher::with(key_words(key), KEYED_HASH)
    }

    /// Key derivation: `context` is a hard-coded, globally unique string
    /// naming the purpose (`"NCFS 2026-10 node checksum"`); the input is
    /// the key material.
    pub fn new_derive_key(context: &str) -> Hasher {
        let mut h = Hasher::with(IV, DERIVE_KEY_CONTEXT);
        h.update(context.as_bytes());
        let mut ck = [0u8; KEY_LEN];
        h.finalize_xof(0, &mut ck);
        Hasher::with(key_words(&ck), DERIVE_KEY_MATERIAL)
    }

    fn add_chunk_cv(&mut self, mut cv: [u32; 8], mut total: u64) {
        // Each trailing zero bit of the new chunk count completes one
        // subtree: merge it with the left sibling on the stack.
        while total & 1 == 0 {
            self.depth -= 1;
            cv = parent(self.stack[usize::from(self.depth)], cv, self.key, self.flags).chaining_value();
            total >>= 1;
        }
        self.stack[usize::from(self.depth)] = cv;
        self.depth += 1;
    }

    pub fn update(&mut self, mut input: &[u8]) -> &mut Hasher {
        while !input.is_empty() {
            // A full chunk with more input to come is not the root.
            if self.chunk.len() == CHUNK_LEN {
                let cv = self.chunk.output().chaining_value();
                let total = self.chunk.counter + 1;
                self.add_chunk_cv(cv, total);
                self.chunk = Chunk::new(self.key, total, self.flags);
            }
            let take = (CHUNK_LEN - self.chunk.len()).min(input.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
        self
    }

    fn root(&self) -> Output {
        let mut out = self.chunk.output();
        for i in (0..usize::from(self.depth)).rev() {
            out = parent(self.stack[i], out.chaining_value(), self.key, self.flags);
        }
        out
    }

    /// The 32-byte digest. The hasher stays usable: more input can follow.
    pub fn finalize(&self) -> [u8; OUT_LEN] {
        let mut out = [0u8; OUT_LEN];
        self.root().root_bytes(0, &mut out);
        out
    }

    /// Output of any length, from byte `seek` of the output stream on.
    pub fn finalize_xof(&self, seek: u64, out: &mut [u8]) {
        self.root().root_bytes(seek, out);
    }
}

/// The BLAKE3 digest of `data`.
pub fn hash(data: &[u8]) -> [u8; OUT_LEN] {
    Hasher::new().update(data).finalize()
}

/// The keyed BLAKE3 digest of `data`.
pub fn keyed_hash(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; OUT_LEN] {
    Hasher::new_keyed(key).update(data).finalize()
}

/// A 32-byte key derived from `material` for the purpose `context` names.
pub fn derive_key(context: &str, material: &[u8]) -> [u8; KEY_LEN] {
    Hasher::new_derive_key(context).update(material).finalize()
}

/// Compares two digests in time independent of where they differ.
pub fn ct_eq(a: &[u8; OUT_LEN], b: &[u8; OUT_LEN]) -> bool {
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    // Keep the comparison from being turned into an early exit.
    core::hint::black_box(d) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;
    use std::vec::Vec;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| std::format!("{x:02x}")).collect()
    }

    /// The input the BLAKE3 test vectors use: byte i is i mod 251.
    fn input(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    const KEY: &[u8; 32] = b"whats the Elvish word for friend";
    const CONTEXT: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    // (length, hash, keyed hash, derived key), from the reference `blake3`
    // package (Python), over every boundary a block, a chunk and the tree
    // have.
    const VECTORS: &[(usize, &str, &str, &str)] = &[
        (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26", "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
        (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b", "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
        (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63", "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a", "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6"),
        (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b", "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae", "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3"),
        (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98", "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6", "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"),
        (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee", "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72", "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8"),
        (127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d", "c64200ae7dfaf35577ac5a9521c47863fb71514a3bcad18819218b818de85818", "c91c090ceee3a3ac81902da31838012625bbcd73fcb92e7d7e56f78deba4f0c3"),
        (128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef", "b04fe15577457267ff3b6f3c947d93be581e7e3a4b018679125eaf86f6a628ec", "81720f34452f58a0120a58b6b4608384b5c51d11f39ce97161a0c0e442ca0225"),
        (129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12", "d4a64dae6cdccbac1e5287f54f17c5f985105457c1a2ec1878ebd4b57e20d38f", "938d2d4435be30eafdbb2b7031f7857c98b04881227391dc40db3c7b21f41fc1"),
        (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11", "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e", "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"),
        (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4", "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"),
        (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444", "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69", "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"),
        (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a", "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1", "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23"),
        (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030", "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5", "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273"),
        (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2", "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df191770", "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b"),
        (3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3", "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a", "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081"),
        (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969", "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0", "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9"),
        (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995", "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc", "aca51029626b55fda7117b42a7c211f8c6e9ba4fe5b7a8ca922f34299500ead8"),
        (5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833", "2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e20", "7a7acac8a02adcf3038d74cdd1d34527de8a0fcc0ee3399d1262397ce5817f60"),
        (5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff", "6ccf1c34753e7a044db80798ecd0782a8f76f33563accaddbfbb2e0ea4b2d024", "b07f01e518e702f7ccb44a267e9e112d403a7b3f4883a47ffbed4b48339b3c34"),
        (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63", "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a", "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d"),
        (8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b", "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5", "af1e0346e389b17c23200270a64aa4e1ead98c61695d917de7d5b00491c9b0f1"),
        (16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4", "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0d", "160e18b5878cd0df1c3af85eb25a0db5344d43a6fbd7a8ef4ed98d0714c3f7e1"),
        (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47", "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419", "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e"),
        (102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085", "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7", "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6"),
    ];

    #[test]
    fn known_answers() {
        for &(n, plain, keyed, derived) in VECTORS {
            let data = input(n);
            assert_eq!(hex(&hash(&data)), plain, "hash, {n} bytes");
            assert_eq!(hex(&keyed_hash(KEY, &data)), keyed, "keyed, {n} bytes");
            assert_eq!(hex(&derive_key(CONTEXT, &data)), derived, "derive_key, {n} bytes");
        }
        assert_eq!(hex(&hash(b"abc")), "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
    }

    #[test]
    fn extended_output_and_seeking() {
        let data = input(1025);
        let want = "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a";
        let mut h = Hasher::new();
        h.update(&data);
        let mut out = [0u8; 131];
        h.finalize_xof(0, &mut out);
        assert_eq!(hex(&out), want);
        // Any window of the stream reads the same bytes.
        for seek in [1usize, 31, 63, 64, 65, 100] {
            let mut part = [0u8; 20];
            h.finalize_xof(seek as u64, &mut part);
            assert_eq!(part[..], out[seek..seek + 20], "seek {seek}");
        }
        let keyed = "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69362396b77fdc0d2634a552970843722066c3c15902ae5097e00ff53f1e116f1cd5352720113a837ab2452cafbde4d54085d9cf5d21ca613071551b25d52e69d6c81123872b6f19cd3bc1333edf0c52b94de23ba772cf82636cff4542540a7738d5b930";
        let mut out = [0u8; 131];
        Hasher::new_keyed(KEY).update(&data).finalize_xof(0, &mut out);
        assert_eq!(hex(&out), keyed);
    }

    /// Every split of the input gives the one-shot digest, and finalising
    /// leaves the hasher able to take more.
    #[test]
    fn incremental_matches_one_shot() {
        let data = input(5121);
        let whole = hash(&data);
        for split in [0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3000, 5120, 5121] {
            let mut h = Hasher::new();
            h.update(&data[..split]);
            let _ = h.finalize();
            h.update(&data[split..]);
            assert_eq!(h.finalize(), whole, "split {split}");
        }
        let mut h = Hasher::new();
        for b in &data {
            h.update(core::slice::from_ref(b));
        }
        assert_eq!(h.finalize(), whole, "byte by byte");
        assert!(ct_eq(&whole, &whole));
        assert!(!ct_eq(&whole, &hash(&data[1..])));
    }
}
