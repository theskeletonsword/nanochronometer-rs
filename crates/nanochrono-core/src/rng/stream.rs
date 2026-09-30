// SPDX-License-Identifier: Apache-2.0
//! The output stage: an XDRBG-256 key expanded by a stream cipher, on the
//! fastest path this CPU has.
//!
//! # Hybrid, chosen at run time
//!
//! | Engine | Needs | Path |
//! |---|---|---|
//! | [`Engine::Vaes512`] | VAES + AVX-512F, ZMM state enabled (CPUID, XCR0) | AES-256-CTR, four blocks per instruction |
//! | [`Engine::Vaes256`] | VAES + AVX2, YMM state enabled | AES-256-CTR, two blocks per instruction |
//! | [`Engine::AesNi`] | AES-NI (CPUID) | AES-256-CTR on XMM |
//! | [`Engine::ArmAes`] | ARMv8 AES (`ID_AA64ISAR0_EL1`, or the OS on a hosted build) | AES-256-CTR with `AESE`/`AESMC` |
//! | [`Engine::ChaCha20`] | nothing | ChaCha20 in portable 32-bit software |
//!
//! [`Engine::detect`] asks [`crate::cpu`] — which checks the OS-enabled
//! register state as well as the CPUID bit, since a ZMM instruction with the
//! state disabled is `#UD`, not a slow path — and the pool then runs the
//! chosen engine's known-answer test before using it. A hardware path that
//! fails its test is dropped for ChaCha20, and the status says so. ChaCha20
//! can also be chosen outright, by design rather than necessity.
//!
//! # Nonces are never reused
//!
//! The stage follows Bernstein's fast-key-erasure construction:
//!
//! 1. Every request takes the next value of a 64-bit nonce counter. The
//!    counter only ever increases, and nothing resets it — not a rekey, not
//!    a reseed — so no key is ever used under the same nonce twice, even in
//!    the (2⁻²⁵⁶) event that a key came back.
//! 2. The keystream's first 32 bytes become the next key and the old key is
//!    erased; the output starts after them. Key blocks are never handed out.
//! 3. A request is at most [`CHUNK`] bytes, so a key is used once, briefly,
//!    and the block counter (32 bits for ChaCha20) is nowhere near a wrap.
//!
//! Once the output of a request has been returned, nothing in memory can
//! recompute it: the key that made it is gone.

use super::keccak::{sha3_256, wipe_bytes};
use super::{chacha20, RngError};

/// Most output per request, and per key.
pub const CHUNK: usize = 4096;

/// A path the output stage can run on. The discriminant is the C ABI's
/// `NC_RNG_ENGINE_*` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Engine {
    /// AES-256-CTR, VAES on ZMM.
    Vaes512 = 1,
    /// AES-256-CTR, VAES on YMM (VAES without AVX-512).
    Vaes256 = 2,
    /// AES-256-CTR, AES-NI on XMM.
    AesNi = 3,
    /// AES-256-CTR, the ARMv8 Cryptography Extension.
    ArmAes = 4,
    /// ChaCha20, software.
    ChaCha20 = 5,
}

/// Which engine the embedder wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EngineChoice {
    /// The fastest the CPU has that passes its self-test.
    #[default]
    Auto,
    /// ChaCha20 even where AES hardware exists.
    Software,
}

impl Engine {
    pub const fn name(self) -> &'static str {
        match self {
            Engine::Vaes512 => "AES-256-CTR (VAES, 512-bit)",
            Engine::Vaes256 => "AES-256-CTR (VAES, 256-bit)",
            Engine::AesNi => "AES-256-CTR (AES-NI)",
            Engine::ArmAes => "AES-256-CTR (ARMv8 AES)",
            Engine::ChaCha20 => "ChaCha20 (software)",
        }
    }

    /// The best engine this build can run on this CPU.
    pub fn detect() -> Engine {
        [Engine::Vaes512, Engine::Vaes256, Engine::AesNi, Engine::ArmAes]
            .into_iter()
            .find(|engine| engine.is_supported())
            .unwrap_or(Engine::ChaCha20)
    }

    /// Whether this engine is compiled into this build *and* the CPU (with
    /// the OS's register state) can run it.
    pub fn is_supported(self) -> bool {
        #[cfg(any(
            all(any(target_arch = "x86_64", target_arch = "x86"), feature = "simd"),
            all(target_arch = "aarch64", feature = "simd")
        ))]
        let f = crate::cpu::features();
        match self {
            #[cfg(all(target_arch = "x86_64", feature = "simd"))]
            Engine::Vaes512 => f.vaes && f.avx512f && f.aesni,
            #[cfg(all(target_arch = "x86_64", feature = "simd"))]
            Engine::Vaes256 => f.vaes && f.avx2 && f.aesni,
            #[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), feature = "simd"))]
            Engine::AesNi => f.aesni,
            #[cfg(all(target_arch = "aarch64", feature = "simd"))]
            Engine::ArmAes => f.arm_aes,
            Engine::ChaCha20 => true,
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Keystream blocks the next key is taken from; output starts after them.
    const fn key_blocks(self) -> u64 {
        match self {
            // Two 16-byte AES blocks.
            Engine::Vaes512 | Engine::Vaes256 | Engine::AesNi | Engine::ArmAes => 2,
            // The first half of one 64-byte block; the second half is dropped.
            Engine::ChaCha20 => 1,
        }
    }

    /// Keystream under `key` and `nonce`, from block `first`, into `out`.
    fn keystream(self, key: &[u8; 32], nonce: u64, first: u64, out: &mut [u8]) {
        match self {
            // SAFETY (all three): a `Stream` only ever holds an engine that
            // `is_supported` accepted, which is the CPUID/XCR0/ID-register
            // check each path's contract asks for.
            #[cfg(all(target_arch = "x86_64", feature = "simd"))]
            Engine::Vaes512 => unsafe { super::aes::vaes512::ctr(key, nonce, first, out) },
            #[cfg(all(target_arch = "x86_64", feature = "simd"))]
            Engine::Vaes256 => unsafe { super::aes::vaes256::ctr(key, nonce, first, out) },
            #[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), feature = "simd"))]
            Engine::AesNi => unsafe { super::aes::aesni::ctr(key, nonce, first, out) },
            #[cfg(all(target_arch = "aarch64", feature = "simd"))]
            Engine::ArmAes => unsafe { super::aes::armv8::ctr(key, nonce, first, out) },
            _ => chacha20::keystream(key, nonce, first as u32, out),
        }
    }
}

/// The output stage's state: the current key, and the nonce counter.
pub struct Stream {
    engine: Engine,
    key: [u8; 32],
    keyed: bool,
    /// The next request's nonce. Strictly increasing; never reset.
    next_nonce: u64,
}

impl core::fmt::Debug for Stream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stream")
            .field("engine", &self.engine)
            .field("keyed", &self.keyed)
            .field("next_nonce", &self.next_nonce)
            .finish_non_exhaustive()
    }
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

impl Stream {
    /// An unkeyed stage on ChaCha20; [`set_engine`](Self::set_engine) picks
    /// the real one once it has passed its self-test.
    pub const fn new() -> Self {
        Stream { engine: Engine::ChaCha20, key: [0; 32], keyed: false, next_nonce: 0 }
    }

    pub fn engine(&self) -> Engine {
        self.engine
    }

    /// Switches engine. One the CPU cannot run becomes ChaCha20, so the
    /// stage never holds an engine whose instructions would fault.
    pub fn set_engine(&mut self, engine: Engine) {
        self.engine = if engine.is_supported() { engine } else { Engine::ChaCha20 };
    }

    /// Nonces consumed so far: one per request.
    pub fn nonces_used(&self) -> u64 {
        self.next_nonce
    }

    /// Installs a fresh key from the XDRBG. The nonce counter carries on.
    pub fn rekey(&mut self, key: &[u8; 32]) {
        self.key = *key;
        self.keyed = true;
    }

    /// Fills `out` (at most [`CHUNK`] bytes) with keystream under a fresh
    /// nonce, and replaces the key with keystream that was not handed out.
    pub fn generate(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        if !self.keyed || out.len() > CHUNK {
            return Err(RngError::Misuse);
        }
        // 2⁶⁴ requests will not happen; if they did, refusing is the only
        // answer that cannot repeat a nonce.
        let nonce = self.next_nonce;
        self.next_nonce = nonce.checked_add(1).ok_or(RngError::Misuse)?;

        let mut next = [0u8; 32];
        self.engine.keystream(&self.key, nonce, 0, &mut next);
        self.engine.keystream(&self.key, nonce, self.engine.key_blocks(), out);
        self.key = next;
        wipe_bytes(&mut next);
        Ok(())
    }

    /// Erases the key. The nonce counter is kept: a later key must not
    /// start the nonces over.
    pub fn wipe(&mut self) {
        wipe_bytes(&mut self.key);
        self.keyed = false;
    }
}

// Known answers from tools/nc_rng_kat.py (OpenSSL through `cryptography`).
/// FIPS 197 C.3: AES-256, key 00..1f, plaintext 00112233…eeff.
const AES256_FIPS197: [u8; 16] = [
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
];
/// SHA3-256 of nine CTR blocks, key 00..1f, nonce 0x0706050403020100.
const AES_CTR_9_SHA3: [u8; 32] = [
    0x12, 0x33, 0xe9, 0x8b, 0x70, 0xbc, 0x3e, 0xe5, 0xad, 0x5e, 0x16, 0xbe, 0x80, 0x11, 0x59, 0x66,
    0x66, 0x45, 0x9a, 0x84, 0x6c, 0x50, 0xa2, 0xa0, 0x3e, 0xd0, 0x84, 0xc9, 0x23, 0x45, 0xbf, 0x3a,
];
/// SHA3-256 of five ChaCha20 blocks under the stage's nonce layout.
const CHACHA_5_SHA3: [u8; 32] = [
    0x12, 0x66, 0xdd, 0x0c, 0xd2, 0x33, 0xc0, 0x94, 0xb7, 0x55, 0x1e, 0xc9, 0x3c, 0x25, 0x59, 0xdc,
    0x0e, 0x1f, 0x12, 0xf9, 0x33, 0xc3, 0x6a, 0xdd, 0x01, 0x73, 0x96, 0xd5, 0x6f, 0xd4, 0x02, 0x6e,
];
/// SHA3-256 of three requests (50, 200 and 1 bytes) from key 00..1f.
const STREAM_AES_SHA3: [u8; 32] = [
    0x69, 0xc6, 0x5c, 0xdd, 0xdc, 0xac, 0xdf, 0x0f, 0xc4, 0x22, 0x79, 0xd6, 0x3e, 0x7d, 0x62, 0x55,
    0xa5, 0x36, 0x52, 0x13, 0x7c, 0x37, 0x61, 0xd3, 0xfe, 0xf2, 0x36, 0xe5, 0xc6, 0xb9, 0x34, 0x7b,
];
const STREAM_CHACHA_SHA3: [u8; 32] = [
    0x30, 0xa1, 0x16, 0x37, 0xd1, 0x6f, 0xc0, 0x1e, 0x12, 0xfd, 0x9b, 0x83, 0x16, 0xfd, 0x71, 0xd9,
    0xdb, 0x96, 0x74, 0xc9, 0xc3, 0xa3, 0x38, 0x97, 0xc3, 0xa4, 0x32, 0x20, 0xd4, 0x53, 0x06, 0xc5,
];

/// The engine's known answers: the raw cipher, its counter layout, and the
/// fast-key-erasure sequence. `false` for an engine this machine cannot run.
pub fn selftest(engine: Engine) -> bool {
    if !engine.is_supported() {
        return false;
    }
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);

    let cipher_ok = match engine {
        Engine::ChaCha20 => {
            let mut five = [0u8; 320];
            engine.keystream(&key, 0x0706_0504_0302_0100, 0, &mut five);
            chacha20::selftest() && sha3_256(&[&five]) == CHACHA_5_SHA3
        }
        _ => {
            // The FIPS plaintext read as a counter block: the nonce is its
            // first eight bytes, the index its last eight.
            let mut single = [0u8; 16];
            engine.keystream(&key, 0x7766_5544_3322_1100, 0xFFEE_DDCC_BBAA_9988, &mut single);
            let mut nine = [0u8; 144];
            engine.keystream(&key, 0x0706_0504_0302_0100, 0, &mut nine);
            single == AES256_FIPS197 && sha3_256(&[&nine]) == AES_CTR_9_SHA3
        }
    };

    let mut stream = Stream::new();
    stream.set_engine(engine);
    stream.rekey(&key);
    let mut out = [0u8; 251];
    let sequence_ok = stream.generate(&mut out[..50]).is_ok()
        && stream.generate(&mut out[50..250]).is_ok()
        && stream.generate(&mut out[250..]).is_ok()
        && sha3_256(&[&out]) == if engine == Engine::ChaCha20 { STREAM_CHACHA_SHA3 } else { STREAM_AES_SHA3 };
    stream.wipe();

    cipher_ok && sequence_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_engine_this_machine_runs_passes_its_known_answers() {
        for engine in [Engine::Vaes512, Engine::Vaes256, Engine::AesNi, Engine::ArmAes, Engine::ChaCha20] {
            if engine.is_supported() {
                assert!(selftest(engine), "{} failed its known answers", engine.name());
            }
        }
    }

    #[test]
    fn report_engines() {
        // `cargo test report_engines -- --nocapture` shows which paths this
        // machine (or emulator) actually exercised.
        for engine in [Engine::Vaes512, Engine::Vaes256, Engine::AesNi, Engine::ArmAes, Engine::ChaCha20] {
            let supported = engine.is_supported();
            let passed = supported && selftest(engine);
            println!("{:<28} supported={supported} known-answers={passed}", engine.name());
        }
        println!("selected: {}", Engine::detect().name());
    }

    #[test]
    fn detection_prefers_hardware_and_falls_back_to_chacha() {
        let engine = Engine::detect();
        assert!(engine.is_supported());
        let f = crate::cpu::features();
        if !(f.aesni || f.arm_aes) {
            assert_eq!(engine, Engine::ChaCha20);
        }
    }

    #[test]
    fn nonces_advance_and_keys_rotate() {
        let mut s = Stream::new();
        s.rekey(&[9; 32]);
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        s.generate(&mut a).unwrap();
        s.generate(&mut b).unwrap();
        assert_ne!(a, b);
        assert_eq!(s.nonces_used(), 2);
        // A rekey to the same key does not rewind the nonce, so the output
        // is not the first request's again.
        s.rekey(&[9; 32]);
        let mut c = [0u8; 64];
        s.generate(&mut c).unwrap();
        assert_ne!(a, c);
        assert_eq!(s.nonces_used(), 3);
    }

    #[test]
    fn requests_are_bounded_and_need_a_key() {
        let mut s = Stream::new();
        assert_eq!(s.generate(&mut [0u8; 8]), Err(RngError::Misuse));
        s.rekey(&[1; 32]);
        let mut big = [0u8; CHUNK + 1];
        assert_eq!(s.generate(&mut big), Err(RngError::Misuse));
    }
}
