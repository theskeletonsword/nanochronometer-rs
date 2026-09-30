// SPDX-License-Identifier: Apache-2.0
//! NC_RNG: an entropy pool fed by every independent source the machine has.
//!
//! # Why a pool, and why several sources
//!
//! No single generator is trusted. `RDRAND` is a DRBG whose design cannot be
//! audited from software; `RDSEED` taps the noise source behind it, and is
//! just as opaque; a timer's jitter depends on caches, buses and firmware
//! that nothing here controls. Each is absorbed into one Keccak sponge, so a
//! source that is broken — or hostile, trying to cancel the others — cannot
//! undo what the others contributed without knowing them, and it never sees
//! them. That sponge seeds an XDRBG-256, and the XDRBG keys the output
//! stage ([`stream`]).
//!
//! The pool follows the jitter-entropy manual this project uses as its
//! specification (CPU execution timing jitter RNG): the measurement, the
//! granularity calibration, the SP 800-90B health tests, the 1600-bit sponge
//! with a 136-byte rate, XDRBG-256, and start-up with 100 + 1024
//! measurements.
//!
//! # Sources, and which of them count
//!
//! | Source | Credited | Notes |
//! |---|---|---|
//! | CPU timing jitter ([`jitter`]) | `1/OSR` bit per healthy sample | the primary source; health-tested |
//! | `RDSEED` ([`hwrng`]) | ½ bit per bit, **only** if jitter cannot run | otherwise additional input |
//! | `RDRAND` | never | a DRBG's output, not a noise source |
//! | Embedder's source ([`External`]) | as the embedder declares, only if jitter cannot run | the OS's CSPRNG on a hosted build |
//! | Event timings ([`EntropyPool::stir`]) | never | key presses, USB and storage completions, frames |
//! | A side counter (the PMU) | never | read around each jitter measurement |
//!
//! Crediting decides only when the pool may produce output; *everything* is
//! mixed in either way. A seed needs `256 + F` credited bits (`F = 65`, the
//! manual's compliance margin, by default). With a working timer that is
//! the jitter source alone — `(256 + 65)·3 = 963` healthy samples at the
//! default OSR — and the hardware generators ride along uncredited. If the
//! timer fails its start-up tests, the pool can still be seeded from
//! `RDSEED` (or the embedder's source) and says so: [`Status::flags`] carries
//! [`FLAG_DEGRADED`]. [`Config::require_jitter`] refuses that fallback.
//!
//! # The output stage: hybrid, picked at run time
//!
//! ```text
//! sources ──► Keccak sponge ──► XDRBG-256 ──► 32-byte key ──► stream cipher ──► output
//!              (conditioning)    (manual §7.5)                 VAES-512 │ VAES-256 │ AES-NI │ ARMv8 AES
//!                                                              └──────► ChaCha20 (software)
//! ```
//!
//! [`stream::Engine::detect`] reads CPUID (and XCR0, since the ZMM state must
//! be enabled too) or the ARM ID registers, and picks AES-256-CTR on VAES
//! with ZMM (AVX-512), VAES with YMM (parts with VAES but no AVX-512), AES-NI
//! with XMM, or the ARMv8 AES instructions; without
//! AES hardware — or by choice, [`stream::EngineChoice::Software`] — it is
//! ChaCha20 in portable 32-bit software. The engine runs its known-answer
//! test first; a hardware path that fails it is replaced by ChaCha20
//! ([`FLAG_ENGINE_FALLBACK`]).
//!
//! **No nonce is ever reused.** The stage is fast-key-erasure: each request
//! takes the next value of a 64-bit counter that nothing resets, and the
//! first keystream block(s) of every request become the next key, so a key
//! serves exactly one request and is erased before the caller sees its
//! output. See [`stream`].
//!
//! # Two ways to read
//!
//! * [`Mode::Fast`]: the output stage, rekeyed from the XDRBG — itself
//!   reseeded with fresh credited entropy every [`Config::reseed_interval`]
//!   bytes. For everything that needs unpredictable bytes quickly.
//! * [`Mode::True`]: a fresh credited seed before every 32-byte block,
//!   straight from the XDRBG, so each block carries its own 256 bits. For
//!   long-term keys. Slow — each block is ~1000 timed measurements.
//!
//! # Failure
//!
//! A health test that trips at the intermittent cutoff discards the block
//! being collected, raises the OSR by one and re-runs start-up (the manual's
//! resilient read); past OSR 20 it becomes permanent. A permanent failure,
//! or a failed known-answer test, takes the pool out of service: every read
//! returns the error and never a partial buffer. Error codes are the
//! manual's (section 2.14), negative, so the C ABI can return them as-is.
//!
//! # No allocator
//!
//! The pool borrows its memory region from the caller — a `static` in the
//! freestanding kernel, a heap buffer in the hosted library — and allocates
//! nothing itself.

pub mod aes;
pub mod chacha20;
pub mod health;
pub mod hwrng;
pub mod jitter;
pub mod keccak;
mod pool;
pub mod stream;
pub mod xdrbg;

pub use pool::{Config, EntropyPool, External};
pub use stream::{Engine, EngineChoice};

/// Why a read failed. The discriminants are the manual's error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RngError {
    /// Bad arguments: a null buffer, a region that is not a power of two, an
    /// OSR above 20.
    Misuse = -1,
    /// Repetition count test, intermittent.
    Rct = -2,
    /// Adaptive proportion test, intermittent.
    Apt = -3,
    /// The timer is unusable: zero, stuck, non-monotonic, or too coarse.
    Timer = -4,
    /// Lag predictor, intermittent.
    Lag = -5,
    /// Repetition count test, permanent.
    RctPermanent = -6,
    /// Adaptive proportion test, permanent.
    AptPermanent = -7,
    /// Lag predictor, permanent.
    LagPermanent = -8,
    /// Reserved for the manual's memory test (not implemented: in the
    /// common mode its cutoff equals the window and can never trip).
    Memory = -9,
    MemoryPermanent = -10,
    /// A known-answer test failed; the pool is out of service.
    SelfTest = -11,
    /// Not in the manual: no source could supply credited entropy at all.
    NoSource = -12,
}

impl RngError {
    /// The negative code the C ABI returns.
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// The error for a set of latched health bits, worst first.
    pub const fn from_health(bits: u32) -> Option<RngError> {
        use health::*;
        if bits & FAIL_RCT_PERMANENT != 0 {
            Some(RngError::RctPermanent)
        } else if bits & FAIL_APT_PERMANENT != 0 {
            Some(RngError::AptPermanent)
        } else if bits & FAIL_LAG_PERMANENT != 0 {
            Some(RngError::LagPermanent)
        } else if bits & FAIL_RCT != 0 {
            Some(RngError::Rct)
        } else if bits & FAIL_APT != 0 {
            Some(RngError::Apt)
        } else if bits & FAIL_LAG != 0 {
            Some(RngError::Lag)
        } else {
            None
        }
    }

    /// An intermittent failure: retried at a higher OSR, not fatal.
    pub const fn is_intermittent(self) -> bool {
        matches!(self, RngError::Rct | RngError::Apt | RngError::Lag | RngError::Memory)
    }

    /// The permanent counterpart of an intermittent failure.
    pub const fn escalate(self) -> RngError {
        match self {
            RngError::Rct => RngError::RctPermanent,
            RngError::Apt => RngError::AptPermanent,
            RngError::Lag => RngError::LagPermanent,
            RngError::Memory => RngError::MemoryPermanent,
            other => other,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            RngError::Misuse => "misuse",
            RngError::Rct => "repetition count (intermittent)",
            RngError::Apt => "adaptive proportion (intermittent)",
            RngError::Timer => "timer unusable",
            RngError::Lag => "lag predictor (intermittent)",
            RngError::RctPermanent => "repetition count (permanent)",
            RngError::AptPermanent => "adaptive proportion (permanent)",
            RngError::LagPermanent => "lag predictor (permanent)",
            RngError::Memory => "memory test (intermittent)",
            RngError::MemoryPermanent => "memory test (permanent)",
            RngError::SelfTest => "known-answer self-test",
            RngError::NoSource => "no credited source",
        }
    }
}

/// How a read is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// XDRBG output, reseeded on a schedule. C value `NC_RNG_FAST` (0).
    #[default]
    Fast,
    /// A freshly credited seed before every 32-byte block. `NC_RNG_TRUE` (1).
    True,
}

impl Mode {
    /// From the C ABI's flags word: bit 0 selects [`Mode::True`].
    pub const fn from_flags(flags: u32) -> Mode {
        if flags & 1 != 0 {
            Mode::True
        } else {
            Mode::Fast
        }
    }
}

// Source bits, for `Status::sources` and `Status::available`.
/// CPU timing jitter.
pub const SOURCE_JITTER: u32 = 1 << 0;
/// x86 `RDSEED`.
pub const SOURCE_RDSEED: u32 = 1 << 1;
/// x86 `RDRAND`.
pub const SOURCE_RDRAND: u32 = 1 << 2;
/// A side counter (the PMU) read around each measurement.
pub const SOURCE_PMU: u32 = 1 << 3;
/// Stirred event timings.
pub const SOURCE_EVENTS: u32 = 1 << 4;
/// The embedder's source (the OS's CSPRNG when hosted).
pub const SOURCE_EXTERNAL: u32 = 1 << 5;

// Flag bits, for `Status::flags`.
/// Seeded and able to produce output.
pub const FLAG_READY: u32 = 1 << 0;
/// Seeded without the jitter source: hardware or embedder entropy only.
pub const FLAG_DEGRADED: u32 = 1 << 1;
/// Out of service after a permanent failure.
pub const FLAG_FAILED: u32 = 1 << 2;
/// The known-answer tests have passed.
pub const FLAG_SELFTEST_PASSED: u32 = 1 << 3;
/// The CPU's AES path failed its known-answer test; ChaCha20 is serving.
pub const FLAG_ENGINE_FALLBACK: u32 = 1 << 4;

// Event tags for `stir`. Only mixed, never interpreted; any value works.
pub const EVENT_KEY: u64 = 1;
pub const EVENT_POINTER: u64 = 2;
pub const EVENT_USB: u64 = 3;
pub const EVENT_STORAGE: u64 = 4;
pub const EVENT_FRAME: u64 = 5;
pub const EVENT_INTERRUPT: u64 = 6;
/// First tag for callers outside the kernel (plugins, applications).
pub const EVENT_USER: u64 = 0x100;

/// A snapshot of the pool, laid out for the C ABI (`nc_rng_status_t`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Status {
    /// `size_of::<Status>()`, so a caller built against a shorter struct
    /// can tell what it was given.
    pub size: u32,
    /// `FLAG_*` bits.
    pub flags: u32,
    /// `SOURCE_*` bits: what fed the most recent seed.
    pub sources: u32,
    /// `SOURCE_*` bits: what this machine offers.
    pub available: u32,
    /// Latched health bits ([`health`]'s `FAIL_*`).
    pub health: u32,
    /// The last error, as its code; 0 if none.
    pub last_error: i32,
    /// Current oversampling rate.
    pub osr: u32,
    /// Stuck samples during the last start-up, per mille.
    pub startup_stuck_permille: u32,
    /// The output stage's engine, as its [`Engine`] value; 0 before start.
    pub engine: u32,
    pub reserved: u32,
    /// The counter's granularity learned at start-up.
    pub granularity: u64,
    pub reseeds: u64,
    pub bytes_out: u64,
    /// Jitter samples taken, and stuck ones among them.
    pub jitter_samples: u64,
    pub jitter_stuck: u64,
    /// Events stirred in.
    pub events: u64,
    /// Healthy words from `RDSEED` and `RDRAND` together.
    pub hw_words: u64,
    /// Nonces the output stage has consumed: one per request, never reused.
    pub nonces: u64,
}
