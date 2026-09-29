// SPDX-License-Identifier: Apache-2.0
//! The benchmark tab: the ISA kernels, RustCrypto and the bare crypto
//! instructions, timed on the counter — laid out and run the way the desktop
//! GUI's benchmark panel is (`nanochrono-bench`): pick a mode, pick a row,
//! run it, read its log.
//!
//! Three modes, all on the machine the kernel owns — no scheduler, no other
//! process, interrupts masked — which is what makes the numbers worth having:
//!
//! - **Mode 1, CPU ISA kernels**: one kernel per SIMD family, the same
//!   instruction sequences the hosted build dispatches
//!   ([`nanochrono_core::kernels`]).
//! - **Mode 2, Crypto (RustCrypto)**: whole algorithms over a 16 KiB buffer —
//!   SHA-256, SHA-512, HMAC-SHA256, AES-256-GCM, ChaCha20-Poly1305 — no_std
//!   and allocation-free. Each crate carries a hardware path and a portable
//!   one and picks at run time through `cpufeatures` — patched for this
//!   kernel (vendor/cpufeatures) to detect on bare metal, which upstream does
//!   not. A CPU without AES-NI or SHA-NI gets the portable code, not a fault,
//!   and the log says which path ran.
//! - **Mode 3, Crypto RAW speed**: the crypto instructions alone (AES round,
//!   SHA-256 step, carry-less multiply, VAES, VPCLMULQDQ). Speed only — no
//!   key schedule, no mode, no authentication; Mode 2 is real crypto.
//!
//! The Linux-only desktop modes (TLS, `AF_ALG`, the kernel module) have no
//! counterpart here: there is no network stack and no Linux.
//!
//! Each run is three passes of increasing length, reported best, worst and
//! mean: if the first pass is much slower than the third, the workload is
//! dominated by warm-up, and that is a finding rather than noise. Cycles per
//! operation come from the PMU where it counts.

use nanochrono_core::backend::Backend;
use nanochrono_core::kernels::{self, CryptoKernel};

use crate::pmu::{CorePmu, CounterRoute};
use crate::text::Text;

/// A benchmark mode, as the desktop panel lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Isa,
    Crypto,
    CryptoRaw,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Isa, Mode::Crypto, Mode::CryptoRaw];

    pub const fn label(self) -> &'static str {
        match self {
            Mode::Isa => "Mode 1: CPU ISA kernels",
            Mode::Crypto => "Mode 2: Crypto (RustCrypto)",
            Mode::CryptoRaw => "Mode 3: Crypto RAW speed",
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Mode::Isa => "CPU ISA kernels",
            Mode::Crypto => "Crypto (RustCrypto, 16 KiB buffers)",
            Mode::CryptoRaw => "Crypto RAW speed (instructions only)",
        }
    }

    /// Whether any row of the mode can run here.
    pub fn is_available(self) -> bool {
        self.items().iter().any(|i| i.is_available())
    }

    /// The rows the mode offers, in display order — unavailable ones
    /// included, so the panel shows the whole landscape.
    pub fn items(self) -> Items {
        let mut out = Items { items: [Item::Crypto(Algorithm::Sha256); MAX_ITEMS], len: 0 };
        match self {
            // This architecture's families first, then the rest (listed as
            // NOT AVAILABLE, as on the desktop): on an ARM or RISC-V screen
            // the rows that can run should not sit below a page of x86.
            Mode::Isa => {
                Backend::ALL.iter().filter(|b| b.is_native()).for_each(|&b| out.push(Item::Isa(b)));
                Backend::ALL.iter().filter(|b| !b.is_native()).for_each(|&b| out.push(Item::Isa(b)));
            }
            Mode::Crypto => Algorithm::ALL.iter().for_each(|&a| out.push(Item::Crypto(a))),
            Mode::CryptoRaw => CryptoKernel::ALL.iter().for_each(|&k| out.push(Item::Raw(k))),
        }
        out
    }
}

const MAX_ITEMS: usize = 32;

/// A fixed-capacity list of rows; the kernel has no allocator.
#[derive(Clone, Copy)]
pub struct Items {
    items: [Item; MAX_ITEMS],
    len: usize,
}

impl Items {
    fn push(&mut self, item: Item) {
        if self.len < MAX_ITEMS {
            self.items[self.len] = item;
            self.len += 1;
        }
    }

    pub fn iter(&self) -> core::slice::Iter<'_, Item> {
        self.items[..self.len].iter()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn get(&self, i: usize) -> Option<Item> {
        self.items[..self.len].get(i).copied()
    }
}

/// A RustCrypto algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha512,
    HmacSha256,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Algorithm {
    pub const ALL: [Algorithm; 5] = [
        Algorithm::Sha256,
        Algorithm::Sha512,
        Algorithm::HmacSha256,
        Algorithm::Aes256Gcm,
        Algorithm::ChaCha20Poly1305,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "SHA-256",
            Algorithm::Sha512 => "SHA-512",
            Algorithm::HmacSha256 => "HMAC-SHA256",
            Algorithm::Aes256Gcm => "AES-256-GCM",
            Algorithm::ChaCha20Poly1305 => "CHACHA20-POLY1305",
        }
    }
}

/// One selectable row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item {
    Isa(Backend),
    Crypto(Algorithm),
    Raw(CryptoKernel),
}

impl Item {
    /// The row's name, upper-cased as the desktop panel shows it.
    pub fn name(self) -> Text<40> {
        let mut t = Text::new();
        let (base, raw) = match self {
            Item::Isa(b) => (b.name(), false),
            Item::Crypto(a) => (a.name(), false),
            Item::Raw(k) => (k.name(), true),
        };
        for b in base.bytes() {
            t.push(b.to_ascii_uppercase());
        }
        if raw {
            t.str(" (raw)");
        }
        t
    }

    pub fn is_available(self) -> bool {
        match self {
            // Native and present: the kernel's instructions are legal here,
            // which is the invariant `resolve_kernel` relies on.
            Item::Isa(b) => b.is_native() && b.is_available(),
            Item::Crypto(_) => cfg!(feature = "crypto"),
            Item::Raw(k) => k.is_available() && kernels::resolve_crypto_kernel(k).is_some(),
        }
    }

    pub const fn mode(self) -> Mode {
        match self {
            Item::Isa(_) => Mode::Isa,
            Item::Crypto(_) => Mode::Crypto,
            Item::Raw(_) => Mode::CryptoRaw,
        }
    }
}

/// A finished run: its log, as the desktop panel prints it.
pub struct Report {
    pub item: Item,
    pub log: Text<2048>,
    /// Best rate, x1000, in the mode's unit; zero when nothing ran.
    pub best_rate_milli: u64,
}

/// Loop counts for the three passes of a kernel row.
const KERNEL_LOOPS: [u64; 3] = [100_000, 200_000, 300_000];
/// 16 KiB buffers processed by each pass of a crypto row.
const CRYPTO_ROUNDS: [u64; 3] = [8, 16, 24];

/// The payload the crypto rows process, and its size.
#[cfg(feature = "crypto")]
const PAYLOAD: usize = 16 * 1024;
#[cfg(feature = "crypto")]
static mut BUFFER: [u8; PAYLOAD] = [0; PAYLOAD];

/// Times one call of `work`; returns (ticks, cycles).
fn timed(pmu: &CorePmu, work: impl FnOnce() -> u64) -> (u64, Option<u64>) {
    // SAFETY: ring 0; `read_cycles` only reads the counter `enable` chose.
    let c0 = (pmu.route != CounterRoute::None).then(|| unsafe { pmu.read_cycles() }).flatten();
    let t0 = crate::arch::counter_ordered();
    let sink = work();
    let t1 = crate::arch::counter_ordered();
    // SAFETY: as above.
    let c1 = (pmu.route != CounterRoute::None).then(|| unsafe { pmu.read_cycles() }).flatten();
    core::hint::black_box(sink);
    let cycles = match (c0, c1) {
        (Some(a), Some(b)) => Some(b.value.wrapping_sub(a.value)),
        _ => None,
    };
    (t1.wrapping_sub(t0), cycles)
}

/// Runs `item`: three passes, each logged, then the summary. Blocks for a
/// fraction of a second.
///
/// # Safety
/// Ring 0 / EL1 / supervisor: the kernels may use any ISA extension the
/// boot stub enabled, and the PMU is read directly.
pub unsafe fn run_one(item: Item, hz: u64, pmu: &CorePmu) -> Report {
    let mut log = Text::<2048>::new();
    log.str("operation: ").str(item.name().as_str()).str("\n");
    log.str("mode: ").str(item.mode().name()).str("\n");
    if !item.is_available() {
        log.str("\nNOT AVAILABLE on this CPU");
        if matches!(item, Item::Crypto(_)) {
            log.str(" (built without the crypto feature)");
        }
        return Report { item, log, best_rate_milli: 0 };
    }

    let crypto = matches!(item, Item::Crypto(_));
    let (unit, bytes_per_op) = if crypto { ("MiB/s", 16 * 1024u128) } else { ("Mop/s", 0) };
    match item {
        Item::Isa(_) => {
            log.str("warmup: inline-asm ISA microbenchmark; gated by the CPU's feature report\n");
            log.str("unit: 1 op = 1 kernel iteration\n\n");
        }
        Item::Raw(k) => {
            log.str("warmup: raw ").str(k.name());
            log.str(" instruction chain, SPEED ONLY: no key schedule, no mode, no authentication, not a cipher - see Mode 2 for real crypto\n");
            log.str("unit: 1 op = 1 kernel iteration (one chain step per lane)\n\n");
        }
        Item::Crypto(_a) => {
            log.str("warmup: real algorithm over a 16 KiB buffer, through RustCrypto\n");
            #[cfg(feature = "crypto")]
            log.str("path: ").str(crypto::path(_a)).str("\n");
            log.str("unit: 1 op = 1 call over the 16 KiB payload\n\n");
        }
    }

    let (mut best, mut worst, mut sum) = (0u64, u64::MAX, 0u64);
    for pass in 0..3 {
        let ops = if crypto { CRYPTO_ROUNDS[pass] } else { KERNEL_LOOPS[pass] };
        let (ticks, cycles) = match item {
            Item::Isa(b) => {
                let kernel = kernels::resolve_kernel(b);
                timed(pmu, || kernel(ops as usize))
            }
            Item::Raw(k) => match kernels::resolve_crypto_kernel(k) {
                Some(kernel) => timed(pmu, || kernel(ops as usize)),
                None => (0, None),
            },
            #[cfg(feature = "crypto")]
            // SAFETY: the buffer is this module's alone; the interface is
            // single-threaded and nothing else touches it.
            Item::Crypto(a) => unsafe {
                let buf = &mut *core::ptr::addr_of_mut!(BUFFER);
                crypto::prepare(buf);
                timed(pmu, || crypto::run(a, ops, buf))
            },
            #[cfg(not(feature = "crypto"))]
            Item::Crypto(_) => (0, None),
        };
        let ns = (ticks as u128 * 1_000_000_000 / hz.max(1) as u128).max(1);
        let rate_milli = if crypto {
            // MiB/s x1000: bytes / ns * 1e9 / 2^20 * 1e3.
            (ops as u128 * bytes_per_op * 1_000_000_000_000 / ns / (1 << 20)) as u64
        } else {
            // Mop/s x1000: ops / ns * 1e3 * 1e3.
            (ops as u128 * 1_000_000 / ns) as u64
        };
        best = best.max(rate_milli);
        worst = worst.min(rate_milli);
        sum += rate_milli;

        log.str("pass ").num(pass as u64 + 1).str(": ");
        log.str(if crypto { "buffers=" } else { "loops=" }).num(ops);
        log.str("  time=").fixed((ns / 1000) as u64, 6).str(" s");
        log.str("  rate=").fixed(rate_milli, 3).str(" ").str(unit);
        if let Some(c) = cycles {
            log.str("  cyc/op=").fixed((c as u128 * 10_000 / ops as u128) as u64, 4);
        }
        log.str("  ns/op=").fixed((ns * 10_000 / ops as u128) as u64, 4).str("\n");
    }
    log.str("  rate: mean ").fixed(sum / 3, 3);
    log.str(" ").str(unit).str("   best ").fixed(best, 3).str("   worst ").fixed(worst, 3).str("\n");
    if worst > 0 && best * 100 / worst > 115 {
        // The desktop harness says the same: a spread this wide means the
        // workload is still warming up, and the last pass is the one to trust.
        log.str("  note: passes differ by more than 15%; the workload is warming up\n");
    }
    log.str("\nstatus: completed successfully.");
    Report { item, log, best_rate_milli: best }
}

#[cfg(feature = "crypto")]
mod crypto {
    use super::{Algorithm, PAYLOAD};

    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use hmac::Mac;
    use sha2::Digest;

    // The same detections the crates make, token for token (sha2 0.10,
    // aes 0.8, polyval 0.6, chacha20 0.9), through the same patched crate.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    cpufeatures::new!(detect_sha_ni, "sha", "sse2", "ssse3", "sse4.1");
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    cpufeatures::new!(detect_avx2, "avx2");
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    cpufeatures::new!(detect_aes_ni, "aes", "sse2");
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    cpufeatures::new!(detect_clmul, "pclmulqdq");
    #[cfg(target_arch = "aarch64")]
    cpufeatures::new!(detect_sha2, "sha2");
    #[cfg(target_arch = "aarch64")]
    cpufeatures::new!(detect_sha3, "sha3");
    #[cfg(target_arch = "aarch64")]
    cpufeatures::new!(detect_aes, "aes");

    /// Which implementation the crate will pick here, by the same features
    /// its `cpufeatures` check asks for. Reported, not assumed: "soft" means
    /// the portable code ran.
    pub(super) fn path(a: Algorithm) -> &'static str {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            match a {
                Algorithm::Sha256 | Algorithm::HmacSha256 => {
                    if detect_sha_ni::get() { "sha-ni" } else { "soft" }
                }
                Algorithm::Sha512 => if detect_avx2::get() { "avx2" } else { "soft" },
                Algorithm::Aes256Gcm => match (detect_aes_ni::get(), detect_clmul::get()) {
                    (true, true) => "aes-ni+clmul",
                    (true, false) => "aes-ni",
                    _ => "soft",
                },
                Algorithm::ChaCha20Poly1305 => if detect_avx2::get() { "avx2" } else { "sse2" },
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            match a {
                Algorithm::Sha256 | Algorithm::HmacSha256 => {
                    if detect_sha2::get() { "armv8 sha2" } else { "soft" }
                }
                Algorithm::Sha512 => if detect_sha3::get() { "armv8.2 sha512" } else { "soft" },
                Algorithm::Aes256Gcm => if detect_aes::get() { "armv8 aes+pmull" } else { "soft" },
                Algorithm::ChaCha20Poly1305 => "neon",
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
        {
            let _ = a;
            "soft"
        }
    }

    /// Processes `rounds` buffers with `a`; returns a value derived from the
    /// output, which the caller keeps live.
    /// Fills the payload; outside the timed region.
    pub(super) fn prepare(buf: &mut [u8; PAYLOAD]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31);
        }
    }

    pub(super) fn run(a: Algorithm, rounds: u64, buf: &mut [u8; PAYLOAD]) -> u64 {
        let mut x = 0u64;
        match a {
            Algorithm::Sha256 => {
                for _ in 0..rounds {
                    x ^= sha2::Sha256::digest(&buf[..])[0] as u64;
                }
            }
            Algorithm::Sha512 => {
                for _ in 0..rounds {
                    x ^= sha2::Sha512::digest(&buf[..])[0] as u64;
                }
            }
            Algorithm::HmacSha256 => {
                for _ in 0..rounds {
                    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(&[7u8; 32])
                        .expect("any key length is valid for HMAC");
                    mac.update(&buf[..]);
                    x ^= mac.finalize().into_bytes()[0] as u64;
                }
            }
            Algorithm::Aes256Gcm => {
                let aes = aes_gcm::Aes256Gcm::new(&[9u8; 32].into());
                for i in 0..rounds {
                    // A fresh nonce per buffer: reuse under one key would be
                    // a real vulnerability even in a benchmark.
                    let mut n = [0u8; 12];
                    n[..8].copy_from_slice(&i.to_le_bytes());
                    if let Ok(tag) = aes.encrypt_in_place_detached(&aes_gcm::Nonce::from(n), b"", &mut buf[..]) {
                        x ^= tag[0] as u64;
                    }
                }
            }
            Algorithm::ChaCha20Poly1305 => {
                let chacha = chacha20poly1305::ChaCha20Poly1305::new(&[5u8; 32].into());
                for i in 0..rounds {
                    let mut n = [0u8; 12];
                    n[..8].copy_from_slice(&i.to_le_bytes());
                    if let Ok(tag) =
                        chacha.encrypt_in_place_detached(&chacha20poly1305::Nonce::from(n), b"", &mut buf[..])
                    {
                        x ^= tag[0] as u64;
                    }
                }
            }
        }
        x
    }
}
