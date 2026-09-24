// SPDX-License-Identifier: Apache-2.0
//! The benchmark tab: the ISA kernels and RustCrypto, timed on the counter.
//!
//! Three groups, all on the machine the kernel owns — no scheduler, no other
//! process, interrupts masked — which is what makes the numbers worth having:
//!
//! - **ISA**: one kernel per SIMD family this core runs, the same
//!   instruction sequences the hosted build dispatches
//!   ([`nanochrono_core::kernels`]).
//! - **Instructions**: the crypto instructions alone (AES round, SHA-256
//!   step, carry-less multiply), where the core has them.
//! - **RustCrypto**: whole algorithms over a 16 KiB buffer — SHA-256,
//!   SHA-512, HMAC-SHA256, AES-256-GCM, ChaCha20-Poly1305 — no_std and
//!   allocation-free. Each crate carries a hardware path and a portable one
//!   and picks at run time through `cpufeatures` — patched for this kernel
//!   (vendor/cpufeatures) to detect on bare metal, which upstream does not.
//!   A CPU without AES-NI or SHA-NI gets the portable code, not a fault, and
//!   every row says which path ran.
//!
//! Each row runs three passes and keeps the best: the first pass warms the
//! caches and the branch predictors, and the best is the least disturbed.
//! Cycles per operation come from the PMU where it counts.

use nanochrono_core::backend::Backend;
use nanochrono_core::kernels::{self, CryptoKernel};

use crate::pmu::{CorePmu, CounterRoute};

/// One measured row.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub group: Group,
    pub name: &'static str,
    /// Which implementation ran: an instruction set, "simd", or "soft".
    pub path: &'static str,
    /// Nanoseconds per operation, times 1000.
    pub ns_per_op_milli: u64,
    /// Operations per second in millions (ISA) or MiB/s (crypto), times 1000.
    pub rate_milli: u64,
    /// Core cycles per operation, times 1000, when the PMU counted.
    pub cycles_per_op_milli: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Isa,
    Instruction,
    Crypto,
}

impl Group {
    pub const fn unit(self) -> &'static str {
        match self {
            Group::Isa | Group::Instruction => "Mop/s",
            Group::Crypto => "MiB/s",
        }
    }
}

pub const MAX_ROWS: usize = 40;

/// The results of the last run.
pub struct Results {
    pub rows: [Option<Row>; MAX_ROWS],
    pub len: usize,
}

impl Results {
    pub const fn new() -> Results {
        Results { rows: [None; MAX_ROWS], len: 0 }
    }

    fn push(&mut self, row: Row) {
        if self.len < MAX_ROWS {
            self.rows[self.len] = Some(row);
            self.len += 1;
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Row> {
        self.rows[..self.len].iter().flatten()
    }
}

/// The payload the crypto rows process, and its size.
#[cfg(feature = "crypto")]
const PAYLOAD: usize = 16 * 1024;
#[cfg(feature = "crypto")]
static mut BUFFER: [u8; PAYLOAD] = [0; PAYLOAD];

/// Runs `work` `passes` times; returns the best (ticks, cycles).
fn best_of(passes: u32, pmu: &CorePmu, mut work: impl FnMut() -> u64) -> (u64, Option<u64>) {
    let mut best_ticks = u64::MAX;
    let mut best_cycles = None;
    let mut sink = 0u64;
    for _ in 0..passes {
        // SAFETY: ring 0; `read_cycles` only reads the counter `enable` chose.
        let c0 = (pmu.route != CounterRoute::None).then(|| unsafe { pmu.read_cycles() }).flatten();
        let t0 = crate::arch::counter_ordered();
        sink ^= work();
        let t1 = crate::arch::counter_ordered();
        // SAFETY: as above.
        let c1 = (pmu.route != CounterRoute::None).then(|| unsafe { pmu.read_cycles() }).flatten();
        let ticks = t1.wrapping_sub(t0);
        if ticks < best_ticks {
            best_ticks = ticks;
            best_cycles = match (c0, c1) {
                (Some(a), Some(b)) => Some(b.value.wrapping_sub(a.value)),
                _ => None,
            };
        }
    }
    core::hint::black_box(sink);
    (best_ticks, best_cycles)
}

fn row(
    group: Group,
    name: &'static str,
    ops: u64,
    bytes_per_op: u64,
    (ticks, cycles): (u64, Option<u64>),
    hz: u64,
) -> Row {
    let ns = (ticks as u128 * 1_000_000_000 / hz.max(1) as u128).max(1);
    let ops = ops.max(1) as u128;
    let rate_milli = match group {
        // Millions of operations per second, x1000: ops / ns * 1e3 * 1e3.
        Group::Isa | Group::Instruction => (ops * 1_000_000 / ns) as u64,
        // MiB/s x1000: bytes / ns * 1e9 / 2^20 * 1e3.
        Group::Crypto => (ops * bytes_per_op as u128 * 1_000_000_000_000 / ns / (1 << 20)) as u64,
    };
    Row {
        group,
        name,
        path: "",
        ns_per_op_milli: (ns * 1000 / ops) as u64,
        rate_milli,
        cycles_per_op_milli: cycles.map(|c| (c as u128 * 1000 / ops) as u64),
    }
}

/// Runs every benchmark this machine can run. Blocks for a few seconds.
///
/// # Safety
/// Ring 0 / EL1 / supervisor: the kernels may use any ISA extension the
/// boot stub enabled, and the PMU is read directly.
pub unsafe fn run_all(hz: u64, pmu: &CorePmu, out: &mut Results) {
    *out = Results::new();

    // --- ISA kernels: every family native to this build that the CPU runs.
    const LOOPS: usize = 200_000;
    // A family without a kernel of its own resolves to another family's
    // (SVE, SVE2 and SME run the NEON kernel today). Timing it again would
    // put the same number under a second name, so it is skipped.
    let mut seen: [usize; 32] = [0; 32];
    let mut seen_len = 0;
    for &backend in Backend::ALL {
        if !backend.is_native() || !backend.is_available() {
            continue;
        }
        // Available: the kernel's instructions are legal here, which is the
        // invariant `resolve_kernel` relies on.
        let kernel = kernels::resolve_kernel(backend);
        let id = kernel as usize;
        if seen[..seen_len].contains(&id) {
            continue;
        }
        if seen_len < seen.len() {
            seen[seen_len] = id;
            seen_len += 1;
        }
        let m = best_of(3, pmu, || kernel(LOOPS));
        out.push(row(Group::Isa, backend.name(), LOOPS as u64, 0, m, hz));
    }

    // --- The crypto instructions alone.
    for &k in CryptoKernel::ALL {
        if !k.is_available() {
            continue;
        }
        if let Some(kernel) = kernels::resolve_crypto_kernel(k) {
            let m = best_of(3, pmu, || kernel(LOOPS));
            out.push(row(Group::Instruction, k.name(), LOOPS as u64, 0, m, hz));
        }
    }

    // --- RustCrypto over the payload.
    #[cfg(feature = "crypto")]
    // SAFETY: the buffer is this function's alone; the interface is single-
    // threaded and nothing else touches it.
    unsafe {
        crypto::run(hz, pmu, out, &mut *core::ptr::addr_of_mut!(BUFFER));
    }
}

#[cfg(feature = "crypto")]
mod crypto {
    use super::{best_of, row, Group, Results, PAYLOAD};
    use crate::pmu::CorePmu;

    use aes_gcm::aead::{AeadInPlace, KeyInit};

    /// Which implementation each crate will pick here, by the same features
    /// its `cpufeatures` check asks for. Reported, not assumed: a row that
    /// says "soft" ran the portable code.
    struct Paths {
        sha256: &'static str,
        sha512: &'static str,
        aes_gcm: &'static str,
        chacha: &'static str,
    }

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

    fn paths() -> Paths {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            Paths {
                sha256: if detect_sha_ni::get() { "sha-ni" } else { "soft" },
                sha512: if detect_avx2::get() { "avx2" } else { "soft" },
                aes_gcm: match (detect_aes_ni::get(), detect_clmul::get()) {
                    (true, true) => "aes-ni+clmul",
                    (true, false) => "aes-ni",
                    _ => "soft",
                },
                chacha: if detect_avx2::get() { "avx2" } else { "sse2" },
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            Paths {
                sha256: if detect_sha2::get() { "armv8 sha2" } else { "soft" },
                sha512: if detect_sha3::get() { "armv8.2 sha512" } else { "soft" },
                aes_gcm: if detect_aes::get() { "armv8 aes+pmull" } else { "soft" },
                chacha: "neon",
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
        {
            Paths { sha256: "soft", sha512: "soft", aes_gcm: "soft", chacha: "soft" }
        }
    }

    use hmac::Mac;
    use sha2::Digest;

    /// Buffers per pass: enough that one pass takes milliseconds.
    const ROUNDS: u64 = 16;

    pub(super) fn run(hz: u64, pmu: &CorePmu, out: &mut Results, buf: &mut [u8; PAYLOAD]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31);
        }
        let ops = ROUNDS;
        let p = paths();
        let with = |mut r: super::Row, path: &'static str| {
            r.path = path;
            r
        };

        let m = best_of(3, pmu, || {
            let mut x = 0u64;
            for _ in 0..ROUNDS {
                x ^= sha2::Sha256::digest(&buf[..])[0] as u64;
            }
            x
        });
        out.push(with(row(Group::Crypto, "sha-256", ops, PAYLOAD as u64, m, hz), p.sha256));

        let m = best_of(3, pmu, || {
            let mut x = 0u64;
            for _ in 0..ROUNDS {
                x ^= sha2::Sha512::digest(&buf[..])[0] as u64;
            }
            x
        });
        out.push(with(row(Group::Crypto, "sha-512", ops, PAYLOAD as u64, m, hz), p.sha512));

        let m = best_of(3, pmu, || {
            let mut x = 0u64;
            for _ in 0..ROUNDS {
                let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(&[7u8; 32])
                    .expect("any key length is valid for HMAC");
                mac.update(&buf[..]);
                x ^= mac.finalize().into_bytes()[0] as u64;
            }
            x
        });
        out.push(with(row(Group::Crypto, "hmac-sha256", ops, PAYLOAD as u64, m, hz), p.sha256));

        let aes = aes_gcm::Aes256Gcm::new(&[9u8; 32].into());
        let nonce = aes_gcm::Nonce::from([1u8; 12]);
        let m = best_of(3, pmu, || {
            let mut x = 0u64;
            for _ in 0..ROUNDS {
                if let Ok(tag) = aes.encrypt_in_place_detached(&nonce, b"", &mut buf[..]) {
                    x ^= tag[0] as u64;
                }
            }
            x
        });
        out.push(with(row(Group::Crypto, "aes-256-gcm", ops, PAYLOAD as u64, m, hz), p.aes_gcm));

        let chacha = chacha20poly1305::ChaCha20Poly1305::new(&[5u8; 32].into());
        let cnonce = chacha20poly1305::Nonce::from([2u8; 12]);
        let m = best_of(3, pmu, || {
            let mut x = 0u64;
            for _ in 0..ROUNDS {
                if let Ok(tag) = chacha.encrypt_in_place_detached(&cnonce, b"", &mut buf[..]) {
                    x ^= tag[0] as u64;
                }
            }
            x
        });
        out.push(with(row(Group::Crypto, "chacha20-poly1305", ops, PAYLOAD as u64, m, hz), p.chacha));
    }
}
