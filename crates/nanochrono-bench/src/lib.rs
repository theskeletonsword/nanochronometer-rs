// SPDX-License-Identifier: Apache-2.0
//! Benchmark modes, kernels and the three-pass harness.
//!
//! # The three modes
//!
//! The C build had *CPU intrinsics*, *OpenSSL EVP* and *libsodium*. The last
//! two existed because the project linked two independent crypto libraries and
//! wanted to compare them. With a single provider that comparison is gone, and
//! keeping two identical modes would be dishonest. So the third slot now
//! measures something the old build could not: a full TLS handshake.
//!
//! | Mode | Measures | Answers |
//! |---|---|---|
//! | [`BenchMode::CpuIsa`] | Inline-asm ISA kernels | What can this core's datapath do? |
//! | [`BenchMode::Crypto`] | rustls/`ring` primitives over real buffers | What does a byte of AEAD or hash cost? |
//! | [`BenchMode::TlsHandshake`] | End-to-end rustls handshakes | What does establishing a session cost? |
//! | [`BenchMode::CryptoRaw`] | Bare crypto instructions (AES round, SHA-256 round, carry-less multiply, VAES, VPCLMULQDQ) | How fast is the silicon, with no cipher around it? |
//!
//! # Why three passes
//!
//! Each run does three passes with increasing iteration counts. The first is
//! partly warm-up: caches are cold, the frequency governor has not responded
//! and the branch predictor is untrained. Reporting best/worst/average across
//! all three makes that visible instead of hiding it behind a single number —
//! if pass 1 is much slower than pass 3, the workload is dominated by warm-up,
//! and that is a finding rather than noise to be averaged away.

use std::fmt::Write as _;

use nanochrono_core::{
    arch, dispatch::Dispatcher, format, Backend, Chronometer, CpuFeatures, CryptoKernel,
    SimdFamily,
};
use nanochrono_crypto::{tls, AeadKey, Algorithm, NONCE_LEN};

/// Which family of work a benchmark run exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BenchMode {
    /// Inline-asm microbenchmarks per ISA family.
    #[default]
    CpuIsa,
    /// Cryptographic primitives through the rustls provider.
    Crypto,
    /// Full TLS handshakes against a remote host.
    TlsHandshake,
    /// The Linux kernel's own crypto, reached from ring 3 through `AF_ALG`.
    ///
    /// A different question from [`BenchMode::Crypto`]. That one times code
    /// compiled into this process; this one times the implementation the
    /// kernel selected for this machine, which is often a driver userspace
    /// does not have — `sha256-avx2`, `ctr-aes-vaes-avx2`, `sha256-ce`. The
    /// syscall is included in the number on purpose: it is what using the
    /// kernel's crypto from userspace actually costs.
    KernelCrypto,
    /// The same kernel crypto, measured *inside* the kernel by the optional
    /// module in `kernel/linux/` — the one that already answers the
    /// hypervisor question.
    ///
    /// The difference between this and [`BenchMode::KernelCrypto`] is the
    /// cost of `AF_ALG`: the socket, the two context switches and the copy in
    /// and out. Neither mode can state that on its own; subtracting them can,
    /// which is the reason both exist.
    ///
    /// The only mode with a prerequisite outside this process. It reports
    /// itself unavailable when the module is not loaded rather than failing,
    /// because not having built a kernel module is the ordinary case.
    KernelCryptoRing0,
    /// The crypto *instructions* alone, in the project's own inline-asm
    /// kernels: `AESENC`, `SHA256RNDS2`, `PCLMULQDQ`, their YMM forms, and
    /// the ARMv8 equivalents.
    ///
    /// Speed only. There is no key schedule, no mode of operation, no
    /// authentication and no constant-time contract to keep — the chains
    /// are built to keep the unit busy, not to encrypt anything. Mode 2 is
    /// the number for real, secure crypto; this one is how fast the silicon
    /// is underneath it, and the gap between the two is the price of doing
    /// it properly.
    CryptoRaw,
}

impl BenchMode {
    pub const fn name(self) -> &'static str {
        match self {
            BenchMode::CpuIsa => "CPU ISA kernels",
            BenchMode::Crypto => "Crypto (rustls/ring)",
            BenchMode::TlsHandshake => "TLS handshake (rustls)",
            BenchMode::KernelCrypto => "Linux crypto API (AF_ALG, ring 3)",
            BenchMode::KernelCryptoRing0 => "Linux crypto API (kernel module, ring 0)",
            BenchMode::CryptoRaw => "Crypto RAW speed (instructions only)",
        }
    }

    /// Short label for the mode row in the benchmark panel.
    pub const fn label(self) -> &'static str {
        match self {
            BenchMode::CpuIsa => "Mode 1: CPU ISA kernels",
            BenchMode::Crypto => "Mode 2: Crypto (rustls/ring)",
            BenchMode::TlsHandshake => "Mode 3: TLS handshake (rustls)",
            BenchMode::KernelCrypto => "Mode 4: Linux crypto API (ring 3)",
            BenchMode::KernelCryptoRing0 => "Mode 5: Linux crypto API (ring 0)",
            // Last in the list, so its number is the list's length: 6 on
            // Linux, 4 where the two Linux-only modes are not offered.
            #[cfg(target_os = "linux")]
            BenchMode::CryptoRaw => "Mode 6: Crypto RAW speed",
            #[cfg(not(target_os = "linux"))]
            BenchMode::CryptoRaw => "Mode 4: Crypto RAW speed",
        }
    }

    /// Whether the mode can run here.
    ///
    /// The first two always can — the provider is compiled in, unlike the C
    /// build where a mode could be "NOT LINKED". TLS needs a network, which
    /// cannot be established without trying, so it is reported as available
    /// and allowed to fail with a message.
    pub fn is_available(self) -> bool {
        match self {
            // The provider is compiled in, unlike the C build where a mode
            // could be "NOT LINKED". TLS needs a network, which cannot be
            // established without trying, so it is reported as available and
            // allowed to fail with a message.
            BenchMode::CpuIsa | BenchMode::Crypto | BenchMode::TlsHandshake => true,
            // This one genuinely can be absent: `AF_ALG` is a kernel config
            // option, it does not exist off Linux, and a container's seccomp
            // filter can refuse the socket even where the kernel has it.
            // Saying so is better than offering a mode that returns errors.
            BenchMode::KernelCrypto => nanochrono_core::kcrypto::available(),
            // The only mode whose prerequisite lives outside this process:
            // the module has to be built and inserted. Absent is the ordinary
            // case, so it is reported rather than treated as a fault.
            BenchMode::KernelCryptoRing0 => nanochrono_core::kcrypto::Ring0::read().is_some(),
            // Offered whenever at least one instruction kernel can run; a
            // CPU with none of them has nothing for the mode to show.
            BenchMode::CryptoRaw => CryptoKernel::ALL.iter().any(|k| k.is_available()),
        }
    }

    /// The modes this build offers, in display order.
    ///
    /// Two of them are Linux's and only Linux's. `AF_ALG` is a Linux socket
    /// family, and the ring-0 mode is a Linux kernel module — neither has an
    /// equivalent on Windows or macOS, and neither could be made to have one.
    /// So off Linux they are not listed at all rather than listed and greyed
    /// out: a mode that can never run on this operating system is not an
    /// unavailable feature, it is a feature that does not apply.
    #[cfg(target_os = "linux")]
    pub const ALL: &'static [BenchMode] = &[
        BenchMode::CpuIsa,
        BenchMode::Crypto,
        BenchMode::TlsHandshake,
        BenchMode::KernelCrypto,
        BenchMode::KernelCryptoRing0,
        BenchMode::CryptoRaw,
    ];

    /// The three portable modes. See the Linux list above for what is missing
    /// and why it is missing rather than disabled.
    #[cfg(not(target_os = "linux"))]
    pub const ALL: &'static [BenchMode] = &[
        BenchMode::CpuIsa,
        BenchMode::Crypto,
        BenchMode::TlsHandshake,
        BenchMode::CryptoRaw,
    ];

    /// Whether this mode exists on this operating system at all.
    ///
    /// Distinct from [`BenchMode::is_available`], which asks whether a mode
    /// that *could* run here can run right now — no network, no module
    /// loaded. This asks whether it is a mode on this platform in the first
    /// place, and the answer never changes at run time.
    pub const fn applies_to_this_platform(self) -> bool {
        match self {
            BenchMode::CpuIsa | BenchMode::Crypto | BenchMode::TlsHandshake | BenchMode::CryptoRaw => true,
            BenchMode::KernelCrypto | BenchMode::KernelCryptoRing0 => {
                cfg!(target_os = "linux")
            }
        }
    }
}

/// One selectable row in the benchmark panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchKernel {
    /// Portable scalar baseline.
    Scalar,
    /// One ISA family's kernel.
    Isa(Backend),
    /// One cryptographic primitive.
    Crypto(Algorithm),
    /// A TLS handshake against the configured host.
    Tls,
    /// One algorithm through the kernel's crypto API, from ring 3.
    Kernel(KernelAlgorithm),
    /// The same algorithm, measured inside the kernel by the module.
    Ring0(KernelAlgorithm),
    /// One bare crypto instruction chain (Mode "Crypto RAW").
    CryptoRaw(CryptoKernel),
}

/// The algorithms this asks the kernel for, by the kernel's own names.
///
/// Two types, not four. `AF_ALG` also carries AEAD, but an AEAD session
/// negotiates its associated-data length and authentication size through the
/// same control message as the data, and a benchmark that got either wrong
/// would report a number for something other than what it named. A hash and a
/// block cipher are enough to show what the kernel's drivers do, and both are
/// simple enough to be certainly right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelAlgorithm {
    Sha1,
    Sha256,
    Sha512,
    Sha3_256,
    Crc32c,
    AesCbc,
    AesCtr,
}

impl KernelAlgorithm {
    /// The name to bind an `AF_ALG` socket to. These are the kernel's
    /// spellings, not ours: `cbc(aes)` is what `/proc/crypto` calls it.
    pub const fn algorithm(self) -> &'static str {
        match self {
            KernelAlgorithm::Sha1 => "sha1",
            KernelAlgorithm::Sha256 => "sha256",
            KernelAlgorithm::Sha512 => "sha512",
            KernelAlgorithm::Sha3_256 => "sha3-256",
            KernelAlgorithm::Crc32c => "crc32c",
            KernelAlgorithm::AesCbc => "cbc(aes)",
            KernelAlgorithm::AesCtr => "ctr(aes)",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            KernelAlgorithm::Sha1 => "SHA-1",
            KernelAlgorithm::Sha256 => "SHA-256",
            KernelAlgorithm::Sha512 => "SHA-512",
            KernelAlgorithm::Sha3_256 => "SHA3-256",
            KernelAlgorithm::Crc32c => "CRC32C",
            KernelAlgorithm::AesCbc => "AES-256-CBC",
            KernelAlgorithm::AesCtr => "AES-256-CTR",
        }
    }

    pub const fn is_hash(self) -> bool {
        !matches!(self, KernelAlgorithm::AesCbc | KernelAlgorithm::AesCtr)
    }

    /// Digest length, for sizing the read buffer.
    ///
    /// A short read here is not an error the kernel reports — it just hands
    /// back fewer bytes — so the buffer has to be right rather than roomy.
    pub const fn digest_len(self) -> usize {
        match self {
            KernelAlgorithm::Sha1 => 20,
            KernelAlgorithm::Sha256 | KernelAlgorithm::Sha3_256 => 32,
            KernelAlgorithm::Sha512 => 64,
            KernelAlgorithm::Crc32c => 4,
            KernelAlgorithm::AesCbc | KernelAlgorithm::AesCtr => 0,
        }
    }

    pub const ALL: &'static [KernelAlgorithm] = &[
        KernelAlgorithm::Sha1,
        KernelAlgorithm::Sha256,
        KernelAlgorithm::Sha512,
        KernelAlgorithm::Sha3_256,
        KernelAlgorithm::Crc32c,
        KernelAlgorithm::AesCbc,
        KernelAlgorithm::AesCtr,
    ];

    /// The hashes, which are the algorithms both rings can measure.
    ///
    /// Mode 5 runs inside the kernel through `shash`, and a symmetric cipher
    /// there needs a request object, scatterlists and a completion — so the
    /// ciphers are ring 3 only. These five are the rows where the two modes
    /// measure the same thing and can be subtracted.
    pub const HASHES: &'static [KernelAlgorithm] = &[
        KernelAlgorithm::Sha1,
        KernelAlgorithm::Sha256,
        KernelAlgorithm::Sha512,
        KernelAlgorithm::Sha3_256,
        KernelAlgorithm::Crc32c,
    ];

    /// Which implementation the kernel would use, from `/proc/crypto`.
    ///
    /// Worth showing next to the number: `sha256-avx2` and `sha256-generic`
    /// are the same algorithm and a different measurement, and without this
    /// the reader cannot tell which one they got.
    pub fn driver(self) -> Option<nanochrono_core::kcrypto::Driver> {
        nanochrono_core::kcrypto::driver_for(self.algorithm())
    }
}

impl BenchKernel {
    pub fn name(self) -> String {
        match self {
            BenchKernel::Scalar => "Scalar baseline".to_string(),
            BenchKernel::Isa(b) => b.name().to_uppercase(),
            BenchKernel::Crypto(a) => a.name().to_string(),
            BenchKernel::Tls => "TLS 1.3 handshake".to_string(),
            BenchKernel::Kernel(a) => format!("{} (ring 3)", a.name()),
            BenchKernel::Ring0(a) => format!("{} (ring 0)", a.name()),
            BenchKernel::CryptoRaw(k) => format!("{} (raw)", k.name().to_uppercase()),
        }
    }

    /// Whether this machine can run the kernel.
    pub fn is_available(self) -> bool {
        match self {
            BenchKernel::Scalar | BenchKernel::Crypto(_) | BenchKernel::Tls => true,
            BenchKernel::Isa(b) => b.is_available(),
            BenchKernel::CryptoRaw(k) => k.is_available(),
            // Available means the kernel offers this algorithm *and* the
            // socket family can be opened. A kernel without `sha512` in its
            // config is an ordinary kernel, not a broken one.
            BenchKernel::Kernel(a) => nanochrono_core::kcrypto::available() && a.driver().is_some(),
            // Offered only if the loaded module actually measured this one. A
            // kernel built without an algorithm makes the module skip it, and
            // a row that cannot produce a number should not be listed.
            BenchKernel::Ring0(a) => nanochrono_core::kcrypto::Ring0::read()
                .is_some_and(|report| report.timings.iter().any(|(n, _)| n == a.algorithm())),
        }
    }

    /// Which mode this kernel belongs to.
    pub const fn mode(self) -> BenchMode {
        match self {
            BenchKernel::Scalar | BenchKernel::Isa(_) => BenchMode::CpuIsa,
            BenchKernel::Crypto(_) => BenchMode::Crypto,
            BenchKernel::Tls => BenchMode::TlsHandshake,
            BenchKernel::Kernel(_) => BenchMode::KernelCrypto,
            BenchKernel::Ring0(_) => BenchMode::KernelCryptoRing0,
            BenchKernel::CryptoRaw(_) => BenchMode::CryptoRaw,
        }
    }

    /// The rows a given mode offers, in display order.
    pub fn rows_for(mode: BenchMode) -> Vec<BenchKernel> {
        match mode {
            BenchMode::CpuIsa => std::iter::once(BenchKernel::Scalar)
                .chain(Backend::ALL.iter().copied().map(BenchKernel::Isa))
                .collect(),
            BenchMode::Crypto => Algorithm::ALL
                .iter()
                .copied()
                .map(BenchKernel::Crypto)
                .collect(),
            BenchMode::TlsHandshake => vec![BenchKernel::Tls],
            BenchMode::KernelCrypto => KernelAlgorithm::ALL
                .iter()
                .copied()
                .map(BenchKernel::Kernel)
                .collect(),
            // Hashes only — see `KernelAlgorithm::HASHES`.
            BenchMode::KernelCryptoRing0 => KernelAlgorithm::HASHES
                .iter()
                .copied()
                .map(BenchKernel::Ring0)
                .collect(),
            BenchMode::CryptoRaw => CryptoKernel::ALL
                .iter()
                .copied()
                .map(BenchKernel::CryptoRaw)
                .collect(),
        }
    }
}

/// Iteration schedule and unit accounting for one kernel.
#[derive(Debug, Clone)]
pub struct BenchProfile {
    pub title: String,
    /// What the kernel actually executes, in one sentence.
    pub description: String,
    /// What "one op" means, so a rate figure can be interpreted.
    pub unit: String,
    pub ops_per_loop: f64,
    pub bytes_per_op: f64,
    /// Loop counts for the three passes.
    pub loops: [usize; 3],
    /// Repeat counts for the three passes.
    pub repeats: [u32; 3],
}

/// What decides whether an ISA kernel may run, on this architecture.
const FEATURE_GATE: &str = if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
    "CPUID + XGETBV"
} else if cfg!(target_arch = "aarch64") {
    "the OS's HWCAP report (the ID registers trap at EL0)"
} else {
    "the OS's CPU feature report"
};

impl BenchProfile {
    /// Schedule for `kernel`, sized so each pass runs long enough to dominate
    /// counter overhead but stays under a second.
    pub fn for_kernel(kernel: BenchKernel, payload_bytes: usize) -> BenchProfile {
        match kernel {
            BenchKernel::Scalar | BenchKernel::Isa(_) => BenchProfile {
                title: kernel.name(),
                description: format!(
                    "inline-asm ISA microbenchmark; dispatch is gated by {} before the kernel \
                     is reached",
                    FEATURE_GATE
                ),
                unit: "1 op = 1 kernel iteration".to_string(),
                ops_per_loop: 1.0,
                bytes_per_op: 8.0,
                loops: [300_000, 600_000, 900_000],
                repeats: [1, 2, 3],
            },
            BenchKernel::CryptoRaw(k) => BenchProfile {
                title: kernel.name(),
                description: format!(
                    "raw {} instruction chain, SPEED ONLY: no key schedule, no mode, no \
                     authentication, not a cipher — see Mode 2 for real crypto; gated by {}",
                    k.name(),
                    FEATURE_GATE
                ),
                unit: "1 op = 1 kernel iteration (one chain step per lane)".to_string(),
                ops_per_loop: 1.0,
                // No bytes: nothing is encrypted, so a MiB/s figure would be
                // a number about a cipher that is not there.
                bytes_per_op: 0.0,
                loops: [300_000, 600_000, 900_000],
                repeats: [1, 2, 3],
            },
            BenchKernel::Crypto(algorithm) => BenchProfile {
                title: algorithm.name().to_string(),
                description: format!(
                    "real {} over a {} buffer, through the rustls crypto provider",
                    algorithm.name(),
                    format::format_bytes(payload_bytes as f64)
                ),
                unit: format!("1 op = 1 {} call over the payload", algorithm.name()),
                ops_per_loop: 1.0,
                bytes_per_op: payload_bytes as f64,
                loops: [1_500, 3_000, 4_500],
                repeats: [1, 2, 3],
            },
            BenchKernel::Kernel(algorithm) => BenchProfile {
                title: algorithm.name().to_string(),
                description: match algorithm.driver() {
                    Some(driver) => format!(
                        "{} over a {} buffer through AF_ALG; the kernel selected `{}`{}",
                        algorithm.algorithm(),
                        format::format_bytes(payload_bytes as f64),
                        driver.driver,
                        if driver.looks_accelerated() {
                            ", which names an accelerated path"
                        } else {
                            ""
                        }
                    ),
                    None => format!(
                        "{} over a {} buffer through AF_ALG",
                        algorithm.algorithm(),
                        format::format_bytes(payload_bytes as f64)
                    ),
                },
                // Named as including the syscall, because it does. Comparing
                // this against Mode 2 without saying so would read as "the
                // kernel's AES is slower", when much of the difference is the
                // two context switches it took to ask.
                unit: "1 op = 1 kernel call over the payload, syscall included".to_string(),
                ops_per_loop: 1.0,
                bytes_per_op: payload_bytes as f64,
                // An order of magnitude fewer than the in-process crypto:
                // each iteration is a `sendmsg` and a `read`, so the same
                // loop count would take ten times as long for no more signal.
                loops: [400, 800, 1_200],
                repeats: [1, 2, 3],
            },
            BenchKernel::Ring0(algorithm) => BenchProfile {
                title: format!("{} (ring 0)", algorithm.name()),
                description: format!(
                    "{} over a {} buffer, measured inside the kernel by the module — \
                     no socket, no syscall, no copy across the privilege boundary",
                    algorithm.algorithm(),
                    format::format_bytes(payload_bytes as f64)
                ),
                unit: "1 op = 1 in-kernel call over the payload".to_string(),
                ops_per_loop: 1.0,
                bytes_per_op: payload_bytes as f64,
                // Not a schedule this process controls. The module takes its
                // own best-of-N inside the kernel and publishes the result;
                // a "pass" here is one read of that, which re-runs it. The
                // real count is reported per pass from what the module says.
                loops: [1, 1, 1],
                repeats: [1, 1, 1],
            },
            BenchKernel::Tls => BenchProfile {
                title: "TLS 1.3 handshake".to_string(),
                // Handshakes are seconds-scale and network-bound, so the
                // schedule is tiny: repeating them measures the remote host's
                // load, not this machine's.
                description: "full rustls handshake: TCP connect, ClientHello, certificate \
                              verification, key exchange"
                    .to_string(),
                unit: "1 op = 1 complete handshake".to_string(),
                ops_per_loop: 1.0,
                bytes_per_op: 0.0,
                loops: [1, 2, 3],
                repeats: [1, 1, 1],
            },
        }
    }
}

/// Payload size for a crypto kernel.
///
/// Large enough that per-call setup does not dominate, small enough to stay in
/// L2 so the number reflects the cipher rather than memory bandwidth.
pub const CRYPTO_PAYLOAD_BYTES: usize = 16 * 1024;

/// Result of one pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassResult {
    pub pass: u32,
    pub repeats: u32,
    pub loops: usize,
    pub cycles: u64,
    pub seconds: f64,
    pub total_ops: f64,
    pub total_bytes: f64,
    pub mops: f64,
    pub cycles_per_op: f64,
    pub ns_per_op: f64,
    pub mib_per_second: f64,
    /// Accumulated output, kept so the optimiser cannot delete the work.
    pub sink: u64,
}

/// Aggregate over all passes of a run.
#[derive(Debug, Clone, Default)]
pub struct BenchSummary {
    pub kernel_name: String,
    pub mode: &'static str,
    pub passes: Vec<PassResult>,
    pub best_mops: f64,
    pub worst_mops: f64,
    pub mean_mops: f64,
    pub best_ns_per_op: f64,
    pub worst_ns_per_op: f64,
    pub total_cycles: u64,
    pub total_seconds: f64,
    /// Present only for TLS runs.
    pub tls: Option<tls::HandshakeTiming>,
}

/// A completed benchmark run: the numbers plus the log the UI displays.
#[derive(Debug, Clone)]
pub struct BenchReport {
    pub summary: BenchSummary,
    pub log: String,
    /// Set when the run could not proceed; `summary` is then empty.
    pub error: Option<String>,
}

impl BenchReport {
    fn failed(kernel: BenchKernel, mode: BenchMode, reason: impl Into<String>) -> BenchReport {
        let reason = reason.into();
        BenchReport {
            summary: BenchSummary {
                kernel_name: kernel.name(),
                mode: mode.name(),
                ..Default::default()
            },
            log: format!("status: {reason}\n"),
            error: Some(reason),
        }
    }
}

/// Knobs for a run.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    pub mode: BenchMode,
    pub kernel: BenchKernel,
    /// Host for TLS runs.
    pub tls_host: String,
    pub tls_port: u16,
}

impl Default for BenchConfig {
    fn default() -> Self {
        BenchConfig {
            mode: BenchMode::CpuIsa,
            kernel: BenchKernel::Scalar,
            tls_host: "www.rust-lang.org".to_string(),
            tls_port: 443,
        }
    }
}

/// Runs the three-pass benchmark described by `config`.
///
/// Never panics and never faults: an unavailable kernel or a failed handshake
/// comes back as [`BenchReport::error`].
pub fn run(chrono: &Chronometer, config: &BenchConfig) -> BenchReport {
    let kernel = config.kernel;
    if !kernel.is_available() {
        // The reason differs by mode, and saying the wrong one sends the
        // reader after the wrong thing: an ISA kernel is missing because the
        // CPU lacks it, while a ring-0 row is missing because a module has
        // not been inserted, which has nothing to do with the CPU at all.
        return BenchReport::failed(
            kernel,
            config.mode,
            match config.mode {
                BenchMode::KernelCryptoRing0 => {
                    "NOT AVAILABLE: the kernel module is not loaded, or it did not \
                     measure this algorithm. Build and insert kernel/linux/ with \
                     `make load`, or use --mode kernel for the ring-3 measurement."
                }
                BenchMode::KernelCrypto => {
                    "NOT AVAILABLE: this kernel does not offer the algorithm through \
                     AF_ALG, or the socket family is unavailable here."
                }
                _ => "NOT AVAILABLE on this CPU",
            },
        );
    }

    let mut log = String::new();
    write_header(&mut log, chrono, config);

    if kernel == BenchKernel::Tls {
        return run_tls(config, log);
    }
    if let BenchKernel::Ring0(algorithm) = kernel {
        return run_ring0(chrono, config, algorithm, log);
    }

    let profile = BenchProfile::for_kernel(kernel, CRYPTO_PAYLOAD_BYTES);
    let _ = writeln!(log, "warmup: {}", profile.description);
    let _ = writeln!(log, "unit: {}\n", profile.unit);

    let dispatcher = Dispatcher::global();
    let mut workload = match Workload::new(kernel) {
        Ok(w) => w,
        Err(reason) => return BenchReport::failed(kernel, config.mode, reason),
    };

    let mut passes = Vec::with_capacity(3);
    for index in 0..3 {
        let pass = run_pass(
            chrono,
            dispatcher,
            &mut workload,
            &profile,
            index as u32 + 1,
            profile.repeats[index],
            profile.loops[index],
        );
        write_pass(&mut log, &profile, &pass);
        passes.push(pass);
    }

    let summary = summarise(kernel, config.mode, passes, None);
    write_summary(&mut log, &profile, &summary);
    let _ = writeln!(log, "\nstatus: completed successfully.");

    BenchReport {
        summary,
        log,
        error: None,
    }
}

/// Handshakes span milliseconds and several scheduler slices, so they are
/// timed off the wall clock rather than the calibrated counter — hence no
/// `Chronometer` parameter here.
fn run_tls(config: &BenchConfig, mut log: String) -> BenchReport {
    let profile = BenchProfile::for_kernel(BenchKernel::Tls, 0);
    let _ = writeln!(log, "warmup: {}", profile.description);
    let _ = writeln!(log, "unit: {}", profile.unit);
    let _ = writeln!(log, "target: {}:{}\n", config.tls_host, config.tls_port);

    let mut passes = Vec::with_capacity(3);
    let mut last_timing = None;

    for index in 0..3 {
        let start = arch::counter_start();
        let timing = tls::probe_handshake(&config.tls_host, config.tls_port, tls::DEFAULT_TIMEOUT);
        let cycles = arch::counter_end().wrapping_sub(start);

        match timing {
            Ok(t) => {
                let _ = writeln!(log, "pass {}: {}", index + 1, t.summary());
                let seconds = t.total_ns as f64 / 1e9;
                passes.push(PassResult {
                    pass: index as u32 + 1,
                    repeats: 1,
                    loops: 1,
                    cycles,
                    seconds,
                    total_ops: 1.0,
                    mops: if seconds > 0.0 { 1e-6 / seconds } else { 0.0 },
                    cycles_per_op: cycles as f64,
                    ns_per_op: t.total_ns as f64,
                    ..Default::default()
                });
                last_timing = Some(t);
            }
            Err(e) => {
                let reason = format!("handshake failed: {e}");
                let _ = writeln!(log, "pass {}: {reason}", index + 1);
                if passes.is_empty() {
                    let mut report = BenchReport::failed(BenchKernel::Tls, config.mode, reason);
                    report.log = log;
                    return report;
                }
            }
        }
    }

    let summary = summarise(BenchKernel::Tls, config.mode, passes, last_timing);
    write_summary(&mut log, &profile, &summary);
    if let Some(t) = &summary.tls {
        let _ = writeln!(
            log,
            "  negotiated: {} / {}   certificates: {}   tls share of total: {:.1}%",
            t.protocol,
            t.cipher_suite,
            t.peer_certificates,
            t.tls_fraction() * 100.0
        );
    }
    let _ = writeln!(log, "\nstatus: completed successfully.");

    BenchReport {
        summary,
        log,
        error: None,
    }
}

/// Owns whatever buffers and keys a kernel needs, so per-pass setup cost does
/// not land inside the timed region.
///
/// The variants differ in size, which does not matter here: exactly one
/// `Workload` exists per benchmark run, and it is constructed before the
/// timed region opens.
#[allow(clippy::large_enum_variant)]
enum Workload {
    Isa(BenchKernel),
    Hash {
        payload: Vec<u8>,
        hmac: bool,
    },
    Aead {
        key: AeadKey,
        payload: Vec<u8>,
        buffer: Vec<u8>,
        nonce: [u8; NONCE_LEN],
    },
    /// A kernel algorithm, held open across the whole run.
    ///
    /// The session is opened once rather than per iteration on purpose. Bind
    /// and accept are setup, not work: including them would measure how fast
    /// this machine can open sockets, which is a different and less
    /// interesting question than how fast its kernel encrypts.
    Kernel {
        session: nanochrono_core::kcrypto::Session,
        algorithm: KernelAlgorithm,
        payload: Vec<u8>,
        out: Vec<u8>,
    },
}

impl Workload {
    fn new(kernel: BenchKernel) -> Result<Workload, String> {
        match kernel {
            BenchKernel::Scalar | BenchKernel::Isa(_) | BenchKernel::CryptoRaw(_) => {
                Ok(Workload::Isa(kernel))
            }
            BenchKernel::Crypto(Algorithm::Sha256) => Ok(Workload::Hash {
                payload: payload(),
                hmac: false,
            }),
            BenchKernel::Crypto(Algorithm::HmacSha256) => Ok(Workload::Hash {
                payload: payload(),
                hmac: true,
            }),
            BenchKernel::Crypto(algorithm) => {
                let key = AeadKey::new(algorithm, &[0x42u8; 32])
                    .map_err(|e| format!("could not build {} key: {e}", algorithm.name()))?;
                let payload = payload();
                Ok(Workload::Aead {
                    key,
                    buffer: Vec::with_capacity(payload.len() + 16),
                    payload,
                    nonce: [0u8; NONCE_LEN],
                })
            }
            BenchKernel::Kernel(algorithm) => {
                let payload = payload();
                let session = if algorithm.is_hash() {
                    nanochrono_core::kcrypto::Session::hash(algorithm.algorithm())
                } else {
                    // A fixed key: this is a stopwatch input, not a secret.
                    // See `kcrypto`'s module documentation.
                    nanochrono_core::kcrypto::Session::skcipher(
                        algorithm.algorithm(),
                        &[0x42u8; 32],
                    )
                }
                .map_err(|e| {
                    format!(
                        "could not open {} through AF_ALG: {e}",
                        algorithm.algorithm()
                    )
                })?;
                let out = vec![0u8; payload.len().max(algorithm.digest_len())];
                Ok(Workload::Kernel {
                    session,
                    algorithm,
                    payload,
                    out,
                })
            }
            BenchKernel::Ring0(_) => Err("ring 0 is measured by run_ring0".to_string()),
            BenchKernel::Tls => Err("TLS is measured by run_tls".to_string()),
        }
    }

    /// Executes `loops` iterations and returns an accumulator derived from the
    /// output, which the caller keeps live.
    fn execute(&mut self, dispatcher: &Dispatcher, loops: usize) -> u64 {
        match self {
            Workload::Isa(BenchKernel::Scalar) => scalar_kernel(loops),
            Workload::Isa(BenchKernel::Isa(backend)) => {
                dispatcher.run_kernel_for(*backend, loops).unwrap_or(0)
            }
            Workload::Isa(BenchKernel::CryptoRaw(k)) => {
                dispatcher.run_crypto_kernel(*k, loops).unwrap_or(0)
            }
            Workload::Isa(_) => 0,
            Workload::Hash { payload, hmac } => {
                let mut sink = 0u64;
                for i in 0..loops {
                    let digest = if *hmac {
                        nanochrono_crypto::hmac_sha256(&[0x5Au8; 32], payload)
                    } else {
                        nanochrono_crypto::sha256(payload)
                    };
                    sink ^= u64::from_le_bytes(digest[..8].try_into().unwrap()) ^ i as u64;
                }
                sink
            }
            Workload::Aead {
                key,
                payload,
                buffer,
                nonce,
            } => {
                let mut sink = 0u64;
                for i in 0..loops {
                    // A fresh nonce per iteration: reuse under one key would
                    // be a real vulnerability even in a benchmark, and it also
                    // keeps the cipher from short-circuiting anything.
                    nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    buffer.clear();
                    buffer.extend_from_slice(payload);
                    if key.seal(nonce, &[], buffer).is_err() {
                        break;
                    }
                    sink ^= u64::from_le_bytes(buffer[buffer.len() - 8..].try_into().unwrap());
                }
                sink
            }
            Workload::Kernel {
                session,
                algorithm,
                payload,
                out,
            } => {
                let mut sink = 0u64;
                // A fixed IV, for the same reason as the fixed key: reusing
                // one would be a real weakness in real use and is meaningless
                // here, where the input is a constant buffer and the output
                // is thrown away. Varying it per iteration would measure the
                // IV setup rather than the cipher.
                let iv = [0x24u8; 16];
                for i in 0..loops {
                    let produced = if algorithm.is_hash() {
                        session.digest(payload, out)
                    } else {
                        session.encrypt(&iv, payload, out)
                    };
                    // A failure part-way through ends the run rather than
                    // being counted as a fast iteration: the caller divides
                    // by `loops`, so a silent early exit would report the
                    // kernel as arbitrarily quick.
                    let Ok(n) = produced else {
                        break;
                    };
                    // Added, not XORed. The payload is constant, so a hash
                    // produces the same digest every iteration — and XORing a
                    // constant an even number of times cancels to zero. The
                    // sink exists to keep the optimiser from deleting the
                    // loop and to show the caller that work happened; one
                    // that reads zero on every run does neither.
                    if n >= 8 {
                        let tail = u64::from_le_bytes(out[n - 8..n].try_into().unwrap());
                        sink = sink.wrapping_add(tail ^ i as u64);
                    }
                }
                sink
            }
        }
    }
}

fn payload() -> Vec<u8> {
    (0..CRYPTO_PAYLOAD_BYTES)
        .map(|i| (i.wrapping_mul(31) & 0xFF) as u8)
        .collect()
}

fn scalar_kernel(loops: usize) -> u64 {
    // `arch::x86::kernel_scalar` compiles for both x86 widths; only targets
    // with no architectural counter at all fall through to `generic`.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        arch::x86::kernel_scalar(loops)
    }
    #[cfg(target_arch = "aarch64")]
    {
        arch::aarch64::kernel_scalar(loops)
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        arch::powerpc::kernel_scalar(loops)
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        arch::riscv::kernel_scalar(loops)
    }
    #[cfg(target_arch = "arm")]
    {
        arch::arm32::kernel_scalar(loops)
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )))]
    {
        arch::generic::kernel_scalar(loops)
    }
}

#[allow(clippy::too_many_arguments)]
/// Reads what the kernel module measured, three times.
///
/// # Why this mode does not time a loop
///
/// Because the work happens on the other side of the privilege boundary, and
/// timing it from here would measure the boundary. That is precisely the
/// quantity the ring-3 mode already reports, and the reason this one exists
/// is to report the *other* half: the primitive with none of the transport.
///
/// So the module does the measuring. Every read of its `/proc` file runs the
/// algorithms again, in kernel, taking a best-of-N with the same counter this
/// process reads — and publishes the cycle count. Three reads give three
/// passes, and the spread between them is real pass-to-pass variance in the
/// kernel's own timing, not variance in how long it took to ask.
///
/// The cycles are converted here rather than there: the module has no
/// calibration of its own, and this process already knows the counter's rate.
///
/// # What the number means
///
/// Cycles for one digest of the module's payload, best of its rounds. Set
/// beside the ring-3 row for the same algorithm, the difference is what
/// `AF_ALG` costs — the socket, the two context switches, and the copy in and
/// out.
fn run_ring0(
    chrono: &Chronometer,
    config: &BenchConfig,
    algorithm: KernelAlgorithm,
    mut log: String,
) -> BenchReport {
    let kernel = config.kernel;
    let profile = BenchProfile::for_kernel(kernel, CRYPTO_PAYLOAD_BYTES);
    let _ = writeln!(log, "warmup: {}", profile.description);
    let _ = writeln!(log, "unit: {}\n", profile.unit);

    let mut passes = Vec::with_capacity(3);
    for pass in 1..=3u32 {
        let Some(report) = nanochrono_core::kcrypto::Ring0::read() else {
            return BenchReport::failed(
                kernel,
                config.mode,
                "the kernel module is not loaded; build and insert kernel/linux/                  (see its README), or use --mode kernel for the ring-3 measurement",
            );
        };
        let Some((_, cycles)) = report
            .timings
            .iter()
            .find(|(name, _)| name == algorithm.algorithm())
        else {
            return BenchReport::failed(
                kernel,
                config.mode,
                format!(
                    "the loaded module did not measure {}; this kernel may not                      provide it",
                    algorithm.algorithm()
                ),
            );
        };

        // The module states the size it measured over. Using the constant
        // here instead would silently report the wrong throughput the moment
        // the two disagreed — an old module against a new build, say.
        let bytes = report.payload_bytes as f64;
        let cycles = *cycles;
        let seconds = chrono.units_to_secs(cycles);

        passes.push(PassResult {
            pass,
            repeats: 1,
            // What the module actually did, not what this process asked for.
            loops: report.rounds,
            cycles,
            seconds,
            total_ops: 1.0,
            total_bytes: bytes,
            mops: if seconds > 0.0 {
                1.0 / seconds / 1e6
            } else {
                0.0
            },
            cycles_per_op: cycles as f64,
            ns_per_op: seconds * 1e9,
            mib_per_second: if seconds > 0.0 {
                bytes / seconds / (1024.0 * 1024.0)
            } else {
                0.0
            },
            // Nothing to keep alive: the work was done in the kernel, where
            // this process's optimiser has no say. Reporting the cycle count
            // makes the value visible rather than leaving a misleading zero.
            sink: cycles,
        });
        write_pass(&mut log, &profile, passes.last().expect("just pushed"));
    }

    // The comparison this mode exists for, stated rather than left as an
    // exercise. Only shown when the ring-3 side can be measured too.
    if let Some(ring3) = ring3_cycles_per_op(algorithm) {
        let ring0 = passes
            .iter()
            .map(|p| p.cycles_per_op)
            .fold(f64::INFINITY, f64::min);
        if ring0.is_finite() && ring0 > 0.0 && ring3 > ring0 {
            let _ = writeln!(
                log,
                "\nAF_ALG overhead: ring 3 {ring3:.0} cyc/op vs ring 0 {ring0:.0} cyc/op \
                 = {:.0} cycles ({:.1}x) spent crossing the boundary",
                ring3 - ring0,
                ring3 / ring0
            );
        }
    }

    let summary = summarise(kernel, config.mode, passes, None);
    write_summary(&mut log, &profile, &summary);
    let _ = writeln!(log, "\nstatus: completed successfully.");

    BenchReport {
        summary,
        log,
        error: None,
    }
}

/// Times the same algorithm through `AF_ALG`, for the comparison line.
///
/// Best of a short run, so the two sides are compared the way each was
/// measured: the module takes a minimum in kernel, and this takes one here.
/// `None` when the ring-3 path cannot run, in which case the comparison is
/// simply not printed rather than being printed against a guess.
fn ring3_cycles_per_op(algorithm: KernelAlgorithm) -> Option<f64> {
    let payload = payload();
    let session = nanochrono_core::kcrypto::Session::hash(algorithm.algorithm()).ok()?;
    let mut out = vec![0u8; algorithm.digest_len().max(64)];

    let mut best = u64::MAX;
    for _ in 0..32 {
        let start = arch::counter_start();
        let produced = session.digest(&payload, &mut out);
        let elapsed = arch::counter_end().wrapping_sub(start);
        produced.ok()?;
        if elapsed != 0 && elapsed < best {
            best = elapsed;
        }
    }
    (best != u64::MAX).then_some(best as f64)
}

fn run_pass(
    chrono: &Chronometer,
    dispatcher: &Dispatcher,
    workload: &mut Workload,
    profile: &BenchProfile,
    pass: u32,
    repeats: u32,
    loops: usize,
) -> PassResult {
    let mut sink = 0u64;

    let start = arch::counter_start();
    for _ in 0..repeats {
        sink ^= workload.execute(dispatcher, loops);
    }
    let cycles = arch::counter_end().wrapping_sub(start);

    // Keeps the whole loop observably alive: without this the optimiser is
    // entitled to delete a pure computation whose result is discarded, and the
    // benchmark would report the cost of nothing.
    let sink = std::hint::black_box(sink);

    let seconds = chrono.units_to_secs(cycles);
    let total_ops = repeats as f64 * loops as f64 * profile.ops_per_loop;
    let total_bytes = total_ops * profile.bytes_per_op;

    PassResult {
        pass,
        repeats,
        loops,
        cycles,
        seconds,
        total_ops,
        total_bytes,
        mops: if seconds > 0.0 {
            total_ops / seconds / 1e6
        } else {
            0.0
        },
        cycles_per_op: if total_ops > 0.0 {
            cycles as f64 / total_ops
        } else {
            0.0
        },
        ns_per_op: if total_ops > 0.0 {
            seconds * 1e9 / total_ops
        } else {
            0.0
        },
        mib_per_second: if seconds > 0.0 && total_bytes > 0.0 {
            total_bytes / (1024.0 * 1024.0) / seconds
        } else {
            0.0
        },
        sink,
    }
}

fn summarise(
    kernel: BenchKernel,
    mode: BenchMode,
    passes: Vec<PassResult>,
    tls: Option<tls::HandshakeTiming>,
) -> BenchSummary {
    let mut summary = BenchSummary {
        kernel_name: kernel.name(),
        mode: mode.name(),
        tls,
        ..Default::default()
    };
    if passes.is_empty() {
        return summary;
    }

    summary.best_mops = f64::MIN;
    summary.worst_mops = f64::MAX;
    summary.best_ns_per_op = f64::MAX;
    summary.worst_ns_per_op = f64::MIN;

    for p in &passes {
        summary.best_mops = summary.best_mops.max(p.mops);
        summary.worst_mops = summary.worst_mops.min(p.mops);
        summary.best_ns_per_op = summary.best_ns_per_op.min(p.ns_per_op);
        summary.worst_ns_per_op = summary.worst_ns_per_op.max(p.ns_per_op);
        summary.total_cycles = summary.total_cycles.saturating_add(p.cycles);
        summary.total_seconds += p.seconds;
        summary.mean_mops += p.mops;
    }
    summary.mean_mops /= passes.len() as f64;
    summary.passes = passes;
    summary
}

fn write_header(log: &mut String, chrono: &Chronometer, config: &BenchConfig) {
    let features: CpuFeatures = nanochrono_core::cpu::features();
    let _ = writeln!(log, "=== NanoChronometer benchmark ===");
    let _ = writeln!(log, "operation: {}", config.kernel.name());
    let _ = writeln!(log, "mode: {}", config.mode.name());
    let _ = writeln!(log, "backend: {}", chrono.backend().name());
    let _ = writeln!(
        log,
        "simd: {}",
        SimdFamily::best().map(SimdFamily::name).unwrap_or("none")
    );
    let _ = writeln!(
        log,
        "counter: {:.3} MHz  invariant={}",
        chrono.counter_hz() as f64 / 1e6,
        features.invariant_counter
    );
    // The ring-0 half, when the optional module is loaded. Shown next to the

    // ring-3 numbers because the difference between them is the point: the

    // same algorithm, once through a socket and once not, and the gap is what

    // `AF_ALG` costs.

    // The ring-0 module is a Linux kernel module; elsewhere there is nothing
    // to be loaded or not, and saying "not loaded" would suggest otherwise.
    #[cfg(target_os = "linux")]
    if let Some(ring0) = nanochrono_core::kcrypto::Ring0::read() {
        let _ = writeln!(
            log,
            "ring 0 module: loaded; {} algorithm(s), best of {} over {}",
            ring0.timings.len(),
            ring0.rounds,
            format::format_bytes(ring0.payload_bytes as f64)
        );

        for (name, cycles) in &ring0.timings {
            let _ = writeln!(log, "  ring 0 {name}: {cycles} cycles/op");
        }
    } else {
        let _ = writeln!(
            log,
            "ring 0 module: not loaded (optional; see kernel/linux/README.md)"
        );
    }
    let _ = writeln!(log, "crypto provider: {}", nanochrono_crypto::PROVIDER);
    let _ = writeln!(log, "cpu flags: {}\n", cpu_flags(&features));
}

/// The crypto and vector flags that matter here, in this architecture's
/// names: x86 flags on an ARM phone read as a CPU without AES, which it has.
fn cpu_flags(f: &nanochrono_core::CpuFeatures) -> String {
    let b = |v: bool| v as u8;
    if cfg!(any(target_arch = "aarch64", target_arch = "arm")) {
        format!(
            "AES={} SHA2={} PMULL={} NEON={} SVE={} SVE2={} SME={}",
            b(f.arm_aes),
            b(f.arm_sha2),
            b(f.pclmulqdq),
            b(f.neon),
            b(f.sve),
            b(f.sve2),
            b(f.sme)
        )
    } else if cfg!(any(target_arch = "powerpc", target_arch = "powerpc64")) {
        format!("ALTIVEC={} VSX={}", b(f.altivec), b(f.vsx))
    } else if cfg!(any(target_arch = "riscv32", target_arch = "riscv64")) {
        format!("RVV={}", b(f.rvv))
    } else {
        format!(
            "AES={} SHA={} VAES={} PCLMUL={} AVX={} AVX2={} AVX-VNNI={} AVX512F={}",
            b(f.aesni),
            b(f.shani),
            b(f.vaes),
            b(f.pclmulqdq),
            b(f.avx),
            b(f.avx2),
            b(f.avx_vnni),
            b(f.avx512f)
        )
    }
}

fn write_pass(log: &mut String, profile: &BenchProfile, r: &PassResult) {
    let _ = write!(
        log,
        "pass {}: repeats={}  loops={}  cycles={}  time={:.6} s  rate={:.3} Mops/s  \
         cyc/op={:.4}  ns/op={:.4}",
        r.pass, r.repeats, r.loops, r.cycles, r.seconds, r.mops, r.cycles_per_op, r.ns_per_op
    );
    if profile.bytes_per_op > 0.0 {
        let _ = write!(log, "  MiB/s={:.3}", r.mib_per_second);
    }
    let _ = writeln!(log, "  sink={:016X}", r.sink);
}

fn write_summary(log: &mut String, profile: &BenchProfile, s: &BenchSummary) {
    let _ = writeln!(log, "\nsummary:");
    let _ = writeln!(log, "  unit: {}", profile.unit);
    let _ = writeln!(
        log,
        "  rate: mean {:.3} Mops/s   best {:.3}   worst {:.3}",
        s.mean_mops, s.best_mops, s.worst_mops
    );
    let _ = writeln!(
        log,
        "  ns/op: best {:.4}   worst {:.4}",
        s.best_ns_per_op, s.worst_ns_per_op
    );
    let _ = writeln!(log, "  aggregate cycles: {}", s.total_cycles);
    let _ = writeln!(log, "  aggregate time: {:.6} s", s.total_seconds);

    // Pass-to-pass spread is the warm-up signal; call it out rather than
    // leaving the reader to compare three lines by eye.
    if s.best_mops > 0.0 && s.worst_mops > 0.0 {
        let spread = (s.best_mops - s.worst_mops) / s.best_mops * 100.0;
        if spread > 15.0 {
            let _ = writeln!(
                log,
                "  note: {spread:.1}% spread between passes — the workload is still warming up, \
                 so trust the last pass over the mean."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mode_offers_rows() {
        for mode in BenchMode::ALL.iter().copied() {
            assert!(!BenchKernel::rows_for(mode).is_empty(), "{mode:?}");
        }
    }

    #[test]
    fn rows_report_the_mode_they_came_from() {
        for mode in BenchMode::ALL.iter().copied() {
            for kernel in BenchKernel::rows_for(mode) {
                assert_eq!(kernel.mode(), mode);
            }
        }
    }

    #[test]
    fn scalar_baseline_produces_a_rate() {
        let chrono = Chronometer::new();
        let config = BenchConfig {
            mode: BenchMode::CpuIsa,
            kernel: BenchKernel::Scalar,
            ..Default::default()
        };
        let report = run(&chrono, &config);
        assert!(report.error.is_none(), "{:?}", report.error);
        assert_eq!(report.summary.passes.len(), 3);
        assert!(report.summary.best_mops > 0.0);
        assert!(report.log.contains("status: completed successfully"));
    }

    #[test]
    fn every_available_isa_kernel_runs() {
        let chrono = Chronometer::new();
        for backend in Backend::ALL.iter().copied() {
            let config = BenchConfig {
                mode: BenchMode::CpuIsa,
                kernel: BenchKernel::Isa(backend),
                ..Default::default()
            };
            let report = run(&chrono, &config);
            if backend.is_available() {
                assert!(
                    report.error.is_none(),
                    "{backend} failed: {:?}",
                    report.error
                );
            } else {
                assert!(report.error.is_some(), "{backend} ran but is unsupported");
            }
        }
    }

    #[test]
    fn unavailable_kernels_report_rather_than_fault() {
        let chrono = Chronometer::new();
        let unavailable = Backend::ALL.iter().copied().find(|b| !b.is_available());
        let Some(backend) = unavailable else {
            return; // every backend runs here; nothing to check
        };
        let report = run(
            &chrono,
            &BenchConfig {
                kernel: BenchKernel::Isa(backend),
                ..Default::default()
            },
        );
        assert!(report.error.is_some());
        assert!(report.summary.passes.is_empty());
    }

    #[test]
    fn every_crypto_primitive_benchmarks() {
        let chrono = Chronometer::new();
        for algorithm in Algorithm::ALL.iter().copied() {
            let config = BenchConfig {
                mode: BenchMode::Crypto,
                kernel: BenchKernel::Crypto(algorithm),
                ..Default::default()
            };
            let report = run(&chrono, &config);
            assert!(
                report.error.is_none(),
                "{} failed: {:?}",
                algorithm.name(),
                report.error
            );
            assert!(report.summary.best_mops > 0.0, "{}", algorithm.name());
            assert!(report.log.contains("rustls/ring"));
        }
    }

    #[test]
    fn aead_benchmark_throughput_is_plausible() {
        let chrono = Chronometer::new();
        let report = run(
            &chrono,
            &BenchConfig {
                mode: BenchMode::Crypto,
                kernel: BenchKernel::Crypto(Algorithm::Aes256Gcm),
                ..Default::default()
            },
        );
        let mib = report.summary.passes[2].mib_per_second;
        // AES-NI does gigabytes per second; software AES does hundreds of MiB.
        // Anything below 1 MiB/s means the workload was optimised away.
        assert!(mib > 1.0, "AES-256-GCM reported {mib:.3} MiB/s");
    }

    #[test]
    fn profiles_describe_their_unit() {
        for mode in BenchMode::ALL.iter().copied() {
            for kernel in BenchKernel::rows_for(mode) {
                let p = BenchProfile::for_kernel(kernel, CRYPTO_PAYLOAD_BYTES);
                assert!(!p.unit.is_empty());
                assert!(!p.description.is_empty());
                assert!(p.loops.iter().all(|&l| l > 0));
            }
        }
    }
}

#[cfg(test)]
mod platform_tests {
    use super::*;

    /// The offered modes must be exactly the ones that apply here.
    ///
    /// Modes 4 and 5 are Linux's: `AF_ALG` is a Linux socket family and the
    /// ring-0 mode is a Linux kernel module. Neither has an equivalent on
    /// Windows or macOS, so neither is *listed* there — a mode that can never
    /// run on an operating system is not an unavailable feature, it is not a
    /// feature of that system at all.
    ///
    /// Asserted rather than trusted to the `cfg` above it, because the list
    /// and the predicate are two places that have to agree and nothing else
    /// makes them.
    #[test]
    fn only_modes_that_apply_to_this_platform_are_offered() {
        for mode in BenchMode::ALL {
            assert!(
                mode.applies_to_this_platform(),
                "{} is offered here and does not apply to this platform",
                mode.name()
            );
        }
        let offered = BenchMode::ALL.len();
        let applicable = [
            BenchMode::CpuIsa,
            BenchMode::Crypto,
            BenchMode::TlsHandshake,
            BenchMode::KernelCrypto,
            BenchMode::KernelCryptoRing0,
            BenchMode::CryptoRaw,
        ]
        .iter()
        .filter(|mode| mode.applies_to_this_platform())
        .count();
        assert_eq!(
            offered, applicable,
            "the offered list and the platform predicate disagree"
        );
    }

    /// The number in each label is the mode's place in the list, which is
    /// also the digit key that selects it in the GUI.
    #[test]
    fn mode_labels_are_numbered_by_position() {
        for (i, mode) in BenchMode::ALL.iter().enumerate() {
            let prefix = format!("Mode {}:", i + 1);
            assert!(mode.label().starts_with(&prefix), "{} is not {prefix}", mode.label());
        }
    }

    /// And the count is what each platform should see.
    #[test]
    fn the_platform_offers_the_expected_number_of_modes() {
        let expected = if cfg!(target_os = "linux") { 6 } else { 4 };
        assert_eq!(
            BenchMode::ALL.len(),
            expected,
            "expected {expected} modes on this platform, got {:?}",
            BenchMode::ALL.iter().map(|m| m.name()).collect::<Vec<_>>()
        );
    }

    /// Every row a mode offers must belong to that mode.
    ///
    /// Cheap, and it catches the copy-paste that puts a ring-3 row in the
    /// ring-0 list — which would silently report one measurement under the
    /// other's name.
    #[test]
    fn every_row_belongs_to_the_mode_that_lists_it() {
        for mode in BenchMode::ALL {
            for kernel in BenchKernel::rows_for(*mode) {
                assert_eq!(
                    kernel.mode(),
                    *mode,
                    "{} is listed under {} but belongs to {}",
                    kernel.name(),
                    mode.name(),
                    kernel.mode().name()
                );
            }
        }
    }

    /// The ring-0 mode measures hashes only, and every one of them has a
    /// ring-3 row measuring the same algorithm — otherwise the two numbers
    /// could not be subtracted, which is the whole point of having both.
    #[cfg(target_os = "linux")]
    #[test]
    fn every_ring0_row_has_a_ring3_counterpart() {
        for kernel in BenchKernel::rows_for(BenchMode::KernelCryptoRing0) {
            let BenchKernel::Ring0(algorithm) = kernel else {
                panic!("{} is not a ring-0 row", kernel.name());
            };
            assert!(
                algorithm.is_hash(),
                "{} is not a hash; ring 0 measures shash only",
                algorithm.name()
            );
            assert!(
                BenchKernel::rows_for(BenchMode::KernelCrypto)
                    .contains(&BenchKernel::Kernel(algorithm)),
                "{} has no ring-3 counterpart to compare against",
                algorithm.name()
            );
        }
    }
}
