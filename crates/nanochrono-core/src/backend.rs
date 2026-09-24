// SPDX-License-Identifier: Apache-2.0
//! Timer backends: which ISA family the counter reads are tagged to.
//!
//! The backend does **not** change how the counter is read — `RDTSC` is
//! `RDTSC` — it selects which family's probe path a measurement is attributed
//! to, so a report can say "measured on the AVX-512 path" and mean it.
//!
//! Selecting a backend the CPU lacks is not an error the caller has to handle:
//! [`Backend::resolve`] degrades to the best available family instead. Nothing
//! ever executes an instruction that CPUID did not confirm.

use crate::cpu::{self, CpuFeatures};

/// A counter backend, ordered from most portable to most specific.
///
/// Discriminants match the C `nc_backend_t` ABI so the FFI layer and the
/// language wrappers keep working unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u32)]
pub enum Backend {
    /// Portable scalar path. Always available.
    #[default]
    Legacy = 0,
    Avx = 1,
    Mmx = 2,
    Sse = 3,
    Sse2 = 4,
    Sse3 = 5,
    Ssse3 = 6,
    Sse41 = 7,
    Sse42 = 8,
    F16c = 9,
    Fma = 10,
    Avx2 = 11,
    AvxVnni = 12,
    Avx512 = 13,
    Avx512Vnni = 14,
    Neon = 15,
    Sve = 16,
    Sve2 = 17,
    Sme = 18,
    /// PowerPC VMX (AltiVec).
    Altivec = 19,
    /// PowerPC VSX.
    Vsx = 20,
    /// RISC-V vector extension.
    Rvv = 21,
}

impl Backend {
    /// Stable lowercase name, as printed in reports and accepted by
    /// [`Backend::parse`].
    pub const fn name(self) -> &'static str {
        match self {
            Backend::Legacy => "legacy-asm",
            Backend::Mmx => "mmx",
            Backend::Sse => "sse",
            Backend::Sse2 => "sse2",
            Backend::Sse3 => "sse3",
            Backend::Ssse3 => "ssse3",
            Backend::Sse41 => "sse4.1",
            Backend::Sse42 => "sse4.2",
            Backend::Avx => "avx",
            Backend::F16c => "f16c",
            Backend::Fma => "fma",
            Backend::Avx2 => "avx2",
            Backend::AvxVnni => "avx-vnni",
            Backend::Avx512 => "avx-512",
            Backend::Avx512Vnni => "avx-512-vnni",
            Backend::Neon => "neon",
            Backend::Sve => "sve",
            Backend::Sve2 => "sve2",
            Backend::Sme => "sme",
            Backend::Altivec => "altivec",
            Backend::Vsx => "vsx",
            Backend::Rvv => "rvv",
        }
    }

    /// Parses a backend name, accepting the spellings the C CLI and the
    /// `NANOCHRONO_BACKEND` environment variable allowed.
    #[cfg(feature = "std")]
    pub fn parse(s: &str) -> Option<Backend> {
        let normalised = s.trim().to_ascii_lowercase().replace(['_', ' '], "-");
        Some(match normalised.as_str() {
            "legacy" | "legacy-asm" | "scalar" | "asm-scalar" => Backend::Legacy,
            "mmx" => Backend::Mmx,
            "sse" => Backend::Sse,
            "sse2" => Backend::Sse2,
            "sse3" => Backend::Sse3,
            "ssse3" => Backend::Ssse3,
            "sse41" | "sse4.1" | "sse4-1" => Backend::Sse41,
            "sse42" | "sse4.2" | "sse4-2" => Backend::Sse42,
            "avx" => Backend::Avx,
            "f16c" => Backend::F16c,
            "fma" => Backend::Fma,
            "avx2" => Backend::Avx2,
            "avx-vnni" | "avxvnni" => Backend::AvxVnni,
            "avx512" | "avx-512" => Backend::Avx512,
            "avx512vnni" | "avx-512-vnni" | "avx512-vnni" => Backend::Avx512Vnni,
            "neon" => Backend::Neon,
            "sve" => Backend::Sve,
            "sve2" => Backend::Sve2,
            "sme" => Backend::Sme,
            "altivec" | "vmx" => Backend::Altivec,
            "vsx" => Backend::Vsx,
            "rvv" | "riscv-v" => Backend::Rvv,
            _ => return None,
        })
    }

    /// Whether this CPU can actually execute the backend's family.
    pub fn is_available(self) -> bool {
        self.is_available_with(&cpu::features())
    }

    fn is_available_with(self, f: &CpuFeatures) -> bool {
        if !self.has_kernel() {
            return false;
        }
        match self {
            Backend::Legacy => true,
            Backend::Mmx => f.mmx,
            Backend::Sse => f.sse,
            Backend::Sse2 => f.sse2,
            Backend::Sse3 => f.sse3,
            Backend::Ssse3 => f.ssse3,
            Backend::Sse41 => f.sse41,
            Backend::Sse42 => f.sse42,
            Backend::Avx => f.avx,
            Backend::F16c => f.f16c,
            Backend::Fma => f.fma,
            Backend::Avx2 => f.avx2,
            Backend::AvxVnni => f.avx_vnni,
            Backend::Avx512 => f.avx512f,
            Backend::Avx512Vnni => f.avx512vnni,
            Backend::Neon => f.neon,
            Backend::Sve => f.sve,
            Backend::Sve2 => f.sve2,
            Backend::Sme => f.sme,
            Backend::Altivec => f.altivec,
            Backend::Vsx => f.vsx,
            Backend::Rvv => f.rvv,
        }
    }

    /// Whether this build carries a kernel for the family.
    ///
    /// Separate from the CPUID question. 32-bit x86 detects SSE2, AVX2 and the
    /// rest through CPUID perfectly well, but the kernels are written against
    /// the 64-bit register file, so a request for `sse2` there would quietly
    /// measure a scalar loop and report it as SSE2. Reporting the backend as
    /// unavailable is the honest answer; the counter routes still work, which
    /// is what the ABI is actually for.
    fn has_kernel(self) -> bool {
        if cfg!(target_arch = "x86") {
            matches!(self, Backend::Legacy)
        } else if cfg!(any(target_arch = "powerpc", target_arch = "powerpc64")) {
            // The vector kernels are compiled only with the `simd` feature.
            matches!(self, Backend::Legacy)
                || (cfg!(feature = "simd") && matches!(self, Backend::Altivec | Backend::Vsx))
        } else if cfg!(any(target_arch = "riscv32", target_arch = "riscv64")) {
            matches!(self, Backend::Legacy) || (cfg!(feature = "simd") && self == Backend::Rvv)
        } else if cfg!(target_arch = "arm") {
            matches!(self, Backend::Legacy) || (cfg!(feature = "simd") && self == Backend::Neon)
        } else {
            true
        }
    }

    /// Best backend this machine supports, widest family first.
    pub fn best() -> Backend {
        let f = cpu::features();
        const X86_ORDER: &[Backend] = &[
            Backend::Avx512Vnni,
            Backend::Avx512,
            Backend::AvxVnni,
            Backend::Avx2,
            Backend::Fma,
            Backend::F16c,
            Backend::Avx,
            Backend::Sse42,
            Backend::Sse41,
            Backend::Ssse3,
            Backend::Sse3,
            Backend::Sse2,
            Backend::Sse,
            Backend::Mmx,
        ];
        const ARM_ORDER: &[Backend] = &[Backend::Sme, Backend::Sve2, Backend::Sve, Backend::Neon];
        const PPC_ORDER: &[Backend] = &[Backend::Vsx, Backend::Altivec];
        const RISCV_ORDER: &[Backend] = &[Backend::Rvv];
        const ARM32_ORDER: &[Backend] = &[Backend::Neon];

        let order = if cfg!(target_arch = "aarch64") {
            ARM_ORDER
        } else if cfg!(any(target_arch = "powerpc", target_arch = "powerpc64")) {
            PPC_ORDER
        } else if cfg!(any(target_arch = "riscv32", target_arch = "riscv64")) {
            RISCV_ORDER
        } else if cfg!(target_arch = "arm") {
            ARM32_ORDER
        } else {
            X86_ORDER
        };
        order
            .iter()
            .copied()
            .find(|b| b.is_available_with(&f))
            .unwrap_or(Backend::Legacy)
    }

    /// Returns `self` if available, otherwise the best available backend.
    ///
    /// Degrading here rather than failing is deliberate: a request for AVX-512
    /// on a machine without it should still produce a working chronometer, and
    /// the caller can compare [`Backend::name`] against what it asked for.
    pub fn resolve(self) -> Backend {
        if self.is_available() {
            self
        } else {
            Backend::best()
        }
    }

    /// Whether the backend's family belongs to this build's architecture.
    /// `Legacy` (the scalar path) belongs everywhere. See
    /// [`SimdFamily::is_native`](crate::SimdFamily::is_native).
    pub const fn is_native(self) -> bool {
        match self {
            Backend::Legacy => true,
            Backend::Neon => cfg!(any(target_arch = "aarch64", target_arch = "arm")),
            Backend::Sve | Backend::Sve2 | Backend::Sme => cfg!(target_arch = "aarch64"),
            Backend::Altivec | Backend::Vsx => {
                cfg!(any(target_arch = "powerpc", target_arch = "powerpc64"))
            }
            Backend::Rvv => cfg!(any(target_arch = "riscv32", target_arch = "riscv64")),
            _ => cfg!(any(target_arch = "x86", target_arch = "x86_64")),
        }
    }

    /// Every backend, for enumeration in UIs and catalogs.
    pub const ALL: &'static [Backend] = &[
        Backend::Legacy,
        Backend::Mmx,
        Backend::Sse,
        Backend::Sse2,
        Backend::Sse3,
        Backend::Ssse3,
        Backend::Sse41,
        Backend::Sse42,
        Backend::Avx,
        Backend::F16c,
        Backend::Fma,
        Backend::Avx2,
        Backend::AvxVnni,
        Backend::Avx512,
        Backend::Avx512Vnni,
        Backend::Neon,
        Backend::Sve,
        Backend::Sve2,
        Backend::Sme,
        Backend::Altivec,
        Backend::Vsx,
        Backend::Rvv,
    ];
}

impl core::fmt::Display for Backend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}
