// SPDX-License-Identifier: Apache-2.0
//! The ISA and crypto-instruction microbenchmark kernels, mapped from the
//! families that name them.
//!
//! `no_std`: the hosted dispatcher ([`crate::dispatch`], with its caching and
//! environment overrides) and the freestanding kernel's benchmark tab call the
//! same [`resolve_kernel`], so both run the same instruction sequences.
//!
//! Every trampoline is `unsafe` underneath; the invariant that discharges it
//! is the caller's: resolve a backend only after [`Backend::is_available`]
//! said yes (for crypto, [`CryptoKernel::is_available`]).

use crate::arch;
use crate::backend::Backend;
use crate::cpu;

/// Signature of a dispatched ISA microbenchmark kernel.
pub type KernelFn = fn(usize) -> u64;

/// A cryptographic instruction family with an instruction-latency kernel.
///
/// These are not timer backends — nothing reads a counter through AES-NI — so
/// they sit outside [`Backend`]. What they measure is what one round of the
/// instruction costs on this core, which is a different question from what a
/// cipher costs; for that, use `nanochrono-crypto`, which goes through the
/// rustls provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoKernel {
    /// `AESENC`/`AESENCLAST` on x86-64, `AESE`/`AESMC` on AArch64.
    Aes,
    /// `SHA256RNDS2` on x86-64, `SHA256H` on AArch64.
    Sha256,
    /// `PCLMULQDQ` on x86-64, `PMULL` on AArch64.
    CarrylessMultiply,
    /// `VAESENC` on YMM (x86-64): two AES blocks per instruction.
    VectorAes,
    /// `VPCLMULQDQ` on YMM (x86-64): two carry-less products per instruction.
    VectorCarryless,
}

impl CryptoKernel {
    pub const fn name(self) -> &'static str {
        match self {
            CryptoKernel::Aes => "aes",
            CryptoKernel::Sha256 => "sha256",
            CryptoKernel::CarrylessMultiply => "carryless-multiply",
            CryptoKernel::VectorAes => "vaes (ymm)",
            CryptoKernel::VectorCarryless => "vpclmulqdq (ymm)",
        }
    }

    /// Whether this CPU implements the family.
    pub fn is_available(self) -> bool {
        let f = cpu::features();
        match self {
            CryptoKernel::Aes => f.aesni || f.arm_aes,
            CryptoKernel::Sha256 => f.shani || f.arm_sha2,
            CryptoKernel::CarrylessMultiply => f.pclmulqdq,
            // The YMM forms: VEX-encoded, so AVX2 is the carrier.
            CryptoKernel::VectorAes => f.vaes && f.avx2,
            CryptoKernel::VectorCarryless => f.vpclmulqdq && f.avx2,
        }
    }

    pub const ALL: &'static [CryptoKernel] = &[
        CryptoKernel::Aes,
        CryptoKernel::Sha256,
        CryptoKernel::CarrylessMultiply,
        CryptoKernel::VectorAes,
        CryptoKernel::VectorCarryless,
    ];
}

/// Wraps each `#[target_feature]` kernel in a safe trampoline.
///
/// The `unsafe` is discharged once, here, by the invariant that
/// [`resolve_kernel`] only hands out a trampoline whose backend passed
/// [`Backend::is_available`].
// Unused on 32-bit x86, which has the counter layer but no ISA kernels.
#[allow(unused_macros)]
macro_rules! kernel_trampolines {
    ($( $name:ident => $target:path ),+ $(,)?) => {
        $(
            fn $name(loops: usize) -> u64 {
                // SAFETY: installed only via `resolve_kernel`, which checks
                // `Backend::is_available()` — i.e. the CPUID bit and, for
                // register files wider than XMM, the matching XCR0 bit.
                unsafe { $target(loops) }
            }
        )+
    };
}

#[cfg(all(target_arch = "x86_64", feature = "simd"))]
kernel_trampolines! {
    kernel_mmx => arch::x86::kernel_mmx,
    kernel_sse => arch::x86::kernel_sse,
    kernel_sse2 => arch::x86::kernel_sse2,
    kernel_sse3 => arch::x86::kernel_sse3,
    kernel_ssse3 => arch::x86::kernel_ssse3,
    kernel_sse41 => arch::x86::kernel_sse41,
    kernel_sse42 => arch::x86::kernel_sse42,
    kernel_f16c => arch::x86::kernel_f16c,
    kernel_fma => arch::x86::kernel_fma,
    kernel_avx => arch::x86::kernel_avx,
    kernel_avx2 => arch::x86::kernel_avx2,
    kernel_avx_vnni => arch::x86::kernel_avx_vnni,
    kernel_avx512 => arch::x86::kernel_avx512,
    kernel_avx512_vnni => arch::x86::kernel_avx512_vnni,
    kernel_aes => arch::x86::kernel_aesni,
    kernel_sha256 => arch::x86::kernel_shani,
    kernel_carryless => arch::x86::kernel_pclmul,
    kernel_vaes => arch::x86::kernel_vaes,
    kernel_vpclmul => arch::x86::kernel_vpclmul,
}

#[cfg(all(target_arch = "aarch64", feature = "simd"))]
kernel_trampolines! {
    kernel_neon => arch::aarch64::kernel_neon,
    kernel_aes => arch::aarch64::kernel_aes,
    kernel_sha256 => arch::aarch64::kernel_sha256,
    kernel_carryless => arch::aarch64::kernel_pmull,
}

#[cfg(all(any(target_arch = "powerpc", target_arch = "powerpc64"), feature = "simd"))]
kernel_trampolines! {
    kernel_altivec => arch::powerpc::kernel_altivec,
    kernel_vsx => arch::powerpc::kernel_vsx,
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), feature = "simd"))]
kernel_trampolines! {
    kernel_rvv => arch::riscv::kernel_rvv,
}

#[cfg(all(target_arch = "arm", feature = "simd"))]
kernel_trampolines! {
    kernel_neon32 => arch::arm32::kernel_neon,
}

/// Maps a crypto family to its kernel, or `None` where the target has none.
pub fn resolve_crypto_kernel(kernel: CryptoKernel) -> Option<KernelFn> {
    #[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "simd"))]
    {
        Some(match kernel {
            CryptoKernel::Aes => kernel_aes,
            CryptoKernel::Sha256 => kernel_sha256,
            CryptoKernel::CarrylessMultiply => kernel_carryless,
            #[cfg(target_arch = "x86_64")]
            CryptoKernel::VectorAes => kernel_vaes,
            #[cfg(target_arch = "x86_64")]
            CryptoKernel::VectorCarryless => kernel_vpclmul,
            // The YMM forms are x86's; AArch64's SVE2 crypto is not here.
            #[cfg(not(target_arch = "x86_64"))]
            CryptoKernel::VectorAes | CryptoKernel::VectorCarryless => return None,
        })
    }
    // Without `simd` (the soft-float stable build) the kernels are not
    // compiled at all.
    #[cfg(not(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "simd")))]
    {
        // 32-bit ARM and x86 Android ABIs reach here: the crypto extensions
        // exist on some devices but the kernels above are written against the
        // 64-bit register files.
        let _ = kernel;
        None
    }
}

/// Maps a backend to its kernel, defaulting to the portable scalar path.
pub fn resolve_kernel(backend: Backend) -> KernelFn {
    #[cfg(all(target_arch = "x86_64", not(feature = "simd")))]
    {
        let _ = backend;
        arch::x86::kernel_scalar
    }
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    {
        match backend {
            Backend::Mmx => kernel_mmx,
            Backend::Sse => kernel_sse,
            Backend::Sse2 => kernel_sse2,
            Backend::Sse3 => kernel_sse3,
            Backend::Ssse3 => kernel_ssse3,
            Backend::Sse41 => kernel_sse41,
            Backend::Sse42 => kernel_sse42,
            Backend::F16c => kernel_f16c,
            Backend::Fma => kernel_fma,
            Backend::Avx => kernel_avx,
            Backend::Avx2 => kernel_avx2,
            Backend::AvxVnni => kernel_avx_vnni,
            Backend::Avx512 => kernel_avx512,
            Backend::Avx512Vnni => kernel_avx512_vnni,
            _ => arch::x86::kernel_scalar,
        }
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "simd")))]
    {
        let _ = backend;
        arch::aarch64::kernel_scalar
    }
    #[cfg(all(target_arch = "aarch64", feature = "simd"))]
    {
        match backend {
            Backend::Neon | Backend::Sve | Backend::Sve2 | Backend::Sme => kernel_neon,
            _ => arch::aarch64::kernel_scalar,
        }
    }
    // 32-bit x86 has the counter layer but no SIMD kernels, so every backend
    // it reports as available resolves to the scalar baseline.
    #[cfg(target_arch = "x86")]
    {
        let _ = backend;
        arch::x86::kernel_scalar
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        match backend {
            #[cfg(feature = "simd")]
            Backend::Altivec => kernel_altivec,
            #[cfg(feature = "simd")]
            Backend::Vsx => kernel_vsx,
            _ => arch::powerpc::kernel_scalar,
        }
    }
    #[cfg(target_arch = "arm")]
    {
        match backend {
            #[cfg(feature = "simd")]
            Backend::Neon => kernel_neon32,
            _ => arch::arm32::kernel_scalar,
        }
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        match backend {
            #[cfg(feature = "simd")]
            Backend::Rvv => kernel_rvv,
            _ => arch::riscv::kernel_scalar,
        }
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
        let _ = backend;
        arch::generic::kernel_scalar
    }
}

