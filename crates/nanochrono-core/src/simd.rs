// SPDX-License-Identifier: Apache-2.0
//! Per-family SIMD probes with CPUID gating.
//!
//! Each [`SimdFamily`] maps to one set of inline-asm probes in [`crate::arch`].
//! The dispatchers here are the *only* way to reach them, and every dispatcher
//! checks [`SimdFamily::is_available`] first. An unavailable family returns
//! `None` rather than executing an instruction the CPU would fault on.

#[cfg(feature = "simd")]
use crate::arch;
use crate::cpu;

/// A SIMD instruction family with its own probe path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SimdFamily {
    Mmx = 0,
    Sse,
    Sse2,
    Sse3,
    Ssse3,
    Sse41,
    Sse42,
    F16c,
    Fma,
    Avx,
    Avx2,
    AvxVnni,
    Avx512,
    Avx512Vnni,
    Neon,
    Sve,
    Sve2,
    Sme,
    /// PowerPC VMX (AltiVec).
    Altivec,
    /// PowerPC VSX.
    Vsx,
    /// RISC-V vector extension.
    Rvv,
}

/// What a probe measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// A bare counter read on this family's path.
    Counter,
    /// One scalar 64-bit load.
    Load,
    /// One scalar 64-bit store.
    Store,
    /// One vector-width load.
    VectorLoad,
    /// One vector-width ALU operation.
    VectorXor,
    /// Back-to-back memory barriers.
    Barrier,
}

impl ProbeKind {
    pub const fn name(self) -> &'static str {
        match self {
            ProbeKind::Counter => "counter",
            ProbeKind::Load => "load",
            ProbeKind::Store => "store",
            ProbeKind::VectorLoad => "vector-load",
            ProbeKind::VectorXor => "vector-xor",
            ProbeKind::Barrier => "barrier",
        }
    }
}

/// One probe measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProbeResult {
    /// Raw counter units: TSC cycles on x86-64, `CNTVCT_EL0` ticks on AArch64.
    pub raw_units: u64,
    /// `raw_units` converted through the calibrated rate, when one was given.
    pub ns: u64,
    /// Bytes touched, for bandwidth figures.
    pub bytes: u64,
}

impl SimdFamily {
    pub const fn name(self) -> &'static str {
        match self {
            SimdFamily::Mmx => "mmx",
            SimdFamily::Sse => "sse",
            SimdFamily::Sse2 => "sse2",
            SimdFamily::Sse3 => "sse3",
            SimdFamily::Ssse3 => "ssse3",
            SimdFamily::Sse41 => "sse4.1",
            SimdFamily::Sse42 => "sse4.2",
            SimdFamily::F16c => "f16c",
            SimdFamily::Fma => "fma",
            SimdFamily::Avx => "avx",
            SimdFamily::Avx2 => "avx2",
            SimdFamily::AvxVnni => "avx-vnni",
            SimdFamily::Avx512 => "avx-512",
            SimdFamily::Avx512Vnni => "avx-512-vnni",
            SimdFamily::Neon => "neon",
            SimdFamily::Sve => "sve",
            SimdFamily::Sve2 => "sve2",
            SimdFamily::Sme => "sme",
            SimdFamily::Altivec => "altivec",
            SimdFamily::Vsx => "vsx",
            SimdFamily::Rvv => "rvv",
        }
    }

    /// Vector width in bytes, which sets the minimum buffer a probe needs.
    ///
    /// SVE is vector-length agnostic; 16 is its architectural floor, and the
    /// probes pass the real byte count to `whilelo` so wider implementations
    /// use their full width.
    pub const fn vector_bytes(self) -> usize {
        match self {
            SimdFamily::Mmx => 8,
            SimdFamily::Sse
            | SimdFamily::Sse2
            | SimdFamily::Sse3
            | SimdFamily::Ssse3
            | SimdFamily::Sse41
            | SimdFamily::Sse42
            | SimdFamily::F16c
            | SimdFamily::Neon => 16,
            SimdFamily::Fma | SimdFamily::Avx | SimdFamily::Avx2 | SimdFamily::AvxVnni => 32,
            SimdFamily::Avx512 | SimdFamily::Avx512Vnni => 64,
            SimdFamily::Sve | SimdFamily::Sve2 | SimdFamily::Sme => 16,
            SimdFamily::Altivec | SimdFamily::Vsx | SimdFamily::Rvv => 16,
        }
    }

    /// Whether this CPU can execute the family *and* this build can probe it.
    ///
    /// 32-bit x86 has the probes too; only the timer *kernels* are x86-64 only
    /// (see [`crate::backend::Backend::has_kernel`]).
    pub fn is_available(self) -> bool {
        let f = cpu::features();
        match self {
            SimdFamily::Mmx => f.mmx,
            SimdFamily::Sse => f.sse,
            SimdFamily::Sse2 => f.sse2,
            SimdFamily::Sse3 => f.sse3,
            SimdFamily::Ssse3 => f.ssse3,
            SimdFamily::Sse41 => f.sse41,
            SimdFamily::Sse42 => f.sse42,
            SimdFamily::F16c => f.f16c,
            SimdFamily::Fma => f.fma,
            SimdFamily::Avx => f.avx,
            SimdFamily::Avx2 => f.avx2,
            SimdFamily::AvxVnni => f.avx_vnni,
            SimdFamily::Avx512 => f.avx512f,
            SimdFamily::Avx512Vnni => f.avx512vnni,
            SimdFamily::Neon => f.neon,
            SimdFamily::Sve => f.sve,
            SimdFamily::Sve2 => f.sve2,
            SimdFamily::Sme => f.sme,
            SimdFamily::Altivec => f.altivec,
            SimdFamily::Vsx => f.vsx,
            SimdFamily::Rvv => f.rvv,
        }
    }

    /// Every family, in enum order.
    /// Whether the family belongs to the architecture this was built for —
    /// separate from [`is_available`](Self::is_available), which asks whether
    /// this CPU has it. SVE on a Snapdragon is native but unavailable; AVX on
    /// it is neither, and a list that shows it as "no" is only noise.
    pub const fn is_native(self) -> bool {
        match self {
            SimdFamily::Neon => cfg!(any(target_arch = "aarch64", target_arch = "arm")),
            SimdFamily::Sve | SimdFamily::Sve2 | SimdFamily::Sme => cfg!(target_arch = "aarch64"),
            SimdFamily::Altivec | SimdFamily::Vsx => {
                cfg!(any(target_arch = "powerpc", target_arch = "powerpc64"))
            }
            SimdFamily::Rvv => cfg!(any(target_arch = "riscv32", target_arch = "riscv64")),
            _ => cfg!(any(target_arch = "x86", target_arch = "x86_64")),
        }
    }

    pub const ALL: &'static [SimdFamily] = &[
        SimdFamily::Mmx,
        SimdFamily::Sse,
        SimdFamily::Sse2,
        SimdFamily::Sse3,
        SimdFamily::Ssse3,
        SimdFamily::Sse41,
        SimdFamily::Sse42,
        SimdFamily::F16c,
        SimdFamily::Fma,
        SimdFamily::Avx,
        SimdFamily::Avx2,
        SimdFamily::AvxVnni,
        SimdFamily::Avx512,
        SimdFamily::Avx512Vnni,
        SimdFamily::Neon,
        SimdFamily::Sve,
        SimdFamily::Sve2,
        SimdFamily::Sme,
        SimdFamily::Altivec,
        SimdFamily::Vsx,
        SimdFamily::Rvv,
    ];

    /// Families this machine can actually run.
    #[cfg(feature = "std")]
    pub fn available() -> Vec<SimdFamily> {
        Self::ALL
            .iter()
            .copied()
            .filter(|f| f.is_available())
            .collect()
    }

    /// Widest available family, or `None` on a target with no SIMD.
    pub fn best() -> Option<SimdFamily> {
        const X86_ORDER: &[SimdFamily] = &[
            SimdFamily::Avx512Vnni,
            SimdFamily::Avx512,
            SimdFamily::AvxVnni,
            SimdFamily::Avx2,
            SimdFamily::Avx,
            SimdFamily::Fma,
            SimdFamily::F16c,
            SimdFamily::Sse42,
            SimdFamily::Sse41,
            SimdFamily::Ssse3,
            SimdFamily::Sse3,
            SimdFamily::Sse2,
            SimdFamily::Sse,
            SimdFamily::Mmx,
        ];
        const ARM_ORDER: &[SimdFamily] = &[
            SimdFamily::Sme,
            SimdFamily::Sve2,
            SimdFamily::Sve,
            SimdFamily::Neon,
        ];
        const PPC_ORDER: &[SimdFamily] = &[SimdFamily::Vsx, SimdFamily::Altivec];
        const RISCV_ORDER: &[SimdFamily] = &[SimdFamily::Rvv];
        const ARM32_ORDER: &[SimdFamily] = &[SimdFamily::Neon];
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
        order.iter().copied().find(|f| f.is_available())
    }
}

impl core::fmt::Display for SimdFamily {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Buffers a probe reads from and writes to.
///
/// Holding these as slices rather than raw pointers is what lets the probe
/// dispatchers be safe functions: length is checked against
/// [`SimdFamily::vector_bytes`] before any inline asm runs.
#[derive(Debug)]
pub struct ProbeBuffers<'a> {
    pub a: &'a [u8],
    pub b: &'a [u8],
    pub out: &'a mut [u8],
}

/// Runs one probe, or returns `None` if the family is unavailable or the
/// buffers are too small for its vector width.
///
/// Needs the `simd` feature, which is on by default. Without it the probes
/// are not compiled — a freestanding x86 target has a soft-float ABI where no
/// vector register can be allocated — and only the [`SimdFamily`] description
/// remains.
#[cfg(feature = "simd")]
pub fn probe(
    family: SimdFamily,
    kind: ProbeKind,
    buffers: Option<ProbeBuffers<'_>>,
    iterations: u32,
) -> Option<ProbeResult> {
    if !family.is_available() {
        return None;
    }

    let width = family.vector_bytes();
    let raw_units = match kind {
        ProbeKind::Counter => counter(family),
        ProbeKind::Barrier => barrier(family, iterations),
        ProbeKind::Load | ProbeKind::Store | ProbeKind::VectorLoad | ProbeKind::VectorXor => {
            let bufs = buffers?;
            if bufs.a.len() < width || bufs.b.len() < width || bufs.out.len() < width {
                return None;
            }
            match kind {
                // SAFETY: the length check above guarantees each pointer has at
                // least one vector width of accessible bytes, and the
                // `is_available` gate guarantees the ISA extension.
                ProbeKind::Load => unsafe { scalar_load(bufs.a.as_ptr()) },
                ProbeKind::Store => unsafe { scalar_store(bufs.out.as_mut_ptr()) },
                ProbeKind::VectorLoad => unsafe { vector_load(family, bufs.a.as_ptr()) },
                ProbeKind::VectorXor => unsafe {
                    vector_xor(
                        family,
                        bufs.a.as_ptr(),
                        bufs.b.as_ptr(),
                        bufs.out.as_mut_ptr(),
                    )
                },
                _ => unreachable!("outer match restricts the kind"),
            }
        }
    };

    let bytes = match kind {
        ProbeKind::VectorLoad => width as u64,
        ProbeKind::VectorXor => (width * 3) as u64,
        ProbeKind::Load | ProbeKind::Store => 8,
        _ => 0,
    };

    Some(ProbeResult {
        raw_units,
        ns: 0,
        bytes,
    })
}

#[cfg(feature = "simd")]
fn counter(family: SimdFamily) -> u64 {
    let _ = family;
    arch::counter_start()
}

#[cfg(feature = "simd")]
fn barrier(family: SimdFamily, iterations: u32) -> u64 {
    let _ = family;
    arch::barrier_overhead(iterations)
}

/// # Safety
/// `ptr` must have 8 readable, suitably aligned bytes.
#[cfg(feature = "simd")]
unsafe fn scalar_load(ptr: *const u8) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        unsafe { arch::x86::probe_load_cycles(ptr as *const u64) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { arch::aarch64::probe_load_ticks(ptr as *const u64) }
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        // `ptr` is only guaranteed byte-aligned and the probe reads a whole
        // `u64`, so an unaligned buffer falls back to the unaligned read.
        if (ptr as usize) % core::mem::align_of::<u64>() == 0 {
            unsafe { arch::powerpc::probe_load_ticks(ptr as *const u64) }
        } else {
            let a = arch::counter_start();
            core::hint::black_box(unsafe { core::ptr::read_unaligned(ptr as *const u64) });
            arch::counter_end().wrapping_sub(a)
        }
    }
    #[cfg(target_arch = "arm")]
    {
        if (ptr as usize) % core::mem::align_of::<u64>() == 0 {
            unsafe { arch::arm32::probe_load(ptr as *const u64) }
        } else {
            let a = arch::counter_start();
            core::hint::black_box(unsafe { core::ptr::read_unaligned(ptr as *const u64) });
            arch::counter_end().wrapping_sub(a)
        }
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        if (ptr as usize) % core::mem::align_of::<u64>() == 0 {
            unsafe { arch::riscv::probe_load_ticks(ptr as *const u64) }
        } else {
            let a = arch::counter_start();
            core::hint::black_box(unsafe { core::ptr::read_unaligned(ptr as *const u64) });
            arch::counter_end().wrapping_sub(a)
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
        let a = arch::counter_start();
        core::hint::black_box(unsafe { core::ptr::read_unaligned(ptr as *const u64) });
        arch::counter_end().wrapping_sub(a)
    }
}

/// # Safety
/// `ptr` must have 8 writable, suitably aligned bytes.
#[cfg(feature = "simd")]
unsafe fn scalar_store(ptr: *mut u8) -> u64 {
    const PATTERN: u64 = 0x5A5A_5A5A_5A5A_5A5A;
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        unsafe { arch::x86::probe_store_cycles(ptr as *mut u64, PATTERN) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { arch::aarch64::probe_store_ticks(ptr as *mut u64, PATTERN) }
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        if (ptr as usize) % core::mem::align_of::<u64>() == 0 {
            unsafe { arch::powerpc::probe_store_ticks(ptr as *mut u64, PATTERN) }
        } else {
            let a = arch::counter_start();
            unsafe { core::ptr::write_unaligned(ptr as *mut u64, PATTERN) };
            arch::counter_end().wrapping_sub(a)
        }
    }
    #[cfg(target_arch = "arm")]
    {
        let a = arch::counter_start();
        unsafe { core::ptr::write_unaligned(ptr as *mut u64, PATTERN) };
        arch::memory_barrier();
        arch::counter_end().wrapping_sub(a)
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        if (ptr as usize) % core::mem::align_of::<u64>() == 0 {
            unsafe { arch::riscv::probe_store_ticks(ptr as *mut u64, PATTERN) }
        } else {
            let a = arch::counter_start();
            unsafe { core::ptr::write_unaligned(ptr as *mut u64, PATTERN) };
            arch::counter_end().wrapping_sub(a)
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
        let a = arch::counter_start();
        unsafe { core::ptr::write_unaligned(ptr as *mut u64, PATTERN) };
        arch::counter_end().wrapping_sub(a)
    }
}

/// # Safety
/// `family` must be available and `ptr` must have `family.vector_bytes()`
/// readable bytes.
#[cfg(feature = "simd")]
unsafe fn vector_load(family: SimdFamily, ptr: *const u8) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    unsafe {
        use arch::x86 as a;
        match family {
            SimdFamily::Mmx => a::mmx::vector_load_cycles(ptr),
            SimdFamily::Sse => a::sse::vector_load_cycles(ptr),
            SimdFamily::Sse2 => a::sse2::vector_load_cycles(ptr),
            SimdFamily::Sse3 => a::sse3::vector_load_cycles(ptr),
            SimdFamily::Ssse3 => a::ssse3::vector_load_cycles(ptr),
            SimdFamily::Sse41 => a::sse41::vector_load_cycles(ptr),
            SimdFamily::Sse42 => a::sse42::vector_load_cycles(ptr),
            SimdFamily::F16c => a::f16c::vector_load_cycles(ptr),
            SimdFamily::Fma => a::fma::vector_load_cycles(ptr),
            SimdFamily::Avx => a::avx::vector_load_cycles(ptr),
            SimdFamily::Avx2 => a::avx2::vector_load_cycles(ptr),
            SimdFamily::AvxVnni => a::avx_vnni::vector_load_cycles(ptr),
            SimdFamily::Avx512 => a::avx512::vector_load_cycles(ptr),
            SimdFamily::Avx512Vnni => a::avx512_vnni::vector_load_cycles(ptr),
            _ => scalar_load(ptr),
        }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        use arch::aarch64 as a;
        match family {
            SimdFamily::Neon => a::neon::vector_load_ticks(ptr),
            SimdFamily::Sve | SimdFamily::Sve2 => a::sve::vector_load_ticks(ptr, family.vector_bytes()),
            // SME does not imply SVE: a part can have the streaming matrix
            // unit and no non-streaming SVE at all (Apple's M4 is one), and on
            // it every SVE instruction outside streaming mode is illegal. The
            // SME family is timed on the SVE path only when SVE exists too.
            SimdFamily::Sme if cpu::features().sve => {
                a::sve::vector_load_ticks(ptr, family.vector_bytes())
            }
            SimdFamily::Sme => a::neon::vector_load_ticks(ptr),
            _ => scalar_load(ptr),
        }
    }
    #[cfg(target_arch = "arm")]
    unsafe {
        match family {
            SimdFamily::Neon => arch::arm32::neon::vector_load_units(ptr),
            _ => scalar_load(ptr),
        }
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        match family {
            SimdFamily::Rvv => arch::riscv::rvv::vector_load_ticks(ptr),
            _ => scalar_load(ptr),
        }
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    unsafe {
        use arch::powerpc as p;
        match family {
            SimdFamily::Altivec => p::altivec::vector_load_ticks(ptr),
            SimdFamily::Vsx => p::vsx::vector_load_ticks(ptr),
            _ => scalar_load(ptr),
        }
    }
    // Targets with no vector probes of their own reach here. They report no
    // SIMD family as available, so this arm is unreachable in practice and
    // exists to keep the match total.
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
    unsafe {
        let _ = family;
        scalar_load(ptr)
    }
}

/// # Safety
/// `family` must be available; `a`/`b` must have `family.vector_bytes()`
/// readable bytes and `out` that many writable bytes.
#[cfg(feature = "simd")]
unsafe fn vector_xor(family: SimdFamily, a: *const u8, b: *const u8, out: *mut u8) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    unsafe {
        use arch::x86 as x;
        match family {
            SimdFamily::Mmx => x::mmx::vector_xor_cycles(a, b, out),
            SimdFamily::Sse => x::sse::vector_xor_cycles(a, b, out),
            SimdFamily::Sse2 => x::sse2::vector_xor_cycles(a, b, out),
            SimdFamily::Sse3 => x::sse3::vector_xor_cycles(a, b, out),
            SimdFamily::Ssse3 => x::ssse3::vector_xor_cycles(a, b, out),
            SimdFamily::Sse41 => x::sse41::vector_xor_cycles(a, b, out),
            SimdFamily::Sse42 => x::sse42::vector_xor_cycles(a, b, out),
            SimdFamily::F16c => x::f16c::vector_xor_cycles(a, b, out),
            SimdFamily::Fma => x::fma::vector_xor_cycles(a, b, out),
            SimdFamily::Avx => x::avx::vector_xor_cycles(a, b, out),
            SimdFamily::Avx2 => x::avx2::vector_xor_cycles(a, b, out),
            SimdFamily::AvxVnni => x::avx_vnni::vector_xor_cycles(a, b, out),
            SimdFamily::Avx512 => x::avx512::vector_xor_cycles(a, b, out),
            SimdFamily::Avx512Vnni => x::avx512_vnni::vector_xor_cycles(a, b, out),
            _ => scalar_load(a),
        }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        use arch::aarch64 as x;
        match family {
            SimdFamily::Neon => x::neon::vector_xor_ticks(a, b, out),
            SimdFamily::Sve | SimdFamily::Sve2 => {
                x::sve::vector_xor_ticks(a, b, out, family.vector_bytes())
            }
            // See `vector_load`: SME without SVE takes the NEON path.
            SimdFamily::Sme if cpu::features().sve => {
                x::sve::vector_xor_ticks(a, b, out, family.vector_bytes())
            }
            SimdFamily::Sme => x::neon::vector_xor_ticks(a, b, out),
            _ => scalar_load(a),
        }
    }
    #[cfg(target_arch = "arm")]
    unsafe {
        match family {
            SimdFamily::Neon => arch::arm32::neon::vector_xor_units(a, b, out),
            _ => scalar_load(a),
        }
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        match family {
            SimdFamily::Rvv => arch::riscv::rvv::vector_xor_ticks(a, b, out),
            _ => scalar_load(a),
        }
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    unsafe {
        use arch::powerpc as p;
        match family {
            SimdFamily::Altivec => p::altivec::vector_xor_ticks(a, b, out),
            SimdFamily::Vsx => p::vsx::vector_xor_ticks(a, b, out),
            _ => scalar_load(a),
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
    unsafe {
        let _ = (family, b, out);
        scalar_load(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_families_return_none() {
        for family in SimdFamily::ALL.iter().copied() {
            let result = probe(family, ProbeKind::Counter, None, 0);
            assert_eq!(
                result.is_some(),
                family.is_available(),
                "{family} probe availability disagrees with CPUID"
            );
        }
    }

    #[test]
    fn undersized_buffers_are_rejected() {
        let Some(family) = SimdFamily::best() else {
            return;
        };
        let a = vec![0u8; 4];
        let b = vec![0u8; 4];
        let mut out = vec![0u8; 4];
        let bufs = ProbeBuffers {
            a: &a,
            b: &b,
            out: &mut out,
        };
        assert!(probe(family, ProbeKind::VectorXor, Some(bufs), 0).is_none());
    }

    #[test]
    fn vector_xor_runs_on_every_available_family() {
        for family in SimdFamily::available() {
            // Named before the probe runs: if a family faults, the last line
            // printed is the one that did it.
            eprintln!("probing {family}");
            let width = family.vector_bytes();
            let a = vec![0xA5u8; width];
            let b = vec![0x5Au8; width];
            let mut out = vec![0u8; width];
            let bufs = ProbeBuffers {
                a: &a,
                b: &b,
                out: &mut out,
            };
            let r = probe(family, ProbeKind::VectorXor, Some(bufs), 0);
            assert!(r.is_some(), "{family} reported available but did not run");
        }
    }
}
