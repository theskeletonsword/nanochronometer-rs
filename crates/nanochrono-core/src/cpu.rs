// SPDX-License-Identifier: Apache-2.0
//! CPU feature detection.
//!
//! Every ISA extension this crate can execute must pass through here first.
//! On x86-64 that means both a CPUID bit *and* an XCR0 check: a CPU can report
//! AVX-512 while the OS has not enabled ZMM state, and executing a ZMM
//! instruction in that situation is `#UD`, not a slow path.

#[cfg(feature = "std")]
use std::sync::OnceLock;

/// One flag per ISA extension the toolkit can dispatch to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuFeatures {
    pub mmx: bool,
    pub sse: bool,
    pub sse2: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse41: bool,
    pub sse42: bool,
    pub aesni: bool,
    pub pclmulqdq: bool,
    pub shani: bool,
    pub avx: bool,
    pub f16c: bool,
    pub fma: bool,
    pub avx2: bool,
    pub avx_vnni: bool,
    pub vaes: bool,
    /// `VPCLMULQDQ`: carry-less multiply on YMM/ZMM lanes (CPUID.7:ECX[10]).
    pub vpclmulqdq: bool,
    pub avx512f: bool,
    pub avx512bw: bool,
    pub avx512vl: bool,
    pub avx512vnni: bool,
    pub neon: bool,
    pub sve: bool,
    pub sve2: bool,
    pub sme: bool,
    pub arm_aes: bool,
    pub arm_sha2: bool,
    /// PowerPC VMX, the vector unit Apple and Motorola called AltiVec.
    pub altivec: bool,
    /// PowerPC Vector-Scalar Extension (ISA 2.06, POWER7 onward).
    pub vsx: bool,
    /// ISA 2.07 (POWER8): the VSX integer and crypto additions.
    pub ppc_isa207: bool,
    /// ISA 3.0 (POWER9).
    pub ppc_isa300: bool,
    /// ISA 3.1 (POWER10).
    pub ppc_isa31: bool,
    /// The in-core AES/SHA vector crypto instructions (`vcipher`, `vshasigma`).
    pub ppc_vec_crypto: bool,
    /// RISC-V "V" vector extension (RVV 1.0), enabled for this process.
    pub rvv: bool,
    /// True when the TSC is invariant, i.e. immune to frequency and C-state
    /// changes. Without this, cycle deltas across a long interval are not
    /// comparable to wall time.
    pub invariant_counter: bool,
}

/// Detected features for this machine, computed once.
///
/// Returned by value rather than by reference: the struct is a few dozen
/// bools and `Copy`, and a freestanding build has no `OnceLock` to hand out a
/// `&'static` from — `OnceLock` needs a blocking primitive the OS provides.
#[cfg(feature = "std")]
pub fn features() -> CpuFeatures {
    static CACHE: OnceLock<CpuFeatures> = OnceLock::new();
    *CACHE.get_or_init(detect)
}

/// Detects the feature set, without caching.
///
/// Detection is pure CPUID (or pure `MRS`) and costs a few dozen cycles, so
/// re-running it is cheaper than the synchronisation a cache would need — and
/// a bare-metal caller that wants it hot can hold the result itself, which
/// `nanochrono-baremetal` does.
#[cfg(not(feature = "std"))]
pub fn features() -> CpuFeatures {
    detect()
}

fn detect() -> CpuFeatures {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        detect_x86()
    }
    #[cfg(target_arch = "aarch64")]
    {
        detect_aarch64()
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        detect_powerpc()
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        detect_riscv()
    }
    #[cfg(target_arch = "arm")]
    {
        detect_arm32()
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
        CpuFeatures::default()
    }
}

/// RISC-V: Linux publishes the single-letter extensions as `AT_HWCAP` bit
/// `letter - 'a'` (FreeBSD's `HWCAP_ISA_BIT` is the same encoding), and sets
/// `v` only when the kernel will enable vector state for the process.
#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), feature = "std"))]
fn detect_riscv() -> CpuFeatures {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: `getauxval` has no preconditions.
    let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) } as u64;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let hwcap = 0u64;
    CpuFeatures {
        rvv: hwcap & (1 << (b'v' - b'a')) != 0,
        // `time` ticks at the platform's fixed timebase.
        invariant_counter: true,
        ..Default::default()
    }
}

/// 32-bit ARM: NEON from `AT_HWCAP` — the kernel's word on whether the unit
/// exists *and* is enabled for user space. Android's bionic provides the same
/// `getauxval`.
#[cfg(target_arch = "arm")]
fn detect_arm32() -> CpuFeatures {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: `getauxval` has no preconditions.
    let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) } as u64;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let hwcap = 0u64;
    CpuFeatures {
        neon: hwcap & crate::arch::arm32::HWCAP_NEON != 0,
        // The generic timer is fixed-rate; the fallback is the monotonic
        // clock. Both are invariant.
        invariant_counter: true,
        ..Default::default()
    }
}

/// RISC-V with no OS: S-mode cannot read `misa`, so the kernel passes on
/// what the device tree's `riscv,isa` said.
#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), not(feature = "std")))]
fn detect_riscv() -> CpuFeatures {
    CpuFeatures {
        rvv: crate::arch::riscv::vector_available(),
        invariant_counter: true,
        ..Default::default()
    }
}

/// `AT_HWCAP` bits, from the kernel's `asm/cputable.h` (the same values
/// FreeBSD publishes in `machine/cpu.h`).
#[cfg(all(any(target_arch = "powerpc", target_arch = "powerpc64"), any(feature = "std", test)))]
mod ppc_hwcap {
    pub const HAS_ALTIVEC: u64 = 0x1000_0000;
    pub const HAS_VSX: u64 = 0x0000_0080;
    /// `AT_HWCAP2`.
    pub const ARCH_2_07: u64 = 0x8000_0000;
    pub const HAS_VEC_CRYPTO: u64 = 0x0200_0000;
    pub const ARCH_3_00: u64 = 0x0080_0000;
    pub const ARCH_3_1: u64 = 0x0004_0000;
}

/// PowerPC feature detection on Linux: the auxiliary vector.
///
/// The kernel is the only party that knows whether it will *allow* the vector
/// unit — it enables `MSR[VEC]`/`MSR[VSX]` lazily on first use and would
/// refuse on a part without one — so HWCAP is the authority, exactly as it is
/// for AArch64.
#[cfg(all(any(target_arch = "powerpc", target_arch = "powerpc64"), feature = "std"))]
fn detect_powerpc() -> CpuFeatures {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: `getauxval` reads this process's auxiliary vector and returns 0
    // for an unknown key; it has no preconditions.
    let (hwcap, hwcap2) = unsafe {
        (
            libc::getauxval(libc::AT_HWCAP) as u64,
            libc::getauxval(libc::AT_HWCAP2) as u64,
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let (hwcap, hwcap2) = (0u64, 0u64);
    from_ppc_hwcap(hwcap, hwcap2)
}

/// Decodes HWCAP/HWCAP2 into features. Split out so it is testable anywhere.
#[cfg(all(any(target_arch = "powerpc", target_arch = "powerpc64"), any(feature = "std", test)))]
fn from_ppc_hwcap(hwcap: u64, hwcap2: u64) -> CpuFeatures {
    use ppc_hwcap::*;
    let altivec = hwcap & HAS_ALTIVEC != 0;
    // VSX extends the AltiVec register file; a kernel reporting one without
    // the other is not something to dispatch on.
    let vsx = altivec && hwcap & HAS_VSX != 0;
    CpuFeatures {
        altivec,
        vsx,
        ppc_isa207: hwcap2 & ARCH_2_07 != 0,
        ppc_isa300: hwcap2 & ARCH_3_00 != 0,
        ppc_isa31: hwcap2 & ARCH_3_1 != 0,
        ppc_vec_crypto: vsx && hwcap2 & HAS_VEC_CRYPTO != 0,
        // The Time Base runs at a fixed rate by architecture.
        invariant_counter: true,
        ..Default::default()
    }
}

/// PowerPC feature detection with no OS: the Processor Version Register.
///
/// A freestanding kernel runs in supervisor state, where `mfpvr` is legal. The
/// version half (bits 0:15) identifies the core family; the table is the
/// published PVR list (FreeBSD's `machine/spr.h` carries the same values).
/// The boot stub is what turns `MSR[VEC]`/`MSR[VSX]` on, and it does so only
/// on a family this table says has the unit — so reporting a feature here and
/// the MSR bit being set are the same decision.
#[cfg(all(any(target_arch = "powerpc", target_arch = "powerpc64"), not(feature = "std")))]
fn detect_powerpc() -> CpuFeatures {
    let pvr: usize;
    // SAFETY: supervisor state, which is the only configuration a `no_std`
    // build of this crate runs in; the read has no side effects.
    unsafe {
        core::arch::asm!("mfpvr {v}", v = out(reg) pvr, options(nomem, nostack, preserves_flags));
    }
    from_pvr(pvr as u32)
}

/// Features implied by a PVR. Unknown parts get none: guessing wrong is an
/// illegal-instruction exception, guessing low is a slower probe.
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
pub fn from_pvr(pvr: u32) -> CpuFeatures {
    let version = (pvr >> 16) as u16;
    // (altivec, vsx, isa 2.07, isa 3.0, isa 3.1)
    let (altivec, vsx, isa207, isa300, isa31) = match version {
        // 7400/7410, 745x/744x: G4.
        0x000C | 0x800C | 0x8000..=0x8004 => (true, false, false, false, false),
        // 970, 970FX, 970MP, 970GX: G5.
        0x0039 | 0x003C | 0x0044 | 0x0045 => (true, false, false, false, false),
        // Cell PPE, POWER6.
        0x0070 | 0x003E => (true, false, false, false, false),
        // POWER7, POWER7+.
        0x003F | 0x004A => (true, true, false, false, false),
        // POWER8E, POWER8NVL, POWER8.
        0x004B..=0x004D => (true, true, true, false, false),
        // POWER9.
        0x004E => (true, true, true, true, false),
        // POWER10, POWER11.
        0x0080 | 0x0082 => (true, true, true, true, true),
        // e6500: 64-bit Book E with AltiVec.
        0x8040 => (true, false, false, false, false),
        _ => (false, false, false, false, false),
    };
    CpuFeatures {
        altivec,
        vsx,
        ppc_isa207: isa207,
        ppc_isa300: isa300,
        ppc_isa31: isa31,
        ppc_vec_crypto: isa207,
        invariant_counter: true,
        ..Default::default()
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn detect_x86() -> CpuFeatures {
    use crate::arch::x86::{cpuid, cpuid_max_leaf, xcr0_safe};

    let mut f = CpuFeatures::default();
    let max_leaf = cpuid_max_leaf();
    if max_leaf < 1 {
        return f;
    }

    let r1 = cpuid(1, 0);
    let (ecx1, edx1) = (r1[2], r1[3]);

    // XCR0 gates every register file wider than XMM. Bits 1|2 are SSE|AVX
    // state; bits 5|6|7 add opmask, ZMM_hi256 and Hi16_ZMM for AVX-512.
    let xcr0 = xcr0_safe();
    let os_ymm = xcr0 & 0x6 == 0x6;
    let os_zmm = xcr0 & 0xE6 == 0xE6;

    f.mmx = edx1 & (1 << 23) != 0;
    f.sse = edx1 & (1 << 25) != 0;
    f.sse2 = edx1 & (1 << 26) != 0;
    f.sse3 = ecx1 & 1 != 0;
    f.pclmulqdq = ecx1 & (1 << 1) != 0;
    f.ssse3 = ecx1 & (1 << 9) != 0;
    f.fma = ecx1 & (1 << 12) != 0 && os_ymm;
    f.sse41 = ecx1 & (1 << 19) != 0;
    f.sse42 = ecx1 & (1 << 20) != 0;
    f.aesni = ecx1 & (1 << 25) != 0;
    f.avx = ecx1 & (1 << 28) != 0 && os_ymm;
    f.f16c = ecx1 & (1 << 29) != 0 && os_ymm;

    if max_leaf >= 7 {
        let r7 = cpuid(7, 0);
        let (max_sub7, ebx7, ecx7) = (r7[0], r7[1], r7[2]);
        f.avx2 = ebx7 & (1 << 5) != 0 && os_ymm;
        f.shani = ebx7 & (1 << 29) != 0;
        f.avx512f = ebx7 & (1 << 16) != 0 && os_zmm;
        f.avx512bw = ebx7 & (1 << 30) != 0 && os_zmm;
        f.avx512vl = ebx7 & (1 << 31) != 0 && os_zmm;
        f.vaes = ecx7 & (1 << 9) != 0 && os_ymm;
        f.vpclmulqdq = ecx7 & (1 << 10) != 0 && os_ymm;
        f.avx512vnni = ecx7 & (1 << 11) != 0 && os_zmm;

        if max_sub7 >= 1 {
            let r71 = cpuid(7, 1);
            f.avx_vnni = r71[0] & (1 << 4) != 0 && os_ymm && f.avx2;
        }
    }

    // CPUID.80000007H:EDX[8] — invariant TSC.
    let ext_max = cpuid(0x8000_0000, 0)[0];
    if ext_max >= 0x8000_0007 {
        f.invariant_counter = cpuid(0x8000_0007, 0)[3] & (1 << 8) != 0;
    }

    #[cfg(target_os = "windows")]
    cross_check_with_windows(&mut f);

    f
}

/// Cross-checks CPUID against `IsProcessorFeaturePresent`.
///
/// Windows is the one platform that publishes its own view of the CPU's
/// features, and it is the *authoritative* one: the OS must have enabled the
/// register state before an instruction is legal, and `IsProcessorFeaturePresent`
/// answers "may this process use it" where CPUID only answers "does the
/// silicon have it". Under a hypervisor that hides a feature from the guest,
/// or on a Windows build that has not enabled AVX state, CPUID can say yes
/// where Windows says no.
///
/// So the two are ANDed: a feature is reported only when both agree. That can
/// only ever remove a feature, never add one, which is the safe direction for
/// something that gates instruction dispatch.
#[cfg(all(
    target_os = "windows",
    any(target_arch = "x86_64", target_arch = "x86")
))]
fn cross_check_with_windows(f: &mut CpuFeatures) {
    use windows_sys::Win32::System::Threading::{
        IsProcessorFeaturePresent, PF_AVX2_INSTRUCTIONS_AVAILABLE,
        PF_AVX512F_INSTRUCTIONS_AVAILABLE, PF_AVX_INSTRUCTIONS_AVAILABLE,
        PF_SSE3_INSTRUCTIONS_AVAILABLE, PF_XMMI64_INSTRUCTIONS_AVAILABLE,
        PF_XMMI_INSTRUCTIONS_AVAILABLE,
    };

    // SAFETY: the function takes a feature constant and has no preconditions.
    let present = |feature| unsafe { IsProcessorFeaturePresent(feature) != 0 };

    f.sse &= present(PF_XMMI_INSTRUCTIONS_AVAILABLE);
    f.sse2 &= present(PF_XMMI64_INSTRUCTIONS_AVAILABLE);
    f.sse3 &= present(PF_SSE3_INSTRUCTIONS_AVAILABLE);
    f.avx &= present(PF_AVX_INSTRUCTIONS_AVAILABLE);
    f.avx2 &= present(PF_AVX2_INSTRUCTIONS_AVAILABLE);

    // Windows gates every AVX-512 subset behind the one AVX-512F flag.
    let avx512 = present(PF_AVX512F_INSTRUCTIONS_AVAILABLE);
    f.avx512f &= avx512;
    f.avx512bw &= avx512;
    f.avx512vl &= avx512;
    f.avx512vnni &= avx512;

    // Features that depend on AVX register state cannot outlive it.
    if !f.avx {
        f.f16c = false;
        f.fma = false;
        f.avx_vnni = false;
        f.vaes = false;
        f.vpclmulqdq = false;
    }
}

/// Windows on AArch64 exposes the NEON and crypto flags the same way.
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
fn cross_check_with_windows(f: &mut CpuFeatures) {
    use windows_sys::Win32::System::Threading::{
        IsProcessorFeaturePresent, PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE,
        PF_ARM_VFP_32_REGISTERS_AVAILABLE,
    };

    // SAFETY: the function takes a feature constant and has no preconditions.
    let present = |feature| unsafe { IsProcessorFeaturePresent(feature) != 0 };

    f.neon &= present(PF_ARM_VFP_32_REGISTERS_AVAILABLE);
    let crypto = present(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);
    f.arm_aes &= crypto;
    f.arm_sha2 &= crypto;
}

#[cfg(target_arch = "aarch64")]
/// AArch64 feature detection without an OS, by reading the ID registers.
///
/// `is_aarch64_feature_detected!` lives in `std::arch` because it has to ask
/// the OS: at EL0 the ID registers trap, so a hosted process cannot read them
/// and must go through HWCAP or a sysctl. A freestanding kernel runs at EL1,
/// where they are simply readable — the one place this is the *easier* path
/// rather than the forbidden one.
///
/// Field positions are from the kernel's `arch/arm64/tools/sysreg` table,
/// which is generated from the ARM ARM.
#[cfg(all(target_arch = "aarch64", not(feature = "std")))]
fn detect_aarch64() -> CpuFeatures {
    /// Extracts a 4-bit ID register field.
    fn field(reg: u64, shift: u32) -> u64 {
        (reg >> shift) & 0xF
    }

    let isar0: u64;
    let pfr0: u64;
    let pfr1: u64;
    // SAFETY: at EL1 these are readable with no trap and no side effects. A
    // freestanding build is the only configuration this function compiles in.
    unsafe {
        core::arch::asm!("mrs {v}, ID_AA64ISAR0_EL1", v = out(reg) isar0,
                         options(nomem, nostack, preserves_flags));
        core::arch::asm!("mrs {v}, ID_AA64PFR0_EL1", v = out(reg) pfr0,
                         options(nomem, nostack, preserves_flags));
        core::arch::asm!("mrs {v}, ID_AA64PFR1_EL1", v = out(reg) pfr1,
                         options(nomem, nostack, preserves_flags));
    }

    // ID_AA64ISAR0_EL1.AES: 0b0001 = AES, 0b0010 = AES + PMULL.
    let aes = field(isar0, 4);
    let sve = field(pfr0, 32) >= 1;

    // ID_AA64ZFR0_EL1 is only architecturally valid when SVE is implemented;
    // reading it otherwise is UNDEFINED, so it is gated on that.
    let sve2 = sve && {
        let zfr0: u64;
        // Named by its raw encoding, `S3_0_C0_C4_4`: the assembler only
        // accepts the mnemonic `ID_AA64ZFR0_EL1` when built with `+sve`, and
        // the base freestanding target is not. The numbers are op0=3, op1=0,
        // CRn=0, CRm=4, op2=4, from the kernel's `arch/arm64/tools/sysreg`
        // table.
        //
        // SAFETY: guarded on ID_AA64PFR0_EL1.SVE above, which is the
        // architectural precondition for this register existing.
        unsafe {
            core::arch::asm!("mrs {v}, S3_0_C0_C4_4", v = out(reg) zfr0,
                             options(nomem, nostack, preserves_flags));
        }
        // SVEver: 0b0000 = SVE, 0b0001 = SVE2.
        field(zfr0, 0) >= 1
    };

    CpuFeatures {
        neon: true,
        invariant_counter: true,
        arm_aes: aes >= 1,
        pclmulqdq: aes >= 2,
        // ID_AA64ISAR0_EL1.SHA2: 0b0001 = SHA256.
        arm_sha2: field(isar0, 12) >= 1,
        sve,
        sve2,
        // ID_AA64PFR1_EL1.SME: 0b0001 = SME, 0b0010 = SME2.
        sme: field(pfr1, 24) >= 1,
        ..Default::default()
    }
}

#[cfg(all(target_arch = "aarch64", feature = "std"))]
fn detect_aarch64() -> CpuFeatures {
    // The only writes after this are platform-gated — the macOS capability
    // buffer and the Windows cross-check — so on a target with neither, `mut`
    // is genuinely unused rather than an oversight.
    #[allow(unused_mut)]
    let mut f = CpuFeatures {
        // NEON is architecturally mandatory on AArch64.
        neon: true,
        // CNTVCT_EL0 runs off a fixed-frequency system counter, so it is
        // invariant by construction — unlike the x86 TSC, which had to earn
        // the label.
        invariant_counter: true,

        // `std::arch::is_aarch64_feature_detected!` reads HWCAP on Linux and
        // the equivalent OS query elsewhere, which is the only supported way
        // to probe these: the ID registers trap at EL0.
        sve: std::arch::is_aarch64_feature_detected!("sve"),
        sve2: std::arch::is_aarch64_feature_detected!("sve2"),
        arm_aes: std::arch::is_aarch64_feature_detected!("aes"),
        arm_sha2: std::arch::is_aarch64_feature_detected!("sha2"),
        pclmulqdq: std::arch::is_aarch64_feature_detected!("pmull"),

        // SME has no stable detection macro yet (rust-lang/rust#127764), so
        // the OS is asked directly. That is what the macro would do anyway,
        // and it keeps the crate building on stable.
        sme: hwcap2_has(HWCAP2_SME),

        ..Default::default()
    };

    // macOS has no auxiliary vector, and `is_aarch64_feature_detected!`
    // resolves several of these through `sysctl` already — but not SME, which
    // Apple Silicon does have from the M4 onwards. Apple publishes the whole
    // extension set as a bit buffer, so one query settles everything the
    // macro could not answer.
    #[cfg(target_os = "macos")]
    if let Some(caps) = crate::platform::darwin::arm_capability_bits() {
        use crate::platform::darwin::has_capability;
        // Bit numbers from the SDK's `arm/cpu_capabilities_public.h`, which
        // states that existing entries are ABI and never renumbered.
        const CAP_BIT_FEAT_SHA256: u32 = 7;
        const CAP_BIT_FEAT_AES: u32 = 10;
        const CAP_BIT_FEAT_PMULL: u32 = 11;
        const CAP_BIT_FEAT_SME: u32 = 40;

        f.sme = has_capability(&caps, CAP_BIT_FEAT_SME);
        // ORed rather than assigned: the detection macro above is
        // authoritative when it answers, and this only fills gaps.
        f.arm_aes |= has_capability(&caps, CAP_BIT_FEAT_AES);
        f.arm_sha2 |= has_capability(&caps, CAP_BIT_FEAT_SHA256);
        f.pclmulqdq |= has_capability(&caps, CAP_BIT_FEAT_PMULL);
    }

    #[cfg(target_os = "windows")]
    cross_check_with_windows(&mut f);

    f
}

/// `HWCAP2_SME`, from `arch/arm64/include/uapi/asm/hwcap.h`.
#[cfg(target_arch = "aarch64")]
#[cfg(all(target_arch = "aarch64", feature = "std"))]
const HWCAP2_SME: u64 = 1 << 23;

/// Tests a bit of the second hardware-capability word the kernel passes in the
/// auxiliary vector.
#[cfg(target_arch = "aarch64")]
#[cfg(all(target_arch = "aarch64", feature = "std"))]
fn hwcap2_has(bit: u64) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: `getauxval` reads the process's own auxiliary vector and
        // returns 0 for an unknown key; it has no preconditions.
        let hwcap2 = unsafe { libc::getauxval(libc::AT_HWCAP2) };
        hwcap2 & bit != 0
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = bit;
        false
    }
}

/// Who made this x86 processor, by the twelve bytes `CPUID.0H` returns.
///
/// # Why this is more than a label
///
/// Because what a part is decides which of its CPUID leaves can be believed.
/// The clearest case is the TSC: leaves `15H` and `16H` state the counter's
/// frequency exactly, and Linux reads them **only on Intel** — every other
/// vendor falls through to measuring the counter against a timer, because
/// their values have not proved trustworthy. A chronometer that took a
/// stated frequency from a part whose statement Linux refuses would be
/// building every subsequent number on it.
///
/// Zhaoxin is the case that prompted this. Its parts are x86-64 descended
/// from VIA's Centaur line, they carry Intel-style architectural PMUs and
/// VMX, and they are close enough to Intel that code which assumes "not AMD
/// means Intel" runs on them and quietly misreads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Intel,
    Amd,
    /// Zhaoxin — `"  Shanghai  "`, spaces included. The joint venture that
    /// took over VIA's x86 line.
    Zhaoxin,
    /// VIA/Centaur — `"CentaurHauls"`. The lineage Zhaoxin continues, and
    /// still what some parts report.
    Centaur,
    /// A vendor string this does not recognise, kept so it can be shown
    /// rather than flattened to "other".
    Other([u8; 12]),
}

impl Vendor {
    /// Decodes the twelve bytes `CPUID.0H` returns in EBX, EDX, ECX.
    ///
    /// That register order is not a mistake: it is the order the instruction
    /// defines, and reading them as EBX, ECX, EDX spells `GenuntelineI`.
    pub const fn from_signature(signature: [u8; 12]) -> Vendor {
        match &signature {
            b"GenuineIntel" => Vendor::Intel,
            b"AuthenticAMD" => Vendor::Amd,
            b"  Shanghai  " => Vendor::Zhaoxin,
            b"CentaurHauls" => Vendor::Centaur,
            _ => Vendor::Other(signature),
        }
    }

    /// The signature as written, for display.
    pub fn as_str(&self) -> &str {
        match self {
            Vendor::Intel => "GenuineIntel",
            Vendor::Amd => "AuthenticAMD",
            Vendor::Zhaoxin => "  Shanghai  ",
            Vendor::Centaur => "CentaurHauls",
            Vendor::Other(raw) => core::str::from_utf8(raw).unwrap_or("?"),
        }
    }

    /// A readable name.
    pub const fn name(&self) -> &'static str {
        match self {
            Vendor::Intel => "Intel",
            Vendor::Amd => "AMD",
            Vendor::Zhaoxin => "Zhaoxin",
            Vendor::Centaur => "VIA/Centaur",
            Vendor::Other(_) => "unknown",
        }
    }

    /// Whether `CPUID.15H` and `CPUID.16H` may be believed as a counter rate.
    ///
    /// Intel only, which is the rule Linux applies in `native_calibrate_tsc`
    /// and `cpu_khz_from_cpuid`. Everything else measures instead — slower to
    /// establish and correct by construction, which is the right trade for a
    /// number every later measurement is divided by.
    pub const fn states_a_trustworthy_tsc_rate(&self) -> bool {
        matches!(self, Vendor::Intel)
    }

    /// Whether the part implements the Centaur extended CPUID range at
    /// `0xC000_0000`.
    ///
    /// Only this lineage does — it is to Centaur what `0x8000_0000` is to
    /// AMD — so a non-zero maximum there is positive identification even
    /// where the vendor string has been changed.
    pub const fn has_centaur_leaves(&self) -> bool {
        matches!(self, Vendor::Zhaoxin | Vendor::Centaur)
    }

    /// Whether this part is Intel-compatible for the architectural PMU,
    /// machine-check banks and topology leaves.
    ///
    /// True for Zhaoxin and Centaur as well as Intel: Linux groups all three
    /// for the architectural performance monitoring leaf, and Zhaoxin's own
    /// PMU driver reads `CPUID.0AH` and requires version 2 — the same
    /// interface, not an imitation of it.
    pub const fn uses_intel_architectural_pmu(&self) -> bool {
        matches!(self, Vendor::Intel | Vendor::Zhaoxin | Vendor::Centaur)
    }
}

/// The raw twelve-byte vendor string of `CPUID.0H` (EBX, EDX, ECX).
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn vendor_signature() -> [u8; 12] {
    use crate::arch::x86::cpuid;
    let [_, ebx, ecx, edx] = cpuid(0, 0);
    let mut signature = [0u8; 12];
    signature[0..4].copy_from_slice(&ebx.to_le_bytes());
    signature[4..8].copy_from_slice(&edx.to_le_bytes());
    signature[8..12].copy_from_slice(&ecx.to_le_bytes());
    signature
}

/// This machine's CPU vendor.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn vendor() -> Vendor {
    Vendor::from_signature(vendor_signature())
}

/// The highest Centaur extended leaf this part answers, or zero.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn centaur_max_leaf() -> u32 {
    use crate::arch::x86::cpuid;
    let max = cpuid(0xC000_0000, 0)[0];
    // A part without the range answers with whatever the highest leaf it does
    // implement returns, so the value only means something if it is inside
    // the range it claims to describe.
    if (0xC000_0000..=0xC000_FFFF).contains(&max) {
        max
    } else {
        0
    }
}

/// Vendor brand string, when the architecture exposes one.
#[cfg(feature = "std")]
pub fn brand_string() -> Option<String> {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        use crate::arch::x86::cpuid;
        if cpuid(0x8000_0000, 0)[0] < 0x8000_0004 {
            return None;
        }
        let mut bytes = Vec::with_capacity(48);
        for leaf in 0x8000_0002u32..=0x8000_0004 {
            for reg in cpuid(leaf, 0) {
                bytes.extend_from_slice(&reg.to_le_bytes());
            }
        }
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(String::from_utf8_lossy(&bytes[..end]).trim().to_string())
    }
    // AArch64 has no brand-string instruction. macOS publishes one anyway,
    // which is how an Apple Silicon part gets named rather than reported as
    // an anonymous ARM core.
    #[cfg(all(
        not(any(target_arch = "x86_64", target_arch = "x86")),
        target_os = "macos"
    ))]
    {
        crate::platform::darwin::sysctl_string("machdep.cpu.brand_string")
            .or_else(|| crate::platform::darwin::sysctl_string("hw.model"))
    }
    #[cfg(all(
        not(any(target_arch = "x86_64", target_arch = "x86")),
        not(target_os = "macos")
    ))]
    {
        None
    }
}

#[cfg(all(test, any(target_arch = "powerpc", target_arch = "powerpc64")))]
mod ppc_tests {
    use super::*;

    #[test]
    fn hwcap_decodes_power9() {
        let f = from_ppc_hwcap(
            ppc_hwcap::HAS_ALTIVEC | ppc_hwcap::HAS_VSX,
            ppc_hwcap::ARCH_2_07 | ppc_hwcap::ARCH_3_00 | ppc_hwcap::HAS_VEC_CRYPTO,
        );
        assert!(f.altivec && f.vsx && f.ppc_isa207 && f.ppc_isa300 && !f.ppc_isa31);
        assert!(f.ppc_vec_crypto);
    }

    #[test]
    fn vsx_without_altivec_is_refused() {
        let f = from_ppc_hwcap(ppc_hwcap::HAS_VSX, 0);
        assert!(!f.vsx && !f.altivec);
    }

    #[test]
    fn unknown_pvrs_claim_nothing() {
        let f = from_pvr(0x1234_0000);
        assert_eq!(f, CpuFeatures { invariant_counter: true, ..Default::default() });
        assert!(from_pvr(0x004E_1202).ppc_isa300);
        assert!(!from_pvr(0x8023_0000).altivec, "e500mc has no AltiVec");
    }
}

#[cfg(test)]
mod vendor_tests {
    use super::*;

    /// The four signatures this knows, byte for byte.
    ///
    /// Zhaoxin's is the one worth pinning: it is `"  Shanghai  "` — two
    /// leading spaces and two trailing, because the field is exactly twelve
    /// bytes and the name is eight. Trimming it, or writing it without the
    /// padding, produces a string that never matches and a part that is
    /// silently treated as unknown.
    #[test]
    fn the_vendor_signatures_are_exact() {
        assert_eq!(Vendor::from_signature(*b"GenuineIntel"), Vendor::Intel);
        assert_eq!(Vendor::from_signature(*b"AuthenticAMD"), Vendor::Amd);
        assert_eq!(Vendor::from_signature(*b"  Shanghai  "), Vendor::Zhaoxin);
        assert_eq!(Vendor::from_signature(*b"CentaurHauls"), Vendor::Centaur);

        // Every signature is twelve bytes; the register triple has no room
        // for more and no padding for less.
        for vendor in [Vendor::Intel, Vendor::Amd, Vendor::Zhaoxin, Vendor::Centaur] {
            assert_eq!(
                vendor.as_str().len(),
                12,
                "{} does not round-trip as twelve bytes",
                vendor.name()
            );
        }
    }

    /// A trimmed Zhaoxin string is not a Zhaoxin string.
    ///
    /// The mistake this guards against is writing the match arm as
    /// `b"Shanghai"`, which compiles, never matches, and leaves the part
    /// reported as unknown — and therefore treated as though its TSC leaves
    /// had never been ruled out.
    #[test]
    fn a_trimmed_zhaoxin_signature_does_not_match() {
        assert!(matches!(
            Vendor::from_signature(*b"Shanghai    "),
            Vendor::Other(_)
        ));
        assert!(matches!(
            Vendor::from_signature(*b"  Shanghai\0\0"),
            Vendor::Other(_)
        ));
    }

    /// Only Intel's counter-rate leaves are believed.
    ///
    /// This is the rule Linux applies in `native_calibrate_tsc` and
    /// `cpu_khz_from_cpuid`, and the reason it matters is that the result is
    /// the divisor of every later measurement: a wrong rate does not produce
    /// a wrong reading, it produces every reading wrong by the same factor,
    /// which is far harder to notice.
    #[test]
    fn only_intel_states_a_trustworthy_counter_rate() {
        assert!(Vendor::Intel.states_a_trustworthy_tsc_rate());
        for vendor in [
            Vendor::Amd,
            Vendor::Zhaoxin,
            Vendor::Centaur,
            Vendor::Other(*b"____________"),
        ] {
            assert!(
                !vendor.states_a_trustworthy_tsc_rate(),
                "{} must fall through to measuring the counter",
                vendor.name()
            );
        }
    }

    /// Zhaoxin and Centaur share Intel's architectural PMU, and have the
    /// Centaur extended range that Intel and AMD do not.
    #[test]
    fn the_zhaoxin_lineage_is_grouped_correctly() {
        for vendor in [Vendor::Zhaoxin, Vendor::Centaur] {
            assert!(vendor.has_centaur_leaves(), "{}", vendor.name());
            assert!(vendor.uses_intel_architectural_pmu(), "{}", vendor.name());
        }
        assert!(Vendor::Intel.uses_intel_architectural_pmu());
        assert!(!Vendor::Intel.has_centaur_leaves());
        assert!(!Vendor::Amd.has_centaur_leaves());
        assert!(!Vendor::Amd.uses_intel_architectural_pmu());
    }

    /// The register order is EBX, EDX, ECX — not EBX, ECX, EDX.
    ///
    /// Getting it wrong spells `GenuntelineI`, which is exactly the kind of
    /// error that looks like a typo in a string constant and is really a
    /// misread of the instruction.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    #[test]
    fn this_machines_vendor_decodes_to_something_real() {
        let vendor = vendor();
        assert!(
            !matches!(vendor, Vendor::Other(_)) || vendor.as_str().is_ascii(),
            "the vendor decoded to something that is not even text: {:?}",
            vendor
        );
        // Whatever this machine is, the string has to be printable — a
        // scrambled register order produces bytes that are not.
        assert!(
            vendor
                .as_str()
                .chars()
                .all(|c| c.is_ascii_graphic() || c == ' '),
            "the vendor string is not printable: {:?}",
            vendor.as_str()
        );
    }
}
