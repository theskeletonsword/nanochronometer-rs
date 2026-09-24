// SPDX-License-Identifier: MIT

//! Hypervisor detection and hypercall probes, ported from the Linux kernel
//! module `kernel/linux/nanochrono.rs` to the Windows kernel ABI.
//!
//! # Safety model (important)
//!
//! The Linux module relies on the kernel's exception fixups (`__ex_table`)
//! plus the Rust `asm!` `sym`-based handlers to run `vmcall`/`vmmcall`/`hvc`
//! even when no hypervisor is present, recovering from the resulting #UD or
//! #NV probe fault.
//!
//! A MinGW-built Windows driver has **no** exception-recovery primitive
//! (verified: neither GCC nor clang#windows-gnu emits real `__try/__except`
//! handlers / `.pdata` funclets). Executing a hypercall on bare metal faults
//! irrecoverably. Therefore the probes in this module are **detection-gated**:
//!
//!   - x86_64 probes are only run when the CPUID hypervisor-present bit is
//!     set (and/or `KeIsHypervisorPresent()`), i.e. when a hypervisor is
//!     actually reported by firmware.
//!   - arm64 probes are only run when `KeIsHypervisorPresent()` reports a
//!     hypervisor, and only `hvc #0` at EL1+, never raw `smc`.
//!
//! The report code in `report.rs` performs this gating before calling the
//! `unsafe` hypercall trampolines below. To obtain real fault recovery you
//! must build with MSVC/WDK (SEH); the porting guide explains how.

#[cfg(target_arch = "x86_64")]
mod x64 {
    use core::arch::asm;

    /// CPUID leaf 0 identifies the vendor string.
    pub const CPUID_LEAF_VENDOR: u32 = 0;
    /// CPUID leaf 1 = 1 exposes the hypervisor-present bit (ecx bit 31) and
    /// VMX (ecx bit 5) / SVM (ecx bit 2) capability bits.
    pub const CPUID_LEAF_FEATURES: u32 = 1;

    /// Raw `cpuid` leaf query. Safe: CPUID is architecturally valid on every
    /// x86-64 CPU.
    ///
    /// Note: on the `*-windows-gnullvm` targets LLVM reserves `rbx`, so the
    /// vendor half (EBX) is shuttled through a scratch register with RBX
    /// saved/restored around the instruction.
    #[inline(always)]
    pub fn cpuid(leaf: u32, subleaf: u32) -> [u32; 4] {
        let mut eax: u32 = 0;
        let mut ecx: u32 = 0;
        let mut edx: u32 = 0;
        let mut ebx: u32 = 0;
        unsafe {
            asm!(
                "push rbx",
                "mov rbx, 0",
                "cpuid",
                "mov {ebx_out:r}, rbx",
                "pop rbx",
                inout("eax") leaf => eax,
                in("ecx") subleaf,
                ebx_out = out(reg) ebx,
                lateout("ecx") ecx,
                lateout("edx") edx,
                options(nostack, preserves_flags)
            );
        }
        [eax, ebx, ecx, edx]
    }

    /// ecx bit 31 of leaf 1: "hypervisor present" (HV === 1).
    pub fn hypervisor_present() -> bool {
        cpuid(CPUID_LEAF_FEATURES, 0)[2] & (1 << 31) != 0
    }

    /// True when the vendor string starts with exactly one of the lead bytes
    /// "KVMKP"/"VMware"/"Microsoft HV"/"XenVMM"/"prl hyperv" etc.; we only need
    /// the first four bytes (8 chars).
    pub fn vendor() -> [u8; 16] {
        let v = cpuid(CPUID_LEAF_VENDOR, 0);
        let mut s = [0u8; 16];
        let b = v[1].to_le_bytes();
        let d = v[3].to_le_bytes();
        let c = v[2].to_le_bytes();
        s[..4].copy_from_slice(&b);
        s[4..8].copy_from_slice(&d);
        s[8..12].copy_from_slice(&c);
        s
    }

    pub fn vmx_available() -> bool {
        cpuid(CPUID_LEAF_FEATURES, 0)[2] & (1 << 5) != 0
    }

    pub fn svm_available() -> bool {
        // SVM is CPUID 8000_0001h ECX bit 2 (AMD APM vol. 3, "CPUID Fn8000_0001_ECX").
        cpuid(0x8000_0000, 0)[0] >= 0x8000_0001 && cpuid(0x8000_0001, 0)[2] & (1 << 2) != 0
    }

    /// The x86-64 hypercall instruction of a vendor.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum HypercallInsn {
        Vmcall,
        Vmmcall,
    }

    impl HypercallInsn {
        pub const fn name(self) -> &'static str {
            match self {
                HypercallInsn::Vmcall => "vmcall",
                HypercallInsn::Vmmcall => "vmmcall",
            }
        }
    }

    /// The hypercall HAL — mandatory, and decided at run time.
    ///
    /// Intel, Zhaoxin and VIA/Centaur (VMX) define `VMCALL`; AMD and Hygon
    /// (SVM) define `VMMCALL`. The other one is `#UD` under most hypervisors,
    /// and an unhandled `#UD` in a driver is a bugcheck. The choice is made
    /// from `CPUID.0H` at every driver start, never at build time: one
    /// Windows installation (on an external SSD, say) boots on an Intel
    /// machine and then an AMD one. An unknown vendor gets no hypercall.
    ///
    /// The same table as `nanochrono_core::hypercall_hal`, which a driver
    /// built without `std` and without that crate carries itself.
    pub fn hypercall_insn() -> Option<HypercallInsn> {
        let v = vendor();
        match &v[..12] {
            b"GenuineIntel" | b"  Shanghai  " | b"CentaurHauls" => Some(HypercallInsn::Vmcall),
            b"AuthenticAMD" | b"HygonGenuine" => Some(HypercallInsn::Vmmcall),
            _ => None,
        }
    }

    /// The 12-byte signature at `CPUID.40000000H`, or zeros when the
    /// hypervisor bit is clear (the leaf is then not defined).
    pub fn hv_signature() -> [u8; 12] {
        let mut s = [0u8; 12];
        if !hypervisor_present() {
            return s;
        }
        let v = cpuid(0x4000_0000, 0);
        s[..4].copy_from_slice(&v[1].to_le_bytes());
        s[4..8].copy_from_slice(&v[2].to_le_bytes());
        s[8..12].copy_from_slice(&v[3].to_le_bytes());
        s
    }

    /// Whether this hypervisor is known to *return* from an unknown
    /// hypercall rather than inject `#UD`.
    ///
    /// Without SEH (see the module docs) a `#UD` here is a bugcheck, so the
    /// probe only runs where the answer is documented: KVM returns
    /// `-KVM_ENOSYS` for an unknown number, Hyper-V (TLFS, with the
    /// hypercall page Windows itself enables) returns
    /// `HV_STATUS_INVALID_HYPERCALL_CODE`, Xen returns `-ENOSYS`.
    pub fn hypercall_known_safe(sig: &[u8; 12]) -> bool {
        sig == b"KVMKVMKVM\0\0\0" || sig == b"Microsoft Hv" || sig == b"XenVMMXenVMM"
    }

    /// Minimum TSC cycles of one `CPUID` over `rounds` tries: under VMX/SVM
    /// every `CPUID` exits, so this is the exit round trip.
    pub fn exit_cost_cycles(rounds: u32) -> u64 {
        use core::arch::x86_64::{_mm_lfence, _rdtsc};
        let mut best = u64::MAX;
        for _ in 0..rounds.max(1) {
            // SAFETY: LFENCE/RDTSC are unprivileged and always present on x86-64.
            let (a, b) = unsafe {
                _mm_lfence();
                let a = _rdtsc();
                _mm_lfence();
                let _ = cpuid(0, 0);
                _mm_lfence();
                let b = _rdtsc();
                (a, b)
            };
            best = best.min(b.wrapping_sub(a));
        }
        best
    }

    /// Hypercall number used by the ported Linux probe (RAX = 0xFFFF).
    pub const PROBE_HYPERCALL_NR: u64 = 0xFFFF;

    /// Executes a `vmcall` with the probe hypercall number. **Unsafe**: only
    /// call when a hypervisor has been detected (see module docs).
    #[inline(always)]
    pub unsafe fn probe_vmcall() -> u64 {
        let mut ret = 0u64;
        asm!(
            "vmcall",
            in("rax") PROBE_HYPERCALL_NR,
            in("rcx") 0u64,
            in("rdx") 0u64,
            in("r8") 0u64,
            in("r9") 0u64,
            lateout("rax") ret,
            // KVM clobbers only RAX; Hyper-V and Xen may write the input
            // registers back. Declare them all lost.
            lateout("rcx") _, lateout("rdx") _, lateout("r8") _, lateout("r9") _,
            lateout("r10") _, lateout("r11") _,
            options(nostack)
        );
        ret
    }

    /// Executes a `vmmcall` (AMD). **Unsafe**: only call when a hypervisor
    /// has been detected.
    #[inline(always)]
    pub unsafe fn probe_vmmcall() -> u64 {
        let mut ret = 0u64;
        asm!(
            "vmmcall",
            in("rax") PROBE_HYPERCALL_NR,
            in("rcx") 0u64,
            in("rdx") 0u64,
            in("r8") 0u64,
            in("r9") 0u64,
            lateout("rax") ret,
            lateout("rcx") _, lateout("rdx") _, lateout("r8") _, lateout("r9") _,
            lateout("r10") _, lateout("r11") _,
            options(nostack)
        );
        ret
    }
}

/// x86_64 re-exports.
#[cfg(target_arch = "x86_64")]
pub use self::x64::{
    exit_cost_cycles, hypercall_insn, HypercallInsn, hv_signature, hypercall_known_safe, hypervisor_present,
    probe_vmcall, probe_vmmcall, svm_available, vendor, vmx_available,
};

/// arm64 module, ported from the Linux `hvc`/`mrs` probes.
#[cfg(target_arch = "aarch64")]
mod arm64 {
    use core::arch::asm;

    /// SMCCC v1.1+ `SMCCC_VERSION` function ID. Kept as public documentation;
    /// the driver currently probes only the vendor UID.
    #[allow(dead_code)]
    pub const SMCCC_VERSION_FUNC_ID: u64 = 0x8000_0000;
    /// SMCCC `SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID` (KVM/other firmware UID).
    pub const SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID: u64 = 0x8600_ff01;

    /// Reads `CurrentEL` (always valid on arm64).
    #[inline(always)]
    pub fn current_el() -> u64 {
        let mut el: u64;
        unsafe {
            asm!("mrs {0}, CurrentEL", out(reg) el, options(nomem, nostack));
        }
        el >> 2
    }

    /// Executes a `hvc #0` hypercall returning registers x0..x3.
    /// **Unsafe**: only call under a detected hypervisor and never below EL1.
    #[inline(always)]
    pub unsafe fn probe_hvc(function_id: u64) -> [u64; 4] {
        let mut out = [0u64; 4];
        asm!(
            "hvc #0",
            in("x0") function_id,
            in("x1") 0u64,
            in("x2") 0u64,
            in("x3") 0u64,
            lateout("x0") out[0],
            lateout("x1") out[1],
            lateout("x2") out[2],
            lateout("x3") out[3],
            // SMCCC v1.0 lets the callee clobber x4-x17; v1.1 preserves
            // them, but which one answers is not known in advance.
            lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _,
            lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _,
            lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _,
            lateout("x16") _, lateout("x17") _,
            options(nostack)
        );
        out
    }
}

/// arm64 re-exports.
#[cfg(target_arch = "aarch64")]
pub use self::arm64::{current_el, probe_hvc, SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID};