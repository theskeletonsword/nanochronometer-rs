// SPDX-License-Identifier: Apache-2.0
//! Hypervisor detection and host time, from ring 0.
//!
//! # Why this is mandatory here and optional in the hosted build
//!
//! The hosted toolkit treats hypercalls as an optional extra behind a kernel
//! module, because `VMCALL` at CPL 3 raises `#UD` and `HVC` at EL0 is
//! undefined — a userspace process simply cannot issue one, so detection there
//! rests on the passive CPUID leaf and the platform's files.
//!
//! This kernel *is* ring 0. The hypercall is available, it is the only source
//! that cannot be spoofed by clearing a CPUID bit, and — the part that
//! matters for a chronometer — it is the only way to get the host's clock
//! paired with this machine's counter. So it is not optional: detection runs
//! CPUID *and* the hypercall, and reports both.
//!
//! # Negotiating nanoseconds with the host
//!
//! Inside a VM the guest counter is not the host's. `KVM_HC_CLOCK_PAIRING`
//! asks the host to sample its own clock and the guest TSC at the same
//! instant, which turns a guest timestamp into a host timestamp. That is the
//! call `ptp_kvm` makes in the Linux guest kernel and publishes through a PTP
//! device; with no kernel there is no device, so the call is made directly.
//!
//! Constants verified against the running kernel's headers:
//! `KVM_HC_CLOCK_PAIRING` is 9 and `KVM_CLOCK_PAIRING_WALLCLOCK` is 0 in
//! `arch/x86/include/uapi/asm/kvm_para.h`; the AArch64 PTP function ID is
//! `ARM_SMCCC_VENDOR_HYP_KVM_PTP_FUNC_ID`, `0x86000001`.

use core::sync::atomic::{AtomicU32, Ordering};

/// Every hypercall this machine has issued.
///
/// # Why it is counted at all
///
/// Because the measurement depends on it staying at one. A hypercall is a
/// `VMCALL`: a trap out of the guest, into the host kernel, and back. It costs
/// microseconds — thousands of times a counter read — and, worse for a
/// chronometer, it costs a *variable* number of them, because what happens on
/// the other side is another operating system's scheduler.
///
/// So the host clock is asked for exactly once, at boot, to learn the offset
/// between this machine's counter and the host's. After that the stopwatch
/// reads `RDTSC` and nothing else: the pairing is arithmetic applied to a
/// counter, not a question asked again. A stopwatch that issued a hypercall
/// per sample would be measuring the hypercall.
///
/// Counting them turns that from a claim in a comment into something the
/// screen shows. The hypervisor panel reports this number; if a change ever
/// puts a hypercall in the frame loop, it stops reading `1` and starts
/// climbing, in front of whoever is looking.
static HYPERCALLS: AtomicU32 = AtomicU32::new(0);

/// How many hypercalls have been issued since power-on.
pub fn hypercalls() -> u32 {
    HYPERCALLS.load(Ordering::Relaxed)
}

/// What was found, and how.
#[derive(Debug, Clone, Copy, Default)]
pub struct Report {
    /// `CPUID.1:ECX[31]`, the architectural hypervisor bit. Passive: a
    /// hypervisor that wants to hide clears it.
    pub cpuid_bit: bool,
    /// The 12-byte signature at `CPUID.40000000H`, when there is one.
    pub signature: [u8; 12],
    /// Highest hypervisor leaf the platform answers.
    pub max_leaf: u32,
    /// A hypercall returned instead of faulting. Proof, not inference — and
    /// it holds even against a hypervisor that cleared the CPUID bit.
    pub hypercall_ok: bool,
    /// Host time paired with this machine's counter, if the host offered it.
    pub pairing: Option<ClockPairing>,
    /// How many hypercalls the machine has issued, in total, ever.
    ///
    /// The whole point is that this is a small number and never grows. See
    /// [`hypercalls`].
    pub hypercalls: u32,
    /// x86-64: the hypercall instruction the HAL chose for this CPU's vendor
    /// (`None` elsewhere, or for an unknown vendor — then no hypercall).
    pub hypercall_insn: Option<nanochrono_core::hypercall_hal::HypercallInsn>,
    /// How many times detection has run: 1 is the boot-time negotiation,
    /// anything more a re-probe the user asked for. See [`reprobe`].
    pub probes: u32,
}

impl Report {
    /// Whether anything says this is a guest.
    pub fn is_virtualized(&self) -> bool {
        self.cpuid_bit || self.hypercall_ok
    }

    /// The signature as text, empty if there is none.
    pub fn signature_str(&self) -> &str {
        let end = self
            .signature
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.signature.len());
        core::str::from_utf8(&self.signature[..end]).unwrap_or("")
    }
}

/// One host/guest timestamp pair, captured together by the host.
#[derive(Debug, Clone, Copy)]
pub struct ClockPairing {
    /// The host's clock, in nanoseconds.
    pub host_ns: u64,
    /// This machine's counter at the same instant.
    pub counter: u64,
}

/// Runs every detector — every time. Only [`detect`] and [`reprobe`] call it.
///
/// # Safety
/// Issues a hypercall and reads MSRs; requires ring 0 / EL1.
unsafe fn probe_now() -> Report {
    #[cfg(x86_any)]
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        x86::detect()
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        arm::detect()
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        ppc::detect()
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        riscv::detect()
    }
    // 32-bit ARM: no detector yet; reported as bare metal would be a claim,
    // so the report says nothing either way.
    #[cfg(target_arch = "arm")]
    {
        Report::default()
    }
}

// ---------------------------------------------------------------------------
// Once at boot, then only on request, behind the cooldown
// ---------------------------------------------------------------------------
//
// The negotiation with the host — the hypercalls, the clock pairing — runs
// once, the first time anything asks (the self-test, during boot). Every
// later caller — the self-test's printout, the GUI, the serial console — gets
// that cached report. A hypervisor on a cloud host (Azure, GCP, AWS,
// Vultr…) reads a guest that keeps exiting as abuse, and throttles or bans
// it; a panel that re-detected on every frame would do exactly that.
//
// The user can ask again (a key in the GUI and the console), at most once
// every `nanochrono_core::reprobe::DEFAULT_COOLDOWN_S` seconds. Settings can
// switch the wait off, with the warning that the ban risk is then the user's.

struct Cache {
    report: Option<Report>,
    /// `arch::counter_ordered()` at the last probe.
    last_ticks: u64,
    cooldown_s: u32,
}

/// One core, no interrupt handler touches it: every access is from the
/// kernel's single thread of control, so a plain static is enough.
static mut CACHE: Cache = Cache {
    report: None,
    last_ticks: 0,
    cooldown_s: nanochrono_core::reprobe::DEFAULT_COOLDOWN_S,
};

fn cache() -> &'static mut Cache {
    // SAFETY: single-threaded kernel, see `CACHE`; no reference outlives the
    // caller's statement.
    unsafe { &mut *core::ptr::addr_of_mut!(CACHE) }
}

fn record(mut report: Report) -> Report {
    let c = cache();
    report.probes = c.report.map_or(1, |r| r.probes.saturating_add(1));
    report.hypercalls = hypercalls();
    c.report = Some(report);
    c.last_ticks = crate::arch::counter_ordered();
    report
}

/// The hypervisor report: probed the first time (the boot negotiation),
/// cached ever after.
///
/// # Safety
/// The first call issues a hypercall and reads MSRs; requires ring 0 / EL1.
pub unsafe fn detect() -> Report {
    if let Some(report) = cache().report {
        return report;
    }
    // SAFETY: forwarded from this function's own contract.
    record(unsafe { probe_now() })
}

/// Whole seconds until [`reprobe`] is allowed; 0 = now. `hz` is the rate of
/// `arch::counter_ordered()`.
pub fn reprobe_wait_s(hz: u64) -> u32 {
    let c = cache();
    if c.cooldown_s == 0 || c.report.is_none() || hz == 0 {
        return 0;
    }
    let elapsed = crate::arch::counter_ordered().wrapping_sub(c.last_ticks);
    let window = c.cooldown_s as u64 * hz;
    window.saturating_sub(elapsed).div_ceil(hz) as u32
}

/// Probes again, if the cooldown allows. `Err` carries the seconds left.
///
/// # Safety
/// As [`detect`]: issues a hypercall; requires ring 0 / EL1.
pub unsafe fn reprobe(hz: u64) -> Result<Report, u32> {
    let wait = reprobe_wait_s(hz);
    if wait > 0 {
        return Err(wait);
    }
    // SAFETY: forwarded from this function's own contract.
    Ok(record(unsafe { probe_now() }))
}

/// Whether the re-probe wait is on.
pub fn cooldown_enabled() -> bool {
    cache().cooldown_s != 0
}

/// Turns the re-probe wait on (the default length) or off. Off is the
/// user's risk: `nanochrono_core::reprobe::COOLDOWN_OFF_WARNING`.
pub fn set_cooldown_enabled(on: bool) {
    cache().cooldown_s = if on { nanochrono_core::reprobe::DEFAULT_COOLDOWN_S } else { 0 };
}

/// RISC-V: the SBI names its implementation. KVM (ID 3), Xvisor (2), Xen (7)
/// and bhyve (11) are hypervisors, and their SBI *is* the hypercall
/// interface — the query is already a hypercall, answered, which is proof.
/// Firmware implementations (OpenSBI, RustSBI, …) mean bare metal.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
mod riscv {
    use super::Report;
    use crate::arch::riscv::{sbi, sbi_identity};

    pub(super) fn detect() -> Report {
        let (_, id, _) = sbi_identity();
        super::HYPERCALLS.fetch_add(3, super::Ordering::Relaxed);
        let mut report = Report::default();
        let name = sbi::impl_name(id).as_bytes();
        let n = name.len().min(report.signature.len());
        report.signature[..n].copy_from_slice(&name[..n]);
        let hypervisor = matches!(id, 2 | 3 | 7 | 11);
        report.hypercall_ok = hypervisor;
        report.cpuid_bit = hypervisor;
        report.hypercalls = super::hypercalls();
        report
    }
}

/// PowerPC: the MSR says it directly, no hypercall needed.
///
/// On 64-bit Book3S, `MSR[HV]` set means this kernel *is* in hypervisor
/// state — `powernv`, bare metal — and clear means a hypervisor sits above
/// it (a `pseries` LPAR under PowerVM or KVM). No `sc 1` is issued: it would
/// be a hypercall into whatever that hypervisor is, with nothing gained that
/// the MSR does not already say. 32-bit Book E has no equivalent visible from
/// the guest, so nothing is claimed there.
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
mod ppc {
    use super::Report;

    pub(super) fn detect() -> Report {
        let mut report = Report::default();
        #[cfg(target_arch = "powerpc64")]
        {
            report.cpuid_bit = crate::arch::ppc::msr() & crate::arch::ppc::MSR_HV == 0;
        }
        report.hypercalls = super::hypercalls();
        report
    }
}

#[cfg(x86_any)]
// The KVM clock pairing below is a long-mode interface (a 64-bit guest
// address in RBX); on i386 it is compiled out and its pieces go unused.
#[cfg_attr(target_arch = "x86", allow(dead_code, unused_imports))]
mod x86 {
    use super::{ClockPairing, Report};
    use crate::arch::x86::cpuid;

    /// `KVM_HC_CLOCK_PAIRING`, from `asm/kvm_para.h`.
    const KVM_HC_CLOCK_PAIRING: u64 = 9;
    /// `KVM_CLOCK_PAIRING_WALLCLOCK`, the only defined pairing type.
    const KVM_CLOCK_PAIRING_WALLCLOCK: u64 = 0;

    /// `struct kvm_clock_pairing`, which the host fills in.
    ///
    /// The layout is ABI: `{ s64 sec; s64 nsec; u64 tsc; u32 flags; u32
    /// pad[9]; }`, sixty-four bytes. The host writes by offset, so this must
    /// match exactly.
    #[repr(C, align(64))]
    #[derive(Default)]
    struct KvmClockPairing {
        sec: i64,
        nsec: i64,
        tsc: u64,
        flags: u32,
        pad: [u32; 9],
    }

    /// The buffer the host writes the pairing into.
    ///
    /// A static rather than a stack local because the hypercall takes a
    /// *physical* address: the identity map makes the two the same here, and
    /// a static has a fixed one that cannot move under the call.
    static mut PAIRING: KvmClockPairing = KvmClockPairing {
        sec: 0,
        nsec: 0,
        tsc: 0,
        flags: 0,
        pad: [0; 9],
    };

    /// # Safety
    /// Requires CPL 0.
    pub(super) unsafe fn detect() -> Report {
        let mut report = Report {
            cpuid_bit: cpuid(1, 0)[2] & (1 << 31) != 0,
            ..Default::default()
        };

        // The vendor leaf. Present even on some hypervisors that clear the
        // feature bit, which is why both are read.
        let leaf = cpuid(0x4000_0000, 0);
        if (0x4000_0000..=0x4001_0000).contains(&leaf[0]) {
            report.max_leaf = leaf[0];
            report.signature[0..4].copy_from_slice(&leaf[1].to_le_bytes());
            report.signature[4..8].copy_from_slice(&leaf[2].to_le_bytes());
            report.signature[8..12].copy_from_slice(&leaf[3].to_le_bytes());
        }

        // The active probe, and the guard it needs.
        //
        // `VMCALL` at CPL 0 under a hypervisor that implements it returns.
        // Anywhere else it is `#UD`, and this kernel has no IDT — so the
        // fault is a triple fault, not an error code. "Something looks like a
        // hypervisor" is *not* a sufficient guard: QEMU's TCG advertises the
        // vendor leaf as `TCGTCGTCGTCG` and implements no KVM hypercall at
        // all, which was exactly how this first went wrong.
        //
        // So the signature has to be KVM's specifically. `KVM_HC_*` is KVM's
        // interface; no other hypervisor answers it, and guessing costs the
        // machine.
        //
        // And the instruction has to be the CPU's own: the hypercall HAL
        // (`nanochrono_core::hypercall_hal`) picks `VMCALL` on Intel,
        // Zhaoxin and Centaur, `VMMCALL` on AMD and Hygon, at every boot —
        // the same image boots on either vendor. An unknown vendor gets none.
        // The clock-pairing hypercall passes a 64-bit guest address in RBX;
        // it is a long-mode interface, so i386 reports the hypervisor from
        // CPUID alone.
        #[cfg(target_arch = "x86_64")]
        {
            report.hypercall_insn = nanochrono_core::hypercall_hal::detect();
            if let (true, Some(insn)) =
                (report.signature_str().starts_with("KVMKVMKVM"), report.hypercall_insn)
            {
                // SAFETY: the vendor leaf identifies KVM, which implements this
                // hypercall; the HAL chose this CPU's instruction; the caller
                // guarantees CPL 0.
                unsafe {
                    report.pairing = clock_pairing(insn);
                    report.hypercall_ok = report.pairing.is_some();
                }
            }
        }
        report.hypercalls = super::hypercalls();
        report
    }

#[cfg(target_arch = "x86_64")]
    /// Asks the host to pair its clock with this machine's counter.
    ///
    /// # Safety
    /// Issues `VMCALL`; requires CPL 0 *and* a hypervisor that implements it.
    /// Without one this is `#UD` with no handler.
    unsafe fn clock_pairing(insn: nanochrono_core::hypercall_hal::HypercallInsn) -> Option<ClockPairing> {
        use nanochrono_core::hypercall_hal::HypercallInsn;
        super::HYPERCALLS.fetch_add(1, super::Ordering::Relaxed);

        // The identity map means the virtual address is the physical one.
        let gpa = &raw const PAIRING as u64;
        let ret: i64;

        // SAFETY: the caller guarantees CPL 0 and that a hypervisor is
        // present. The host writes only into the buffer `gpa` names.
        //
        // RBX is shuttled through another register: LLVM reserves it and
        // rejects it as an operand, which is the same reason `cpuid` in
        // `nanochrono-core` is written this way.
        unsafe {
            match insn {
                HypercallInsn::Vmcall => core::arch::asm!(
                    "xchg rbx, {gpa}",
                    "vmcall",
                    "xchg rbx, {gpa}",
                    gpa = inout(reg) gpa => _,
                    inlateout("rax") KVM_HC_CLOCK_PAIRING => ret,
                    in("rcx") KVM_CLOCK_PAIRING_WALLCLOCK,
                    options(nostack),
                ),
                HypercallInsn::Vmmcall => core::arch::asm!(
                    "xchg rbx, {gpa}",
                    "vmmcall",
                    "xchg rbx, {gpa}",
                    gpa = inout(reg) gpa => _,
                    inlateout("rax") KVM_HC_CLOCK_PAIRING => ret,
                    in("rcx") KVM_CLOCK_PAIRING_WALLCLOCK,
                    options(nostack),
                ),
            }
        }
        if ret != 0 {
            return None;
        }

        // SAFETY: the host filled the buffer, and this is the only reader.
        let (sec, nsec, tsc) = unsafe { (PAIRING.sec, PAIRING.nsec, PAIRING.tsc) };
        if sec <= 0 {
            return None;
        }
        Some(ClockPairing {
            host_ns: (sec as u64).saturating_mul(1_000_000_000) + nsec.max(0) as u64,
            counter: tsc,
        })
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use super::{ClockPairing, Report};

    /// `ARM_SMCCC_VERSION`: every conforming implementation answers it.
    const SMCCC_VERSION: u64 = 0x8000_0000;
    /// `ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID`: identifies the hypervisor.
    const VENDOR_HYP_UID: u64 = 0x8600_FF01;
    /// `ARM_SMCCC_VENDOR_HYP_KVM_PTP_FUNC_ID`: host time, the AArch64
    /// counterpart of `KVM_HC_CLOCK_PAIRING`.
    const KVM_PTP: u64 = 0x8600_0001;
    /// `KVM_PTP_VIRT_COUNTER`.
    const KVM_PTP_VIRT_COUNTER: u64 = 0;
    /// `SMCCC_RET_NOT_SUPPORTED`.
    const NOT_SUPPORTED: i64 = -1;
    /// KVM's vendor-hypervisor UID, as the four registers return it
    /// (`28b46fb6-2ec5-11e9-a9ca-4b564d003a74`).
    const KVM_UID: [u64; 4] = [0xB66F_B428, 0xE911_C52E, 0x564B_CAA9, 0x743A_004D];
    /// `ARM_SMCCC_VENDOR_HYP_KVM_FEATURES_FUNC_ID`: bitmap of KVM services.
    const KVM_FEATURES: u64 = 0x8600_0000;
    /// Bit in that bitmap for the PTP service.
    const KVM_FEATURE_PTP: u32 = 1;

    /// # Safety
    /// Requires EL1 or above.
    pub(super) unsafe fn detect() -> Report {
        let mut report = Report::default();

        // AArch64 has no CPUID bit to read, so the hypercall is the probe.
        //
        // At EL2 or EL3 there is nothing above to ask: this kernel *is* the
        // hypervisor level, and an `HVC` would trap straight back into its
        // own vector table. Only EL1 asks.
        //
        // At EL1 the call is safe whether or not anything answers: an
        // UNDEFINED `HVC` is caught by the vector table and comes back as
        // SMCCC "not supported" (see `arch::arm::hvc`). That replaces the old
        // guard — a guess from the counter frequency — which let the call
        // through on bare metal clocked at 1 GHz and refused it under KVM on
        // boards clocked at anything other than 62.5 MHz or 1 GHz.
        if crate::arch::arm::current_el() != 1 {
            return report;
        }

        // SAFETY: at EL1, with the vectors the entry stub installed.
        unsafe {
            let version = hvc(SMCCC_VERSION, 0);
            if version[0] as i64 == NOT_SUPPORTED {
                return report;
            }
            report.hypercall_ok = true;

            let uid = hvc(VENDOR_HYP_UID, 0);
            let is_kvm = uid == KVM_UID;
            if uid[0] as i64 != NOT_SUPPORTED {
                // The four words are reported raw: the byte order that
                // assembles them into a UUID has never been testable here
                // against a real AArch64 guest.
                for (i, word) in uid.iter().take(3).enumerate() {
                    report.signature[i * 4..i * 4 + 4]
                        .copy_from_slice(&(*word as u32).to_le_bytes());
                }
            }

            // The vendor-hypervisor range (0x8600_xxxx) means whatever each
            // vendor says it means, so a KVM function ID is only issued to a
            // hypervisor that identified itself as KVM *and* lists PTP in its
            // feature bitmap. Issued to anything else it is a different call.
            if !is_kvm || hvc(KVM_FEATURES, 0)[0] & (1 << KVM_FEATURE_PTP) == 0 {
                report.hypercalls = super::hypercalls();
                return report;
            }

            let ptp = hvc(KVM_PTP, KVM_PTP_VIRT_COUNTER);
            if (ptp[0] as i64) >= 0 {
                // a0:a1 is the host's ktime in nanoseconds, a2:a3 the guest
                // counter, each as two 32-bit halves — the convention
                // `drivers/ptp/ptp_kvm_arm.c` uses.
                report.pairing = Some(ClockPairing {
                    host_ns: (ptp[0] << 32) | (ptp[1] & 0xFFFF_FFFF),
                    counter: (ptp[2] << 32) | (ptp[3] & 0xFFFF_FFFF),
                });
            }
        }
        report.hypercalls = super::hypercalls();
        report
    }

    /// Counts the call and forwards it to the fault-tolerant stub.
    ///
    /// # Safety
    /// Requires EL1 with the exception vectors installed.
    unsafe fn hvc(function: u64, arg: u64) -> [u64; 4] {
        super::HYPERCALLS.fetch_add(1, super::Ordering::Relaxed);
        // SAFETY: forwarded from this function's own contract.
        unsafe { crate::arch::arm::hvc(function, arg) }
    }
}
