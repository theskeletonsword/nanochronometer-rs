// SPDX-License-Identifier: MIT

//! Builds the `key=value` report handed back to user mode, mirroring the
//! Linux module's `/proc/nanochrono`.
//!
//! # Once per load
//!
//! The probes — the hypercall, the `CPUID` exit-cost loop — make the guest
//! exit to its hypervisor. They run once, in `DriverEntry`, and the text is
//! cached; `IOCTL_NANOCHRONO_REPORT` copies the cache and never probes. On a
//! cloud host (Azure, GCP, AWS, Vultr…) a guest exiting in a loop reads as
//! abuse and gets throttled or banned; a user-mode program polling the report
//! must not be able to cause that.
//!
//! `IOCTL_NANOCHRONO_REPROBE` runs them again, at most once per cooldown
//! (10 s by default), enforced here. `IOCTL_NANOCHRONO_SET_COOLDOWN` with 0
//! removes the limit — the caller then assumes the provider's reaction.

use core::cell::UnsafeCell;
use core::fmt::{self, Write};
use core::ptr;

use crate::hypercall;
use crate::nt;

/// Maximum bytes of report.
pub const REPORT_CAPACITY: usize = 1500;

/// Seconds between re-probes unless changed by IOCTL.
pub const DEFAULT_COOLDOWN_S: u32 = 10;

/// A `core::fmt::Write` sink over a byte slice; truncates when full.
struct ReportBuffer<'a> {
    data: &'a mut [u8],
    len: usize,
}

impl<'a> ReportBuffer<'a> {
    fn new(data: &'a mut [u8]) -> Self {
        Self { data, len: 0 }
    }
}

impl<'a> fmt::Write for ReportBuffer<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let src = s.as_bytes();
        let avail = self.data.len().saturating_sub(self.len);
        let n = src.len().min(avail);
        self.data[self.len..self.len + n].copy_from_slice(&src[..n]);
        self.len += n;
        Ok(())
    }
}

struct Cache {
    text: [u8; REPORT_CAPACITY],
    len: usize,
    probes: u32,
    /// `KeQueryPerformanceCounter` at the last probe.
    last_qpc: i64,
    cooldown_s: u32,
    /// A re-probe is running outside the lock.
    probing: bool,
}

/// The cache and its `KSPIN_LOCK`. Every access holds the lock except the
/// single-threaded `init` in `DriverEntry`.
struct Shared {
    lock: UnsafeCell<usize>,
    cache: UnsafeCell<Cache>,
}

// SAFETY: all access goes through `locked`, which holds the spin lock.
unsafe impl Sync for Shared {}

static SHARED: Shared = Shared {
    lock: UnsafeCell::new(0),
    cache: UnsafeCell::new(Cache {
        text: [0; REPORT_CAPACITY],
        len: 0,
        probes: 0,
        last_qpc: 0,
        cooldown_s: DEFAULT_COOLDOWN_S,
        probing: false,
    }),
};

fn locked<R>(f: impl FnOnce(&mut Cache) -> R) -> R {
    // SAFETY: the lock is a zero-initialised KSPIN_LOCK (what
    // KeInitializeSpinLock produces); the cache is only touched under it.
    // The closures below never call anything that needs IRQL < DISPATCH.
    unsafe {
        let irql = nt::KeAcquireSpinLockRaiseToDpc(SHARED.lock.get());
        let r = f(&mut *SHARED.cache.get());
        nt::KeReleaseSpinLock(SHARED.lock.get(), irql);
        r
    }
}

/// `(counter, frequency)`.
fn qpc() -> (i64, i64) {
    let mut freq = nt::LargeInteger { quad_part: 0 };
    // SAFETY: kernel export; `freq` is a valid out-pointer.
    let now = unsafe { nt::KeQueryPerformanceCounter(&mut freq) };
    (now.quad_part, freq.quad_part.max(1))
}

fn store(text: &[u8], len: usize) {
    let now = qpc().0;
    locked(|c| {
        c.text[..len].copy_from_slice(&text[..len]);
        c.len = len;
        c.probes = c.probes.saturating_add(1);
        c.last_qpc = now;
        c.probing = false;
    });
}

/// The one probe of this load. Called from `DriverEntry` (PASSIVE_LEVEL).
pub fn init() {
    let mut buf = [0u8; REPORT_CAPACITY];
    let len = probe(&mut buf);
    store(&buf, len);
}

/// Milliseconds until a re-probe is allowed, and the cooldown.
fn wait_ms(c: &Cache, now: i64, freq: i64) -> u64 {
    if c.cooldown_s == 0 {
        return 0;
    }
    let elapsed_ms = (now.saturating_sub(c.last_qpc).max(0) as u128 * 1000 / freq as u128) as u64;
    (c.cooldown_s as u64 * 1000).saturating_sub(elapsed_ms)
}

/// Runs the probes again if the cooldown allows. PASSIVE_LEVEL.
pub fn reprobe() -> nt::NTSTATUS {
    let (now, freq) = qpc();
    let allowed = locked(|c| {
        if c.probing || wait_ms(c, now, freq) > 0 {
            return false;
        }
        c.probing = true;
        true
    });
    if !allowed {
        return nt::STATUS_DEVICE_BUSY;
    }
    let mut buf = [0u8; REPORT_CAPACITY];
    let len = probe(&mut buf);
    store(&buf, len);
    nt::dbg_print("NanoChronometer: re-probed\r\n");
    nt::STATUS_SUCCESS
}

/// Sets the cooldown; 0 removes it (the caller assumes the provider's
/// reaction to repeated exits).
pub fn set_cooldown(seconds: u32) {
    locked(|c| c.cooldown_s = seconds);
    if seconds == 0 {
        nt::dbg_print(
            "NanoChronometer: re-probe cooldown disabled; the user assumes the provider's reaction\r\n",
        );
    }
}

/// Copies the cached report plus the bookkeeping into `out`. Never probes.
pub fn serve(out: &mut [u8]) -> usize {
    let (now, freq) = qpc();
    let mut local = [0u8; REPORT_CAPACITY];
    let (len, probes, age_ms, cooldown_s, next_ms) = locked(|c| {
        local[..c.len].copy_from_slice(&c.text[..c.len]);
        let age_ms = (now.saturating_sub(c.last_qpc).max(0) as u128 * 1000 / freq as u128) as u64;
        (c.len, c.probes, age_ms, c.cooldown_s, wait_ms(c, now, freq))
    });
    let mut r = ReportBuffer::new(out);
    let _ = r.write_str(core::str::from_utf8(&local[..len]).unwrap_or(""));
    let _ = writeln!(r, "hypercall_probes={probes}");
    let _ = writeln!(r, "hypercall_age_ms={age_ms}");
    let _ = writeln!(r, "hypercall_cooldown_s={cooldown_s}");
    let _ = writeln!(r, "hypercall_next_ms={next_ms}");
    if cooldown_s == 0 {
        let _ = writeln!(
            r,
            "hypercall_warning=re-probe limit disabled: repeated VM exits may get this guest throttled or banned by the provider"
        );
    }
    let _ = writeln!(r, "done_ok=1");
    r.len
}

/// Runs every probe into `out`, returning the bytes produced.
fn probe(out: &mut [u8]) -> usize {
    let mut r = ReportBuffer::new(out);

    let _ = writeln!(r, "version=2");

    #[cfg(target_arch = "x86_64")]
    let _ = writeln!(r, "arch=x86");
    #[cfg(target_arch = "aarch64")]
    let _ = writeln!(r, "arch=arm64");

    // KeIsHypervisorPresent() is the WDM hypervisor hint. It is combined with
    // the CPUID bit before any hypercall, because unlike the Linux module
    // (which has __ex_table fixups) a MinGW driver cannot recover from a
    // fault caused by executing a hypercall where none is handled.
    // SAFETY: kernel ABI import.
    let hv_present = unsafe { nt::KeIsHypervisorPresent() != 0 };
    let _ = writeln!(r, "hv_present={}", u8::from(hv_present));

    #[cfg(target_arch = "x86_64")]
    {
        let _ = writeln!(r, "cpuid_hypervisor_bit={}", u8::from(hypercall::hypervisor_present()));
        let _ = writeln!(r, "vmx_available={}", u8::from(hypercall::vmx_available()));
        let _ = writeln!(r, "svm_available={}", u8::from(hypercall::svm_available()));

        let vendor = hypercall::vendor();
        let _ = writeln!(r, "cpuid_vendor={}", core::str::from_utf8(&vendor[..12]).unwrap_or("?"));
        let sig = hypercall::hv_signature();
        let sig_len = sig.iter().position(|&b| b == 0).unwrap_or(12);
        let _ = writeln!(r, "hv_signature={}", core::str::from_utf8(&sig[..sig_len]).unwrap_or("?"));

        // The hypercall HAL: one instruction, the one this CPU's vendor
        // defines (VMCALL: Intel, Zhaoxin, Centaur; VMMCALL: AMD, Hygon),
        // chosen at this start — never the other one, and none for an
        // unknown vendor. Then only under a hypervisor known to return from
        // an unknown hypercall.
        let insn = hypercall::hypercall_insn();
        let _ = writeln!(r, "hypercall_insn={}", insn.map_or("none", |i| i.name()));
        let under_hv = hypercall::hypervisor_present() || hv_present;
        match insn {
            Some(i) if under_hv && hypercall::hypercall_known_safe(&sig) => {
                // SAFETY: gated as above; see hypercall.rs.
                let ret = unsafe {
                    match i {
                        hypercall::HypercallInsn::Vmcall => hypercall::probe_vmcall(),
                        hypercall::HypercallInsn::Vmmcall => hypercall::probe_vmmcall(),
                    }
                };
                let _ = writeln!(r, "{}_ok=1", i.name());
                let _ = writeln!(r, "hypercall_result={}", ret as i64);
            }
            Some(_) if under_hv => {
                let _ = writeln!(r, "hypercall_skipped=hypervisor not known to return from an unknown hypercall");
            }
            None if under_hv => {
                let _ = writeln!(r, "hypercall_skipped=unknown CPU vendor: no hypercall instruction chosen");
            }
            _ => {}
        }

        // Every CPUID exits under VMX/SVM: the minimum over 128 is the exit
        // round trip, in TSC cycles, as the Linux module measures it.
        let _ = writeln!(r, "exit_cycles={}", hypercall::exit_cost_cycles(128));
    }

    #[cfg(target_arch = "aarch64")]
    {
        let el = hypercall::current_el();
        let _ = writeln!(r, "current_el={el}");

        // HVC is only meaningful at EL1 under a hypervisor (at EL2 it is a
        // call into this very kernel).
        if hv_present && el == 1 {
            // SAFETY: KeIsHypervisorPresent() reported a hypervisor and we are
            // at EL1; SMCCC defines an unknown ID as returning -1.
            let uid = unsafe { hypercall::probe_hvc(hypercall::SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID) };
            let _ = writeln!(r, "hvc_ok=1");
            if uid[0] as i64 != -1 {
                // SMCCC returns the UID as four 32-bit words in w0..w3.
                let _ = writeln!(
                    r,
                    "hvc_vendor_uid={:08x} {:08x} {:08x} {:08x}",
                    uid[0] as u32, uid[1] as u32, uid[2] as u32, uid[3] as u32
                );
            }
        } else {
            let _ = writeln!(r, "hvc_ok=0");
        }
    }

    phys_memory_demo(&mut r);
    r.len
}

/// Runs the physical-memory demo: allocate one nonpaged page, resolve its
/// physical address, map and read it back, then release everything — the WDM
/// analogue of the Linux module's `virt_to_phys` / `ioremap` probe.
fn phys_memory_demo(r: &mut ReportBuffer<'_>) {
    const PAGE: usize = 4 * 1024;
    // SAFETY: NonPagedPoolNx allocation; freed in every path below.
    unsafe {
        let va = nt::ExAllocatePoolWithTag(nt::POOL_NON_PAGED_NX, PAGE, nt::POOL_TAG);
        if va.is_null() {
            let _ = writeln!(r, "phys_ok=0");
            let _ = writeln!(r, "phys_error=alloc_failed");
            return;
        }
        // Write a recognizable pattern so the readback is meaningful.
        ptr::write_volatile(va.cast::<u32>(), 0x4E414E4F);
        // Barrier so the store is visible before the MMIO-style read.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        let phys = nt::MmGetPhysicalAddress(va);
        let mapped = nt::MmMapIoSpace(phys, PAGE, nt::MM_NON_CACHED);
        if mapped.is_null() {
            let _ = writeln!(r, "phys_ok=0");
            let _ = writeln!(r, "phys_error=map_failed");
            let _ = writeln!(r, "phys_addr={:#x}", phys.quad_part as u64);
            nt::ExFreePoolWithTag(va, nt::POOL_TAG);
            return;
        }
        let readback = ptr::read_volatile(mapped.cast::<u32>());
        nt::MmUnmapIoSpace(mapped, PAGE);
        nt::ExFreePoolWithTag(va, nt::POOL_TAG);

        let _ = writeln!(r, "phys_ok=1");
        let _ = writeln!(r, "phys_addr={:#x}", phys.quad_part as u64);
        let _ = writeln!(r, "phys_readback={:#x}", readback);
    }
}
