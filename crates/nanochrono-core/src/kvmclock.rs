// SPDX-License-Identifier: Apache-2.0
//! Host-to-guest time synchronisation inside a KVM guest.
//!
//! A guest's own clock is not the host's. The two drift, and a measurement
//! that spans a VM exit is denominated in a timebase the workload does not
//! share with anything outside the VM. Closing that gap needs a timestamp
//! taken on both sides of the boundary at the same instant, and only the
//! hypervisor can produce one.
//!
//! # Which ring this needs
//!
//! The hypercalls that fetch such a pair — `VMCALL`/`VMMCALL` carrying
//! `KVM_HC_CLOCK_PAIRING` on x86, `HVC` carrying the KVM PTP function on
//! AArch64 — are privileged. `VMCALL` at CPL 3 raises `#UD`; `HVC` at EL0 is
//! an undefined instruction. There is no unprivileged form of either.
//!
//! That would put this in the kernel module, except that Linux already ships
//! a driver which makes the call and publishes the answer: `ptp_kvm` performs
//! the hypercall in ring 0 and exposes the paired timestamps through a PTP
//! character device. So the whole feature is reachable from ring 3 after all,
//! through `PTP_SYS_OFFSET_PRECISE`, and this module needs no module of its
//! own.
//!
//! Two distinct facilities are covered here, and they answer different
//! questions:
//!
//! * **`kvm-clock`** — the paravirtual clocksource. When the kernel has
//!   selected it, `CLOCK_MONOTONIC` is already derived from the host's
//!   timebase, through a page the host maintains and the vDSO reads. Nothing
//!   has to be done to use it; what matters is *knowing*, because it means a
//!   TSC calibrated against `CLOCK_MONOTONIC` was calibrated against the
//!   host's notion of time rather than an independent one.
//! * **`ptp_kvm`** — an explicit pairing. It answers "what did the host's
//!   clock read at the instant my counter read X", which `kvm-clock` does not,
//!   and it is what an absolute offset has to be computed from.

/// How the guest's nanoseconds relate to the host's.
#[derive(Debug, Clone, PartialEq)]
pub struct HostSync {
    /// The kernel selected a paravirtual clocksource, so `CLOCK_MONOTONIC`
    /// already comes from the host's timebase.
    pub paravirtual_clocksource: Option<String>,
    /// A pairing read from `ptp_kvm`, when the driver is present.
    pub pairing: Option<ClockPairing>,
}

use core::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

/// How many times this process has asked the host for its clock.
///
/// # Why this is counted, and kept at one
///
/// `PTP_SYS_OFFSET_PRECISE` on the `ptp_kvm` device is not a file read. The
/// driver services it by making the guest issue `KVM_HC_CLOCK_PAIRING` — a
/// `VMCALL` on x86, an `HVC` on AArch64 — which traps out of this virtual
/// machine and into the host kernel, where it is serviced on a CPU that other
/// tenants are also using.
///
/// On a laptop that costs microseconds and nobody notices. On a shared VPS —
/// an Azure or GCE instance sitting on a host with a dozen neighbours — a
/// program that did it per measurement would be taking a scheduling event out
/// of somebody else's machine, thousands of times a second, to answer a
/// question whose answer does not change. That is not a performance problem
/// for this program; it is this program being a bad neighbour.
///
/// So the pairing is read **once** per process, by [`cached`], and every
/// later caller gets the same value back. The offset between a host's clock
/// and a guest's is established at the start and applied as arithmetic
/// afterwards, exactly as the bare-metal kernel does it.
///
/// The count is exposed rather than merely promised, so that "once" is
/// something a user can check rather than something this documentation
/// asserts. See [`host_queries`].
static HOST_QUERIES: AtomicU32 = AtomicU32::new(0);

/// How many host-clock pairings this process has requested. Should be one.
pub fn host_queries() -> u32 {
    HOST_QUERIES.load(Ordering::Relaxed)
}

/// The process-wide host synchronisation, read once.
///
/// Every caller that wants to know how this machine relates to its host
/// should come through here. Calling [`HostSync::read`] directly issues a
/// fresh hypercall, which is right exactly once — at startup — and wrong
/// everywhere else. See [`HOST_QUERIES`].
pub fn cached() -> &'static HostSync {
    static CACHE: OnceLock<HostSync> = OnceLock::new();
    CACHE.get_or_init(HostSync::read)
}

impl HostSync {
    /// Reads whatever synchronisation this machine offers.
    pub fn read() -> HostSync {
        HostSync {
            paravirtual_clocksource: paravirtual_clocksource(),
            pairing: ClockPairing::read(),
        }
    }

    /// Whether the guest's monotonic clock is derived from the host's.
    ///
    /// True under `kvm-clock` and the other paravirtual clocksources: the
    /// guest is not keeping independent time, it is reading the host's.
    pub fn monotonic_follows_host(&self) -> bool {
        self.paravirtual_clocksource.is_some()
    }

    /// What this means for a measurement, in one line.
    pub fn advice(&self) -> &'static str {
        match (&self.pairing, self.monotonic_follows_host()) {
            (Some(_), _) => {
                "Host and guest clocks can be paired: absolute timestamps are comparable \
                 across the VM boundary."
            }
            (None, true) => {
                "The monotonic clock already comes from the host, so intervals are sound, \
                 but nothing here can state an absolute offset. Load ptp_kvm for that."
            }
            (None, false) => {
                // Worded to hold on bare metal as well: this type cannot tell
                // the two apart, and claiming to be in a guest would be wrong
                // on most machines that reach here.
                "No host clock to synchronise against: either this is bare metal, or the \
                 guest keeps time independently of its host."
            }
        }
    }
}

/// The paravirtual clocksource the kernel selected, if it selected one.
///
/// These are the names of clocksources whose ticks come from the host rather
/// than from hardware the guest owns.
fn paravirtual_clocksource() -> Option<String> {
    const PARAVIRTUAL: &[&str] = &["kvm-clock", "xen", "hyperv_clocksource_tsc_page", "vmware"];

    let current =
        std::fs::read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource")
            .ok()?;
    let current = current.trim().to_string();
    PARAVIRTUAL
        .iter()
        .any(|name| current == *name)
        .then_some(current)
}

/// One host/guest timestamp pair, captured together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockPairing {
    /// The host clock, in nanoseconds.
    pub host_ns: u64,
    /// This guest's `CLOCK_REALTIME` at the same instant, in nanoseconds.
    pub guest_realtime_ns: u64,
    /// This guest's `CLOCK_MONOTONIC_RAW` at the same instant.
    pub guest_monotonic_raw_ns: u64,
}

impl ClockPairing {
    /// Reads a pairing from the `ptp_kvm` device, if one exists.
    ///
    /// Returns `None` on a machine that is not a KVM guest, on a guest where
    /// `ptp_kvm` is not loaded, and where the device exists but the calling
    /// user cannot open it — all of which are ordinary, so none is an error.
    #[cfg(target_os = "linux")]
    pub fn read() -> Option<ClockPairing> {
        let index = kvm_ptp_index()?;
        HOST_QUERIES.fetch_add(1, Ordering::Relaxed);
        read_precise_offset(index)
    }

    /// No `ptp_kvm` outside Linux: the driver and the device it registers are
    /// Linux's, and nothing on another platform stands in for them.
    #[cfg(not(target_os = "linux"))]
    pub fn read() -> Option<ClockPairing> {
        None
    }

    /// How far the host's clock is ahead of the guest's, in nanoseconds.
    ///
    /// Signed: a negative value means the guest is ahead. This is the number
    /// to add to a guest timestamp to express it on the host's timebase.
    pub fn host_offset_ns(&self) -> i64 {
        self.host_ns as i64 - self.guest_realtime_ns as i64
    }
}

/// Finds the PTP device backed by the KVM clock.
#[cfg(target_os = "linux")]
///
/// Matched by `clock_name` rather than by index: a guest with a NIC that also
/// offers PTP will have several, and `/dev/ptp0` is whichever registered
/// first. The driver names its clock, so the name is what identifies it.
fn kvm_ptp_index() -> Option<u32> {
    let entries = std::fs::read_dir("/sys/class/ptp").ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = std::fs::read_to_string(path.join("clock_name")).ok() else {
            continue;
        };
        if !names_the_kvm_clock(&name) {
            continue;
        }
        let index = path
            .file_name()
            .and_then(|f| f.to_str())
            .and_then(|f| f.strip_prefix("ptp"))
            .and_then(|n| n.parse().ok())?;
        return Some(index);
    }
    None
}

/// Whether a PTP device's `clock_name` is the one `ptp_kvm` registers.
#[cfg(target_os = "linux")]
///
/// The driver calls itself "KVM virtual PTP". Matched on both words rather
/// than as an exact string, so a wording change does not silently turn the
/// feature off; and on both rather than either, because a NIC's PTP clock is
/// also named "…PTP" and is not host time.
fn names_the_kvm_clock(name: &str) -> bool {
    let lowered = name.trim().to_ascii_lowercase();
    lowered.contains("kvm") && lowered.contains("ptp")
}

/// `struct ptp_clock_time` from `include/uapi/linux/ptp_clock.h`.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct PtpClockTime {
    sec: i64,
    nsec: u32,
    reserved: u32,
}

#[cfg(target_os = "linux")]
impl PtpClockTime {
    fn as_ns(self) -> u64 {
        (self.sec.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(self.nsec as u64)
    }
}

/// `struct ptp_sys_offset_precise`, 64 bytes.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct PtpSysOffsetPrecise {
    device: PtpClockTime,
    sys_realtime: PtpClockTime,
    sys_monoraw: PtpClockTime,
    reserved: [u32; 4],
}

/// `PTP_SYS_OFFSET_PRECISE`: `_IOWR('=', 8, struct ptp_sys_offset_precise)`.
///
/// Spelled out rather than computed, because the encoding is fixed ABI and a
/// wrong value here is a call to some other driver's ioctl.
///
/// The same number on every Linux architecture, including the ones with a
/// different `_IOC` layout: PowerPC, MIPS and SPARC put the direction in
/// three bits at 29 with `READ|WRITE = 6`, which is `0xC000_0000` — the same
/// bits as the generic `3 << 30` — and 64 bytes fits both size fields.
#[cfg(target_os = "linux")]
const PTP_SYS_OFFSET_PRECISE: libc::c_ulong = 0xc040_3d08;

/// Asks the driver for a host/guest pair captured together.
#[cfg(target_os = "linux")]
fn read_precise_offset(index: u32) -> Option<ClockPairing> {
    use std::os::fd::AsRawFd;

    let path = format!("/dev/ptp{index}");
    // Read-only: the pairing is a query, and asking for write access would
    // fail on a device the caller is only permitted to read.
    let file = std::fs::File::open(&path).ok()?;

    let mut offset = PtpSysOffsetPrecise::default();
    // SAFETY: the fd is open, the request code matches the struct this passes,
    // and `offset` is a live, correctly sized out-parameter.
    let status = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            // glibc takes the request as `c_ulong`, musl as `c_int`; the bit
            // pattern is what the kernel decodes, so it is cast, not converted.
            PTP_SYS_OFFSET_PRECISE as _,
            &mut offset as *mut PtpSysOffsetPrecise,
        )
    };
    if status != 0 {
        return None;
    }

    Some(ClockPairing {
        host_ns: offset.device.as_ns(),
        guest_realtime_ns: offset.sys_realtime.as_ns(),
        guest_monotonic_raw_ns: offset.sys_monoraw.as_ns(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever this machine is, the report has to be internally consistent.
    #[test]
    fn host_sync_is_self_consistent() {
        // The cache, not a fresh read: on a KVM guest `HostSync::read` is a
        // hypercall, and a test suite is no more entitled to spend one per
        // run than a measurement loop is.
        let sync = cached();
        assert_eq!(
            sync.monotonic_follows_host(),
            sync.paravirtual_clocksource.is_some()
        );
        assert!(!sync.advice().is_empty());

        // A pairing can only come from a guest, so it implies a hypervisor.
        if sync.pairing.is_some() {
            assert!(
                crate::hypervisor::cached().is_virtualized(),
                "a KVM PTP pairing was read on a machine reported as bare metal"
            );
        }
    }

    /// Bare metal has no paravirtual clocksource, and this machine's
    /// clocksource file is readable either way.
    #[test]
    fn only_paravirtual_clocksources_are_named() {
        if let Some(name) = paravirtual_clocksource() {
            assert!(
                ["kvm-clock", "xen", "hyperv_clocksource_tsc_page", "vmware"].contains(&&*name),
                "{name} is not a paravirtual clocksource"
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn nanosecond_conversion_saturates_rather_than_wrapping() {
        let t = PtpClockTime {
            sec: 1_700_000_000,
            nsec: 123_456_789,
            reserved: 0,
        };
        assert_eq!(t.as_ns(), 1_700_000_000_123_456_789);

        // A negative second count is not a time this can express; it must not
        // wrap into an enormous positive one.
        let negative = PtpClockTime {
            sec: -5,
            nsec: 0,
            reserved: 0,
        };
        assert_eq!(negative.as_ns(), 0);
    }

    /// The struct is ABI: the kernel writes into it by offset.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_offset_struct_matches_the_kernel_layout() {
        assert_eq!(std::mem::size_of::<PtpClockTime>(), 16);
        assert_eq!(std::mem::size_of::<PtpSysOffsetPrecise>(), 64);
        // The ioctl encodes the size it expects; if they disagree the kernel
        // rejects the call, so this pins the number the constant was built
        // from.
        assert_eq!(
            (PTP_SYS_OFFSET_PRECISE >> 16) & 0x3fff,
            std::mem::size_of::<PtpSysOffsetPrecise>() as libc::c_ulong
        );
    }

    /// The device is chosen by name, because index order is not stable and a
    /// NIC's PTP clock is not the host's.
    #[test]
    #[cfg(target_os = "linux")]
    fn only_the_kvm_clock_is_selected() {
        assert!(names_the_kvm_clock("KVM virtual PTP"));
        assert!(names_the_kvm_clock("  kvm virtual ptp\n"));

        // Real names from other PTP providers, which must all be refused.
        for other in [
            "iwlwifi-PTP",
            "ptp_vmw",
            "i40e-PTP",
            "mlx5_ptp",
            "ptp_dfl_tod",
            "",
        ] {
            assert!(!names_the_kvm_clock(other), "{other} was accepted");
        }
    }

    /// A pairing, when there is one, has to describe the same instant.
    #[test]
    fn a_pairing_describes_one_instant() {
        let Some(pairing) = ClockPairing::read() else {
            return;
        };
        assert!(pairing.host_ns > 0);
        assert!(pairing.guest_realtime_ns > 0);
        // Both sides are wall clocks on the same machine: an offset larger
        // than a day means the two fields were not read from one capture.
        assert!(
            pairing.host_offset_ns().abs() < 86_400_000_000_000,
            "host and guest are a day apart: {} ns",
            pairing.host_offset_ns()
        );
    }
}

#[cfg(test)]
mod once_tests {
    use super::*;

    /// The pairing is read once per process, however many times it is asked
    /// for.
    ///
    /// The point is not performance. `PTP_SYS_OFFSET_PRECISE` is serviced by
    /// a hypercall out of this guest and into a host that other tenants are
    /// running on, so a program that asked per measurement would be taking
    /// scheduling events out of somebody else's machine to re-answer a
    /// question whose answer does not change.
    ///
    /// Holds on a machine with no `ptp_kvm` too: there the count stays at
    /// zero, which is also not more than one.
    #[test]
    fn the_host_is_asked_at_most_once_however_often_it_is_read() {
        // Measured as a delta rather than against zero. The whole test binary
        // is one process and its tests run in parallel, so the count is
        // shared: an absolute assertion here would be asserting something
        // about the rest of the suite, and would pass or fail by scheduling
        // order. What has to hold is the invariant that matters — that going
        // through the cache never asks again.
        let _ = cached();
        let after_first = host_queries();

        for _ in 0..1_000 {
            let _ = cached();
        }

        assert_eq!(
            host_queries(),
            after_first,
            "a thousand reads through the cache issued {} further hypercall(s); \
             the host must be asked once and the offset applied as arithmetic",
            host_queries() - after_first
        );
        assert!(
            after_first <= 1,
            "initialising the cache took {after_first} hypercalls"
        );
    }

    /// And the cache hands back the same reading every time, rather than a
    /// fresh one that happens not to have been counted.
    #[test]
    fn the_cached_pairing_is_stable() {
        let first = cached().pairing;
        for _ in 0..100 {
            assert_eq!(cached().pairing, first);
        }
    }
}
