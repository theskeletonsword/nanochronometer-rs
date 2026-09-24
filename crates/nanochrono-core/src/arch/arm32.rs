// SPDX-License-Identifier: Apache-2.0
//! 32-bit ARM (ARMv7-A, and AArch32 on ARMv8): Linux, Android and the
//! freestanding kernel.
//!
//! # The counter
//!
//! The generic timer's virtual count, `CNTVCT` (`mrrc p15, 1, lo, hi, c14`),
//! is the counterpart of AArch64's `CNTVCT_EL0`: fixed rate, stated in
//! `CNTFRQ`. Unlike on AArch64 its availability cannot be assumed:
//!
//! * ARMv7 cores before the virtualization extensions (Cortex-A8, A9) have
//!   no generic timer at all;
//! * where there is one, user-space access depends on `CNTKCTL.PL0VCTEN`,
//!   which the kernel sets only when it uses the timer for the vDSO and no
//!   erratum workaround turned it off.
//!
//! Either way the instruction is undefined in user space where it is not
//! allowed, which is a `SIGILL`, not an error return. No HWCAP bit states
//! the access (`HWCAP_EVTSTRM` only says the event stream is on), so it is
//! probed once, in a forked child that executes the two reads and exits: a
//! `SIGILL` kills the child and answers the question. Without the timer the
//! counter is `CLOCK_MONOTONIC_RAW` in nanoseconds — honest about its
//! resolution, and still vDSO-fast.
//!
//! There is no user-readable cycle counter (`PMCCNTR` needs
//! `PMUSERENR.EN`, which Linux leaves clear); cycles come from
//! `perf_event_open`, as on every other Linux target.

use core::arch::asm;
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// `HWCAP_NEON`, from the kernel's `asm/hwcap.h` (FreeBSD's `machine/elf.h`
/// has the same value).
pub const HWCAP_NEON: u64 = 1 << 12;

/// Whether `CNTVCT`/`CNTFRQ` are readable from this process, and `CNTFRQ`.
#[cfg(feature = "std")]
fn generic_timer() -> Option<u32> {
    static TIMER: OnceLock<Option<u32>> = OnceLock::new();
    *TIMER.get_or_init(probe_generic_timer)
}

/// Executes the timer reads in a child process.
///
/// Between `fork` and `_exit` the child runs only the two instructions — no
/// allocation, no lock — which is what makes this safe to do from a
/// multi-threaded parent. The parent reads the frequency itself once the
/// child has proved the read legal.
#[cfg(feature = "std")]
fn probe_generic_timer() -> Option<u32> {
    if !cfg!(target_feature = "v7") {
        // Before ARMv7 there is no generic timer to ask about.
        return None;
    }
    // SAFETY: `fork` has no preconditions; the child path is async-signal
    // safe (two coprocessor reads and `_exit`).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return None;
    }
    if pid == 0 {
        // A SIGILL here is the expected "no" and must not leave a core file
        // in the caller's working directory.
        let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: `setrlimit` is a plain system call on a valid struct.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
        // SAFETY: in the child. If the reads are not permitted this raises
        // SIGILL, which is the answer.
        let hz = unsafe {
            let _ = cntvct_unchecked();
            cntfrq_unchecked()
        };
        // SAFETY: `_exit` never returns and runs no destructors.
        unsafe { libc::_exit(if hz != 0 { 0 } else { 2 }) };
    }
    let mut status = 0;
    loop {
        // SAFETY: `pid` is our child; `status` is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            break;
        }
        if r < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return None;
        }
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        // SAFETY: the child just proved the read is legal in this process.
        Some(unsafe { cntfrq_unchecked() })
    } else {
        None
    }
}

/// `CNTVCT`.
///
/// # Safety
/// Undefined instruction unless the generic timer exists and PL0 access is
/// enabled; see [`generic_timer`].
#[inline(always)]
unsafe fn cntvct_unchecked() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: forwarded from this function's contract.
    unsafe {
        asm!("mrrc p15, 1, {lo}, {hi}, c14", lo = out(reg) lo, hi = out(reg) hi,
             options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

/// `CNTFRQ`.
///
/// # Safety
/// As [`cntvct_unchecked`].
#[inline(always)]
unsafe fn cntfrq_unchecked() -> u32 {
    let v: u32;
    // SAFETY: forwarded from this function's contract.
    unsafe {
        asm!("mrc p15, 0, {v}, c14, c0, 0", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// `ISB` where the architecture has it (ARMv7), nothing before.
#[inline(always)]
pub fn isb() {
    #[cfg(target_feature = "v7")]
    // SAFETY: no operands, no effect beyond ordering.
    unsafe {
        asm!("isb", options(nostack, preserves_flags));
    }
}

/// `DMB` (ARMv7) or a compiler fence.
#[inline(always)]
pub fn dmb() {
    #[cfg(target_feature = "v7")]
    // SAFETY: as above.
    unsafe {
        asm!("dmb ish", options(nostack, preserves_flags));
    }
    #[cfg(not(target_feature = "v7"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Freestanding (the bare-metal kernel, at PL1): the generic timer is
/// readable without asking — `CNTKCTL` gates only PL0 — so there is nothing
/// to probe. It must exist: this assumes ARMv7 with the virtualization
/// extensions (Cortex-A7/A15 and later, and every AArch32 ARMv8 core), which
/// is what QEMU's `virt` models. On a Cortex-A8/A9 the read is undefined.
#[cfg(not(feature = "std"))]
fn generic_timer() -> Option<u32> {
    // SAFETY: PL1, on a core with the generic timer (see above).
    Some(unsafe { cntfrq_unchecked() })
}

/// Whether the counter is the generic timer (ticks) rather than the
/// monotonic clock (nanoseconds).
pub fn uses_generic_timer() -> bool {
    generic_timer().is_some()
}

/// Raw counter read.
#[inline(always)]
pub fn counter_raw() -> u64 {
    #[cfg(feature = "std")]
    {
        if uses_generic_timer() {
            // SAFETY: `generic_timer` proved the read legal in this process.
            unsafe { cntvct_unchecked() }
        } else {
            crate::platform::monotonic_ns()
        }
    }
    // SAFETY: freestanding at PL1; see the no-std `generic_timer`.
    #[cfg(not(feature = "std"))]
    unsafe {
        cntvct_unchecked()
    }
}

/// Ordered read for either end of an interval.
#[inline(always)]
pub fn counter_isb() -> u64 {
    isb();
    let v = counter_raw();
    isb();
    v
}

/// The counter's rate: `CNTFRQ`, or 1 GHz when the counter is nanoseconds.
pub fn counter_hz() -> Option<u64> {
    match generic_timer() {
        Some(0) => None,
        Some(hz) => Some(hz as u64),
        None => Some(1_000_000_000),
    }
}

/// Back-to-back ordered reads: the measurement floor.
#[inline]
pub fn read_overhead() -> u64 {
    let a = counter_isb();
    let b = counter_isb();
    b.saturating_sub(a)
}

/// Units for `iterations` back-to-back `DMB`s.
#[inline]
pub fn probe_barrier(iterations: u32) -> u64 {
    let n = iterations.max(1);
    let start = counter_isb();
    for _ in 0..n {
        dmb();
    }
    counter_isb().wrapping_sub(start)
}

/// Units for one 64-bit load.
///
/// # Safety
/// `ptr` must be valid for an aligned `u64` read.
#[inline]
pub unsafe fn probe_load(ptr: *const u64) -> u64 {
    let start = counter_isb();
    // SAFETY: forwarded from this function's contract.
    let v = unsafe { core::ptr::read_volatile(ptr) };
    let end = counter_isb();
    core::hint::black_box(v);
    end.wrapping_sub(start)
}

/// Units to follow `steps` links of a pointer-chase list.
///
/// # Safety
/// `first` must head a chain of at least `steps` valid links.
#[inline]
pub unsafe fn probe_pointer_chase(first: *const *const u8, steps: usize) -> u64 {
    let start = counter_isb();
    let mut p = first;
    for _ in 0..steps {
        if p.is_null() {
            break;
        }
        // SAFETY: forwarded from this function's contract.
        p = unsafe { *p } as *const *const u8;
    }
    let end = counter_isb();
    core::hint::black_box(p);
    end.wrapping_sub(start)
}

/// NEON probes.
///
/// The Rust ARMv7 targets build without NEON (`-neon`), so each block turns
/// the assembler's NEON support on for itself with `.fpu neon` and clobbers
/// the D registers it uses — `d0`-`d3` are `q0`/`q1` — which the VFP register
/// class the target does have can name. The runtime gate is `HWCAP_NEON`.
#[cfg(feature = "simd")]
pub mod neon {
    use super::*;

    #[inline]
    pub fn counter() -> u64 {
        counter_isb()
    }

    /// # Safety
    /// Requires NEON. `ptr` must have 16 readable bytes.
    #[inline]
    pub unsafe fn vector_load_units(ptr: *const u8) -> u64 {
        let start = counter_isb();
        // SAFETY: forwarded from this function's contract.
        unsafe {
            asm!(
                ".fpu neon",
                "vld1.8 {{d0, d1}}, [{a}]",
                a = in(reg) ptr,
                out("d0") _, out("d1") _,
                options(nostack, preserves_flags, readonly),
            );
        }
        counter_isb().wrapping_sub(start)
    }

    /// # Safety
    /// Requires NEON. `a`/`b` must have 16 readable bytes and `out` 16
    /// writable bytes.
    #[inline]
    pub unsafe fn vector_xor_units(a: *const u8, b: *const u8, out: *mut u8) -> u64 {
        let start = counter_isb();
        // SAFETY: forwarded from this function's contract.
        unsafe {
            asm!(
                ".fpu neon",
                "vld1.8 {{d0, d1}}, [{a}]",
                "vld1.8 {{d2, d3}}, [{b}]",
                "veor q0, q0, q1",
                "vst1.8 {{d0, d1}}, [{o}]",
                a = in(reg) a,
                b = in(reg) b,
                o = in(reg) out,
                out("d0") _, out("d1") _, out("d2") _, out("d3") _,
                options(nostack, preserves_flags),
            );
        }
        counter_isb().wrapping_sub(start)
    }
}

/// Scalar ALU loop — the ARM32 baseline.
#[inline(never)]
pub fn kernel_scalar(loops: usize) -> u64 {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..loops {
        x = x.rotate_left(57) ^ 0xD1B5_4A32_D192_ED03;
        x = core::hint::black_box(x.wrapping_add(0xD1B5_4A32_D192_ED03));
    }
    x
}

/// NEON integer loop.
///
/// # Safety
/// Requires NEON.
#[cfg(feature = "simd")]
#[inline(never)]
pub unsafe fn kernel_neon(loops: usize) -> u64 {
    let mut acc = [0x5Au8; 16];
    for i in 0..loops {
        acc[0] = i as u8;
        // SAFETY: NEON per the contract; `acc` is 16 bytes.
        unsafe {
            asm!(
                ".fpu neon",
                "vld1.8 {{d0, d1}}, [{p}]",
                "vadd.i32 q1, q0, q0",
                "veor q0, q0, q1",
                "vst1.8 {{d0, d1}}, [{p}]",
                p = in(reg) acc.as_mut_ptr(),
                out("d0") _, out("d1") _, out("d2") _, out("d3") _,
                options(nostack, preserves_flags),
            );
        }
    }
    u64::from_ne_bytes(acc[..8].try_into().unwrap_or([0; 8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counter_moves_and_has_a_rate() {
        let a = counter_isb();
        let mut x = 0u64;
        for i in 0..100_000u64 {
            x = core::hint::black_box(x.wrapping_add(i));
        }
        assert!(counter_isb() > a);
        assert!(counter_hz().is_some_and(|hz| hz > 0));
    }
}
