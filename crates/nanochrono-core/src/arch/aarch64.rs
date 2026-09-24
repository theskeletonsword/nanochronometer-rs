// SPDX-License-Identifier: Apache-2.0
//! AArch64 counter and probe primitives.
//!
//! Mirrors [`super::x86_64`] one-for-one so the dispatchers above can stay
//! architecture-agnostic. Everything the old `asm/arm64/**/*.S` files emitted
//! lives here as `core::arch::asm!`.
//!
//! The architectural counter is `CNTVCT_EL0`, which ticks at `CNTFRQ_EL0` Hz
//! (typically 24 MHz) rather than at core frequency. That makes its raw units
//! coarser than an x86 TSC cycle but immune to frequency scaling, so no
//! invariance check is needed.

use core::arch::asm;

// ---------------------------------------------------------------------------
// Counter reads
// ---------------------------------------------------------------------------

/// Raw `CNTVCT_EL0`. No barrier: reads may be reordered around it.
#[inline(always)]
pub fn cntvct_raw() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {v}, cntvct_el0", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// `ISB` + `CNTVCT_EL0`: the ordered read used for interval boundaries.
#[inline(always)]
pub fn cntvct_isb() -> u64 {
    let v: u64;
    unsafe {
        asm!(
            "isb",
            "mrs {v}, cntvct_el0",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// `DSB SY` + `ISB` + `CNTVCT_EL0` + `ISB`: the fully ordered virtual read.
///
/// The mirror of [`cntpct_ordered`]: the same barriers around the *virtual*
/// counter, which reads `CNTPCT_EL0` minus `CNTVOFF_EL2`. A hypervisor sets
/// that offset so a guest sees a timeline starting when the guest did, so the
/// virtual counter is the safe default for any kernel that may run inside
/// one — the physical counter would expose (and splice together) the host's
/// real timeline.
///
/// `DSB SY` waits for memory traffic so the counter is sampled at the end of
/// the bracketed work, exactly as [`cntpct_ordered`] does for its counter.
#[inline(always)]
pub fn cntvct_ordered() -> u64 {
    let v: u64;
    // SAFETY: the barriers have no operands or memory effects, and CNTVCT_EL0
    // is readable at EL0 when CNTKCTL_EL1.EL0VCTEN allows it (always at EL1).
    unsafe {
        asm!(
            "dsb sy",
            "isb",
            "mrs {v}, cntvct_el0",
            "isb",
            v = out(reg) v,
            options(nostack, preserves_flags),
        );
    }
    v
}

/// Raw `CNTPCT_EL0`, the *physical* counter.
///
/// `CNTVCT_EL0` is the virtual counter: it reads `CNTPCT_EL0` minus
/// `CNTVOFF_EL2`, an offset a hypervisor sets so a guest sees a timeline
/// starting when the guest did. That is the right counter for a hosted
/// process, which lives inside whatever timeline it was given.
///
/// A freestanding kernel is not inside one. It runs at EL1 with no EL2 above
/// it, so the offset is nothing but an extra subtraction against a value that
/// may not be zero if firmware left it set — and the physical counter is what
/// the hardware actually ticks.
#[inline(always)]
pub fn cntpct_raw() -> u64 {
    let v: u64;
    // SAFETY: CNTPCT_EL0 is readable at EL0 when CNTKCTL_EL1.EL0PCTEN allows
    // it, and always at EL1. The read has no side effects.
    unsafe {
        asm!("mrs {v}, cntpct_el0", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// `ISB` + `DSB SY` + `CNTPCT_EL0`: the fully ordered physical read.
///
/// `ISB` alone orders the *instruction* stream, so the counter read cannot be
/// hoisted past earlier instructions. It says nothing about memory: a store
/// issued before the read may still be in flight when the counter is sampled,
/// which for a measurement that brackets memory work means the interval ends
/// before the work does.
///
/// `DSB SY` waits for that traffic to complete. Together they are what the
/// ARM ARM prescribes for reading the counter as a timestamp rather than as a
/// number — and they cost a few dozen cycles, which is why the hosted build
/// uses the cheaper `ISB`-only form and this one is reserved for a kernel
/// that is measuring the machine itself.
#[inline(always)]
pub fn cntpct_ordered() -> u64 {
    let v: u64;
    // SAFETY: as above; the barriers have no operands and no memory effects
    // beyond ordering.
    unsafe {
        asm!(
            "dsb sy",
            "isb",
            "mrs {v}, cntpct_el0",
            "isb",
            v = out(reg) v,
            options(nostack, preserves_flags),
        );
    }
    v
}

/// `ISB` + `CNTPCT_EL0`: the interval-boundary read of the physical counter.
#[inline(always)]
pub fn cntpct_isb() -> u64 {
    let v: u64;
    // SAFETY: only reached once the physical counter was selected, which
    // requires `physical_permitted()` (or EL1+, freestanding).
    unsafe {
        asm!(
            "isb",
            "mrs {v}, cntpct_el0",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

// ---------------------------------------------------------------------------
// Virtual or physical: the "Enable Physical Counter" setting
// ---------------------------------------------------------------------------
//
// Every architectural read in this crate goes through `counter_raw` and
// `counter_isb` below, so the choice made here reaches the stopwatch, the
// calibration and the probes alike. Virtual is the default: it is what every
// OS hands user space, and a hypervisor never needs to trap it. Physical is
// what the hardware ticks — equal on bare metal, but inside a VM the
// hypervisor may trap every read, and under nested virtualization that trap
// is forwarded through a second hypervisor, which makes it slow and unstable.

static PHYSICAL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether reads use `CNTPCT_EL0`.
#[inline(always)]
pub fn physical_selected() -> bool {
    PHYSICAL.load(core::sync::atomic::Ordering::Relaxed)
}

/// Selects the counter. Enabling it is only sound once
/// [`physical_permitted`] has said yes; `arch::set_counter_source` checks.
pub(crate) fn select_physical(on: bool) {
    PHYSICAL.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// The selected counter, unordered.
#[inline(always)]
pub fn counter_raw() -> u64 {
    if physical_selected() {
        cntpct_raw()
    } else {
        cntvct_raw()
    }
}

/// The selected counter, `ISB`-ordered.
#[inline(always)]
pub fn counter_isb() -> u64 {
    if physical_selected() {
        cntpct_isb()
    } else {
        cntvct_isb()
    }
}

/// Whether this process may read `CNTPCT_EL0` at all.
///
/// Freestanding (EL1 and above) it always may. From user space it depends on
/// the kernel: `CNTKCTL_EL1.EL0PCTEN` decides whether the read executes,
/// traps to the kernel for emulation, or is undefined — and undefined is
/// `SIGILL`, not an error return. So it is tried once where a failure cannot
/// hurt: a forked child on Unix, a vectored exception handler on Windows.
#[cfg(not(feature = "std"))]
pub fn physical_permitted() -> bool {
    true
}

#[cfg(all(feature = "std", unix))]
pub fn physical_permitted() -> bool {
    use std::sync::OnceLock;
    static PERMITTED: OnceLock<bool> = OnceLock::new();
    *PERMITTED.get_or_init(|| {
        // SAFETY: the child runs only async-signal-safe code: a system call,
        // one register read and `_exit`.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            // A SIGILL is the expected "no" and must not leave a core file.
            let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            // SAFETY: a plain system call on a valid struct.
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
            // The child inherits the parent's signal handlers. In an Android
            // app that is debuggerd's, and in any app with a crash reporter
            // (Crashpad, Breakpad) it is the reporter's: the "no" below would
            // be written up as a crash — a tombstone per probe — instead of
            // quietly ending the child. `signal` is async-signal-safe.
            // SAFETY: resets one disposition in a single-threaded child.
            unsafe { libc::signal(libc::SIGILL, libc::SIG_DFL) };
            core::hint::black_box(cntpct_raw());
            // SAFETY: never returns, runs no destructors.
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        loop {
            // SAFETY: `pid` is our child; `status` is a valid out-pointer.
            let r = unsafe { libc::waitpid(pid, &mut status, 0) };
            if r == pid {
                break;
            }
            if r < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return false;
            }
        }
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    })
}

#[cfg(all(feature = "std", windows))]
pub fn physical_permitted() -> bool {
    use std::sync::OnceLock;
    static PERMITTED: OnceLock<bool> = OnceLock::new();
    *PERMITTED.get_or_init(windows_probe::run)
}

/// Windows has no `fork`, so the probe runs in-process under a vectored
/// exception handler that recognises exactly one faulting address — the
/// probe's own `mrs` — steps over it and records the fault. Any other
/// exception is passed on untouched.
#[cfg(all(feature = "std", windows))]
mod windows_probe {
    use core::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS,
    };

    core::arch::global_asm!(
        ".global nc_cntpct_probe",
        ".global nc_cntpct_probe_site",
        "nc_cntpct_probe:",
        "nc_cntpct_probe_site:",
        "    mrs x0, cntpct_el0",
        "    ret",
    );

    extern "C" {
        fn nc_cntpct_probe() -> u64;
        static nc_cntpct_probe_site: u8;
    }

    static FAULTED: AtomicBool = AtomicBool::new(false);

    /// `STATUS_ILLEGAL_INSTRUCTION`.
    const ILLEGAL_INSTRUCTION: i32 = 0xC000_001Du32 as i32;
    const CONTINUE_EXECUTION: i32 = -1;
    const CONTINUE_SEARCH: i32 = 0;

    unsafe extern "system" fn handler(info: *mut EXCEPTION_POINTERS) -> i32 {
        // SAFETY: Windows passes valid exception and context records.
        unsafe {
            let record = &*(*info).ExceptionRecord;
            let site = &raw const nc_cntpct_probe_site as usize;
            if record.ExceptionCode == ILLEGAL_INSTRUCTION && record.ExceptionAddress as usize == site {
                FAULTED.store(true, Ordering::Relaxed);
                (*(*info).ContextRecord).Pc += 4;
                return CONTINUE_EXECUTION;
            }
        }
        CONTINUE_SEARCH
    }

    pub(super) fn run() -> bool {
        FAULTED.store(false, Ordering::Relaxed);
        // SAFETY: the handler is 'static and removed before returning.
        unsafe {
            let cookie = AddVectoredExceptionHandler(1, Some(handler));
            if cookie.is_null() {
                return false;
            }
            core::hint::black_box(nc_cntpct_probe());
            RemoveVectoredExceptionHandler(cookie);
        }
        !FAULTED.load(Ordering::Relaxed)
    }
}

/// Nanoseconds per read of `read`: the best of several batches, timed with
/// the virtual counter, which no hypervisor traps.
pub fn read_cost_ns(read: fn() -> u64) -> u64 {
    const BATCH: u64 = 64;
    let hz = cntfrq();
    if hz == 0 {
        return 0;
    }
    let mut best = u64::MAX;
    for _ in 0..16 {
        let a = cntvct_isb();
        for _ in 0..BATCH {
            core::hint::black_box(read());
        }
        let b = cntvct_isb();
        best = best.min(b.wrapping_sub(a));
    }
    best.saturating_mul(1_000_000_000) / hz / BATCH
}

/// `CNTFRQ_EL0` — the counter's tick rate in Hz.
#[inline]
pub fn cntfrq() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {v}, cntfrq_el0", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// `CTR_EL0` — the Cache Type Register.
///
/// One of the handful of registers architecturally readable at EL0, so it
/// costs nothing and cannot fault. Its cache-line geometry is a weak
/// fingerprint: an emulator that does not model caches has to invent values.
#[inline]
pub fn ctr_el0() -> u64 {
    let v: u64;
    // SAFETY: CTR_EL0 is readable at EL0 on every ARMv8 implementation; the
    // read has no side effects.
    unsafe {
        asm!("mrs {v}, ctr_el0", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// `DCZID_EL0` — the Data Cache Zero ID Register.
///
/// Also EL0-readable by architecture. Bit 4 (`DZP`) says whether `DC ZVA` is
/// prohibited, which some emulators set because they do not implement it.
#[inline]
pub fn dczid_el0() -> u64 {
    let v: u64;
    // SAFETY: DCZID_EL0 is readable at EL0 by architecture, no side effects.
    unsafe {
        asm!("mrs {v}, dczid_el0", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// The cost of a bare counter read pair and of a synchronised one, in units.
///
/// `ISB` forces the pipeline to be re-fetched. Real silicon absorbs that in a
/// few dozen cycles, so both numbers land within a small factor of each
/// other. An emulator has to end its translation block and re-enter the
/// dispatch loop, which costs orders of magnitude more — so the *ratio*
/// between the two separates emulation from execution. Both sides are in
/// counter units, so the counter's own frequency cancels out and the result
/// is comparable across machines.
///
/// Minimum-of-N on both sides: anything above the minimum is interference,
/// and interference is what must not leak into the ratio.
pub fn barrier_cost_pair() -> (u64, u64) {
    const ROUNDS: u32 = 256;

    let bare = (0..ROUNDS)
        .map(|_| {
            let a = cntvct_raw();
            let b = cntvct_raw();
            b.wrapping_sub(a)
        })
        .min()
        .unwrap_or(0);

    let synchronised = (0..ROUNDS)
        .map(|_| {
            let a = cntvct_isb();
            let b = cntvct_isb();
            b.wrapping_sub(a)
        })
        .min()
        .unwrap_or(0);

    (bare, synchronised)
}

// `PMCCNTR_EL0` is deliberately absent.
//
// The C build read it directly behind a `NANOCHRONO_USE_PMCCNTR_EL0` opt-in,
// which is an environment variable that says "please try an instruction that
// may kill this process": the register traps to EL1 unless `PMUSERENR_EL0.EN`
// is set, and there is no way to probe that from EL0 without taking the trap.
// It is also not virtualised or context-switched, so a preempted thread reads
// cycles that belonged to someone else.
//
// Cycle counting now goes through `perf_event_open` — see [`crate::perf`] —
// which the kernel schedules per thread, saves across context switches, and
// exposes without privileges.

// ---------------------------------------------------------------------------
// Barriers and hints
// ---------------------------------------------------------------------------

#[inline(always)]
pub fn isb() {
    unsafe { asm!("isb", options(nostack, preserves_flags)) }
}

#[inline(always)]
pub fn dmb_sy() {
    unsafe { asm!("dmb sy", options(nostack, preserves_flags)) }
}

#[inline(always)]
pub fn dsb_sy() {
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)) }
}

#[inline(always)]
pub fn yield_hint() {
    unsafe { asm!("yield", options(nomem, nostack, preserves_flags)) }
}

// ---------------------------------------------------------------------------
// Scalar probes
// ---------------------------------------------------------------------------

/// Ticks for one dependent 64-bit load.
///
/// # Safety
/// `ptr` must be a valid, aligned `*const u64`.
#[inline]
pub unsafe fn probe_load_ticks(ptr: *const u64) -> u64 {
    let start = cntvct_isb();
    let sink: u64;
    unsafe {
        asm!("ldr {v}, [{p}]", p = in(reg) ptr, v = out(reg) sink,
             options(nostack, preserves_flags, readonly));
    }
    let end = cntvct_isb();
    core::hint::black_box(sink);
    end.wrapping_sub(start)
}

/// Ticks for one 64-bit load with a full system barrier on both sides.
///
/// # Safety
/// `ptr` must be a valid, aligned `*const u64`.
#[inline]
pub unsafe fn probe_load_dsb_ticks(ptr: *const u64) -> u64 {
    dsb_sy();
    let start = cntvct_isb();
    let sink: u64;
    unsafe {
        asm!("ldr {v}, [{p}]", p = in(reg) ptr, v = out(reg) sink,
             options(nostack, preserves_flags, readonly));
    }
    dsb_sy();
    let end = cntvct_isb();
    core::hint::black_box(sink);
    end.wrapping_sub(start)
}

/// Ticks for one 64-bit store.
///
/// # Safety
/// `ptr` must be a valid, aligned, writable `*mut u64`.
#[inline]
pub unsafe fn probe_store_ticks(ptr: *mut u64, value: u64) -> u64 {
    let start = cntvct_isb();
    unsafe {
        asm!("str {v}, [{p}]", "dmb sy", p = in(reg) ptr, v = in(reg) value,
             options(nostack, preserves_flags));
    }
    let end = cntvct_isb();
    end.wrapping_sub(start)
}

/// Ticks for a prefetch followed by a reload of the same line.
///
/// # Safety
/// `ptr` must be a valid, aligned `*const u64`.
#[inline]
pub unsafe fn probe_prefetch_load_ticks(ptr: *const u64) -> u64 {
    unsafe {
        asm!("prfm pldl1keep, [{p}]", p = in(reg) ptr,
             options(nostack, preserves_flags, readonly));
        probe_load_ticks(ptr)
    }
}

/// Ticks to walk `pattern` as a data-dependent branch sequence.
///
/// # Safety
/// `pattern` must point to `count` readable bytes.
#[inline]
pub unsafe fn probe_branch_ticks(pattern: *const u8, count: usize) -> u64 {
    let start = cntvct_isb();
    let mut acc: u64 = 0;
    for i in 0..count {
        if unsafe { *pattern.add(i) } & 1 != 0 {
            acc = acc.wrapping_add(1);
        } else {
            acc = acc.wrapping_mul(3);
        }
    }
    let end = cntvct_isb();
    core::hint::black_box(acc);
    end.wrapping_sub(start)
}

/// Ticks to follow `steps` links of a pointer-chase list.
///
/// # Safety
/// `first` must head a chain of at least `steps` valid links.
#[inline]
pub unsafe fn probe_pointer_chase_ticks(first: *const *const u8, steps: usize) -> u64 {
    let start = cntvct_isb();
    let mut p = first;
    for _ in 0..steps {
        if p.is_null() {
            break;
        }
        p = unsafe { *p } as *const *const u8;
    }
    let end = cntvct_isb();
    core::hint::black_box(p);
    end.wrapping_sub(start)
}

/// Ticks for `iterations` back-to-back `DMB SY` barriers.
#[inline]
pub fn probe_barrier_ticks(iterations: u32) -> u64 {
    let n = iterations.max(1);
    let start = cntvct_isb();
    for _ in 0..n {
        dmb_sy();
    }
    let end = cntvct_isb();
    end.wrapping_sub(start)
}

/// Back-to-back counter reads: the measurement floor.
#[inline]
pub fn read_overhead_ticks() -> u64 {
    let a = cntvct_isb();
    let b = cntvct_isb();
    b.saturating_sub(a)
}

// ---------------------------------------------------------------------------
// NEON probes and kernels
// ---------------------------------------------------------------------------

pub mod neon {
    use super::*;

    #[inline]
    pub fn counter() -> u64 {
        cntvct_isb()
    }

    /// # Safety
    /// `ptr` must have 16 readable bytes.
    #[inline]
    #[target_feature(enable = "neon")]
    pub unsafe fn vector_load_ticks(ptr: *const u8) -> u64 {
        let start = cntvct_isb();
        unsafe {
            asm!("ldr q0, [{p}]", p = in(reg) ptr, out("q0") _,
                 options(nostack, preserves_flags, readonly));
        }
        let end = cntvct_isb();
        end.wrapping_sub(start)
    }

    /// # Safety
    /// `a`/`b` must have 16 readable bytes, `out` 16 writable bytes.
    #[inline]
    #[target_feature(enable = "neon")]
    pub unsafe fn vector_xor_ticks(a: *const u8, b: *const u8, out: *mut u8) -> u64 {
        let start = cntvct_isb();
        unsafe {
            asm!(
                "ldr q0, [{a}]",
                "ldr q1, [{b}]",
                "eor v0.16b, v0.16b, v1.16b",
                "str q0, [{o}]",
                a = in(reg) a, b = in(reg) b, o = in(reg) out,
                out("q0") _, out("q1") _,
                options(nostack, preserves_flags),
            );
        }
        let end = cntvct_isb();
        end.wrapping_sub(start)
    }

    #[inline]
    pub fn barrier_ticks(iterations: u32) -> u64 {
        probe_barrier_ticks(iterations)
    }
}

/// SVE probes.
///
/// SVE is vector-length agnostic, so the predicate covers whatever width the
/// implementation exposes; `whilelo` derives it from the byte count rather
/// than assuming 128 bits.
pub mod sve {
    use super::*;

    #[inline]
    pub fn counter() -> u64 {
        cntvct_isb()
    }

    /// # Safety
    /// Requires SVE. `ptr` must have `bytes` readable bytes.
    #[inline]
    #[target_feature(enable = "sve")]
    pub unsafe fn vector_load_ticks(ptr: *const u8, bytes: usize) -> u64 {
        let start = cntvct_isb();
        unsafe {
            asm!(
                "whilelo p0.b, xzr, {n}",
                "ld1b {{ z0.b }}, p0/z, [{p}]",
                p = in(reg) ptr, n = in(reg) bytes,
                out("p0") _, out("z0") _,
                options(nostack, preserves_flags, readonly),
            );
        }
        let end = cntvct_isb();
        end.wrapping_sub(start)
    }

    /// # Safety
    /// Requires SVE. `a`/`b` must have `bytes` readable bytes, `out` `bytes`
    /// writable bytes.
    #[inline]
    #[target_feature(enable = "sve")]
    pub unsafe fn vector_xor_ticks(a: *const u8, b: *const u8, out: *mut u8, bytes: usize) -> u64 {
        let start = cntvct_isb();
        unsafe {
            asm!(
                "whilelo p0.b, xzr, {n}",
                "ld1b {{ z0.b }}, p0/z, [{a}]",
                "ld1b {{ z1.b }}, p0/z, [{b}]",
                "eor z0.d, z0.d, z1.d",
                "st1b {{ z0.b }}, p0, [{o}]",
                a = in(reg) a, b = in(reg) b, o = in(reg) out, n = in(reg) bytes,
                out("p0") _, out("z0") _, out("z1") _,
                options(nostack, preserves_flags),
            );
        }
        let end = cntvct_isb();
        end.wrapping_sub(start)
    }

    #[inline]
    pub fn barrier_ticks(iterations: u32) -> u64 {
        probe_barrier_ticks(iterations)
    }
}

// ---------------------------------------------------------------------------
// Microbenchmark kernels
// ---------------------------------------------------------------------------

/// Scalar 64-bit ALU loop — the AArch64 baseline.
#[inline(never)]
pub fn kernel_scalar(loops: usize) -> u64 {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..loops {
        unsafe {
            asm!(
                "ror {x}, {x}, #7",
                "eor {x}, {x}, {c}",
                "add {x}, {x}, {c}",
                x = inout(reg) x,
                c = in(reg) 0xD1B5_4A32_D192_ED03u64,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    x
}

/// NEON integer loop.
///
/// # Safety
/// Requires NEON, which is mandatory on AArch64 but still gated for symmetry
/// with the optional families.
#[inline(never)]
#[target_feature(enable = "neon")]
pub unsafe fn kernel_neon(loops: usize) -> u64 {
    let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..loops {
        unsafe {
            asm!(
                "dup v0.2d, {x}",
                "add v0.2d, v0.2d, v0.2d",
                "eor v0.16b, v0.16b, v0.16b",
                "umov {x}, v0.d[0]",
                "add {x}, {x}, #1",
                x = inout(reg) acc,
                out("v0") _,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    acc
}

/// AES round loop on the crypto extension.
///
/// Like its x86 counterpart this times `AESE`/`AESMC` latency; it is not a
/// cipher implementation.
///
/// # Safety
/// Requires the ARMv8 AES extension.
#[inline(never)]
#[target_feature(enable = "aes")]
pub unsafe fn kernel_aes(loops: usize) -> u64 {
    let mut acc: u64 = 0x0F1E_2D3C_4B5A_6978;
    for _ in 0..loops {
        // The round key is a constant, not the accumulator: `AESE` begins
        // with state XOR key, and with both equal to `x` that is zero on
        // every iteration — a constant output, a chain that no longer
        // depends on its input, and a checksum that stopped changing.
        unsafe {
            asm!(
                "dup v0.2d, {x}",
                "dup v1.2d, {k}",
                "aese v0.16b, v1.16b",
                "aesmc v0.16b, v0.16b",
                "umov {x}, v0.d[0]",
                "add {x}, {x}, #1",
                x = inout(reg) acc,
                k = in(reg) 0x6A09_E667_F3BC_C908u64,
                out("v0") _, out("v1") _,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    acc
}

/// SHA-256 round loop on the crypto extension.
///
/// # Safety
/// Requires the ARMv8 SHA2 extension.
#[inline(never)]
#[target_feature(enable = "sha2")]
pub unsafe fn kernel_sha256(loops: usize) -> u64 {
    let mut acc: u64 = 0x6A09_E667_BB67_AE85;
    for _ in 0..loops {
        unsafe {
            asm!(
                "dup v0.2d, {x}",
                "mov v1.16b, v0.16b",
                "mov v2.16b, v0.16b",
                "sha256su0 v0.4s, v1.4s",
                "sha256h q1, q2, v0.4s",
                "umov {x}, v1.d[0]",
                "add {x}, {x}, #1",
                x = inout(reg) acc,
                out("v0") _, out("v1") _, out("v2") _,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    acc
}

/// Polynomial multiply loop — the AArch64 GHASH datapath.
///
/// # Safety
/// Requires the ARMv8 PMULL extension.
#[inline(never)]
#[target_feature(enable = "aes")]
pub unsafe fn kernel_pmull(loops: usize) -> u64 {
    let mut acc: u64 = 0x0123_4567_89AB_CDEF;
    for _ in 0..loops {
        unsafe {
            asm!(
                "dup v0.2d, {x}",
                "dup v1.2d, {x}",
                "pmull v2.1q, v0.1d, v1.1d",
                "umov {x}, v2.d[0]",
                "add {x}, {x}, #1",
                x = inout(reg) acc,
                out("v0") _, out("v1") _, out("v2") _,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    acc
}
