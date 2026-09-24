// SPDX-License-Identifier: Apache-2.0
//! PowerPC counter and probe primitives, 32- and 64-bit, either byte order.
//!
//! The architectural counter is the Time Base: a 64-bit register that ticks
//! at a fixed, implementation-defined rate (512 MHz on POWER8 and later,
//! whatever the board's bus clock divides to on a 32-bit part). Like
//! `CNTVCT_EL0` it is immune to frequency scaling, so its units are ticks,
//! not core cycles, and its rate is *stated* rather than measured — by the
//! device tree on bare metal and by `/proc/cpuinfo` on Linux. The ISA itself
//! has no register that says it.
//!
//! # Reading it
//!
//! `mftb` is readable in problem state on every PowerPC this supports, so
//! the same instruction runs in a hosted process and in the freestanding
//! kernel.
//!
//! * **64-bit** reads the whole register in one instruction.
//! * **32-bit** cannot. It reads `TBU` and `TBL` separately, and `TBL` can
//!   carry into `TBU` between the two reads — once every 2³² ticks, about
//!   every 8 s at 512 MHz. Reading the upper half on both sides of the lower
//!   half and retrying until they agree is the architected answer (Power ISA
//!   Book II, "Reading the Time Base on 32-bit implementations").
//!
//! `mftb` is not execution-synchronising: the core may read it before older
//! instructions finish or after younger ones start. `isync` on the correct
//! side of each boundary read orders it, the same job `ISB` does on AArch64
//! and `LFENCE` on x86.
//!
//! # Endianness
//!
//! Nothing here depends on it. The Time Base is a register, not memory, and
//! the vector probes load and store bytes whose value is never interpreted.

use core::arch::asm;

// ---------------------------------------------------------------------------
// Counter reads
// ---------------------------------------------------------------------------

/// Raw Time Base. No ordering.
#[cfg(target_arch = "powerpc64")]
#[inline(always)]
pub fn timebase_raw() -> u64 {
    let v: u64;
    // SAFETY: `mftb` is readable at every privilege level and has no side
    // effects.
    unsafe {
        asm!("mftb {v}", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Raw Time Base. No ordering.
///
/// The high/low/high loop is the rollover guard described in the module
/// documentation: without it a read that straddles a carry out of `TBL` is
/// off by 2³² ticks, in either direction.
///
/// # The encoding is spelled out
///
/// LLVM assembles `mftb`/`mftbu` as `mfspr rD,268/269` (XO 339), which the
/// current ISA recommends — and which the classic 32-bit cores (603, G3,
/// the G4's 74xx) reject as an illegal instruction: on those the Time Base
/// is readable *only* through the original `mftb` form (XO 371). Every core
/// a 32-bit build can meet — classic, e500, and 64-bit parts running 32-bit
/// code — implements XO 371, so it is emitted as a literal word. The
/// registers are fixed because the word encodes them: `mftbu r5`,
/// `mftb r6`, `mftbu r7`.
#[cfg(target_arch = "powerpc")]
#[inline(always)]
pub fn timebase_raw() -> u64 {
    let hi: u32;
    let lo: u32;
    // SAFETY: `mftb`/`mftbu` are readable at every privilege level and have
    // no side effects. `cmplw` writes CR0, which is why `preserves_flags` is
    // absent.
    unsafe {
        asm!(
            "2:",
            ".long 0x7CAD42E6", // mftbu r5  (XO 371, TBR 269)
            ".long 0x7CCC42E6", // mftb  r6  (XO 371, TBR 268)
            ".long 0x7CED42E6", // mftbu r7
            "cmplw 5, 7",
            "bne- 2b",
            out("r5") hi,
            out("r6") lo,
            out("r7") _,
            options(nomem, nostack),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// Time Base read for the *start* of an interval: read, then `isync`, so no
/// instruction of the measured work begins before the read.
#[inline(always)]
pub fn timebase_start() -> u64 {
    let v = timebase_raw();
    isync();
    v
}

/// Time Base read for the *end* of an interval: `isync`, then read, so the
/// read waits for every instruction of the measured work to complete.
#[inline(always)]
pub fn timebase_end() -> u64 {
    isync();
    timebase_raw()
}

/// `sync` + `isync` + Time Base + `isync`: the fully ordered read, for a
/// measurement that brackets memory traffic. `sync` waits for stores to be
/// performed, which `isync` alone does not.
#[inline(always)]
pub fn timebase_ordered() -> u64 {
    sync();
    isync();
    let v = timebase_raw();
    isync();
    v
}

// ---------------------------------------------------------------------------
// The counter's rate
// ---------------------------------------------------------------------------

/// The Time Base frequency, as the platform states it.
///
/// Hosted: `/proc/cpuinfo`'s `timebase` line, which Linux copies from the
/// device tree's `timebase-frequency`. Read once.
#[cfg(feature = "std")]
pub fn timebase_hz() -> Option<u64> {
    use std::sync::OnceLock;
    static HZ: OnceLock<Option<u64>> = OnceLock::new();
    *HZ.get_or_init(|| {
        let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        parse_cpuinfo_timebase(&text)
    })
}

/// Freestanding: whatever the kernel read out of the device tree and handed
/// over through [`set_timebase_hz`]. `u32` because 32-bit PowerPC has no
/// 64-bit atomics, and no Time Base runs anywhere near 4 GHz.
#[cfg(not(feature = "std"))]
static TIMEBASE_HZ: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Freestanding: the rate [`set_timebase_hz`] recorded, if any.
#[cfg(not(feature = "std"))]
pub fn timebase_hz() -> Option<u64> {
    match TIMEBASE_HZ.load(core::sync::atomic::Ordering::Relaxed) {
        0 => None,
        hz => Some(hz as u64),
    }
}

/// Records the Time Base rate for a freestanding build, which learns it from
/// the device tree before anything is calibrated. Rates that do not fit are
/// refused rather than truncated: a wrong divisor is worse than none.
#[cfg(not(feature = "std"))]
pub fn set_timebase_hz(hz: u64) {
    if let Ok(hz) = u32::try_from(hz) {
        TIMEBASE_HZ.store(hz, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Extracts the `timebase : <hz>` line Linux prints in `/proc/cpuinfo` on
/// PowerPC. Split out so it can be tested on any host.
pub fn parse_cpuinfo_timebase(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "timebase" {
            return None;
        }
        value.trim().parse::<u64>().ok().filter(|&hz| hz > 0)
    })
}

// ---------------------------------------------------------------------------
// Barriers and hints
// ---------------------------------------------------------------------------

/// `isync`: completes every older instruction and discards any younger one
/// already fetched.
#[inline(always)]
pub fn isync() {
    // SAFETY: no operands, no effect beyond ordering.
    unsafe { asm!("isync", options(nostack, preserves_flags)) }
}

/// `sync` (heavyweight sync): orders and completes all storage accesses.
#[inline(always)]
pub fn sync() {
    // SAFETY: as above.
    unsafe { asm!("sync", options(nostack, preserves_flags)) }
}

/// `or 27,27,27`: the "yield" / low-priority hint the ISA defines for spin
/// loops. A no-op on parts without SMT priorities.
#[inline(always)]
pub fn yield_hint() {
    // SAFETY: `or rN,rN,rN` changes no architectural state.
    unsafe { asm!("or 27, 27, 27", options(nomem, nostack, preserves_flags)) }
}

// ---------------------------------------------------------------------------
// Scalar probes
// ---------------------------------------------------------------------------

/// Ticks for one dependent pointer-sized load.
///
/// # Safety
/// `ptr` must be valid for an aligned `u64` read.
#[inline]
pub unsafe fn probe_load_ticks(ptr: *const u64) -> u64 {
    let start = timebase_start();
    // SAFETY: forwarded from this function's contract.
    let v = unsafe { core::ptr::read_volatile(ptr) };
    let end = timebase_end();
    core::hint::black_box(v);
    end.wrapping_sub(start)
}

/// Ticks for one load with `sync` on both sides.
///
/// # Safety
/// `ptr` must be valid for an aligned `u64` read.
#[inline]
pub unsafe fn probe_load_sync_ticks(ptr: *const u64) -> u64 {
    sync();
    let start = timebase_start();
    // SAFETY: forwarded from this function's contract.
    let v = unsafe { core::ptr::read_volatile(ptr) };
    sync();
    let end = timebase_end();
    core::hint::black_box(v);
    end.wrapping_sub(start)
}

/// Ticks for one store, completed by `sync`.
///
/// # Safety
/// `ptr` must be valid for an aligned `u64` write.
#[inline]
pub unsafe fn probe_store_ticks(ptr: *mut u64, value: u64) -> u64 {
    let start = timebase_start();
    // SAFETY: forwarded from this function's contract.
    unsafe { core::ptr::write_volatile(ptr, value) };
    sync();
    let end = timebase_end();
    end.wrapping_sub(start)
}

/// Ticks for `dcbt` (touch) followed by a reload of the same line.
///
/// # Safety
/// `ptr` must be valid for an aligned `u64` read.
#[inline]
pub unsafe fn probe_prefetch_load_ticks(ptr: *const u64) -> u64 {
    // SAFETY: `dcbt` is a hint; it never faults, even on a bad address.
    unsafe {
        asm!("dcbt 0, {p}", p = in(reg_nonzero) ptr, options(nostack, preserves_flags, readonly));
        probe_load_ticks(ptr)
    }
}

/// Ticks to follow `steps` links of a pointer-chase list.
///
/// # Safety
/// `first` must head a chain of at least `steps` valid links.
#[inline]
pub unsafe fn probe_pointer_chase_ticks(first: *const *const u8, steps: usize) -> u64 {
    let start = timebase_start();
    let mut p = first;
    for _ in 0..steps {
        if p.is_null() {
            break;
        }
        // SAFETY: forwarded from this function's contract.
        p = unsafe { *p } as *const *const u8;
    }
    let end = timebase_end();
    core::hint::black_box(p);
    end.wrapping_sub(start)
}

/// Ticks for `iterations` back-to-back `sync` barriers.
#[inline]
pub fn probe_barrier_ticks(iterations: u32) -> u64 {
    let n = iterations.max(1);
    let start = timebase_start();
    for _ in 0..n {
        sync();
    }
    let end = timebase_end();
    end.wrapping_sub(start)
}

/// Back-to-back ordered reads: the measurement floor.
#[inline]
pub fn read_overhead_ticks() -> u64 {
    let a = timebase_start();
    let b = timebase_end();
    b.saturating_sub(a)
}

// ---------------------------------------------------------------------------
// Vector probes and kernels
//
// Written with explicit register clobbers and no `#[target_feature]`: the
// PowerPC target features are still unstable in Rust, and the dispatcher
// already gates every call on the hardware capability, which is the only
// guard that matters for an instruction that is illegal where it is absent.
// `v0`/`v1` and `vs32`/`vs33` are the same registers; the clobber list names
// the AltiVec view because that is the register class Rust exposes.
// ---------------------------------------------------------------------------

/// AltiVec (VMX) probes.
#[cfg(feature = "simd")]
pub mod altivec {
    use super::*;

    #[inline]
    pub fn counter() -> u64 {
        timebase_start()
    }

    /// # Safety
    /// Requires AltiVec, enabled (`MSR[VEC]`). `ptr` must have 16 readable
    /// bytes. `lvx` silently ignores the low four address bits, so an
    /// unaligned caller buffer would be read from *before* its start; the
    /// bytes are copied to an aligned scratch block first and only the `lvx`
    /// is timed.
    #[inline]
    pub unsafe fn vector_load_ticks(ptr: *const u8) -> u64 {
        let mut scratch = Aligned16([0; 16]);
        // SAFETY: the caller guarantees 16 readable bytes.
        unsafe { core::ptr::copy_nonoverlapping(ptr, scratch.0.as_mut_ptr(), 16) };
        let start = timebase_start();
        // SAFETY: `scratch` is 16-byte aligned and 16 bytes long.
        unsafe {
            asm!("lvx 0, 0, {p}", p = in(reg_nonzero) scratch.0.as_ptr(), out("v0") _,
                 options(nostack, preserves_flags, readonly));
        }
        let end = timebase_end();
        end.wrapping_sub(start)
    }

    /// # Safety
    /// Requires AltiVec, enabled. `a`/`b` must have 16 readable bytes and
    /// `out` 16 writable bytes.
    #[inline]
    pub unsafe fn vector_xor_ticks(a: *const u8, b: *const u8, out: *mut u8) -> u64 {
        let mut sa = Aligned16([0; 16]);
        let mut sb = Aligned16([0; 16]);
        let mut so = Aligned16([0; 16]);
        // SAFETY: the caller guarantees 16 readable bytes behind each.
        unsafe {
            core::ptr::copy_nonoverlapping(a, sa.0.as_mut_ptr(), 16);
            core::ptr::copy_nonoverlapping(b, sb.0.as_mut_ptr(), 16);
        }
        let start = timebase_start();
        // SAFETY: all three scratch blocks are 16-byte aligned, 16 bytes.
        unsafe {
            asm!(
                "lvx 0, 0, {a}",
                "lvx 1, 0, {b}",
                "vxor 0, 0, 1",
                "stvx 0, 0, {o}",
                a = in(reg_nonzero) sa.0.as_ptr(),
                b = in(reg_nonzero) sb.0.as_ptr(),
                o = in(reg_nonzero) so.0.as_mut_ptr(),
                out("v0") _, out("v1") _,
                options(nostack, preserves_flags),
            );
        }
        let end = timebase_end();
        // SAFETY: the caller guarantees 16 writable bytes.
        unsafe { core::ptr::copy_nonoverlapping(so.0.as_ptr(), out, 16) };
        end.wrapping_sub(start)
    }

    #[inline]
    pub fn barrier_ticks(iterations: u32) -> u64 {
        probe_barrier_ticks(iterations)
    }
}

/// VSX probes. `lxvd2x`/`stxvd2x` take any alignment, unlike `lvx`.
#[cfg(feature = "simd")]
pub mod vsx {
    use super::*;

    #[inline]
    pub fn counter() -> u64 {
        timebase_start()
    }

    /// # Safety
    /// Requires VSX, enabled (`MSR[VSX]`). `ptr` must have 16 readable bytes.
    #[inline]
    pub unsafe fn vector_load_ticks(ptr: *const u8) -> u64 {
        let start = timebase_start();
        // SAFETY: forwarded from this function's contract.
        unsafe {
            asm!("lxvd2x 32, 0, {p}", p = in(reg_nonzero) ptr, out("v0") _,
                 options(nostack, preserves_flags, readonly));
        }
        let end = timebase_end();
        end.wrapping_sub(start)
    }

    /// # Safety
    /// Requires VSX, enabled. `a`/`b` must have 16 readable bytes and `out`
    /// 16 writable bytes.
    #[inline]
    pub unsafe fn vector_xor_ticks(a: *const u8, b: *const u8, out: *mut u8) -> u64 {
        let start = timebase_start();
        // SAFETY: forwarded from this function's contract.
        unsafe {
            asm!(
                "lxvd2x 32, 0, {a}",
                "lxvd2x 33, 0, {b}",
                "xxlxor 32, 32, 33",
                "stxvd2x 32, 0, {o}",
                a = in(reg_nonzero) a,
                b = in(reg_nonzero) b,
                o = in(reg_nonzero) out,
                out("v0") _, out("v1") _,
                options(nostack, preserves_flags),
            );
        }
        let end = timebase_end();
        end.wrapping_sub(start)
    }

    #[inline]
    pub fn barrier_ticks(iterations: u32) -> u64 {
        probe_barrier_ticks(iterations)
    }
}

#[cfg(feature = "simd")]
#[repr(C, align(16))]
struct Aligned16([u8; 16]);

/// Scalar ALU loop — the PowerPC baseline.
#[inline(never)]
pub fn kernel_scalar(loops: usize) -> u64 {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..loops {
        x = x.rotate_left(57) ^ 0xD1B5_4A32_D192_ED03;
        x = core::hint::black_box(x.wrapping_add(0xD1B5_4A32_D192_ED03));
    }
    x
}

/// AltiVec integer loop.
///
/// # Safety
/// Requires AltiVec, enabled.
#[cfg(feature = "simd")]
#[inline(never)]
pub unsafe fn kernel_altivec(loops: usize) -> u64 {
    let mut acc = Aligned16([0x5A; 16]);
    for i in 0..loops {
        acc.0[0] = i as u8;
        // SAFETY: `acc` is 16-byte aligned; AltiVec per the contract.
        unsafe {
            asm!(
                "lvx 0, 0, {p}",
                "vadduwm 1, 0, 0",
                "vxor 0, 0, 1",
                "stvx 0, 0, {p}",
                p = in(reg_nonzero) acc.0.as_mut_ptr(),
                out("v0") _, out("v1") _,
                options(nostack, preserves_flags),
            );
        }
    }
    u64::from_ne_bytes(acc.0[..8].try_into().unwrap_or([0; 8]))
}

/// VSX double-precision loop.
///
/// # Safety
/// Requires VSX, enabled.
#[cfg(feature = "simd")]
#[inline(never)]
pub unsafe fn kernel_vsx(loops: usize) -> u64 {
    let mut acc = Aligned16([0x3C; 16]);
    for i in 0..loops {
        acc.0[0] = i as u8;
        // SAFETY: VSX per the contract; `lxvd2x` takes any alignment.
        unsafe {
            asm!(
                "lxvd2x 32, 0, {p}",
                "xxlxor 33, 32, 32",
                "xvadddp 32, 32, 33",
                "stxvd2x 32, 0, {p}",
                p = in(reg_nonzero) acc.0.as_mut_ptr(),
                out("v0") _, out("v1") _,
                options(nostack, preserves_flags),
            );
        }
    }
    u64::from_ne_bytes(acc.0[..8].try_into().unwrap_or([0; 8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cpuinfo_timebase_line_is_found() {
        let text = "processor\t: 0\ncpu\t\t: POWER9 (raw), altivec supported\n\
                    clock\t\t: 2200.000000MHz\nrevision\t: 2.2 (pvr 004e 1202)\n\n\
                    timebase\t: 512000000\nplatform\t: PowerNV\n";
        assert_eq!(parse_cpuinfo_timebase(text), Some(512_000_000));
    }

    #[test]
    fn a_missing_or_zero_timebase_is_none() {
        assert_eq!(parse_cpuinfo_timebase("cpu : e500mc\n"), None);
        assert_eq!(parse_cpuinfo_timebase("timebase : 0\n"), None);
        assert_eq!(parse_cpuinfo_timebase("timebase : fast\n"), None);
        // A key that merely starts with the word is not the line.
        assert_eq!(parse_cpuinfo_timebase("timebase-ish : 5\n"), None);
    }
}
