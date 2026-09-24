// SPDX-License-Identifier: Apache-2.0
//! RISC-V counter and probe primitives, RV32 and RV64.
//!
//! # Which counter
//!
//! Zicntr defines three unprivileged counters: `cycle`, `time` and
//! `instret`. Only `time` is usable from a hosted process everywhere: Linux
//! 6.6 and later clear `scounteren.CY`/`IR` by default (the counters leak
//! timing across processes), so `rdcycle` in user space is an illegal
//! instruction unless an administrator opted in. `rdtime` stays enabled — the
//! vDSO depends on it — and ticks at the fixed `timebase-frequency` the device
//! tree states, so like `CNTVCT_EL0` and the PowerPC Time Base its units are
//! ticks, not cycles. Cycles on Linux come from `perf_event_open`.
//!
//! A freestanding kernel runs in S-mode, where `cycle` and `instret` are
//! readable when M-mode firmware (OpenSBI) set `mcounteren` — see
//! `nanochrono-baremetal`'s PMU driver, which checks rather than assumes.
//!
//! # RV32
//!
//! Each counter is 64 bits read as two halves (`rdtimeh`, `rdtime`), with the
//! same carry hazard as the 32-bit PowerPC Time Base, and the same answer:
//! high, low, high again, retry until the highs agree (the unprivileged spec's
//! own sample sequence for `rdcycleh`).
//!
//! # Ordering
//!
//! RISC-V has no instruction-stream serialisation a counter read can lean on;
//! the reads are ordered against memory with `fence`, which is the strongest
//! ordering the base ISA offers.

use core::arch::asm;

// ---------------------------------------------------------------------------
// Counter reads
// ---------------------------------------------------------------------------

/// Reads a 64-bit unprivileged counter CSR: one instruction on RV64, the
/// high/low/high sequence on RV32.
macro_rules! read_counter {
    ($lo:literal, $hi:literal) => {{
        #[cfg(target_arch = "riscv64")]
        {
            let v: u64;
            // SAFETY: a counter CSR read; no side effects.
            unsafe { asm!(concat!("csrr {v}, ", $lo), v = out(reg) v, options(nomem, nostack, preserves_flags)) };
            v
        }
        #[cfg(target_arch = "riscv32")]
        {
            let (hi, lo): (u32, u32);
            // SAFETY: as above. RISC-V has no flags register.
            unsafe {
                asm!(
                    "2:",
                    concat!("csrr {hi}, ", $hi),
                    concat!("csrr {lo}, ", $lo),
                    concat!("csrr {chk}, ", $hi),
                    "bne {hi}, {chk}, 2b",
                    hi = out(reg) hi,
                    lo = out(reg) lo,
                    chk = out(reg) _,
                    options(nomem, nostack, preserves_flags),
                );
            }
            ((hi as u64) << 32) | lo as u64
        }
    }};
}

/// Raw `time` (`rdtime`). No ordering.
#[inline(always)]
pub fn rdtime_raw() -> u64 {
    read_counter!("time", "timeh")
}

/// Raw `cycle` (`rdcycle`).
///
/// # Safety
/// Illegal instruction unless the privilege level above allowed it
/// (`mcounteren.CY` for S-mode, `scounteren.CY` for U-mode) — which recent
/// Linux does not, for user space.
#[inline(always)]
pub unsafe fn rdcycle_raw() -> u64 {
    read_counter!("cycle", "cycleh")
}

/// Raw `instret` (`rdinstret`).
///
/// # Safety
/// As [`rdcycle_raw`], with the `IR` enable bits.
#[inline(always)]
pub unsafe fn rdinstret_raw() -> u64 {
    read_counter!("instret", "instreth")
}

/// `time` for the *start* of an interval: read, then a fence.
#[inline(always)]
pub fn rdtime_start() -> u64 {
    let v = rdtime_raw();
    fence();
    v
}

/// `time` for the *end* of an interval: a fence, then read.
#[inline(always)]
pub fn rdtime_end() -> u64 {
    fence();
    rdtime_raw()
}

// ---------------------------------------------------------------------------
// The counter's rate
// ---------------------------------------------------------------------------

/// The `time` rate, from the device tree Linux exposes.
#[cfg(feature = "std")]
pub fn timebase_hz() -> Option<u64> {
    use std::sync::OnceLock;
    static HZ: OnceLock<Option<u64>> = OnceLock::new();
    *HZ.get_or_init(|| {
        let bytes = std::fs::read("/proc/device-tree/cpus/timebase-frequency").ok()?;
        parse_dt_frequency(&bytes)
    })
}

/// A device-tree frequency cell: one or two big-endian 32-bit cells.
pub fn parse_dt_frequency(bytes: &[u8]) -> Option<u64> {
    let hz = match bytes.len() {
        4 => u32::from_be_bytes(bytes.try_into().ok()?) as u64,
        8 => u64::from_be_bytes(bytes.try_into().ok()?),
        _ => return None,
    };
    (hz > 0).then_some(hz)
}

#[cfg(not(feature = "std"))]
static TIMEBASE_HZ: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Freestanding: what the kernel read from the device tree.
#[cfg(not(feature = "std"))]
pub fn timebase_hz() -> Option<u64> {
    match TIMEBASE_HZ.load(core::sync::atomic::Ordering::Relaxed) {
        0 => None,
        hz => Some(hz as u64),
    }
}

/// Records the `time` rate for a freestanding build. `u32` storage because
/// RV32 has no 64-bit atomics; rates that do not fit are refused.
#[cfg(not(feature = "std"))]
pub fn set_timebase_hz(hz: u64) {
    if let Ok(hz) = u32::try_from(hz) {
        TIMEBASE_HZ.store(hz, core::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(not(feature = "std"))]
static VECTOR: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Freestanding: whether the hart implements V, as the device tree's ISA
/// string said. S-mode cannot read `misa`, so the kernel is told.
#[cfg(not(feature = "std"))]
pub fn set_vector_available(present: bool) {
    VECTOR.store(present, core::sync::atomic::Ordering::Relaxed);
}

/// Freestanding: what [`set_vector_available`] recorded.
#[cfg(not(feature = "std"))]
pub fn vector_available() -> bool {
    VECTOR.load(core::sync::atomic::Ordering::Relaxed)
}

/// Whether a `riscv,isa` string (e.g. `rv64imafdcv_zicsr`) names the V
/// extension: a `v` among the single-letter extensions, before the first `_`.
pub fn isa_string_has_vector(isa: &[u8]) -> bool {
    let isa = isa.split(|&b| b == b'_' || b == 0).next().unwrap_or(&[]);
    // Skip the `rv32`/`rv64` prefix; the letters follow.
    isa.len() > 4 && isa[..2].eq_ignore_ascii_case(b"rv") && isa[4..].iter().any(|&b| b == b'v' || b == b'V')
}

// ---------------------------------------------------------------------------
// Barriers and hints
// ---------------------------------------------------------------------------

/// `fence rw, rw`: orders all earlier loads and stores before later ones.
#[inline(always)]
pub fn fence() {
    // SAFETY: no operands, no effect beyond ordering.
    unsafe { asm!("fence rw, rw", options(nostack, preserves_flags)) }
}

/// `pause` (Zihintpause), encoded as the `fence w, 0` hint it is defined as,
/// so it assembles without the extension and is a no-op on harts without it.
#[inline(always)]
pub fn pause() {
    // SAFETY: a hint; no architectural state changes.
    unsafe { asm!(".insn i 0x0F, 0, x0, x0, 0x010", options(nomem, nostack, preserves_flags)) }
}

// ---------------------------------------------------------------------------
// Scalar probes
// ---------------------------------------------------------------------------

/// Ticks for one 64-bit load.
///
/// # Safety
/// `ptr` must be valid for an aligned `u64` read.
#[inline]
pub unsafe fn probe_load_ticks(ptr: *const u64) -> u64 {
    let start = rdtime_start();
    // SAFETY: forwarded from this function's contract.
    let v = unsafe { core::ptr::read_volatile(ptr) };
    let end = rdtime_end();
    core::hint::black_box(v);
    end.wrapping_sub(start)
}

/// Ticks for one 64-bit store, completed by a fence.
///
/// # Safety
/// `ptr` must be valid for an aligned `u64` write.
#[inline]
pub unsafe fn probe_store_ticks(ptr: *mut u64, value: u64) -> u64 {
    let start = rdtime_start();
    // SAFETY: forwarded from this function's contract.
    unsafe { core::ptr::write_volatile(ptr, value) };
    let end = rdtime_end();
    end.wrapping_sub(start)
}

/// Ticks to follow `steps` links of a pointer-chase list.
///
/// # Safety
/// `first` must head a chain of at least `steps` valid links.
#[inline]
pub unsafe fn probe_pointer_chase_ticks(first: *const *const u8, steps: usize) -> u64 {
    let start = rdtime_start();
    let mut p = first;
    for _ in 0..steps {
        if p.is_null() {
            break;
        }
        // SAFETY: forwarded from this function's contract.
        p = unsafe { *p } as *const *const u8;
    }
    let end = rdtime_end();
    core::hint::black_box(p);
    end.wrapping_sub(start)
}

/// Ticks for `iterations` back-to-back fences.
#[inline]
pub fn probe_barrier_ticks(iterations: u32) -> u64 {
    let n = iterations.max(1);
    let start = rdtime_start();
    for _ in 0..n {
        fence();
    }
    let end = rdtime_end();
    end.wrapping_sub(start)
}

/// Back-to-back ordered reads: the measurement floor.
#[inline]
pub fn read_overhead_ticks() -> u64 {
    let a = rdtime_start();
    let b = rdtime_end();
    b.saturating_sub(a)
}

// ---------------------------------------------------------------------------
// Vector (RVV 1.0) probes and kernels
//
// `.option arch, +v` scopes the extension to each asm block, so the crate
// needs no vector target feature and the dispatcher's runtime check is the
// only gate. Every block sets its own `vl`/`vtype` with `vsetivli`: both are
// caller-clobbered state in the psABI, and nothing else in a build without V
// uses them. 16 bytes at e8/m1 fits the V extension's minimum VLEN of 128.
// ---------------------------------------------------------------------------

/// RVV probes.
#[cfg(feature = "simd")]
pub mod rvv {
    use super::*;

    #[inline]
    pub fn counter() -> u64 {
        rdtime_start()
    }

    /// # Safety
    /// Requires V, enabled (`sstatus.VS` ≠ Off). `ptr` must have 16 readable
    /// bytes.
    #[inline]
    pub unsafe fn vector_load_ticks(ptr: *const u8) -> u64 {
        let start = rdtime_start();
        // SAFETY: forwarded from this function's contract.
        unsafe {
            asm!(
                ".option push",
                ".option arch, +v",
                "vsetivli zero, 16, e8, m1, ta, ma",
                "vle8.v v0, ({p})",
                ".option pop",
                p = in(reg) ptr,
                out("v0") _,
                options(nostack, preserves_flags, readonly),
            );
        }
        let end = rdtime_end();
        end.wrapping_sub(start)
    }

    /// # Safety
    /// Requires V, enabled. `a`/`b` must have 16 readable bytes and `out` 16
    /// writable bytes.
    #[inline]
    pub unsafe fn vector_xor_ticks(a: *const u8, b: *const u8, out: *mut u8) -> u64 {
        let start = rdtime_start();
        // SAFETY: forwarded from this function's contract.
        unsafe {
            asm!(
                ".option push",
                ".option arch, +v",
                "vsetivli zero, 16, e8, m1, ta, ma",
                "vle8.v v0, ({a})",
                "vle8.v v1, ({b})",
                "vxor.vv v0, v0, v1",
                "vse8.v v0, ({o})",
                ".option pop",
                a = in(reg) a,
                b = in(reg) b,
                o = in(reg) out,
                out("v0") _, out("v1") _,
                options(nostack, preserves_flags),
            );
        }
        let end = rdtime_end();
        end.wrapping_sub(start)
    }

    #[inline]
    pub fn barrier_ticks(iterations: u32) -> u64 {
        probe_barrier_ticks(iterations)
    }
}

/// Scalar ALU loop — the RISC-V baseline.
#[inline(never)]
pub fn kernel_scalar(loops: usize) -> u64 {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..loops {
        x = x.rotate_left(57) ^ 0xD1B5_4A32_D192_ED03;
        x = core::hint::black_box(x.wrapping_add(0xD1B5_4A32_D192_ED03));
    }
    x
}

/// RVV integer loop.
///
/// # Safety
/// Requires V, enabled.
#[cfg(feature = "simd")]
#[inline(never)]
pub unsafe fn kernel_rvv(loops: usize) -> u64 {
    let mut acc = [0x5Au8; 16];
    for i in 0..loops {
        acc[0] = i as u8;
        // SAFETY: V per the contract; `acc` is 16 bytes.
        unsafe {
            asm!(
                ".option push",
                ".option arch, +v",
                "vsetivli zero, 16, e8, m1, ta, ma",
                "vle8.v v0, ({p})",
                "vadd.vv v1, v0, v0",
                "vxor.vv v0, v0, v1",
                "vse8.v v0, ({p})",
                ".option pop",
                p = in(reg) acc.as_mut_ptr(),
                out("v0") _, out("v1") _,
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
    fn dt_frequency_cells_decode() {
        assert_eq!(parse_dt_frequency(&10_000_000u32.to_be_bytes()), Some(10_000_000));
        assert_eq!(parse_dt_frequency(&24_000_000u64.to_be_bytes()), Some(24_000_000));
        assert_eq!(parse_dt_frequency(&[0, 0, 0, 0]), None);
        assert_eq!(parse_dt_frequency(&[1, 2, 3]), None);
    }

    #[test]
    fn isa_strings_are_read_for_v() {
        assert!(isa_string_has_vector(b"rv64imafdcv_zicsr_zifencei"));
        assert!(isa_string_has_vector(b"rv64gcv\0"));
        assert!(!isa_string_has_vector(b"rv64imafdc_zicsr_zve32x"));
        assert!(!isa_string_has_vector(b"rv32imac"));
        // `v` inside a multi-letter extension name does not count.
        assert!(!isa_string_has_vector(b"rv64imac_zvkb"));
    }

    #[test]
    fn the_time_counter_moves() {
        let a = rdtime_start();
        let mut x = 0u64;
        for i in 0..100_000u64 {
            x = core::hint::black_box(x.wrapping_add(i));
        }
        assert!(rdtime_end() > a);
    }
}
