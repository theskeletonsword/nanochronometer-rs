// SPDX-License-Identifier: Apache-2.0
//! The C ABI: what C and assembly reach, through the static archive
//! (`libnanochrono.a`) or the shared object (`libnanochrono.so`).
//!
//! `include/nanochrono.h` is generated from this file and nothing else
//! (`tools/gen-header.sh`), so every name here is the stable, unmangled one a
//! linker or a symbol resolver looks up — Rust's mangled names are not a
//! stable thing to look up. A Rust kernel can call the Rust API directly
//! instead. For the shared object, see `docs/BAREMETAL_LIBRARIES.md` for the
//! loader that has to exist on the other side.
//!
//! Every function here is safe to call at ring 0 / EL1 and nowhere else, and
//! several program the PMU. There is no way to express that in a C signature,
//! so it is stated once: **this is a ring 0 interface.**

use crate::pmu::{CorePmu, CounterRoute};

/// Layout version, so a loader can refuse a module it does not understand.
pub const NC_BM_ABI_VERSION: u32 = 1;

/// What one core's PMU offers, flattened for C.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_bm_pmu_t {
    pub version: u32,
    pub general_counters: u32,
    pub general_width: u32,
    pub fixed_counters: u32,
    pub fixed_width: u32,
    /// 0 uniform, 1 performance, 2 efficiency, 3 unknown.
    pub core_type: u32,
    /// 0 none, 1 fixed, 2 general-purpose.
    pub route: u32,
    /// Which general-purpose counter, when `route` is 2. Was padding in the
    /// first cut of version 1 and always written as zero, so a caller that
    /// passes back what `nc_bm_pmu_enable` filled in is compatible either way.
    pub route_index: u32,
}

/// The ABI version this module was built with.
#[no_mangle]
pub extern "C" fn nc_bm_abi_version() -> u32 {
    NC_BM_ABI_VERSION
}

/// Describes this core's PMU without programming it.
///
/// # Safety
/// Executes `CPUID` or reads `PMCR_EL0`; requires ring 0 / EL1.
#[no_mangle]
pub unsafe extern "C" fn nc_bm_pmu_detect(out: *mut nc_bm_pmu_t) -> i32 {
    let Some(out) = (unsafe { out.as_mut() }) else {
        return -1;
    };
    let pmu = CorePmu::detect();
    *out = flatten(&pmu);
    0
}

/// Programs the counters and proves one advances.
///
/// Returns the route it settled on: 0 none, 1 fixed, 2 general-purpose. Zero
/// means no counter on this core moves, and no measurement should be reported
/// — see `CorePmu::enable`.
///
/// # Safety
/// Writes MSRs or PMU control registers; requires ring 0 / EL1, and must run
/// on the core it is programming.
#[no_mangle]
pub unsafe extern "C" fn nc_bm_pmu_enable(out: *mut nc_bm_pmu_t) -> u32 {
    let mut pmu = CorePmu::detect();
    // SAFETY: forwarded from this function's own contract.
    let route = unsafe { pmu.enable() };
    if let Some(out) = unsafe { out.as_mut() } {
        *out = flatten(&pmu);
    }
    route_code(route)
}

/// Reads the counter `nc_bm_pmu_enable` selected, into `out`.
///
/// Returns 1 on success, 0 if nothing counts on this core.
///
/// # Safety
/// Executes `RDPMC` or reads `PMCCNTR_EL0`; requires ring 0 / EL1.
#[no_mangle]
pub unsafe extern "C" fn nc_bm_pmu_read(pmu: *const nc_bm_pmu_t, out: *mut u64) -> i32 {
    let (Some(flat), Some(out)) = (unsafe { pmu.as_ref() }, unsafe { out.as_mut() }) else {
        return 0;
    };
    // The route is taken from what `nc_bm_pmu_enable` returned, not
    // re-established here. Re-enabling on every read — what this used to do,
    // because a freshly detected PMU never has a route — reprograms and
    // resets the counters between the two reads of an interval, so the
    // difference measured nothing.
    let mut live = CorePmu::detect();
    live.route = match flat.route {
        1 => CounterRoute::Fixed,
        // The index is checked against this core's own count: an
        // out-of-range `RDPMC` index is #GP, and the struct is caller memory.
        2 if flat.route_index < live.leaf.general_counters as u32 => {
            CounterRoute::General(flat.route_index)
        }
        _ => return 0,
    };
    // SAFETY: forwarded from this function's own contract; the route names a
    // counter this core has, programmed by `nc_bm_pmu_enable`.
    match unsafe { live.read_cycles() } {
        Some(r) => {
            *out = r.value;
            1
        }
        None => 0,
    }
}

/// The architectural counter, ordered. Nanoseconds are not implied: the unit
/// is counter ticks, and their rate is the platform's.
///
/// # Safety
/// Executes a counter read; requires ring 0 / EL1 on AArch64.
#[no_mangle]
pub unsafe extern "C" fn nc_bm_counter() -> u64 {
    crate::arch::counter_ordered()
}

/// Which AArch64 counter the kernel reads: 0 `CNTVCT_EL0` (virtual, default,
/// safe under a hypervisor), 1 `CNTPCT_EL0` (physical, bare metal only).
///
/// This reports the current selection, the same number a later
/// [`nc_bm_counter_source_set`] call would need to change it.
#[no_mangle]
pub extern "C" fn nc_bm_counter_source() -> u32 {
    crate::arch::counter_source().as_u8() as u32
}

/// Selects which AArch64 counter the kernel reads.
///
/// Pass the result of [`nc_bm_counter_source`]: 0 for the virtual counter
/// (default), 1 for the physical counter. The physical counter is **not
/// recommended inside a VM** — it exposes and splices together the host's
/// real timeline — so a loader should only set it on bare metal.
///
/// This is the backing store for the interface's *Enable Physical Counter*
/// toggle; on x86-64 it is a no-op, since there is one counter and no choice.
///
/// Returns the previously selected source (0 or 1).
#[no_mangle]
pub extern "C" fn nc_bm_counter_source_set(counter: u32) -> u32 {
    let source = crate::arch::CounterSource::from_u8(counter as u8);
    let previous = crate::arch::counter_source();
    let _ = crate::arch::set_counter_source(source);
    previous.as_u8() as u32
}

fn flatten(pmu: &CorePmu) -> nc_bm_pmu_t {
    use nanochrono_core::pmu_leaf::CoreType;
    nc_bm_pmu_t {
        version: pmu.leaf.version as u32,
        general_counters: pmu.leaf.general_counters as u32,
        general_width: pmu.leaf.general_width as u32,
        fixed_counters: pmu.leaf.fixed_counters as u32,
        fixed_width: pmu.leaf.fixed_width as u32,
        core_type: match pmu.core_type {
            CoreType::Uniform => 0,
            CoreType::Performance => 1,
            CoreType::Efficiency => 2,
            CoreType::Unknown(_) => 3,
        },
        route: route_code(pmu.route),
        route_index: match pmu.route {
            crate::pmu::CounterRoute::General(i) => i,
            _ => 0,
        },
    }
}

fn route_code(route: crate::pmu::CounterRoute) -> u32 {
    use crate::pmu::CounterRoute;
    match route {
        CounterRoute::None => 0,
        CounterRoute::Fixed => 1,
        CounterRoute::General(_) => 2,
    }
}

// ===========================================================================
// NC_RNG: the entropy pool.
//
// The same names, values, struct and meaning as libnanochrono's hosted
// functions (crates/nanochrono-ffi), so C written against one builds against
// the other. These are the ring-0 entry points: the caller vouches for its
// own pointers, as with any C function. A plugin reaches the pool through its
// NcApi instead, where its pointers and capabilities are checked
// (`crate::rng::nc_rng_fill` and friends).
// ===========================================================================

/// `nc_rng_fill` flag: a fresh credited seed before every 32-byte block
/// (slow; for long-term keys). Without it the output stage serves the read.
pub const NC_RNG_TRUE: u32 = 1;
/// `nc_rng_fill` flags value for the output stage (the default).
pub const NC_RNG_FAST: u32 = 0;
/// Most bytes one `nc_rng_fill` call may ask for.
pub const NC_RNG_MAX_FILL: u32 = 1 << 20;

/// Error codes (negative), as the entropy manual numbers them.
pub const NC_RNG_EMISUSE: i32 = -1;
pub const NC_RNG_ERCT: i32 = -2;
pub const NC_RNG_EAPT: i32 = -3;
pub const NC_RNG_ETIMER: i32 = -4;
pub const NC_RNG_ELAG: i32 = -5;
pub const NC_RNG_ERCT_PERMANENT: i32 = -6;
pub const NC_RNG_EAPT_PERMANENT: i32 = -7;
pub const NC_RNG_ELAG_PERMANENT: i32 = -8;
pub const NC_RNG_EMEMORY: i32 = -9;
pub const NC_RNG_EMEMORY_PERMANENT: i32 = -10;
pub const NC_RNG_ESELFTEST: i32 = -11;
pub const NC_RNG_ENOSOURCE: i32 = -12;

/// `nc_rng_status_t::flags` bits.
pub const NC_RNG_READY: u32 = 1 << 0;
pub const NC_RNG_DEGRADED: u32 = 1 << 1;
pub const NC_RNG_FAILED: u32 = 1 << 2;
pub const NC_RNG_SELFTEST_PASSED: u32 = 1 << 3;
pub const NC_RNG_ENGINE_FALLBACK: u32 = 1 << 4;

/// `nc_rng_status_t::sources` / `available` bits.
pub const NC_RNG_SOURCE_JITTER: u32 = 1 << 0;
pub const NC_RNG_SOURCE_RDSEED: u32 = 1 << 1;
pub const NC_RNG_SOURCE_RDRAND: u32 = 1 << 2;
pub const NC_RNG_SOURCE_PMU: u32 = 1 << 3;
pub const NC_RNG_SOURCE_EVENTS: u32 = 1 << 4;
pub const NC_RNG_SOURCE_EXTERNAL: u32 = 1 << 5;

/// `nc_rng_status_t::engine` values: the output stage's path.
pub const NC_RNG_ENGINE_VAES512: u32 = 1;
pub const NC_RNG_ENGINE_VAES256: u32 = 2;
pub const NC_RNG_ENGINE_AESNI: u32 = 3;
pub const NC_RNG_ENGINE_ARM_AES: u32 = 4;
pub const NC_RNG_ENGINE_CHACHA20: u32 = 5;

/// First event tag that belongs to the caller (`nc_rng_stir`).
pub const NC_RNG_EVENT_USER: u64 = 0x100;

/// A snapshot of the pool. Set `size` to `sizeof(nc_rng_status_t)` before
/// calling `nc_rng_status`; it comes back as the number of bytes written.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_rng_status_t {
    pub size: u32,
    /// `NC_RNG_READY`, `NC_RNG_DEGRADED`, … bits.
    pub flags: u32,
    /// `NC_RNG_SOURCE_*` bits that fed the most recent seed.
    pub sources: u32,
    /// `NC_RNG_SOURCE_*` bits this machine offers.
    pub available: u32,
    /// Latched health-test failures.
    pub health: u32,
    /// The last error code, 0 if none.
    pub last_error: i32,
    /// Current oversampling rate (jitter samples per credited bit).
    pub osr: u32,
    /// Stuck samples in the timer's start-up test, per mille.
    pub startup_stuck_permille: u32,
    /// `NC_RNG_ENGINE_*`; 0 before the pool has started.
    pub engine: u32,
    pub reserved: u32,
    /// The timer's granularity, learned at start-up.
    pub granularity: u64,
    pub reseeds: u64,
    pub bytes_out: u64,
    pub jitter_samples: u64,
    pub jitter_stuck: u64,
    pub events: u64,
    pub hw_words: u64,
    /// Output-stage nonces consumed: one per request, never reused.
    pub nonces: u64,
}

// The pool's own struct is copied out byte for byte, so the two layouts must
// stay identical — as they must with the hosted library's, which states the
// same check.
const _: () = assert!(
    core::mem::size_of::<nc_rng_status_t>()
        == core::mem::size_of::<nanochrono_core::rng::Status>()
);
const _: () = assert!(
    core::mem::align_of::<nc_rng_status_t>()
        == core::mem::align_of::<nanochrono_core::rng::Status>()
);

/// A ring-0 caller's pointer is its own: nothing to check it against.
fn ring0_owns(_ptr: usize, _len: usize) -> bool {
    true
}

/// Fills `buf` with `len` bytes and returns `len`, or a negative `NC_RNG_E*`
/// code with `buf` zeroed. `flags` is `NC_RNG_FAST` or `NC_RNG_TRUE`; at most
/// `NC_RNG_MAX_FILL` bytes per call.
///
/// # Safety
/// `buf` must be valid for writes of `len` bytes. Ring 0 / EL1.
#[no_mangle]
pub unsafe extern "C" fn nc_rng_fill(buf: *mut core::ffi::c_void, len: usize, flags: u32) -> i64 {
    crate::rng::fill_c(buf.cast::<u8>(), len, flags, ring0_owns)
}

/// Writes a snapshot of the pool into `out`: set `out->size` to
/// `sizeof(nc_rng_status_t)` first. Returns 0 or a negative `NC_RNG_E*` code.
///
/// # Safety
/// `out` must be valid for reads and writes of `out->size` bytes. Ring 0 /
/// EL1.
#[no_mangle]
pub unsafe extern "C" fn nc_rng_status(out: *mut nc_rng_status_t) -> i32 {
    crate::rng::status_c(out.cast::<u8>(), ring0_owns)
}

/// Mixes the caller's event into the pool, uncredited. Tags from
/// `NC_RNG_EVENT_USER` up are the caller's.
#[no_mangle]
pub extern "C" fn nc_rng_stir(tag: u64, value: u64) {
    crate::rng::stir(tag, value);
}

/// Re-runs the known-answer tests: 0, or `NC_RNG_ESELFTEST` with the pool out
/// of service.
#[no_mangle]
pub extern "C" fn nc_rng_selftest() -> i32 {
    crate::rng::selftest_c()
}
