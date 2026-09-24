// SPDX-License-Identifier: Apache-2.0
//! The C ABI a loaded module is reached through.
//!
//! Only meaningful for the shared object: a kernel linking the static archive
//! calls the Rust API directly and needs none of this. It exists because a
//! symbol resolver looks names up, and Rust's mangled names are not a stable
//! thing to look up — see `docs/BAREMETAL_LIBRARIES.md` for the loader that
//! has to exist on the other side.
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
