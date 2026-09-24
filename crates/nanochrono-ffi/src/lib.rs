// SPDX-License-Identifier: Apache-2.0
//! C ABI for NanoChronometer.
//!
//! The project ships wrappers for Python, Go, Java, C#, Node, Lua and Zig, all
//! of which load `nanochrono.{so,dll,dylib}` and call `nc_*` symbols. This
//! crate keeps that contract: same names, same signatures, same
//! `nc_backend_t` discriminants, so the wrappers work unchanged against the
//! Rust implementation.
//!
//! # Rules for everything below
//!
//! * A null context is not an error. Every accessor returns a documented
//!   default, because the C callers do not check and never did.
//! * No panic may cross the boundary. Unwinding into C is undefined behaviour,
//!   so anything fallible returns a status code instead.
//! * Buffers are written only within the capacity the caller states, and
//!   output strings are always NUL-terminated.

// The identifiers here are the C ABI. Renaming them to Rust conventions would
// break every wrapper that links against this library.
#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_void};

use nanochrono_core::{
    clock::{self, ClockRoute, StableClockConfig},
    dispatch::Dispatcher,
    format::{self, DetailMode, TimeZoneMode},
    ntp, platform,
    probe::{self, CacheProbe},
    Backend, Chronometer, CryptoKernel, NanoclockSnapshot, SimdFamily,
};

/// Opaque handle. Layout is deliberately not part of the ABI.
pub struct nc_ctx(Chronometer);

// -- status codes ----------------------------------------------------------

pub const NC_OK: c_int = 0;
pub const NC_ERR_UNSUPPORTED: c_int = -1;
pub const NC_ERR_BAD_ARGUMENT: c_int = -2;
pub const NC_ERR_CRYPTO_BACKEND: c_int = -3;

// -- lifecycle -------------------------------------------------------------

/// Creates a chronometer on the dispatcher's chosen backend.
///
/// Returns null only if allocation fails. Free with [`nc_destroy`].
#[no_mangle]
pub extern "C" fn nc_create() -> *mut nc_ctx {
    Box::into_raw(Box::new(nc_ctx(Chronometer::new())))
}

/// Creates a chronometer on a specific backend, degrading if unsupported.
#[no_mangle]
pub extern "C" fn nc_create_backend(backend: u32) -> *mut nc_ctx {
    let backend = backend_from_u32(backend);
    Box::into_raw(Box::new(nc_ctx(Chronometer::with_backend(backend))))
}

/// Frees a chronometer. Null is a no-op.
#[no_mangle]
pub unsafe extern "C" fn nc_destroy(ctx: *mut nc_ctx) {
    if !ctx.is_null() {
        drop(unsafe { Box::from_raw(ctx) });
    }
}

/// Re-measures the counter frequency. Returns 1 on success.
#[no_mangle]
pub unsafe extern "C" fn nc_calibrate(ctx: *mut nc_ctx, ms: u32) -> c_int {
    match unsafe { ctx.as_mut() } {
        Some(c) => c.0.calibrate(ms) as c_int,
        None => 0,
    }
}

/// Rebases the elapsed-time origin to now.
#[no_mangle]
pub unsafe extern "C" fn nc_reset(ctx: *mut nc_ctx) {
    if let Some(c) = unsafe { ctx.as_mut() } {
        c.0.reset();
    }
}

// -- start / stop ----------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn nc_start(ctx: *mut nc_ctx) -> u64 {
    unsafe { ctx.as_mut() }.map_or(0, |c| c.0.start())
}

#[no_mangle]
pub unsafe extern "C" fn nc_stop(ctx: *mut nc_ctx) -> u64 {
    unsafe { ctx.as_mut() }.map_or(0, |c| c.0.elapsed_units())
}

#[no_mangle]
pub unsafe extern "C" fn nc_now_cycles(ctx: *mut nc_ctx) -> u64 {
    unsafe { ctx.as_ref() }.map_or(0, |c| c.0.now_units())
}

// -- conversion ------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn nc_cycles_to_ns(ctx: *mut nc_ctx, cycles: u64) -> u64 {
    unsafe { ctx.as_ref() }.map_or(0, |c| c.0.units_to_ns(cycles))
}

#[no_mangle]
pub unsafe extern "C" fn nc_cycles_to_us(ctx: *mut nc_ctx, cycles: u64) -> u64 {
    unsafe { ctx.as_ref() }.map_or(0, |c| c.0.units_to_us(cycles))
}

#[no_mangle]
pub unsafe extern "C" fn nc_cycles_to_ms(ctx: *mut nc_ctx, cycles: u64) -> u64 {
    unsafe { ctx.as_ref() }.map_or(0, |c| c.0.units_to_ms(cycles))
}

#[no_mangle]
pub unsafe extern "C" fn nc_cycles_to_sec(ctx: *mut nc_ctx, cycles: u64) -> f64 {
    unsafe { ctx.as_ref() }.map_or(0.0, |c| c.0.units_to_secs(cycles))
}

#[no_mangle]
pub unsafe extern "C" fn nc_ns_to_cycles(ctx: *mut nc_ctx, ns: u64) -> u64 {
    unsafe { ctx.as_ref() }.map_or(0, |c| c.0.ns_to_units(ns))
}

// -- elapsed ---------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn nc_elapsed_cycles(ctx: *mut nc_ctx) -> u64 {
    unsafe { ctx.as_mut() }.map_or(0, |c| c.0.elapsed_units())
}

#[no_mangle]
pub unsafe extern "C" fn nc_elapsed_ns(ctx: *mut nc_ctx) -> u64 {
    unsafe { ctx.as_mut() }.map_or(0, |c| c.0.elapsed_ns())
}

#[no_mangle]
pub unsafe extern "C" fn nc_elapsed_us(ctx: *mut nc_ctx) -> u64 {
    unsafe { ctx.as_mut() }.map_or(0, |c| c.0.elapsed_us())
}

#[no_mangle]
pub unsafe extern "C" fn nc_elapsed_ms(ctx: *mut nc_ctx) -> u64 {
    unsafe { ctx.as_mut() }.map_or(0, |c| c.0.elapsed_ms())
}

#[no_mangle]
pub unsafe extern "C" fn nc_elapsed_sec(ctx: *mut nc_ctx) -> f64 {
    unsafe { ctx.as_mut() }.map_or(0.0, |c| c.0.elapsed_secs())
}

// -- spin sleep ------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn nc_sleep_ns(ctx: *mut nc_ctx, ns: u64) {
    if let Some(c) = unsafe { ctx.as_ref() } {
        c.0.spin_ns(ns);
    }
}

#[no_mangle]
pub unsafe extern "C" fn nc_sleep_us(ctx: *mut nc_ctx, us: u64) {
    if let Some(c) = unsafe { ctx.as_ref() } {
        c.0.spin_us(us);
    }
}

// -- info ------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn nc_tsc_hz(ctx: *mut nc_ctx) -> u64 {
    unsafe { ctx.as_ref() }.map_or(0, |c| c.0.counter_hz())
}

#[no_mangle]
pub unsafe extern "C" fn nc_drift_ppm(ctx: *mut nc_ctx) -> f64 {
    unsafe { ctx.as_ref() }.map_or(0.0, |c| c.0.drift_ppm())
}

#[no_mangle]
pub unsafe extern "C" fn nc_backend(ctx: *mut nc_ctx) -> u32 {
    unsafe { ctx.as_ref() }.map_or(Backend::Legacy as u32, |c| c.0.backend() as u32)
}

/// Name of a backend. The returned pointer is a static string; never free it.
#[no_mangle]
pub extern "C" fn nc_backend_name(backend: u32) -> *const c_char {
    static_cstr(backend_from_u32(backend).name())
}

#[no_mangle]
pub extern "C" fn nc_backend_is_available(backend: u32) -> c_int {
    backend_from_u32(backend).is_available() as c_int
}

#[no_mangle]
pub extern "C" fn nc_select_best_backend() -> u32 {
    Dispatcher::global().backend() as u32
}

#[no_mangle]
pub unsafe extern "C" fn nc_measure_overhead_cycles(ctx: *mut nc_ctx) -> u64 {
    unsafe { ctx.as_mut() }.map_or(0, |c| c.0.measure_overhead())
}

#[no_mangle]
pub unsafe extern "C" fn nc_measure_ffi_overhead_cycles(ctx: *mut nc_ctx, iterations: u32) -> u64 {
    unsafe { ctx.as_ref() }.map_or(0, |c| c.0.measure_ffi_overhead(iterations))
}

/// Best-case cost of calling `f(arg)`, in counter units.
///
/// # Safety
/// `f` must be a valid C function pointer that does not unwind.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_call_overhead_cycles(
    ctx: *mut nc_ctx,
    f: Option<extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    iterations: u32,
) -> u64 {
    let (Some(c), Some(f)) = (unsafe { ctx.as_ref() }, f) else {
        return 0;
    };
    c.0.measure_call_overhead(|| f(arg), iterations)
}

// -- CPU features ----------------------------------------------------------

/// Mirrors the C `nc_cpu_features_t` field order exactly.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_cpu_features_t {
    pub mmx: c_int,
    pub sse: c_int,
    pub sse2: c_int,
    pub sse3: c_int,
    pub ssse3: c_int,
    pub sse41: c_int,
    pub sse42: c_int,
    pub aesni: c_int,
    pub pclmulqdq: c_int,
    pub shani: c_int,
    pub avx: c_int,
    pub f16c: c_int,
    pub fma: c_int,
    pub avx2: c_int,
    pub avx_vnni: c_int,
    pub vaes: c_int,
    pub avx512f: c_int,
    pub avx512bw: c_int,
    pub avx512vl: c_int,
    pub avx512vnni: c_int,
}

/// Fills `out` with detected CPU features. Null is a no-op.
#[no_mangle]
pub unsafe extern "C" fn nc_get_cpu_features(out: *mut nc_cpu_features_t) {
    let Some(out) = (unsafe { out.as_mut() }) else {
        return;
    };
    let f = nanochrono_core::cpu::features();
    *out = nc_cpu_features_t {
        mmx: f.mmx as c_int,
        sse: f.sse as c_int,
        sse2: f.sse2 as c_int,
        sse3: f.sse3 as c_int,
        ssse3: f.ssse3 as c_int,
        sse41: f.sse41 as c_int,
        sse42: f.sse42 as c_int,
        aesni: f.aesni as c_int,
        pclmulqdq: f.pclmulqdq as c_int,
        shani: f.shani as c_int,
        avx: f.avx as c_int,
        f16c: f.f16c as c_int,
        fma: f.fma as c_int,
        avx2: f.avx2 as c_int,
        avx_vnni: f.avx_vnni as c_int,
        vaes: f.vaes as c_int,
        avx512f: f.avx512f as c_int,
        avx512bw: f.avx512bw as c_int,
        avx512vl: f.avx512vl as c_int,
        avx512vnni: f.avx512vnni as c_int,
    };
}

/// Emits one `nc_cpu_has_*` predicate per feature flag.
macro_rules! feature_predicates {
    ($( $name:ident => $field:ident ),+ $(,)?) => {
        $(
            #[no_mangle]
            pub extern "C" fn $name() -> c_int {
                nanochrono_core::cpu::features().$field as c_int
            }
        )+
    };
}

feature_predicates! {
    nc_cpu_has_mmx => mmx,
    nc_cpu_has_sse => sse,
    nc_cpu_has_sse2 => sse2,
    nc_cpu_has_sse3 => sse3,
    nc_cpu_has_ssse3 => ssse3,
    nc_cpu_has_sse41 => sse41,
    nc_cpu_has_sse42 => sse42,
    nc_cpu_has_aesni => aesni,
    nc_cpu_has_shani => shani,
    nc_cpu_has_vaes => vaes,
    nc_cpu_has_pclmulqdq => pclmulqdq,
    nc_cpu_has_f16c => f16c,
    nc_cpu_has_fma => fma,
    nc_cpu_has_avx2 => avx2,
    nc_cpu_has_avx_vnni => avx_vnni,
    nc_cpu_has_avx512f => avx512f,
    nc_cpu_has_avx512bw => avx512bw,
    nc_cpu_has_avx512vl => avx512vl,
    nc_cpu_has_avx512vnni => avx512vnni,
}

#[no_mangle]
pub extern "C" fn nc_is_avx_available() -> c_int {
    nanochrono_core::cpu::features().avx as c_int
}

// -- raw counters ----------------------------------------------------------

#[no_mangle]
pub extern "C" fn nc_tsc_raw() -> u64 {
    nanochrono_core::arch::counter_raw()
}

#[no_mangle]
pub extern "C" fn nc_tsc_start() -> u64 {
    nanochrono_core::arch::counter_start()
}

#[no_mangle]
pub extern "C" fn nc_tsc_end() -> u64 {
    nanochrono_core::arch::counter_end()
}

/// Core/socket id from the last counter read, or 0 where unavailable.
#[no_mangle]
pub extern "C" fn nc_tsc_aux() -> u32 {
    nanochrono_core::arch::counter_aux().unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn nc_tsc_overhead() -> u64 {
    nanochrono_core::arch::read_overhead()
}

#[no_mangle]
pub extern "C" fn nc_tsc_delta(start: u64, end: u64) -> u64 {
    end.wrapping_sub(start)
}

#[no_mangle]
pub extern "C" fn nc_tsc_invariant() -> c_int {
    nanochrono_core::cpu::features().invariant_counter as c_int
}

#[no_mangle]
pub extern "C" fn nc_wall_time_ns() -> u64 {
    platform::monotonic_ns()
}

#[no_mangle]
pub extern "C" fn nc_monotonic_time_ns() -> u64 {
    platform::monotonic_ns()
}

#[no_mangle]
pub extern "C" fn nc_unix_time_ns() -> u64 {
    platform::unix_time_ns()
}

#[no_mangle]
pub extern "C" fn nc_process_time_ns() -> u64 {
    platform::process_time_ns()
}

#[no_mangle]
pub extern "C" fn nc_thread_time_ns() -> u64 {
    platform::thread_time_ns()
}

#[no_mangle]
pub extern "C" fn nc_cpu_relax() {
    nanochrono_core::arch::cpu_relax();
}

#[no_mangle]
pub extern "C" fn nc_memory_barrier() {
    nanochrono_core::arch::memory_barrier();
}

// -- affinity --------------------------------------------------------------

#[no_mangle]
pub extern "C" fn nc_clock_current_cpu() -> u32 {
    platform::current_cpu()
}

#[no_mangle]
pub extern "C" fn nc_clock_pin_thread_to_cpu(cpu_index: u32) -> c_int {
    platform::pin_thread_to_cpu(cpu_index) as c_int
}

// -- formatting ------------------------------------------------------------

/// Writes `hh:mm:ss:mmm:uuu:nnn` into `buf`.
#[no_mangle]
pub unsafe extern "C" fn nc_format_ns(ns: u64, buf: *mut c_char, cap: usize) {
    unsafe { write_cstr(&format::format_elapsed_nano(ns), buf, cap) };
}

/// Writes the current elapsed time into `buf`.
#[no_mangle]
pub unsafe extern "C" fn nc_format_elapsed(ctx: *mut nc_ctx, buf: *mut c_char, cap: usize) {
    let ns = unsafe { ctx.as_mut() }.map_or(0, |c| c.0.elapsed_ns());
    unsafe { write_cstr(&format::format_elapsed_nano(ns), buf, cap) };
}

/// Writes a UTC timestamp into `buf`.
#[no_mangle]
pub unsafe extern "C" fn nc_format_unix_time_ns(unix_ns: u64, buf: *mut c_char, cap: usize) {
    unsafe { write_cstr(&format::format_unix_utc(unix_ns), buf, cap) };
}

/// Writes a zoned timestamp into `buf`. `mode`: 0 local, 1 UTC, 2 fixed offset.
/// Returns 1 on success.
#[no_mangle]
pub unsafe extern "C" fn nc_format_unix_time_ns_ex(
    unix_ns: u64,
    mode: u32,
    utc_offset_minutes: i32,
    buf: *mut c_char,
    cap: usize,
) -> c_int {
    let zone = match mode {
        1 => TimeZoneMode::Utc,
        2 => TimeZoneMode::CustomOffset(utc_offset_minutes),
        _ => TimeZoneMode::Local,
    };
    unsafe { write_cstr(&format::format_unix_zoned(unix_ns, zone), buf, cap) }
}

/// Writes just the time of day. `detail`: 0 simple, 1 nanosecond.
#[no_mangle]
pub unsafe extern "C" fn nc_format_clock_face(
    unix_ns: u64,
    mode: u32,
    utc_offset_minutes: i32,
    detail: u32,
    buf: *mut c_char,
    cap: usize,
) -> c_int {
    let zone = match mode {
        1 => TimeZoneMode::Utc,
        2 => TimeZoneMode::CustomOffset(utc_offset_minutes),
        _ => TimeZoneMode::Local,
    };
    let fractional = detail == DetailMode::Nano as u32 || detail == 1;
    unsafe {
        write_cstr(
            &format::format_clock_face(unix_ns, zone, fractional),
            buf,
            cap,
        )
    }
}

// -- clock routes and snapshot ---------------------------------------------

#[no_mangle]
pub extern "C" fn nc_clock_route_name(route: u32) -> *const c_char {
    static_cstr(route_from_u32(route).name())
}

#[no_mangle]
pub extern "C" fn nc_clock_select_best_route() -> u32 {
    route_to_u32(ClockRoute::best())
}

#[no_mangle]
pub extern "C" fn nc_asm_simd_family_name(family: u32) -> *const c_char {
    static_cstr(
        SimdFamily::ALL
            .get(family as usize)
            .map_or("unknown", |f| f.name()),
    )
}

/// `nc_set_physical_counter` result: the counter was switched.
pub const NC_COUNTER_OK: c_int = 0;
/// The architecture has no separate physical counter (only AArch64 does).
pub const NC_COUNTER_NO_PHYSICAL: c_int = -1;
/// The OS does not let this process read `CNTPCT_EL0`.
pub const NC_COUNTER_NOT_PERMITTED: c_int = -2;

/// AArch64: nonzero selects the physical counter (`CNTPCT_EL0`) for every
/// read, zero the virtual one (`CNTVCT_EL0`, the default).
///
/// A virtual machine is not a refusal: the counter can be enabled there,
/// which is what [`nc_physical_counter_warning`] exists to caution against —
/// the hypervisor may trap every read, and under nested virtualization it is
/// slow and unstable. Call before creating a context so its calibration uses
/// the chosen counter.
#[no_mangle]
pub extern "C" fn nc_set_physical_counter(enable: c_int) -> c_int {
    use nanochrono_core::arch::{self, CounterSource, CounterSourceError};
    let source = if enable != 0 { CounterSource::Physical } else { CounterSource::Virtual };
    match arch::set_counter_source(source) {
        Ok(()) => NC_COUNTER_OK,
        Err(CounterSourceError::NoPhysicalCounter) => NC_COUNTER_NO_PHYSICAL,
        Err(CounterSourceError::NotPermitted) => NC_COUNTER_NOT_PERMITTED,
    }
}

/// 1 when reads use the physical counter, 0 otherwise.
#[no_mangle]
pub extern "C" fn nc_physical_counter_enabled() -> c_int {
    (nanochrono_core::arch::counter_source() == nanochrono_core::arch::CounterSource::Physical) as c_int
}

/// The warning interfaces should show next to the setting (static string).
#[no_mangle]
pub extern "C" fn nc_physical_counter_warning() -> *const c_char {
    static_cstr(nanochrono_core::arch::PHYSICAL_COUNTER_WARNING)
}

#[no_mangle]
pub extern "C" fn nc_select_best_simd_family() -> u32 {
    SimdFamily::best().map_or(0, |f| f as u32)
}

#[no_mangle]
pub extern "C" fn nc_asm_simd_family_available(family: u32) -> c_int {
    SimdFamily::ALL
        .get(family as usize)
        .is_some_and(|f| f.is_available()) as c_int
}

/// Reads one clock route. Writes raw units to `raw_out` when non-null,
/// returns nanoseconds.
#[no_mangle]
pub unsafe extern "C" fn nc_nanoclock_now_ns(
    ctx: *mut nc_ctx,
    route: u32,
    raw_out: *mut u64,
) -> u64 {
    let Some(c) = (unsafe { ctx.as_ref() }) else {
        return 0;
    };
    let (raw, ns) = route_from_u32(route).read(&c.0);
    if let Some(slot) = unsafe { raw_out.as_mut() } {
        *slot = raw;
    }
    ns
}

/// Flattened `NanoclockSnapshot` for C consumers.
///
/// Field order and padding match the 2.x `nc_nanoclock_snapshot_t` byte for
/// byte, including the implicit four bytes after `backend`. The Python, Go and
/// C# wrappers declare this layout by hand, so changing it would silently
/// corrupt every field they read.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_nanoclock_snapshot_t {
    pub status: c_int,
    pub arch: u32,
    pub route: u32,
    pub best_simd_family: u32,
    pub backend: u32,
    /// Explicit, not implicit: the 2.x ABI had four bytes of padding here
    /// that the compiler inserted to 8-align the `u64` run. On i386 System V
    /// (Linux, Android) a `u64` is only 4-aligned, so the implicit padding
    /// vanished there and every later field moved by four bytes — and Go and
    /// .NET, which disagree with C about that alignment, would read a third
    /// layout. Spelled out, the offsets are the same on every target and
    /// unchanged from 2.x on the 64-bit ones.
    pub _pad_backend: u32,
    pub unix_time_ns: u64,
    pub monotonic_ns: u64,
    pub process_time_ns: u64,
    pub thread_time_ns: u64,
    pub selected_raw_units: u64,
    pub selected_ns: u64,
    pub selected_overhead_units: u64,
    pub rdtsc_raw: u64,
    pub rdtsc_lfence: u64,
    pub rdtsc_mfence: u64,
    pub rdtscp_lfence: u64,
    pub rdtscp_aux: u32,
    pub _pad0: u32,
    pub arm64_cntfrq_el0: u64,
    pub arm64_cntvct_el0: u64,
    pub arm64_cntvct_isb: u64,
    pub arm64_cntvct_ns: u64,
    /// Thread cycles from `perf_event_open`. Occupies the slot 2.x used for
    /// `arm64_pmccntr_el0`, which no longer exists — see [`nanochrono_core::perf`].
    pub perf_cycles: u64,
    pub perf_cycles_ns: u64,
    pub perf_available: u32,
    pub perf_status: u32,
    pub best_simd_counter: u64,
    pub best_simd_counter_ns: u64,
    pub native_overhead_cycles: u64,
    pub ffi_overhead_cycles: u64,
    pub dll_boundary_cycles: u64,
    pub wrapper_hint_cycles: u64,
}

/// Architecture tags, as reported in `nc_nanoclock_snapshot_t::arch`.
pub const NC_ARCH_UNKNOWN: u32 = 0;
pub const NC_ARCH_X64: u32 = 1;
pub const NC_ARCH_ARM64: u32 = 2;
/// PowerPC, 32- or 64-bit, either byte order.
pub const NC_ARCH_POWERPC: u32 = 3;
/// RISC-V, RV32 or RV64.
pub const NC_ARCH_RISCV: u32 = 4;
/// 32-bit ARM.
pub const NC_ARCH_ARM32: u32 = 5;

/// Captures every clock route into `out`. Returns 1 on success.
#[no_mangle]
pub unsafe extern "C" fn nc_nanoclock_snapshot(
    ctx: *mut nc_ctx,
    out: *mut nc_nanoclock_snapshot_t,
) -> c_int {
    let (Some(c), Some(out)) = (unsafe { ctx.as_ref() }, unsafe { out.as_mut() }) else {
        return 0;
    };
    let s: NanoclockSnapshot = NanoclockSnapshot::capture(&c.0);
    *out = nc_nanoclock_snapshot_t {
        status: NC_OK,
        arch: match nanochrono_core::arch::ARCH {
            nanochrono_core::arch::Arch::X86 => NC_ARCH_X64,
            nanochrono_core::arch::Arch::Aarch64 => NC_ARCH_ARM64,
            nanochrono_core::arch::Arch::PowerPc => NC_ARCH_POWERPC,
            nanochrono_core::arch::Arch::RiscV => NC_ARCH_RISCV,
            nanochrono_core::arch::Arch::Arm32 => NC_ARCH_ARM32,
            nanochrono_core::arch::Arch::Portable => NC_ARCH_UNKNOWN,
        },
        route: route_to_u32(s.route),
        best_simd_family: s.best_simd.map_or(0, |f| f as u32),
        backend: s.backend as u32,
        _pad_backend: 0,
        unix_time_ns: s.unix_time_ns,
        monotonic_ns: s.monotonic_ns,
        process_time_ns: s.process_time_ns,
        thread_time_ns: s.thread_time_ns,
        selected_raw_units: s.selected_raw_units,
        selected_ns: s.selected_ns,
        selected_overhead_units: s.selected_overhead_units,
        rdtsc_raw: s.rdtsc_raw,
        rdtsc_lfence: s.rdtsc_lfence,
        rdtsc_mfence: s.rdtsc_mfence,
        rdtscp_lfence: s.rdtscp_lfence,
        rdtscp_aux: s.rdtscp_aux,
        arm64_cntfrq_el0: s.cntfrq_el0,
        arm64_cntvct_el0: s.cntvct_el0,
        arm64_cntvct_isb: s.cntvct_isb,
        arm64_cntvct_ns: s.cntvct_ns,
        perf_cycles: s.perf_cycles.unwrap_or(0),
        perf_cycles_ns: s.perf_cycles.map_or(0, |v| c.0.units_to_ns(v)),
        perf_available: s.perf_cycles.is_some() as u32,
        perf_status: if s.perf_cycles.is_some() {
            NC_OK as u32
        } else {
            NC_ERR_UNSUPPORTED as u32
        },
        best_simd_counter: s.simd_counter,
        best_simd_counter_ns: s.simd_counter_ns,
        native_overhead_cycles: s.native_overhead_units,
        ffi_overhead_cycles: s.ffi_overhead_units,
        dll_boundary_cycles: s.ffi_overhead_units,
        wrapper_hint_cycles: s.ffi_overhead_units,
        _pad0: 0,
    };
    1
}

// -- calibration -----------------------------------------------------------

/// Result of [`nc_calibrate_cycles_per_ns`].
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_stable_clock_state_t {
    pub status: c_int,
    pub route: u32,
    pub pinned: u32,
    pub cpu_before: u32,
    pub cpu_after: u32,
    pub migrated: u32,
    pub invariant_hint: u32,
    pub _pad: u32,
    pub raw_start: u64,
    pub raw_end: u64,
    pub elapsed_units: u64,
    pub elapsed_ns: u64,
    pub cycles_per_ns: f64,
    pub ns_per_cycle: f64,
    pub read_overhead_units: u64,
    pub kernel_timecall_overhead_cycles: u64,
    pub api_call_overhead_cycles: u64,
}

/// Calibrates cycles-per-nanosecond. Returns 1 when the factor is usable.
#[no_mangle]
pub unsafe extern "C" fn nc_calibrate_cycles_per_ns(
    ctx: *mut nc_ctx,
    pin_cpu: u32,
    cpu_index: u32,
    calibration_ms: u32,
    out: *mut nc_stable_clock_state_t,
) -> c_int {
    let (Some(c), Some(out)) = (unsafe { ctx.as_ref() }, unsafe { out.as_mut() }) else {
        return 0;
    };
    let config = StableClockConfig {
        pin_cpu: pin_cpu != 0,
        cpu_index,
        calibration_ms: if calibration_ms == 0 {
            500
        } else {
            calibration_ms
        },
        require_no_migration: false,
        ..Default::default()
    };
    let s = clock::calibrate_cycles_per_ns(&c.0, &config);
    *out = nc_stable_clock_state_t {
        status: if s.is_usable() {
            NC_OK
        } else {
            NC_ERR_UNSUPPORTED
        },
        route: route_to_u32(s.route),
        pinned: s.pinned as u32,
        cpu_before: s.cpu_before,
        cpu_after: s.cpu_after,
        migrated: s.migrated as u32,
        invariant_hint: s.invariant as u32,
        raw_start: s.raw_start,
        raw_end: s.raw_end,
        elapsed_units: s.elapsed_units,
        elapsed_ns: s.elapsed_ns,
        cycles_per_ns: s.cycles_per_ns(),
        ns_per_cycle: s.ns_per_cycle(),
        read_overhead_units: s.read_overhead_units,
        kernel_timecall_overhead_cycles: s.kernel_timecall_overhead_units,
        api_call_overhead_cycles: s.api_call_overhead_units,
        ..Default::default()
    };
    s.is_usable() as c_int
}

/// Mirrors the C `nc_stable_clock_config_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_stable_clock_config_t {
    pub route: u32,
    pub pin_cpu: u32,
    pub cpu_index: u32,
    pub warmup_ms: u32,
    pub calibration_ms: u32,
    pub samples: u32,
    pub require_no_migration: u32,
}

/// Fills `cfg` with the defaults. Returns 1 on success.
#[no_mangle]
pub unsafe extern "C" fn nc_stable_clock_default_config(
    cfg: *mut nc_stable_clock_config_t,
) -> c_int {
    let Some(cfg) = (unsafe { cfg.as_mut() }) else {
        return 0;
    };
    let d = StableClockConfig::default();
    *cfg = nc_stable_clock_config_t {
        route: route_to_u32(d.route),
        pin_cpu: d.pin_cpu as u32,
        cpu_index: d.cpu_index,
        warmup_ms: d.warmup_ms,
        calibration_ms: d.calibration_ms,
        // The Rust calibration is time-bounded rather than sample-bounded,
        // so this reports the window in microseconds: the same number the C
        // default carried, and what `nc_calibrate_clock_route` reads back.
        samples: d.calibration_ms.saturating_mul(1_000),
        require_no_migration: d.require_no_migration as u32,
    };
    1
}

/// Mirrors the C `nc_clock_calibration_result_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_clock_calibration_result_t {
    pub status: c_int,
    pub route: u32,
    pub cpu_before: u32,
    pub cpu_after: u32,
    pub migrated: u32,
    pub pinned: u32,
    pub samples: u64,
    pub elapsed_raw_units: u64,
    pub elapsed_ns: u64,
    pub units_per_second: f64,
    pub ns_per_unit: f64,
    pub ppm_error_vs_context: f64,
    pub read_overhead_units: u64,
    pub kernel_timecall_overhead_cycles: u64,
    pub api_call_overhead_cycles: u64,
}

/// Calibrates one specific clock route. Returns 1 when the result is usable.
///
/// `samples` is honoured as a calibration window in milliseconds, capped so a
/// caller passing the C default of 200000 does not stall for three minutes.
#[no_mangle]
pub unsafe extern "C" fn nc_calibrate_clock_route(
    ctx: *mut nc_ctx,
    route: u32,
    samples: u32,
    pin_cpu: u32,
    cpu_index: u32,
    out: *mut nc_clock_calibration_result_t,
) -> c_int {
    let (Some(c), Some(out)) = (unsafe { ctx.as_ref() }, unsafe { out.as_mut() }) else {
        return 0;
    };
    let config = StableClockConfig {
        route: route_from_u32(route),
        pin_cpu: pin_cpu != 0,
        cpu_index,
        calibration_ms: (samples / 1_000).clamp(50, 2_000),
        require_no_migration: false,
        ..Default::default()
    };
    let s = clock::calibrate_cycles_per_ns(&c.0, &config);
    let units_per_second = s.cycles_per_ns() * 1e9;
    let context_hz = c.0.counter_hz() as f64;
    *out = nc_clock_calibration_result_t {
        status: if s.is_usable() {
            NC_OK
        } else {
            NC_ERR_UNSUPPORTED
        },
        route: route_to_u32(s.route),
        cpu_before: s.cpu_before,
        cpu_after: s.cpu_after,
        migrated: s.migrated as u32,
        pinned: s.pinned as u32,
        samples: samples as u64,
        elapsed_raw_units: s.elapsed_units,
        elapsed_ns: s.elapsed_ns,
        units_per_second,
        ns_per_unit: s.ns_per_cycle(),
        ppm_error_vs_context: if context_hz > 0.0 {
            (units_per_second - context_hz) / context_hz * 1e6
        } else {
            0.0
        },
        read_overhead_units: s.read_overhead_units,
        kernel_timecall_overhead_cycles: s.kernel_timecall_overhead_units,
        api_call_overhead_cycles: s.api_call_overhead_units,
    };
    s.is_usable() as c_int
}

/// Best-case cost of one OS time syscall, in counter units.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_kernel_timecall_overhead_cycles(
    ctx: *mut nc_ctx,
    iterations: u32,
) -> u64 {
    match unsafe { ctx.as_ref() } {
        Some(c) => clock::measure_kernel_timecall_overhead(&c.0, iterations),
        None => 0,
    }
}

/// Best-case cost of one call across this library's own boundary.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_api_call_overhead_cycles(
    ctx: *mut nc_ctx,
    iterations: u32,
) -> u64 {
    match unsafe { ctx.as_ref() } {
        Some(c) => clock::measure_api_call_overhead(&c.0, iterations),
        None => 0,
    }
}

/// Reads one specific route's raw counter without disturbing the context.
#[no_mangle]
pub unsafe extern "C" fn nc_clock_read_raw_route(ctx: *mut nc_ctx, route: u32) -> u64 {
    match unsafe { ctx.as_ref() } {
        Some(c) => route_from_u32(route).read_raw(&c.0),
        None => 0,
    }
}

/// Converts a raw counter delta to nanoseconds with a calibrated factor.
#[no_mangle]
pub extern "C" fn nc_raw_delta_to_ns_calibrated(
    raw_start: u64,
    raw_end: u64,
    units_per_ns: f64,
) -> u64 {
    clock::raw_delta_to_ns(raw_start, raw_end, units_per_ns)
}

#[no_mangle]
pub extern "C" fn nc_cycles_to_ns_calibrated(cycles: u64, cycles_per_ns: f64) -> u64 {
    clock::units_to_ns_calibrated(cycles, cycles_per_ns)
}

#[no_mangle]
pub extern "C" fn nc_clock_stability_advice() -> *const c_char {
    static_cstr(clock::STABILITY_ADVICE)
}

// -- NTP -------------------------------------------------------------------

/// Result of [`nc_ntp_query`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nc_ntp_sample_t {
    pub status: c_int,
    pub stratum: u32,
    pub version: u32,
    pub leap_indicator: u32,
    pub migrated: u32,
    pub _pad: u32,
    pub local_send_unix_ns: u64,
    pub local_recv_unix_ns: u64,
    pub ntp_transmit_unix_ns: u64,
    pub offset_ns: i64,
    pub delay_ns: u64,
    pub socket_setup_overhead_units: u64,
    pub send_recv_overhead_units: u64,
}

impl Default for nc_ntp_sample_t {
    fn default() -> Self {
        // Zeroed except for the status, which must not read as success.
        nc_ntp_sample_t {
            status: NC_ERR_UNSUPPORTED,
            stratum: 0,
            version: 0,
            leap_indicator: 0,
            migrated: 0,
            _pad: 0,
            local_send_unix_ns: 0,
            local_recv_unix_ns: 0,
            ntp_transmit_unix_ns: 0,
            offset_ns: 0,
            delay_ns: 0,
            socket_setup_overhead_units: 0,
            send_recv_overhead_units: 0,
        }
    }
}

/// Queries an NTP server. Returns 1 on success.
///
/// # Safety
/// `server` must be a NUL-terminated UTF-8 string, or null for the default.
#[no_mangle]
pub unsafe extern "C" fn nc_ntp_query(
    ctx: *mut nc_ctx,
    server: *const c_char,
    timeout_ms: u32,
    out: *mut nc_ntp_sample_t,
) -> c_int {
    let (Some(c), Some(out)) = (unsafe { ctx.as_ref() }, unsafe { out.as_mut() }) else {
        return 0;
    };
    *out = nc_ntp_sample_t::default();

    let server = if server.is_null() {
        ntp::DEFAULT_SERVER.to_string()
    } else {
        match unsafe { std::ffi::CStr::from_ptr(server) }.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                out.status = NC_ERR_BAD_ARGUMENT;
                return 0;
            }
        }
    };

    match ntp::query(&c.0, &server, timeout_ms, ClockRoute::Auto) {
        Ok(s) => {
            *out = nc_ntp_sample_t {
                status: NC_OK,
                stratum: s.stratum as u32,
                version: s.version as u32,
                leap_indicator: s.leap_indicator as u32,
                migrated: s.migrated as u32,
                local_send_unix_ns: s.local_send_unix_ns,
                local_recv_unix_ns: s.local_recv_unix_ns,
                ntp_transmit_unix_ns: s.ntp_transmit_unix_ns,
                offset_ns: s.offset_ns,
                delay_ns: s.delay_ns,
                socket_setup_overhead_units: s.socket_setup_units,
                send_recv_overhead_units: s.send_recv_units,
                _pad: 0,
            };
            1
        }
        Err(_) => 0,
    }
}

// -- probes ----------------------------------------------------------------

/// Runs one local timing probe over a caller-owned buffer.
///
/// Returns raw counter units, or 0 when the probe is unsupported here or the
/// buffer is too small.
///
/// # Safety
/// `buffer` must point to `bytes` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nc_probe_cycles(
    kind: u32,
    buffer: *mut u8,
    bytes: usize,
    steps: usize,
) -> u64 {
    const KINDS: [CacheProbe; 9] = [
        CacheProbe::Load,
        CacheProbe::LoadFenced,
        CacheProbe::FlushReload,
        CacheProbe::PrefetchReload,
        CacheProbe::Store,
        CacheProbe::Branch,
        CacheProbe::PointerChase,
        CacheProbe::Barrier,
        CacheProbe::Counter,
    ];
    let Some(&probe_kind) = KINDS.get(kind as usize) else {
        return 0;
    };
    if buffer.is_null() || bytes == 0 {
        // Only the buffer-free probes can proceed.
        let mut empty: [u8; 0] = [];
        return probe::run(probe_kind, &mut empty, steps).unwrap_or(0);
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buffer, bytes) };
    probe::run(probe_kind, slice, steps).unwrap_or(0)
}

/// Constant-time byte comparison. Returns 1 when equal.
///
/// # Safety
/// `a` and `b` must each point to `n` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn nc_constant_time_eq(a: *const u8, b: *const u8, n: usize) -> c_int {
    if a.is_null() || b.is_null() {
        return 0;
    }
    let (a, b) = unsafe {
        (
            std::slice::from_raw_parts(a, n),
            std::slice::from_raw_parts(b, n),
        )
    };
    probe::constant_time_eq(a, b) as c_int
}

// -- crypto ----------------------------------------------------------------

/// Name of the crypto provider. Static string; never free it.
#[no_mangle]
pub extern "C" fn nc_crypto_provider_name() -> *const c_char {
    static_cstr(nanochrono_crypto::PROVIDER)
}

/// SHA-256 of `msg` into a 32-byte `out`. Returns [`NC_OK`] on success.
///
/// # Safety
/// `msg` must have `len` readable bytes; `out` must have 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nc_crypto_sha256(msg: *const u8, len: usize, out: *mut u8) -> c_int {
    if (msg.is_null() && len != 0) || out.is_null() {
        return NC_ERR_BAD_ARGUMENT;
    }
    let msg = if len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(msg, len) }
    };
    let digest = nanochrono_crypto::sha256(msg);
    unsafe { std::ptr::copy_nonoverlapping(digest.as_ptr(), out, digest.len()) };
    NC_OK
}

/// HMAC-SHA-256 into a 32-byte `out`. Returns [`NC_OK`] on success.
///
/// # Safety
/// Each pointer must have the stated number of accessible bytes.
#[no_mangle]
pub unsafe extern "C" fn nc_crypto_hmac_sha256(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
) -> c_int {
    if key.is_null() || (msg.is_null() && msg_len != 0) || out.is_null() {
        return NC_ERR_BAD_ARGUMENT;
    }
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };
    let msg = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(msg, msg_len) }
    };
    let tag = nanochrono_crypto::hmac_sha256(key, msg);
    unsafe { std::ptr::copy_nonoverlapping(tag.as_ptr(), out, tag.len()) };
    NC_OK
}

/// Fills `buf` from the system CSPRNG. Returns [`NC_OK`] on success.
///
/// # Safety
/// `buf` must have `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nc_crypto_random_bytes(buf: *mut u8, len: usize) -> c_int {
    if buf.is_null() {
        return NC_ERR_BAD_ARGUMENT;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    match nanochrono_crypto::random_bytes(slice) {
        Ok(()) => NC_OK,
        Err(_) => NC_ERR_CRYPTO_BACKEND,
    }
}

// -- version ---------------------------------------------------------------

#[no_mangle]
pub extern "C" fn nc_toolkit_version() -> *const c_char {
    static_cstr(concat!(
        "NanoChronometer Toolkit ",
        env!("CARGO_PKG_VERSION"),
        "\0"
    ))
}

/// Writes the runtime dispatcher's selection report into `buf`.
#[no_mangle]
pub unsafe extern "C" fn nc_dispatch_report(buf: *mut c_char, cap: usize) -> c_int {
    unsafe { write_cstr(&Dispatcher::global().report(), buf, cap) }
}

// -- helpers ---------------------------------------------------------------

fn backend_from_u32(value: u32) -> Backend {
    Backend::ALL
        .iter()
        .copied()
        .find(|b| *b as u32 == value)
        .unwrap_or(Backend::Legacy)
}

/// Route discriminants follow `ClockRoute::ALL` order, with 0 reserved for
/// `Auto` to match the C `NC_CLOCK_ROUTE_AUTO`.
fn route_from_u32(value: u32) -> ClockRoute {
    if value == 0 {
        return ClockRoute::Auto;
    }
    ClockRoute::ALL
        .get(value as usize - 1)
        .copied()
        .unwrap_or(ClockRoute::Auto)
}

fn route_to_u32(route: ClockRoute) -> u32 {
    ClockRoute::ALL
        .iter()
        .position(|r| *r == route)
        .map_or(0, |i| i as u32 + 1)
}

/// Returns a pointer to a NUL-terminated copy of `s`, leaked once per string.
///
/// The C API promises static lifetimes for name accessors. Names come from a
/// closed set of enum variants, so the number of leaks is bounded by the
/// number of variants, not by call count.
fn static_cstr(s: &str) -> *const c_char {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<String, &'static std::ffi::CStr>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = match cache.lock() {
        Ok(m) => m,
        // A poisoned mutex must not abort a C caller; an empty name is a
        // survivable degradation.
        Err(_) => return c"".as_ptr(),
    };
    let entry = map.entry(s.to_string()).or_insert_with(|| {
        let trimmed = s.trim_end_matches('\0');
        let owned = std::ffi::CString::new(trimmed).unwrap_or_default();
        Box::leak(owned.into_boxed_c_str())
    });
    entry.as_ptr()
}

/// Copies `s` into `buf`, truncating to fit and always NUL-terminating.
///
/// # Safety
/// `buf` must have `cap` writable bytes.
unsafe fn write_cstr(s: &str, buf: *mut c_char, cap: usize) -> c_int {
    if buf.is_null() || cap == 0 {
        return 0;
    }
    // Truncate on a char boundary so a multi-byte sequence is never cut.
    let mut end = s.len().min(cap - 1);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let bytes = &s.as_bytes()[..end];
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, bytes.len());
        *buf.add(bytes.len()) = 0;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_round_trips() {
        let ctx = nc_create();
        assert!(!ctx.is_null());
        unsafe {
            assert!(nc_tsc_hz(ctx) > 0);
            nc_start(ctx);
            nc_sleep_us(ctx, 500);
            assert!(nc_elapsed_ns(ctx) >= 400_000);
            nc_destroy(ctx);
        }
    }

    /// The C callers never null-checked, so nothing here may dereference one.
    #[test]
    fn null_context_returns_defaults() {
        unsafe {
            assert_eq!(nc_tsc_hz(std::ptr::null_mut()), 0);
            assert_eq!(nc_elapsed_ns(std::ptr::null_mut()), 0);
            assert_eq!(nc_drift_ppm(std::ptr::null_mut()), 0.0);
            assert_eq!(nc_backend(std::ptr::null_mut()), Backend::Legacy as u32);
            assert_eq!(nc_calibrate(std::ptr::null_mut(), 10), 0);
            nc_destroy(std::ptr::null_mut());
            nc_reset(std::ptr::null_mut());
        }
    }

    #[test]
    fn backend_discriminants_survive_the_round_trip() {
        for backend in Backend::ALL.iter().copied() {
            assert_eq!(backend_from_u32(backend as u32), backend);
        }
        // An out-of-range value degrades rather than indexing past the end.
        assert_eq!(backend_from_u32(9999), Backend::Legacy);
    }

    #[test]
    fn route_discriminants_survive_the_round_trip() {
        assert_eq!(route_from_u32(0), ClockRoute::Auto);
        for route in ClockRoute::ALL.iter().copied() {
            assert_eq!(route_from_u32(route_to_u32(route)), route);
        }
        assert_eq!(route_from_u32(9999), ClockRoute::Auto);
    }

    #[test]
    fn format_truncates_without_overflowing() {
        let mut buf = [0 as std::ffi::c_char; 8];
        unsafe {
            nc_format_ns(3_661_000_000_000, buf.as_mut_ptr(), buf.len());
            let s = std::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s.len(), 7, "must leave room for the terminator");
            assert!("01:01:01:000:000:000".starts_with(s));
        }
    }

    #[test]
    fn format_rejects_a_null_or_empty_buffer() {
        unsafe {
            nc_format_ns(0, std::ptr::null_mut(), 16);
            let mut buf = [0 as std::ffi::c_char; 4];
            assert_eq!(nc_format_unix_time_ns_ex(0, 1, 0, buf.as_mut_ptr(), 0), 0);
        }
    }

    #[test]
    fn feature_predicates_agree_with_the_struct() {
        let mut features = nc_cpu_features_t::default();
        unsafe { nc_get_cpu_features(&mut features) };
        assert_eq!(features.sse2, nc_cpu_has_sse2());
        assert_eq!(features.avx2, nc_cpu_has_avx2());
        assert_eq!(features.avx512f, nc_cpu_has_avx512f());
    }

    /// The wrappers hand-declare this layout. If a field moves, they read
    /// garbage silently — so the offsets are pinned here rather than trusted.
    #[test]
    fn snapshot_layout_matches_the_2x_abi() {
        use std::mem::{offset_of, size_of};

        assert_eq!(offset_of!(nc_nanoclock_snapshot_t, status), 0);
        assert_eq!(offset_of!(nc_nanoclock_snapshot_t, arch), 4);
        assert_eq!(offset_of!(nc_nanoclock_snapshot_t, route), 8);
        assert_eq!(offset_of!(nc_nanoclock_snapshot_t, best_simd_family), 12);
        assert_eq!(offset_of!(nc_nanoclock_snapshot_t, backend), 16);
        // Four bytes of padding here so the u64 run starts 8-byte aligned.
        assert_eq!(offset_of!(nc_nanoclock_snapshot_t, unix_time_ns), 24);
        assert_eq!(offset_of!(nc_nanoclock_snapshot_t, rdtscp_aux), 112);
        assert_eq!(offset_of!(nc_nanoclock_snapshot_t, arm64_cntfrq_el0), 120);
        assert_eq!(offset_of!(nc_nanoclock_snapshot_t, perf_cycles), 152);
        assert_eq!(
            offset_of!(nc_nanoclock_snapshot_t, dll_boundary_cycles),
            208
        );
        assert_eq!(
            offset_of!(nc_nanoclock_snapshot_t, wrapper_hint_cycles),
            216
        );
        assert_eq!(size_of::<nc_nanoclock_snapshot_t>(), 224);
    }

    #[test]
    fn snapshot_fills_the_flat_struct() {
        let ctx = nc_create();
        let mut snap = nc_nanoclock_snapshot_t::default();
        unsafe {
            assert_eq!(nc_nanoclock_snapshot(ctx, &mut snap), 1);
            nc_destroy(ctx);
        }
        assert_eq!(snap.status, NC_OK);
        assert!(snap.unix_time_ns > 1_600_000_000_000_000_000);
        assert!(snap.monotonic_ns > 0);
    }

    #[test]
    fn names_are_stable_pointers() {
        let a = nc_backend_name(Backend::Sse2 as u32);
        let b = nc_backend_name(Backend::Sse2 as u32);
        assert_eq!(a, b, "repeated calls must return the same static pointer");
        let name = unsafe { std::ffi::CStr::from_ptr(a) }.to_str().unwrap();
        assert_eq!(name, "sse2");
    }

    /// Regression: `nc_measure_aesenc_cycles` and its siblings returned
    /// NC_ERR_UNSUPPORTED unconditionally, because no kernel was mapped to the
    /// AES, SHA or PCLMUL family indices.
    #[test]
    fn instruction_family_entry_points_dispatch() {
        let ctx = nc_create();
        for (family, run) in [
            (
                1u32,
                nc_measure_aesenc_cycles as unsafe extern "C" fn(_, _, _) -> u64,
            ),
            (2, nc_measure_sha256msg_cycles),
            (3, nc_measure_pclmul_cycles),
        ] {
            let mut out = nc_instruction_result_t::default();
            unsafe { run(ctx, 256, &mut out) };
            if nc_instruction_family_available(family) != 0
                && Dispatcher::global()
                    .run_crypto_kernel(
                        match family {
                            1 => CryptoKernel::Aes,
                            2 => CryptoKernel::Sha256,
                            _ => CryptoKernel::CarrylessMultiply,
                        },
                        1,
                    )
                    .is_some()
            {
                assert_eq!(out.status, NC_OK, "family {family} did not dispatch");
                assert!(out.cycles > 0, "family {family} reported no cycles");
            } else {
                assert_eq!(out.status, NC_ERR_UNSUPPORTED, "family {family}");
            }
        }
        unsafe { nc_destroy(ctx) };
    }

    #[test]
    fn crypto_matches_the_rust_api() {
        let mut digest = [0u8; 32];
        let msg = b"abc";
        unsafe {
            assert_eq!(
                nc_crypto_sha256(msg.as_ptr(), msg.len(), digest.as_mut_ptr()),
                NC_OK
            );
        }
        assert_eq!(digest, nanochrono_crypto::sha256(msg));
    }

    #[test]
    fn crypto_rejects_null_arguments() {
        unsafe {
            assert_eq!(
                nc_crypto_sha256(std::ptr::null(), 4, std::ptr::null_mut()),
                NC_ERR_BAD_ARGUMENT
            );
            assert_eq!(
                nc_crypto_random_bytes(std::ptr::null_mut(), 8),
                NC_ERR_BAD_ARGUMENT
            );
        }
    }

    #[test]
    fn probe_survives_a_null_buffer() {
        unsafe {
            // Counter probe needs no buffer; load probe must refuse one.
            assert!(nc_probe_cycles(8, std::ptr::null_mut(), 0, 0) > 0);
            assert_eq!(nc_probe_cycles(0, std::ptr::null_mut(), 0, 0), 0);
        }
    }

    #[test]
    fn constant_time_eq_matches_the_rust_api() {
        let a = b"secret";
        let b = b"secret";
        let c = b"secreu";
        unsafe {
            assert_eq!(nc_constant_time_eq(a.as_ptr(), b.as_ptr(), 6), 1);
            assert_eq!(nc_constant_time_eq(a.as_ptr(), c.as_ptr(), 6), 0);
            assert_eq!(nc_constant_time_eq(std::ptr::null(), c.as_ptr(), 6), 0);
        }
    }
}

// =========================================================================
// Toolkit surface used by the language wrappers
//
// These complete the 2.x C API: the Python, Go, Java and C# bindings call
// them directly, so a symbol missing here is a wrapper that fails to load.
// =========================================================================

/// Mirrors the C `nc_sample_stats_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_sample_stats_t {
    pub count: u64,
    pub min_cycles: u64,
    pub max_cycles: u64,
    pub mean_cycles: u64,
    pub median_cycles: u64,
    pub p90_cycles: u64,
    pub p99_cycles: u64,
    pub variance_cycles: f64,
    pub stdev_cycles: f64,
}

/// Mirrors the C `nc_instruction_result_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_instruction_result_t {
    pub status: c_int,
    pub family: u32,
    pub backend: u32,
    pub _pad: u32,
    pub cycles: u64,
    pub ns: u64,
    pub blocks: u64,
    pub checksum: u64,
}

/// Mirrors the C `nc_sidechannel_result_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_sidechannel_result_t {
    pub status: c_int,
    pub _pad: u32,
    pub cached_cycles: u64,
    pub flushed_cycles: u64,
    pub prefetched_cycles: u64,
    pub threshold_cycles: u64,
    pub separation_score: f64,
}

/// Instruction families, matching the 2.x `nc_instruction_family_t`.
/// Whether a CPU can execute an instruction family.
type FamilyGate = fn(&CpuFeatures) -> bool;

const INSTRUCTION_FAMILIES: &[(&str, FamilyGate)] = &[
    ("scalar", |_| true),
    ("aes", |f| f.aesni || f.arm_aes),
    ("sha", |f| f.shani || f.arm_sha2),
    ("pclmulqdq/pmull", |f| f.pclmulqdq),
    ("crc32", |f| f.sse42),
    ("sse2", |f| f.sse2),
    ("avx2", |f| f.avx2),
    ("avx512", |f| f.avx512f),
    ("neon", |f| f.neon),
    ("sve", |f| f.sve),
    ("sve2", |f| f.sve2),
    ("sme", |f| f.sme),
    ("altivec", |f| f.altivec),
    ("vsx", |f| f.vsx),
    ("rvv", |f| f.rvv),
];

use nanochrono_core::CpuFeatures;

#[no_mangle]
pub extern "C" fn nc_instruction_family_name(family: u32) -> *const c_char {
    static_cstr(
        INSTRUCTION_FAMILIES
            .get(family as usize)
            .map_or("unknown", |(name, _)| *name),
    )
}

#[no_mangle]
pub extern "C" fn nc_instruction_family_available(family: u32) -> c_int {
    let features = nanochrono_core::cpu::features();
    INSTRUCTION_FAMILIES
        .get(family as usize)
        .is_some_and(|(_, available)| available(&features)) as c_int
}

/// What a family index dispatches to.
///
/// The 2.x API mixes two kinds of family in one enum: SIMD families that are
/// also timer backends, and crypto instruction families that are not.
enum FamilyKernel {
    Timer(Backend),
    Crypto(CryptoKernel),
}

fn kernel_for_family(family: u32) -> Option<FamilyKernel> {
    Some(match family {
        0 => FamilyKernel::Timer(Backend::Legacy),
        1 => FamilyKernel::Crypto(CryptoKernel::Aes),
        2 => FamilyKernel::Crypto(CryptoKernel::Sha256),
        3 => FamilyKernel::Crypto(CryptoKernel::CarrylessMultiply),
        // CRC32 (index 4) has no dedicated kernel; SSE4.2's timer backend
        // exercises the same `crc32` instruction, so it stands in.
        4 => FamilyKernel::Timer(Backend::Sse42),
        5 => FamilyKernel::Timer(Backend::Sse2),
        6 => FamilyKernel::Timer(Backend::Avx2),
        7 => FamilyKernel::Timer(Backend::Avx512),
        8 => FamilyKernel::Timer(Backend::Neon),
        9 => FamilyKernel::Timer(Backend::Sve),
        10 => FamilyKernel::Timer(Backend::Sve2),
        11 => FamilyKernel::Timer(Backend::Sme),
        12 => FamilyKernel::Timer(Backend::Altivec),
        13 => FamilyKernel::Timer(Backend::Vsx),
        14 => FamilyKernel::Timer(Backend::Rvv),
        _ => return None,
    })
}

/// Times an instruction family's kernel. Returns cycles, 0 if unsupported.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_instruction_family_cycles(
    ctx: *mut nc_ctx,
    family: u32,
    iterations: u32,
    out: *mut nc_instruction_result_t,
) -> u64 {
    let iterations = if iterations == 0 { 1024 } else { iterations };
    let result = |status, cycles, checksum| {
        if let Some(out) = unsafe { out.as_mut() } {
            *out = nc_instruction_result_t {
                status,
                family,
                backend: unsafe { ctx.as_ref() }.map_or(0, |c| c.0.backend() as u32),
                cycles,
                ns: unsafe { ctx.as_ref() }.map_or(0, |c| c.0.units_to_ns(cycles)),
                blocks: iterations as u64,
                checksum,
                _pad: 0,
            };
        }
        cycles
    };

    if nc_instruction_family_available(family) == 0 {
        return result(NC_ERR_UNSUPPORTED, 0, 0);
    }
    let Some(kernel) = kernel_for_family(family) else {
        return result(NC_ERR_UNSUPPORTED, 0, 0);
    };

    let dispatcher = Dispatcher::global();
    let start = nanochrono_core::arch::counter_start();
    let checksum = match kernel {
        FamilyKernel::Timer(backend) => dispatcher.run_kernel_for(backend, iterations as usize),
        FamilyKernel::Crypto(crypto) => dispatcher.run_crypto_kernel(crypto, iterations as usize),
    };
    let cycles = nanochrono_core::arch::counter_end().wrapping_sub(start);

    // A family the CPU advertises but this build cannot dispatch — the crypto
    // kernels on a 32-bit ABI, say — must say so rather than report zero work.
    match checksum {
        Some(checksum) => result(NC_OK, cycles, checksum),
        None => result(NC_ERR_UNSUPPORTED, 0, 0),
    }
}

/// Family index 1 (AES), kept as a named entry point for the wrappers.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_aesenc_cycles(
    ctx: *mut nc_ctx,
    blocks: u32,
    out: *mut nc_instruction_result_t,
) -> u64 {
    unsafe { nc_measure_instruction_family_cycles(ctx, 1, blocks, out) }
}

/// Family index 2 (SHA).
#[no_mangle]
pub unsafe extern "C" fn nc_measure_sha256msg_cycles(
    ctx: *mut nc_ctx,
    blocks: u32,
    out: *mut nc_instruction_result_t,
) -> u64 {
    unsafe { nc_measure_instruction_family_cycles(ctx, 2, blocks, out) }
}

/// Family index 3 (PCLMULQDQ / PMULL).
#[no_mangle]
pub unsafe extern "C" fn nc_measure_pclmul_cycles(
    ctx: *mut nc_ctx,
    blocks: u32,
    out: *mut nc_instruction_result_t,
) -> u64 {
    unsafe { nc_measure_instruction_family_cycles(ctx, 3, blocks, out) }
}

/// Cache residency for one caller-owned line.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_cache_probe_cycles(
    ctx: *mut nc_ctx,
    ptr: *mut u8,
    out: *mut nc_sidechannel_result_t,
) -> u64 {
    let _ = ctx;
    let Some(out) = (unsafe { out.as_mut() }) else {
        return 0;
    };
    *out = nc_sidechannel_result_t {
        status: NC_ERR_BAD_ARGUMENT,
        ..Default::default()
    };
    if ptr.is_null() {
        return 0;
    }
    // The probe touches one 64-bit word; the caller guarantees the line.
    let buffer = unsafe { std::slice::from_raw_parts_mut(ptr, 64) };
    let Some(audit) = probe::cache_audit(buffer) else {
        return 0;
    };
    *out = nc_sidechannel_result_t {
        status: NC_OK,
        cached_cycles: audit.cached_units,
        flushed_cycles: audit.flushed_units,
        prefetched_cycles: audit.prefetched_units,
        threshold_cycles: audit.threshold_units,
        separation_score: audit.separation,
        _pad: 0,
    };
    audit.flushed_units
}

/// Flush-and-reload latency for one caller-owned line.
///
/// # Safety
/// `ptr` must point to at least 64 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn nc_time_flush_reload_cycles(ctx: *mut nc_ctx, ptr: *mut u8) -> u64 {
    let _ = ctx;
    if ptr.is_null() {
        return 0;
    }
    let buffer = unsafe { std::slice::from_raw_parts_mut(ptr, 64) };
    probe::run(CacheProbe::FlushReload, buffer, 0).unwrap_or(0)
}

/// Cycles for a `memcmp` over `n` bytes; writes its result to `cmp_out`.
///
/// # Safety
/// `a` and `b` must each have `n` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn nc_time_memcmp_cycles(
    ctx: *mut nc_ctx,
    a: *const u8,
    b: *const u8,
    n: usize,
    cmp_out: *mut c_int,
) -> u64 {
    let _ = ctx;
    if a.is_null() || b.is_null() {
        return 0;
    }
    let (a, b) = unsafe {
        (
            std::slice::from_raw_parts(a, n),
            std::slice::from_raw_parts(b, n),
        )
    };
    let start = nanochrono_core::arch::counter_start();
    let ordering = a.cmp(b);
    let end = nanochrono_core::arch::counter_end();
    if let Some(slot) = unsafe { cmp_out.as_mut() } {
        *slot = match ordering {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        };
    }
    end.wrapping_sub(start)
}

/// Cycles for a constant-time comparison over `n` bytes.
///
/// # Safety
/// `a` and `b` must each have `n` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn nc_time_constant_time_eq_cycles(
    ctx: *mut nc_ctx,
    a: *const u8,
    b: *const u8,
    n: usize,
    eq_out: *mut c_int,
) -> u64 {
    let _ = ctx;
    if a.is_null() || b.is_null() {
        return 0;
    }
    let (a, b) = unsafe {
        (
            std::slice::from_raw_parts(a, n),
            std::slice::from_raw_parts(b, n),
        )
    };
    let start = nanochrono_core::arch::counter_start();
    let equal = probe::constant_time_eq(a, b);
    let end = nanochrono_core::arch::counter_end();
    if let Some(slot) = unsafe { eq_out.as_mut() } {
        *slot = equal as c_int;
    }
    end.wrapping_sub(start)
}

/// A no-op call, for measuring call overhead from a wrapper's own loop.
#[no_mangle]
pub extern "C" fn nc_empty_call() -> u64 {
    0
}

/// An identity call, so a wrapper can measure argument marshalling too.
#[no_mangle]
pub extern "C" fn nc_empty_call_u64(x: u64) -> u64 {
    x
}

/// Best-case cost of one call to `f(arg)`.
///
/// # Safety
/// `f` must be a valid C function pointer that does not unwind.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_callback_min_cycles(
    ctx: *mut nc_ctx,
    f: Option<extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    iterations: u32,
) -> u64 {
    unsafe { nc_measure_call_overhead_cycles(ctx, f, arg, iterations) }
}

/// Mean cost of one call to `f(arg)`.
///
/// # Safety
/// `f` must be a valid C function pointer that does not unwind.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_callback_avg_cycles(
    ctx: *mut nc_ctx,
    f: Option<extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    iterations: u32,
) -> u64 {
    let (Some(c), Some(f)) = (unsafe { ctx.as_ref() }, f) else {
        return 0;
    };
    c.0.measure_call_avg(|| f(arg), iterations)
}

/// Cost of crossing the shared-library boundary.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_dll_boundary_cycles(ctx: *mut nc_ctx, iterations: u32) -> u64 {
    unsafe { nc_measure_ffi_overhead_cycles(ctx, iterations) }
}

/// Native baseline for a Python extension call.
///
/// This is the *native* half only. An interpreted wrapper must add its own
/// marshalling cost, which this process cannot observe.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_python_wheel_boundary_cycles(
    ctx: *mut nc_ctx,
    iterations: u32,
) -> u64 {
    unsafe { nc_measure_ffi_overhead_cycles(ctx, iterations) }
}

/// Native call-overhead baseline for a language wrapper.
#[no_mangle]
pub unsafe extern "C" fn nc_measure_wrapper_overhead_cycles(
    ctx: *mut nc_ctx,
    kind: u32,
    iterations: u32,
) -> u64 {
    let Some(c) = (unsafe { ctx.as_ref() }) else {
        return 0;
    };
    let kind = nanochrono_core::clock::WrapperKind::ALL
        .get(kind as usize)
        .copied()
        .unwrap_or(nanochrono_core::clock::WrapperKind::CApi);
    clock::measure_wrapper_overhead(&c.0, kind, iterations)
}

/// Times `count` calls to `f(arg)` into `samples`. Returns 1 on success.
///
/// # Safety
/// `f` must not unwind, and `samples` must have room for `count` `u64`s.
#[no_mangle]
pub unsafe extern "C" fn nc_collect_samples_cycles(
    ctx: *mut nc_ctx,
    f: Option<extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    samples: *mut u64,
    count: u32,
) -> c_int {
    let (Some(c), Some(f)) = (unsafe { ctx.as_ref() }, f) else {
        return 0;
    };
    if samples.is_null() || count == 0 {
        return 0;
    }
    let out = unsafe { std::slice::from_raw_parts_mut(samples, count as usize) };
    for slot in out.iter_mut() {
        let start = nanochrono_core::arch::counter_start();
        f(arg);
        *slot = nanochrono_core::arch::counter_end().wrapping_sub(start);
    }
    let _ = c;
    1
}

/// Summarises `count` samples into `out`. Returns 1 on success.
///
/// # Safety
/// `samples` must have `count` readable `u64`s.
#[no_mangle]
pub unsafe extern "C" fn nc_analyze_samples(
    samples: *const u64,
    count: u32,
    out: *mut nc_sample_stats_t,
) -> c_int {
    let (false, Some(out)) = (samples.is_null(), unsafe { out.as_mut() }) else {
        return 0;
    };
    let samples = unsafe { std::slice::from_raw_parts(samples, count as usize) };
    let Some(stats) = nanochrono_core::SampleStats::analyze(samples) else {
        return 0;
    };
    *out = nc_sample_stats_t {
        count: stats.count,
        min_cycles: stats.min,
        max_cycles: stats.max,
        mean_cycles: stats.mean as u64,
        median_cycles: stats.median,
        p90_cycles: stats.p90,
        p99_cycles: stats.p99,
        variance_cycles: stats.variance,
        stdev_cycles: stats.stdev,
    };
    1
}

/// Welch's t statistic for two timing samples.
///
/// # Safety
/// Each pointer must have the stated number of readable `u64`s.
#[no_mangle]
pub unsafe extern "C" fn nc_welch_t_score(a: *const u64, na: u32, b: *const u64, nb: u32) -> f64 {
    if a.is_null() || b.is_null() {
        return 0.0;
    }
    let (a, b) = unsafe {
        (
            std::slice::from_raw_parts(a, na as usize),
            std::slice::from_raw_parts(b, nb as usize),
        )
    };
    nanochrono_core::stats::welch_t(a, b)
}

/// Which crypto backends are linked in.
///
/// Always 1: there is exactly one provider now (rustls/`ring`), where 2.x
/// could report OpenSSL (bit 0), libsodium (bit 1), both, or neither.
#[no_mangle]
pub extern "C" fn nc_crypto_backend_mask() -> c_int {
    1
}

/// Times a SHA-256 over `msg`, writing the digest to `out_digest`.
///
/// # Safety
/// `msg` must have `len` readable bytes; `out_digest` 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nc_crypto_sha256_cycles(
    ctx: *mut nc_ctx,
    msg: *const u8,
    len: usize,
    out_digest: *mut u8,
    out: *mut nc_instruction_result_t,
) -> u64 {
    if (msg.is_null() && len != 0) || out_digest.is_null() {
        if let Some(out) = unsafe { out.as_mut() } {
            out.status = NC_ERR_BAD_ARGUMENT;
        }
        return 0;
    }
    let message = if len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(msg, len) }
    };

    let start = nanochrono_core::arch::counter_start();
    let digest = nanochrono_crypto::sha256(message);
    let cycles = nanochrono_core::arch::counter_end().wrapping_sub(start);
    unsafe { std::ptr::copy_nonoverlapping(digest.as_ptr(), out_digest, digest.len()) };

    if let Some(out) = unsafe { out.as_mut() } {
        *out = nc_instruction_result_t {
            status: NC_OK,
            family: 2, // SHA
            backend: unsafe { ctx.as_ref() }.map_or(0, |c| c.0.backend() as u32),
            cycles,
            ns: unsafe { ctx.as_ref() }.map_or(0, |c| c.0.units_to_ns(cycles)),
            blocks: (len / 64) as u64,
            checksum: u64::from_le_bytes(digest[..8].try_into().unwrap_or_default()),
            _pad: 0,
        };
    }
    cycles
}

// =========================================================================
// Hypervisor detection
//
// Exposed so a wrapper can qualify its own measurements: a nanosecond figure
// from an emulated platform means something different from one taken on bare
// metal, and the caller has no other way to tell.
// =========================================================================

/// Timing impact, matching `nc_timing_impact_t` in the header.
pub const NC_TIMING_NATIVE: u32 = 0;
pub const NC_TIMING_HARDWARE_ASSISTED: u32 = 1;
pub const NC_TIMING_EMULATED: u32 = 2;

/// Detection confidence, matching `nc_hv_confidence_t`.
pub const NC_HV_CONFIDENCE_NONE: u32 = 0;
pub const NC_HV_CONFIDENCE_SUSPECTED: u32 = 1;
pub const NC_HV_CONFIDENCE_CONFIRMED: u32 = 2;

/// Mirrors the C `nc_hypervisor_report_t`.
///
/// Fixed-size strings rather than pointers, so a caller can keep the struct on
/// the stack and never has to free anything.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nc_hypervisor_report_t {
    pub present: c_int,
    pub confidence: u32,
    pub timing_impact: u32,
    /// Whether the optional ring 0 module contributed.
    pub kernel_module_loaded: u32,
    /// Whether a ring 0 hypercall was accepted — proof, not inference.
    pub hypercall_accepted: u32,
    pub _pad: u32,
    /// Minimum cycles for a `CPUID`, and for a bare counter pair.
    pub trap_cycles: u64,
    pub baseline_cycles: u64,
    /// `trap_cycles / baseline_cycles`. Above ~20 means the trap exits.
    pub trap_ratio: f64,
    /// TSC frequency the hypervisor declares, in kHz; 0 if none.
    pub declared_tsc_khz: u32,
    pub _pad2: u32,
    /// Hypervisor name, NUL-terminated.
    pub name: [c_char; 32],
    /// Raw 12-byte CPUID signature, NUL-terminated; empty if none.
    pub cpuid_signature: [c_char; 16],
    /// `CNTFRQ_EL0` in Hz on AArch64, zero elsewhere.
    ///
    /// The AArch64 counterpart of the CPUID vendor leaf: the only
    /// identification signal readable without a trap on that architecture.
    pub arm_counter_hz: u64,
    /// `MIDR_EL1` on AArch64, zero elsewhere or if unreadable.
    pub arm_midr_el1: u64,
    /// `CTR_EL0` on AArch64, zero elsewhere.
    pub arm_ctr_el0: u64,
}

impl Default for nc_hypervisor_report_t {
    fn default() -> Self {
        nc_hypervisor_report_t {
            present: 0,
            confidence: NC_HV_CONFIDENCE_NONE,
            timing_impact: NC_TIMING_NATIVE,
            kernel_module_loaded: 0,
            hypercall_accepted: 0,
            _pad: 0,
            trap_cycles: 0,
            baseline_cycles: 0,
            trap_ratio: 0.0,
            declared_tsc_khz: 0,
            _pad2: 0,
            arm_counter_hz: 0,
            arm_midr_el1: 0,
            arm_ctr_el0: 0,
            name: [0; 32],
            cpuid_signature: [0; 16],
        }
    }
}

/// Fills `out` with the cached hypervisor detection. Returns 1 on success.
///
/// Detection runs once per process, so repeated calls are free.
#[no_mangle]
pub unsafe extern "C" fn nc_hypervisor_detect(out: *mut nc_hypervisor_report_t) -> c_int {
    let Some(out) = (unsafe { out.as_mut() }) else {
        return 0;
    };
    let report = nanochrono_core::hypervisor::cached();
    let mut c = nc_hypervisor_report_t {
        present: report.is_virtualized() as c_int,
        confidence: match report.confidence {
            nanochrono_core::hypervisor::Confidence::None => NC_HV_CONFIDENCE_NONE,
            nanochrono_core::hypervisor::Confidence::Suspected => NC_HV_CONFIDENCE_SUSPECTED,
            nanochrono_core::hypervisor::Confidence::Confirmed => NC_HV_CONFIDENCE_CONFIRMED,
        },
        timing_impact: match report.timing_impact {
            nanochrono_core::TimingImpact::Native => NC_TIMING_NATIVE,
            nanochrono_core::TimingImpact::HardwareAssisted => NC_TIMING_HARDWARE_ASSISTED,
            nanochrono_core::TimingImpact::Emulated => NC_TIMING_EMULATED,
        },
        kernel_module_loaded: report.has_kernel_module() as u32,
        hypercall_accepted: report
            .kernel
            .as_ref()
            .is_some_and(|k| k.hypercall_accepted()) as u32,
        declared_tsc_khz: report.declared_tsc_khz.unwrap_or(0),
        arm_counter_hz: report.arm_counter_hz,
        arm_midr_el1: report.arm_midr_el1,
        arm_ctr_el0: report.arm_ctr_el0,
        ..Default::default()
    };
    if let Some(cost) = &report.exit_cost {
        c.trap_cycles = cost.trap_cycles;
        c.baseline_cycles = cost.baseline_cycles;
        c.trap_ratio = cost.ratio;
    }
    fill_c_array(&mut c.name, report.hypervisor.name());
    if let Some(sig) = &report.signature {
        fill_c_array(&mut c.cpuid_signature, sig);
    }
    *out = c;
    1
}

/// One-line platform summary, e.g. `"QEMU TCG [confirmed, emulated]"`.
///
/// Static string; never free it.
#[no_mangle]
pub extern "C" fn nc_hypervisor_summary() -> *const c_char {
    static_cstr(&nanochrono_core::hypervisor::cached().summary())
}

/// What the platform means for the numbers, as a sentence for a status line.
#[no_mangle]
pub extern "C" fn nc_timing_impact_advice() -> *const c_char {
    static_cstr(nanochrono_core::hypervisor::cached().timing_impact.advice())
}

/// Copies `text` into a fixed C array, truncating on a char boundary and
/// always leaving room for the terminator.
fn fill_c_array(dst: &mut [c_char], text: &str) {
    let capacity = dst.len().saturating_sub(1);
    let mut end = text.len().min(capacity);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    for (slot, byte) in dst.iter_mut().zip(text.as_bytes()[..end].iter()) {
        *slot = *byte as c_char;
    }
    dst[end] = 0;
}

#[cfg(test)]
mod hypervisor_tests {
    use super::*;

    #[test]
    fn detection_fills_the_struct() {
        let mut report = nc_hypervisor_report_t::default();
        assert_eq!(unsafe { nc_hypervisor_detect(&mut report) }, 1);

        let name = unsafe { std::ffi::CStr::from_ptr(report.name.as_ptr()) }
            .to_str()
            .unwrap();
        assert!(!name.is_empty());
        // The verdict and the presence flag must not disagree.
        assert_eq!(
            report.present != 0,
            report.confidence != NC_HV_CONFIDENCE_NONE
        );
        if report.present == 0 {
            assert_eq!(report.timing_impact, NC_TIMING_NATIVE);
            assert_eq!(name, "none");
        }
    }

    #[test]
    fn a_null_pointer_is_refused() {
        assert_eq!(unsafe { nc_hypervisor_detect(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn summary_and_advice_are_non_empty() {
        for ptr in [nc_hypervisor_summary(), nc_timing_impact_advice()] {
            let s = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
            assert!(!s.is_empty());
        }
    }

    /// A long name must truncate rather than run past the array.
    #[test]
    fn fixed_arrays_truncate_safely() {
        let mut buf = [0 as c_char; 8];
        fill_c_array(&mut buf, "a-very-long-hypervisor-name");
        let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_str()
            .unwrap();
        assert_eq!(s.len(), 7);
        assert_eq!(buf[7], 0);
    }

    /// Truncation must not split a multi-byte sequence.
    #[test]
    fn truncation_respects_char_boundaries() {
        let mut buf = [0 as c_char; 4];
        fill_c_array(&mut buf, "ééé");
        let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_str();
        assert!(s.is_ok(), "truncation produced invalid UTF-8");
    }
}

// =========================================================================
// Stored-state integrity
//
// Exposed so a wrapper running a long measurement can scrub the calibration
// and see whether anything was repaired. A silently corrupted constant scales
// every duration the process reports, and the caller has no other way to know.
// =========================================================================

/// Integrity outcomes, matching `nc_integrity_t` in the header.
pub const NC_INTEGRITY_CLEAN: u32 = 0;
pub const NC_INTEGRITY_CORRECTED_ECC: u32 = 1;
pub const NC_INTEGRITY_CORRECTED_TMR: u32 = 2;
pub const NC_INTEGRITY_UNRECOVERABLE: u32 = 3;

/// Mirrors the C `nc_integrity_stats_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nc_integrity_stats_t {
    pub checks: u64,
    pub ecc_corrections: u64,
    pub tmr_corrections: u64,
    pub unrecoverable: u64,
}

/// Reads the process-wide integrity counters. Returns 1 on success.
#[no_mangle]
pub unsafe extern "C" fn nc_integrity_stats(out: *mut nc_integrity_stats_t) -> c_int {
    let Some(out) = (unsafe { out.as_mut() }) else {
        return 0;
    };
    let s = nanochrono_core::redundancy::stats();
    *out = nc_integrity_stats_t {
        checks: s.checks,
        ecc_corrections: s.ecc_corrections,
        tmr_corrections: s.tmr_corrections,
        unrecoverable: s.unrecoverable,
    };
    1
}

/// Verifies and repairs the chronometer's calibration constant.
///
/// Returns one of the `NC_INTEGRITY_*` values. `NC_INTEGRITY_UNRECOVERABLE`
/// means the constant is gone and `nc_calibrate` must be run before any
/// further reading means anything.
///
/// ECC runs first and handles any single-bit flip; the triple-redundancy vote
/// is reached only when the code detects damage it cannot repair, so this is
/// cheap enough to call on a timer.
#[no_mangle]
pub unsafe extern "C" fn nc_verify_calibration(ctx: *mut nc_ctx) -> u32 {
    let Some(c) = (unsafe { ctx.as_mut() }) else {
        return NC_INTEGRITY_UNRECOVERABLE;
    };
    integrity_to_u32(c.0.verify_calibration())
}

/// What the last integrity checkpoint found, without running a new one.
#[no_mangle]
pub unsafe extern "C" fn nc_last_integrity(ctx: *mut nc_ctx) -> u32 {
    match unsafe { ctx.as_ref() } {
        Some(c) => integrity_to_u32(c.0.last_integrity()),
        None => NC_INTEGRITY_UNRECOVERABLE,
    }
}

/// Flips one bit of the stored calibration, for fault-injection drills.
///
/// Exists so a caller can exercise the repair paths without a particle
/// source. `bit` 0..63 hits the working copy, 64..71 the check byte, and
/// 72..199 the two replicas.
#[no_mangle]
pub unsafe extern "C" fn nc_inject_calibration_flip(ctx: *mut nc_ctx, bit: u32) {
    if let Some(c) = unsafe { ctx.as_mut() } {
        c.0.inject_calibration_flip(bit);
    }
}

fn integrity_to_u32(integrity: nanochrono_core::Integrity) -> u32 {
    use nanochrono_core::Integrity;
    match integrity {
        Integrity::Clean => NC_INTEGRITY_CLEAN,
        Integrity::CorrectedByEcc { .. } => NC_INTEGRITY_CORRECTED_ECC,
        Integrity::CorrectedByTmr { .. } => NC_INTEGRITY_CORRECTED_TMR,
        Integrity::Unrecoverable => NC_INTEGRITY_UNRECOVERABLE,
    }
}

#[cfg(test)]
mod integrity_tests {
    use super::*;

    /// The whole feature, through the C ABI: corrupt the calibration, watch a
    /// conversion go wrong, verify, watch it come back.
    #[test]
    fn a_flip_is_repaired_through_the_abi() {
        let ctx = nc_create();
        unsafe {
            let good = nc_cycles_to_ns(ctx, 1_000_000);
            assert!(good > 0);

            nc_inject_calibration_flip(ctx, 40);
            assert_ne!(nc_cycles_to_ns(ctx, 1_000_000), good);

            let outcome = nc_verify_calibration(ctx);
            assert_eq!(outcome, NC_INTEGRITY_CORRECTED_ECC);
            assert_eq!(nc_cycles_to_ns(ctx, 1_000_000), good);
            assert_eq!(nc_last_integrity(ctx), NC_INTEGRITY_CORRECTED_ECC);

            nc_destroy(ctx);
        }
    }

    #[test]
    fn a_double_flip_escalates_through_the_abi() {
        let ctx = nc_create();
        unsafe {
            let good = nc_cycles_to_ns(ctx, 1_000_000);
            nc_inject_calibration_flip(ctx, 5);
            nc_inject_calibration_flip(ctx, 37);
            assert_eq!(nc_verify_calibration(ctx), NC_INTEGRITY_CORRECTED_TMR);
            assert_eq!(nc_cycles_to_ns(ctx, 1_000_000), good);
            nc_destroy(ctx);
        }
    }

    #[test]
    fn stats_are_readable_and_null_is_refused() {
        let mut stats = nc_integrity_stats_t::default();
        assert_eq!(unsafe { nc_integrity_stats(&mut stats) }, 1);
        assert_eq!(unsafe { nc_integrity_stats(std::ptr::null_mut()) }, 0);
    }

    /// A null context must not be reported as healthy.
    #[test]
    fn a_null_context_reports_unrecoverable() {
        unsafe {
            assert_eq!(
                nc_verify_calibration(std::ptr::null_mut()),
                NC_INTEGRITY_UNRECOVERABLE
            );
            assert_eq!(
                nc_last_integrity(std::ptr::null_mut()),
                NC_INTEGRITY_UNRECOVERABLE
            );
            nc_inject_calibration_flip(std::ptr::null_mut(), 0);
        }
    }
}
