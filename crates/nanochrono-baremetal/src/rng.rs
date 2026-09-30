// SPDX-License-Identifier: Apache-2.0
//! NC_RNG in the kernel: one entropy pool for the machine, and its C ABI.
//!
//! The pool itself is `nanochrono_core::rng` — the same code the hosted
//! library runs. What this module adds is what only a kernel has:
//!
//! * the memory region, a 256 KiB `static` (the manual's default when the
//!   cache size is not known), since there is no allocator;
//! * the PMU, read around every jitter measurement as uncredited input once
//!   the interface has probed it ([`attach_pmu`]);
//! * the events only a kernel sees: every key byte from the 8042, every
//!   xHCI event (keyboard, mouse and USB storage transfers — the "disk
//!   activity"), every I2C-HID report, every frame ([`stir`]);
//! * the `nc_rng_*` functions a plugin calls through [`crate::ncplu`].
//!
//! # One core, no interrupts
//!
//! The kernel runs one thread with interrupts masked, so nothing preempts a
//! read. A `BUSY` flag still guards the pool, because a fault handler or a
//! plugin could call back in: an event that finds the pool busy is folded
//! into a small side word and mixed in at the next stir, a read returns
//! [`RngError::Misuse`] rather than touching the pool twice.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use nanochrono_core::rng::{jitter::DEFAULT_REGION_LEN, Config, EntropyPool, Mode, RngError, Status};

use crate::pmu::CorePmu;

/// Whether the running plugin may use the RNG. On x86-64 this is the plugin
/// capability check; elsewhere there are no plugins (the RNG C ABI is only for
/// hosted libraries), so it is always allowed.
#[cfg(target_arch = "x86_64")]
fn rng_cap_ok() -> bool {
    crate::ncplu::cap_granted(crate::ncplu::CAP_RNG)
}
#[cfg(not(target_arch = "x86_64"))]
fn rng_cap_ok() -> bool {
    true
}

/// The jitter source's memory walk.
#[repr(C, align(4096))]
struct Region([u8; DEFAULT_REGION_LEN]);

static mut REGION: Region = Region([0; DEFAULT_REGION_LEN]);
static mut POOL: Option<EntropyPool<'static>> = None;
static BUSY: AtomicBool = AtomicBool::new(false);
/// Events that arrived while the pool was busy, folded together.
static MISSED: AtomicU32 = AtomicU32::new(0);

/// The interface's PMU, copied in once it has been enabled.
static mut PMU: Option<CorePmu> = None;

/// Runs `f` on the pool, creating it on first use. `None` if the pool is
/// already in use further up the stack, or could not be created.
fn with_pool<T>(f: impl FnOnce(&mut EntropyPool<'static>) -> T) -> Option<T> {
    if BUSY.swap(true, Ordering::Acquire) {
        return None;
    }
    // SAFETY: `BUSY` makes this the only live reference to `POOL`, and the
    // kernel has one core.
    let pool = unsafe { &mut *(&raw mut POOL) };
    if pool.is_none() {
        // SAFETY: `REGION` is borrowed here and nowhere else, once: after
        // this `POOL` is `Some` and the branch is never taken again.
        let region = unsafe { &mut (*(&raw mut REGION)).0 };
        *pool = EntropyPool::new(region, Config::DEFAULT).ok();
    }
    let result = pool.as_mut().map(f);
    BUSY.store(false, Ordering::Release);
    result
}

/// Self-tests, source detection, jitter start-up and the first seed. Called
/// from the boot self-test so the ~2000 timed measurements happen there and
/// not under the first key press.
pub fn start() -> Result<(), RngError> {
    with_pool(|pool| pool.start()).unwrap_or(Err(RngError::Misuse))
}

/// Fills `out`, or returns an error and leaves `out` zeroed.
pub fn fill(out: &mut [u8], mode: Mode) -> Result<usize, RngError> {
    match with_pool(|pool| pool.fill(out, mode)) {
        Some(result) => result,
        None => {
            nanochrono_core::rng::keccak::wipe_bytes(out);
            Err(RngError::Misuse)
        }
    }
}

/// A snapshot of the pool; all zeros before it exists.
pub fn status() -> Status {
    with_pool(|pool| pool.status()).unwrap_or_default()
}

/// The output stage's engine, by name, for the self-test and the interface.
pub fn engine_name() -> &'static str {
    with_pool(|pool| pool.engine().name()).unwrap_or("not started")
}

/// Mixes an event into the pool: a tag, a value, and — taken inside — the
/// counter at the moment of the call. Never credited; cheap enough for
/// every input byte and every USB event.
pub fn stir(tag: u64, value: u64) {
    let stirred = with_pool(|pool| {
        let missed = MISSED.swap(0, Ordering::Relaxed);
        if missed != 0 {
            pool.stir(nanochrono_core::rng::EVENT_INTERRUPT, missed as u64);
        }
        pool.stir(tag, value);
    });
    if stirred.is_none() {
        // Busy: keep something of it for the next stir. Added rather than
        // XORed, so two identical events do not cancel.
        let low = crate::arch::counter_ordered() as u32 ^ value as u32 ^ tag as u32;
        MISSED.fetch_add(low, Ordering::Relaxed);
    }
}

/// Hands the pool the PMU the interface enabled, so every later jitter
/// measurement also carries a cycle-counter difference.
pub fn attach_pmu(pmu: &CorePmu) {
    if !pmu.is_available() {
        return;
    }
    // SAFETY: written once, from the interface's start-up, before any read
    // through `pmu_cycles`; one core.
    unsafe { *(&raw mut PMU) = Some(*pmu) };
    with_pool(|pool| pool.set_sampler(Some(pmu_cycles)));
}

/// The sampler: core cycles from the PMU, 0 where there is no reading.
fn pmu_cycles() -> u64 {
    // SAFETY: `PMU` is only written by `attach_pmu`, before the sampler is
    // installed; the kernel runs at ring 0 / EL1, which the read requires.
    unsafe {
        match *(&raw const PMU) {
            Some(ref pmu) => pmu.read_cycles().map_or(0, |r| r.value),
            None => 0,
        }
    }
}

// ===========================================================================
// The C ABI: what a plugin reaches through NcApi / nc_resolve_symbol, with
// the same names and meaning as libnanochrono's hosted functions.
// ===========================================================================

/// Most bytes one `nc_rng_fill` call may ask for.
pub const NC_RNG_MAX_FILL: usize = 1 << 20;

/// `int64_t nc_rng_fill(void *buf, size_t len, uint32_t flags)`: fills
/// `buf` and returns `len`, or a negative `NC_RNG_E*` code with `buf`
/// zeroed. Bit 0 of `flags` selects `NC_RNG_TRUE`.
#[allow(clippy::not_unsafe_ptr_arg_deref)] // C-ABI entry; the pointer is
// checked with caller_owns before any access.
pub extern "C" fn nc_rng_fill(buf: *mut u8, len: usize, flags: u32) -> i64 {
    if !rng_cap_ok() {
        return RngError::Misuse.code() as i64;
    }
    if len == 0 {
        return 0;
    }
    if buf.is_null() || len > NC_RNG_MAX_FILL || !caller_owns(buf as usize, len) {
        return RngError::Misuse.code() as i64;
    }
    // SAFETY: `[buf, buf + len)` lies in the calling plugin's own memory
    // (its arena or its stack), checked just above: the kernel never writes
    // where a plugin merely points it.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    match fill(out, Mode::from_flags(flags)) {
        Ok(n) => n as i64,
        Err(error) => error.code() as i64,
    }
}

/// `int32_t nc_rng_status(nc_rng_status_t *out)`: the caller sets
/// `out->size` to the size it was built with; up to that many bytes are
/// written, and `size` is set to the number written. 0 or a negative code.
#[allow(clippy::not_unsafe_ptr_arg_deref)] // C-ABI entry; the pointer is
// checked with caller_owns before any access.
pub extern "C" fn nc_rng_status(out: *mut Status) -> i32 {
    if !rng_cap_ok() {
        return RngError::Misuse.code();
    }
    if out.is_null() || !caller_owns(out as usize, 8) {
        return RngError::Misuse.code();
    }
    // SAFETY: the first 8 bytes are the caller's (checked above), and the
    // struct starts with its size.
    let capacity = unsafe { core::ptr::read_unaligned(out.cast::<u32>()) } as usize;
    if capacity < 8 {
        return RngError::Misuse.code();
    }
    let status = status();
    let n = capacity.min(core::mem::size_of::<Status>());
    if !caller_owns(out as usize, n) {
        return RngError::Misuse.code();
    }
    // SAFETY: `n` bytes fit in the caller's struct by its own declaration,
    // and `status` is a plain `repr(C)` value.
    unsafe {
        core::ptr::copy_nonoverlapping((&raw const status).cast::<u8>(), out.cast::<u8>(), n);
        core::ptr::write_unaligned(out.cast::<u32>(), n as u32);
    }
    0
}

/// Whether a buffer passed through the C ABI belongs to the caller. Only
/// plugins call these functions, and only on x86-64; anything outside the
/// plugin's own memory is refused rather than read or written.
fn caller_owns(ptr: usize, len: usize) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        crate::ncplu::plugin_owns(ptr, len)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (ptr, len);
        false
    }
}

/// After a plugin was stopped by a fault inside one of these calls: the pool
/// may still hold its lock, and half an update. The call will never resume,
/// so the lock is released and the pool restarts from its self-tests —
/// nothing half-done is ever used.
pub fn recover_after_abort() {
    if BUSY.load(Ordering::Acquire) {
        // SAFETY: single core; the reference the aborted call held is gone
        // with the plugin's stack.
        unsafe {
            if let Some(pool) = (*(&raw mut POOL)).as_mut() {
                pool.wipe();
            }
        }
        BUSY.store(false, Ordering::Release);
    }
}

/// `void nc_rng_stir(uint64_t tag, uint64_t value)`: mixes a caller's event
/// in (uncredited). Tags from `NC_RNG_EVENT_USER` (0x100) up are the
/// caller's.
pub extern "C" fn nc_rng_stir(tag: u64, value: u64) {
    if !rng_cap_ok() {
        return;
    }
    stir(tag, value);
}

/// `int32_t nc_rng_selftest(void)`: re-runs the known-answer tests; 0, or
/// `NC_RNG_ESELFTEST` with the pool out of service.
pub extern "C" fn nc_rng_selftest() -> i32 {
    if !rng_cap_ok() {
        return RngError::Misuse.code();
    }
    match with_pool(|pool| pool.selftest()) {
        Some(Ok(())) => 0,
        Some(Err(error)) => error.code(),
        None => RngError::Misuse.code(),
    }
}
