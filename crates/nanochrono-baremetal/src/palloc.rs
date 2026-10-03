// SPDX-License-Identifier: Apache-2.0
//! Physical pages: [`nanochrono_core::frames`] over the RAM the loader
//! reported, minus what is already in use.
//!
//! Everything the kernel itself needs still lives in its image — that has
//! not changed, and nothing here is reached on the paths that existed before
//! it. What comes from here is what the image cannot size in advance: a back
//! buffer for a mode larger than the static one (a 4K screen), and the
//! memory a driver module asks for (`crate::ncdri`).
//!
//! # What is reserved before anything is handed out
//!
//! Everything below the end of the kernel image — the first megabyte (the
//! BIOS data area, the EBDA, the legacy video window) and the image itself,
//! `.bss` included — the loader's information structure and every table and
//! string it points to (the command line and module names are borrowed from
//! there for the whole run), and every module the loader placed.
//!
//! # Where it hands out from
//!
//! Below [`CEILING`], top first. On x86-64 that is the first gigabyte: the
//! boot page tables map everything above it uncached, for MMIO, and a back
//! buffer or driver code there would run at device-memory speed. On i386
//! paging is off and the firmware's MTRRs make RAM write-back wherever it is,
//! so the ceiling is the 4 GiB a pointer reaches.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use nanochrono_core::frames::{Frames, PAGE};

/// Free runs the table holds. A PC's memory map has a few dozen entries; the
/// reservations split a handful more.
const RANGES: usize = 128;

/// The highest address (exclusive) handed out: see the module docs.
#[cfg(target_arch = "x86_64")]
pub const CEILING: u64 = 1 << 30;
#[cfg(not(target_arch = "x86_64"))]
pub const CEILING: u64 = 0xFFFF_F000;

static mut FRAMES: Frames<RANGES> = Frames::new();
static READY: AtomicBool = AtomicBool::new(false);
/// Bytes handed out and not given back. A `usize`: 32-bit PowerPC and
/// RISC-V have no 64-bit atomics, and what is handed out lies below the
/// ceiling anyway.
static IN_USE: AtomicUsize = AtomicUsize::new(0);

extern "C" {
    /// The end of the kernel image, `.bss` included (the linker script).
    static __kernel_end: u8;
}

/// What the allocator holds, for `/proc/meminfo` and the boot log.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    /// Bytes free below the ceiling.
    pub free: u64,
    /// Bytes handed out and not given back.
    pub in_use: u64,
    /// Bytes lost to a full range table (zero on any ordinary map).
    pub dropped: u64,
    /// Free runs.
    pub runs: usize,
}

/// Whether [`init_multiboot`] has run.
pub fn ready() -> bool {
    READY.load(Ordering::Relaxed)
}

/// Builds the free ranges from a multiboot information structure.
///
/// # Safety
/// Once, at boot, before anything is allocated; `info` is the pointer the
/// loader passed and `multiboot2` says which structure it is.
#[cfg(x86_any)]
pub unsafe fn init_multiboot(info: u64, multiboot2: bool) -> Stats {
    // SAFETY: once, single core, before any other reference to the table.
    let frames = unsafe { &mut *core::ptr::addr_of_mut!(FRAMES) };
    // The whole map first (the table refuses RAM once anything is taken),
    // and only what lies below the ceiling: nothing above is handed out.
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        crate::multiboot::usable_ram(info, multiboot2, |base, len| {
            let end = base.saturating_add(len).min(CEILING);
            if end > base {
                frames.add(base, end - base);
            }
        });
    }
    let image_end = core::ptr::addr_of!(__kernel_end) as u64;
    frames.reserve(0, image_end);
    // SAFETY: as above.
    unsafe {
        crate::multiboot::loader_ranges(info, multiboot2, |base, len| frames.reserve(base, len));
        crate::multiboot::modules(info, multiboot2, |m| frames.reserve(m.start, m.end - m.start));
    }
    READY.store(true, Ordering::Relaxed);
    stats()
}

/// `len` bytes of physical memory, rounded up to pages, aligned to `align`
/// (a power of two; a page at least), below [`CEILING`]: the address, which
/// the identity map makes a pointer too. Not zeroed. `None` before
/// [`init_multiboot`] or when no run is large enough.
pub fn alloc(len: usize, align: usize) -> Option<usize> {
    if !ready() {
        return None;
    }
    // SAFETY: single core, interrupts masked; nothing else holds the table.
    let frames = unsafe { &mut *core::ptr::addr_of_mut!(FRAMES) };
    let addr = frames.alloc(len as u64, align as u64, CEILING)?;
    let rounded = (len as u64).div_ceil(PAGE) * PAGE;
    IN_USE.fetch_add(rounded as usize, Ordering::Relaxed);
    usize::try_from(addr).ok()
}

/// [`alloc`], zeroed.
pub fn alloc_zeroed(len: usize, align: usize) -> Option<usize> {
    let addr = alloc(len, align)?;
    // SAFETY: the run was just handed out, is identity-mapped below the
    // ceiling, and nothing else refers to it.
    unsafe { core::ptr::write_bytes(addr as *mut u8, 0, len) };
    Some(addr)
}

/// Gives back what [`alloc`] returned, with the length it was asked for.
/// `false` (and nothing changes) for a run that is not one: a double free,
/// or the wrong length.
pub fn free(addr: usize, len: usize) -> bool {
    if !ready() {
        return false;
    }
    // SAFETY: as in `alloc`.
    let frames = unsafe { &mut *core::ptr::addr_of_mut!(FRAMES) };
    let ok = frames.free(addr as u64, len as u64);
    if ok {
        let rounded = ((len as u64).div_ceil(PAGE) * PAGE) as usize;
        IN_USE.fetch_sub(rounded.min(IN_USE.load(Ordering::Relaxed)), Ordering::Relaxed);
    }
    ok
}

/// What the allocator holds now.
pub fn stats() -> Stats {
    // SAFETY: a read of the table; single core, nothing writes meanwhile.
    let frames = unsafe { &*core::ptr::addr_of!(FRAMES) };
    Stats {
        free: frames.free_bytes(),
        in_use: IN_USE.load(Ordering::Relaxed) as u64,
        dropped: frames.dropped(),
        runs: frames.ranges().len(),
    }
}
