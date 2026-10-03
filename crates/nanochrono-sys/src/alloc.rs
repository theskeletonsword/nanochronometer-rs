// SPDX-License-Identifier: Apache-2.0
//! A global allocator over the POSIX-class `mmap`/`munmap`.
//!
//! Page-granular on purpose: every allocation is its own anonymous mapping,
//! rounded up to 4 KiB, returned zeroed by the kernel and given back whole on
//! `dealloc`. That is the smallest allocator that is correct with nothing
//! underneath it, and the right one for the few, large buffers a ring-3 tool
//! or benchmark keeps. A program with many small objects wants a real
//! `malloc` on top of these same two calls — `nclibc` takes FreeBSD libc's
//! (jemalloc) for that, `docs/NCTOOLCHAIN.md` §3.1 — rather than this.
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOC: nanochrono_sys::alloc::NcAlloc = nanochrono_sys::alloc::NcAlloc;
//! ```

use core::alloc::{GlobalAlloc, Layout};

use crate::nr::{map, prot};
use crate::posix;

/// The allocation unit: one 4 KiB page.
pub const PAGE: usize = 4096;

/// The page allocator. Alignments up to [`PAGE`] are served; larger ones
/// fail (`null`), which `alloc::alloc::handle_alloc_error` reports.
#[derive(Clone, Copy, Debug, Default)]
pub struct NcAlloc;

fn pages(layout: Layout) -> Option<usize> {
    let size = layout.size().max(1);
    size.checked_add(PAGE - 1).map(|s| s & !(PAGE - 1))
}

// SAFETY: every pointer returned is a fresh mapping of at least
// `layout.size()` bytes, page-aligned (so aligned for any `layout.align()`
// up to PAGE), owned by no one else until `dealloc` unmaps it.
unsafe impl GlobalAlloc for NcAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > PAGE {
            return core::ptr::null_mut();
        }
        let Some(len) = pages(layout) else { return core::ptr::null_mut() };
        // SAFETY: an anonymous private mapping; nothing else refers to it.
        unsafe { posix::mmap(core::ptr::null_mut(), len, prot::READ | prot::WRITE, map::ANON | map::PRIVATE, -1, 0) }
            .unwrap_or(core::ptr::null_mut())
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Anonymous mappings arrive zeroed.
        // SAFETY: forwarded.
        unsafe { self.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(len) = pages(layout) {
            // SAFETY: `ptr` came from `alloc` with this layout, and the caller
            // gives it up.
            let _ = unsafe { posix::munmap(ptr, len) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_round_to_pages() {
        assert_eq!(pages(Layout::from_size_align(0, 1).unwrap()), Some(PAGE));
        assert_eq!(pages(Layout::from_size_align(1, 8).unwrap()), Some(PAGE));
        assert_eq!(pages(Layout::from_size_align(PAGE, 8).unwrap()), Some(PAGE));
        assert_eq!(pages(Layout::from_size_align(PAGE + 1, 8).unwrap()), Some(2 * PAGE));
    }
}
