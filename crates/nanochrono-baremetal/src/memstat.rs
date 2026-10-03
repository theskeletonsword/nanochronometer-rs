// SPDX-License-Identifier: Apache-2.0
//! Where the kernel's memory goes, for `free`, `top` and `/proc/meminfo`.
//!
//! There is no allocator, so there is no heap to report: every byte the
//! kernel uses is in its image — code, data, and `.bss`, where the big
//! static pools are. This names the pools, with their sizes, so the report
//! can say *what* the image's megabytes are rather than only how many.

/// The pools, as `(name, bytes)`. A fixed array with the unused tail empty,
/// since which pools exist depends on the architecture.
pub fn pools() -> impl Iterator<Item = (&'static str, u64)> {
    let mut out: [(&'static str, u64); 16] = [("", 0); 16];
    let mut n = 0;
    let mut add = |name: &'static str, bytes: usize| {
        if n < out.len() {
            out[n] = (name, bytes as u64);
            n += 1;
        }
    };
    add("back buffer", crate::framebuffer::SHADOW_BYTES);
    add("kernel log", crate::serial::klog::CAPACITY);
    add("terminal", crate::cli::CELLS_BYTES);
    #[cfg(target_arch = "x86_64")]
    {
        add("app arena", crate::ncplu::ARENA_SPAN);
        add("app image", crate::ncplu::IMAGE_BUF_LEN);
        add("app unpack", crate::ncplu::UNPACK_BUF_LEN);
        add("app stack", crate::ncplu::PLUGIN_STACK_LEN);
        add("verify stack", crate::ncplu::VERIFY_STACK_LEN);
        add("ring 3", 2 * 0x20_0000);
    }
    for (name, bytes) in crate::desktop::pools() {
        add(name, bytes);
    }
    out.into_iter().take(n)
}
