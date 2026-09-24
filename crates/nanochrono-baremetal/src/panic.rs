// SPDX-License-Identifier: Apache-2.0
//! What happens when the kernel cannot continue.
//!
//! The handler lives in the library rather than the binary so the static
//! archive is a complete link unit: a `staticlib` has no other crate to get a
//! `#[panic_handler]` from, and a consumer linking it would otherwise have to
//! write one.

use crate::framebuffer::Framebuffer;

/// The framebuffer, kept for the panic handler.
///
/// A `static mut` because the handler takes no arguments and cannot be given
/// one. Written once before anything can panic, on a single core with
/// interrupts masked, and read only from the handler — so there is no
/// concurrent access for the missing synchronisation to protect.
static mut FRAMEBUFFER: Option<Framebuffer> = None;

/// Records the framebuffer for the panic screen to draw on.
///
/// Call once, during boot, before anything that could panic.
pub fn set_framebuffer(fb: Option<Framebuffer>) {
    // SAFETY: single core, interrupts masked, called once before any panic
    // can occur; nothing else reads or writes this.
    unsafe { FRAMEBUFFER = fb };
}

/// There is nothing to unwind into and nobody to report to, so a panic shows
/// the reason and waits.
///
/// It does not restart. A kernel that reboots on panic loses the one thing
/// worth having, and a machine that reboots into the same fault does it
/// forever — so this stops and offers the choice instead.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    // The serial port may not be initialised yet — a panic before `kmain`
    // reaches `Serial::init` prints nothing, which is the best available
    // outcome and better than faulting inside the handler.
    crate::println!("\npanic: {info}");

    // The message needs to reach the screen without an allocator, so it is
    // rendered into a fixed buffer. A reason longer than this is truncated,
    // which is better than losing all of it.
    let mut reason = ReasonBuffer::new();
    let _ = core::fmt::write(&mut reason, format_args!("{info}"));

    // The stop screen needs a framebuffer and a keyboard, both of which are
    // PC firmware. An AArch64 board has already had the reason over serial,
    // and stopping there is the same outcome without the drawing.
    #[cfg(x86_any)]
    {
        // SAFETY: written once before anything can panic, on a single core
        // with interrupts masked.
        let fb = unsafe { FRAMEBUFFER };
        // SAFETY: a panic is only reachable from kernel code, at CPL 0.
        unsafe { crate::panic_screen::show(fb.as_ref(), reason.as_str()) }
    }
    #[cfg(not(x86_any))]
    {
        crate::println!("stopped; not restarting");
        crate::arch::halt()
    }
}

/// A fixed-size sink for the panic message.
struct ReasonBuffer {
    bytes: [u8; 512],
    len: usize,
}

impl ReasonBuffer {
    const fn new() -> ReasonBuffer {
        ReasonBuffer {
            bytes: [0; 512],
            len: 0,
        }
    }

    #[cfg_attr(not(x86_any), allow(dead_code))]
    fn as_str(&self) -> &str {
        // Truncation can land mid-character, so the longest valid prefix is
        // taken rather than risking a panic inside the panic handler.
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("panic (message not valid UTF-8)")
    }
}

impl core::fmt::Write for ReasonBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.bytes.len() {
                break;
            }
            self.bytes[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}
