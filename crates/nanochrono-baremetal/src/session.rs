// SPDX-License-Identifier: Apache-2.0
//! Starts the interface the command line asked for (`crate::boot`): the
//! classic instrument, the Desktop Experience, or the CLI.

use crate::framebuffer::Framebuffer;
use crate::multiboot::Memory;

/// Runs the session for the rest of the boot.
///
/// # Safety
/// Kernel privilege, once, after the boot-time setup; `fb`, when given, is
/// the screen the loader described, with its back buffer attached.
pub unsafe fn start(fb: Option<&Framebuffer>, memory: Memory) -> ! {
    let mode = crate::boot::mode();
    crate::println!("session: {} ({})", mode.name(), if fb.is_some() { "framebuffer" } else { "no framebuffer" });
    // SAFETY (each arm): forwarded from this function's own contract.
    match (mode, fb) {
        (crate::boot::Mode::Cli, fb) => unsafe { crate::cli::run(fb, memory) },
        (crate::boot::Mode::Desktop, Some(fb)) => unsafe { crate::desktop::run(fb, memory) },
        (crate::boot::Mode::Desktop, None) => {
            crate::println!("session: the desktop needs a framebuffer; starting the CLI instead");
            unsafe { crate::cli::run(None, memory) }
        }
        (crate::boot::Mode::Classic, Some(fb)) => unsafe { crate::gui::run(fb, memory) },
        (crate::boot::Mode::Classic, None) => unsafe { crate::console::run() },
    }
}
