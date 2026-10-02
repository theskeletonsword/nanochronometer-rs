// SPDX-License-Identifier: Apache-2.0
//! What the boot loader handed over, kept for the whole session: the kernel
//! command line, the interface it asks for, and the modules it loaded.
//!
//! # The interfaces
//!
//! One kernel, three ways to use it, chosen by `mode=` on the command line —
//! which the ISO's GRUB menu sets, one entry each:
//!
//! * `mode=classic` (the default): the instrument — the stopwatch, clock and
//!   timer full screen, as every release has drawn it.
//! * `mode=desktop`: the NanoChronometer Desktop Experience — windows, a
//!   taskbar, apps (`crate::desktop`).
//! * `mode=cli`: a text terminal and a Unix-like shell, the hosted CLI's
//!   `nanochrono` among its commands (`crate::cli`).
//!
//! Other options: `kbd=us|es` (the keyboard layout), `wallpaper=<n>`.
//! Off x86 the command line is the device tree's `/chosen/bootargs`.
//!
//! # Modules
//!
//! Files the loader placed in memory: GRUB's `module2 <file> <path>`, or the
//! device tree's initrd. Each is filed under the path its string names —
//! `/usr/lib/libfoo.nsdyn`, `/apps/SNAKE.NCPLU`, `/boot/drivers/X.NCDRI` —
//! and a cpio archive (`initrd`, or a name ending in `.cpio`) is unpacked
//! into the same tree. `crate::vfs` serves them.

use crate::multiboot::Module;
use crate::text::Text;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

/// The interface a session runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Classic,
    Desktop,
    Cli,
}

impl Mode {
    pub fn from_name(name: &str) -> Option<Mode> {
        match name {
            "classic" | "instrument" | "gui" => Some(Mode::Classic),
            "desktop" | "de" => Some(Mode::Desktop),
            "cli" | "shell" | "text" | "terminal" => Some(Mode::Cli),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Mode::Classic => "classic",
            Mode::Desktop => "desktop",
            Mode::Cli => "cli",
        }
    }
}

static MODE: AtomicU8 = AtomicU8::new(0);
static mut COMMAND_LINE: Text<512> = Text::new();

/// The most modules kept: far past what a boot menu loads.
pub const MAX_MODULES: usize = 64;
static mut MODULES: [Option<Module>; MAX_MODULES] = [None; MAX_MODULES];
static MODULE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Keeps the command line and acts on the options read once at boot:
/// `mode=` and `kbd=`.
pub fn record_command_line(line: &str) {
    // SAFETY: once, at boot, on one core, before anything reads it.
    unsafe {
        let t = &mut *core::ptr::addr_of_mut!(COMMAND_LINE);
        t.clear();
        t.str(line);
    }
    if let Some(mode) = option("mode").and_then(Mode::from_name) {
        set_mode(mode);
    }
    if let Some(layout) = option("kbd").and_then(crate::kbd::Layout::from_name) {
        crate::kbd::set_default_layout(layout);
    }
}

/// The command line as the loader gave it.
pub fn command_line() -> &'static str {
    // SAFETY: written once at boot, before anything reads it.
    unsafe { (*core::ptr::addr_of!(COMMAND_LINE)).as_str() }
}

/// The value of `key=value` on the command line, if present.
pub fn option(key: &str) -> Option<&'static str> {
    command_line().split_ascii_whitespace().find_map(|w| {
        let (k, v) = w.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// Whether a bare word (or `key=1`/`key=on`) is on the command line.
pub fn flag(key: &str) -> bool {
    command_line()
        .split_ascii_whitespace()
        .any(|w| w == key || matches!(w.split_once('='), Some((k, "1" | "on" | "yes" | "true")) if k == key))
}

pub fn mode() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        1 => Mode::Desktop,
        2 => Mode::Cli,
        _ => Mode::Classic,
    }
}

pub fn set_mode(mode: Mode) {
    MODE.store(
        match mode {
            Mode::Classic => 0,
            Mode::Desktop => 1,
            Mode::Cli => 2,
        },
        Ordering::Relaxed,
    );
}

/// Files a module the loader placed in memory.
pub fn record_module(module: Module) {
    let n = MODULE_COUNT.load(Ordering::Relaxed);
    if n < MAX_MODULES {
        // SAFETY: at boot, on one core; slots are written once each, below
        // the count published after.
        unsafe { (*core::ptr::addr_of_mut!(MODULES))[n] = Some(module) };
        MODULE_COUNT.store(n + 1, Ordering::Relaxed);
    }
}

/// Every module recorded, in the loader's order.
pub fn modules() -> impl Iterator<Item = Module> {
    let n = MODULE_COUNT.load(Ordering::Relaxed);
    // SAFETY: slots below the published count are written and never change.
    let all = unsafe { &*core::ptr::addr_of!(MODULES) };
    all[..n].iter().flatten().copied()
}
