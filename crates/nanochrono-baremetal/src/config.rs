// SPDX-License-Identifier: Apache-2.0
//! The system's settings: what Settings shows and the rest of the kernel
//! reads.
//!
//! Defaults are the safe side of every switch: **NCVBS on** (Settings'
//! "Disable NCVBS" off), **ring-0 community modules and drivers refused**.
//! The command line can set them for a boot (`ncvbs=off`,
//! `ring0community=on`, `wallpaper=<n>`); Settings changes them for the
//! session. They are kept across boots once the state store exists
//! (docs/ECOSYSTEM.md); until then a change lasts until power-off, and the
//! ones that act at boot (NCVBS) say they apply from the next one.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static NCVBS_DISABLED: AtomicBool = AtomicBool::new(false);
static RING0_COMMUNITY: AtomicBool = AtomicBool::new(false);
static WALLPAPER: AtomicUsize = AtomicUsize::new(0);

/// Reads the command line's overrides, once, at boot.
pub fn from_command_line() {
    if let Some(v) = crate::boot::option("ncvbs") {
        NCVBS_DISABLED.store(matches!(v, "off" | "0" | "no" | "false"), Ordering::Relaxed);
    }
    if crate::boot::flag("ring0community") {
        RING0_COMMUNITY.store(true, Ordering::Relaxed);
    }
    if let Some(n) = crate::boot::option("wallpaper").and_then(|v| v.parse::<usize>().ok()) {
        WALLPAPER.store(n, Ordering::Relaxed);
    }
}

/// NanoChronometer Virtualization-Based Security: on unless disabled.
pub fn ncvbs_enabled() -> bool {
    !NCVBS_DISABLED.load(Ordering::Relaxed)
}

/// Settings' "Disable NCVBS".
pub fn set_ncvbs_disabled(disabled: bool) {
    NCVBS_DISABLED.store(disabled, Ordering::Relaxed);
}

/// "Enable Ring0 Community Modules and Drivers": whether an unsigned or
/// self-signed plugin or driver may run in ring 0. Off by default.
pub fn ring0_community() -> bool {
    RING0_COMMUNITY.load(Ordering::Relaxed)
}

pub fn set_ring0_community(on: bool) {
    RING0_COMMUNITY.store(on, Ordering::Relaxed);
}

/// The embedded wallpaper in use.
pub fn wallpaper() -> usize {
    WALLPAPER.load(Ordering::Relaxed)
}

pub fn set_wallpaper(n: usize) {
    WALLPAPER.store(n, Ordering::Relaxed);
}
