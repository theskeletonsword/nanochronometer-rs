// SPDX-License-Identifier: Apache-2.0
//! Loadable modules — `.ncapp` apps, straight or out of a `.ncpkg`
//! package — their loader, and the symbol table the kernel exports to them.
//! (The module format's magic still reads `NCPLU`; `.ncplu` itself now
//! names an app plugin, which its host app loads, not this launcher.)
//!
//! # Why a plugin boundary at all
//!
//! Two reasons, and the licence one is not secondary. NanoChronometer is
//! Apache-2.0, and a GPL program — DOOM, a GPL audio decoder — cannot be
//! built into it. A `.ncplu` is loaded at run time from a filesystem, never
//! linked into the kernel image, so a GPL plugin is the user's own separate
//! work that this kernel merely runs. The same wall that keeps an untrusted
//! plugin out of ring-0 internals keeps an incompatible licence out of the
//! Apache tree. In-tree plugins (Snake, Minesweeper) are Apache-2.0
//! originals; DOOM and the like are external and only *supported*.
//!
//! # No allocator
//!
//! The kernel has none, on purpose, and this does not add one. A plugin is
//! loaded into a single fixed [`Arena`] in `.bss`; one plugin runs at a time,
//! from the interface, and hands the screen back when it returns. Everything
//! the loader needs — the image, the relocation scratch — is static.
//!
//! # The three steps, and where each is checked
//!
//! 1. **Read** the `.ncplu` bytes from the FAT partition (see
//!    [`crate::usb_storage::read_file`]).
//! 2. **Verify** the hybrid signature (ML-DSA-87 + P-521) against the pinned
//!    root public keys ([`verify`]). Both must verify for [`Tier::Official`];
//!    anything else — no signature, one bad half, a kernel built without the
//!    `plugin-verify` feature or without root keys — is [`Tier::Community`].
//! 3. **Load**: copy sections into the arena, zero `.bss`, apply
//!    relocations (resolving kernel imports through [`nc_resolve_symbol`]),
//!    and jump to the entry export.
//!
//! Every field read out of the file is bounds-checked before it is used, the
//! way the multiboot and FAT parsers in this crate already are: a plugin is
//! untrusted input, and a malformed one must fail the load rather than read
//! or write outside the arena.
//!
//! # The kernel call ABI
//!
//! Kernel services reach the plugin as a table of function pointers
//! ([`NcApi`]) passed to its entry point, not as linker imports. A
//! freestanding loader has no PLT to route a `call` to an absent symbol
//! through, so calls go through the table instead — which needs only that
//! the plugin dereference a pointer, never a relocation against code. The
//! [`nc_resolve_symbol`] path and `IMPORT64` relocations still exist, for
//! importing a kernel **data** symbol's address; see [`Reloc`].

#![allow(clippy::missing_safety_doc)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// ===========================================================================
// On-disk format
//
// The format and its validating parser live in `nanochrono_core::ncplu`,
// where the hosted test build fuzzes them. This file only applies an image
// that has passed every check there — see `load`.
// ===========================================================================

pub use nanochrono_core::ncplu::{
    fnv1a, Arch, FormatError, Image, Kind, Reloc, ABI_VERSION, CAP_ALL, CAP_INPUT, CAP_LOG, CAP_PMU, CAP_RNG,
    CAP_SCREEN, CAP_TIMER, FLAG_HAS_CAPS, FLAG_WANTS_PRIVILEGED, FORMAT_VERSION, HEADER_SIZE, MAGIC,
    ROOT_MLDSA_LEN, ROOT_P521_LEN, SIGNATURE_LEN,
};

/// The capabilities the running plugin was granted. Each service checks it, so
/// a plugin — kernel-tier or ring 3 — only reaches the groups it declared.
static GRANTED_CAPS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Whether the running plugin may use a capability group (`CAP_*`).
pub(crate) fn cap_granted(cap: u32) -> bool {
    GRANTED_CAPS.load(Ordering::Relaxed) & cap == cap
}

// ===========================================================================
// Trust tier
// ===========================================================================

/// How far a plugin is trusted, decided by its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Signed by the creator's key (✅). Runs in the kernel and may import
    /// privileged symbols.
    Creator,
    /// Signed by a root this machine's owner trusts (🌳) — the "root of the
    /// tree". Runs in the kernel and may import privileged symbols, exactly
    /// like [`Tier::Creator`]; the two differ only in who vouched for it.
    TreeRoot,
    /// No badge: unsigned, or signed by a key this kernel does not trust.
    /// Belongs in ring 3, unprivileged and isolated (the next module). Until
    /// that exists it runs in the kernel *contained* — its own guarded stack,
    /// its faults caught — and only the unprivileged symbols resolve for it.
    Community,
}

impl Tier {
    pub const fn label(self) -> &'static str {
        match self {
            Tier::Creator => "creator",
            Tier::TreeRoot => "trusted root",
            Tier::Community => "community",
        }
    }

    /// Runs with the kernel's own privilege (ring 0). A community plugin does
    /// not — it is bound for ring 3.
    pub const fn runs_in_kernel(self) -> bool {
        !matches!(self, Tier::Community)
    }

    /// Whether a symbol of `min_tier` may be resolved for this plugin.
    fn may_use(self, min_tier: u8) -> bool {
        match self {
            Tier::Creator | Tier::TreeRoot => true,
            Tier::Community => min_tier == 0,
        }
    }
}

// ===========================================================================
// The kernel's exported symbol table
// ===========================================================================

/// The unprivileged tier: any plugin may resolve it.
const TIER_ANY: u8 = 0;
/// Kernel-tier only (✅ or 🌳): port I/O, MSRs, the PMU. None are exported
/// yet; the constant marks where they will go.
#[allow(dead_code)]
const TIER_PRIVILEGED: u8 = 1;

/// The public kernel symbols, version [`ABI_VERSION`], as name to
/// (address, required tier). Data symbols (`nc_abi_version`) as well as
/// functions: a data symbol's *address* is what an `IMPORT64` relocation
/// resolves against.
///
/// A match rather than a `static` table because a `static` is const-evaluated
/// and a function address is not a constant there. The names are also listed
/// in [`EXPORT_NAMES`], for the UI and for debugging.
pub fn nc_resolve_symbol(name: &[u8]) -> Option<(usize, u8)> {
    let entry: (usize, u8) = match name {
        b"nc_fill_rect" => (nc_fill_rect as *const () as usize, TIER_ANY),
        b"nc_clear" => (nc_clear as *const () as usize, TIER_ANY),
        b"nc_present" => (nc_present as *const () as usize, TIER_ANY),
        b"nc_poll_event" => (nc_poll_event as *const () as usize, TIER_ANY),
        b"nc_ticks" => (nc_ticks as *const () as usize, TIER_ANY),
        b"nc_ticks_per_sec" => (nc_ticks_per_sec as *const () as usize, TIER_ANY),
        b"nc_log" => (nc_log as *const () as usize, TIER_ANY),
        b"nc_timer_now" => (nc_timer_now as *const () as usize, TIER_ANY),
        b"nc_timer_now_end" => (nc_timer_now_end as *const () as usize, TIER_ANY),
        b"nc_timer_hz" => (nc_timer_hz as *const () as usize, TIER_ANY),
        b"nc_timer_source" => (nc_timer_source as *const () as usize, TIER_ANY),
        b"nc_timer_ticks_to_ns" => (nc_timer_ticks_to_ns as *const () as usize, TIER_ANY),
        b"nc_pmu_caps" => (nc_pmu_caps as *const () as usize, TIER_ANY),
        b"nc_pmu_open" => (nc_pmu_open as *const () as usize, TIER_ANY),
        b"nc_pmu_read" => (nc_pmu_read as *const () as usize, TIER_ANY),
        b"nc_pmu_close" => (nc_pmu_close as *const () as usize, TIER_ANY),
        b"nc_rng_fill" => (crate::rng::nc_rng_fill as *const () as usize, TIER_ANY),
        b"nc_rng_status" => (crate::rng::nc_rng_status as *const () as usize, TIER_ANY),
        b"nc_rng_stir" => (crate::rng::nc_rng_stir as *const () as usize, TIER_ANY),
        b"nc_rng_selftest" => (crate::rng::nc_rng_selftest as *const () as usize, TIER_ANY),
        b"nc_abi_version" => (&raw const NC_ABI_VERSION as usize, TIER_ANY),
        // What -fstack-protector code calls on: the canary, and the handler
        // for a canary that changed.
        b"__stack_chk_guard" => (&raw const NC_STACK_CHK_GUARD as usize, TIER_ANY),
        b"__stack_chk_fail" => (nc_stack_chk_fail as *const () as usize, TIER_ANY),
        _ => return None,
    };
    Some(entry)
}

/// Every symbol [`nc_resolve_symbol`] knows, for the plugin manager to show
/// and for a sanity check that a name here also matches there.
pub static EXPORT_NAMES: &[&str] = &[
    "nc_fill_rect",
    "nc_clear",
    "nc_present",
    "nc_poll_event",
    "nc_ticks",
    "nc_ticks_per_sec",
    "nc_log",
    "nc_timer_now",
    "nc_timer_now_end",
    "nc_timer_hz",
    "nc_timer_source",
    "nc_timer_ticks_to_ns",
    "nc_pmu_caps",
    "nc_pmu_open",
    "nc_pmu_read",
    "nc_pmu_close",
    "nc_rng_fill",
    "nc_rng_status",
    "nc_rng_stir",
    "nc_rng_selftest",
    "nc_abi_version",
    "__stack_chk_guard",
    "__stack_chk_fail",
];

/// A data symbol, exported so the `IMPORT64` relocation path has something to
/// resolve. Its address, not its value, is what a plugin imports.
#[no_mangle]
static NC_ABI_VERSION: u32 = ABI_VERSION;

/// The stack canary a plugin's `-fstack-protector` code compares against: its
/// `__stack_chk_guard` import. A fresh random value for every run, set before
/// any of the plugin's code runs; the low byte is zero, so a string copy that
/// runs over a buffer cannot write the value back.
static NC_STACK_CHK_GUARD: AtomicU64 = AtomicU64::new(0);

/// Set when the running plugin's canary check failed, for `run` to report.
static STACK_SMASHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The code a plugin stopped by its canary returns with.
const ABORT_STACK_SMASHED: i64 = -0x200;

/// A canary for the next run, from NC_RNG; from the counter if the pool cannot
/// serve (then guessable, but never the same twice).
fn new_stack_guard() -> u64 {
    let mut bytes = [0u8; 8];
    let value = match crate::rng::fill(&mut bytes, nanochrono_core::rng::Mode::Fast) {
        Ok(_) => u64::from_le_bytes(bytes),
        Err(_) => crate::arch::counter_ordered().rotate_left(29) ^ 0x9E37_79B9_7F4A_7C15,
    };
    value & !0xFF
}

/// The current run's canary, which the ring-3 runtime copies to user memory.
pub(crate) fn stack_guard() -> u64 {
    NC_STACK_CHK_GUARD.load(Ordering::Relaxed)
}

/// `__stack_chk_fail` for a kernel-tier plugin. Its canary changed, so its
/// stack is corrupt and its return address is not to be trusted: it is
/// abandoned the way a contained fault abandons it, on the kernel's own saved
/// stack, and `run` reports why. (A ring-3 plugin reaches the same end through
/// `nccall`; see `crate::ring3`.)
extern "C" fn nc_stack_chk_fail() -> ! {
    if RUNNING_ARENA.load(Ordering::Relaxed) == 0 {
        panic!("stack smashing detected outside a plugin");
    }
    STACK_SMASHED.store(true, Ordering::Relaxed);
    // SAFETY: a kernel-tier plugin is running, so nc_plugin_call saved the
    // kernel's stack and registers, which nc_plugin_abort returns to; single
    // core, and nothing else touches the abort code.
    unsafe {
        *core::ptr::addr_of_mut!(NC_PLUGIN_ABORT_CODE) = ABORT_STACK_SMASHED;
        nc_plugin_abort();
    }
    unreachable!("nc_plugin_abort returns to nc_plugin_call's caller")
}

/// C-ABI form of [`nc_resolve_symbol`], for a plugin that wants to resolve a
/// name itself at run time rather than through a load-time relocation.
///
/// # Safety
/// `name` must point at `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn nc_resolve_symbol_c(name: *const u8, len: usize) -> usize {
    if name.is_null() || len == 0 || len > 128 {
        return 0;
    }
    // SAFETY: forwarded from this function's own contract.
    let bytes = unsafe { core::slice::from_raw_parts(name, len) };
    nc_resolve_symbol(bytes).map_or(0, |(addr, _)| addr)
}

// ===========================================================================
// The call ABI handed to a plugin
// ===========================================================================

/// The table of kernel services a plugin is given at entry. Function pointers
/// rather than linker imports; see the module docs.
#[repr(C)]
pub struct NcApi {
    pub abi_version: u32,
    pub screen_w: u32,
    pub screen_h: u32,
    pub _reserved: u32,
    pub ticks_per_sec: u64,
    pub fill_rect: extern "C" fn(x: i32, y: i32, w: i32, h: i32, rgb: u32),
    pub clear: extern "C" fn(rgb: u32),
    pub present: extern "C" fn(),
    /// Next input event, or 0. Encoding: `0` none; otherwise bit 31 set,
    /// bit 8 = pressed, bits 7..0 = set-1 scancode.
    pub poll_event: extern "C" fn() -> u32,
    pub ticks: extern "C" fn() -> u64,
    pub log: extern "C" fn(msg: *const u8, len: usize),
    // NC_TIMER / NC_PMU (module 3). Appended, so a plugin built against the
    // shorter table still reads its own prefix correctly.
    pub timer_now: extern "C" fn() -> u64,
    pub timer_now_end: extern "C" fn() -> u64,
    pub timer_hz: extern "C" fn() -> u64,
    pub timer_source: extern "C" fn() -> u32,
    pub timer_ticks_to_ns: extern "C" fn(ticks: u64) -> u64,
    pub pmu_caps: extern "C" fn() -> u32,
    pub pmu_open: extern "C" fn(event: u32) -> i32,
    pub pmu_read: extern "C" fn(handle: i32) -> u64,
    pub pmu_close: extern "C" fn(handle: i32),
    // NC_RNG: the kernel's entropy pool (see `crate::rng`). Same names and
    // meaning as libnanochrono's hosted functions.
    /// Fills `len` bytes; returns `len` or a negative `NC_RNG_E*` code (the
    /// buffer is then zeroed). Bit 0 of `flags` asks for `NC_RNG_TRUE`.
    pub rng_fill: extern "C" fn(buf: *mut u8, len: usize, flags: u32) -> i64,
    /// Fills an `nc_rng_status_t` whose `size` the caller set; 0 or `< 0`.
    pub rng_status: extern "C" fn(out: *mut nanochrono_core::rng::Status) -> i32,
    /// Mixes an event in, uncredited. Tags from 0x100 are the plugin's.
    pub rng_stir: extern "C" fn(tag: u64, value: u64),
}

// sdk/include/ncplu.h mirrors this table for C plugins and pins the same size
// (and every section's offset) with static asserts. A change here that the
// header does not follow fails one build or the other.
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<NcApi>() == 168);

// The plugin entry point is `extern "C" fn ncplu_main(api: *const NcApi) ->
// i32`, called through `nc_plugin_call` on the plugin's own stack.

// ===========================================================================
// The nc_* service functions
//
// Each reads its state from PLUGIN_CTX, set by `run` before the plugin is
// entered. Function pointers cannot capture, so the state is a static; one
// plugin runs at a time on the one core, so nothing races it.
// ===========================================================================

struct PluginCtx {
    fb: *const crate::framebuffer::Framebuffer,
    input: *mut crate::input::Input,
    /// The performance counters the machine probe already enabled. Read-only
    /// for a plugin, through `nc_pmu_*`.
    pmu: *const crate::pmu::CorePmu,
}

static PLUGIN_CTX: AtomicUsize = AtomicUsize::new(0);
static PLUGIN_TICKS_PER_SEC: AtomicU64 = AtomicU64::new(1);

fn ctx() -> Option<&'static PluginCtx> {
    let p = PLUGIN_CTX.load(Ordering::Relaxed);
    // SAFETY: set by `run` to a `&mut PluginCtx` on its own stack, which
    // outlives the plugin call; cleared to 0 afterwards.
    (p != 0).then(|| unsafe { &*(p as *const PluginCtx) })
}

pub(crate) extern "C" fn nc_fill_rect(x: i32, y: i32, w: i32, h: i32, rgb: u32) {
    if !cap_granted(CAP_SCREEN) { return; }
    let Some(ctx) = ctx() else { return };
    // SAFETY: `fb` is valid for the plugin's run; drawing takes `&self`.
    let fb = unsafe { &*ctx.fb };
    // Clip a rectangle that starts off the left/top edge rather than
    // wrapping its unsigned width around.
    let (x0, w) = clamp_span(x, w, fb.width);
    let (y0, h) = clamp_span(y, h, fb.height);
    fb.fill(x0, y0, w, h, rgb);
}

pub(crate) extern "C" fn nc_clear(rgb: u32) {
    if !cap_granted(CAP_SCREEN) { return; }
    if let Some(ctx) = ctx() {
        // SAFETY: as `nc_fill_rect`.
        unsafe { &*ctx.fb }.clear(rgb);
    }
}

pub(crate) extern "C" fn nc_present() {
    if !cap_granted(CAP_SCREEN) { return; }
    if let Some(ctx) = ctx() {
        // SAFETY: as `nc_fill_rect`.
        unsafe { &*ctx.fb }.present_damage();
    }
}

pub(crate) extern "C" fn nc_poll_event() -> u32 {
    if !cap_granted(CAP_INPUT) { return 0; }
    let Some(ctx) = ctx() else { return 0 };
    // SAFETY: `input` is valid for the plugin's run; `poll` needs `&mut`, and
    // nothing else touches it while the plugin has the screen.
    match unsafe { (*ctx.input).poll() } {
        Some(crate::input::Event::Key(k)) => {
            (1 << 31) | ((k.pressed as u32) << 8) | k.scancode as u32
        }
        // A pointer motion is not delivered to plugins yet.
        _ => 0,
    }
}

pub(crate) extern "C" fn nc_ticks() -> u64 {
    if !cap_granted(CAP_TIMER) { return 0; }
    crate::arch::counter_ordered()
}

extern "C" fn nc_ticks_per_sec() -> u64 {
    if !cap_granted(CAP_TIMER) { return 0; }
    PLUGIN_TICKS_PER_SEC.load(Ordering::Relaxed)
}

pub(crate) extern "C" fn nc_log(msg: *const u8, len: usize) {
    if !cap_granted(CAP_LOG) { return; }
    if msg.is_null() || len == 0 || len > 4096 || !plugin_owns(msg as usize, len) {
        return;
    }
    // SAFETY: the plugin passes a pointer and length into its own image.
    let bytes = unsafe { core::slice::from_raw_parts(msg, len) };
    #[cfg(x86_any)]
    crate::serial::write_uart_only(bytes);
    #[cfg(not(x86_any))]
    let _ = bytes;
}

/// Clips a span `[start, start+len)` to `[0, limit)`, returning the clipped
/// start and width as unsigned.
fn clamp_span(start: i32, len: i32, limit: u32) -> (u32, u32) {
    if len <= 0 {
        return (0, 0);
    }
    let end = (start as i64 + len as i64).clamp(0, limit as i64);
    let start = start.clamp(0, limit as i32) as i64;
    if end <= start {
        (0, 0)
    } else {
        (start as u32, (end - start) as u32)
    }
}

// ===========================================================================
// NC_TIMER and NC_PMU: the standard timing and performance APIs (module 3)
//
// So a plugin never hand-writes RDTSC/RDPMC/CPUID/LFENCE. The kernel already
// does the serialisation and the ISA split in nanochrono-core; these expose
// it. Reading counters is unprivileged (tier 0): RDPMC runs at ring 0 here,
// and the reads have no side effects.
// ===========================================================================

// Timer source codes returned by `nc_timer_source`.
pub const NC_TIMER_TSC: u32 = 1; // x86 RDTSC/RDTSCP
pub const NC_TIMER_CNTVCT: u32 = 2; // AArch64 virtual count
pub const NC_TIMER_CNTPCT: u32 = 3; // AArch64 physical count
pub const NC_TIMER_OTHER: u32 = 0;

// PMU event ids and capability bits.
pub const NC_PMU_CYCLES: u32 = 0;
pub const NC_PMU_INSTRUCTIONS: u32 = 1;
pub const NC_PMU_CACHE_MISSES: u32 = 2;
const NC_PMU_CAP_CYCLES: u32 = 1 << NC_PMU_CYCLES;
const NC_PMU_CAP_INSTRUCTIONS: u32 = 1 << NC_PMU_INSTRUCTIONS;

/// A serialised counter read with a *start* barrier: nothing after it in
/// program order is timed before the counter is sampled (`LFENCE; RDTSC` on
/// x86, `ISB; read` on AArch64). Use for the first timestamp of a measurement.
pub(crate) extern "C" fn nc_timer_now() -> u64 {
    if !cap_granted(CAP_TIMER) { return 0; }
    nanochrono_core::arch::counter_start()
}

/// A serialised counter read with an *end* barrier: everything before it in
/// program order has retired before the counter is sampled (`RDTSCP; LFENCE`
/// on x86). Use for the second timestamp of a measurement.
pub(crate) extern "C" fn nc_timer_now_end() -> u64 {
    if !cap_granted(CAP_TIMER) { return 0; }
    nanochrono_core::arch::counter_end()
}

/// The counter's frequency in Hz, so ticks can be turned into time.
pub(crate) extern "C" fn nc_timer_hz() -> u64 {
    if !cap_granted(CAP_TIMER) { return 0; }
    PLUGIN_TICKS_PER_SEC.load(Ordering::Relaxed)
}

/// Which hardware counter backs the timer, as an `NC_TIMER_*` code.
pub(crate) extern "C" fn nc_timer_source() -> u32 {
    if !cap_granted(CAP_TIMER) { return 0; }
    #[cfg(target_arch = "x86_64")]
    {
        NC_TIMER_TSC
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        NC_TIMER_OTHER
    }
}

/// Converts counter ticks to nanoseconds using the calibrated frequency.
pub(crate) extern "C" fn nc_timer_ticks_to_ns(ticks: u64) -> u64 {
    if !cap_granted(CAP_TIMER) { return 0; }
    let hz = PLUGIN_TICKS_PER_SEC.load(Ordering::Relaxed).max(1);
    ((ticks as u128 * 1_000_000_000) / hz as u128) as u64
}

/// Which PMU events this machine can supply, as `NC_PMU_CAP_*` bits.
pub(crate) extern "C" fn nc_pmu_caps() -> u32 {
    if !cap_granted(CAP_PMU) { return 0; }
    let Some(ctx) = ctx() else { return 0 };
    // SAFETY: `pmu` is valid for the plugin's run.
    if !unsafe { (*ctx.pmu).is_available() } {
        return 0;
    }
    // Cycles and retired instructions are read directly; cache misses need a
    // programmable slot and are not offered in this phase.
    NC_PMU_CAP_CYCLES | NC_PMU_CAP_INSTRUCTIONS
}

/// Opens a counter for `event` (`NC_PMU_*`). Returns a small non-negative
/// handle, or -1 if the event is unavailable. Allocation-free: the handle is
/// the event id, and the counter is read live — one plugin runs at a time and
/// the counters are the machine's, already enabled.
pub(crate) extern "C" fn nc_pmu_open(event: u32) -> i32 {
    if !cap_granted(CAP_PMU) { return -1; }
    let caps = nc_pmu_caps();
    match event {
        NC_PMU_CYCLES if caps & NC_PMU_CAP_CYCLES != 0 => NC_PMU_CYCLES as i32,
        NC_PMU_INSTRUCTIONS if caps & NC_PMU_CAP_INSTRUCTIONS != 0 => NC_PMU_INSTRUCTIONS as i32,
        _ => -1,
    }
}

/// Reads the current count of a handle from `nc_pmu_open`, or 0 if invalid.
pub(crate) extern "C" fn nc_pmu_read(handle: i32) -> u64 {
    if !cap_granted(CAP_PMU) { return 0; }
    let Some(ctx) = ctx() else { return 0 };
    // SAFETY: ring 0; `pmu` is valid for the plugin's run and the reads have
    // no side effects.
    let reading = unsafe {
        match handle as u32 {
            NC_PMU_CYCLES => (*ctx.pmu).read_cycles(),
            NC_PMU_INSTRUCTIONS => (*ctx.pmu).read_instructions(),
            _ => None,
        }
    };
    reading.map_or(0, |r| r.value)
}

/// Closes a handle. A no-op: the counters are shared machine state, not owned
/// by the plugin, so there is nothing to release.
pub(crate) extern "C" fn nc_pmu_close(_handle: i32) {
    // No cap check: closing is a no-op and there is nothing to gate.
}

// ===========================================================================
// The arena and the loader
// ===========================================================================

/// How much memory a loaded plugin may occupy: text, rodata, data and bss
/// together. 1 MiB is far more than Snake or Minesweeper need and still a
/// rounding error against the back buffer. The format's own cap, so a parsed
/// image always fits.
pub const ARENA_LEN: usize = nanochrono_core::ncplu::MAX_ARENA;

/// The one place a plugin's image lives. Executable because the boot page
/// tables map all of RAM without the NX bit, and **2 MiB aligned and sized**:
/// a community plugin runs at ring 3, and the arena is mapped user by setting
/// the user bit on exactly its one 2 MiB page (see `crate::ring3`), so nothing
/// kernel may share it. Only the first [`ARENA_LEN`] bytes are ever used.
pub(crate) const ARENA_SPAN: usize = 0x20_0000;
#[repr(C, align(0x200000))]
struct Arena {
    bytes: [u8; ARENA_SPAN],
}

static mut ARENA: Arena = Arena { bytes: [0; ARENA_SPAN] };

/// Why a load failed. Reported rather than swallowed: a plugin that will not
/// load and a plugin that is not there need different answers on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// The file broke one of the format's rules; nothing was copied.
    Format(FormatError),
    /// The digest in the header does not match the file: it was damaged on
    /// the way (or edited without re-packing). Refused at every tier.
    Corrupt,
    /// It asks for privileged services and is not officially signed.
    Privileged,
    /// A relocation names a kernel symbol that does not exist, or that its
    /// tier may not use.
    UnresolvedImport,
    /// Built for another architecture: a package's entry for a machine this
    /// kernel is not, installed by mistake. Never loaded, never executed.
    WrongArch,
    /// A driver, a shared library or an app plugin: installed, not run.
    /// Drivers load at boot from `/boot/drivers`, libraries from
    /// `/usr/lib`, plugins through their host app; none is a program to
    /// launch from here. Also a `lib` package, which holds no app.
    NotRunnable,
    /// The file breaks the `.ncpkg` container format. Nothing from it was
    /// loaded.
    BadPackage(nanochrono_core::ncpkg::FormatError),
    /// The package's manifest is malformed, or does not match its files.
    BadManifest(nanochrono_core::ncpkg::meta::Error),
}

impl LoadError {
    pub const fn message(self) -> &'static str {
        match self {
            LoadError::Format(e) => e.message(),
            LoadError::Corrupt => "digest mismatch: the file is damaged or was edited",
            LoadError::Privileged => "asks for privileged services but is not officially signed",
            LoadError::UnresolvedImport => "a needed kernel symbol is missing or privileged",
            LoadError::WrongArch => "built for another architecture",
            LoadError::NotRunnable => "a driver, a library or a plugin: installed, not run",
            LoadError::BadPackage(e) => e.message(),
            LoadError::BadManifest(e) => e.message(),
        }
    }
}

/// The architecture this kernel was built for: what [`Arch`] a module must
/// name to load here.
pub const fn this_arch() -> Arch {
    #[cfg(target_arch = "x86_64")]
    {
        Arch::X86_64
    }
    #[cfg(target_arch = "x86")]
    {
        Arch::I386
    }
    #[cfg(target_arch = "aarch64")]
    {
        Arch::Aarch64
    }
    #[cfg(target_arch = "arm")]
    {
        Arch::Arm32
    }
    #[cfg(target_arch = "riscv64")]
    {
        Arch::Riscv64
    }
    #[cfg(target_arch = "riscv32")]
    {
        Arch::Riscv32
    }
    #[cfg(all(target_arch = "powerpc64", target_endian = "big"))]
    {
        Arch::Ppc64
    }
    #[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
    {
        Arch::Ppc64Le
    }
    #[cfg(target_arch = "powerpc")]
    {
        Arch::Ppc
    }
}

/// What the signature check found: which trusted root, if any, both halves
/// verified against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    /// This kernel trusts no root key — built without `plugin-verify`, or
    /// with neither root embedded — so no plugin can earn a badge.
    NoRoot,
    /// The reserved signature block was never filled in.
    Unsigned,
    /// Both halves verified against the creator's root (✅).
    Creator,
    /// Both halves verified against the local tree root (🌳).
    TreeRoot,
    /// Signed, but by no root this kernel trusts, or changed after signing.
    /// The bits are for the creator root; a plugin that fails both roots is
    /// simply untrusted.
    Untrusted { mldsa: bool, p521: bool },
}

impl Signature {
    pub const fn tier(self) -> Tier {
        match self {
            Signature::Creator => Tier::Creator,
            Signature::TreeRoot => Tier::TreeRoot,
            _ => Tier::Community,
        }
    }

    pub const fn describe(self) -> &'static str {
        match self {
            Signature::NoRoot => "this kernel trusts no root key",
            Signature::Unsigned => "not signed",
            Signature::Creator => "signed by the creator (ML-DSA-87 + P-521)",
            Signature::TreeRoot => "signed by a trusted root (ML-DSA-87 + P-521)",
            Signature::Untrusted { mldsa: false, p521: false } => "signed by no key this kernel trusts",
            Signature::Untrusted { mldsa: false, .. } => "the ML-DSA-87 signature does not match",
            Signature::Untrusted { .. } => "the P-521 signature does not match",
        }
    }
}

/// A plugin loaded and ready to enter.
pub struct Loaded {
    entry: usize,
    /// The entry's offset within the arena (its base is [`arena_ptr`]).
    entry_off: usize,
    /// The capability groups the plugin was granted (`CAP_*`).
    pub capabilities: u32,
    pub tier: Tier,
    pub signature: Signature,
    pub arena_size: u32,
    pub file_size: u32,
    /// The first bytes of the image's SHA-512, for the log and the card.
    pub digest: [u8; 8],
    /// Counter ticks the integrity and signature checks took.
    pub check_ticks: u64,
}

/// The integrity check and the hybrid signature: SHA-512 over the signed
/// region (with the header's digest field taken as zero, as the packer
/// computed it) must equal the header's digest, and both ML-DSA-87 and
/// P-521 must verify over it against a trusted root for a kernel tier.
#[cfg(feature = "plugin-verify")]
fn check(image: &Image<'_>) -> Result<(Signature, [u8; 8]), LoadError> {
    let digest = verify_impl::digest(image.signed(), nanochrono_core::ncplu::H_DIGEST);
    if image.header_digest() != &digest[..] {
        return Err(LoadError::Corrupt);
    }
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    Ok((verify_on_scratch(&digest, image.signature_block()), prefix))
}

/// The signature check, on the verification stack: ML-DSA-87 verify alone
/// needs ~768 KiB, far past the kernel's 64 KiB, so it does not run on the
/// kernel's own stack.
#[cfg(feature = "plugin-verify")]
fn verify_on_scratch(digest: &[u8; 64], block: Option<&[u8]>) -> Signature {
    struct Job {
        digest: [u8; 64],
        block: *const u8,
        block_len: usize,
        has_block: bool,
        out: Signature,
    }
    extern "C" fn run(arg: *mut u8) {
        // SAFETY: `arg` is the `Job` `on_verify_stack` was handed.
        let job = unsafe { &mut *(arg as *mut Job) };
        let block = job.has_block.then(|| {
            // SAFETY: the slice is the image's signature block, valid for the
            // call; the switched stack does not move it.
            unsafe { core::slice::from_raw_parts(job.block, job.block_len) }
        });
        job.out = verify_impl::verify(&job.digest, block);
    }
    let mut job = Job {
        digest: *digest,
        block: block.map_or(core::ptr::null(), <[u8]>::as_ptr),
        block_len: block.map_or(0, <[u8]>::len),
        has_block: block.is_some(),
        out: Signature::Unsigned,
    };
    // SAFETY: ring 0, single core; `run` uses `arg` as the `Job` it is given.
    unsafe { on_verify_stack(run, &mut job as *mut Job as *mut u8) };
    job.out
}

/// Without the `plugin-verify` feature there is no SHA-512 to check with:
/// nothing is Official, and integrity rests on the format checks alone.
#[cfg(not(feature = "plugin-verify"))]
fn check(_image: &Image<'_>) -> Result<(Signature, [u8; 8]), LoadError> {
    Ok((Signature::NoRoot, [0; 8]))
}

/// A trusted root's fingerprint, as `ncplu-sign` prints it: the first 8
/// bytes of SHA-512 over its two public keys. `Creator` (✅) or `TreeRoot`
/// (🌳); `None` when that root is not embedded.
pub fn root_fingerprint(which: Tier) -> Option<[u8; 8]> {
    #[cfg(feature = "plugin-verify")]
    {
        verify_impl::root_fingerprint(which)
    }
    #[cfg(not(feature = "plugin-verify"))]
    {
        let _ = which;
        None
    }
}

/// The verifier proper. Its own module so the heavy crypto crates are pulled
/// in only with the feature.
#[cfg(feature = "plugin-verify")]
mod verify_impl {
    use super::{Signature, Tier, ROOT_MLDSA_LEN, ROOT_P521_LEN};
    use nanochrono_core::ncplu::{
        DIGEST_LEN, SIG_MAGIC, SIG_MLDSA_LEN, SIG_MLDSA_OFF, SIG_P521_LEN, SIG_P521_OFF,
    };
    use sha512::{Digest, Sha512};

    // The pinned root public keys, embedded by build.rs from NCPLU_ROOT_CREATOR
    // (✅) and NCPLU_ROOT_TREE (🌳), both outside the repo. Each is `None`
    // when that root was not given. Provides CREATOR_MLDSA/CREATOR_P521 and
    // TREE_MLDSA/TREE_P521.
    include!(concat!(env!("OUT_DIR"), "/ncplu_root_keys.rs"));

    type Root = (Option<&'static [u8; ROOT_MLDSA_LEN]>, Option<&'static [u8; ROOT_P521_LEN]>);
    const fn root(which: Tier) -> Root {
        match which {
            Tier::Creator => (CREATOR_MLDSA, CREATOR_P521),
            _ => (TREE_MLDSA, TREE_P521),
        }
    }

    fn finish(h: Sha512) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(h.finalize().as_slice());
        out
    }

    /// SHA-512 of the signed region with the header's digest field zeroed,
    /// hashed in three pieces so nothing is copied. `digest_at` is the
    /// field's offset, [`H_DIGEST`](crate::ncplu::H_DIGEST).
    pub fn digest(signed: &[u8], digest_at: usize) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(signed.get(..digest_at).unwrap_or(&[]));
        h.update([0u8; DIGEST_LEN]);
        h.update(signed.get(digest_at + DIGEST_LEN..).unwrap_or(&[]));
        finish(h)
    }

    pub fn root_fingerprint(which: Tier) -> Option<[u8; 8]> {
        let (Some(mldsa), Some(p521)) = root(which) else { return None };
        let mut h = Sha512::new();
        h.update(&mldsa[..]);
        h.update(&p521[..]);
        let d = finish(h);
        let mut out = [0u8; 8];
        out.copy_from_slice(&d[..8]);
        Some(out)
    }

    /// Both halves against one root.
    fn matches(which: Tier, digest: &[u8; 64], block: &[u8]) -> bool {
        let (Some(mldsa), Some(p521)) = root(which) else { return false };
        block
            .get(SIG_MLDSA_OFF..SIG_MLDSA_OFF + SIG_MLDSA_LEN)
            .is_some_and(|sig| verify_mldsa(mldsa, digest, sig))
            && block
                .get(SIG_P521_OFF..SIG_P521_OFF + SIG_P521_LEN)
                .is_some_and(|sig| verify_p521(p521, digest, sig))
    }

    pub fn verify(digest: &[u8; 64], block: Option<&[u8]>) -> Signature {
        // No root at all, no badge — a safe default, never a hardcoded key.
        if CREATOR_MLDSA.is_none() && TREE_MLDSA.is_none() {
            return Signature::NoRoot;
        }
        let Some(block) = block else { return Signature::Unsigned };
        if block.get(..4) != Some(&SIG_MAGIC[..]) {
            return Signature::Unsigned;
        }
        // The creator's root wins the ✅ badge; then the local tree root (🌳).
        if matches(Tier::Creator, digest, block) {
            return Signature::Creator;
        }
        if matches(Tier::TreeRoot, digest, block) {
            return Signature::TreeRoot;
        }
        // Untrusted: report the creator halves, for the card's hint.
        let (mldsa, p521) = match root(Tier::Creator) {
            (Some(m), Some(p)) => (
                block
                    .get(SIG_MLDSA_OFF..SIG_MLDSA_OFF + SIG_MLDSA_LEN)
                    .is_some_and(|sig| verify_mldsa(m, digest, sig)),
                block
                    .get(SIG_P521_OFF..SIG_P521_OFF + SIG_P521_LEN)
                    .is_some_and(|sig| verify_p521(p, digest, sig)),
            ),
            _ => (false, false),
        };
        Signature::Untrusted { mldsa, p521 }
    }

    fn verify_mldsa(key: &[u8; ROOT_MLDSA_LEN], msg: &[u8], sig: &[u8]) -> bool {
        use ml_dsa::signature::Verifier;
        use ml_dsa::MlDsa87;
        let Ok(enc_vk) = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(&key[..]) else {
            return false;
        };
        let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&enc_vk);
        let Ok(enc_sig) = ml_dsa::EncodedSignature::<MlDsa87>::try_from(sig) else {
            return false;
        };
        let Some(sig) = ml_dsa::Signature::<MlDsa87>::decode(&enc_sig) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }

    fn verify_p521(key: &[u8; ROOT_P521_LEN], msg: &[u8], sig: &[u8]) -> bool {
        use p521::ecdsa::signature::Verifier;
        let Ok(vk) = p521::ecdsa::VerifyingKey::from_sec1_bytes(&key[..]) else {
            return false;
        };
        let Ok(sig) = p521::ecdsa::Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }
}

/// Loads a `.ncplu` into the arena and returns its entry point.
///
/// The file is untrusted — it comes off a USB stick and may be crafted. So
/// nothing is copied until [`Image::parse`] has checked all of it (see
/// `nanochrono_core::ncplu` for the rules), then its digest, then its
/// signature. The copy and the relocations after that re-read each entry
/// through the same checks and index the arena only with `get_mut`: there
/// is no path from a byte in the file to a write outside the arena, or to a
/// panic.
///
/// # Safety
/// Writes the executable arena and resolves kernel symbols; requires ring 0.
/// No plugin may be running.
pub unsafe fn inspect(file: &[u8]) -> Result<Inspected<'_>, LoadError> {
    let image = Image::parse(file).map_err(LoadError::Format)?;
    if image.arch() != this_arch() {
        return Err(LoadError::WrongArch);
    }
    let t0 = crate::arch::counter_ordered();
    let (signature, digest) = check(&image)?;
    let check_ticks = crate::arch::counter_ordered().wrapping_sub(t0);
    let tier = signature.tier();
    if image.flags & FLAG_WANTS_PRIVILEGED != 0 && !tier.runs_in_kernel() {
        // Loading it anyway would leave its privileged imports unresolved and
        // crash it later; refuse now, with the reason.
        return Err(LoadError::Privileged);
    }
    Ok(Inspected {
        arena_size: image.arena_size as u32,
        file_size: image.bytes().len() as u32,
        image,
        tier,
        signature,
        digest,
        check_ticks,
    })
}

/// A validated, verified plugin, before it is copied into the arena. Holds
/// where the arena will need mapping (`arena_size`) so a ring-3 run can map
/// and build its user `NcApi` before [`place`] resolves the plugin's imports
/// against it.
pub struct Inspected<'a> {
    image: Image<'a>,
    pub tier: Tier,
    pub signature: Signature,
    pub digest: [u8; 8],
    pub check_ticks: u64,
    pub arena_size: u32,
    pub file_size: u32,
}

/// The arena's base address (2 MiB-aligned, its own page), for the ring-3
/// mapper.
pub fn arena_ptr() -> usize {
    core::ptr::addr_of!(ARENA) as usize
}

/// Copies the inspected plugin into the arena and applies its relocations.
/// `abi_user` is `Some(addr)` for a ring-3 plugin — the user-memory address its
/// `nc_abi_version` import resolves to, with the stack canary's two symbols
/// beside it (`crate::ring3::user_symbol`); a ring-3 plugin may import nothing
/// else (kernel functions are reached through the `NcApi`, kernel data is not
/// user-readable). `None` is a kernel-tier plugin, resolved as before.
///
/// # Safety
/// Writes the executable arena; ring 0; no plugin running.
pub unsafe fn place(insp: &Inspected<'_>, abi_user: Option<usize>) -> Result<Loaded, LoadError> {
    let image = &insp.image;
    let tier = insp.tier;
    // SAFETY: single core, interrupts masked, and no plugin is running: this is
    // the only reference to the arena.
    let whole = unsafe { &mut (*core::ptr::addr_of_mut!(ARENA)).bytes };
    let bad = LoadError::Format(FormatError::BadSection);
    let arena = whole.get_mut(..image.arena_size).ok_or(bad)?;
    arena.fill(0);

    for i in 0..image.section_count() {
        let section = image.section(i).map_err(LoadError::Format)?;
        let bytes = image.section_bytes(&section).map_err(LoadError::Format)?;
        let end = section.mem_off.checked_add(bytes.len()).ok_or(bad)?;
        arena.get_mut(section.mem_off..end).ok_or(bad)?.copy_from_slice(bytes);
    }

    let base = arena.as_ptr() as u64;
    for i in 0..image.reloc_count() {
        let (offset, value) = match image.reloc(i).map_err(LoadError::Format)? {
            Reloc::Relative { offset, target } => (offset, base + target as u64),
            Reloc::Import { offset, import } => {
                let name = image.import_name(import).map_err(LoadError::Format)?;
                let addr = match abi_user {
                    // Ring 3: only what is laid out in user memory.
                    Some(abi) => {
                        crate::ring3::user_symbol(name, abi).ok_or(LoadError::UnresolvedImport)?
                    }
                    // Kernel tier: the kernel's own symbols, tier-gated.
                    None => {
                        let (addr, min_tier) =
                            nc_resolve_symbol(name).ok_or(LoadError::UnresolvedImport)?;
                        if !tier.may_use(min_tier) {
                            return Err(LoadError::UnresolvedImport);
                        }
                        addr
                    }
                };
                (offset, addr as u64)
            }
        };
        let end = offset.checked_add(8).ok_or(bad)?;
        let slot = arena.get_mut(offset..end).ok_or(LoadError::Format(FormatError::BadRelocation))?;
        slot.copy_from_slice(&value.to_le_bytes());
    }

    Ok(Loaded {
        entry: base as usize + image.entry,
        entry_off: image.entry,
        capabilities: image.capabilities,
        tier,
        signature: insp.signature,
        arena_size: insp.arena_size,
        file_size: insp.file_size,
        digest: insp.digest,
        check_ticks: insp.check_ticks,
    })
}

// ===========================================================================
// Running a plugin: its own stack, guard pages, and fault containment
//
// A plugin runs at ring 0 (ring 3 is the next module), so nothing here can
// stop deliberately hostile plugin code from touching kernel memory with its
// own instructions — the signature tier and the launch card are the barrier
// for that today. What this does stop:
//
// * the kernel being turned against itself: every buffer a plugin hands a
//   kernel service must lie in the plugin's own memory ([`plugin_owns`]), so
//   the kernel never reads or writes where a plugin points it;
// * a runaway stack: the plugin runs on a stack of its own between two
//   unmapped guard pages, so overflowing it — or unwinding past its top —
//   faults instead of running into the kernel's stack or statics;
// * a crash taking the machine down: a fault in the plugin's code, or on its
//   guards, abandons the plugin and returns to the interface
//   ([`contain_fault`]). A fault in kernel code is never hidden this way.
// ===========================================================================

/// The plugin's stack.
pub const PLUGIN_STACK_LEN: usize = 256 * 1024;

#[repr(C, align(4096))]
struct PluginStack {
    low_guard: [u8; 4096],
    stack: [u8; PLUGIN_STACK_LEN],
    high_guard: [u8; 4096],
}

static mut PLUGIN_STACK: PluginStack =
    PluginStack { low_guard: [0; 4096], stack: [0; PLUGIN_STACK_LEN], high_guard: [0; 4096] };

/// The running plugin's arena size; 0 when no plugin runs.
static RUNNING_ARENA: AtomicUsize = AtomicUsize::new(0);

fn arena_base() -> usize {
    core::ptr::addr_of!(ARENA) as usize
}

fn stack_range() -> core::ops::Range<usize> {
    let base = core::ptr::addr_of!(PLUGIN_STACK) as usize + 4096;
    base..base + PLUGIN_STACK_LEN
}

fn guard_ranges() -> [core::ops::Range<usize>; 2] {
    let low = core::ptr::addr_of!(PLUGIN_STACK) as usize;
    let high = low + 4096 + PLUGIN_STACK_LEN;
    [low..low + 4096, high..high + 4096]
}

/// Whether `[ptr, ptr + len)` lies wholly inside memory the running plugin
/// owns: its loaded arena or its stack. Every kernel service that takes a
/// pointer from a plugin checks it with this first, and refuses rather than
/// follows one that points anywhere else — a plugin cannot aim the kernel at
/// kernel memory. False when no plugin is running.
pub fn plugin_owns(ptr: usize, len: usize) -> bool {
    // A ring-3 plugin's memory is its arena, user stack and shared page.
    if crate::ring3::active() {
        return crate::ring3::user_owns(ptr, len);
    }
    let arena = RUNNING_ARENA.load(Ordering::Relaxed);
    let Some(end) = ptr.checked_add(len) else { return false };
    if arena == 0 {
        return false;
    }
    let base = arena_base();
    let stack = stack_range();
    (base <= ptr && end <= base + arena) || (stack.start <= ptr && end <= stack.end)
}

// ---- guard pages -----------------------------------------------------------

/// 4 KiB page tables for the 2 MiB pages the guards sit in, when the boot
/// map left those pages whole. Two: the guards can straddle a 2 MiB line.
#[repr(C, align(4096))]
struct PageTable([u64; 512]);
static mut GUARD_TABLES: [PageTable; 2] = [PageTable([0; 512]), PageTable([0; 512])];
/// 0 not tried yet, 1 armed, 2 could not be armed.
static GUARDS: AtomicUsize = AtomicUsize::new(0);

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_FLAGS: u64 = 0x1F; // present, writable, user, write-through, cache-disable
const PTE_HUGE: u64 = 1 << 7;
const PTE_ADDR: u64 = 0x000F_FFFF_FFFF_F000;

/// Unmaps one 4 KiB page of the identity map. If the 2 MiB page it sits in
/// is still whole, it is re-expressed as 4 KiB pages first, in one of
/// [`GUARD_TABLES`] — the same thing boot32.S does for the kernel stack's
/// guard, which is why the first gigabyte is already a page directory here.
///
/// # Safety
/// Ring 0, identity-mapped page tables (physical equals virtual), and `addr`
/// in the first gigabyte, as the whole kernel image is.
unsafe fn unmap_page(addr: usize, spare: &mut usize) -> bool {
    let cr3: u64;
    // SAFETY: reading CR3 at CPL 0 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
    // SAFETY (the reads and writes below): every table is reached through a
    // present entry of the live map, which is identity-mapped.
    unsafe {
        let pml4 = (cr3 & PTE_ADDR) as *const u64;
        let e4 = *pml4.add((addr >> 39) & 511);
        if e4 & PTE_PRESENT == 0 {
            return false;
        }
        let pdpt = (e4 & PTE_ADDR) as *const u64;
        let e3 = *pdpt.add((addr >> 30) & 511);
        if e3 & PTE_PRESENT == 0 || e3 & PTE_HUGE != 0 {
            return false;
        }
        let pd = (e3 & PTE_ADDR) as *mut u64;
        let slot = pd.add((addr >> 21) & 511);
        let e2 = *slot;
        if e2 & PTE_PRESENT == 0 {
            return false;
        }
        let pt: *mut u64 = if e2 & PTE_HUGE != 0 {
            if *spare >= 2 {
                return false;
            }
            let table = (*core::ptr::addr_of_mut!(GUARD_TABLES)).as_mut_ptr().add(*spare) as *mut u64;
            *spare += 1;
            let frame = e2 & PTE_ADDR & !0x1F_FFFF;
            for i in 0..512u64 {
                *table.add(i as usize) = (frame + i * 4096) | (e2 & PTE_FLAGS);
            }
            *slot = (table as u64) | PTE_PRESENT | PTE_WRITABLE;
            table
        } else {
            (e2 & PTE_ADDR) as *mut u64
        };
        *pt.add((addr >> 12) & 511) = 0;
        // A whole-TLB flush, global entries included: a 2 MiB entry may just
        // have become a table, and the boot map's first gigabyte is global.
        crate::arch::x86::flush_tlb_all();
    }
    true
}

/// Unmaps both guards, once. Returns whether they are armed.
fn arm_guards() -> bool {
    match GUARDS.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let mut spare = 0;
    let ok = guard_ranges().iter().all(|g| {
        // SAFETY: ring 0; the guards are this image's own statics, in the
        // first gigabyte, identity-mapped; nothing else lives in their pages.
        unsafe { unmap_page(g.start, &mut spare) }
    });
    GUARDS.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
    ok
}

// ---- the call, and the way back from a fault -------------------------------

/// The kernel's RSP while a plugin runs, and the state `nc_plugin_call`
/// restores after it: MXCSR and the x87 control word, which a plugin may
/// change (a rounding mode, an unmasked exception) and the kernel's own float
/// code must not inherit.
static mut NC_PLUGIN_KERNEL_RSP: u64 = 0;
static mut NC_PLUGIN_MXCSR: u32 = 0;
static mut NC_PLUGIN_FCW: u16 = 0;
/// What `nc_plugin_abort` returns: set by [`contain_fault`].
static mut NC_PLUGIN_ABORT_CODE: i64 = 0;

// nc_plugin_call(entry, api, stack_top) -> i64
//   Saves the callee-saved registers, MXCSR and the x87 control word, moves
//   to the plugin's stack and calls entry(api). Returns its result, sign-
//   extended; or, entered at nc_plugin_abort after a contained fault, the
//   abort code. Either way the kernel's stack and state come back.
core::arch::global_asm!(
    ".global nc_plugin_call",
    "nc_plugin_call:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "sub rsp, 8",
    "stmxcsr [rip + {mxcsr}]",
    "fnstcw [rip + {fcw}]",
    "mov [rip + {krsp}], rsp",
    "mov rsp, rdx",
    "mov rax, rdi",
    "mov rdi, rsi",
    "call rax",
    "movsxd rax, eax",
    "jmp 2f",
    ".global nc_plugin_abort",
    "nc_plugin_abort:",
    "mov rax, [rip + {code}]",
    "2:",
    "mov rsp, [rip + {krsp}]",
    "cld",
    "ldmxcsr [rip + {mxcsr}]",
    "fldcw [rip + {fcw}]",
    "add rsp, 8",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    krsp = sym NC_PLUGIN_KERNEL_RSP,
    mxcsr = sym NC_PLUGIN_MXCSR,
    fcw = sym NC_PLUGIN_FCW,
    code = sym NC_PLUGIN_ABORT_CODE,
);

extern "C" {
    fn nc_plugin_call(entry: usize, api: *const NcApi, stack_top: usize) -> i64;
    fn nc_plugin_abort();
    fn nc_run_on_stack(func: extern "C" fn(*mut u8), arg: *mut u8, stack_top: usize);
}

// nc_run_on_stack(func, arg, stack_top): run func(arg) on another stack, then
// come back. For work whose stack use dwarfs the kernel's own 64 KiB stack —
// verifying an ML-DSA-87 signature needs about 768 KiB — without enlarging
// every interrupt's stack to match. Saves the callee-saved registers and the
// kernel's RSP, switches, calls, and restores.
core::arch::global_asm!(
    ".global nc_run_on_stack",
    "nc_run_on_stack:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov [rip + {rsp}], rsp",
    "mov rsp, rdx",
    "mov rax, rdi",
    "mov rdi, rsi",
    "call rax",
    "mov rsp, [rip + {rsp}]",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    rsp = sym NC_SCRATCH_SAVED_RSP,
);
static mut NC_SCRATCH_SAVED_RSP: u64 = 0;

/// A stack of its own for signature verification, with a guard page below it:
/// 1.5 MiB, comfortably past ML-DSA-87 verify's ~768 KiB at -O0. An overflow
/// hits the guard and faults (a crash dump) instead of silently running into
/// the kernel's statics. Zeroed `.bss`, in the first gigabyte like the rest
/// of the image, so [`unmap_page`] can punch its guard.
pub const VERIFY_STACK_LEN: usize = 3 * 512 * 1024;

#[repr(C, align(4096))]
struct VerifyStack {
    guard: [u8; 4096],
    stack: [u8; VERIFY_STACK_LEN],
}
static mut VERIFY_STACK: VerifyStack = VerifyStack { guard: [0; 4096], stack: [0; VERIFY_STACK_LEN] };
/// 0 not tried, 1 guard armed, 2 could not arm.
static VERIFY_GUARD: AtomicUsize = AtomicUsize::new(0);

/// Runs `func(arg)` on the verification stack, arming its guard page once.
///
/// # Safety
/// Ring 0, single core; `func` must treat `arg` as it was handed.
unsafe fn on_verify_stack(func: extern "C" fn(*mut u8), arg: *mut u8) {
    if VERIFY_GUARD.load(Ordering::Relaxed) == 0 {
        let base = core::ptr::addr_of!(VERIFY_STACK) as usize;
        let mut spare = 0;
        // SAFETY: ring 0; the guard is this image's own static, in the first
        // gigabyte, identity-mapped, and nothing else lives in its page.
        let ok = unsafe { unmap_page(base, &mut spare) };
        VERIFY_GUARD.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
    }
    let top = core::ptr::addr_of!(VERIFY_STACK) as usize + 4096 + VERIFY_STACK_LEN;
    // SAFETY: `top` is the top of the dedicated stack, 16-byte aligned (the
    // struct is page-aligned and its sizes are multiples of 16); the
    // trampoline restores the kernel's stack and registers on return.
    unsafe { nc_run_on_stack(func, arg, top) };
}

/// What stopped the last plugin, if a fault did.
#[derive(Debug, Clone, Copy)]
pub struct Fault {
    pub vector: u64,
    pub rip: u64,
    pub cr2: u64,
    /// It ran off its stack into a guard page.
    pub stack: bool,
    /// The fault was inside a kernel service the plugin had called.
    pub in_service: bool,
}

static mut LAST_FAULT: Option<Fault> = None;

/// First stage of the trap path, with CR2 already read: if the fault belongs
/// to the running plugin, record it and rewrite `frame` to resume at
/// `nc_plugin_abort` on the kernel's stack — the plugin is abandoned, the
/// machine carries on. Otherwise leave it to the crash path.
///
/// The plugin's are faults in its own code, or any fault on its guard pages
/// (its stack ran out, even inside a kernel service it called). The NMI,
/// double fault and machine check are never contained.
pub fn contain_fault(frame: &mut crate::crashdump::TrapFrame, cr2: u64) -> bool {
    // A fault from a ring-3 plugin (any fault: it cannot harm the kernel) is
    // contained by the ring-3 runtime, which unwinds to the kernel.
    if crate::ring3::contain(frame, cr2) {
        return true;
    }
    let arena = RUNNING_ARENA.load(Ordering::Relaxed);
    if arena == 0 {
        return false;
    }
    let vector = frame.vector;
    let base = arena_base();
    let in_code = (base..base + arena).contains(&(frame.rip as usize));
    let on_guard = vector == 14 && guard_ranges().iter().any(|g| g.contains(&(cr2 as usize)));
    let containable = matches!(vector, 0 | 3 | 4 | 5 | 6 | 7 | 12 | 13 | 14 | 16 | 17 | 19);
    if !containable || !(in_code || on_guard) {
        return false;
    }
    // SAFETY: single core; the plugin is not running while its fault is
    // handled, and nothing else touches these.
    unsafe {
        *core::ptr::addr_of_mut!(LAST_FAULT) =
            Some(Fault { vector, rip: frame.rip, cr2, stack: on_guard, in_service: !in_code });
        *core::ptr::addr_of_mut!(NC_PLUGIN_ABORT_CODE) = -(0x100 + vector as i64);
        frame.rsp = *core::ptr::addr_of!(NC_PLUGIN_KERNEL_RSP);
    }
    frame.rip = nc_plugin_abort as *const () as usize as u64;
    // IF clear, as the kernel runs; DF and TF clear; bit 1 is reserved-one.
    frame.rflags = 0x2;
    true
}

/// The name of an exception vector, for the log and the card.
pub const fn vector_name(vector: u64) -> &'static str {
    match vector {
        0 => "divide error",
        3 => "breakpoint",
        4 => "overflow",
        5 => "bound range",
        6 => "invalid opcode",
        7 => "no FPU",
        12 => "stack-segment fault",
        13 => "general protection fault",
        14 => "page fault",
        16 => "x87 floating-point error",
        17 => "alignment check",
        19 => "SIMD floating-point error",
        _ => "exception",
    }
}

/// Loads and runs an app, handing it the screen until it returns.
///
/// `image` is whatever a path held: a `.ncpkg` package, a single `.ncapp`,
/// or — refused with the reason on a card — a driver, a library, a plugin,
/// or a module for another machine. A package goes through [`unpack`]
/// first, which picks this architecture's app out of it and checks it
/// against the manifest's SHA-512; the module it yields is then run exactly
/// as if it had arrived alone — its own signature decides its tier.
///
/// Returns the app's exit code; -1 if it was refused, -2 if the user
/// cancelled it at the launch card, and -(0x100 + vector) if a fault stopped
/// it.
///
/// # Safety
/// Drives the framebuffer and input on the app's behalf; requires ring 0.
/// `fb` and `input` must stay valid until this returns.
pub unsafe fn run(
    name: &str,
    image: &[u8],
    fb: &crate::framebuffer::Framebuffer,
    input: &mut crate::input::Input,
    pmu: &crate::pmu::CorePmu,
    ticks_per_sec: u64,
) -> i32 {
    if image.get(..8) == Some(&nanochrono_core::ncpkg::MAGIC[..]) {
        // SAFETY: one app loads at a time (this function's contract), so
        // the unpack buffer is free.
        return match unsafe { unpack(image) } {
            // SAFETY: forwarded from this function's own contract.
            Ok(module) => unsafe { run(name, module, fb, input, pmu, ticks_per_sec) },
            Err(e) => {
                crate::println!("plugin: {name}: refused: {}", e.message());
                crate::plugin_card::refused(fb, input, name, e, ticks_per_sec.max(1));
                -1
            }
        };
    }
    // A driver or a library is installed, not run: say so now, with the
    // reason, rather than faulting later on a missing entry point.
    if image.get(..8) == Some(&MAGIC[..]) {
        if let Ok(single) = Image::parse(image) {
            if single.kind() != Kind::App {
                let e = LoadError::NotRunnable;
                crate::println!("plugin: {name}: refused: {}", e.message());
                crate::plugin_card::refused(fb, input, name, e, ticks_per_sec.max(1));
                return -1;
            }
        }
    }
    #[cfg(x86_any)]
    let _crumb = crate::crashdump::Driver::Interface.enter();
    let hz = ticks_per_sec.max(1);
    NC_STACK_CHK_GUARD.store(new_stack_guard(), Ordering::Relaxed);
    STACK_SMASHED.store(false, Ordering::Relaxed);

    // Parse, verify and gate. Nothing is copied into the arena yet.
    // SAFETY: forwarded from this function's own contract; no plugin runs.
    let inspected = match unsafe { inspect(image) } {
        Ok(i) => i,
        Err(e) => {
            crate::println!("plugin: {name}: refused: {}", e.message());
            crate::plugin_card::refused(fb, input, name, e, hz);
            return -1;
        }
    };
    let tier = inspected.tier;

    // A community plugin runs at ring 3: its arena and a user stack are mapped
    // user, and it is handed an NcApi in user memory whose calls trap in. A
    // creator or trusted-root plugin runs in the kernel, called directly.
    let ring3_plugin = !tier.runs_in_kernel();
    let prepared = if ring3_plugin {
        // SAFETY: ring 0; the arena is the 2 MiB-aligned plugin page, and
        // SYSCALL/SYSRET are armed here on first use.
        unsafe {
            crate::ring3::init();
            Some(crate::ring3::prepare(
                arena_ptr(),
                inspected.arena_size as usize,
                fb.width,
                fb.height,
                ticks_per_sec,
            ))
        }
    } else {
        None
    };
    let abi_user = prepared.as_ref().map(|p| p.abi_user);

    // SAFETY: ring 0; no plugin running. For ring 3, imports resolve to user
    // memory; for the kernel tier, to the kernel's symbols.
    let loaded = match unsafe { place(&inspected, abi_user) } {
        Ok(l) => l,
        Err(e) => {
            crate::println!("plugin: {name}: refused: {}", e.message());
            crate::plugin_card::refused(fb, input, name, e, hz);
            return -1;
        }
    };
    report(name, &loaded, hz);

    if !crate::plugin_card::confirm(fb, input, name, &loaded, hz) {
        crate::println!("plugin: {name}: cancelled at the launch card");
        return -2;
    }

    // Grant exactly what the plugin declared, only for as long as it runs;
    // every service checks it.
    GRANTED_CAPS.store(loaded.capabilities, Ordering::Relaxed);
    let mut ctx = PluginCtx { fb, input, pmu };
    PLUGIN_TICKS_PER_SEC.store(hz, Ordering::Relaxed);
    PLUGIN_CTX.store(&mut ctx as *mut PluginCtx as usize, Ordering::Relaxed);

    let code = if let Some(prepared) = prepared {
        // ---- ring 3 ----
        // SAFETY: prepare() mapped the arena, stack and shared page and built
        // the user NcApi; the entry is inside the loaded code; PLUGIN_CTX is
        // set for the services the nccall dispatcher forwards to.
        let outcome = unsafe {
            crate::ring3::run(arena_ptr() + loaded.entry_off, prepared.api_user)
        };
        PLUGIN_CTX.store(0, Ordering::Relaxed);
        match outcome {
            crate::ring3::Outcome::Exited(code) => {
                if crate::ring3::stack_smashed() {
                    crate::println!(
                        "plugin: {name}: stopped \u{2014} stack smashing detected (a stack canary was overwritten)"
                    );
                    crate::plugin_card::smashed(fb, input, name, hz);
                }
                if let Some(num) = crate::ring3::denied_call() {
                    crate::println!(
                        "plugin: {name}: stopped \u{2014} nccall {num} needs a capability it was not granted"
                    );
                }
                code
            }
            crate::ring3::Outcome::Faulted(f) => {
                crate::println!(
                    "plugin: {name}: stopped by a {} at rip {:#x} (ring 3){}",
                    vector_name(f.vector),
                    f.rip,
                    if f.vector == 14 { ", page fault outside its memory" } else { "" },
                );
                crate::rng::recover_after_abort();
                let card = Fault { vector: f.vector, rip: f.rip, cr2: f.cr2, stack: false, in_service: false };
                crate::plugin_card::stopped(fb, input, name, &card, hz);
                -(0x100 + f.vector as i32)
            }
        }
    } else {
        // ---- kernel tier ----
        if !arm_guards() {
            crate::println!("plugin: warning: the stack guard pages could not be armed");
        }
        let api = NcApi {
            abi_version: ABI_VERSION,
            screen_w: fb.width,
            screen_h: fb.height,
            _reserved: 0,
            ticks_per_sec,
            fill_rect: nc_fill_rect,
            clear: nc_clear,
            present: nc_present,
            poll_event: nc_poll_event,
            ticks: nc_ticks,
            log: nc_log,
            timer_now: nc_timer_now,
            timer_now_end: nc_timer_now_end,
            timer_hz: nc_timer_hz,
            timer_source: nc_timer_source,
            timer_ticks_to_ns: nc_timer_ticks_to_ns,
            pmu_caps: nc_pmu_caps,
            pmu_open: nc_pmu_open,
            pmu_read: nc_pmu_read,
            pmu_close: nc_pmu_close,
            rng_fill: crate::rng::nc_rng_fill,
            rng_status: crate::rng::nc_rng_status,
            rng_stir: crate::rng::nc_rng_stir,
        };
        // SAFETY: single core; nothing else reads or writes the fault record.
        unsafe { *core::ptr::addr_of_mut!(LAST_FAULT) = None };
        RUNNING_ARENA.store(loaded.arena_size as usize, Ordering::Relaxed);
        // SAFETY: the entry lies in the loaded code (the parser checked it);
        // the stack is the plugin's own; the trampoline gives back the kernel's
        // stack and registers however the plugin ends.
        let code = unsafe { nc_plugin_call(loaded.entry, &api, stack_range().end) };
        RUNNING_ARENA.store(0, Ordering::Relaxed);
        PLUGIN_CTX.store(0, Ordering::Relaxed);
        if STACK_SMASHED.swap(false, Ordering::Relaxed) {
            crate::println!(
                "plugin: {name}: stopped \u{2014} stack smashing detected (a stack canary was overwritten)"
            );
            crate::plugin_card::smashed(fb, input, name, hz);
        }
        // SAFETY: as above.
        if let Some(fault) = unsafe { (*core::ptr::addr_of_mut!(LAST_FAULT)).take() } {
            crate::println!(
                "plugin: {name}: stopped by a {} at rip {:#x}{}{}",
                vector_name(fault.vector),
                fault.rip,
                if fault.stack { " (ran off its stack into a guard page)" } else { "" },
                if fault.in_service { ", inside a kernel service" } else { "" },
            );
            if fault.in_service {
                crate::rng::recover_after_abort();
            }
            crate::plugin_card::stopped(fb, input, name, &fault, hz);
        }
        code as i32
    };

    GRANTED_CAPS.store(0, Ordering::Relaxed);
    crate::println!("plugin: {name}: returned {code}");
    code
}

/// The load's findings, on the serial log.
fn report(name: &str, loaded: &Loaded, hz: u64) {
    let mut digest = crate::text::Text::<24>::new();
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for b in loaded.digest {
        digest.push(DIGITS[(b >> 4) as usize]).push(DIGITS[(b & 15) as usize]);
    }
    crate::println!(
        "plugin: {name}: {} bytes, arena {} bytes, SHA-512 {}...",
        loaded.file_size,
        loaded.arena_size,
        digest.as_str()
    );
    let (mark, where_) = match loaded.tier {
        Tier::Creator => ("\u{2705}", "kernel"),
        Tier::TreeRoot => ("\u{1F333}", "kernel"),
        Tier::Community => ("", "ring 3 (user mode, isolated)"),
    };
    crate::println!(
        "plugin: {name}: tier {} {mark} ({}), runs in {where_}, checked in {} ms",
        loaded.tier.label(),
        loaded.signature.describe(),
        loaded.check_ticks.saturating_mul(1000) / hz.max(1)
    );
    for (which, tag) in [(Tier::Creator, "creator \u{2705}"), (Tier::TreeRoot, "tree \u{1F333}")] {
        if let Some(fp) = root_fingerprint(which) {
            let mut t = crate::text::Text::<24>::new();
            crate::plugin_card::fingerprint(&mut t, &fp);
            crate::println!("plugin: trusted root {tag}: {}", t.as_str());
        }
    }
    let mut caps = crate::text::Text::<64>::new();
    write_caps(&mut caps, loaded.capabilities);
    crate::println!("plugin: {name}: capabilities {}", caps.as_str());
}

/// Writes the granted capability groups by name into `t`.
pub fn write_caps<const N: usize>(t: &mut crate::text::Text<N>, caps: u32) {
    if caps == CAP_ALL {
        t.str("all");
        return;
    }
    if caps == 0 {
        t.str("none");
        return;
    }
    let mut first = true;
    for (bit, name) in [
        (CAP_SCREEN, "screen"),
        (CAP_INPUT, "input"),
        (CAP_LOG, "log"),
        (CAP_TIMER, "timer"),
        (CAP_PMU, "pmu"),
        (CAP_RNG, "rng"),
    ] {
        if caps & bit != 0 {
            if !first {
                t.str(" ");
            }
            t.str(name);
            first = false;
        }
    }
}

// ===========================================================================
// Packages
// ===========================================================================

/// Where a compressed app is inflated before it is run: the module limit,
/// static like every other buffer here.
pub(crate) const UNPACK_BUF_LEN: usize = nanochrono_core::ncplu::MAX_IMAGE;
static mut UNPACK_BUF: [u8; UNPACK_BUF_LEN] = [0; UNPACK_BUF_LEN];

/// Picks this machine's app out of a `.ncpkg`: the container and the
/// manifest checked (`nanochrono_core::ncpkg`), the manifest's app entry
/// for this architecture found, inflated if it was stored compressed, and
/// its SHA-512 compared with the one the manifest lists — so a damaged or
/// altered package fails here, before anything of it is mapped.
///
/// The package's own signatures are judged when it is installed (`ncpkg`);
/// what runs is judged by the module's own signature, as for any module.
///
/// # Safety
/// Uses the unpack buffer: no other app may be loading.
pub unsafe fn unpack(image: &[u8]) -> Result<&[u8], LoadError> {
    use nanochrono_core::ncpkg::{self, meta::Meta, Method};
    let pkg = ncpkg::Package::parse(image).map_err(LoadError::BadPackage)?;
    let meta = Meta::parse(pkg.meta()).map_err(LoadError::BadManifest)?;
    meta.check_container(&pkg).map_err(LoadError::BadManifest)?;
    let app = meta.app().ok_or(LoadError::NotRunnable)?;
    if !meta.supports(this_arch()) {
        return Err(LoadError::WrongArch);
    }
    let entry = pkg.app_entry(this_arch(), app.entry).ok_or(LoadError::BadPackage(ncpkg::FormatError::NotFound))?;
    let listed = meta.file(entry.path).ok_or(LoadError::BadPackage(ncpkg::FormatError::NotFound))?;
    let module: &[u8] = match entry.method {
        Method::Stored => entry.stored,
        Method::Deflate => {
            // SAFETY: the caller guarantees no other load uses the buffer;
            // the slice handed back lives until the next unpack.
            let buf = unsafe { &mut *core::ptr::addr_of_mut!(UNPACK_BUF) };
            let n = entry.read_into(buf).map_err(LoadError::BadPackage)?;
            &buf[..n]
        }
    };
    if !nanochrono_core::sha512::ct_eq(&nanochrono_core::sha512::digest(module), &listed.sha512) {
        return Err(LoadError::Corrupt);
    }
    Ok(module)
}

// ===========================================================================
// Command-line trigger: `plugin=<name>` on the kernel command line
// ===========================================================================

/// The raw `.ncplu` bytes are read into this before loading. 512 KiB is far
/// larger than any phase-1 plugin (`-O0` Snake is ~90 KiB) and still static.
pub(crate) const IMAGE_BUF_LEN: usize = nanochrono_core::ncplu::MAX_IMAGE;
static mut IMAGE_BUF: [u8; IMAGE_BUF_LEN] = [0; IMAGE_BUF_LEN];

/// The scratch buffer a plugin's file is read into. One plugin loads at a
/// time, so a single buffer suffices.
///
/// # Safety
/// Single core, interrupts masked; not re-entrant across a load.
pub unsafe fn image_buffer() -> &'static mut [u8] {
    // SAFETY: forwarded from this function's own contract.
    unsafe { &mut *core::ptr::addr_of_mut!(IMAGE_BUF) }
}

/// A plugin armed on the command line, run once the interface is up.
static mut PENDING_PLUGIN: Option<[u8; 32]> = None;
static PENDING_PLUGIN_LEN: AtomicUsize = AtomicUsize::new(0);

/// Arms `plugin=<name>` for launch after the interface starts. `name` is the
/// base, without an extension; see [`PENDING_EXTENSIONS`] for the files
/// tried.
pub fn arm_plugin(name: &str) {
    let mut buf = [0u8; 32];
    let n = name.len().min(buf.len());
    buf[..n].copy_from_slice(&name.as_bytes()[..n]);
    // SAFETY: single core, interrupts masked, called once at boot.
    unsafe { PENDING_PLUGIN = Some(buf) };
    PENDING_PLUGIN_LEN.store(n, Ordering::Relaxed);
}

/// The files `plugin=<name>` looks for on the boot medium, in order: the
/// app itself, a package holding it, and the name modules had before the
/// `.ncapp`/`.ncpkg` split (a 4.0 stick's plugins still run).
pub const PENDING_EXTENSIONS: [&str; 3] = [".NCAPP", ".NCPKG", ".NCPLU"];

/// Takes the armed app's upper-cased base name, if one was armed; the
/// caller appends each of [`PENDING_EXTENSIONS`] in turn (see
/// [`pending_file_name`]).
pub fn take_pending_plugin() -> Option<([u8; 32], usize)> {
    // SAFETY: see `arm_plugin`.
    let base = unsafe { (*core::ptr::addr_of_mut!(PENDING_PLUGIN)).take()? };
    let n = PENDING_PLUGIN_LEN.load(Ordering::Relaxed);
    let mut name = [0u8; 32];
    for (dst, &b) in name.iter_mut().zip(&base[..n]) {
        *dst = b.to_ascii_uppercase();
    }
    Some((name, n))
}

/// `base` and `extension` as the 8.3-plus-LFN name
/// [`crate::usb_storage::read_file`] matches case-insensitively.
pub fn pending_file_name(base: &[u8], extension: &str) -> ([u8; 40], usize) {
    let mut name = [0u8; 40];
    let mut len = 0;
    for &b in base.iter().chain(extension.as_bytes()).take(40) {
        name[len] = b;
        len += 1;
    }
    (name, len)
}

/// Runs the plugin whose `n` image bytes are already in [`image_buffer`].
///
/// # Safety
/// As [`run`]; `image_buffer` must hold `n` valid bytes.
pub unsafe fn run_loaded(
    name: &str,
    n: usize,
    fb: &crate::framebuffer::Framebuffer,
    input: &mut crate::input::Input,
    pmu: &crate::pmu::CorePmu,
    ticks_per_sec: u64,
) -> i32 {
    let n = n.min(IMAGE_BUF_LEN);
    // SAFETY: the caller filled `n` bytes; the shared view does not outlive
    // this call, and nothing writes the buffer while the plugin runs.
    let image = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(IMAGE_BUF) as *const u8, n) };
    // SAFETY: forwarded from this function's own contract.
    unsafe { run(name, image, fb, input, pmu, ticks_per_sec) }
}

