// SPDX-License-Identifier: Apache-2.0
//! `.ncdri` driver modules: found among the boot modules (`/boot/drivers/`),
//! checked, placed in memory of their own, and served through the kernel's
//! table, `nckernel_api_t` — `sdk/include/ncdri_api.h`, docs/NCDRI.md.
//!
//! A driver is what the kernel does not build in (docs/SYSTEM.md §4): it
//! includes no kernel header and links no kernel symbol, so one built today
//! loads on every kernel of the same major version. What it can do, it does
//! through this table; every handle it holds is a pointer into one of the
//! pools below, checked on every call.
//!
//! # The order a module goes through
//!
//! 1. **Read and verify**, with the app launcher's checks
//!    ([`crate::ncplu::inspect`]): the format, the architecture, the
//!    digest, the hybrid signature.
//! 2. **Trust.** A driver runs in ring 0. Signed by a root this kernel
//!    trusts for ring 0, it loads; unsigned or self-signed, it loads only
//!    when the owner has turned on *Enable Ring0 Community Modules and
//!    Drivers* — for this boot, `ncdri.community=on` on the command line
//!    (docs/ECOSYSTEM.md §3). Off by default.
//! 3. **Inspect.** It must be a driver (`Kind::Driver`) whose only imports
//!    are the two the compiler emits for stack canaries.
//! 4. **Place** in memory from the page allocator ([`crate::palloc`]),
//!    relocated with the launcher's own code. The identity map has no NX
//!    and no per-page protection below 2 MiB yet, so its text is not made
//!    read-only — a limit of the boot page tables, recorded in NCDRI.md.
//! 5. **`ncdri_main(&table, sizeof table)`**; an error unloads it again.
//! 6. **Match**: every PCI device the kernel does not drive itself (bridges
//!    and USB host controllers are its own) is offered to each registered
//!    driver's `probe`; the best offer gets `attach`, with a zeroed softc.
//!
//! # What a driver gets, and what it does not yet
//!
//! Memory, register windows (MMIO and I/O ports), configuration space, bus
//! mastering, DMA memory below the cached ceiling (identity-mapped: the
//! bus address is the physical one; there is no IOMMU programmed), locks,
//! time, NC_RNG, and — minor 1 — the display: a driver that set a mode
//! hands the kernel its scanout. Interrupts are not delivered to drivers
//! yet (`irq_establish` says `ENOTSUP`: the kernel runs with them masked),
//! and a saved floating-point context is not offered (`fpu_alloc` says
//! `ENOTSUP`; the `NCDRI_FPU_NOCTX` bracket works).

#![allow(clippy::missing_safety_doc)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::framebuffer::Framebuffer;
use crate::ncplu::{copy_and_relocate, Kind, LoadError};
use crate::pci;

/// The ABI this kernel implements (`NCDRI_API_MAJOR`, `NCDRI_API_MINOR`).
const API_MAJOR: u16 = 1;
const API_MINOR: u16 = 1;

/// The errno values of ncdri_api.h (FreeBSD's).
mod errno {
    pub const OK: i32 = 0;
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const ENXIO: i32 = 6;
    pub const ENOMEM: i32 = 12;
    pub const EFAULT: i32 = 14;
    pub const EBUSY: i32 = 16;
    pub const EINVAL: i32 = 22;
    pub const ENOSPC: i32 = 28;
    pub const EAGAIN: i32 = 35;
    pub const ENOTSUP: i32 = 45;
}

const BUS_PCI: u32 = 1;
const RES_MEMORY: u32 = 1;
const RES_IOPORT: u32 = 2;
const MTX_SPIN: u32 = 1;
const MTX_SLEEP: u32 = 2;
const FPU_NOCTX: u32 = 0x4;
const LOG_ERROR: i32 = 0;
const LOG_WARN: i32 = 1;
/// DRM fourcc `XR24`: 32-bit `0x00RRGGBB`, the format the drawing code writes.
const FORMAT_XRGB8888: u32 = 0x3432_5258;

/// How far a physical address can reach: the 512 GiB boot32.S identity-maps.
const ADDRESSABLE: u64 = 512 << 30;

/// The kernel's version, NUL-terminated, for `kernel_version`.
static KERNEL_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

type Handle = *mut c_void;

// ---------------------------------------------------------------------------
// The structures that cross, as ncdri_api.h lays them out
// ---------------------------------------------------------------------------

/// `ncdri_devinfo_t`.
#[repr(C)]
#[derive(Clone, Copy)]
struct DevInfo {
    size: u32,
    bus: u32,
    vendor: u16,
    device: u16,
    subvendor: u16,
    subdevice: u16,
    class_code: u8,
    subclass: u8,
    progif: u8,
    revision: u8,
    hid: [u8; 32],
    reserved: [u32; 8],
}

const _: () = assert!(core::mem::size_of::<DevInfo>() == 84);

/// `ncdri_driver_t`. The method slots are kept as addresses, checked to lie
/// in the module before one is ever called.
#[repr(C)]
#[derive(Clone, Copy)]
struct DriverDesc {
    size: u32,
    api_major: u16,
    api_minor: u16,
    name: usize,
    softc_size: usize,
    probe: usize,
    attach: usize,
    detach: usize,
    suspend: usize,
    resume: usize,
    shutdown: usize,
    reserved: [usize; 8],
}

impl DriverDesc {
    const EMPTY: DriverDesc = DriverDesc {
        size: 0,
        api_major: 0,
        api_minor: 0,
        name: 0,
        softc_size: 0,
        probe: 0,
        attach: 0,
        detach: 0,
        suspend: 0,
        resume: 0,
        shutdown: 0,
        reserved: [0; 8],
    };
}

/// `ncdri_scanout_t`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Scanout {
    size: u32,
    res_index: u32,
    offset: u64,
    width: u32,
    height: u32,
    pitch: u32,
    format: u32,
    reserved: [u32; 6],
}

const _: () = assert!(core::mem::size_of::<Scanout>() == 56);
/// The fields a scanout must carry for the kernel to read it.
const SCANOUT_MIN: u32 = 32;

/// `nckernel_api_t`, field for field.
#[repr(C)]
#[derive(Clone, Copy)]
struct Api {
    size: u32,
    api_major: u16,
    api_minor: u16,
    kernel_version: *const u8,
    self_: Handle,
    driver_register: unsafe extern "C" fn(Handle, *const DriverDesc) -> i32,
    driver_unregister: unsafe extern "C" fn(Handle, *const DriverDesc) -> i32,
    device_name: unsafe extern "C" fn(Handle) -> *const u8,
    device_softc: unsafe extern "C" fn(Handle) -> *mut c_void,
    log: unsafe extern "C" fn(Handle, i32, *const u8, usize),
    mem_alloc: unsafe extern "C" fn(usize, usize, u32, *mut *mut c_void) -> i32,
    mem_free: unsafe extern "C" fn(*mut c_void, usize),
    resource_map: unsafe extern "C" fn(Handle, u32, u32, *mut Handle, *mut u64) -> i32,
    resource_unmap: unsafe extern "C" fn(Handle),
    read_1: unsafe extern "C" fn(Handle, u64) -> u8,
    read_2: unsafe extern "C" fn(Handle, u64) -> u16,
    read_4: unsafe extern "C" fn(Handle, u64) -> u32,
    read_8: unsafe extern "C" fn(Handle, u64) -> u64,
    write_1: unsafe extern "C" fn(Handle, u64, u8),
    write_2: unsafe extern "C" fn(Handle, u64, u16),
    write_4: unsafe extern "C" fn(Handle, u64, u32),
    write_8: unsafe extern "C" fn(Handle, u64, u64),
    barrier: unsafe extern "C" fn(Handle, u64, u64, u32),
    pci_cfg_read: unsafe extern "C" fn(Handle, u32, u32, *mut u32) -> i32,
    pci_cfg_write: unsafe extern "C" fn(Handle, u32, u32, u32) -> i32,
    pci_enable_busmaster: unsafe extern "C" fn(Handle, i32) -> i32,
    dma_alloc: unsafe extern "C" fn(Handle, usize, usize, u64, u32, *mut Handle) -> i32,
    dma_free: unsafe extern "C" fn(Handle),
    dma_kva: unsafe extern "C" fn(Handle) -> *mut c_void,
    dma_bus_addr: unsafe extern "C" fn(Handle) -> u64,
    dma_sync: unsafe extern "C" fn(Handle, usize, usize, u32),
    irq_establish: unsafe extern "C" fn(Handle, u32, usize, *mut c_void, *mut Handle) -> i32,
    irq_disestablish: unsafe extern "C" fn(Handle),
    mtx_init: unsafe extern "C" fn(*mut Handle, u32, *const u8) -> i32,
    mtx_enter: unsafe extern "C" fn(Handle),
    mtx_tryenter: unsafe extern "C" fn(Handle) -> i32,
    mtx_exit: unsafe extern "C" fn(Handle),
    mtx_destroy: unsafe extern "C" fn(Handle),
    time_ns: unsafe extern "C" fn() -> u64,
    delay_ns: unsafe extern "C" fn(u64),
    fpu_alloc: unsafe extern "C" fn(*mut Handle) -> i32,
    fpu_free: unsafe extern "C" fn(Handle),
    fpu_begin: unsafe extern "C" fn(Handle, u32),
    fpu_end: unsafe extern "C" fn(Handle),
    memcpy: unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> *mut c_void,
    memset: unsafe extern "C" fn(*mut c_void, i32, usize) -> *mut c_void,
    memcmp: unsafe extern "C" fn(*const c_void, *const c_void, usize) -> i32,
    rng_fill: unsafe extern "C" fn(*mut c_void, usize, u32) -> i32,
    // Minor 1.
    display_scanout: unsafe extern "C" fn(Handle, *const Scanout, *const u8, usize) -> i32,
    edid_preferred: unsafe extern "C" fn(*const u8, usize, *mut u32, *mut u32, *mut u32) -> i32,
    reserved: [usize; 30],
}

// The header's own pins: the table keeps its size within a major.
const _: () = assert!(core::mem::size_of::<Api>() == 8 + 77 * core::mem::size_of::<usize>());
const _: () = assert!(core::mem::offset_of!(Api, rng_fill) == 8 + 44 * core::mem::size_of::<usize>());
const _: () = assert!(core::mem::offset_of!(Api, display_scanout) == 8 + 45 * core::mem::size_of::<usize>());

// ---------------------------------------------------------------------------
// The pools every handle points into
// ---------------------------------------------------------------------------

const MAX_MODULES: usize = 16;
const MAX_DRIVERS: usize = 16;
const MAX_DEVICES: usize = 32;
const MAX_RESOURCES: usize = 64;
const MAX_DMA: usize = 64;
const MAX_MTX: usize = 64;

#[derive(Clone, Copy)]
struct Module {
    used: bool,
    base: usize,
    len: usize,
    api: Option<Api>,
}

#[derive(Clone, Copy)]
struct DriverSlot {
    used: bool,
    module: usize,
    desc_addr: usize,
    desc: DriverDesc,
    name: [u8; 12],
    units: u32,
}

#[derive(Clone, Copy)]
struct Device {
    used: bool,
    attached: bool,
    pci: Option<pci::Device>,
    driver: usize,
    softc: usize,
    softc_len: usize,
    /// `<driver name><unit>`, NUL-terminated.
    name: [u8; 16],
}

#[derive(Clone, Copy)]
struct Resource {
    used: bool,
    device: usize,
    io: bool,
    base: u64,
    len: u64,
}

#[derive(Clone, Copy)]
struct Dma {
    used: bool,
    device: usize,
    addr: usize,
    len: usize,
}

#[derive(Clone, Copy)]
struct Mtx {
    used: bool,
    held: bool,
}

trait Slot: Copy {
    const EMPTY: Self;
    fn used(&self) -> bool;
}

impl Slot for Module {
    const EMPTY: Self = Module { used: false, base: 0, len: 0, api: None };
    fn used(&self) -> bool {
        self.used
    }
}
impl Slot for DriverSlot {
    const EMPTY: Self = DriverSlot { used: false, module: 0, desc_addr: 0, desc: DriverDesc::EMPTY, name: [0; 12], units: 0 };
    fn used(&self) -> bool {
        self.used
    }
}
impl Slot for Device {
    const EMPTY: Self =
        Device { used: false, attached: false, pci: None, driver: 0, softc: 0, softc_len: 0, name: [0; 16] };
    fn used(&self) -> bool {
        self.used
    }
}
impl Slot for Resource {
    const EMPTY: Self = Resource { used: false, device: 0, io: false, base: 0, len: 0 };
    fn used(&self) -> bool {
        self.used
    }
}
impl Slot for Dma {
    const EMPTY: Self = Dma { used: false, device: 0, addr: 0, len: 0 };
    fn used(&self) -> bool {
        self.used
    }
}
impl Slot for Mtx {
    const EMPTY: Self = Mtx { used: false, held: false };
    fn used(&self) -> bool {
        self.used
    }
}

static mut MODULES: [Module; MAX_MODULES] = [Module::EMPTY; MAX_MODULES];
static mut DRIVERS: [DriverSlot; MAX_DRIVERS] = [DriverSlot::EMPTY; MAX_DRIVERS];
static mut DEVICES: [Device; MAX_DEVICES] = [Device::EMPTY; MAX_DEVICES];
static mut RESOURCES: [Resource; MAX_RESOURCES] = [Resource::EMPTY; MAX_RESOURCES];
static mut DMAS: [Dma; MAX_DMA] = [Dma::EMPTY; MAX_DMA];
static mut MTXS: [Mtx; MAX_MTX] = [Mtx::EMPTY; MAX_MTX];

/// The pool behind a handle: its index, when the handle is exactly one of
/// the pool's entries and that entry is in use. Nothing else is ever
/// dereferenced — a stale or made-up handle is refused, not followed.
///
/// # Safety
/// `pool` is one of the statics above; single core, interrupts masked.
unsafe fn index_of<T: Slot, const N: usize>(pool: *mut [T; N], h: Handle) -> Option<usize> {
    let base = pool as usize;
    let size = core::mem::size_of::<T>();
    let a = h as usize;
    if a < base || a >= base + size * N || (a - base) % size != 0 {
        return None;
    }
    let i = (a - base) / size;
    // SAFETY: `i` indexes the pool, per the checks above.
    unsafe { (*pool)[i].used().then_some(i) }
}

/// A free entry of `pool`, marked used by the caller.
///
/// # Safety
/// As [`index_of`].
unsafe fn free_slot<T: Slot, const N: usize>(pool: *mut [T; N]) -> Option<usize> {
    // SAFETY: forwarded.
    unsafe { (*pool).iter().position(|t| !t.used()) }
}

fn handle_of<T, const N: usize>(pool: *mut [T; N], i: usize) -> Handle {
    (pool as usize + i * core::mem::size_of::<T>()) as Handle
}

/// The device a handle names.
///
/// # Safety
/// As [`index_of`].
unsafe fn device(h: Handle) -> Option<(usize, Device)> {
    // SAFETY: forwarded.
    unsafe {
        let pool = core::ptr::addr_of_mut!(DEVICES);
        index_of(pool, h).map(|i| (i, (*pool)[i]))
    }
}

/// The resource a handle names.
///
/// # Safety
/// As [`index_of`].
unsafe fn resource(h: Handle) -> Option<Resource> {
    // SAFETY: forwarded.
    unsafe {
        let pool = core::ptr::addr_of_mut!(RESOURCES);
        index_of(pool, h).map(|i| (*pool)[i])
    }
}

// ---------------------------------------------------------------------------
// The services
// ---------------------------------------------------------------------------

/// The time base drivers see: the counter, calibrated once when the first
/// driver loads (the session's own clock starts later).
static mut CALIBRATION: Option<crate::clock::Calibration> = None;
static TIME_ORIGIN: AtomicU64 = AtomicU64::new(0);

/// The stack-canary value every driver's `__stack_chk_guard` names.
static DRIVER_STACK_GUARD: AtomicU64 = AtomicU64::new(0);

/// `__stack_chk_fail` for a driver: its stack is corrupt, in ring 0, with
/// nothing to unwind to — the kernel stops, with the crash dump.
extern "C" fn driver_stack_chk_fail() -> ! {
    panic!("ncdri: a driver's stack canary changed: its stack is corrupt")
}

/// Writes one log line: `ncdri: <device>: <message>`, the message printable
/// ASCII only and cut at 200 bytes.
unsafe extern "C" fn k_log(dev: Handle, level: i32, msg: *const u8, len: usize) {
    let mut line = [0u8; 200];
    let n = len.min(line.len());
    if !msg.is_null() {
        for (i, slot) in line.iter_mut().enumerate().take(n) {
            // SAFETY: the driver's own `len` bytes at `msg`.
            let b = unsafe { msg.add(i).read() };
            *slot = if (0x20..0x7F).contains(&b) { b } else { b'?' };
        }
    }
    let text = core::str::from_utf8(&line[..n]).unwrap_or("?");
    let tag = match level {
        LOG_ERROR => "error: ",
        LOG_WARN => "warning: ",
        _ => "",
    };
    // SAFETY: a lookup only.
    match unsafe { device(dev) } {
        Some((_, d)) => crate::println!("ncdri: {}: {tag}{text}", name_str(&d.name)),
        None => crate::println!("ncdri: {tag}{text}"),
    }
}

fn name_str(name: &[u8]) -> &str {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    core::str::from_utf8(&name[..end]).unwrap_or("?")
}

unsafe extern "C" fn k_driver_register(module: Handle, desc: *const DriverDesc) -> i32 {
    // SAFETY: single core; lookups and copies only.
    unsafe {
        let mods = core::ptr::addr_of_mut!(MODULES);
        let Some(m) = index_of(mods, module) else { return errno::EINVAL };
        let (base, len) = ((*mods)[m].base, (*mods)[m].len);
        let inside = |a: usize, n: usize| a >= base && a.checked_add(n).is_some_and(|e| e <= base + len);
        let at = desc as usize;
        if !inside(at, 8) {
            return errno::EFAULT;
        }
        let size = (desc as *const u32).read_unaligned() as usize;
        let take = size.min(core::mem::size_of::<DriverDesc>());
        if size < core::mem::offset_of!(DriverDesc, detach) || !inside(at, take) {
            return errno::EINVAL;
        }
        let mut d = DriverDesc::EMPTY;
        core::ptr::copy_nonoverlapping(desc as *const u8, &mut d as *mut DriverDesc as *mut u8, take);
        if d.api_major != API_MAJOR {
            return errno::ENOTSUP;
        }
        // Every method must be code of this module (or absent, but probe and
        // attach are required), and the softc of a sane size.
        let method_ok = |f: usize| f == 0 || inside(f, 1);
        let methods = [d.probe, d.attach, d.detach, d.suspend, d.resume, d.shutdown];
        if d.probe == 0 || d.attach == 0 || !methods.iter().all(|&f| method_ok(f)) || d.softc_size > 16 << 20 {
            return errno::EINVAL;
        }
        let mut name = [0u8; 12];
        let mut n = 0;
        if inside(d.name, 1) {
            while n < 11 && inside(d.name + n, 1) {
                let b = ((d.name + n) as *const u8).read();
                if !b.is_ascii_alphanumeric() && b != b'_' {
                    break;
                }
                name[n] = b;
                n += 1;
            }
        }
        if n == 0 {
            name[..3].copy_from_slice(b"drv");
        }
        let drvs = core::ptr::addr_of_mut!(DRIVERS);
        let Some(i) = free_slot(drvs) else { return errno::ENOSPC };
        (*drvs)[i] = DriverSlot { used: true, module: m, desc_addr: at, desc: d, name, units: 0 };
        errno::OK
    }
}

unsafe extern "C" fn k_driver_unregister(module: Handle, desc: *const DriverDesc) -> i32 {
    // SAFETY: single core; lookups only.
    unsafe {
        let Some(m) = index_of(core::ptr::addr_of_mut!(MODULES), module) else { return errno::EINVAL };
        let drvs = core::ptr::addr_of_mut!(DRIVERS);
        let Some(i) = (*drvs).iter().position(|s| s.used && s.module == m && s.desc_addr == desc as usize) else {
            return errno::ENOENT;
        };
        if (*core::ptr::addr_of!(DEVICES)).iter().any(|d| d.used && d.driver == i) {
            return errno::EBUSY;
        }
        (*drvs)[i] = DriverSlot::EMPTY;
        errno::OK
    }
}

unsafe extern "C" fn k_device_name(dev: Handle) -> *const u8 {
    // SAFETY: a lookup; the name lives in the pool for as long as the device.
    match unsafe { index_of(core::ptr::addr_of_mut!(DEVICES), dev) } {
        Some(i) => unsafe { (*core::ptr::addr_of!(DEVICES))[i].name.as_ptr() },
        None => b"?\0".as_ptr(),
    }
}

unsafe extern "C" fn k_device_softc(dev: Handle) -> *mut c_void {
    // SAFETY: a lookup only.
    unsafe { device(dev) }.map_or(core::ptr::null_mut(), |(_, d)| d.softc as *mut c_void)
}

unsafe extern "C" fn k_mem_alloc(size: usize, align: usize, _flags: u32, out: *mut *mut c_void) -> i32 {
    if out.is_null() || size == 0 || (align != 0 && !align.is_power_of_two()) {
        return errno::EINVAL;
    }
    // Pages, zeroed whatever the flags say: a driver never sees another
    // one's leftovers.
    match crate::palloc::alloc_zeroed(size, align.max(4096)) {
        Some(p) => {
            // SAFETY: the caller's out-pointer.
            unsafe { out.write(p as *mut c_void) };
            errno::OK
        }
        None => errno::ENOMEM,
    }
}

unsafe extern "C" fn k_mem_free(p: *mut c_void, size: usize) {
    if !p.is_null() && !crate::palloc::free(p as usize, size) {
        crate::println!("ncdri: mem_free of {p:p} ({size} bytes): not a run mem_alloc returned");
    }
}

unsafe extern "C" fn k_resource_map(dev: Handle, kind: u32, index: u32, out: *mut Handle, len: *mut u64) -> i32 {
    if out.is_null() || index > 5 {
        return errno::EINVAL;
    }
    // SAFETY: lookups, and configuration space of the driver's own device.
    unsafe {
        let Some((di, d)) = device(dev) else { return errno::EINVAL };
        let Some(p) = d.pci else { return errno::ENXIO };
        let Some(bar) = p.bar(index as u8) else { return errno::ENXIO };
        match kind {
            RES_MEMORY if !bar.io => {
                if bar.base == 0 || bar.base.checked_add(bar.size).is_none_or(|end| end > ADDRESSABLE) {
                    return errno::ENXIO;
                }
                p.enable_mmio();
            }
            RES_IOPORT if bar.io => {
                let command = p.config_read(0x04, 2).unwrap_or(0);
                p.config_write(0x04, 2, command | 1);
            }
            _ => return errno::EINVAL,
        }
        let pool = core::ptr::addr_of_mut!(RESOURCES);
        let Some(i) = free_slot(pool) else { return errno::ENOSPC };
        (*pool)[i] = Resource { used: true, device: di, io: bar.io, base: bar.base, len: bar.size };
        out.write(handle_of(pool, i));
        if !len.is_null() {
            len.write(bar.size);
        }
        errno::OK
    }
}

unsafe extern "C" fn k_resource_unmap(res: Handle) {
    // SAFETY: a lookup, then the entry is cleared.
    unsafe {
        let pool = core::ptr::addr_of_mut!(RESOURCES);
        if let Some(i) = index_of(pool, res) {
            (*pool)[i] = Resource::EMPTY;
        }
    }
}

/// Where an access of `width` bytes at `off` lands: inside the window and
/// aligned to its width, or `None`.
fn target(r: &Resource, off: u64, width: u64) -> Option<u64> {
    (off % width == 0 && off.checked_add(width).is_some_and(|e| e <= r.len)).then(|| r.base + off)
}

/// I/O ports, one width each.
///
/// # Safety
/// Ring 0; `port` is inside a window the kernel mapped for the driver.
unsafe fn in8(port: u16) -> u8 {
    let v: u8;
    // SAFETY: forwarded.
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
    v
}
unsafe fn in16(port: u16) -> u16 {
    let v: u16;
    // SAFETY: as `in8`.
    unsafe { core::arch::asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack, preserves_flags)) };
    v
}
unsafe fn in32(port: u16) -> u32 {
    let v: u32;
    // SAFETY: as `in8`.
    unsafe { core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags)) };
    v
}
unsafe fn out8(port: u16, v: u8) {
    // SAFETY: as `in8`.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) };
}
unsafe fn out16(port: u16, v: u16) {
    // SAFETY: as `in8`.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)) };
}
unsafe fn out32(port: u16, v: u32) {
    // SAFETY: as `in8`.
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)) };
}

macro_rules! accessors {
    ($read:ident, $write:ident, $t:ty, $w:expr, $inf:ident, $outf:ident) => {
        unsafe extern "C" fn $read(res: Handle, off: u64) -> $t {
            // SAFETY: a lookup; the access is bounds- and alignment-checked
            // against the window the kernel sized and mapped.
            unsafe {
                let Some(r) = resource(res) else { return <$t>::MAX };
                let Some(at) = target(&r, off, $w) else { return <$t>::MAX };
                if r.io {
                    $inf(at as u16)
                } else {
                    core::ptr::read_volatile(at as usize as *const $t)
                }
            }
        }
        unsafe extern "C" fn $write(res: Handle, off: u64, v: $t) {
            // SAFETY: as the read above.
            unsafe {
                let Some(r) = resource(res) else { return };
                let Some(at) = target(&r, off, $w) else { return };
                if r.io {
                    $outf(at as u16, v);
                } else {
                    core::ptr::write_volatile(at as usize as *mut $t, v);
                }
            }
        }
    };
}

accessors!(k_read_1, k_write_1, u8, 1, in8, out8);
accessors!(k_read_2, k_write_2, u16, 2, in16, out16);
accessors!(k_read_4, k_write_4, u32, 4, in32, out32);

unsafe extern "C" fn k_read_8(res: Handle, off: u64) -> u64 {
    // SAFETY: as the accessors above; memory windows only (no 64-bit port).
    unsafe {
        match resource(res) {
            Some(r) if !r.io => target(&r, off, 8).map_or(u64::MAX, |at| core::ptr::read_volatile(at as usize as *const u64)),
            _ => u64::MAX,
        }
    }
}

unsafe extern "C" fn k_write_8(res: Handle, off: u64, v: u64) {
    // SAFETY: as above.
    unsafe {
        if let Some(r) = resource(res) {
            if let (false, Some(at)) = (r.io, target(&r, off, 8)) {
                core::ptr::write_volatile(at as usize as *mut u64, v);
            }
        }
    }
}

unsafe extern "C" fn k_barrier(_res: Handle, _off: u64, _len: u64, _flags: u32) {
    core::sync::atomic::fence(Ordering::SeqCst);
}

unsafe extern "C" fn k_pci_cfg_read(dev: Handle, off: u32, width: u32, out: *mut u32) -> i32 {
    if out.is_null() || off > u16::MAX as u32 || width > 4 {
        return errno::EINVAL;
    }
    // SAFETY: the driver's own device's configuration space.
    unsafe {
        let Some((_, d)) = device(dev) else { return errno::EINVAL };
        let Some(p) = d.pci else { return errno::ENXIO };
        match p.config_read(off as u16, width as u8) {
            Some(v) => {
                out.write(v);
                errno::OK
            }
            None => errno::EINVAL,
        }
    }
}

unsafe extern "C" fn k_pci_cfg_write(dev: Handle, off: u32, width: u32, v: u32) -> i32 {
    if off > u16::MAX as u32 || width > 4 {
        return errno::EINVAL;
    }
    // SAFETY: as above.
    unsafe {
        let Some((_, d)) = device(dev) else { return errno::EINVAL };
        let Some(p) = d.pci else { return errno::ENXIO };
        if p.config_write(off as u16, width as u8, v) {
            errno::OK
        } else {
            errno::EINVAL
        }
    }
}

unsafe extern "C" fn k_pci_enable_busmaster(dev: Handle, on: i32) -> i32 {
    // SAFETY: as above. The boot-time lockdown took bus mastering from every
    // device the kernel does not drive; a driver that drives one may give it
    // back, and the log says so.
    unsafe {
        let Some((_, d)) = device(dev) else { return errno::EINVAL };
        let Some(p) = d.pci else { return errno::ENXIO };
        let command = p.config_read(0x04, 2).unwrap_or(0);
        let next = if on != 0 { command | (1 << 2) } else { command & !(1 << 2) };
        if next != command {
            p.config_write(0x04, 2, next);
            if on != 0 {
                crate::println!("ncdri: {}: bus mastering on, at its driver's request", name_str(&d.name));
            }
        }
        errno::OK
    }
}

unsafe extern "C" fn k_dma_alloc(dev: Handle, size: usize, align: usize, boundary: u64, _flags: u32, out: *mut Handle) -> i32 {
    if out.is_null() || size == 0 || (align != 0 && !align.is_power_of_two()) {
        return errno::EINVAL;
    }
    // A run that may not cross `boundary`: aligned to it, and no longer.
    let mut align = align.max(4096);
    if boundary != 0 {
        if !boundary.is_power_of_two() || size as u64 > boundary {
            return errno::EINVAL;
        }
        align = align.max(boundary as usize);
    }
    // SAFETY: a lookup, then a new entry.
    unsafe {
        let Some((di, _)) = device(dev) else { return errno::EINVAL };
        let pool = core::ptr::addr_of_mut!(DMAS);
        let Some(i) = free_slot(pool) else { return errno::ENOSPC };
        // Below the cached ceiling (1 GiB): inside every DMA mask, and
        // coherent — x86 snoops device accesses to write-back memory.
        let Some(addr) = crate::palloc::alloc_zeroed(size, align) else { return errno::ENOMEM };
        (*pool)[i] = Dma { used: true, device: di, addr, len: size };
        out.write(handle_of(pool, i));
        errno::OK
    }
}

unsafe extern "C" fn k_dma_free(dma: Handle) {
    // SAFETY: a lookup, then the entry and its run go.
    unsafe {
        let pool = core::ptr::addr_of_mut!(DMAS);
        if let Some(i) = index_of(pool, dma) {
            let d = (*pool)[i];
            crate::palloc::free(d.addr, d.len);
            (*pool)[i] = Dma::EMPTY;
        }
    }
}

unsafe extern "C" fn k_dma_kva(dma: Handle) -> *mut c_void {
    // SAFETY: a lookup only.
    unsafe {
        let pool = core::ptr::addr_of_mut!(DMAS);
        index_of(pool, dma).map_or(core::ptr::null_mut(), |i| (*pool)[i].addr as *mut c_void)
    }
}

unsafe extern "C" fn k_dma_bus_addr(dma: Handle) -> u64 {
    // Identity-mapped, no IOMMU programmed: the bus address is the physical
    // one, which is the virtual one.
    // SAFETY: a lookup only.
    unsafe { k_dma_kva(dma) as u64 }
}

unsafe extern "C" fn k_dma_sync(_dma: Handle, _off: usize, _len: usize, _ops: u32) {
    core::sync::atomic::fence(Ordering::SeqCst);
}

unsafe extern "C" fn k_irq_establish(_dev: Handle, _index: u32, _f: usize, _arg: *mut c_void, out: *mut Handle) -> i32 {
    if !out.is_null() {
        // SAFETY: the caller's out-pointer.
        unsafe { out.write(core::ptr::null_mut()) };
    }
    // The kernel runs with interrupts masked; none is delivered to a driver
    // yet. A driver polls, or does without.
    errno::ENOTSUP
}

unsafe extern "C" fn k_irq_disestablish(_irq: Handle) {}

unsafe extern "C" fn k_mtx_init(out: *mut Handle, kind: u32, _name: *const u8) -> i32 {
    if out.is_null() || (kind != MTX_SPIN && kind != MTX_SLEEP) {
        return errno::EINVAL;
    }
    // SAFETY: a new entry.
    unsafe {
        let pool = core::ptr::addr_of_mut!(MTXS);
        let Some(i) = free_slot(pool) else { return errno::ENOSPC };
        (*pool)[i] = Mtx { used: true, held: false };
        out.write(handle_of(pool, i));
    }
    errno::OK
}

unsafe extern "C" fn k_mtx_enter(m: Handle) {
    // One core, interrupts masked: a lock is never contended. Taking one
    // twice is a deadlock on any machine; here it is reported instead.
    // SAFETY: a lookup, then the entry.
    unsafe {
        let pool = core::ptr::addr_of_mut!(MTXS);
        if let Some(i) = index_of(pool, m) {
            if (*pool)[i].held {
                crate::println!("ncdri: warning: a lock taken while held (a deadlock with more than one core)");
            }
            (*pool)[i].held = true;
        }
    }
}

unsafe extern "C" fn k_mtx_tryenter(m: Handle) -> i32 {
    // SAFETY: as above.
    unsafe {
        let pool = core::ptr::addr_of_mut!(MTXS);
        match index_of(pool, m) {
            Some(i) if !(*pool)[i].held => {
                (*pool)[i].held = true;
                1
            }
            _ => 0,
        }
    }
}

unsafe extern "C" fn k_mtx_exit(m: Handle) {
    // SAFETY: as above.
    unsafe {
        let pool = core::ptr::addr_of_mut!(MTXS);
        if let Some(i) = index_of(pool, m) {
            (*pool)[i].held = false;
        }
    }
}

unsafe extern "C" fn k_mtx_destroy(m: Handle) {
    // SAFETY: as above.
    unsafe {
        let pool = core::ptr::addr_of_mut!(MTXS);
        if let Some(i) = index_of(pool, m) {
            (*pool)[i] = Mtx::EMPTY;
        }
    }
}

unsafe extern "C" fn k_time_ns() -> u64 {
    // SAFETY: written once, before any driver runs.
    let Some(cal) = (unsafe { *core::ptr::addr_of!(CALIBRATION) }) else { return 0 };
    cal.ticks_to_ns(crate::arch::counter_ordered().wrapping_sub(TIME_ORIGIN.load(Ordering::Relaxed)))
}

unsafe extern "C" fn k_delay_ns(ns: u64) {
    // SAFETY: as above.
    let Some(cal) = (unsafe { *core::ptr::addr_of!(CALIBRATION) }) else { return };
    // Ten seconds at most: a busy wait longer than that is a bug.
    let until = crate::arch::counter_ordered().wrapping_add(cal.ns_to_ticks(ns.min(10_000_000_000)));
    while (crate::arch::counter_ordered().wrapping_sub(until) as i64) < 0 {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn k_fpu_alloc(out: *mut Handle) -> i32 {
    if !out.is_null() {
        // SAFETY: the caller's out-pointer.
        unsafe { out.write(core::ptr::null_mut()) };
    }
    errno::ENOTSUP
}

unsafe extern "C" fn k_fpu_free(_ctx: Handle) {}

/// What `fpu_begin(NULL, NCDRI_FPU_NOCTX)` saved: the two callee-saved
/// controls, MXCSR and the x87 control word. The vector registers are
/// caller-saved in the SysV ABI every call into a driver follows.
static mut FPU_SAVED: Option<(u32, u16)> = None;

unsafe extern "C" fn k_fpu_begin(ctx: Handle, flags: u32) {
    if ctx.is_null() && flags & FPU_NOCTX != 0 {
        let (mut mxcsr, mut fcw) = (0u32, 0u16);
        // SAFETY: stores the current controls; ring 0, SSE enabled at boot.
        unsafe {
            core::arch::asm!("stmxcsr [{m}]", "fnstcw [{c}]", m = in(reg) &mut mxcsr, c = in(reg) &mut fcw,
                             options(nostack, preserves_flags));
            *core::ptr::addr_of_mut!(FPU_SAVED) = Some((mxcsr, fcw));
        }
    }
}

unsafe extern "C" fn k_fpu_end(_ctx: Handle) {
    // SAFETY: restores what fpu_begin saved, if it saved anything.
    unsafe {
        if let Some((mxcsr, fcw)) = (*core::ptr::addr_of_mut!(FPU_SAVED)).take() {
            core::arch::asm!("ldmxcsr [{m}]", "fldcw [{c}]", m = in(reg) &mxcsr, c = in(reg) &fcw,
                             options(nostack, preserves_flags));
        }
    }
}

unsafe extern "C" fn k_memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // SAFETY: the driver's own buffers; `copy` tolerates overlap.
    unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, n) };
    dst
}

unsafe extern "C" fn k_memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
    // SAFETY: the driver's own buffer.
    unsafe { core::ptr::write_bytes(dst as *mut u8, c as u8, n) };
    dst
}

unsafe extern "C" fn k_memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: the driver's own buffers.
        let (x, y) = unsafe { ((a as *const u8).add(i).read(), (b as *const u8).add(i).read()) };
        if x != y {
            return x as i32 - y as i32;
        }
    }
    0
}

unsafe extern "C" fn k_rng_fill(buf: *mut c_void, len: usize, flags: u32) -> i32 {
    if buf.is_null() || len > crate::rng::NC_RNG_MAX_FILL {
        return errno::EINVAL;
    }
    // SAFETY: the driver's own buffer.
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
    match crate::rng::fill(out, nanochrono_core::rng::Mode::from_flags(flags)) {
        Ok(n) if n == len => errno::OK,
        _ => errno::EAGAIN,
    }
}

/// The monitor a display driver named, for the boot log.
#[derive(Debug, Clone, Copy)]
pub struct Monitor {
    pub maker: [u8; 3],
    pub name: [u8; 13],
    pub native: Option<(u32, u32, u32)>,
}

impl Monitor {
    pub fn name(&self) -> &str {
        name_str(&self.name)
    }

    pub fn maker(&self) -> &str {
        core::str::from_utf8(&self.maker).unwrap_or("???")
    }
}

/// The scanout a display driver handed over, waiting for `kmain` to adopt.
#[derive(Clone, Copy)]
struct Pending {
    fb: Framebuffer,
    device: [u8; 16],
    monitor: Option<Monitor>,
}

static mut PENDING: Option<Pending> = None;

/// The most EDID a driver may pass: the base block and seven extensions
/// (QEMU's window is exactly this; a monitor rarely sends more than four).
const EDID_MAX: usize = 1024;

/// Copies a driver's EDID out of its memory and parses it.
///
/// # Safety
/// `edid` is the driver's `len` bytes, or null.
unsafe fn read_edid(edid: *const u8, len: usize, copy: &mut [u8; EDID_MAX]) -> Option<nanochrono_core::edid::Edid<'_>> {
    if edid.is_null() || len < nanochrono_core::edid::BLOCK_LEN {
        return None;
    }
    let n = len.min(copy.len());
    // SAFETY: forwarded from this function's own contract.
    unsafe { core::ptr::copy_nonoverlapping(edid, copy.as_mut_ptr(), n) };
    nanochrono_core::edid::Edid::parse(&copy[..n]).ok()
}

unsafe extern "C" fn k_display_scanout(dev: Handle, s: *const Scanout, edid: *const u8, edid_len: usize) -> i32 {
    if s.is_null() {
        return errno::EINVAL;
    }
    // SAFETY: lookups, the driver's own structure (read to the size it
    // declares), and configuration space of its own device.
    unsafe {
        let Some((_, d)) = device(dev) else { return errno::EINVAL };
        let Some(p) = d.pci else { return errno::ENXIO };
        let size = (s as *const u32).read_unaligned();
        if size < SCANOUT_MIN {
            return errno::EINVAL;
        }
        let mut sc = Scanout { size: 0, res_index: 0, offset: 0, width: 0, height: 0, pitch: 0, format: 0, reserved: [0; 6] };
        let take = (size as usize).min(core::mem::size_of::<Scanout>());
        core::ptr::copy_nonoverlapping(s as *const u8, &mut sc as *mut Scanout as *mut u8, take);
        if sc.format != FORMAT_XRGB8888 || sc.res_index > 5 {
            return errno::EINVAL;
        }
        if !(320..=16384).contains(&sc.width) || !(200..=16384).contains(&sc.height) {
            return errno::EINVAL;
        }
        // Rows of whole pixels, and a surface whose every offset fits the
        // 32-bit arithmetic the drawing code does.
        let span = sc.pitch as u64 * sc.height as u64;
        if sc.pitch < sc.width * 4 || sc.pitch % 4 != 0 || span > u32::MAX as u64 {
            return errno::EINVAL;
        }
        let Some(bar) = p.bar(sc.res_index as u8) else { return errno::ENXIO };
        let fits = sc.offset.checked_add(span).is_some_and(|end| end <= bar.size);
        let top = bar.base.checked_add(bar.size).is_some_and(|end| end <= ADDRESSABLE);
        if bar.io || bar.base == 0 || !fits || !top {
            return errno::EFAULT;
        }
        let fb = Framebuffer::new((bar.base + sc.offset) as usize as *mut u8, sc.width, sc.height, sc.pitch, 32);
        if !fb.is_usable() {
            return errno::EINVAL;
        }
        let mut copy = [0u8; EDID_MAX];
        let monitor = read_edid(edid, edid_len, &mut copy).map(|e| {
            let mut name = [0u8; 13];
            if let Some(n) = e.name() {
                let n = n.as_bytes();
                name[..n.len().min(12)].copy_from_slice(&n[..n.len().min(12)]);
            }
            Monitor {
                maker: e.manufacturer(),
                name,
                native: e.preferred().map(|t| (t.width, t.height, t.refresh_mhz)),
            }
        });
        *core::ptr::addr_of_mut!(PENDING) = Some(Pending { fb, device: d.name, monitor });
        errno::OK
    }
}

unsafe extern "C" fn k_edid_preferred(edid: *const u8, len: usize, w: *mut u32, h: *mut u32, hz: *mut u32) -> i32 {
    let mut copy = [0u8; EDID_MAX];
    // SAFETY: the driver's `len` bytes.
    let Some(e) = (unsafe { read_edid(edid, len, &mut copy) }) else { return errno::EINVAL };
    let Some(t) = e.preferred() else { return errno::ENOENT };
    // SAFETY: the caller's out-pointers, each optional.
    unsafe {
        if !w.is_null() {
            w.write(t.width);
        }
        if !h.is_null() {
            h.write(t.height);
        }
        if !hz.is_null() {
            hz.write(t.refresh_mhz);
        }
    }
    errno::OK
}

/// The table one module is handed: every service, its own `self`.
fn table(module: Handle) -> Api {
    Api {
        size: core::mem::size_of::<Api>() as u32,
        api_major: API_MAJOR,
        api_minor: API_MINOR,
        kernel_version: KERNEL_VERSION.as_ptr(),
        self_: module,
        driver_register: k_driver_register,
        driver_unregister: k_driver_unregister,
        device_name: k_device_name,
        device_softc: k_device_softc,
        log: k_log,
        mem_alloc: k_mem_alloc,
        mem_free: k_mem_free,
        resource_map: k_resource_map,
        resource_unmap: k_resource_unmap,
        read_1: k_read_1,
        read_2: k_read_2,
        read_4: k_read_4,
        read_8: k_read_8,
        write_1: k_write_1,
        write_2: k_write_2,
        write_4: k_write_4,
        write_8: k_write_8,
        barrier: k_barrier,
        pci_cfg_read: k_pci_cfg_read,
        pci_cfg_write: k_pci_cfg_write,
        pci_enable_busmaster: k_pci_enable_busmaster,
        dma_alloc: k_dma_alloc,
        dma_free: k_dma_free,
        dma_kva: k_dma_kva,
        dma_bus_addr: k_dma_bus_addr,
        dma_sync: k_dma_sync,
        irq_establish: k_irq_establish,
        irq_disestablish: k_irq_disestablish,
        mtx_init: k_mtx_init,
        mtx_enter: k_mtx_enter,
        mtx_tryenter: k_mtx_tryenter,
        mtx_exit: k_mtx_exit,
        mtx_destroy: k_mtx_destroy,
        time_ns: k_time_ns,
        delay_ns: k_delay_ns,
        fpu_alloc: k_fpu_alloc,
        fpu_free: k_fpu_free,
        fpu_begin: k_fpu_begin,
        fpu_end: k_fpu_end,
        memcpy: k_memcpy,
        memset: k_memset,
        memcmp: k_memcmp,
        rng_fill: k_rng_fill,
        display_scanout: k_display_scanout,
        edid_preferred: k_edid_preferred,
        reserved: [0; 30],
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// What the boot-time load did.
#[derive(Default)]
pub struct Outcome {
    /// `.ncdri` modules among the boot modules.
    pub found: u32,
    pub loaded: u32,
    pub refused: u32,
    /// Devices a driver attached to.
    pub attached: u32,
    /// The screen a display driver set up, if one did: the session draws
    /// there instead of on the firmware's framebuffer.
    pub screen: Option<Framebuffer>,
    /// The driver that set it up, and the monitor it names.
    pub screen_device: [u8; 16],
    pub monitor: Option<Monitor>,
}

impl Outcome {
    pub fn screen_device(&self) -> &str {
        name_str(&self.screen_device)
    }
}

/// Why a module was not loaded.
#[derive(Debug, Clone, Copy)]
enum Refusal {
    Load(LoadError),
    NotDriver,
    Untrusted,
    Imports,
    NoMemory,
    NoSlot,
    Main(i32),
}

impl Refusal {
    fn message(self) -> &'static str {
        match self {
            Refusal::Load(e) => e.message(),
            Refusal::NotDriver => "not a driver module",
            Refusal::Untrusted => {
                "a ring-0 driver must be signed for ring 0; ncdri.community=on allows an unsigned one for this boot"
            }
            Refusal::Imports => "imports a kernel symbol (a driver may import only the stack-canary pair)",
            Refusal::NoMemory => "no memory for it",
            Refusal::NoSlot => "too many modules",
            Refusal::Main(_) => "its ncdri_main failed",
        }
    }
}

/// Loads every `.ncdri` among the boot modules and attaches its drivers.
///
/// # Safety
/// Once, at boot, in ring 0, after the modules are recorded
/// (`crate::boot`) and the page allocator is up, before the session.
pub unsafe fn load_boot_drivers() -> Outcome {
    let mut out = Outcome::default();
    let community = crate::boot::flag("ncdri.community");
    for m in crate::boot::modules() {
        let path = m.name.split_ascii_whitespace().next().unwrap_or("");
        if !path.to_ascii_lowercase_ends_with(".ncdri") {
            continue;
        }
        out.found += 1;
        if out.found == 1 {
            // SAFETY: ring 0; the PIT is free at this point of the boot.
            unsafe { start_clock() };
        }
        // SAFETY: a module the loader reported; forwarded contract.
        match unsafe { load(path, m.bytes(), community) } {
            Ok(()) => out.loaded += 1,
            Err(Refusal::Main(e)) => {
                crate::println!("ncdri: {path}: refused: {} ({}, {e})", Refusal::Main(e).message(), errno_name(e));
                out.refused += 1;
            }
            Err(why) => {
                crate::println!("ncdri: {path}: refused: {}", why.message());
                out.refused += 1;
            }
        }
    }
    if out.loaded > 0 {
        // SAFETY: forwarded.
        out.attached = unsafe { attach_devices() };
    }
    // SAFETY: single core; the drivers have returned.
    if let Some(p) = unsafe { (*core::ptr::addr_of_mut!(PENDING)).take() } {
        out.screen = Some(p.fb);
        out.screen_device = p.device;
        out.monitor = p.monitor;
    }
    out
}

/// Ends-with, ASCII case folded, without allocating.
trait EndsWithFolded {
    fn to_ascii_lowercase_ends_with(&self, suffix: &str) -> bool;
}

impl EndsWithFolded for str {
    fn to_ascii_lowercase_ends_with(&self, suffix: &str) -> bool {
        self.len() >= suffix.len() && self.as_bytes()[self.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
    }
}

/// The drivers' time base and their stack canary, once.
///
/// # Safety
/// Ring 0; drives the PIT in the calibration fallback.
unsafe fn start_clock() {
    // SAFETY: forwarded.
    let cal = unsafe { crate::clock::Calibration::measure() };
    // SAFETY: once, before any driver runs.
    unsafe { *core::ptr::addr_of_mut!(CALIBRATION) = Some(cal) };
    TIME_ORIGIN.store(crate::arch::counter_ordered(), Ordering::Relaxed);
    let mut guard = [0u8; 8];
    let seeded = crate::rng::fill(&mut guard, nanochrono_core::rng::Mode::Fast).is_ok();
    let mut value = u64::from_le_bytes(guard);
    if !seeded || value == 0 {
        // No pool yet: the counter, mixed. Weaker, never constant.
        value = crate::arch::counter_ordered().wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    }
    // A zero low byte, as glibc's: a string copy that runs into the canary
    // stops there instead of reading past it.
    DRIVER_STACK_GUARD.store(value & !0xFF, Ordering::Relaxed);
}

/// Loads one module.
///
/// # Safety
/// As [`load_boot_drivers`]; `bytes` is the module's.
unsafe fn load(path: &str, bytes: &[u8], community: bool) -> Result<(), Refusal> {
    // SAFETY: forwarded; nothing is running that the checks could disturb.
    let insp = unsafe { crate::ncplu::inspect(bytes) }.map_err(Refusal::Load)?;
    let image = insp.image();
    if image.kind() != Kind::Driver {
        return Err(Refusal::NotDriver);
    }
    let trusted = insp.tier.runs_in_kernel();
    if !trusted && !community {
        crate::println!("ncdri: {path}: {} ({})", insp.tier.label(), insp.signature.describe());
        return Err(Refusal::Untrusted);
    }
    for i in 0..image.import_count() {
        let name = image.import_name(i).map_err(|e| Refusal::Load(LoadError::Format(e)))?;
        if name != b"__stack_chk_guard" && name != b"__stack_chk_fail" {
            return Err(Refusal::Imports);
        }
    }
    // SAFETY: single core; a new entry.
    let mods = core::ptr::addr_of_mut!(MODULES);
    let Some(m) = (unsafe { free_slot(mods) }) else { return Err(Refusal::NoSlot) };
    let len = image.arena_size.max(1);
    let base = crate::palloc::alloc_zeroed(len, 4096).ok_or(Refusal::NoMemory)?;
    // SAFETY: the run was just handed out; nothing else refers to it.
    let arena = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
    let placed = copy_and_relocate(image, arena, base as u64, &mut |name| match name {
        b"__stack_chk_guard" => Ok(DRIVER_STACK_GUARD.as_ptr() as u64),
        b"__stack_chk_fail" => Ok(driver_stack_chk_fail as *const () as u64),
        _ => Err(LoadError::UnresolvedImport),
    });
    if let Err(e) = placed {
        crate::palloc::free(base, len);
        return Err(Refusal::Load(e));
    }
    let handle = handle_of(mods, m);
    // SAFETY: the new entry; its table never moves (the pool is a static).
    let api: *const Api = unsafe {
        (*mods)[m] = Module { used: true, base, len, api: Some(table(handle)) };
        (*mods)[m].api.as_ref().expect("just set")
    };
    let tier = if trusted { insp.tier.label() } else { "community, by the owner's switch (ncdri.community=on)" };
    crate::println!("ncdri: {path}: {} KiB, {tier}; entering ncdri_main", len.div_ceil(1024));

    // SAFETY: the entry was validated by the format check to lie inside the
    // image, now placed and relocated at `base`; the ABI is the C one.
    let rc = unsafe {
        let main: unsafe extern "C" fn(*const Api, u32) -> i32 = core::mem::transmute(base + image.entry);
        main(api, core::mem::size_of::<Api>() as u32)
    };
    if rc != errno::OK {
        // SAFETY: single core; its drivers go, then its memory.
        unsafe {
            for s in (*core::ptr::addr_of_mut!(DRIVERS)).iter_mut() {
                if s.used && s.module == m {
                    *s = DriverSlot::EMPTY;
                }
            }
            (*mods)[m] = Module::EMPTY;
        }
        crate::palloc::free(base, len);
        return Err(Refusal::Main(rc));
    }
    Ok(())
}

/// Offers every PCI device the kernel does not drive itself to every
/// registered driver; the best offer attaches. Returns how many attached.
///
/// # Safety
/// As [`load_boot_drivers`].
unsafe fn attach_devices() -> u32 {
    let mut found: [Option<pci::Device>; 128] = [None; 128];
    let mut n = 0;
    // SAFETY: ring 0; the list is taken first so no driver runs mid-walk.
    unsafe {
        pci::scan(|d| {
            if n < found.len() {
                found[n] = Some(d);
                n += 1;
            }
            true
        });
    }
    let mut attached = 0;
    for p in found[..n].iter().flatten() {
        // The kernel's own: the bridges, and the USB host controllers its
        // input and storage stacks drive.
        if p.header_type != 0 || p.usb_kind().is_some() {
            continue;
        }
        // SAFETY: forwarded.
        if unsafe { offer(*p) } {
            attached += 1;
        }
    }
    attached
}

/// Offers one device; `true` when a driver attached.
///
/// # Safety
/// As [`load_boot_drivers`].
unsafe fn offer(p: pci::Device) -> bool {
    // SAFETY: single core; the device's own configuration space.
    unsafe {
        let devs = core::ptr::addr_of_mut!(DEVICES);
        let Some(di) = free_slot(devs) else { return false };
        (*devs)[di] = Device { used: true, pci: Some(p), ..Device::EMPTY };
        let handle = handle_of(devs, di);
        let subsys = p.config_read(0x2C, 4).unwrap_or(0);
        let revision = p.config_read(0x08, 1).unwrap_or(0) as u8;
        let info = DevInfo {
            size: core::mem::size_of::<DevInfo>() as u32,
            bus: BUS_PCI,
            vendor: p.vendor,
            device: p.device,
            subvendor: subsys as u16,
            subdevice: (subsys >> 16) as u16,
            class_code: p.class,
            subclass: p.subclass,
            progif: p.prog_if,
            revision,
            hid: [0; 32],
            reserved: [0; 8],
        };
        let drvs = core::ptr::addr_of_mut!(DRIVERS);
        let mut best: Option<(usize, i32)> = None;
        for i in 0..MAX_DRIVERS {
            // A copy: no borrow of the table lives across the driver's code.
            let s = (*drvs)[i];
            if !s.used {
                continue;
            }
            let probe: unsafe extern "C" fn(Handle, *const DevInfo) -> i32 = core::mem::transmute(s.desc.probe);
            let rc = probe(handle, &info);
            if rc <= 0 && best.is_none_or(|(_, b)| rc > b) {
                best = Some((i, rc));
            }
        }
        let Some((i, _)) = best else {
            (*devs)[di] = Device::EMPTY;
            return false;
        };
        let desc = (*drvs)[i].desc;
        let softc_len = desc.softc_size;
        let softc = if softc_len > 0 {
            let Some(addr) = crate::palloc::alloc_zeroed(softc_len, 4096) else {
                crate::println!("ncdri: no memory for a softc of {softc_len} bytes");
                (*devs)[di] = Device::EMPTY;
                return false;
            };
            addr
        } else {
            0
        };
        // `<name><unit>`: stdvga0, stdvga1, …
        let unit = (*drvs)[i].units;
        (*drvs)[i].units += 1;
        let mut name = [0u8; 16];
        let base = name_str(&(*drvs)[i].name);
        let mut t = crate::text::Text::<16>::new();
        t.str(base).num(unit as u64);
        let t = t.as_str().as_bytes();
        name[..t.len().min(15)].copy_from_slice(&t[..t.len().min(15)]);
        (*devs)[di] = Device { used: true, attached: false, pci: Some(p), driver: i, softc, softc_len, name };

        let attach: unsafe extern "C" fn(Handle, *mut c_void) -> i32 = core::mem::transmute(desc.attach);
        let rc = attach(handle, softc as *mut c_void);
        if rc != errno::OK {
            crate::println!(
                "ncdri: {}: attach failed ({}, {rc}) at PCI {:02x}:{:02x}.{} ({:04x}:{:04x})",
                name_str(&name), errno_name(rc), p.bus, p.slot, p.function, p.vendor, p.device
            );
            release(di);
            return false;
        }
        (*devs)[di].attached = true;
        crate::println!(
            "ncdri: {}: attached at PCI {:02x}:{:02x}.{} ({:04x}:{:04x})",
            name_str(&name), p.bus, p.slot, p.function, p.vendor, p.device
        );
        true
    }
}

/// Takes back everything a device holds — what a failed `attach` left
/// behind (a driver should undo its own steps; this is the net under it):
/// its windows, its DMA memory, its softc, and the device entry itself.
///
/// # Safety
/// Single core; no driver code is running for the device.
unsafe fn release(di: usize) {
    // SAFETY: forwarded; every pool is a static only this file touches.
    unsafe {
        for r in (*core::ptr::addr_of_mut!(RESOURCES)).iter_mut() {
            if r.used && r.device == di {
                *r = Resource::EMPTY;
            }
        }
        for d in (*core::ptr::addr_of_mut!(DMAS)).iter_mut() {
            if d.used && d.device == di {
                crate::palloc::free(d.addr, d.len);
                *d = Dma::EMPTY;
            }
        }
        let dev = &mut (*core::ptr::addr_of_mut!(DEVICES))[di];
        if dev.softc != 0 {
            crate::palloc::free(dev.softc, dev.softc_len);
        }
        *dev = Device::EMPTY;
    }
}

/// The name of an errno a driver returned, for the log.
const fn errno_name(e: i32) -> &'static str {
    match e {
        errno::OK => "ok",
        errno::ENOENT => "ENOENT",
        errno::EIO => "EIO",
        errno::ENXIO => "ENXIO",
        errno::ENOMEM => "ENOMEM",
        errno::EFAULT => "EFAULT",
        errno::EBUSY => "EBUSY",
        errno::EINVAL => "EINVAL",
        errno::ENOSPC => "ENOSPC",
        errno::EAGAIN => "EAGAIN",
        errno::ENOTSUP => "ENOTSUP",
        _ => "errno",
    }
}
