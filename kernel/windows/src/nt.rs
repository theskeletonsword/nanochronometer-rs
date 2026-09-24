// SPDX-License-Identifier: MIT

//! FFI surface of the Windows kernel ABI (WDM) that the driver uses, plus the
//! struct mirrors and verified offsets.
//!
//! Every numeric offset in this file was cross-checked by compiling
//! `defs/offsets-check.c` against the toolchain headers for **both** x86_64
//! and ARM64 (the Makefile runs that check before linking). The layout
//! asserted below at compile time is therefore grounded in the actual
//! compiler, not in memory.
//!
//! Notable finding, and a trap: the mingw-w64 `wdm.h` wraps
//! `IO_STACK_LOCATION` in `pshpack4.h` on every target that is not `_AMD64_`
//! or `_IA64_` — a leftover from x86-32 — so compiled for ARM64 it reports the
//! `DeviceIoControl` block at 4/8/12/16. The Microsoft WDK excludes ARM64
//! from that packing too, and `POINTER_ALIGNMENT` is `DECLSPEC_ALIGN(8)` on
//! every `_WIN64` target, so on real ARM64 Windows the block sits at
//! 8/16/24/32 exactly as on x64. Reading the packed offsets there takes the
//! IOCTL code and the buffer lengths from padding. See `defs/offsets-check.c`.

use core::ffi::{c_char, c_int, c_void};
use core::mem::offset_of;

pub type NTSTATUS = c_int;

pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023u32 as i32;
pub const STATUS_INVALID_DEVICE_REQUEST: NTSTATUS = 0xC000_0010u32 as i32;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000Du32 as i32;
pub const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022u32 as i32;

/// `KPROCESSOR_MODE`: the caller came from kernel mode.
pub const KERNEL_MODE: i8 = 0;
/// Maps to `ERROR_BUSY` in user mode: a re-probe inside the cooldown.
pub const STATUS_DEVICE_BUSY: NTSTATUS = 0x8000_0011u32 as i32;

pub const IRP_MJ_CREATE: usize = 0x00;
pub const IRP_MJ_CLOSE: usize = 0x02;
pub const IRP_MJ_DEVICE_CONTROL: usize = 0x0E;

/// `DO_DEVICE_INITIALIZING` in `DEVICE_OBJECT.Flags`.
pub const DO_DEVICE_INITIALIZING: u32 = 0x0000_0080;

/// `FILE_DEVICE_UNKNOWN`.
pub const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;

/// `FILE_DEVICE_SECURE_OPEN`.
pub const FILE_DEVICE_SECURE_OPEN: u32 = 0x0000_0100;

/// `NonPagedPoolNx` (POOL_TYPE).
pub const POOL_NON_PAGED_NX: u32 = 512;

/// `MmNonCached` cache type for `MmMapIoSpace`.
pub const MM_NON_CACHED: u32 = 2;

/// Pool tag `'Nano'` (little-endian u32).
pub const POOL_TAG: u32 = u32::from_le_bytes(*b"Nano");

// ---------------------------------------------------------------------------
// Struct mirrors with compile-time offset assertions
// ---------------------------------------------------------------------------

/// LARGE_INTEGER as exported by the kernel ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LargeInteger {
    pub quad_part: i64,
}

/// `UNICODE_STRING` (`ntdef.h`): u16 length, u16 max length, wchar_t*.
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

/// IO_STATUS_BLOCK (`wdm.h`): NTSTATUS + ULONG_PTR.
#[repr(C)]
pub struct IoStatusBlock {
    pub status: NTSTATUS,
    pub information: usize,
}

/// The `Tail.Overlay` anonymous struct inside `_IRP`, which carries
/// `CurrentStackLocation` (that is what `IoGetCurrentIrpStackLocation` reads).
#[repr(C)]
pub struct IrpTailOverlay {
    /// union { KDEVICE_QUEUE_ENTRY; PVOID DriverContext[4]; } — 32 bytes.
    _start: [u8; 32],
    thread: *mut c_void,
    auxiliary_buffer: *mut c_void,
    list_entry: [usize; 2],
    pub current_stack_location: *mut c_void,
    original_file_object: *mut c_void,
}

/// The few `_IRP` fields a METHOD_BUFFERED driver touches.
///
/// Layout is `repr(C)`; the two assertions at the bottom certify that the
/// mirrors line up with the C compiler (the C check in the Makefile certifies
/// the compiler line against the header expectations).
#[repr(C)]
pub struct Irp {
    typ: u16,
    size: u16,
    mdl_address: *mut c_void,
    flags: u32,
    /// `AssociatedIrp.SystemBuffer` for METHOD_BUFFERED.
    pub associated_irp: usize,
    thread_list_entry: [usize; 2],
    io_status: IoStatusBlock,
    /// RequestorMode..AllocationFlags (8 × UCHAR).
    _meta: [u8; 8],
    user_iosb: *mut c_void,
    user_event: *mut c_void,
    /// Overlay union (AsynchronousParameters | AllocationSize).
    _overlay: [usize; 2],
    cancel_routine: *mut c_void,
    pub user_buffer: *mut c_void,
    pub tail: IrpTailOverlay,
}

impl Irp {
    /// `&mut IRP.IoStatus` (offset 48).
    pub fn io_status(&mut self) -> *mut IoStatusBlock {
        core::ptr::addr_of_mut!(self.io_status)
    }
}

/// `_DRIVER_OBJECT` — only the fields this driver reads or writes.
#[repr(C)]
pub struct DriverObject {
    pub typ: u16,
    pub size: u16,
    pub device_object: *mut c_void,
    pub flags: u32,
    pub driver_start: *mut c_void,
    pub driver_size: u32,
    pub driver_section: *mut c_void,
    pub driver_extension: *mut c_void,
    pub driver_name: UnicodeString,
    pub hardware_database: *mut c_void,
    pub fast_io_dispatch: *mut c_void,
    pub driver_init: *mut c_void,
    pub driver_start_io: *mut c_void,
    pub driver_unload: Option<unsafe extern "system" fn(*mut c_void) -> ()>,
    pub major_function: [Option<unsafe extern "system" fn(*mut c_void, *mut Irp) -> NTSTATUS>; 28],
}

/// `_DEVICE_OBJECT` — first fields, up to `Flags` (48) and `DeviceExtension`
/// (64), which are the only ones the driver touches.
#[repr(C)]
pub struct DeviceObject {
    pub typ: u16,
    pub size: u16,
    pub reference_count: i32,
    pub driver_object: *mut c_void,
    pub next_device: *mut c_void,
    pub attached_device: *mut c_void,
    pub current_irp: *mut c_void,
    pub timer: *mut c_void,
    pub flags: u32,
    pub characteristics: u32,
    pub vpb: *mut c_void,
    pub device_extension: *mut c_void,
}

// ---------------------------------------------------------------------------
// IO_STACK_LOCATION parameter offsets, verified per architecture.
// `Parameters.DeviceIoControl` { OutputBufferLength, _pad, InputBufferLength,
// _pad, IoControlCode, _pad, Type3InputBuffer }.
// ---------------------------------------------------------------------------

/// Offset of `Parameters.DeviceIoControl.OutputBufferLength` in the current
/// stack location. The same on x86_64 and ARM64: see the module docs for why
/// the mingw headers say otherwise.
pub const ISL_OUTPUT_BUFFER_LENGTH: usize = 8;
/// Offset of `Parameters.DeviceIoControl.IoControlCode`.
pub const ISL_IO_CONTROL_CODE: usize = 24;
/// Offset of `Parameters.DeviceIoControl.InputBufferLength`.
pub const ISL_INPUT_BUFFER_LENGTH: usize = 16;
/// Offset of `Parameters.DeviceIoControl.Type3InputBuffer`. Documented for
/// completeness; the driver currently only reads the length and the ioctl
/// code. Kept asserted (see offsets-check.c) so it cannot rot.
#[allow(dead_code)]
pub const ISL_TYPE3_INPUT: usize = 32;

/// `IRP.AssociatedIrp.SystemBuffer` offset (both architectures).
pub const IRP_SYSTEM_BUFFER: usize = 24;
/// Offset of `IRP.Tail.Overlay.CurrentStackLocation` (both architectures).
pub const IRP_CURRENT_STACK_LOCATION: usize = 184;

// ---------------------------------------------------------------------------
// Compile-time certification of the offsets above.
// ---------------------------------------------------------------------------

const _: () = {
    assert!(size_of::<UnicodeString>() == 16);
    assert!(size_of::<IoStatusBlock>() == 16);
    assert!(offset_of!(Irp, associated_irp) == IRP_SYSTEM_BUFFER);
    assert!(offset_of!(Irp, io_status) == 48);
    assert!(offset_of!(Irp, tail) == 120);
    assert!(offset_of!(IrpTailOverlay, current_stack_location) == 64);
    assert!(IRP_CURRENT_STACK_LOCATION == 120 + 64);
    assert!(offset_of!(DriverObject, driver_unload) == 104);
    assert!(offset_of!(DriverObject, major_function) == 112);
    assert!(size_of::<DriverObject>() == 336);
    assert!(offset_of!(DeviceObject, flags) == 48);
    assert!(offset_of!(DeviceObject, device_extension) == 64);
};

// ---------------------------------------------------------------------------
// Kernel imports
// ---------------------------------------------------------------------------

extern "system" {
    pub fn IoCreateDevice(
        driver_object: *mut c_void,
        device_extension_size: u32,
        device_name: *const UnicodeString,
        device_type: u32,
        device_characteristics: u32,
        exclusive: u8,
        device_object: *mut *mut c_void,
    ) -> NTSTATUS;
    pub fn IoDeleteDevice(device_object: *mut c_void);
    pub fn IoCreateSymbolicLink(
        symbolic_link_name: *const UnicodeString,
        device_name: *const UnicodeString,
    ) -> NTSTATUS;
    pub fn IoDeleteSymbolicLink(symbolic_link_name: *const UnicodeString) -> NTSTATUS;
    pub fn RtlInitUnicodeString(destination: *mut UnicodeString, source: *const u16);
    pub fn DbgPrintEx(component: u32, level: u32, format: *const c_char, ...) -> NTSTATUS;
    pub fn ExAllocatePoolWithTag(pool_type: u32, number_of_bytes: usize, tag: u32) -> *mut c_void;
    pub fn ExFreePoolWithTag(pool: *mut c_void, tag: u32);
    pub fn KeIsHypervisorPresent() -> u8;
    /// `frequency` (optional) receives the counter's rate in Hz.
    pub fn KeQueryPerformanceCounter(frequency: *mut LargeInteger) -> LargeInteger;
    pub fn KeAcquireSpinLockRaiseToDpc(lock: *mut usize) -> u8;
    pub fn KeReleaseSpinLock(lock: *mut usize, new_irql: u8);
    /// Completes an IRP. Every dispatch routine that returns anything but
    /// `STATUS_PENDING` must call it, or the caller's I/O never finishes.
    pub fn IofCompleteRequest(irp: *mut Irp, priority_boost: i8);
    pub fn KeBugCheck(code: u32) -> !;
    pub fn MmGetPhysicalAddress(base_address: *mut c_void) -> LargeInteger;
    pub fn MmMapIoSpace(physical_address: LargeInteger, number_of_bytes: usize, cache: u32)
        -> *mut c_void;
    pub fn MmUnmapIoSpace(base_address: *mut c_void, number_of_bytes: usize);
    /// The mode the current thread's request came from (`KERNEL_MODE` or 1).
    pub fn ExGetPreviousMode() -> i8;
    /// The current thread's process. Create dispatch runs in the opener's
    /// thread for a device opened directly, as this one is.
    pub fn IoGetCurrentProcess() -> *mut c_void;
    pub fn PsReferencePrimaryToken(process: *mut c_void) -> *mut c_void;
    pub fn PsDereferencePrimaryToken(token: *mut c_void);
    /// Whether the token has the Administrators group *enabled* — which a
    /// UAC-filtered token has only as deny-only, so it takes an elevated one.
    pub fn SeTokenIsAdmin(token: *mut c_void) -> u8;
}

/// Logs a printf-style line through `DbgPrintEx` (no varargs, one format key).
pub fn dbg_print(format: &str) {
    // SAFETY: `format` is a NUL-terminated byte slice built from a Rust string
    // literal plus a terminating NUL, and DbgPrintEx only reads it.
    unsafe {
        let mut buf = [0u8; 256];
        let bytes = format.as_bytes();
        let n = bytes.len().min(buf.len() - 1);
        buf[..n].copy_from_slice(&bytes[..n]);
        DbgPrintEx(0, 0, buf.as_ptr().cast());
    }
}