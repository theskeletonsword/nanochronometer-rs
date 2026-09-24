// SPDX-License-Identifier: MIT
#![no_std]
#![no_main]
//! NanoChronometer Windows kernel driver (WDM), x86_64 + ARM64.
//!
//! Port of `kernel/linux/nanochrono.rs`: a ring-0 hypervisor detector that
//! reports hypervisor presence, hypercall results and a physical-memory demo
//! to user mode. This driver exposes a `\Device\NanoChronometer` device and
//! three METHOD_BUFFERED IOCTLs: the `key=value` report (cached — the probes
//! run once, in `DriverEntry`), a re-probe behind a 10-second cooldown, and
//! the cooldown setting. See `report.rs` for why the probes are rationed.
//!
//! # Targets / toolchain
//!
//! Built with `rustc --target {x86_64,aarch64}-pc-windows-gnullvm` and the
//! clang-based mingw-w64 drivers under
//! `/home/skels/toolchains/windows-crosscompilers/bin/`; linked as a native
//! PE (`--subsystem native --entry DriverEntry`) against a dlltool-generated
//! `ntoskrnl.exe` import library. See the `Makefile`.

use core::ptr;

mod hypercall;
mod mem;
mod nt;
mod report;

use nt::{NTSTATUS, STATUS_SUCCESS};

/// `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)`:
/// the cached report. `0x222004`.
const IOCTL_NANOCHRONO_REPORT: u32 = (nt::FILE_DEVICE_UNKNOWN << 16) | (0x801 << 2);
/// `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)`:
/// run the probes again; `STATUS_DEVICE_BUSY` (ERROR_BUSY) while cooling
/// down. `0x22A008`.
const IOCTL_NANOCHRONO_REPROBE: u32 = (nt::FILE_DEVICE_UNKNOWN << 16) | (2 << 14) | (0x802 << 2);
/// `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)`:
/// input = a little-endian u32, the cooldown in seconds (0 = off, at the
/// caller's risk). `0x22A00C`.
const IOCTL_NANOCHRONO_SET_COOLDOWN: u32 = (nt::FILE_DEVICE_UNKNOWN << 16) | (2 << 14) | (0x803 << 2);

/// Widens an ASCII byte string to UTF-16LE (for `RtlInitUnicodeString`), with
/// a trailing NUL, zero-filled to the array length.
const fn widen<const N: usize>(s: &[u8]) -> [u16; N] {
    let mut out = [0u16; N];
    let n = if s.len() >= N - 1 { N - 1 } else { s.len() };
    let mut i = 0;
    while i < n {
        out[i] = s[i] as u16;
        i += 1;
    }
    out
}

/// Device name buffers. `const` (RtlInitUnicodeString only reads the source);
/// the loader guarantees `DriverEntry` runs before anything else touches them.
const DEVICE_NAME_BUF: [u16; 32] = widen::<32>(b"\\Device\\NanoChronometer");
const SYMLINK_NAME_BUF: [u16; 32] = widen::<32>(b"\\DosDevices\\NanoChronometer");

/// The device object handed back by `IoCreateDevice`, needed at unload time.
/// Written once at `DriverEntry`, read once at `DriverUnload` — no concurrent
/// access (load/unload are serialized by the loader).
static mut DEVICE_OBJECT: *mut core::ffi::c_void = core::ptr::null_mut();

/// Terminates the system on a Rust panic. A panicking kernel driver must not
/// fall through; bugchecking is the well-defined failure mode.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: KeBugCheck does not return.
    unsafe { nt::KeBugCheck(0xC0DE_C0DE) }
}

/// Stub for the personality routine that the prebuilt `core` rlib references
/// even under `-C panic=abort` on the gnullvm targets. Never invoked with a
/// panic=abort build; exists only to satisfy the linker.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

/// `DriverEntry` — WDM entrypoint called by the I/O manager.
///
/// # Safety
/// Called once by the kernel loader with valid `DRIVER_OBJECT`/registry path.
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(
    driver_object: *mut core::ffi::c_void,
    _registry_path: *const core::ffi::c_void,
) -> NTSTATUS {
    let dev_obj = driver_object.cast::<nt::DriverObject>();
    debug_assert!(!dev_obj.is_null());

    let mut device_name = nt::UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: ptr::null_mut(),
    };
    let mut symlink_name = nt::UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: ptr::null_mut(),
    };
    // SAFETY: source buffers are const and only read by RtlInitUnicodeString.
    nt::RtlInitUnicodeString(&mut device_name, DEVICE_NAME_BUF.as_ptr());
    nt::RtlInitUnicodeString(&mut symlink_name, SYMLINK_NAME_BUF.as_ptr());

    // SAFETY: standard WDM libraries invoked with valid objects.
    let mut device: *mut core::ffi::c_void = ptr::null_mut();
    let status = nt::IoCreateDevice(
        dev_obj.cast(),
        0,                     // no extension
        &device_name,
        nt::FILE_DEVICE_UNKNOWN,
        nt::FILE_DEVICE_SECURE_OPEN,
        false as u8,
        &mut device,
    );
    if status != STATUS_SUCCESS {
        // No device was created: there is nothing to delete, and
        // IoDeleteDevice(NULL) would bugcheck.
        return status;
    }
    DEVICE_OBJECT = device;

    // Clear DO_DEVICE_INITIALIZING so the I/O manager releases the device.
    // SAFETY: `device` was initialized by IoCreateDevice and holds a valid
    // DEVICE_OBJECT whose flags word is at verified offset 48.
    let dev = device.cast::<nt::DeviceObject>();
    (*dev).flags &= !nt::DO_DEVICE_INITIALIZING;

    // Wire the dispatch table: create/close share a completion routine, the
    // report lives on IRP_MJ_DEVICE_CONTROL.
    // SAFETY: `major_function` (offset 112) is an array of 28 function
    // pointers in a valid DRIVER_OBJECT.
    let dispatch = (*dev_obj).major_function.as_mut_ptr();
    dispatch.add(nt::IRP_MJ_CREATE).write(Some(create));
    dispatch.add(nt::IRP_MJ_CLOSE).write(Some(close));
    dispatch.add(nt::IRP_MJ_DEVICE_CONTROL).write(Some(device_control));

    // SAFETY: valid DRIVER_OBJECT; stored unload is safe because DriverUnload
    // is only invoked after the last handle/IRP to the device is gone.
    (*dev_obj).driver_unload = Some(unload);

    // The one probe of this load, before user mode can reach the device;
    // every report request serves its cache.
    report::init();

    // Expose the user-mode-facing name.
    let status = nt::IoCreateSymbolicLink(&symlink_name, &device_name);
    if status != STATUS_SUCCESS {
        // SAFETY: valid device object.
        nt::IoDeleteDevice(device);
        return status;
    }

    nt::dbg_print("NanoChronometer: driver loaded (probed once)\r\n");
    STATUS_SUCCESS
}

/// Opens the device for an elevated administrator or for kernel code, and
/// for nobody else.
///
/// The device is created without a security descriptor (`IoCreateDeviceSecure`
/// lives in `wdmsec.lib`, not in `ntoskrnl.exe`), so its DACL is whatever the
/// `\Device` directory hands down — which is not something to rely on. This
/// is the check that does not depend on it. Everything behind the handle is
/// an administrator's business: the report describes the hypervisor and
/// physical memory, and a cooldown set to 0 turns the re-probe into a stream
/// of VM exits that a cloud provider can read as an attack.
///
/// # Safety
/// Called by the I/O manager with a valid `IRP` whose stack location belongs
/// to this driver, in the opening thread's context.
unsafe extern "system" fn create(_device: *mut core::ffi::c_void, irp: *mut nt::Irp) -> NTSTATUS {
    if nt::ExGetPreviousMode() == nt::KERNEL_MODE {
        return complete(irp, STATUS_SUCCESS, 0);
    }
    // SAFETY: the current process is valid for the duration of this call,
    // and the reference taken on its token is dropped before returning.
    let token = nt::PsReferencePrimaryToken(nt::IoGetCurrentProcess());
    if token.is_null() {
        return complete(irp, nt::STATUS_ACCESS_DENIED, 0);
    }
    let admin = nt::SeTokenIsAdmin(token) != 0;
    nt::PsDereferencePrimaryToken(token);
    if admin {
        complete(irp, STATUS_SUCCESS, 0)
    } else {
        complete(irp, nt::STATUS_ACCESS_DENIED, 0)
    }
}

/// Completes `close` IRPs with `STATUS_SUCCESS`.
///
/// # Safety
/// Called by the I/O manager with a valid `IRP` whose stack location belongs
/// to this driver.
unsafe extern "system" fn close(_device: *mut core::ffi::c_void, irp: *mut nt::Irp) -> NTSTATUS {
    complete(irp, STATUS_SUCCESS, 0)
}

/// The three IOCTLs (METHOD_BUFFERED).
///
/// # Safety
/// Called by the I/O manager with a valid METHOD_BUFFERED IRP.
unsafe extern "system" fn device_control(
    _device: *mut core::ffi::c_void,
    irp: *mut nt::Irp,
) -> NTSTATUS {
    // SAFETY: IRP fields at the offsets verified by the C check in the
    // Makefile (see nt.rs module docs). The stack location is a pointer
    // stored in the IRP, not inline.
    let sp = *((irp as *const u8).add(nt::IRP_CURRENT_STACK_LOCATION) as *const *const u8);
    if sp.is_null() {
        return complete(irp, nt::STATUS_INVALID_PARAMETER, 0);
    }
    let output_len = *(sp.add(nt::ISL_OUTPUT_BUFFER_LENGTH) as *const u32);
    let input_len = *(sp.add(nt::ISL_INPUT_BUFFER_LENGTH) as *const u32);
    let ioctl = *(sp.add(nt::ISL_IO_CONTROL_CODE) as *const u32);

    // METHOD_BUFFERED: one SystemBuffer, sized by the I/O manager to the
    // greater of the two lengths, input copied in, output copied out.
    // SAFETY: SystemBuffer at verified offset 24.
    let sysbuf = *((irp as *const u8).add(nt::IRP_SYSTEM_BUFFER) as *const *mut u8);

    match ioctl {
        IOCTL_NANOCHRONO_REPORT => {
            if output_len < 1 || sysbuf.is_null() {
                return complete(irp, nt::STATUS_BUFFER_TOO_SMALL, 0);
            }
            let cap = (output_len as usize).min(report::REPORT_CAPACITY);
            let out = core::slice::from_raw_parts_mut(sysbuf, cap);
            let written = report::serve(out);
            complete(irp, STATUS_SUCCESS, written)
        }
        IOCTL_NANOCHRONO_REPROBE => complete(irp, report::reprobe(), 0),
        IOCTL_NANOCHRONO_SET_COOLDOWN => {
            if input_len < 4 || sysbuf.is_null() {
                return complete(irp, nt::STATUS_BUFFER_TOO_SMALL, 0);
            }
            let seconds = u32::from_le_bytes(ptr::read_unaligned(sysbuf as *const [u8; 4]));
            report::set_cooldown(seconds);
            complete(irp, STATUS_SUCCESS, 0)
        }
        _ => complete(irp, nt::STATUS_INVALID_DEVICE_REQUEST, 0),
    }
}

/// Sets the IRP's final status and completes it. Returning a status without
/// `IofCompleteRequest` leaves the caller's I/O pending forever.
fn complete(irp: *mut nt::Irp, status: NTSTATUS, information: usize) -> NTSTATUS {
    // SAFETY: a valid IRP owned by this dispatch routine until completed.
    unsafe {
        (*irp).io_status().write(nt::IoStatusBlock { status, information });
        nt::IofCompleteRequest(irp, 0);
    }
    status
}

/// Removes the symbolic link and the device.
///
/// # Safety
/// Invoked by the I/O manager after the driver has no outstanding IRPs.
unsafe extern "system" fn unload(_driver: *mut core::ffi::c_void) {
    // SAFETY: buffer was filled at DriverEntry.
    let mut symlink_name = nt::UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: ptr::null_mut(),
    };
    // SAFETY: source buffer is const and only read by RtlInitUnicodeString.
    nt::RtlInitUnicodeString(&mut symlink_name, SYMLINK_NAME_BUF.as_ptr());
    nt::IoDeleteSymbolicLink(&symlink_name);
    // SAFETY: device object stored at DriverEntry.
    nt::IoDeleteDevice(DEVICE_OBJECT);
    nt::dbg_print("NanoChronometer: driver unloaded\r\n");
}