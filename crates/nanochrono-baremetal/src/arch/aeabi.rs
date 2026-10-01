// SPDX-License-Identifier: Apache-2.0
//! The ARM run-time ABI's unaligned-access helpers, for 32-bit ARM.
//!
//! On a strict-alignment target — this one, where the MMU is off and an
//! unaligned word access faults — LLVM optimising for size (`-Oz`) replaces an
//! unaligned load or store with a call to `__aeabi_uread4` and its kin (the ARM
//! RTABI's unaligned-access helpers). A hosted toolchain's libgcc provides
//! them; Rust's compiler_builtins does not, so without these an `OPT=-Oz`
//! kernel does not link.
//!
//! Each moves one byte at a time through volatile accesses. Plain byte
//! accesses could be merged back into the very unaligned access these stand
//! for, which would compile to a call to themselves.

use core::ptr::{read_volatile, write_volatile};

/// Reads `N` bytes from a possibly unaligned address.
///
/// # Safety
/// `address` must be valid for `N` bytes of reads.
unsafe fn read_bytes<const N: usize>(address: *const u8) -> [u8; N] {
    let mut bytes = [0u8; N];
    for (i, b) in bytes.iter_mut().enumerate() {
        // SAFETY: forwarded from this function's own contract.
        *b = unsafe { read_volatile(address.add(i)) };
    }
    bytes
}

/// Writes `bytes` to a possibly unaligned address.
///
/// # Safety
/// `address` must be valid for `N` bytes of writes.
unsafe fn write_bytes<const N: usize>(address: *mut u8, bytes: [u8; N]) {
    for (i, b) in bytes.into_iter().enumerate() {
        // SAFETY: forwarded from this function's own contract.
        unsafe { write_volatile(address.add(i), b) };
    }
}

/// `int __aeabi_uread4(void *address)`.
///
/// # Safety
/// Called by compiled code for an unaligned access it makes: `address` is
/// valid for 4 bytes.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_uread4(address: *const u8) -> u32 {
    // SAFETY: forwarded.
    u32::from_ne_bytes(unsafe { read_bytes(address) })
}

/// `int __aeabi_uwrite4(int value, void *address)`; returns `value`.
///
/// # Safety
/// As [`__aeabi_uread4`], for writes.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_uwrite4(value: u32, address: *mut u8) -> u32 {
    // SAFETY: forwarded.
    unsafe { write_bytes(address, value.to_ne_bytes()) };
    value
}

/// `long long __aeabi_uread8(void *address)`.
///
/// # Safety
/// As [`__aeabi_uread4`], for 8 bytes.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_uread8(address: *const u8) -> u64 {
    // SAFETY: forwarded.
    u64::from_ne_bytes(unsafe { read_bytes(address) })
}

/// `long long __aeabi_uwrite8(long long value, void *address)`; returns
/// `value`.
///
/// # Safety
/// As [`__aeabi_uread4`], for 8 bytes of writes.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_uwrite8(value: u64, address: *mut u8) -> u64 {
    // SAFETY: forwarded.
    unsafe { write_bytes(address, value.to_ne_bytes()) };
    value
}
