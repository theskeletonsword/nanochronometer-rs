// SPDX-License-Identifier: MIT

//! Self-contained `mem*` implementations.
//!
//! A Windows kernel driver may only import from kernel images (`ntoskrnl.exe`
//! etc.). The prebuilt `core`/`compiler_builtins` for the gnullvm targets
//! references CRT `memcpy`, which the GNU driver would resolve to
//! `api-ms-win-crt-*.dll` — a user-mode DLL that is invalid in kernel mode.
//! Defining the symbols locally keeps every import inside `ntoskrnl.exe`.

// SAFETY: all routines expect caller-validated memory; this module only adds
// bytewise access and never touches undefined memory on its own.
#![allow(clippy::needless_return)]

#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut core::ffi::c_void, src: *const core::ffi::c_void, n: usize) -> *mut core::ffi::c_void {
    let (dst, src) = (dst as *mut u8, src as *const u8);
    let mut i = 0usize;
    while i < n {
        // SAFETY: caller guarantees dst/src valid for n bytes.
        unsafe {
            *dst.add(i) = *src.add(i);
        }
        i += 1;
    }
    dst.cast()
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut core::ffi::c_void, src: *const core::ffi::c_void, n: usize) -> *mut core::ffi::c_void {
    let (dst, src) = (dst as *mut u8, src as *const u8);
    if dst as usize <= src as usize {
        let mut i = 0usize;
        while i < n {
            // SAFETY: caller guarantees ranges.
            unsafe {
                *dst.add(i) = *src.add(i);
            }
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            // SAFETY: caller guarantees ranges.
            unsafe {
                *dst.add(i) = *src.add(i);
            }
        }
    }
    dst.cast()
}

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut core::ffi::c_void, c: i32, n: usize) -> *mut core::ffi::c_void {
    let s = s as *mut u8;
    let v = c as u8;
    let mut i = 0usize;
    while i < n {
        // SAFETY: caller guarantees range.
        unsafe {
            *s.add(i) = v;
        }
        i += 1;
    }
    s.cast()
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const core::ffi::c_void, b: *const core::ffi::c_void, n: usize) -> i32 {
    let (a, b) = (a as *const u8, b as *const u8);
    let mut i = 0usize;
    while i < n {
        // SAFETY: caller guarantees ranges.
        let x = unsafe { *a.add(i) };
        let y = unsafe { *b.add(i) };
        if x != y {
            return (x as i32) - (y as i32);
        }
        i += 1;
    }
    0
}