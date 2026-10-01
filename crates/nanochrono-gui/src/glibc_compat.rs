// SPDX-License-Identifier: Apache-2.0
//! `acosf` and `asinf` of the GUI's own, on Linux with glibc.
//!
//! glibc 2.43 gave both new symbol versions, and the graphics stack (glam,
//! lyon, tiny-skia, kurbo, …) calls them, so a GUI linked against 2.43 would
//! refuse to start on any older glibc — Ubuntu 24.04, Debian 13, RHEL 10.
//! Defined here, they bind inside the binary and the GUI needs only the glibc
//! its other symbols do. The `libm` crate is a port of musl's implementations.

/// `float acosf(float)`.
#[no_mangle]
pub extern "C" fn acosf(x: f32) -> f32 {
    libm::acosf(x)
}

/// `float asinf(float)`.
#[no_mangle]
pub extern "C" fn asinf(x: f32) -> f32 {
    libm::asinf(x)
}
