// SPDX-License-Identifier: Apache-2.0
//! `nccall`: the kernel's one system call, on every architecture.
//!
//! A program reaches the kernel with one trap instruction — `syscall`,
//! `int $0x80`, `svc #0`, `sc` or `ecall` — and the same numbers, arguments
//! and errors whatever it was written in: C, C++, assembly, Rust. Where each
//! ISA keeps them is its convention ([`nanochrono_sys::abi`]); what they
//! mean is decided here, once, for all of them.
//!
//! ```text
//!  trap instruction
//!   → the ISA's entry (assembly, beside its vectors): the caller's
//!     registers into a frame, on a kernel stack
//!   → the ISA's glue (`hal`): the number and six arguments out of the
//!     frame, as `nanochrono_sys::abi` places them
//!   → dispatch(): `nanochrono_core::nccall`, the same code the host tests run
//!   → back through the glue: two results and the error flag, where the
//!     convention puts them; or the caller is ended
//! ```
//!
//! Who is calling is a [`Caller`]: a ring-3 app on x86-64 (`ring3.rs`), or
//! the kernel's own self-test, which makes calls through the real trap on
//! each ISA at boot (`hal::selftest`). The caller decides what memory is
//! its own, which capabilities it was granted and which call sites the
//! kernel vouches for; the rules are the same for all of them.

pub mod hal;

pub use nanochrono_core::nccall::{
    capability, current_owns, dispatch, dispatch_current, serve, Call, Caller, Ending, Reply, Violation, MAX_RANDOM,
};

// getrandom's cap is NC_RNG's own.
const _: () = assert!(MAX_RANDOM == crate::rng::NC_RNG_MAX_FILL);

/// `write(1|2, …)`: the bytes to the console — the UART, or what stands in
/// for it — and nowhere else (not the kernel log, not a terminal's sink).
pub fn console(bytes: &[u8]) {
    #[cfg(x86_any)]
    crate::serial::write_uart_only(bytes);
    #[cfg(not(x86_any))]
    {
        // The other consoles take text: valid UTF-8 as it is, anything else
        // byte by byte as U+FFFD.
        let mut rest = bytes;
        while !rest.is_empty() {
            match core::str::from_utf8(rest) {
                Ok(s) => {
                    crate::serial::console_write(s);
                    break;
                }
                Err(e) => {
                    let (good, bad) = rest.split_at(e.valid_up_to());
                    // SAFETY: from_utf8 vouched for this prefix.
                    crate::serial::console_write(unsafe { core::str::from_utf8_unchecked(good) });
                    crate::serial::console_write("\u{FFFD}");
                    rest = &bad[e.error_len().unwrap_or(bad.len())..];
                }
            }
        }
    }
}

/// `getrandom(…)`: NC_RNG's output in `mode`, or `None` when it cannot give
/// it now (the pool not yet seeded for TRUE mode, say).
pub fn random(out: &mut [u8], mode: nanochrono_core::rng::Mode) -> Option<usize> {
    crate::rng::fill(out, mode).ok()
}
