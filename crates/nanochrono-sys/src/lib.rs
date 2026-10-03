// SPDX-License-Identifier: Apache-2.0
//! `nccall`: the one door between ring 3 and ring 0, on every architecture
//! NanoChronometer runs on — as data both sides agree on, and as the code a
//! ring-3 program uses to knock.
//!
//! The specification is `docs/NCCALL.md`. This crate is its executable half:
//!
//! * [`abi`] — the register convention of each ISA (which instruction, which
//!   register holds the call number, where the arguments and results go, how
//!   failure is flagged), the red zone its psABI grants user code, and how
//!   the kernel's entry path keeps off it. The invariants the specification
//!   states are checked by this crate's tests, for all nine targets, on any
//!   host.
//! * [`nr`] — the call numbers. Two classes: NanoChronometer's own services
//!   (the plugin API the kernel already serves) and the POSIX class, numbered
//!   after FreeBSD's `sys/kern/syscalls.master` so a libc adapted from BSD
//!   finds the calls where it expects them.
//! * [`errno`] — the error values, FreeBSD's `sys/sys/errno.h`.
//! * [`raw`], [`nccall!`] — the instruction itself, in inline assembly, for
//!   x86-64, i386, AArch64, ARM32, PowerPC (32, 64 big- and little-endian)
//!   and RISC-V (32 and 64). Each call site also records its address and
//!   number in the `nccall_pins` section, the way OpenBSD's libc does for
//!   `pinsyscalls(2)`, so a loader can tell the kernel exactly where calls
//!   may come from.
//! * [`posix`], [`io`] and (feature `alloc`) [`alloc`] — `write`, `mmap`,
//!   `getrandom` and the rest as typed functions, standard output as a
//!   `core::fmt::Write`, and a global allocator over `mmap`: the layer a
//!   `std::sys::nanochronometer` port sits on, as the FreeBSD one sits on
//!   the `libc` crate.
//!
//! The kernel depends on this crate too, for [`nr`] and [`errno`]: the
//! dispatcher matches on the same constants the stubs load.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod abi;
pub mod errno;
pub mod nr;

pub use errno::Errno;

/// The instruction-level layer: one function per architecture family, and
/// the [`nccall!`] macro over it.
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv32",
    target_arch = "riscv64",
))]
pub mod raw;

#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv32",
    target_arch = "riscv64",
))]
pub mod posix;

#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv32",
    target_arch = "riscv64",
))]
pub mod io;

#[cfg(all(
    feature = "alloc",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
    )
))]
pub mod alloc;
