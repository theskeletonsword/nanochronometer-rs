// SPDX-License-Identifier: Apache-2.0
//! The POSIX-class calls as typed functions: what `nclibc`'s `write(2)` or a
//! Rust `std` port's `sys::fd::write` reduce to. Each is one pinned
//! `nccall`; none allocates, none keeps state.
//!
//! What the kernel serves today is in `docs/NCCALL.md` §8; a call it does not
//! serve yet returns [`Errno::ENOSYS`], so these are safe to call on any
//! kernel this ABI version runs on.

use crate::nccall;
use crate::nr::{self, posix, Timespec};
use crate::Errno;

/// A file descriptor.
pub type Fd = i32;
/// Standard input, output and error.
pub const STDIN: Fd = 0;
pub const STDOUT: Fd = 1;
pub const STDERR: Fd = 2;

/// Ends the program with `status`. Never returns.
pub fn exit(status: i32) -> ! {
    // SAFETY: exit takes one word and touches no memory of the caller's.
    let _ = unsafe { nccall!(posix::EXIT, status) };
    // The kernel does not come back from an exit. If it ever did, spinning
    // is the only thing left that cannot do harm.
    loop {
        core::hint::spin_loop();
    }
}

/// Writes `buf` to `fd`. Returns how many bytes were taken.
pub fn write(fd: Fd, buf: &[u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel reads `buf.len()` bytes from `buf`, which is ours.
    unsafe { nccall!(posix::WRITE, fd, buf.as_ptr(), buf.len()) }.result()
}

/// Writes all of `buf`, retrying short writes.
pub fn write_all(fd: Fd, mut buf: &[u8]) -> Result<(), Errno> {
    while !buf.is_empty() {
        match write(fd, buf)? {
            0 => return Err(Errno::EIO),
            n => buf = &buf[n.min(buf.len())..],
        }
    }
    Ok(())
}

/// Reads into `buf` from `fd`. Returns how many bytes arrived.
pub fn read(fd: Fd, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe { nccall!(posix::READ, fd, buf.as_mut_ptr(), buf.len()) }.result()
}

/// Closes `fd`.
pub fn close(fd: Fd) -> Result<(), Errno> {
    // SAFETY: one word, no memory.
    unsafe { nccall!(posix::CLOSE, fd) }.result().map(drop)
}

/// The caller's process id.
pub fn getpid() -> Result<i32, Errno> {
    // SAFETY: no arguments.
    unsafe { nccall!(posix::GETPID) }.result().map(|v| v as i32)
}

/// Maps `len` bytes. Only anonymous, private mappings exist today
/// (`MAP_ANON | MAP_PRIVATE`, `fd` = -1, `offset` = 0); the memory comes back
/// zeroed. `offset` is in bytes here and goes to the kernel in 4 KiB units,
/// so it must be a multiple of 4096.
///
/// # Safety
/// The returned memory is the caller's to manage: a later [`munmap`] of it
/// while references into it live is a use after free.
pub unsafe fn mmap(addr: *mut u8, len: usize, prot: u32, flags: u32, fd: Fd, offset: u64) -> Result<*mut u8, Errno> {
    if !offset.is_multiple_of(nr::map::OFFSET_UNIT) {
        return Err(Errno::EINVAL);
    }
    let units = offset / nr::map::OFFSET_UNIT;
    if units > usize::MAX as u64 {
        return Err(Errno::EOVERFLOW);
    }
    // SAFETY: forwarded; the kernel writes nothing of ours.
    unsafe { nccall!(posix::MMAP, addr, len, prot, flags, fd, units as usize) }
        .result()
        .map(|p| p as *mut u8)
}

/// Unmaps `[addr, addr + len)`.
///
/// # Safety
/// Nothing may use the range afterwards.
pub unsafe fn munmap(addr: *mut u8, len: usize) -> Result<(), Errno> {
    // SAFETY: forwarded.
    unsafe { nccall!(posix::MUNMAP, addr, len) }.result().map(drop)
}

/// Changes the protection of `[addr, addr + len)`.
///
/// # Safety
/// Removing access to memory still in use faults at the next access.
pub unsafe fn mprotect(addr: *mut u8, len: usize, prot: u32) -> Result<(), Errno> {
    // SAFETY: forwarded.
    unsafe { nccall!(posix::MPROTECT, addr, len, prot) }.result().map(drop)
}

/// Fills `buf` from NC_RNG. Returns how many bytes were written (all of
/// them, unless `GRND_NONBLOCK` and the pool is not seeded yet).
pub fn getrandom(buf: &mut [u8], flags: u32) -> Result<usize, Errno> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe { nccall!(posix::GETRANDOM, buf.as_mut_ptr(), buf.len(), flags) }.result()
}

/// Reads clock `clock` ([`nr::clock`]).
pub fn clock_gettime(clock: u32) -> Result<Timespec, Errno> {
    let mut ts = Timespec::default();
    // SAFETY: the kernel writes one Timespec into `ts`.
    unsafe { nccall!(posix::CLOCK_GETTIME, clock, &mut ts as *mut Timespec) }.result()?;
    Ok(ts)
}

/// Sleeps for `ts`.
pub fn nanosleep(ts: &Timespec) -> Result<(), Errno> {
    // SAFETY: the kernel reads one Timespec from `ts`; no remainder pointer.
    unsafe { nccall!(posix::NANOSLEEP, ts as *const Timespec, 0usize) }.result().map(drop)
}

/// Opens a socket. No address family is served until the network stack
/// (`docs/SYSTEM.md` §5) exists: today this is `ENOSYS`.
pub fn socket(domain: i32, ty: i32, protocol: i32) -> Result<Fd, Errno> {
    // SAFETY: three words, no memory.
    unsafe { nccall!(posix::SOCKET, domain, ty, protocol) }.result().map(|v| v as Fd)
}

/// Starts the program at `path` with `argv` and `envp` (NULL-terminated
/// arrays of NUL-terminated strings) as a new process: NetBSD's
/// `posix_spawn(2)` model, one call and no `fork`. Returns its process id.
/// Reserved in class 0 ([`nr::nc::SPAWN`]); `ENOSYS` until processes exist.
///
/// # Safety
/// `path`, `argv` and `envp` must be valid as described for as long as the
/// call runs.
pub unsafe fn spawn(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> Result<i32, Errno> {
    // SAFETY: forwarded. The fourth word is the attribute block, none yet.
    unsafe { nccall!(nr::nc::SPAWN, path, argv, envp, 0usize) }.result().map(|v| v as i32)
}
