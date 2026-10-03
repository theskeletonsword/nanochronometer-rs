// SPDX-License-Identifier: Apache-2.0
//! Error values: what a failed `nccall` hands back.
//!
//! A failed call raises the architecture's error flag (`abi::ErrorFlag`) and
//! puts one of these in the first return register; a successful one clears
//! the flag. The values are FreeBSD's, so a C library adapted from BSD maps
//! them one to one and `strerror` needs no table of its own.
//!
//! # Reference
//!
//! Values and names follow FreeBSD's `sys/sys/errno.h` (BSD-3-Clause; see
//! NOTICE). Only the values the kernel can return today, and the ones the
//! POSIX wrappers in this crate name, are listed; the rest keep FreeBSD's
//! numbers when they are added.

use core::fmt;

/// A system error number. Transparent over the `u32` the kernel returns.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Errno(pub u32);

impl Errno {
    /// Operation not permitted.
    pub const EPERM: Errno = Errno(1);
    /// No such file or directory.
    pub const ENOENT: Errno = Errno(2);
    /// No such process.
    pub const ESRCH: Errno = Errno(3);
    /// Interrupted system call.
    pub const EINTR: Errno = Errno(4);
    /// Input/output error.
    pub const EIO: Errno = Errno(5);
    /// Argument list too long.
    pub const E2BIG: Errno = Errno(7);
    /// Bad file descriptor.
    pub const EBADF: Errno = Errno(9);
    /// Cannot allocate memory.
    pub const ENOMEM: Errno = Errno(12);
    /// Permission denied.
    pub const EACCES: Errno = Errno(13);
    /// Bad address: a pointer outside the caller's own memory.
    pub const EFAULT: Errno = Errno(14);
    /// Device busy.
    pub const EBUSY: Errno = Errno(16);
    /// File exists.
    pub const EEXIST: Errno = Errno(17);
    /// Invalid argument.
    pub const EINVAL: Errno = Errno(22);
    /// No space left on device.
    pub const ENOSPC: Errno = Errno(28);
    /// Result too large.
    pub const ERANGE: Errno = Errno(34);
    /// Resource temporarily unavailable.
    pub const EAGAIN: Errno = Errno(35);
    /// Operation not supported.
    pub const EOPNOTSUPP: Errno = Errno(45);
    /// Operation not supported (the POSIX spelling of [`Errno::EOPNOTSUPP`]).
    pub const ENOTSUP: Errno = Errno(45);
    /// Address family not supported by protocol family.
    pub const EAFNOSUPPORT: Errno = Errno(47);
    /// Function not implemented: a POSIX-class number the kernel does not
    /// serve (yet).
    pub const ENOSYS: Errno = Errno(78);
    /// Value too large to be stored in data type.
    pub const EOVERFLOW: Errno = Errno(84);
    /// Capabilities insufficient: the program did not declare the capability
    /// group the call belongs to (Capsicum's meaning).
    pub const ENOTCAPABLE: Errno = Errno(93);
    /// Not permitted in capability mode.
    pub const ECAPMODE: Errno = Errno(94);
    /// Integrity check failed.
    pub const EINTEGRITY: Errno = Errno(97);

    /// The largest value defined (FreeBSD's `ELAST`): anything the kernel
    /// puts in the result register with the error flag up is at most this.
    pub const LAST: u32 = 97;

    /// The raw number.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// FreeBSD's name for the value, or `"E?"` for one not listed here.
    pub const fn name(self) -> &'static str {
        match self.0 {
            1 => "EPERM",
            2 => "ENOENT",
            3 => "ESRCH",
            4 => "EINTR",
            5 => "EIO",
            7 => "E2BIG",
            9 => "EBADF",
            12 => "ENOMEM",
            13 => "EACCES",
            14 => "EFAULT",
            16 => "EBUSY",
            17 => "EEXIST",
            22 => "EINVAL",
            28 => "ENOSPC",
            34 => "ERANGE",
            35 => "EAGAIN",
            45 => "EOPNOTSUPP",
            47 => "EAFNOSUPPORT",
            78 => "ENOSYS",
            84 => "EOVERFLOW",
            93 => "ENOTCAPABLE",
            94 => "ECAPMODE",
            97 => "EINTEGRITY",
            _ => "E?",
        }
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name(), self.0)
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for e in [Errno::EPERM, Errno::EFAULT, Errno::EINVAL, Errno::ENOSYS, Errno::ENOTCAPABLE] {
            assert_ne!(e.name(), "E?");
            assert!(e.get() <= Errno::LAST);
        }
        assert_eq!(Errno::ENOTSUP, Errno::EOPNOTSUPP);
        assert_eq!(Errno(1000).name(), "E?");
    }
}
