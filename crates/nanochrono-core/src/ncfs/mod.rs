// SPDX-License-Identifier: Apache-2.0
//! NCFS: NanoChronometer's own filesystem.
//!
//! A copy-on-write filesystem in the line of Btrfs and ZFS, made for a
//! system that can lose power at any instant:
//!
//! * **Nothing committed is ever overwritten.** A commit writes every
//!   changed node to free space, then — after a barrier — a new superblock
//!   in the other of two slots. A power cut leaves the last commit whole;
//!   a torn superblock fails its checksum and the other slot is used. No
//!   journal to replay, no `fsck` to run after a crash.
//! * **A Merkle tree.** Every pointer carries the BLAKE3 of what it points
//!   at — node or extent — so bit rot, a misdirected write or a lost write
//!   is found when the block is read, and the superblock's root hash covers
//!   every byte of the volume. Signing that one hash signs the volume: an
//!   `ncinitramdisk` is a sealed NCFS image.
//! * **Snapshots** in constant time (a second pointer to a root), and
//!   rollback by making a snapshot the default subvolume.
//! * **Deduplication** of identical 128 KiB windows, found by the BLAKE3
//!   every extent carries anyway and confirmed byte for byte.
//! * **Transparent compression**: LZ4 for what the system writes, ZSTD for
//!   images built on a host; a window stays raw unless compressing saves a
//!   block. All-zero windows are holes.
//! * **Nanosecond timestamps**, as befits a NanoChronometer.
//!
//! # The code
//!
//! | Module | What | Needs |
//! |---|---|---|
//! | [`format`] | the on-disk structures, checked field by field | nothing |
//! | [`read`] | reading a volume through caller-provided buffers | nothing (the kernel's half) |
//! | [`seal`] | sealed volumes: the signed superblock of an `ncinitramdisk` | nothing to check, `alloc` to seal |
//! | [`write`] | mkfs, the copy-on-write engine, files, snapshots | `alloc` |
//! | [`check`] | `fsck` and scrub: every rule, every checksum | `alloc` |
//! | [`pkgfs`] | NCFS as the filesystem `ncpkg` installs into | `alloc` |
//!
//! docs/NCFS.md is the specification.

pub mod format;
pub mod read;
pub mod seal;

#[cfg(feature = "alloc")]
pub mod check;
#[cfg(feature = "alloc")]
pub mod pkgfs;
#[cfg(feature = "alloc")]
pub mod write;

#[cfg(all(test, feature = "std"))]
pub(crate) mod tests;

pub use format::{Compression, Inode, Key, Ptr, RootItem, Superblock, BLOCK};
pub use read::{BlockDev, Scratch, SliceDev, Volume};

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The device failed.
    Io,
    /// No valid superblock: not an NCFS volume, or both copies damaged.
    NoSuperblock,
    /// A format version or incompatible feature this code does not know.
    Unsupported,
    /// A block whose BLAKE3 does not match the pointer to it.
    Checksum(u64),
    /// A block or item that breaks the format.
    Corrupt(u64),
    NotFound,
    Exists,
    NotADirectory,
    IsADirectory,
    NotASymlink,
    NotEmpty,
    InvalidName,
    /// Too many symbolic links in a path.
    Loop,
    NoSpace,
    /// A sealed volume, a read-only subvolume, or unknown features.
    ReadOnly,
    /// Past a size limit (a file, an item).
    TooBig,
    /// The default subvolume cannot be deleted.
    Busy,
    Lz4(crate::lz4::Error),
    Zstd(crate::zstd::Error),
}

impl Error {
    pub fn message(self) -> &'static str {
        match self {
            Error::Io => "input/output error",
            Error::NoSuperblock => "no valid NCFS superblock",
            Error::Unsupported => "an NCFS version or feature this build does not support",
            Error::Checksum(_) => "checksum mismatch: the block is not what was written",
            Error::Corrupt(_) => "the volume breaks the NCFS format",
            Error::NotFound => "no such file or directory",
            Error::Exists => "already exists",
            Error::NotADirectory => "not a directory",
            Error::IsADirectory => "is a directory",
            Error::NotASymlink => "not a symbolic link",
            Error::NotEmpty => "directory not empty",
            Error::InvalidName => "invalid name",
            Error::Loop => "too many symbolic links",
            Error::NoSpace => "no space left on the volume",
            Error::ReadOnly => "read-only",
            Error::TooBig => "too large",
            Error::Busy => "in use",
            Error::Lz4(e) => e.message(),
            Error::Zstd(e) => e.message(),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Checksum(b) | Error::Corrupt(b) if *b != 0 => write!(f, "{} (block {b})", self.message()),
            _ => f.write_str(self.message()),
        }
    }
}
