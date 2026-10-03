// SPDX-License-Identifier: Apache-2.0
//! The `.ncpkg` package: one compressed download for every architecture.
//!
//! # What goes in one
//!
//! A package is a small file tree, laid out the way it installs:
//!
//! ```text
//! ncpkg.meta                    the manifest (JSON): what, who, which ring,
//!                               every file with its SHA-512, the signatures
//! icon.png                      the package's icon (optional): the desktop's
//!                               and the dock's, copied to the icon cache
//! ncapp/<arch>/main.ncapp       the app, one per architecture (gui, cli)
//! lib/<arch>/libfoo.ncdyn       shared libraries, per architecture
//! plugins/<arch>/x.ncplu        extensions for an app (a codec pack)
//! res/…                         icons, data: stored once for every arch
//! ```
//!
//! The module formats inside (`.ncapp`, `.ncdyn`, `.ncplu`) are
//! [`crate::ncplu`]'s; the manifest is [`meta`]; installing and removing,
//! with `/usr/lib` reference-counted, is [`manager`]. This module is the
//! container: how the tree is stored, and the rules a reader checks before
//! it believes a byte of it.
//!
//! # The rules
//!
//! The same discipline as [`crate::ncplu`] — untrusted input, a kernel
//! that must not panic — plus what a container needs:
//!
//! * One table, read once. No local headers to disagree with it (the ZIP
//!   failure mode), no second directory.
//! * **Every byte is accounted for.** Header, table, names and data follow
//!   each other with no gaps; names and file bodies tile their regions in
//!   table order; nothing may sit between or after them. There is nowhere
//!   to hide a payload.
//! * Entry 0 is `ncpkg.meta`, stored uncompressed: a kernel without an
//!   allocator reads the manifest in place.
//! * Every other path is a [`path::package_path`] (`icon.png`, `ncapp/`,
//!   `lib/`, `plugins/`, `res/`), and the paths are in strictly increasing
//!   case-folded order — canonical, and no two equal on a case-insensitive
//!   volume.
//! * Files are stored or DEFLATE-compressed ([`crate::inflate`]); a
//!   compressed file must decode to exactly the size the table declares,
//!   which is bounded ([`MAX_FILE`], [`MAX_TOTAL`]), so a decompression bomb
//!   stops at the size it promised.
//!
//! Integrity and trust are the manifest's: it lists each file's SHA-512 and
//! carries the signatures ([`sig`]). The container has no digest of its own
//! — the bytes that matter are covered by what the signatures cover.
//!
//! # Layout
//!
//! Little-endian. Header (64 bytes):
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 8 | magic `NCPKG\x1b\0\0` |
//! | 8 | 2 | format version, 2 |
//! | 10 | 2 | header size, 64 |
//! | 12 | 4 | flags, 0 |
//! | 16 | 8 | total size |
//! | 24 | 4 | file count (1..=[`MAX_FILES`]) |
//! | 28 | 4 | table offset (64) |
//! | 32 | 4 | names offset (table offset + count × 40) |
//! | 36 | 4 | names length |
//! | 40 | 8 | data offset (names offset + names length) |
//! | 48 | 8 | data length (total size − data offset) |
//! | 56 | 8 | reserved, 0 |
//!
//! Table entry (40 bytes): name offset (4, relative to the names region),
//! name length (2), method (1: 0 stored, 1 DEFLATE), flags (1, 0), data
//! offset (8, relative to the data region), stored size (8), size (8),
//! reserved (8, 0). Parsed field by field, never cast from a struct.

use crate::inflate;
use crate::ncplu::Arch;

pub mod base64;
pub mod icon;
pub mod meta;
pub mod path;
pub mod sig;
pub mod version;

#[cfg(feature = "alloc")]
pub mod db;
#[cfg(feature = "alloc")]
pub mod fs;
#[cfg(feature = "alloc")]
pub mod journal;
#[cfg(feature = "alloc")]
pub mod manager;
#[cfg(all(test, feature = "std"))]
mod manager_tests;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

pub use path::{Area, ICON, META};

/// `b"NCPKG"`, an ESC to make it non-textual, then two NULs.
pub const MAGIC: [u8; 8] = *b"NCPKG\x1b\0\0";
/// The only format version this reads. Version 1 (a fixed entry table
/// with a `key: value` manifest) was never released.
pub const FORMAT_VERSION: u16 = 2;
pub const HEADER_SIZE: usize = 64;
pub const ENTRY_SIZE: usize = 40;

pub const H_MAGIC: usize = 0;
pub const H_FORMAT_VERSION: usize = 8;
pub const H_HEADER_SIZE: usize = 10;
pub const H_FLAGS: usize = 12;
pub const H_TOTAL_SIZE: usize = 16;
pub const H_FILE_COUNT: usize = 24;
pub const H_TABLE_OFF: usize = 28;
pub const H_NAMES_OFF: usize = 32;
pub const H_NAMES_LEN: usize = 36;
pub const H_DATA_OFF: usize = 40;
pub const H_DATA_LEN: usize = 48;
pub const H_RESERVED: usize = 56;

pub const E_NAME_OFF: usize = 0;
pub const E_NAME_LEN: usize = 4;
pub const E_METHOD: usize = 6;
pub const E_FLAGS: usize = 7;
pub const E_DATA_OFF: usize = 8;
pub const E_STORED: usize = 16;
pub const E_SIZE: usize = 24;
pub const E_RESERVED: usize = 32;

/// The largest package, compressed.
pub const MAX_PACKAGE: u64 = 1 << 30;
/// The most files in one package, the manifest included.
pub const MAX_FILES: usize = 4096;
/// The largest single file, uncompressed.
pub const MAX_FILE: u64 = 256 << 20;
/// All files together, uncompressed.
pub const MAX_TOTAL: u64 = 2 << 30;
/// The largest manifest: room for every file and eight signatures of the
/// largest SLH-DSA parameter set.
pub const MAX_META: usize = 2 << 20;

/// The bare-metal shell's own commands (`nanochrono-baremetal`'s
/// `shell::builtins`, kept in step by hand): names a `cli` package may not
/// take for its `/usr/bin` launchers.
pub const RESERVED_COMMANDS: &[&str] = &[
    "help", "nanochrono", "stopwatch", "top", "ps", "free", "uptime", "date", "uname", "hostname", "whoami", "echo",
    "clear", "ls", "cd", "pwd", "cat", "hexdump", "dmesg", "lscpu", "cpuctl", "lspci", "hypervisor", "selftest",
    "bench", "loadkeys", "color", "apps", "ncpkg", "sudo", "history", "sleep", "desktop", "classic", "reboot",
    "poweroff", "true", "false", "exit", "shutdown", "cpuinfo", "halt",
];

/// How a file is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Stored = 0,
    /// Raw DEFLATE (RFC 1951), no zlib or gzip wrapper.
    Deflate = 1,
}

impl Method {
    pub const fn from_u8(v: u8) -> Option<Method> {
        match v {
            0 => Some(Method::Stored),
            1 => Some(Method::Deflate),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Method::Stored => "stored",
            Method::Deflate => "deflate",
        }
    }
}

/// Why a package was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    TooSmall,
    BadMagic,
    /// Another format version, a non-zero flag or reserved field.
    BadVersion,
    TooBig,
    /// A field points past the end of the file.
    Truncated,
    /// The regions do not follow each other, or the names or file bodies
    /// leave a gap, overlap or overrun their region.
    BadLayout,
    /// A path outside the package layout, or with characters it may not use.
    BadPath,
    /// Two paths equal (ignoring case), or out of order.
    Duplicate,
    /// Unknown method, sizes that do not agree, or a file past the limits.
    BadEntry,
    /// Entry 0 is not an uncompressed `ncpkg.meta` of sane size.
    NoMeta,
    /// A compressed file does not decode to its declared size.
    BadData(inflate::Error),
    /// No such file in the package.
    NotFound,
    /// The caller's buffer is smaller than the file.
    BufferTooSmall,
}

impl FormatError {
    pub const fn message(self) -> &'static str {
        match self {
            FormatError::TooSmall => "file shorter than a package header",
            FormatError::BadMagic => "not an .ncpkg package (bad magic)",
            FormatError::BadVersion => "unsupported .ncpkg format version or flags",
            FormatError::TooBig => "package larger than allowed",
            FormatError::Truncated => "a field points past the end of the file",
            FormatError::BadLayout => "regions overlap, leave gaps or overrun the file",
            FormatError::BadPath => "a path outside the package layout",
            FormatError::Duplicate => "two files with the same path, or files out of order",
            FormatError::BadEntry => "a file entry with a bad method or sizes",
            FormatError::NoMeta => "the first file is not an uncompressed ncpkg.meta",
            FormatError::BadData(e) => e.message(),
            FormatError::NotFound => "no such file in the package",
            FormatError::BufferTooSmall => "file larger than the buffer",
        }
    }
}

impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

// Checked little-endian reads: an error rather than a panic, whatever `at`.
fn rd16(b: &[u8], at: usize) -> Result<u16, FormatError> {
    let s = b.get(at..at.checked_add(2).ok_or(FormatError::Truncated)?).ok_or(FormatError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn rd32(b: &[u8], at: usize) -> Result<u32, FormatError> {
    let s = b.get(at..at.checked_add(4).ok_or(FormatError::Truncated)?).ok_or(FormatError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd64(b: &[u8], at: usize) -> Result<u64, FormatError> {
    let s = b.get(at..at.checked_add(8).ok_or(FormatError::Truncated)?).ok_or(FormatError::Truncated)?;
    Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}
fn size(v: u64) -> Result<usize, FormatError> {
    usize::try_from(v).map_err(|_| FormatError::TooBig)
}

/// A package that passed every check.
#[derive(Debug, Clone, Copy)]
pub struct Package<'a> {
    bytes: &'a [u8],
    count: usize,
    names_off: usize,
    names_len: usize,
    data_off: usize,
    data_len: usize,
}

/// One file of a package.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// Its path inside the package (`ncapp/x86_64/main.ncapp`).
    pub path: &'a str,
    pub method: Method,
    /// The bytes as stored: the file itself, or its DEFLATE stream.
    pub stored: &'a [u8],
    /// The file's size once decoded.
    pub size: u64,
}

impl<'a> Package<'a> {
    /// Validates everything about the container. See the module docs.
    pub fn parse(file: &'a [u8]) -> Result<Package<'a>, FormatError> {
        if file.len() < HEADER_SIZE {
            return Err(FormatError::TooSmall);
        }
        if file.get(H_MAGIC..H_MAGIC + 8) != Some(&MAGIC[..]) {
            return Err(FormatError::BadMagic);
        }
        if rd16(file, H_FORMAT_VERSION)? != FORMAT_VERSION
            || usize::from(rd16(file, H_HEADER_SIZE)?) != HEADER_SIZE
            || rd32(file, H_FLAGS)? != 0
            || rd64(file, H_RESERVED)? != 0
        {
            return Err(FormatError::BadVersion);
        }
        let total = rd64(file, H_TOTAL_SIZE)?;
        if total > MAX_PACKAGE {
            return Err(FormatError::TooBig);
        }
        let total = size(total)?;
        if total < HEADER_SIZE {
            return Err(FormatError::TooSmall);
        }
        // Bytes past `total` (a sector-padded read) are not the package's.
        let bytes = file.get(..total).ok_or(FormatError::Truncated)?;

        let count = size(u64::from(rd32(bytes, H_FILE_COUNT)?))?;
        if count == 0 || count > MAX_FILES {
            return Err(FormatError::BadLayout);
        }
        let table_off = size(u64::from(rd32(bytes, H_TABLE_OFF)?))?;
        let names_off = size(u64::from(rd32(bytes, H_NAMES_OFF)?))?;
        let names_len = size(u64::from(rd32(bytes, H_NAMES_LEN)?))?;
        let data_off = size(rd64(bytes, H_DATA_OFF)?)?;
        let data_len = size(rd64(bytes, H_DATA_LEN)?)?;
        // The regions follow each other exactly.
        let regions_tile = table_off == HEADER_SIZE
            && Some(names_off) == count.checked_mul(ENTRY_SIZE).and_then(|t| t.checked_add(table_off))
            && Some(data_off) == names_off.checked_add(names_len)
            && Some(total) == data_off.checked_add(data_len);
        if !regions_tile {
            return Err(FormatError::BadLayout);
        }

        let pkg = Package { bytes, count, names_off, names_len, data_off, data_len };

        // Every entry, in order: names and bodies tile their regions, paths
        // are valid and strictly increasing.
        let mut name_cursor = 0usize;
        let mut data_cursor = 0u64;
        let mut unpacked = 0u64;
        let mut prev: Option<&str> = None;
        for i in 0..count {
            let at = HEADER_SIZE + i * ENTRY_SIZE;
            let name_off = size(u64::from(rd32(bytes, at + E_NAME_OFF)?))?;
            let entry_data_off = rd64(bytes, at + E_DATA_OFF)?;
            if name_off != name_cursor || entry_data_off != data_cursor {
                return Err(FormatError::BadLayout);
            }
            let e = pkg.entry(i)?;
            name_cursor += e.path.len();
            data_cursor = data_cursor.checked_add(e.stored.len() as u64).ok_or(FormatError::BadLayout)?;
            unpacked = unpacked.checked_add(e.size).ok_or(FormatError::TooBig)?;
            if unpacked > MAX_TOTAL {
                return Err(FormatError::TooBig);
            }
            if i == 0 {
                if e.path != META || e.method != Method::Stored || e.size == 0 || e.size > MAX_META as u64 {
                    return Err(FormatError::NoMeta);
                }
                continue;
            }
            match path::package_path(e.path) {
                Some(Area::Meta) | None => return Err(FormatError::BadPath),
                Some(_) => {}
            }
            if let Some(p) = prev {
                if path::cmp_folded(p, e.path) != core::cmp::Ordering::Less {
                    return Err(FormatError::Duplicate);
                }
            }
            prev = Some(e.path);
        }
        if name_cursor != names_len || data_cursor != data_len as u64 {
            return Err(FormatError::BadLayout);
        }
        Ok(pkg)
    }

    /// The whole package.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Files, the manifest included.
    pub fn file_count(&self) -> usize {
        self.count
    }

    /// Entry `i`, with every field checked again.
    pub fn entry(&self, i: usize) -> Result<Entry<'a>, FormatError> {
        if i >= self.count {
            return Err(FormatError::NotFound);
        }
        let b = self.bytes;
        let at = HEADER_SIZE + i * ENTRY_SIZE;
        let name_off = size(u64::from(rd32(b, at + E_NAME_OFF)?))?;
        let name_len = usize::from(rd16(b, at + E_NAME_LEN)?);
        let method = Method::from_u8(*b.get(at + E_METHOD).ok_or(FormatError::Truncated)?).ok_or(FormatError::BadEntry)?;
        let flags = *b.get(at + E_FLAGS).ok_or(FormatError::Truncated)?;
        let data_off = size(rd64(b, at + E_DATA_OFF)?)?;
        let stored_len = rd64(b, at + E_STORED)?;
        let unpacked = rd64(b, at + E_SIZE)?;
        if flags != 0 || rd64(b, at + E_RESERVED)? != 0 {
            return Err(FormatError::BadVersion);
        }
        if name_len == 0 || name_len > path::MAX_PATH || name_off.checked_add(name_len).is_none_or(|e| e > self.names_len) {
            return Err(FormatError::BadPath);
        }
        let name = b.get(self.names_off + name_off..self.names_off + name_off + name_len).ok_or(FormatError::Truncated)?;
        let path = core::str::from_utf8(name).map_err(|_| FormatError::BadPath)?;
        if unpacked > MAX_FILE {
            return Err(FormatError::TooBig);
        }
        let consistent = match method {
            Method::Stored => stored_len == unpacked,
            // An empty file compresses to two bytes; nothing compresses to
            // none, and nothing expands a thousandfold and more.
            Method::Deflate => stored_len >= 1 && unpacked <= stored_len.saturating_mul(1032),
        };
        if !consistent {
            return Err(FormatError::BadEntry);
        }
        let stored_len = size(stored_len)?;
        if data_off.checked_add(stored_len).is_none_or(|e| e > self.data_len) {
            return Err(FormatError::BadLayout);
        }
        let start = self.data_off + data_off;
        let stored = b.get(start..start + stored_len).ok_or(FormatError::Truncated)?;
        Ok(Entry { path, method, stored, size: unpacked })
    }

    /// The manifest's bytes.
    pub fn meta(&self) -> &'a [u8] {
        self.entry(0).map(|e| e.stored).unwrap_or(&[])
    }

    /// The payload files (everything but the manifest), in stored order.
    pub fn files(&self) -> impl Iterator<Item = Entry<'a>> + '_ {
        (1..self.count).filter_map(move |i| self.entry(i).ok())
    }

    /// The file at `path` (exact spelling), found by binary search over the
    /// sorted table.
    pub fn find(&self, path: &str) -> Option<Entry<'a>> {
        let (mut lo, mut hi) = (1usize, self.count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let e = self.entry(mid).ok()?;
            match path::cmp_folded(e.path, path) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return (e.path == path).then_some(e),
            }
        }
        None
    }

    /// The app module for `arch`: `ncapp/<arch>/<entry>`.
    pub fn app_entry(&self, arch: Arch, entry: &str) -> Option<Entry<'a>> {
        let mut buf = [0u8; path::MAX_PATH];
        let p = join(&mut buf, &["ncapp", arch.name(), entry])?;
        self.find(p)
    }

    /// Rebuilds the package with a new manifest, every other file copied as
    /// stored — what a signer does after adding a signature.
    #[cfg(feature = "alloc")]
    pub fn with_meta(&self, meta: &[u8]) -> Result<Vec<u8>, FormatError> {
        let mut b = Builder::new(meta.to_vec());
        for e in self.files() {
            b.add_raw(e.path, e.method, e.stored.to_vec(), e.size)?;
        }
        b.finish()
    }
}

/// `parts` joined by `/` into `buf`.
fn join<'b>(buf: &'b mut [u8], parts: &[&str]) -> Option<&'b str> {
    let mut n = 0;
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            *buf.get_mut(n)? = b'/';
            n += 1;
        }
        buf.get_mut(n..n + part.len())?.copy_from_slice(part.as_bytes());
        n += part.len();
    }
    core::str::from_utf8(buf.get(..n)?).ok()
}

impl<'a> Entry<'a> {
    /// Decodes the file into `out`, which must hold at least
    /// [`size`](Self::size) bytes; returns the size.
    pub fn read_into(&self, out: &mut [u8]) -> Result<usize, FormatError> {
        let n = size(self.size)?;
        let out = out.get_mut(..n).ok_or(FormatError::BufferTooSmall)?;
        match self.method {
            Method::Stored => out.copy_from_slice(self.stored),
            Method::Deflate => {
                let got = inflate::inflate_into(self.stored, out).map_err(FormatError::BadData)?;
                if got != n {
                    return Err(FormatError::BadData(inflate::Error::Truncated));
                }
            }
        }
        Ok(n)
    }

    /// The file's SHA-512, decoding through `window` rather than holding
    /// the whole file: for files larger than any buffer at hand.
    pub fn sha512(&self, window: &mut [u8; inflate::WINDOW]) -> Result<[u8; 64], FormatError> {
        let mut h = crate::sha512::Sha512::new();
        match self.method {
            Method::Stored => h.update(self.stored),
            Method::Deflate => {
                let mut sink = |piece: &[u8]| {
                    h.update(piece);
                    true
                };
                let n = inflate::inflate_to(self.stored, window, self.size, &mut sink).map_err(FormatError::BadData)?;
                if n != self.size {
                    return Err(FormatError::BadData(inflate::Error::Truncated));
                }
            }
        }
        Ok(h.finalize())
    }

    /// The decoded file.
    #[cfg(feature = "alloc")]
    pub fn read(&self) -> Result<Vec<u8>, FormatError> {
        match self.method {
            Method::Stored => Ok(self.stored.to_vec()),
            Method::Deflate => inflate::inflate_vec(self.stored, size(self.size)?).map_err(FormatError::BadData),
        }
    }
}

/// Assembles a package. Files may be added in any order; [`finish`]
/// sorts them, lays the container out and parses the result before
/// returning it, so a builder never emits a package a reader refuses.
///
/// [`finish`]: Builder::finish
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct Builder {
    meta: Vec<u8>,
    files: Vec<(String, Method, Vec<u8>, u64)>,
}

#[cfg(feature = "alloc")]
impl Builder {
    pub fn new(meta: Vec<u8>) -> Builder {
        Builder { meta, files: Vec::new() }
    }

    /// Adds a file, uncompressed.
    pub fn add_stored(&mut self, path: &str, data: Vec<u8>) -> Result<(), FormatError> {
        let n = data.len() as u64;
        self.add_raw(path, Method::Stored, data, n)
    }

    /// Adds a file as stored bytes: the file itself (`Stored`) or a raw
    /// DEFLATE stream that decodes to `size` bytes (`Deflate`; checked).
    pub fn add_raw(&mut self, path: &str, method: Method, stored: Vec<u8>, size: u64) -> Result<(), FormatError> {
        match path::package_path(path) {
            Some(Area::Meta) | None => return Err(FormatError::BadPath),
            Some(_) => {}
        }
        if self.files.iter().any(|f| path::cmp_folded(&f.0, path) == core::cmp::Ordering::Equal) {
            return Err(FormatError::Duplicate);
        }
        if size > MAX_FILE {
            return Err(FormatError::TooBig);
        }
        match method {
            Method::Stored if stored.len() as u64 != size => return Err(FormatError::BadEntry),
            Method::Deflate => {
                let n = self::size(size)?;
                let mut out = alloc::vec![0u8; n];
                let got = inflate::inflate_into(&stored, &mut out).map_err(FormatError::BadData)?;
                if got != n {
                    return Err(FormatError::BadData(inflate::Error::Truncated));
                }
            }
            Method::Stored => {}
        }
        self.files.push((String::from(path), method, stored, size));
        Ok(())
    }

    /// The paths added so far.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(|f| f.0.as_str())
    }

    pub fn finish(mut self) -> Result<Vec<u8>, FormatError> {
        if self.meta.is_empty() || self.meta.len() > MAX_META {
            return Err(FormatError::NoMeta);
        }
        if self.files.len() + 1 > MAX_FILES {
            return Err(FormatError::BadLayout);
        }
        self.files.sort_by(|a, b| path::cmp_folded(&a.0, &b.0));
        let meta_len = self.meta.len() as u64;
        let mut entries: Vec<(&str, Method, &[u8], u64)> = Vec::with_capacity(self.files.len() + 1);
        entries.push((META, Method::Stored, &self.meta, meta_len));
        for (p, m, s, n) in &self.files {
            entries.push((p.as_str(), *m, s.as_slice(), *n));
        }
        let count = entries.len();
        let names_len: usize = entries.iter().map(|e| e.0.len()).sum();
        let data_len: usize = entries.iter().map(|e| e.2.len()).sum();
        let names_off = HEADER_SIZE + count * ENTRY_SIZE;
        let data_off = names_off + names_len;
        let total = data_off + data_len;
        if total as u64 > MAX_PACKAGE {
            return Err(FormatError::TooBig);
        }
        let mut out = alloc::vec![0u8; total];
        out[..8].copy_from_slice(&MAGIC);
        out[H_FORMAT_VERSION..H_FORMAT_VERSION + 2].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out[H_HEADER_SIZE..H_HEADER_SIZE + 2].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        out[H_TOTAL_SIZE..H_TOTAL_SIZE + 8].copy_from_slice(&(total as u64).to_le_bytes());
        out[H_FILE_COUNT..H_FILE_COUNT + 4].copy_from_slice(&(count as u32).to_le_bytes());
        out[H_TABLE_OFF..H_TABLE_OFF + 4].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        out[H_NAMES_OFF..H_NAMES_OFF + 4].copy_from_slice(&(names_off as u32).to_le_bytes());
        out[H_NAMES_LEN..H_NAMES_LEN + 4].copy_from_slice(&(names_len as u32).to_le_bytes());
        out[H_DATA_OFF..H_DATA_OFF + 8].copy_from_slice(&(data_off as u64).to_le_bytes());
        out[H_DATA_LEN..H_DATA_LEN + 8].copy_from_slice(&(data_len as u64).to_le_bytes());
        let (mut name_at, mut data_at) = (0usize, 0usize);
        for (i, (p, m, s, n)) in entries.iter().enumerate() {
            let at = HEADER_SIZE + i * ENTRY_SIZE;
            out[at + E_NAME_OFF..at + E_NAME_OFF + 4].copy_from_slice(&(name_at as u32).to_le_bytes());
            out[at + E_NAME_LEN..at + E_NAME_LEN + 2].copy_from_slice(&(p.len() as u16).to_le_bytes());
            out[at + E_METHOD] = *m as u8;
            out[at + E_DATA_OFF..at + E_DATA_OFF + 8].copy_from_slice(&(data_at as u64).to_le_bytes());
            out[at + E_STORED..at + E_STORED + 8].copy_from_slice(&(s.len() as u64).to_le_bytes());
            out[at + E_SIZE..at + E_SIZE + 8].copy_from_slice(&n.to_le_bytes());
            out[names_off + name_at..names_off + name_at + p.len()].copy_from_slice(p.as_bytes());
            out[data_off + data_at..data_off + data_at + s.len()].copy_from_slice(s);
            name_at += p.len();
            data_at += s.len();
        }
        Package::parse(&out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// "Hello, NanoChronometer! Hello, NanoChronometer!" as raw DEFLATE
    /// (zlib, fixed Huffman).
    const HELLO_DEFLATE: &str = "f348cdc9c9d751f04bcccb77ce28cacfcbcf4d2d492d5254f0c02e0e00";
    const HELLO: &[u8] = b"Hello, NanoChronometer! Hello, NanoChronometer!";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn sample() -> Vec<u8> {
        let mut b = Builder::new(br#"{"format":"ncpkg/2"}"#.to_vec());
        b.add_stored("res/icon.png", b"\x89PNG fake".to_vec()).unwrap();
        b.add_stored("ncapp/x86_64/main.ncapp", b"x86 module".to_vec()).unwrap();
        b.add_raw("ncapp/aarch64/main.ncapp", Method::Deflate, unhex(HELLO_DEFLATE), HELLO.len() as u64).unwrap();
        b.add_stored("lib/x86_64/libfoo.ncdyn", b"lib".to_vec()).unwrap();
        b.add_stored("res/empty", Vec::new()).unwrap();
        b.finish().unwrap()
    }

    #[test]
    fn builds_parses_and_finds() {
        let bytes = sample();
        let pkg = Package::parse(&bytes).unwrap();
        assert_eq!(pkg.file_count(), 6);
        assert_eq!(pkg.meta(), br#"{"format":"ncpkg/2"}"#);
        let order: Vec<&str> = pkg.files().map(|e| e.path).collect();
        assert_eq!(order, ["lib/x86_64/libfoo.ncdyn", "ncapp/aarch64/main.ncapp", "ncapp/x86_64/main.ncapp", "res/empty", "res/icon.png"]);
        let arm = pkg.app_entry(Arch::Aarch64, "main.ncapp").unwrap();
        assert_eq!(arm.method, Method::Deflate);
        assert_eq!(arm.read().unwrap(), HELLO);
        let mut buf = [0u8; 64];
        assert_eq!(arm.read_into(&mut buf).unwrap(), HELLO.len());
        assert_eq!(&buf[..HELLO.len()], HELLO);
        let mut window = [0u8; inflate::WINDOW];
        assert_eq!(arm.sha512(&mut window).unwrap(), crate::sha512::digest(HELLO));
        assert_eq!(pkg.find("res/icon.png").unwrap().read().unwrap(), b"\x89PNG fake");
        assert!(pkg.find("RES/ICON.PNG").is_none(), "find wants the exact spelling");
        assert!(pkg.find("res/nothing").is_none());
        assert!(pkg.app_entry(Arch::Riscv64, "main.ncapp").is_none());
        assert_eq!(pkg.find("res/empty").unwrap().size, 0);
        let mut tiny = [0u8; 4];
        assert_eq!(arm.read_into(&mut tiny), Err(FormatError::BufferTooSmall));
    }

    #[test]
    fn builder_refuses_what_a_reader_would() {
        let mut b = Builder::new(b"{}".to_vec());
        assert_eq!(b.add_stored("ncpkg.meta", Vec::new()), Err(FormatError::BadPath));
        assert_eq!(b.add_stored("../etc/passwd", Vec::new()), Err(FormatError::BadPath));
        assert_eq!(b.add_stored("bin/x", Vec::new()), Err(FormatError::BadPath));
        b.add_stored("res/A", Vec::new()).unwrap();
        assert_eq!(b.add_stored("res/a", Vec::new()), Err(FormatError::Duplicate));
        assert_eq!(b.add_raw("res/b", Method::Deflate, unhex(HELLO_DEFLATE), 3), Err(FormatError::BadData(inflate::Error::Overflow)));
        assert_eq!(b.add_raw("res/c", Method::Stored, b"abc".to_vec(), 4), Err(FormatError::BadEntry));
        assert_eq!(Builder::new(Vec::new()).finish(), Err(FormatError::NoMeta));
    }

    #[test]
    fn rebuilding_with_a_new_manifest_keeps_every_file() {
        let bytes = sample();
        let pkg = Package::parse(&bytes).unwrap();
        let again = pkg.with_meta(br#"{"format":"ncpkg/2","signed":{}}"#).unwrap();
        let pkg2 = Package::parse(&again).unwrap();
        assert_eq!(pkg2.meta(), br#"{"format":"ncpkg/2","signed":{}}"#);
        for (a, b) in pkg.files().zip(pkg2.files()) {
            assert_eq!((a.path, a.method, a.stored, a.size), (b.path, b.method, b.stored, b.size));
        }
    }

    fn set32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn set64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn each_rule_has_its_error() {
        let base = sample();
        let e1 = HEADER_SIZE + ENTRY_SIZE;
        let names_off = rd32(&base, H_NAMES_OFF).unwrap() as usize;
        let cases: &[(&str, &dyn Fn(&mut Vec<u8>), FormatError)] = &[
            ("short", &|b| b.truncate(40), FormatError::TooSmall),
            ("magic", &|b| b[0] = b'X', FormatError::BadMagic),
            ("version 1", &|b| b[H_FORMAT_VERSION] = 1, FormatError::BadVersion),
            ("flags", &|b| b[H_FLAGS] = 1, FormatError::BadVersion),
            ("reserved", &|b| b[H_RESERVED + 3] = 1, FormatError::BadVersion),
            ("total past the file", &|b| {
                let n = b.len() as u64;
                set64(b, H_TOTAL_SIZE, n + 1);
            }, FormatError::Truncated),
            ("total past the limit", &|b| set64(b, H_TOTAL_SIZE, MAX_PACKAGE + 1), FormatError::TooBig),
            ("no files", &|b| set32(b, H_FILE_COUNT, 0), FormatError::BadLayout),
            ("too many files", &|b| set32(b, H_FILE_COUNT, MAX_FILES as u32 + 1), FormatError::BadLayout),
            ("a gap after the names", &|b| {
                let n = rd32(b, H_NAMES_LEN).unwrap();
                set32(b, H_NAMES_LEN, n + 1);
            }, FormatError::BadLayout),
            ("data region short of the end", &|b| {
                let n = rd64(b, H_DATA_LEN).unwrap();
                set64(b, H_DATA_LEN, n - 1);
            }, FormatError::BadLayout),
            ("trailing byte inside total", &|b| {
                b.push(0);
                let t = b.len() as u64;
                set64(b, H_TOTAL_SIZE, t);
            }, FormatError::BadLayout),
            ("a body out of order", &|b| set64(b, e1 + E_DATA_OFF, 1), FormatError::BadLayout),
            ("a name out of order", &|b| set32(b, e1 + E_NAME_OFF, 1), FormatError::BadLayout),
            ("unknown method", &|b| b[e1 + E_METHOD] = 7, FormatError::BadEntry),
            ("stored with sizes that differ", &|b| set64(b, e1 + E_SIZE, 1), FormatError::BadEntry),
            ("entry flags", &|b| b[e1 + E_FLAGS] = 1, FormatError::BadVersion),
            ("manifest compressed", &|b| b[HEADER_SIZE + E_METHOD] = 1, FormatError::NoMeta),
            ("manifest renamed", &|b| b[names_off] = b'N', FormatError::NoMeta),
            ("a path with ..", &|b| {
                let at = names_off + META.len();
                b[at..at + 3].copy_from_slice(b"../");
            }, FormatError::BadPath),
            ("two paths out of order", &|b| {
                // "lib/…" → "res/…" sorts after "ncapp/…".
                let at = names_off + META.len();
                b[at..at + 3].copy_from_slice(b"res");
            }, FormatError::Duplicate),
        ];
        for (what, mutate, want) in cases {
            let mut b = base.clone();
            mutate(&mut b);
            assert_eq!(Package::parse(&b).err(), Some(*want), "{what}");
        }
        // Bytes after `total` (a padded read) are ignored.
        let mut padded = base.clone();
        padded.extend_from_slice(&[0u8; 100]);
        assert!(Package::parse(&padded).is_ok());
    }

    #[test]
    fn corrupted_packages_never_panic() {
        let base = sample();
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let nasty: [u64; 8] = [0, 1, 39, 40, 64, 0xFFFF, u32::MAX as u64, u64::MAX];
        let mut accepted = 0;
        let mut window = [0u8; inflate::WINDOW];
        for _ in 0..20_000 {
            let mut b = base.clone();
            for _ in 0..(next() % 3 + 1) {
                let r = next();
                if b.len() < 8 {
                    break;
                }
                match r % 4 {
                    0 => {
                        let at = (r >> 8) as usize % b.len();
                        b[at] ^= (r >> 40) as u8 | 1;
                    }
                    1 => {
                        let at = ((r >> 8) as usize % (b.len() / 8)) * 8;
                        set64(&mut b, at, nasty[(r >> 40) as usize % nasty.len()]);
                    }
                    2 => {
                        let at = ((r >> 8) as usize % (b.len() / 4)) * 4;
                        set32(&mut b, at, nasty[(r >> 40) as usize % nasty.len()] as u32);
                    }
                    _ => b.truncate((r >> 8) as usize % b.len()),
                }
            }
            if let Ok(pkg) = Package::parse(&b) {
                accepted += 1;
                let _ = pkg.meta();
                for e in pkg.files() {
                    let _ = e.read();
                    let _ = e.sha512(&mut window);
                    let _ = pkg.find(e.path);
                }
            }
        }
        assert!(accepted > 0);
    }
}
