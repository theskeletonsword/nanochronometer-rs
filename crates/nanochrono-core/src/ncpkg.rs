// SPDX-License-Identifier: Apache-2.0
//! The `.ncplu` package format: one download for every architecture.
//!
//! # Why a container
//!
//! An `.ncapp` is one app for one architecture — the flat module format the
//! loader maps (`crate::ncplu`, with an architecture and a kind in its
//! header). Shipping one file per architecture means a user downloads nine
//! times, or the wrong one, and a mirror lists nine files that differ in one
//! letter. A `.ncplu` holds them all: a manifest (title, version, licence,
//! creator), one `.ncapp` per architecture, the `.nsdyn` libraries they
//! share, and assets the packer copies once (icon, data) instead of once per
//! architecture. The loader picks the entry for its own architecture and
//! loads it exactly as if it had arrived alone.
//!
//! # The rules
//!
//! The same discipline as [`crate::ncplu`]: the header is [`HEADER_SIZE`]
//! bytes; `total_size` covers at least the header and at most the file, and
//! a package is at most [`MAX_PACKAGE`]; the signature block ends the file
//! exactly and everything loadable lies inside the signed region; every
//! count is capped ([`MAX_ENTRIES`], [`MAX_MANIFEST`]); entries lie inside
//! the signed region, do not overlap, and name a known [`Arch`](crate::ncplu::Arch)
//! and [`Kind`](crate::ncplu::Kind); the manifest names a title, a version
//! and a licence. Every number from the file is checked: a value that does
//! not fit is an error, never a wrap.
//!
//! The entries' bytes are *not* validated here — the loader parses the entry
//! it picked with [`crate::ncplu::Image::parse`], which checks all of it —
//! so a package with an entry for an architecture this kernel never runs
//! still parses: the bytes are opaque until selected.
//!
//! # Layout
//!
//! Little-endian throughout, matched byte for byte by the packer,
//! `tools/ncplu.py` (`pack-pkg`). Parsed field by field rather than cast
//! from a struct, so layout and padding cannot drift between the two.

use crate::ncplu::{Arch, Kind, DIGEST_LEN, SIGNATURE_LEN};

/// `b"NCPKG"`, an ESC to make it non-textual, then two NULs.
pub const MAGIC: [u8; 8] = *b"NCPKG\x1b\0\0";
/// The only format version this parses.
pub const FORMAT_VERSION: u16 = 1;
/// The kernel's export-table ABI, as in [`crate::ncplu`]: the entries were
/// built against it, and a package built against another is refused rather
/// than run against symbols that may have moved.
pub const ABI_VERSION: u32 = crate::ncplu::ABI_VERSION;
/// Fixed header size, in bytes.
pub const HEADER_SIZE: usize = 128;

// Header field offsets.
pub const H_MAGIC: usize = 0;
pub const H_FORMAT_VERSION: usize = 8;
pub const H_HEADER_SIZE: usize = 10;
pub const H_FLAGS: usize = 12;
pub const H_TOTAL_SIZE: usize = 16;
pub const H_ABI_VERSION: usize = 24;
pub const H_MANIFEST_OFF: usize = 28;
pub const H_MANIFEST_LEN: usize = 32;
pub const H_ENTRIES_OFF: usize = 36;
pub const H_ENTRIES_N: usize = 40;
pub const H_SIGNATURE_OFF: usize = 44;
pub const H_SIGNATURE_LEN: usize = 48;
/// The SHA-512 digest of the signed region, taken with this field zeroed.
pub const H_DIGEST: usize = 52;
pub const H_STRINGS_OFF: usize = 116;
pub const H_STRINGS_LEN: usize = 120;
// 124..128: reserved, zero.

// One entry's fields, relative to its start.
pub const E_ARCH: usize = 0;
pub const E_KIND: usize = 2;
pub const E_FLAGS: usize = 4;
pub const E_OFFSET: usize = 8;
pub const E_SIZE: usize = 16;
pub const E_NAME_OFF: usize = 24;
pub const E_NAME_LEN: usize = 28;
// 32..40: reserved, zero.
/// One entry's size, in bytes.
pub const ENTRY_SIZE: usize = 40;

/// Limits well beyond any real package; they bound every loop and every size.
/// Sixteen entries cover nine architectures with room for shared libraries.
pub const MAX_PACKAGE: usize = 8 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 16;
pub const MAX_MANIFEST: usize = 4096;
pub const MAX_NAME: usize = 128;

/// Why a package was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    TooSmall,
    BadMagic,
    BadVersion,
    AbiMismatch,
    TooBig,
    Truncated,
    BadSignatureBlock,
    BadTable,
    BadManifest,
    /// An entry names no known architecture or kind, or two entries overlap.
    BadEntry,
    /// No entry for the requested architecture and kind.
    NoEntry,
}

impl FormatError {
    pub const fn message(self) -> &'static str {
        match self {
            FormatError::TooSmall => "file shorter than a header",
            FormatError::BadMagic => "not an .ncplu package (bad magic)",
            FormatError::BadVersion => "unsupported .ncplu package version",
            FormatError::AbiMismatch => "built against a different kernel ABI",
            FormatError::TooBig => "package larger than the package buffer",
            FormatError::Truncated => "a field points past the end of the file",
            FormatError::BadSignatureBlock => "the signature block is not at the end of the file",
            FormatError::BadTable => "a table runs outside the signed region, or is too long",
            FormatError::BadManifest => "the manifest is missing a field or malformed",
            FormatError::BadEntry => "an entry is unknown, overlaps another, or out of range",
            FormatError::NoEntry => "no entry for this architecture",
        }
    }
}

// Checked little-endian reads: `None` rather than a panic, whatever `at` is.
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
/// A file-supplied 32-bit offset or size, as `usize`.
fn rdsize(b: &[u8], at: usize) -> Result<usize, FormatError> {
    usize::try_from(rd32(b, at)?).map_err(|_| FormatError::TooBig)
}

/// `[off, off + len)` as a checked range.
fn span(off: usize, len: usize) -> Option<core::ops::Range<usize>> {
    Some(off..off.checked_add(len)?)
}

/// One validated entry: a module for one architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub arch: Arch,
    pub kind: Kind,
    /// Offset and length of the entry's bytes (a whole `.ncapp`, `.nsdyn`
    /// or asset) inside the package.
    pub offset: usize,
    pub size: usize,
    /// The entry's file name (`app.x86_64.ncapp`), as a range in the string
    /// table.
    pub name: (usize, usize),
}

/// The manifest's fields, as string ranges into its bytes.
#[derive(Debug, Clone, Copy)]
pub struct Manifest<'a> {
    bytes: &'a [u8],
    title: (usize, usize),
    version: (usize, usize),
    license: (usize, usize),
    creator: Option<(usize, usize)>,
    description: Option<(usize, usize)>,
}

impl<'a> Manifest<'a> {
    fn at(&self, range: (usize, usize)) -> &'a str {
        self.bytes.get(range.0..range.1).and_then(|b| core::str::from_utf8(b).ok()).unwrap_or("")
    }

    pub fn title(&self) -> &'a str {
        self.at(self.title)
    }
    pub fn version(&self) -> &'a str {
        self.at(self.version)
    }
    /// The SPDX identifier (or `X OR Y` dual licence, or `Proprietary`).
    pub fn license(&self) -> &'a str {
        self.at(self.license)
    }
    /// `None` when no creator is given: anonymous, which the launch card
    /// flags as suspicious for a ring-0 plugin or a driver — it still runs.
    pub fn creator(&self) -> Option<&'a str> {
        self.creator.map(|r| self.at(r))
    }
    pub fn description(&self) -> Option<&'a str> {
        self.description.map(|r| self.at(r))
    }
}

/// What a licence identifier means, in one line for newcomers. Dual
/// licences (`MIT OR Apache-2.0`) explain each half.
pub fn license_explain(license: &str) -> &'static str {
    let license = license.trim();
    // A dual licence explains its halves; an unknown half falls through to
    // the unknown-licence line rather than claiming to explain it.
    if let Some((a, b)) = license.split_once(" OR ") {
        return match (license_explain(a), license_explain(b)) {
            ("", _) | (_, "") => "",
            _ => "a choice of two licences — either half's terms apply",
        };
    }
    match license {
        "CC0-1.0" => "public domain: do anything, no conditions",
        "MIT" => "do anything, keep the copyright notice",
        "Apache-2.0" => "do anything, keep notices, grant patents back",
        "BSD-2-Clause" => "do anything, keep the copyright notice",
        "BSD-3-Clause" => "do anything, keep the notice, no endorsement",
        "GPL-2.0" | "GPL-3.0" => "share alike: derivatives stay GPL",
        "AGPL-3.0" => "share alike, including over a network",
        "LGPL-2.1" | "LGPL-3.0" => "share alike for the library itself",
        "Proprietary" => "all rights reserved: no licence to copy",
        _ => "",
    }
}

/// A package that passed every check. Its accessors re-read entries with the
/// same validation `parse` ran, so they return errors rather than trusting
/// the earlier pass.
#[derive(Debug, Clone, Copy)]
pub struct Package<'a> {
    bytes: &'a [u8],
    manifest: Manifest<'a>,
    /// Length of the signed region: everything before the signature block.
    pub signed_len: usize,
    signature_len: usize,
    entries_off: usize,
    entries_n: usize,
    strings: (usize, usize),
}

impl<'a> Package<'a> {
    /// Validates everything. See the module docs for the rules.
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
            || file.get(124..128) != Some(&[0u8; 4][..])
        {
            return Err(FormatError::BadVersion);
        }
        if rd32(file, H_ABI_VERSION)? != ABI_VERSION {
            return Err(FormatError::AbiMismatch);
        }

        let total = usize::try_from(rd64(file, H_TOTAL_SIZE)?).map_err(|_| FormatError::TooBig)?;
        if total < HEADER_SIZE {
            return Err(FormatError::TooSmall);
        }
        if total > MAX_PACKAGE {
            return Err(FormatError::TooBig);
        }
        let bytes = file.get(..total).ok_or(FormatError::Truncated)?;

        let manifest_off = rdsize(bytes, H_MANIFEST_OFF)?;
        let manifest_len = rdsize(bytes, H_MANIFEST_LEN)?;
        if manifest_len == 0 || manifest_len > MAX_MANIFEST {
            return Err(FormatError::BadManifest);
        }
        let manifest_range = span(manifest_off, manifest_len).ok_or(FormatError::BadManifest)?;

        let entries_off = rdsize(bytes, H_ENTRIES_OFF)?;
        let entries_n = rdsize(bytes, H_ENTRIES_N)?;
        if entries_n == 0 || entries_n > MAX_ENTRIES {
            return Err(FormatError::BadTable);
        }
        let entries_len = entries_n.checked_mul(ENTRY_SIZE).ok_or(FormatError::BadTable)?;
        let entries_range = span(entries_off, entries_len).ok_or(FormatError::BadTable)?;

        let strings_off = rdsize(bytes, H_STRINGS_OFF)?;
        let strings_len = rdsize(bytes, H_STRINGS_LEN)?;
        let strings = span(strings_off, strings_len).ok_or(FormatError::BadTable)?;

        // The signature block ends the file: either the reserved block, or
        // (from a packer that reserves none) nothing at all.
        let sig_off = rdsize(bytes, H_SIGNATURE_OFF)?;
        let sig_len = rdsize(bytes, H_SIGNATURE_LEN)?;
        let block_fits = sig_off >= HEADER_SIZE && sig_off.checked_add(sig_len) == Some(total);
        if !block_fits || (sig_len != 0 && sig_len != SIGNATURE_LEN) {
            return Err(FormatError::BadSignatureBlock);
        }
        let signed_len = sig_off;

        // Every table lies inside the signed region — nothing loadable sits
        // outside what a signature covers.
        for range in [manifest_range.clone(), entries_range, strings.clone()] {
            if range.start < HEADER_SIZE || range.end > signed_len {
                return Err(FormatError::BadTable);
            }
        }

        let manifest_bytes = bytes.get(manifest_range).ok_or(FormatError::BadManifest)?;
        let manifest = Manifest::parse(manifest_bytes)?;

        let mut pkg = Package {
            bytes,
            manifest,
            signed_len,
            signature_len: sig_len,
            entries_off,
            entries_n,
            strings: (strings.start, strings.end),
        };

        // Every entry on its own, then every pair for overlap.
        for i in 0..entries_n {
            let a = pkg.entry(i)?;
            for j in 0..i {
                let b = pkg.entry(j)?;
                if a.offset < b.offset + b.size && b.offset < a.offset + a.size {
                    return Err(FormatError::BadEntry);
                }
            }
        }
        Ok(pkg)
    }

    /// The whole package (`total_size` bytes).
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The signed region: everything before the signature block.
    pub fn signed(&self) -> &'a [u8] {
        self.bytes.get(..self.signed_len).unwrap_or(&[])
    }

    /// The signature block, if the package reserves one.
    pub fn signature_block(&self) -> Option<&'a [u8]> {
        (self.signature_len == SIGNATURE_LEN).then(|| self.bytes.get(self.signed_len..)).flatten()
    }

    /// The digest the packer recorded in the header.
    pub fn header_digest(&self) -> &'a [u8] {
        self.bytes.get(H_DIGEST..H_DIGEST + DIGEST_LEN).unwrap_or(&[])
    }

    pub fn manifest(&self) -> Manifest<'a> {
        self.manifest
    }

    pub fn entry_count(&self) -> usize {
        self.entries_n
    }

    /// Entry `i`, validated.
    pub fn entry(&self, i: usize) -> Result<Entry, FormatError> {
        if i >= self.entries_n {
            return Err(FormatError::BadEntry);
        }
        let at = self.entries_off + i * ENTRY_SIZE;
        let arch = Arch::from_u16(rd16(self.bytes, at + E_ARCH)?).ok_or(FormatError::BadEntry)?;
        let kind = Kind::from_u16(rd16(self.bytes, at + E_KIND)?).ok_or(FormatError::BadEntry)?;
        if rd32(self.bytes, at + E_FLAGS)? != 0 || self.bytes.get(at + 32..at + 40) != Some(&[0u8; 8][..]) {
            return Err(FormatError::BadVersion);
        }
        let offset = usize::try_from(rd64(self.bytes, at + E_OFFSET)?).map_err(|_| FormatError::BadEntry)?;
        let size = usize::try_from(rd64(self.bytes, at + E_SIZE)?).map_err(|_| FormatError::BadEntry)?;
        let name_off = rdsize(self.bytes, at + E_NAME_OFF)?;
        let name_len = rdsize(self.bytes, at + E_NAME_LEN)?;
        if name_len == 0 || name_len > MAX_NAME {
            return Err(FormatError::BadEntry);
        }
        let name = span(name_off, name_len).ok_or(FormatError::BadEntry)?;
        if name.start < self.strings.0 || name.end > self.strings.1 {
            return Err(FormatError::BadEntry);
        }
        if core::str::from_utf8(self.bytes.get(name.clone()).unwrap_or(&[])).is_err() {
            return Err(FormatError::BadEntry);
        }
        let body = span(offset, size).ok_or(FormatError::BadEntry)?;
        if size == 0 || body.start < HEADER_SIZE || body.end > self.signed_len {
            return Err(FormatError::BadEntry);
        }
        Ok(Entry { arch, kind, offset, size, name: (name.start, name.end) })
    }

    /// The entry's file name (`app.x86_64.ncapp`).
    pub fn entry_name(&self, entry: &Entry) -> &'a str {
        self.bytes
            .get(entry.name.0..entry.name.1)
            .and_then(|b| core::str::from_utf8(b).ok())
            .unwrap_or("")
    }

    /// The entry's bytes: a whole module for [`crate::ncplu::Image::parse`].
    pub fn entry_bytes(&self, entry: &Entry) -> Result<&'a [u8], FormatError> {
        self.bytes.get(entry.offset..entry.offset + entry.size).ok_or(FormatError::BadEntry)
    }

    /// The first entry for `arch` and `kind`: what the loader maps.
    pub fn select(&self, arch: Arch, kind: Kind) -> Result<Entry, FormatError> {
        for i in 0..self.entries_n {
            let e = self.entry(i)?;
            if e.arch == arch && e.kind == kind {
                return Ok(e);
            }
        }
        Err(FormatError::NoEntry)
    }
}

impl<'a> Manifest<'a> {
    /// Parses `key: value` lines. `title`, `version` and `license` are
    /// required; `creator` and `description` are optional.
    fn parse(bytes: &'a [u8]) -> Result<Manifest<'a>, FormatError> {
        let text = core::str::from_utf8(bytes).map_err(|_| FormatError::BadManifest)?;
        let base = bytes.as_ptr() as usize;
        let mut manifest = Manifest { bytes, title: (0, 0), version: (0, 0), license: (0, 0), creator: None, description: None };
        let mut have = 0u32;
        for line in text.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                return Err(FormatError::BadManifest);
            };
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() || value.len() > 256 {
                return Err(FormatError::BadManifest);
            }
            if !key.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') || key.len() > 32 {
                return Err(FormatError::BadManifest);
            }
            let off = value.as_ptr() as usize - base;
            let range = (off, off + value.len());
            match key {
                "title" => {
                    manifest.title = range;
                    have |= 1;
                }
                "version" => {
                    manifest.version = range;
                    have |= 2;
                }
                "license" => {
                    manifest.license = range;
                    have |= 4;
                }
                "creator" => manifest.creator = Some(range),
                "description" => manifest.description = Some(range),
                _ => return Err(FormatError::BadManifest),
            }
        }
        if have != 7 {
            return Err(FormatError::BadManifest);
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    const APP_X64: &[u8] = b"fake module for x86_64";
    const APP_ARM: &[u8] = b"fake module for aarch64, a bit longer";
    const LIB_X64: &[u8] = b"fake shared library";

    fn manifest_bytes() -> Vec<u8> {
        b"title: Snake\nversion: 1.2.0\nlicense: MIT\ncreator: Someone\ndescription: A game\n".to_vec()
    }

    /// A minimal valid package: manifest, two apps, one library, names, then
    /// the reserved signature block.
    fn build() -> Vec<u8> {
        let manifest = manifest_bytes();
        let names = b"snake.x86_64.ncapp\0snake.aarch64.ncapp\0libsnake.x86_64.nsdyn\0";
        let n0 = 0usize;
        let n1 = 19usize;
        let n2 = 39usize;

        let entries_off = HEADER_SIZE;
        let entries_n = 3usize;
        let manifest_off = entries_off + entries_n * ENTRY_SIZE;
        let strings_off = manifest_off + manifest.len();
        let m0 = strings_off + names.len();
        let m1 = m0 + APP_X64.len();
        let m2 = m1 + APP_ARM.len();
        let m3 = m2 + LIB_X64.len();
        let sig_off = m3;
        let total = sig_off + SIGNATURE_LEN;

        let mut b = vec![0u8; total];
        b[..8].copy_from_slice(&MAGIC);
        b[H_FORMAT_VERSION..H_FORMAT_VERSION + 2].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        b[H_HEADER_SIZE..H_HEADER_SIZE + 2].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        b[H_TOTAL_SIZE..H_TOTAL_SIZE + 8].copy_from_slice(&(total as u64).to_le_bytes());
        b[H_ABI_VERSION..H_ABI_VERSION + 4].copy_from_slice(&ABI_VERSION.to_le_bytes());
        b[H_MANIFEST_OFF..H_MANIFEST_OFF + 4].copy_from_slice(&(manifest_off as u32).to_le_bytes());
        b[H_MANIFEST_LEN..H_MANIFEST_LEN + 4].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
        b[H_ENTRIES_OFF..H_ENTRIES_OFF + 4].copy_from_slice(&(entries_off as u32).to_le_bytes());
        b[H_ENTRIES_N..H_ENTRIES_N + 4].copy_from_slice(&(entries_n as u32).to_le_bytes());
        b[H_SIGNATURE_OFF..H_SIGNATURE_OFF + 4].copy_from_slice(&(sig_off as u32).to_le_bytes());
        b[H_SIGNATURE_LEN..H_SIGNATURE_LEN + 4].copy_from_slice(&(SIGNATURE_LEN as u32).to_le_bytes());
        b[H_STRINGS_OFF..H_STRINGS_OFF + 4].copy_from_slice(&(strings_off as u32).to_le_bytes());
        b[H_STRINGS_LEN..H_STRINGS_LEN + 4].copy_from_slice(&(names.len() as u32).to_le_bytes());

        let mut entry = |i: usize, arch: Arch, kind: Kind, off: usize, size: usize, name: (usize, usize)| {
            let at = entries_off + i * ENTRY_SIZE;
            b[at..at + 2].copy_from_slice(&(arch as u16).to_le_bytes());
            b[at + 2..at + 4].copy_from_slice(&(kind as u16).to_le_bytes());
            b[at + 8..at + 16].copy_from_slice(&(off as u64).to_le_bytes());
            b[at + 16..at + 24].copy_from_slice(&(size as u64).to_le_bytes());
            b[at + 24..at + 28].copy_from_slice(&((strings_off + name.0) as u32).to_le_bytes());
            b[at + 28..at + 32].copy_from_slice(&((name.1 - name.0) as u32).to_le_bytes());
        };
        entry(0, Arch::X86_64, Kind::App, m0, APP_X64.len(), (n0, n1 - 1));
        entry(1, Arch::Aarch64, Kind::App, m1, APP_ARM.len(), (n1, n2 - 1));
        entry(2, Arch::X86_64, Kind::Library, m2, LIB_X64.len(), (n2, names.len() - 1));

        b[manifest_off..manifest_off + manifest.len()].copy_from_slice(&manifest);
        b[strings_off..strings_off + names.len()].copy_from_slice(names);
        b[m0..m0 + APP_X64.len()].copy_from_slice(APP_X64);
        b[m1..m1 + APP_ARM.len()].copy_from_slice(APP_ARM);
        b[m2..m2 + LIB_X64.len()].copy_from_slice(LIB_X64);
        b
    }

    #[test]
    fn a_well_formed_package_parses_and_selects() {
        let b = build();
        let pkg = Package::parse(&b).expect("valid package");
        assert_eq!(pkg.entry_count(), 3);
        assert_eq!(pkg.manifest().title(), "Snake");
        assert_eq!(pkg.manifest().version(), "1.2.0");
        assert_eq!(pkg.manifest().license(), "MIT");
        assert_eq!(pkg.manifest().creator(), Some("Someone"));
        let app = pkg.select(Arch::Aarch64, Kind::App).expect("aarch64 app");
        assert_eq!(pkg.entry_bytes(&app).unwrap(), APP_ARM);
        assert_eq!(pkg.entry_name(&app), "snake.aarch64.ncapp");
        let lib = pkg.select(Arch::X86_64, Kind::Library).expect("x86_64 library");
        assert_eq!(pkg.entry_bytes(&lib).unwrap(), LIB_X64);
        assert_eq!(pkg.select(Arch::Riscv64, Kind::App).err(), Some(FormatError::NoEntry));
        assert!(pkg.signature_block().is_some());
    }

    #[test]
    fn licences_explain_themselves() {
        assert!(license_explain("MIT").contains("copyright"));
        assert!(license_explain("Proprietary").contains("rights reserved"));
        assert!(license_explain("MIT OR Apache-2.0").contains("choice"));
        assert_eq!(license_explain("WTFPL"), "");
    }

    #[test]
    fn each_rule_has_its_error() {
        let base = build();
        let set32 = |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let cases: &[(&str, &dyn Fn(&mut Vec<u8>), FormatError)] = &[
            ("total below the header", &|b| b[H_TOTAL_SIZE..H_TOTAL_SIZE + 8].copy_from_slice(&40u64.to_le_bytes()), FormatError::TooSmall),
            ("total past the buffer", &|b| b[H_TOTAL_SIZE..H_TOTAL_SIZE + 8].copy_from_slice(&u64::MAX.to_le_bytes()), FormatError::TooBig),
            ("signature not at the end", &|b| set32(b, H_SIGNATURE_OFF, 200), FormatError::BadSignatureBlock),
            ("too many entries", &|b| set32(b, H_ENTRIES_N, (MAX_ENTRIES + 1) as u32), FormatError::BadTable),
            ("manifest outside the signed region", &|b| set32(b, H_MANIFEST_OFF, u32::MAX - 8), FormatError::BadTable),
            ("manifest without a licence", &|b| {
                let m = manifest_bytes();
                // Blank the licence value: "license: MIT" -> "license:   ".
                if let Some(at) = m.windows(13).position(|w| w == b"license: MIT\n") {
                    let off = rdsize(b, H_MANIFEST_OFF).unwrap() + at + 9;
                    b[off..off + 3].copy_from_slice(b"   ");
                }
            }, FormatError::BadManifest),
            ("unknown entry arch", &|b| b[HEADER_SIZE..HEADER_SIZE + 2].copy_from_slice(&0xFFu16.to_le_bytes()), FormatError::BadEntry),
            ("overlapping entries", &|b| {
                let e0 = rdsize(b, H_ENTRIES_OFF).unwrap();
                let off0 = b[e0 + 8..e0 + 16].to_vec();
                b[e0 + ENTRY_SIZE + 8..e0 + ENTRY_SIZE + 16].copy_from_slice(&off0);
            }, FormatError::BadEntry),
            ("entry outside the signed region", &|b| {
                let e0 = rdsize(b, H_ENTRIES_OFF).unwrap();
                b[e0 + 8..e0 + 16].copy_from_slice(&u64::MAX.to_le_bytes());
            }, FormatError::BadEntry),
        ];
        for (what, mutate, expected) in cases {
            let mut b = base.clone();
            mutate(&mut b);
            assert_eq!(Package::parse(&b).err(), Some(*expected), "{what}");
        }
    }

    #[test]
    fn real_packer_output_parses() {
        // `NCPKG_FILES=a.NCPLU:b.NCPLU cargo test real_packer_output` checks
        // packages packed by tools/ncplu.py against these rules; without the
        // variable there is nothing to read and the test passes vacuously.
        let Ok(list) = std::env::var("NCPKG_FILES") else { return };
        for path in list.split(':').filter(|p| !p.is_empty()) {
            let bytes = std::fs::read(path).unwrap();
            let pkg = Package::parse(&bytes).unwrap_or_else(|e| panic!("{path}: {}", e.message()));
            for i in 0..pkg.entry_count() {
                let e = pkg.entry(i).unwrap();
                let _ = pkg.entry_bytes(&e).unwrap();
                let _ = pkg.entry_name(&e);
            }
            std::println!("{path}: ok, {} entries", pkg.entry_count());
        }
    }

    #[test]
    fn corrupted_packages_never_panic() {
        let base = build();
        let nasty: [u8; 8] = [0, 1, 7, 40, 127, 128, 200, 255];
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut accepted = 0;
        for _ in 0..20_000 {
            let mut b = base.clone();
            for _ in 0..(next() % 3 + 1) {
                let r = next();
                if b.len() < 4 {
                    break;
                }
                match r % 3 {
                    0 => {
                        let at = (r >> 8) as usize % b.len();
                        b[at] ^= nasty[(r >> 40) as usize % nasty.len()] | 1;
                    }
                    1 => {
                        let at = ((r >> 8) as usize % (b.len() / 4)) * 4;
                        b[at] = nasty[(r >> 40) as usize % nasty.len()];
                    }
                    _ => {
                        let keep = (r >> 8) as usize % b.len();
                        b.truncate(keep);
                    }
                }
            }
            if let Ok(pkg) = Package::parse(&b) {
                for i in 0..pkg.entry_count() {
                    if let Ok(e) = pkg.entry(i) {
                        let _ = pkg.entry_bytes(&e);
                        let _ = pkg.entry_name(&e);
                    }
                }
                let _ = pkg.select(Arch::X86_64, Kind::App);
                accepted += 1;
            }
        }
        assert!(accepted > 0);
    }
}
