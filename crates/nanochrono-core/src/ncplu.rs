// SPDX-License-Identifier: Apache-2.0
//! The `.ncplu` plugin format, and a parser that checks all of it before
//! anything is loaded.
//!
//! # Why the parser lives here
//!
//! A `.ncplu` arrives on a USB stick: untrusted input, possibly crafted to
//! break the loader. The kernel copies it into a fixed arena and patches
//! pointers inside it, and for **any** byte sequence it must never write
//! outside that arena, read outside the file, or panic — a panic halts a
//! kernel. Rust's bounds checks turn a would-be overflow into a panic, which
//! is safer than silent corruption but is still a denial of service. So the
//! format is validated completely, up front, by code with no indexing that
//! can panic, and only an image that passes is ever copied. After
//! [`Image::parse`] succeeds, loading cannot fail except for a kernel symbol
//! lookup.
//!
//! `no_std` and pure, like [`crate::aml`] and [`crate::hid_report`]: the
//! freestanding kernel runs exactly this code, and the hosted test build
//! throws tens of thousands of corrupted images at it with overflow checks
//! on.
//!
//! # The rules
//!
//! * The header is [`HEADER_SIZE`] bytes; `total_size` covers at least the
//!   header and at most the file, and the image is at most [`MAX_IMAGE`].
//! * The signature block ends the file exactly. Everything before it is the
//!   *signed region*, and every table and every section's bytes lie inside
//!   that region — nothing that gets loaded can sit outside what a signature
//!   covers.
//! * Every count is capped ([`MAX_SECTIONS`], [`MAX_RELOCS`], …): a loop is
//!   bounded by the format, not by whatever a header claims.
//! * Sections lie inside the arena, do not overlap, respect their alignment,
//!   and `.bss` carries no file bytes.
//! * A relocation patches 8 bytes wholly inside one section that is not
//!   code — the loader never writes into `.text` — a `RELATIVE` one points
//!   inside the image, and an `IMPORT64` one names a declared import with no
//!   offset.
//! * The entry point is inside a code section's loaded bytes.
//!
//! Every piece of arithmetic on a number from the file is checked: a value
//! that does not fit is an error, never a wrap.
//!
//! # Layout
//!
//! Little-endian throughout, matched byte for byte by the packer,
//! `tools/ncplu.py`. Parsed field by field rather than cast from a struct,
//! so layout and padding cannot drift between the two.

/// `b"NCPLU"`, an ESC to make it non-textual, then two NULs.
pub const MAGIC: [u8; 8] = *b"NCPLU\x1b\0\0";
/// The only format version this parses.
pub const FORMAT_VERSION: u16 = 1;
/// The kernel's export-table ABI. A plugin built against another is refused
/// rather than run against symbols that may have moved.
pub const ABI_VERSION: u32 = 1;
/// Fixed header size, in bytes.
pub const HEADER_SIZE: usize = 160;

// Header field offsets.
pub const H_MAGIC: usize = 0;
pub const H_FORMAT_VERSION: usize = 8;
pub const H_HEADER_SIZE: usize = 10;
pub const H_FLAGS: usize = 12;
pub const H_TOTAL_SIZE: usize = 16;
pub const H_ABI_VERSION: usize = 24;
pub const H_ENTRY_EXPORT: usize = 28;
pub const H_SECTIONS_OFF: usize = 32;
pub const H_SECTIONS_N: usize = 36;
pub const H_IMPORTS_OFF: usize = 40;
pub const H_IMPORTS_N: usize = 44;
pub const H_EXPORTS_OFF: usize = 48;
pub const H_EXPORTS_N: usize = 52;
pub const H_RELOCS_OFF: usize = 56;
pub const H_RELOCS_N: usize = 60;
pub const H_STRINGS_OFF: usize = 64;
pub const H_STRINGS_LEN: usize = 68;
pub const H_SIGNATURE_OFF: usize = 72;
pub const H_SIGNATURE_LEN: usize = 76;
pub const H_ARENA_SIZE: usize = 80;
/// Requested capabilities (`CAP_*`), meaningful when `FLAG_HAS_CAPS` is set.
pub const H_CAPABILITIES: usize = 84;
/// The SHA-512 digest of the signed region, taken with this field zeroed.
pub const H_DIGEST: usize = 88;
pub const DIGEST_LEN: usize = 64;
// 152..160: pad.

/// Header flag: the plugin asks for privileged kernel symbols, which only an
/// officially signed plugin is granted.
pub const FLAG_WANTS_PRIVILEGED: u32 = 1 << 0;
/// The header's [`H_CAPABILITIES`] field is meaningful. A packer that predates
/// capabilities leaves it clear, and the loader then grants the full set.
pub const FLAG_HAS_CAPS: u32 = 1 << 1;

/// Capability bits: the groups of kernel services a plugin may reach. A plugin
/// declares the set it needs and the kernel grants no more, so a plugin — or a
/// bug or exploit in one — is confined to what it asked for. Kept in step with
/// `tools/ncplu.py` and the kernel's `nccall` dispatcher.
pub const CAP_SCREEN: u32 = 1 << 0; // fill_rect, clear, present
pub const CAP_INPUT: u32 = 1 << 1; // poll_event
pub const CAP_LOG: u32 = 1 << 2; // log
pub const CAP_TIMER: u32 = 1 << 3; // ticks, timer_*
pub const CAP_PMU: u32 = 1 << 4; // pmu_*
pub const CAP_RNG: u32 = 1 << 5; // rng_*
/// Every capability.
pub const CAP_ALL: u32 = CAP_SCREEN | CAP_INPUT | CAP_LOG | CAP_TIMER | CAP_PMU | CAP_RNG;

// The signature block. Both signatures are over the digest above.
pub const SIG_MAGIC: [u8; 4] = *b"NCS1";
pub const SIG_MLDSA_OFF: usize = 8;
/// ML-DSA-87 (FIPS 204) signature size.
pub const SIG_MLDSA_LEN: usize = 4627;
pub const SIG_P521_OFF: usize = SIG_MLDSA_OFF + SIG_MLDSA_LEN;
/// P-521 ECDSA raw signature: r ‖ s, 66 bytes each.
pub const SIG_P521_LEN: usize = 132;
/// The whole signature block.
pub const SIGNATURE_LEN: usize = SIG_P521_OFF + SIG_P521_LEN;
/// ML-DSA-87 verifying key, and P-521 SEC1 uncompressed public key.
pub const ROOT_MLDSA_LEN: usize = 2592;
pub const ROOT_P521_LEN: usize = 133;

// Table entry sizes.
pub const SECTION_SIZE: usize = 24;
pub const IMPORT_SIZE: usize = 16;
pub const EXPORT_SIZE: usize = 24;
pub const RELOC_SIZE: usize = 32;

// Section kinds, and relocation kinds.
pub const SECTION_TEXT: u8 = 1;
pub const SECTION_RODATA: u8 = 2;
pub const SECTION_DATA: u8 = 3;
pub const SECTION_BSS: u8 = 4;
/// `*(base + offset) = base + addend`: a pointer into the plugin's own image.
pub const RELOC_RELATIVE: u32 = 1;
/// `*(base + offset) = resolve(imports[sym])`: a kernel data symbol's address.
pub const RELOC_IMPORT64: u32 = 2;

/// Limits well beyond any real plugin; they bound every loop and every size.
/// The kernel's image buffer and arena are exactly these.
pub const MAX_IMAGE: usize = 512 * 1024;
pub const MAX_ARENA: usize = 1 << 20;
pub const MAX_SECTIONS: usize = 64;
pub const MAX_IMPORTS: usize = 256;
pub const MAX_EXPORTS: usize = 256;
pub const MAX_RELOCS: usize = 1 << 16;
pub const MAX_NAME: usize = 128;
pub const MAX_ALIGN: usize = 4096;

/// FNV-1a of a symbol name, stored beside each import and export so a name
/// that was corrupted in transit is caught at parse time.
pub const fn fnv1a(s: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    let mut i = 0;
    while i < s.len() {
        h ^= s[i] as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    h
}

/// Why an image was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    TooSmall,
    BadMagic,
    BadVersion,
    AbiMismatch,
    /// Larger than the image buffer or the arena.
    TooBig,
    /// A field points past the end of the file.
    Truncated,
    /// The signature block is not where the format puts it.
    BadSignatureBlock,
    /// A table is out of bounds, outside the signed region, or too long.
    BadTable,
    /// A section is out of the arena, misaligned, or of an unknown kind.
    BadSection,
    OverlappingSections,
    /// A relocation writes outside its section, into code, or points outside
    /// the image.
    BadRelocation,
    /// An import or export name is out of bounds or fails its hash.
    BadSymbol,
    /// No entry export, or one outside the code.
    NoEntry,
}

impl FormatError {
    pub const fn message(self) -> &'static str {
        match self {
            FormatError::TooSmall => "file shorter than a header",
            FormatError::BadMagic => "not an .ncplu (bad magic)",
            FormatError::BadVersion => "unsupported .ncplu format version",
            FormatError::AbiMismatch => "built against a different kernel ABI",
            FormatError::TooBig => "image larger than the plugin buffer or arena",
            FormatError::Truncated => "a field points past the end of the file",
            FormatError::BadSignatureBlock => "the signature block is not at the end of the file",
            FormatError::BadTable => "a table runs outside the signed region, or is too long",
            FormatError::BadSection => "a section is outside the arena, misaligned or unknown",
            FormatError::OverlappingSections => "two sections overlap in memory",
            FormatError::BadRelocation => "a relocation writes outside its section or into code",
            FormatError::BadSymbol => "a symbol name is out of bounds or corrupt",
            FormatError::NoEntry => "no entry point inside the code",
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

/// What a section is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Text,
    Rodata,
    Data,
    Bss,
}

/// A validated section: `[mem_off, mem_off + mem_size)` in the arena, the
/// first `file_size` bytes of which come from `[file_off, …)` in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub kind: SectionKind,
    pub mem_off: usize,
    pub mem_size: usize,
    pub file_off: usize,
    pub file_size: usize,
}

impl Section {
    fn contains(&self, range: &core::ops::Range<usize>) -> bool {
        self.mem_off <= range.start && range.end <= self.mem_off + self.mem_size
    }
}

/// A validated relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reloc {
    /// Write `base + target` at `offset`.
    Relative { offset: usize, target: usize },
    /// Write the address of kernel symbol `imports[import]` at `offset`.
    Import { offset: usize, import: usize },
}

#[derive(Debug, Clone, Copy)]
struct Table {
    off: usize,
    n: usize,
}

/// An image that passed every check. Its accessors re-read entries with the
/// same validation `parse` ran, so they return errors rather than trusting
/// the earlier pass — there is no path from file bytes to an unchecked index.
#[derive(Debug, Clone, Copy)]
pub struct Image<'a> {
    bytes: &'a [u8],
    pub flags: u32,
    /// The capabilities the plugin may use (`CAP_*`): the requested set when
    /// `FLAG_HAS_CAPS` is present, else the full set for an older plugin.
    pub capabilities: u32,
    /// Bytes of arena the image occupies.
    pub arena_size: usize,
    /// Length of the signed region: everything before the signature block.
    pub signed_len: usize,
    signature_len: usize,
    sections: Table,
    imports: Table,
    exports: Table,
    relocs: Table,
    /// The string table, as `(start, end)`.
    strings: (usize, usize),
    /// Arena offset of the entry point.
    pub entry: usize,
}

impl<'a> Image<'a> {
    /// Validates everything. See the module docs for the rules.
    pub fn parse(file: &'a [u8]) -> Result<Image<'a>, FormatError> {
        if file.len() < HEADER_SIZE {
            return Err(FormatError::TooSmall);
        }
        if file.get(H_MAGIC..H_MAGIC + 8) != Some(&MAGIC[..]) {
            return Err(FormatError::BadMagic);
        }
        if rd16(file, H_FORMAT_VERSION)? != FORMAT_VERSION
            || usize::from(rd16(file, H_HEADER_SIZE)?) != HEADER_SIZE
        {
            return Err(FormatError::BadVersion);
        }
        if rd32(file, H_ABI_VERSION)? != ABI_VERSION {
            return Err(FormatError::AbiMismatch);
        }

        // The file's own length claim: at least a header (the rest of the
        // header is read from the trimmed slice), at most what was read.
        let total = usize::try_from(rd64(file, H_TOTAL_SIZE)?).map_err(|_| FormatError::TooBig)?;
        if total < HEADER_SIZE {
            return Err(FormatError::TooSmall);
        }
        if total > MAX_IMAGE {
            return Err(FormatError::TooBig);
        }
        let bytes = file.get(..total).ok_or(FormatError::Truncated)?;

        let arena_size = rdsize(bytes, H_ARENA_SIZE)?;
        if arena_size == 0 || arena_size > MAX_ARENA {
            return Err(FormatError::TooBig);
        }

        // The signature block ends the file: either the reserved block, or
        // (from a packer that reserves none) nothing at all.
        let sig_off = rdsize(bytes, H_SIGNATURE_OFF)?;
        let sig_len = rdsize(bytes, H_SIGNATURE_LEN)?;
        let block_fits = sig_off >= HEADER_SIZE && sig_off.checked_add(sig_len) == Some(total);
        if !block_fits || (sig_len != 0 && sig_len != SIGNATURE_LEN) {
            return Err(FormatError::BadSignatureBlock);
        }
        let signed_len = sig_off;

        let table = |off_at: usize, n_at: usize, entry: usize, max: usize| -> Result<Table, FormatError> {
            let off = rdsize(bytes, off_at)?;
            let n = rdsize(bytes, n_at)?;
            if n > max {
                return Err(FormatError::BadTable);
            }
            if n > 0 {
                let len = n.checked_mul(entry).ok_or(FormatError::BadTable)?;
                let range = span(off, len).ok_or(FormatError::BadTable)?;
                if range.start < HEADER_SIZE || range.end > signed_len {
                    return Err(FormatError::BadTable);
                }
            }
            Ok(Table { off, n })
        };
        let sections = table(H_SECTIONS_OFF, H_SECTIONS_N, SECTION_SIZE, MAX_SECTIONS)?;
        let imports = table(H_IMPORTS_OFF, H_IMPORTS_N, IMPORT_SIZE, MAX_IMPORTS)?;
        let exports = table(H_EXPORTS_OFF, H_EXPORTS_N, EXPORT_SIZE, MAX_EXPORTS)?;
        let relocs = table(H_RELOCS_OFF, H_RELOCS_N, RELOC_SIZE, MAX_RELOCS)?;

        let strings_off = rdsize(bytes, H_STRINGS_OFF)?;
        let strings_len = rdsize(bytes, H_STRINGS_LEN)?;
        let strings = span(strings_off, strings_len).ok_or(FormatError::BadTable)?;
        if strings_len > 0 && (strings.start < HEADER_SIZE || strings.end > signed_len) {
            return Err(FormatError::BadTable);
        }

        let mut image = Image {
            bytes,
            flags: rd32(bytes, H_FLAGS)?,
            capabilities: {
                let flags = rd32(bytes, H_FLAGS)?;
                if flags & FLAG_HAS_CAPS != 0 {
                    rd32(bytes, H_CAPABILITIES)? & CAP_ALL
                } else {
                    CAP_ALL
                }
            },
            arena_size,
            signed_len,
            signature_len: sig_len,
            sections,
            imports,
            exports,
            relocs,
            strings: (strings.start, strings.end),
            entry: 0,
        };

        // Every section on its own, then every pair for overlap.
        for i in 0..sections.n {
            let a = image.section(i)?;
            for j in 0..i {
                let b = image.section(j)?;
                if a.mem_off < b.mem_off + b.mem_size && b.mem_off < a.mem_off + a.mem_size {
                    return Err(FormatError::OverlappingSections);
                }
            }
        }
        for i in 0..imports.n {
            image.import_name(i)?;
        }
        for i in 0..exports.n {
            image.export(i)?;
        }
        for i in 0..relocs.n {
            image.reloc(i)?;
        }

        // The entry: a declared export, inside a code section's file bytes.
        let entry_index = rdsize(bytes, H_ENTRY_EXPORT)?;
        if entry_index >= exports.n {
            return Err(FormatError::NoEntry);
        }
        let (_, entry) = image.export(entry_index)?;
        let mut in_code = false;
        for i in 0..sections.n {
            let s = image.section(i)?;
            if s.kind == SectionKind::Text && s.mem_off <= entry && entry < s.mem_off + s.file_size {
                in_code = true;
            }
        }
        if !in_code {
            return Err(FormatError::NoEntry);
        }
        image.entry = entry;
        Ok(image)
    }

    /// The whole image (`total_size` bytes).
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The signed region: everything before the signature block.
    pub fn signed(&self) -> &'a [u8] {
        self.bytes.get(..self.signed_len).unwrap_or(&[])
    }

    /// The signature block, if the image reserves one.
    pub fn signature_block(&self) -> Option<&'a [u8]> {
        (self.signature_len == SIGNATURE_LEN).then(|| self.bytes.get(self.signed_len..)).flatten()
    }

    /// The digest the packer recorded in the header.
    pub fn header_digest(&self) -> &'a [u8] {
        self.bytes.get(H_DIGEST..H_DIGEST + DIGEST_LEN).unwrap_or(&[])
    }

    pub fn section_count(&self) -> usize {
        self.sections.n
    }

    pub fn reloc_count(&self) -> usize {
        self.relocs.n
    }

    pub fn import_count(&self) -> usize {
        self.imports.n
    }

    /// Section `i`, validated.
    pub fn section(&self, i: usize) -> Result<Section, FormatError> {
        if i >= self.sections.n {
            return Err(FormatError::BadSection);
        }
        let at = self.sections.off + i * SECTION_SIZE;
        let kind = match self.bytes.get(at).copied() {
            Some(SECTION_TEXT) => SectionKind::Text,
            Some(SECTION_RODATA) => SectionKind::Rodata,
            Some(SECTION_DATA) => SectionKind::Data,
            Some(SECTION_BSS) => SectionKind::Bss,
            _ => return Err(FormatError::BadSection),
        };
        let align = usize::from(rd16(self.bytes, at + 2)?).max(1);
        let s = Section {
            kind,
            mem_off: rdsize(self.bytes, at + 4)?,
            file_off: rdsize(self.bytes, at + 8)?,
            file_size: rdsize(self.bytes, at + 12)?,
            mem_size: rdsize(self.bytes, at + 16)?,
        };
        let in_arena = span(s.mem_off, s.mem_size).is_some_and(|r| r.end <= self.arena_size);
        if !align.is_power_of_two()
            || align > MAX_ALIGN
            || !s.mem_off.is_multiple_of(align)
            || s.mem_size == 0
            || !in_arena
            || s.file_size > s.mem_size
        {
            return Err(FormatError::BadSection);
        }
        if kind == SectionKind::Bss {
            if s.file_size != 0 {
                return Err(FormatError::BadSection);
            }
        } else if s.file_size > 0 {
            let file = span(s.file_off, s.file_size).ok_or(FormatError::BadSection)?;
            if file.start < HEADER_SIZE || file.end > self.signed_len {
                return Err(FormatError::BadSection);
            }
        }
        Ok(s)
    }

    /// The file bytes of a section from [`section`](Self::section).
    pub fn section_bytes(&self, s: &Section) -> Result<&'a [u8], FormatError> {
        let range = span(s.file_off, s.file_size).ok_or(FormatError::BadSection)?;
        if s.file_size > 0 && range.end > self.signed_len {
            return Err(FormatError::BadSection);
        }
        if s.file_size == 0 {
            return Ok(&[]);
        }
        self.bytes.get(range).ok_or(FormatError::BadSection)
    }

    /// A name `(offset, length, hash)` triple at `at`, checked against the
    /// string table and its hash.
    fn name_at(&self, at: usize) -> Result<&'a [u8], FormatError> {
        let off = rdsize(self.bytes, at)?;
        let len = rdsize(self.bytes, at + 4)?;
        let hash = rd64(self.bytes, at + 8)?;
        if len == 0 || len > MAX_NAME {
            return Err(FormatError::BadSymbol);
        }
        let range = span(off, len).ok_or(FormatError::BadSymbol)?;
        let strings = self.bytes.get(self.strings.0..self.strings.1).ok_or(FormatError::BadSymbol)?;
        let name = strings.get(range).ok_or(FormatError::BadSymbol)?;
        if fnv1a(name) != hash {
            return Err(FormatError::BadSymbol);
        }
        Ok(name)
    }

    /// The name of import `i`.
    pub fn import_name(&self, i: usize) -> Result<&'a [u8], FormatError> {
        if i >= self.imports.n {
            return Err(FormatError::BadSymbol);
        }
        self.name_at(self.imports.off + i * IMPORT_SIZE)
    }

    /// Export `i`: its name and arena offset.
    pub fn export(&self, i: usize) -> Result<(&'a [u8], usize), FormatError> {
        if i >= self.exports.n {
            return Err(FormatError::BadSymbol);
        }
        let at = self.exports.off + i * EXPORT_SIZE;
        let name = self.name_at(at)?;
        let mem_off = rdsize(self.bytes, at + 16)?;
        if mem_off >= self.arena_size {
            return Err(FormatError::BadSymbol);
        }
        Ok((name, mem_off))
    }

    /// Relocation `i`, validated against the sections.
    pub fn reloc(&self, i: usize) -> Result<Reloc, FormatError> {
        if i >= self.relocs.n {
            return Err(FormatError::BadRelocation);
        }
        let at = self.relocs.off + i * RELOC_SIZE;
        let kind = rd32(self.bytes, at)?;
        let offset = usize::try_from(rd64(self.bytes, at + 8)?).map_err(|_| FormatError::BadRelocation)?;
        let sym = rdsize(self.bytes, at + 16)?;
        let addend = rd64(self.bytes, at + 24)?;

        // The 8 bytes written lie wholly inside one section that is not code.
        let target = span(offset, 8).ok_or(FormatError::BadRelocation)?;
        let mut inside = false;
        for j in 0..self.sections.n {
            let s = self.section(j)?;
            if s.contains(&target) {
                if s.kind == SectionKind::Text {
                    return Err(FormatError::BadRelocation);
                }
                inside = true;
            }
        }
        if !inside {
            return Err(FormatError::BadRelocation);
        }

        match kind {
            RELOC_RELATIVE => {
                // A pointer into the image, or one past its end — never out.
                let target = usize::try_from(addend).map_err(|_| FormatError::BadRelocation)?;
                if target > self.arena_size {
                    return Err(FormatError::BadRelocation);
                }
                Ok(Reloc::Relative { offset, target })
            }
            RELOC_IMPORT64 => {
                if sym >= self.imports.n || addend != 0 {
                    return Err(FormatError::BadRelocation);
                }
                Ok(Reloc::Import { offset, import: sym })
            }
            _ => Err(FormatError::BadRelocation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// A minimal valid image, laid out the way tools/ncplu.py lays one out:
    /// header, sections, imports, exports, relocations, strings, section
    /// bytes, then the reserved signature block.
    fn build() -> Vec<u8> {
        let strings = b"nc_abi_versionncplu_main";
        let import_name = (0u32, 14u32);
        let export_name = (14u32, 10u32);

        let sections_off = HEADER_SIZE;
        let n_sections = 3; // text, data, bss
        let imports_off = sections_off + n_sections * SECTION_SIZE;
        let exports_off = imports_off + IMPORT_SIZE;
        let relocs_off = exports_off + EXPORT_SIZE;
        let n_relocs = 2;
        let strings_off = relocs_off + n_relocs * RELOC_SIZE;
        let text_off = strings_off + strings.len();
        let text = [0xC3u8; 32]; // ret
        let data_off = text_off + text.len();
        let data = [0u8; 16];
        let sig_off = data_off + data.len();
        let total = sig_off + SIGNATURE_LEN;

        let mut b = vec![0u8; total];
        b[..8].copy_from_slice(&MAGIC);
        b[H_FORMAT_VERSION..H_FORMAT_VERSION + 2].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        b[H_HEADER_SIZE..H_HEADER_SIZE + 2].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        let put32 = |b: &mut Vec<u8>, at: usize, v: usize| b[at..at + 4].copy_from_slice(&(v as u32).to_le_bytes());
        b[H_TOTAL_SIZE..H_TOTAL_SIZE + 8].copy_from_slice(&(total as u64).to_le_bytes());
        put32(&mut b, H_ABI_VERSION, ABI_VERSION as usize);
        put32(&mut b, H_ENTRY_EXPORT, 0);
        put32(&mut b, H_SECTIONS_OFF, sections_off);
        put32(&mut b, H_SECTIONS_N, n_sections);
        put32(&mut b, H_IMPORTS_OFF, imports_off);
        put32(&mut b, H_IMPORTS_N, 1);
        put32(&mut b, H_EXPORTS_OFF, exports_off);
        put32(&mut b, H_EXPORTS_N, 1);
        put32(&mut b, H_RELOCS_OFF, relocs_off);
        put32(&mut b, H_RELOCS_N, n_relocs);
        put32(&mut b, H_STRINGS_OFF, strings_off);
        put32(&mut b, H_STRINGS_LEN, strings.len());
        put32(&mut b, H_SIGNATURE_OFF, sig_off);
        put32(&mut b, H_SIGNATURE_LEN, SIGNATURE_LEN);
        put32(&mut b, H_ARENA_SIZE, 0x3000);

        // Sections: text at 0x1000, data at 0x2000, bss at 0x2100.
        let mut sec = |i: usize, kind: u8, mem: usize, foff: usize, fsize: usize, msize: usize| {
            let at = sections_off + i * SECTION_SIZE;
            b[at] = kind;
            b[at + 2..at + 4].copy_from_slice(&16u16.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&(mem as u32).to_le_bytes());
            b[at + 8..at + 12].copy_from_slice(&(foff as u32).to_le_bytes());
            b[at + 12..at + 16].copy_from_slice(&(fsize as u32).to_le_bytes());
            b[at + 16..at + 20].copy_from_slice(&(msize as u32).to_le_bytes());
        };
        sec(0, SECTION_TEXT, 0x1000, text_off, text.len(), text.len());
        sec(1, SECTION_DATA, 0x2000, data_off, data.len(), data.len());
        sec(2, SECTION_BSS, 0x2100, 0, 0, 0x100);

        let name = |b: &mut Vec<u8>, at: usize, (off, len): (u32, u32)| {
            b[at..at + 4].copy_from_slice(&off.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&len.to_le_bytes());
            let s = &strings[off as usize..(off + len) as usize];
            b[at + 8..at + 16].copy_from_slice(&fnv1a(s).to_le_bytes());
        };
        name(&mut b, imports_off, import_name);
        name(&mut b, exports_off, export_name);
        b[exports_off + 16..exports_off + 20].copy_from_slice(&0x1000u32.to_le_bytes());

        // Relocs: a RELATIVE pointer to the entry, and the import, both in data.
        let mut rel = |i: usize, kind: u32, offset: u64, sym: u32, addend: u64| {
            let at = relocs_off + i * RELOC_SIZE;
            b[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            b[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            b[at + 16..at + 20].copy_from_slice(&sym.to_le_bytes());
            b[at + 24..at + 32].copy_from_slice(&addend.to_le_bytes());
        };
        rel(0, RELOC_RELATIVE, 0x2000, 0, 0x1000);
        rel(1, RELOC_IMPORT64, 0x2008, 0, 0);

        b[strings_off..strings_off + strings.len()].copy_from_slice(strings);
        b[text_off..text_off + text.len()].copy_from_slice(&text);
        b[data_off..data_off + data.len()].copy_from_slice(&data);
        b
    }

    fn set32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn a_well_formed_image_parses() {
        let b = build();
        let img = Image::parse(&b).expect("valid image");
        assert_eq!(img.entry, 0x1000);
        assert_eq!(img.section_count(), 3);
        assert_eq!(img.reloc(0), Ok(Reloc::Relative { offset: 0x2000, target: 0x1000 }));
        assert_eq!(img.reloc(1), Ok(Reloc::Import { offset: 0x2008, import: 0 }));
        assert_eq!(img.import_name(0), Ok(&b"nc_abi_version"[..]));
        assert!(img.signature_block().is_some());
    }

    #[test]
    fn each_rule_has_its_error() {
        let base = build();
        let secs = HEADER_SIZE;
        let relocs = rd32(&base, H_RELOCS_OFF).unwrap() as usize;
        let cases: &[(&str, &dyn Fn(&mut Vec<u8>), FormatError)] = &[
            // The panic this parser exists to prevent: a total smaller than
            // the header, which used to shrink the slice under later reads.
            ("total below the header", &|b| b[H_TOTAL_SIZE..H_TOTAL_SIZE + 8].copy_from_slice(&40u64.to_le_bytes()), FormatError::TooSmall),
            ("total past the file", &|b| b[H_TOTAL_SIZE..H_TOTAL_SIZE + 8].copy_from_slice(&u64::MAX.to_le_bytes()), FormatError::TooBig),
            ("arena beyond the kernel's", &|b| set32(b, H_ARENA_SIZE, (MAX_ARENA + 1) as u32), FormatError::TooBig),
            ("signature not at the end", &|b| set32(b, H_SIGNATURE_OFF, 200), FormatError::BadSignatureBlock),
            ("section table past the signed region", &|b| set32(b, H_SECTIONS_OFF, u32::MAX - 8), FormatError::BadTable),
            ("too many relocations", &|b| set32(b, H_RELOCS_N, (MAX_RELOCS + 1) as u32), FormatError::BadTable),
            ("section outside the arena", &|b| set32(b, secs + 4, 0x2FF0), FormatError::BadSection),
            ("misaligned section", &|b| set32(b, secs + 4, 0x1004), FormatError::BadSection),
            ("bss with file bytes", &|b| set32(b, secs + 2 * SECTION_SIZE + 12, 4), FormatError::BadSection),
            ("overlapping sections", &|b| set32(b, secs + SECTION_SIZE + 4, 0x1010), FormatError::OverlappingSections),
            ("relocation into code", &|b| b[relocs + 8..relocs + 16].copy_from_slice(&0x1000u64.to_le_bytes()), FormatError::BadRelocation),
            ("relocation past its section", &|b| b[relocs + 8..relocs + 16].copy_from_slice(&0x200Cu64.to_le_bytes()), FormatError::BadRelocation),
            ("relative pointer out of the image", &|b| b[relocs + 24..relocs + 32].copy_from_slice(&(-8i64 as u64).to_le_bytes()), FormatError::BadRelocation),
            ("import with an offset", &|b| b[relocs + 32 + 24..relocs + 64].copy_from_slice(&8u64.to_le_bytes()), FormatError::BadRelocation),
            ("entry outside the code", &|b| {
                let e = rd32(b, H_EXPORTS_OFF).unwrap() as usize;
                set32(b, e + 16, 0x2000);
            }, FormatError::NoEntry),
        ];
        for (what, mutate, expected) in cases {
            let mut b = base.clone();
            mutate(&mut b);
            assert_eq!(Image::parse(&b).err(), Some(*expected), "{what}");
        }
    }

    /// Applies an image the way the kernel does, into a host arena, with
    /// indexing that panics on any out-of-bounds access. A parse that lets
    /// such an image through fails the test.
    fn apply(img: &Image<'_>) {
        let mut arena = vec![0u8; img.arena_size];
        for i in 0..img.section_count() {
            let s = img.section(i).unwrap();
            let bytes = img.section_bytes(&s).unwrap();
            arena[s.mem_off..s.mem_off + bytes.len()].copy_from_slice(bytes);
        }
        for i in 0..img.reloc_count() {
            let offset = match img.reloc(i).unwrap() {
                Reloc::Relative { offset, target } => {
                    assert!(target <= img.arena_size);
                    offset
                }
                Reloc::Import { offset, import } => {
                    img.import_name(import).unwrap();
                    offset
                }
            };
            arena[offset..offset + 8].copy_from_slice(&[0xAA; 8]);
        }
        assert!(img.entry < img.arena_size);
    }

    #[test]
    fn real_packer_output_parses() {
        // `NCPLU_FILES=a.NCPLU:b.NCPLU cargo test real_packer_output` checks
        // plugins packed by tools/ncplu.py against these rules; without the
        // variable there is nothing to read and the test passes vacuously.
        let Ok(list) = std::env::var("NCPLU_FILES") else { return };
        for path in list.split(':').filter(|p| !p.is_empty()) {
            let bytes = std::fs::read(path).unwrap();
            let img = Image::parse(&bytes).unwrap_or_else(|e| panic!("{path}: {}", e.message()));
            apply(&img);
            std::println!("{path}: ok, {} sections, {} relocations", img.section_count(), img.reloc_count());
        }
    }

    #[test]
    fn corrupted_images_never_panic_and_never_escape() {
        let base = build();
        // Values that tend to break bounds arithmetic.
        let nasty: [u32; 10] = [0, 1, 7, 8, 159, 160, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFF8, u32::MAX];
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut accepted = 0;
        for _ in 0..60_000 {
            let mut b = base.clone();
            for _ in 0..(next() % 4 + 1) {
                let r = next();
                if b.len() < 4 {
                    break;
                }
                match r % 4 {
                    // Flip a random byte.
                    0 => {
                        let at = (r >> 8) as usize % b.len();
                        b[at] ^= (r >> 40) as u8 | 1;
                    }
                    // Overwrite a random 32-bit field with a nasty value.
                    1 | 2 => {
                        let at = ((r >> 8) as usize % (b.len() / 4)) * 4;
                        let v = nasty[(r >> 40) as usize % nasty.len()];
                        set32(&mut b, at, v);
                    }
                    // Truncate.
                    _ => {
                        let keep = (r >> 8) as usize % b.len();
                        b.truncate(keep);
                    }
                }
            }
            if let Ok(img) = Image::parse(&b) {
                apply(&img);
                accepted += 1;
            }
        }
        // Some mutations land in harmless bytes (the signature block, code);
        // those images are still valid, and must apply cleanly.
        assert!(accepted > 0);
    }
}
