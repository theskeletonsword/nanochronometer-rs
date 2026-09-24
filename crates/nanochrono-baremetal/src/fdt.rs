// SPDX-License-Identifier: Apache-2.0
//! A read-only flattened device tree (DTB) reader.
//!
//! The PowerPC boards this kernel boots on — and ARM ones, once the AArch64
//! port reads it — describe themselves with a device tree instead of ACPI or
//! a multiboot structure: where the UART is, and how fast the Time Base
//! ticks, a number the ISA has no register for.
//!
//! # Trust
//!
//! The blob comes from firmware, but it is still input: a truncated tree, an
//! offset past the end, a property length that runs off the block, a string
//! with no terminator. Every access here is bounds-checked against the
//! header's own sizes, and a malformed tree yields `None` rather than a read
//! outside it. Nothing is allocated; the walker is a loop over a byte slice.
//!
//! The format is the one the Devicetree Specification (v0.4) defines: a
//! 40-byte big-endian header, a structure block of 32-bit tokens, and a
//! strings block the property names index into.

/// `FDT_MAGIC`.
const MAGIC: u32 = 0xD00D_FEED;
/// The largest blob accepted. Real trees are tens of kilobytes; the cap keeps
/// a corrupt `totalsize` from turning into a multi-gigabyte slice.
const MAX_TOTALSIZE: u32 = 4 << 20;
/// Deepest nesting followed. Real trees are well under ten levels.
const MAX_DEPTH: usize = 16;

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

/// A validated device tree.
#[derive(Clone, Copy)]
pub struct Fdt<'a> {
    structs: &'a [u8],
    strings: &'a [u8],
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a big-endian number of `cells` 32-bit cells (1 or 2) from `bytes`.
fn read_cells(bytes: &[u8], cells: u32) -> Option<u64> {
    match cells {
        1 => be32(bytes, 0).map(u64::from),
        2 => Some((u64::from(be32(bytes, 0)?) << 32) | u64::from(be32(bytes, 4)?)),
        _ => None,
    }
}

/// The NUL-terminated string at the start of `bytes`, without the NUL.
fn cstr(bytes: &[u8]) -> Option<&[u8]> {
    let end = bytes.iter().position(|&b| b == 0)?;
    Some(&bytes[..end])
}

const fn align4(n: usize) -> Option<usize> {
    match n.checked_add(3) {
        Some(v) => Some(v & !3),
        None => None,
    }
}

/// One step of the structure walk.
enum Token<'a> {
    Begin(&'a [u8]),
    End,
    Prop(&'a [u8], &'a [u8]),
}

impl<'a> Fdt<'a> {
    /// Validates a tree held in `blob`.
    pub fn from_bytes(blob: &'a [u8]) -> Option<Fdt<'a>> {
        if be32(blob, 0)? != MAGIC {
            return None;
        }
        let total = be32(blob, 4)? as usize;
        if total < 40 || total > blob.len() {
            return None;
        }
        let blob = &blob[..total];
        let off_struct = be32(blob, 8)? as usize;
        let off_strings = be32(blob, 12)? as usize;
        let version = be32(blob, 20)?;
        let last_compatible = be32(blob, 24)?;
        // The size fields only exist from version 17; every tree a current
        // loader produces is 17, and older ones are not worth guessing at.
        if version < 17 || last_compatible > 17 {
            return None;
        }
        let size_strings = be32(blob, 32)? as usize;
        let size_struct = be32(blob, 36)? as usize;
        let structs = blob.get(off_struct..off_struct.checked_add(size_struct)?)?;
        let strings = blob.get(off_strings..off_strings.checked_add(size_strings)?)?;
        Some(Fdt { structs, strings })
    }

    /// Validates a tree at a raw address handed over by the loader.
    ///
    /// # Safety
    /// `ptr` must be readable for at least 40 bytes and, if those bytes carry
    /// the FDT magic, for the `totalsize` they state (capped here at 4 MiB).
    pub unsafe fn from_ptr(ptr: *const u8) -> Option<Fdt<'static>> {
        if ptr.is_null() || (ptr as usize) % 4 != 0 {
            return None;
        }
        // SAFETY: the caller guarantees the header is readable.
        let header = unsafe { core::slice::from_raw_parts(ptr, 40) };
        if be32(header, 0)? != MAGIC {
            return None;
        }
        let total = be32(header, 4)?;
        if !(40..=MAX_TOTALSIZE).contains(&total) {
            return None;
        }
        // SAFETY: the caller guarantees `totalsize` bytes are readable, and
        // the value was capped above.
        let blob = unsafe { core::slice::from_raw_parts(ptr, total as usize) };
        Fdt::from_bytes(blob)
    }

    /// Walks the structure block, calling `visit` for each token until it
    /// returns `false` or the block ends. Returns `None` on a malformed block.
    fn walk(&self, mut visit: impl FnMut(Token<'a>) -> bool) -> Option<()> {
        let s = self.structs;
        let mut pos = 0usize;
        let mut depth = 0usize;
        loop {
            let token = be32(s, pos)?;
            pos += 4;
            let step = match token {
                FDT_BEGIN_NODE => {
                    let name = cstr(s.get(pos..)?)?;
                    pos = align4(pos.checked_add(name.len() + 1)?)?;
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return None;
                    }
                    Token::Begin(name)
                }
                FDT_END_NODE => {
                    depth = depth.checked_sub(1)?;
                    Token::End
                }
                FDT_PROP => {
                    let len = be32(s, pos)? as usize;
                    let name_off = be32(s, pos + 4)? as usize;
                    pos += 8;
                    let value = s.get(pos..pos.checked_add(len)?)?;
                    pos = align4(pos.checked_add(len)?)?;
                    let name = cstr(self.strings.get(name_off..)?)?;
                    Token::Prop(name, value)
                }
                FDT_NOP => continue,
                FDT_END => return Some(()),
                _ => return None,
            };
            if !visit(step) {
                return Some(());
            }
        }
    }

    /// The Time Base (or timer) rate: `timebase-frequency` on a CPU node, or
    /// on `/cpus` itself, where the specification also allows it.
    pub fn timebase_frequency(&self) -> Option<u64> {
        let mut depth = 0usize;
        // Depth at which `/cpus` was entered, while inside it.
        let mut cpus_depth: Option<usize> = None;
        let mut found = None;
        self.walk(|token| {
            match token {
                Token::Begin(name) => {
                    depth += 1;
                    if depth == 2 && name == b"cpus" {
                        cpus_depth = Some(depth);
                    }
                }
                Token::End => {
                    if cpus_depth == Some(depth) {
                        cpus_depth = None;
                    }
                    depth -= 1;
                }
                Token::Prop(name, value) => {
                    if cpus_depth.is_some() && name == b"timebase-frequency" {
                        found = match value.len() {
                            4 => read_cells(value, 1),
                            8 => read_cells(value, 2),
                            _ => None,
                        }
                        .filter(|&hz| hz > 0);
                        if found.is_some() {
                            return false;
                        }
                    }
                }
            }
            true
        })?;
        found
    }

    /// Property `name` of the first node whose `compatible` list contains
    /// `compatible` — for a device's own parameters (a framebuffer's width,
    /// a UART's clock). A node's properties all precede its children, so it
    /// is decided at its first child or its end.
    pub fn compatible_property(&self, compatible: &[u8], name: &[u8]) -> Option<&'a [u8]> {
        let mut depth = 0usize;
        let mut matches = [false; MAX_DEPTH + 1];
        let mut value: [Option<&'a [u8]>; MAX_DEPTH + 1] = [None; MAX_DEPTH + 1];
        let mut found = None;
        self.walk(|token| {
            match token {
                Token::Begin(_) | Token::End if matches[depth] && value[depth].is_some() => {
                    found = value[depth];
                    return false;
                }
                _ => {}
            }
            match token {
                Token::Begin(_) => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return false;
                    }
                    matches[depth] = false;
                    value[depth] = None;
                }
                Token::End => depth = depth.saturating_sub(1),
                Token::Prop(prop, v) => {
                    if prop == b"compatible" {
                        matches[depth] = v.split(|&c| c == 0).any(|c| c == compatible);
                    } else if prop == name {
                        value[depth] = Some(v);
                    }
                }
            }
            true
        })?;
        found
    }

    /// The `index`th address in the `reg` of a `compatible` node that sits
    /// directly under the root, in the root's `#address-cells` and
    /// `#size-cells`. For a device with several register windows — a GICv2's
    /// distributor and CPU interface — where [`find_compatible_reg`] gives
    /// only the first. No `ranges` translation: root children need none.
    ///
    /// [`find_compatible_reg`]: Self::find_compatible_reg
    pub fn compatible_reg_at(&self, compatible: &[u8], index: usize) -> Option<u64> {
        let reg = self.compatible_property(compatible, b"reg")?;
        let (addr_cells, size_cells) = self.root_cells();
        let entry = (addr_cells + size_cells) as usize * 4;
        let at = index.checked_mul(entry)?;
        read_cells(reg.get(at..at.checked_add(entry)?)?, addr_cells)
    }

    /// The root node's `#address-cells` and `#size-cells` (2 and 1 when
    /// absent, as the specification defaults them).
    pub fn root_cells(&self) -> (u32, u32) {
        let (mut a, mut sz) = (2, 1);
        let mut depth = 0usize;
        let _ = self.walk(|token| {
            match token {
                Token::Begin(_) => {
                    depth += 1;
                    if depth > 1 {
                        return false;
                    }
                }
                Token::End => depth = depth.saturating_sub(1),
                Token::Prop(name, v) if depth == 1 && v.len() >= 4 => {
                    let cells = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                    if name == b"#address-cells" {
                        a = cells;
                    } else if name == b"#size-cells" {
                        sz = cells;
                    }
                }
                Token::Prop(..) => {}
            }
            true
        });
        (a.min(2), sz.min(2))
    }

    /// A one-cell (`u32`) property of a `compatible` node.
    pub fn compatible_u32(&self, compatible: &[u8], name: &[u8]) -> Option<u32> {
        let v = self.compatible_property(compatible, name)?;
        Some(u32::from_be_bytes(v.get(..4)?.try_into().ok()?))
    }

    /// A string property of a `compatible` node, without its NUL.
    pub fn compatible_str(&self, compatible: &[u8], name: &[u8]) -> Option<&'a [u8]> {
        cstr(self.compatible_property(compatible, name)?)
    }

    /// The value of property `name` on the first CPU node (`/cpus/cpu@…`),
    /// e.g. `riscv,isa`.
    pub fn cpu_property(&self, name: &[u8]) -> Option<&'a [u8]> {
        let mut depth = 0usize;
        let mut in_cpus = false;
        let mut found = None;
        self.walk(|token| {
            match token {
                Token::Begin(node) => {
                    depth += 1;
                    if depth == 2 {
                        in_cpus = node == b"cpus";
                    }
                }
                Token::End => {
                    if depth == 2 {
                        in_cpus = false;
                    }
                    depth -= 1;
                }
                Token::Prop(prop, value) => {
                    if in_cpus && depth == 3 && prop == name {
                        found = Some(value);
                        return false;
                    }
                }
            }
            true
        })?;
        found
    }

    /// The CPU address of the first register window of the first enabled
    /// node whose `compatible` list contains `compatible`, translated through
    /// every parent bus's `ranges`.
    pub fn find_compatible_reg(&self, compatible: &[u8]) -> Option<u64> {
        /// What a node says about the address space of its children.
        #[derive(Clone, Copy)]
        struct Bus<'a> {
            address_cells: u32,
            size_cells: u32,
            /// `None`: no `ranges`, the children are not CPU-addressable.
            /// `Some(empty)`: identity mapping.
            ranges: Option<&'a [u8]>,
        }
        const DEFAULT_BUS: Bus<'static> = Bus { address_cells: 2, size_cells: 1, ranges: None };

        let mut stack = [DEFAULT_BUS; MAX_DEPTH + 1];
        let mut depth = 0usize;
        // The node currently being read: its compatible, reg, status.
        let mut matches = false;
        let mut disabled = false;
        let mut reg: Option<&[u8]> = None;
        let mut result = None;
        // A node's properties all come before its first child, so a node is
        // decided when the next Begin or its own End arrives.
        let mut pending = false;

        let decide = |depth: usize,
                          stack: &[Bus<'a>; MAX_DEPTH + 1],
                          matches: bool,
                          disabled: bool,
                          reg: Option<&'a [u8]>|
         -> Option<u64> {
            if !matches || disabled || depth < 2 {
                return None;
            }
            let parent = stack[depth - 1];
            let mut addr = read_cells(reg?, parent.address_cells)?;
            // Translate upwards: at each bus, its `ranges` map its child
            // address space into its own parent's. The root (depth 1) is not
            // translated: its children's address space is the CPU's.
            let mut level = depth - 1;
            while level >= 2 {
                let bus = stack[level];
                let upper = stack[level - 1];
                let ranges = bus.ranges?;
                if !ranges.is_empty() {
                    let child = bus.address_cells as usize * 4;
                    let parent_cells = upper.address_cells as usize * 4;
                    let size = bus.size_cells as usize * 4;
                    let entry = child + parent_cells + size;
                    if entry == 0 {
                        return None;
                    }
                    let mut hit = None;
                    for r in ranges.chunks_exact(entry) {
                        let c = read_cells(r, bus.address_cells)?;
                        let p = read_cells(&r[child..], upper.address_cells)?;
                        let len = read_cells(&r[child + parent_cells..], bus.size_cells)?;
                        if addr >= c && addr - c < len {
                            hit = Some(p.checked_add(addr - c)?);
                            break;
                        }
                    }
                    addr = hit?;
                }
                level -= 1;
            }
            Some(addr)
        };

        self.walk(|token| {
            match token {
                Token::Begin(_) => {
                    if pending {
                        result = decide(depth, &stack, matches, disabled, reg);
                        if result.is_some() {
                            return false;
                        }
                    }
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return false;
                    }
                    stack[depth] = Bus { ranges: None, ..DEFAULT_BUS };
                    matches = false;
                    disabled = false;
                    reg = None;
                    pending = true;
                }
                Token::End => {
                    if pending {
                        result = decide(depth, &stack, matches, disabled, reg);
                        if result.is_some() {
                            return false;
                        }
                    }
                    pending = false;
                    depth = depth.saturating_sub(1);
                }
                Token::Prop(name, value) => match name {
                    b"#address-cells" => {
                        if let Some(v) = be32(value, 0) {
                            stack[depth].address_cells = v;
                        }
                    }
                    b"#size-cells" => {
                        if let Some(v) = be32(value, 0) {
                            stack[depth].size_cells = v;
                        }
                    }
                    b"ranges" => stack[depth].ranges = Some(value),
                    b"reg" => reg = Some(value),
                    b"status" => {
                        disabled = !matches!(cstr(value), Some(b"okay") | Some(b"ok"));
                    }
                    b"compatible" => {
                        matches = value.split(|&b| b == 0).any(|c| c == compatible);
                    }
                    _ => {}
                },
            }
            true
        })?;
        result
    }
}
