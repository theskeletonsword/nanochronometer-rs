// SPDX-License-Identifier: Apache-2.0
//! Reading what the loader left behind.
//!
//! Only the framebuffer tag is parsed. The rest of the multiboot2 information
//! structure — memory maps, modules, the command line — describes resources
//! this kernel does not manage, and parsing tags it will never act on would
//! be code with no way to be wrong loudly.

use crate::framebuffer::Framebuffer;

/// Tag type 8: the framebuffer the loader actually set up.
const TAG_FRAMEBUFFER: u32 = 8;
/// Tag type 0 ends the list.
const TAG_END: u32 = 0;

/// Framebuffer type 1 is a linear RGB surface. Type 2 is EGA text, which this
/// cannot draw on, and type 0 is indexed colour, which would need the palette
/// programmed first.
const FRAMEBUFFER_TYPE_RGB: u8 = 1;

/// How far a physical address can reach: the 512 GiB boot32.S identity-maps
/// on x86_64; on i386, with paging off, the 4 GiB a 32-bit pointer names.
/// A framebuffer beyond it would be written through a truncated pointer.
#[cfg(target_pointer_width = "64")]
const ADDRESSABLE: u64 = 512 << 30;
#[cfg(target_pointer_width = "32")]
const ADDRESSABLE: u64 = 1 << 32;

/// Finds the framebuffer the loader set up, if it set one up.
///
/// # Safety
/// `info` must be the multiboot2 information pointer the loader passed, or
/// zero. Reads it as the specification lays it out.
pub unsafe fn framebuffer(info: u64) -> Option<Framebuffer> {
    if info == 0 || info % 8 != 0 {
        return None;
    }
    let base = info as usize;

    // The structure starts with its total size and a reserved word; tags
    // follow, each 8-byte aligned.
    // SAFETY: forwarded from this function's own contract.
    let total = unsafe { core::ptr::read_volatile(base as *const u32) } as usize;
    if !(16..0x10_0000).contains(&total) {
        return None;
    }

    let mut offset = 8;
    while offset + 8 <= total {
        // SAFETY: bounded by the total size the header declares.
        let (kind, size) = unsafe {
            (
                core::ptr::read_volatile((base + offset) as *const u32),
                core::ptr::read_volatile((base + offset + 4) as *const u32) as usize,
            )
        };
        // A tag that claims to run past the structure is corrupt, and
        // reading its body would read past what the loader handed over.
        if kind == TAG_END || size < 8 || offset + size > total {
            break;
        }
        if kind == TAG_FRAMEBUFFER && size >= 32 {
            let tag = base + offset;
            // SAFETY: the tag's declared size covers these fields.
            let fb = unsafe {
                let address = core::ptr::read_unaligned((tag + 8) as *const u64);
                let pitch = core::ptr::read_unaligned((tag + 16) as *const u32);
                let width = core::ptr::read_unaligned((tag + 20) as *const u32);
                let height = core::ptr::read_unaligned((tag + 24) as *const u32);
                let bpp = core::ptr::read_unaligned((tag + 28) as *const u8);
                let fb_type = core::ptr::read_unaligned((tag + 29) as *const u8);

                if fb_type != FRAMEBUFFER_TYPE_RGB {
                    return None;
                }
                // The identity map covers the first 512 GiB, sized for
                // exactly this: firmware puts framebuffers in high MMIO
                // space, and a UEFI machine routinely puts one above 4 GiB.
                // Anything beyond the map would fault on the first store, so
                // it is refused rather than written to.
                if address == 0 || address >= ADDRESSABLE {
                    return None;
                }
                Framebuffer::new(address as *mut u8, width, height, pitch, bpp)
            };
            // The whole surface, not just its first byte, has to sit inside
            // the identity map the boot stub built.
            let fits = (fb.base_address() as u64)
                .checked_add(fb.size_bytes())
                .is_some_and(|end| end <= ADDRESSABLE);
            return (fb.is_usable() && fits).then_some(fb);
        }
        // Tags are padded to an 8-byte boundary.
        offset += size.div_ceil(8) * 8;
    }
    None
}

/// Tag type 6: the firmware memory map, entry by entry.
const TAG_MEMORY_MAP: u32 = 6;
/// Tag type 4: the two coarse figures a multiboot1 loader also supplies.
const TAG_BASIC_MEMORY: u32 = 4;

/// Memory-map entry type 1 is ordinary usable RAM. Everything else is
/// reserved, ACPI, or bad — none of which is memory this machine has to run
/// in, so none of it is counted.
const MEMORY_AVAILABLE: u32 = 1;

/// What the firmware says is installed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Memory {
    /// Total usable RAM in bytes, summed from the map.
    pub total: u64,
    /// How many entries the map had. Zero means the loader supplied none and
    /// `total` came from the coarse tag, or from nothing at all.
    pub regions: u32,
}

impl Memory {
    pub fn is_known(&self) -> bool {
        self.total > 0
    }
}

/// Sums the usable RAM the loader described.
///
/// Reported by the interface rather than assumed, because "how much memory
/// does this machine have" has no other answer without an operating system —
/// and a status bar that shows a fraction of an unknown total is showing
/// nothing.
///
/// # Safety
/// `info` must be the multiboot2 information pointer the loader passed, or
/// zero.
pub unsafe fn memory(info: u64) -> Memory {
    let mut out = Memory::default();
    if info == 0 || info % 8 != 0 {
        return out;
    }
    let base = info as usize;
    // SAFETY: forwarded from this function's own contract.
    let total_size = unsafe { core::ptr::read_volatile(base as *const u32) } as usize;
    if !(16..0x10_0000).contains(&total_size) {
        return out;
    }

    let mut offset = 8;
    while offset + 8 <= total_size {
        // SAFETY: bounded by the size the header declares.
        let (kind, size) = unsafe {
            (
                core::ptr::read_volatile((base + offset) as *const u32),
                core::ptr::read_volatile((base + offset + 4) as *const u32) as usize,
            )
        };
        // A tag that claims to run past the structure is corrupt, and
        // reading its body would read past what the loader handed over.
        if kind == TAG_END || size < 8 || offset + size > total_size {
            break;
        }

        if kind == TAG_MEMORY_MAP && size >= 16 {
            // SAFETY: the tag's declared size covers its header.
            let (entry_size, _version) = unsafe {
                (
                    core::ptr::read_unaligned((base + offset + 8) as *const u32) as usize,
                    core::ptr::read_unaligned((base + offset + 12) as *const u32),
                )
            };
            // The entry size is a forward-compatibility field: a later
            // revision may make entries longer, and the correct response is
            // to stride by what the loader says rather than by what this
            // code was compiled against. Zero would loop forever.
            if entry_size >= 24 {
                let mut at = offset + 16;
                while at + entry_size <= offset + size {
                    // SAFETY: bounded by the tag's own declared size.
                    let (addr, length, region) = unsafe {
                        (
                            core::ptr::read_unaligned((base + at) as *const u64),
                            core::ptr::read_unaligned((base + at + 8) as *const u64),
                            core::ptr::read_unaligned((base + at + 16) as *const u32),
                        )
                    };
                    let _ = addr;
                    if region == MEMORY_AVAILABLE {
                        out.total = out.total.saturating_add(length);
                        out.regions += 1;
                    }
                    at += entry_size;
                }
            }
        } else if kind == TAG_BASIC_MEMORY && size >= 16 && out.total == 0 {
            // The coarse tag: lower memory in KiB below 1 MiB, upper memory
            // in KiB above it. Only used where there is no map, and it
            // famously saturates at whatever the firmware could report
            // through the legacy BIOS call — so the map is always preferred.
            // SAFETY: the tag's declared size covers both fields.
            let (lower, upper) = unsafe {
                (
                    core::ptr::read_unaligned((base + offset + 8) as *const u32) as u64,
                    core::ptr::read_unaligned((base + offset + 12) as *const u32) as u64,
                )
            };
            out.total = (lower + upper) * 1024;
        }

        offset += size.div_ceil(8) * 8;
    }
    out
}

/// Memory size from a *multiboot1* information structure (QEMU's `-kernel`
/// loader): `mem_lower`/`mem_upper` in KiB, valid when `flags` bit 0 is set.
///
/// # Safety
/// `info` must be the pointer a multiboot1 loader passed with its magic.
pub unsafe fn memory_v1(info: u64) -> Memory {
    if info == 0 || info % 4 != 0 {
        return Memory::default();
    }
    let base = info as usize;
    // SAFETY: the caller guarantees a multiboot1 structure, whose first
    // twelve bytes are flags, mem_lower and mem_upper.
    let (flags, lower, upper) = unsafe {
        (
            core::ptr::read_volatile(base as *const u32),
            core::ptr::read_volatile((base + 4) as *const u32) as u64,
            core::ptr::read_volatile((base + 8) as *const u32) as u64,
        )
    };
    if flags & 1 == 0 {
        return Memory::default();
    }
    Memory {
        total: (lower + upper) * 1024,
        regions: 0,
    }
}

extern "C" {
    /// Placed by the linker script at the bottom and top of the image.
    static __kernel_start: u8;
    static __kernel_end: u8;
}

/// How many bytes of RAM the kernel image occupies.
///
/// Text, read-only data, data and `.bss` — which is where the back buffer
/// lives, and therefore most of the figure. This is what the machine is
/// actually using: there is no allocator, no page cache and no other process,
/// so the image *is* the footprint.
pub fn kernel_footprint() -> u64 {
    // Only the addresses of these symbols are taken; their contents are never
    // read, which is the documented way to use a symbol that has no object
    // behind it. Taking an address is safe — dereferencing would not be.
    let start = core::ptr::addr_of!(__kernel_start) as u64;
    let end = core::ptr::addr_of!(__kernel_end) as u64;
    end.saturating_sub(start)
}

/// Tag type 14: the ACPI 1.0 RSDP, copied by the loader.
const TAG_ACPI_OLD: u32 = 14;
/// Tag type 15: the ACPI 2.0 RSDP, which also carries the XSDT.
const TAG_ACPI_NEW: u32 = 15;

/// Where the ACPI root tables are.
///
/// # Why this has to come from the loader
///
/// On a BIOS machine the RSDP is found by scanning the EBDA and the top of
/// the first megabyte, which is what the specification says and what
/// [`crate::acpi`] does as a fallback.
///
/// **On a UEFI machine it is in neither place.** There is no BIOS data area
/// to hold the EBDA pointer and no reason for firmware to have put a copy in
/// the legacy window; the RSDP's address is handed to the OS loader through
/// the EFI configuration table and nowhere else. A kernel that only scans
/// therefore finds no ACPI at all on every recent laptop — which is exactly
/// how a touchpad whose address lives in the DSDT becomes unreachable, with
/// "the DSDT could not be read" as the only symptom.
///
/// GRUB solves this by copying the structure into the multiboot information,
/// which is what this reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rsdp {
    /// The 32-bit root table. Zero on firmware that provides only an XSDT,
    /// which ACPI 2.0 explicitly permits.
    pub rsdt: u32,
    /// The 64-bit root table, or zero before ACPI 2.0.
    pub xsdt: u64,
    pub revision: u8,
}

impl Rsdp {
    pub fn is_usable(&self) -> bool {
        self.rsdt != 0 || self.xsdt != 0
    }
}

/// Reads the RSDP the loader copied into the boot information.
///
/// Prefers the ACPI 2.0 tag, which carries the XSDT — the 64-bit root table
/// is the authoritative one from that revision, and firmware is allowed to
/// leave the 32-bit address zero.
///
/// # Safety
/// `info` must be the multiboot2 information pointer the loader passed, or
/// zero.
pub unsafe fn acpi_rsdp(info: u64) -> Option<Rsdp> {
    if info == 0 || info % 8 != 0 {
        return None;
    }
    let base = info as usize;
    // SAFETY: forwarded from this function's own contract.
    let total = unsafe { core::ptr::read_volatile(base as *const u32) } as usize;
    if !(16..0x10_0000).contains(&total) {
        return None;
    }

    let mut best: Option<Rsdp> = None;
    let mut offset = 8;
    while offset + 8 <= total {
        // SAFETY: bounded by the size the header declares.
        let (kind, size) = unsafe {
            (
                core::ptr::read_volatile((base + offset) as *const u32),
                core::ptr::read_volatile((base + offset + 4) as *const u32) as usize,
            )
        };
        // A tag that claims to run past the structure is corrupt, and
        // reading its body would read past what the loader handed over.
        if kind == TAG_END || size < 8 || offset + size > total {
            break;
        }

        if kind == TAG_ACPI_OLD || kind == TAG_ACPI_NEW {
            let body = base + offset + 8;
            let body_len = size - 8;
            // SAFETY: the tag's declared size covers the copy.
            if let Some(rsdp) = unsafe { parse_rsdp(body, body_len) } {
                // The 2.0 form wins wherever both are present.
                if kind == TAG_ACPI_NEW || best.is_none() {
                    best = Some(rsdp);
                }
            }
        }

        offset += size.div_ceil(8) * 8;
    }
    best
}

/// Validates an RSDP copy and pulls the root table addresses out of it.
///
/// The checksums are the point. An RSDP is identified by an eight-byte
/// signature, and eight bytes is short enough that it appears by accident;
/// the checksum is what the specification provides to tell a real one from a
/// coincidence, and following an address out of a false positive is a walk
/// through arbitrary memory.
///
/// # Safety
/// `at` must be `length` readable bytes.
unsafe fn parse_rsdp(at: usize, length: usize) -> Option<Rsdp> {
    if length < 20 {
        return None;
    }
    // SAFETY: forwarded from this function's own contract.
    let signature = unsafe { core::ptr::read_volatile(at as *const [u8; 8]) };
    if &signature != b"RSD PTR " {
        return None;
    }

    // SAFETY: as above.
    let sum = |count: usize| -> u8 {
        let mut total = 0u8;
        for i in 0..count {
            total = total.wrapping_add(unsafe { core::ptr::read_volatile((at + i) as *const u8) });
        }
        total
    };
    if sum(20) != 0 {
        return None;
    }

    // SAFETY: the first twenty bytes are present and verified.
    let revision = unsafe { core::ptr::read_volatile((at + 15) as *const u8) };
    let rsdt = unsafe { core::ptr::read_unaligned((at + 16) as *const u32) };

    let mut xsdt = 0u64;
    if revision >= 2 && length >= 36 {
        // The extended structure has its own checksum over the whole 36
        // bytes; a copy that fails it has an XSDT address not worth reading.
        if sum(36) == 0 {
            // SAFETY: the extended fields are present and verified.
            xsdt = unsafe { core::ptr::read_unaligned((at + 24) as *const u64) };
        }
    }

    let rsdp = Rsdp {
        rsdt,
        xsdt,
        revision,
    };
    rsdp.is_usable().then_some(rsdp)
}
