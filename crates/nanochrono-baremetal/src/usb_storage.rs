// SPDX-License-Identifier: Apache-2.0
//! Finding `CRASH.DMP` on a USB stick, so the crash path can write to it.
//!
//! The write itself must not touch a filesystem: a kernel that has just
//! faulted cannot be trusted to walk one correctly, and a stray write to a
//! FAT is how a stick full of a person's files stops mounting. So all of the
//! filesystem work happens **here, at boot**, while the machine is healthy:
//! this reads the partition table and the FAT, resolves `CRASH.DMP` to a list
//! of block ranges ([`Extent`]s), and hands those back. The crash path
//! ([`crate::crashdump`]) then does nothing but write raw blocks into ranges
//! that were already there — it never allocates a cluster, never grows the
//! file and never rewrites a directory entry. Nothing here writes at all.
//!
//! The file must therefore exist, and be at least as large as a dump, before
//! it can catch anything. The x86_64 ISO carries one on a small FAT partition
//! of its own, so a stick written from it with `dd` is its own dump target;
//! any other stick needs the file created on it. `docs/CRASH_DUMPS.md` says
//! how.
//!
//! # What is supported
//!
//! FAT16 and FAT32, with 512-byte logical sectors equal to the device's block
//! size (almost every stick). FAT12 is not read. The volume may be the whole
//! device (a "superfloppy", no partition table), any partition of an MBR, or
//! any partition of a GPT — which is what a hybrid ISO written to a stick
//! carries. A partition is only used once its boot sector parses as FAT, so
//! the ISO 9660, HFS+ and EFI areas of such a stick are passed over. A stick
//! with none of this is reported as having no `CRASH.DMP`, and the crash
//! dump falls back to the serial port.
//!
//! # Reference
//!
//! Microsoft's FAT specification for the boot-sector layout and the FAT12/16
//! cluster-count rule, and the UEFI specification for the GPT header and
//! entry layout. FreeBSD's `sys/fs/msdosfs` (`msdosfs_vfsops.c`, `fat.h`) was
//! consulted to cross-check how a FAT32 volume is recognised; it is
//! BSD-4-Clause, and nothing of it is reproduced here.

use crate::xhci::Xhci;

/// A contiguous run of device blocks belonging to the file.
#[derive(Clone, Copy, Default)]
pub struct Extent {
    pub lba: u32,
    pub blocks: u32,
}

/// The most fragments of `CRASH.DMP` this will follow. A 64 KiB file on a
/// stick with 4 KiB clusters is sixteen clusters; a fragmented one, more.
/// Past this the file is treated as not found rather than partially written.
pub const MAX_EXTENTS: usize = 64;

/// Where `CRASH.DMP` lives on the stick, as raw block ranges.
#[derive(Clone, Copy)]
pub struct CrashFile {
    pub extents: [Extent; MAX_EXTENTS],
    pub extent_count: usize,
    /// The directory entry's file size: how many bytes may be written.
    pub size: u32,
}

impl CrashFile {
    /// Total bytes the extents can hold.
    pub fn capacity(&self) -> u64 {
        self.extents[..self.extent_count]
            .iter()
            .map(|e| e.blocks as u64)
            .sum::<u64>()
            * BLOCK as u64
    }
}

/// The one block size this understands. A stick reporting anything else is
/// declined rather than misread.
const BLOCK: usize = 512;

/// One sector, read from the stick.
type Sector = [u8; BLOCK];

/// Reads `lba` into a fresh sector, or `None`.
///
/// # Safety
/// Drives the controller; requires ring 0.
unsafe fn read(xhci: &mut Xhci, lba: u32) -> Option<Sector> {
    let mut sector = [0u8; BLOCK];
    // SAFETY: forwarded from this function's own contract.
    unsafe { xhci.read_block(lba, &mut sector)? };
    Some(sector)
}

/// Finds `CRASH.DMP` on the stick `xhci` has enumerated.
///
/// # Safety
/// Drives the controller; requires ring 0.
pub unsafe fn find_crash_file(xhci: &mut Xhci) -> Option<CrashFile> {
    // Only the 512-byte case is handled; the FAT arithmetic below counts in
    // logical sectors and assumes they are device blocks.
    if xhci.block_size() != BLOCK as u32 {
        return None;
    }

    // SAFETY: forwarded from this function's own contract.
    let sector0 = unsafe { read(xhci, 0)? };
    if sector0[510] != 0x55 || sector0[511] != 0xAA {
        return None;
    }

    // A superfloppy: the boot sector of the volume is sector 0 itself.
    if parse_volume(&sector0, 0).is_some() {
        // SAFETY: as above.
        return unsafe { find_in_volume(xhci, 0) };
    }

    // A protective MBR (type 0xEE) means the real table is the GPT.
    let protective = (0..4).any(|i| sector0[0x1BE + i * 16 + 4] == 0xEE);
    if protective {
        // SAFETY: as above.
        return unsafe { find_in_gpt(xhci) };
    }

    // Otherwise the four primary MBR partitions, any FAT type.
    for i in 0..4 {
        let entry = &sector0[0x1BE + i * 16..0x1BE + i * 16 + 16];
        let kind = entry[4];
        let start = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
        // 0x04/0x06/0x0E are FAT16, 0x0B/0x0C FAT32. The boot sector still
        // has to parse before anything is trusted.
        if matches!(kind, 0x04 | 0x06 | 0x0E | 0x0B | 0x0C) && start != 0 {
            // SAFETY: as above.
            if let Some(file) = unsafe { find_in_volume(xhci, start) } {
                return Some(file);
            }
        }
    }
    None
}

/// The GPT header's signature, at the start of LBA 1.
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

/// How many GPT entries are looked at. 128 is what every tool writes.
const GPT_MAX_ENTRIES: u32 = 128;

/// Walks the GPT for a partition whose boot sector parses as FAT and holds
/// `CRASH.DMP`.
///
/// The partition type GUID is not trusted to say FAT — "Microsoft basic
/// data" covers NTFS and exFAT too, and a hybrid ISO labels its ISO 9660
/// area with it — so every used entry is tried and the boot sector decides.
///
/// # Safety
/// Drives the controller; requires ring 0.
unsafe fn find_in_gpt(xhci: &mut Xhci) -> Option<CrashFile> {
    // SAFETY: forwarded from this function's own contract.
    let header = unsafe { read(xhci, 1)? };
    if &header[0..8] != GPT_SIGNATURE {
        return None;
    }
    let entries_lba = u64::from_le_bytes(header[72..80].try_into().ok()?);
    let count = u32::from_le_bytes(header[80..84].try_into().ok()?).min(GPT_MAX_ENTRIES);
    let entry_size = u32::from_le_bytes(header[84..88].try_into().ok()?) as usize;
    // The specification allows 128 << n; anything that does not divide a
    // sector evenly is not something this reads.
    if entry_size < 128 || BLOCK % entry_size != 0 || entries_lba > u32::MAX as u64 {
        return None;
    }
    let per_sector = BLOCK / entry_size;

    for n in 0..count as usize {
        let lba = entries_lba as u32 + (n / per_sector) as u32;
        // SAFETY: as above.
        let sector = unsafe { read(xhci, lba)? };
        let at = (n % per_sector) * entry_size;
        let entry = &sector[at..at + entry_size];
        // An all-zero type GUID is an unused entry.
        if entry[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        let first = u64::from_le_bytes(entry[32..40].try_into().ok()?);
        if first == 0 || first > u32::MAX as u64 {
            continue;
        }
        // SAFETY: as above.
        let Some(boot) = (unsafe { read(xhci, first as u32) }) else {
            continue;
        };
        if parse_volume(&boot, first as u32).is_none() {
            continue;
        }
        // SAFETY: as above.
        if let Some(file) = unsafe { find_in_volume(xhci, first as u32) } {
            return Some(file);
        }
    }
    None
}

/// Which FAT a volume is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FatKind {
    Fat16,
    Fat32,
}

/// The parsed boot-sector fields the walk needs.
struct Volume {
    kind: FatKind,
    fat_start: u32,
    data_start: u32,
    sectors_per_cluster: u32,
    /// FAT32: the root directory's first cluster.
    root_cluster: u32,
    /// FAT16: the fixed root directory region, between the FATs and the data.
    root_start: u32,
    root_sectors: u32,
    total_clusters: u32,
}

/// Reads and validates the boot sector of a volume at `part_start`, and
/// works out whether it is FAT16 or FAT32.
///
/// FAT32 is recognised by its boot sector — no 16-bit FAT size — the way
/// FreeBSD's msdosfs and Linux's vfat do, which also accepts the small FAT32
/// volumes formatters make below the specification's 65525 clusters. FAT12
/// and FAT16 are then told apart by cluster count, as the specification
/// requires. The type string is never consulted: it is informational, and
/// formatters get it wrong.
fn parse_volume(bpb: &Sector, part_start: u32) -> Option<Volume> {
    // A boot sector starts with a jump and ends with the signature.
    if !matches!(bpb[0], 0xEB | 0xE9) || bpb[510] != 0x55 || bpb[511] != 0xAA {
        return None;
    }
    let bytes_per_sector = u16::from_le_bytes([bpb[11], bpb[12]]) as u32;
    let sectors_per_cluster = bpb[13] as u32;
    let reserved = u16::from_le_bytes([bpb[14], bpb[15]]) as u32;
    let num_fats = bpb[16] as u32;
    let root_entries = u16::from_le_bytes([bpb[17], bpb[18]]) as u32;
    let total16 = u16::from_le_bytes([bpb[19], bpb[20]]) as u32;
    let fat16_size = u16::from_le_bytes([bpb[22], bpb[23]]) as u32;
    let total32 = u32::from_le_bytes([bpb[32], bpb[33], bpb[34], bpb[35]]);
    let fat32_size = u32::from_le_bytes([bpb[36], bpb[37], bpb[38], bpb[39]]);
    let root_cluster = u32::from_le_bytes([bpb[44], bpb[45], bpb[46], bpb[47]]);

    if bytes_per_sector != BLOCK as u32
        || sectors_per_cluster == 0
        || !sectors_per_cluster.is_power_of_two()
        || reserved == 0
        || num_fats == 0
    {
        return None;
    }
    let fat_size = if fat16_size != 0 { fat16_size } else { fat32_size };
    let total = if total16 != 0 { total16 } else { total32 };
    if fat_size == 0 || total == 0 {
        return None;
    }

    let root_sectors = (root_entries * 32).div_ceil(BLOCK as u32);
    let meta = reserved
        .checked_add(num_fats.checked_mul(fat_size)?)?
        .checked_add(root_sectors)?;
    let data_sectors = total.checked_sub(meta)?;
    let total_clusters = data_sectors / sectors_per_cluster;

    let kind = if fat16_size == 0 {
        FatKind::Fat32
    } else if total_clusters < 4085 {
        // FAT12: not read.
        return None;
    } else if total_clusters < 65525 {
        FatKind::Fat16
    } else {
        // A 16-bit FAT cannot number this many clusters: inconsistent.
        return None;
    };
    // A FAT32 volume has no fixed root region and a real root cluster; a
    // FAT16 one has the region. Anything else is inconsistent.
    match kind {
        FatKind::Fat32 if root_entries != 0 || root_cluster < 2 => return None,
        FatKind::Fat16 if root_entries == 0 => return None,
        _ => {}
    }

    let fat_start = part_start.checked_add(reserved)?;
    let root_start = fat_start.checked_add(num_fats * fat_size)?;
    let data_start = root_start.checked_add(root_sectors)?;
    Some(Volume {
        kind,
        fat_start,
        data_start,
        sectors_per_cluster,
        root_cluster,
        root_start,
        root_sectors,
        total_clusters,
    })
}

/// The first block of a cluster.
fn cluster_lba(vol: &Volume, cluster: u32) -> u32 {
    vol.data_start + (cluster - 2) * vol.sectors_per_cluster
}

/// Whether `cluster` names a data cluster of this volume. End-of-chain,
/// bad-cluster and free markers all fall outside, which is what ends a walk.
fn is_data_cluster(vol: &Volume, cluster: u32) -> bool {
    cluster >= 2 && cluster < vol.total_clusters + 2
}

/// The next cluster in a chain, read from the first FAT.
///
/// # Safety
/// Drives the controller; requires ring 0.
unsafe fn next_cluster(xhci: &mut Xhci, vol: &Volume, cluster: u32) -> Option<u32> {
    let width = match vol.kind {
        FatKind::Fat16 => 2,
        FatKind::Fat32 => 4,
    };
    let byte = cluster as usize * width;
    let fat_sector = vol.fat_start + (byte / BLOCK) as u32;
    let offset = byte % BLOCK;
    // SAFETY: forwarded from this function's own contract.
    let sector = unsafe { read(xhci, fat_sector)? };
    Some(match vol.kind {
        FatKind::Fat16 => u16::from_le_bytes([sector[offset], sector[offset + 1]]) as u32,
        // FAT32 entries are 28 bits; the top four are reserved.
        FatKind::Fat32 => {
            u32::from_le_bytes([
                sector[offset],
                sector[offset + 1],
                sector[offset + 2],
                sector[offset + 3],
            ]) & 0x0FFF_FFFF
        }
    })
}

/// `CRASH.DMP` as an 8.3 directory name: eight-plus-three, space padded.
const CRASH_DMP_83: &[u8; 11] = b"CRASH   DMP";

/// The most root-directory clusters walked on FAT32 before giving up, so a
/// corrupt chain cannot loop forever.
const MAX_DIR_CLUSTERS: usize = 32;

/// What scanning one directory sector found.
enum Scan {
    /// The entry: first cluster and size.
    Found(u32, u32),
    /// The end-of-directory marker: no such file.
    End,
    /// Neither: keep reading.
    More,
}

/// Looks through one sector of directory entries for `CRASH.DMP`.
fn scan_directory(sector: &Sector) -> Scan {
    for e in 0..(BLOCK / 32) {
        let entry = &sector[e * 32..e * 32 + 32];
        match entry[0] {
            0x00 => return Scan::End, // end of directory
            0xE5 => continue,         // deleted
            _ => {}
        }
        // Long-file-name components and the volume label are not files.
        if entry[11] & 0x0F == 0x0F || entry[11] & 0x08 != 0 {
            continue;
        }
        if &entry[0..11] == CRASH_DMP_83 {
            // The high half is FAT32's; FAT16 keeps it zero, and a volume
            // that does not is caught by the data-cluster check downstream.
            let first = (u16::from_le_bytes([entry[20], entry[21]]) as u32) << 16
                | u16::from_le_bytes([entry[26], entry[27]]) as u32;
            let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
            return Scan::Found(first, size);
        }
    }
    Scan::More
}

/// Looks for `CRASH.DMP` in the root directory of the FAT volume at
/// `part_start`.
///
/// # Safety
/// Drives the controller; requires ring 0.
unsafe fn find_in_volume(xhci: &mut Xhci, part_start: u32) -> Option<CrashFile> {
    // SAFETY: forwarded from this function's own contract.
    let bpb = unsafe { read(xhci, part_start)? };
    let vol = parse_volume(&bpb, part_start)?;

    match vol.kind {
        // FAT16: the root directory is a fixed run of sectors.
        FatKind::Fat16 => {
            for s in 0..vol.root_sectors {
                // SAFETY: as above.
                let sector = unsafe { read(xhci, vol.root_start + s)? };
                match scan_directory(&sector) {
                    // SAFETY: as above.
                    Scan::Found(first, size) => return unsafe { extents_of(xhci, &vol, first, size) },
                    Scan::End => return None,
                    Scan::More => {}
                }
            }
        }
        // FAT32: the root directory is a cluster chain like any file.
        FatKind::Fat32 => {
            let mut cluster = vol.root_cluster;
            for _ in 0..MAX_DIR_CLUSTERS {
                if !is_data_cluster(&vol, cluster) {
                    break;
                }
                for s in 0..vol.sectors_per_cluster {
                    // SAFETY: as above.
                    let sector = unsafe { read(xhci, cluster_lba(&vol, cluster) + s)? };
                    match scan_directory(&sector) {
                        Scan::Found(first, size) => {
                            // SAFETY: as above.
                            return unsafe { extents_of(xhci, &vol, first, size) };
                        }
                        Scan::End => return None,
                        Scan::More => {}
                    }
                }
                // SAFETY: as above.
                cluster = unsafe { next_cluster(xhci, &vol, cluster)? };
            }
        }
    }
    None
}

/// Follows a file's cluster chain into a coalesced list of block extents.
///
/// # Safety
/// Drives the controller; requires ring 0.
unsafe fn extents_of(xhci: &mut Xhci, vol: &Volume, first: u32, size: u32) -> Option<CrashFile> {
    let mut file = CrashFile {
        extents: [Extent::default(); MAX_EXTENTS],
        extent_count: 0,
        size,
    };
    let per_cluster = vol.sectors_per_cluster;
    let mut cluster = first;
    // Enough clusters to cover the file and no more: the chain is followed
    // only as far as the size says, so a chain longer than the file (or a
    // loop in a corrupt FAT) cannot run away.
    let cluster_bytes = per_cluster as u64 * BLOCK as u64;
    let needed = (size as u64).div_ceil(cluster_bytes).max(1);

    for _ in 0..needed {
        if !is_data_cluster(vol, cluster) {
            break;
        }
        let lba = cluster_lba(vol, cluster);
        // Coalesce a cluster physically contiguous with the last extent, so
        // an unfragmented file is one extent, not dozens.
        let extended = match file.extent_count {
            0 => false,
            n => {
                let last = &mut file.extents[n - 1];
                if last.lba + last.blocks == lba {
                    last.blocks += per_cluster;
                    true
                } else {
                    false
                }
            }
        };
        if !extended {
            if file.extent_count == MAX_EXTENTS {
                // Too fragmented to record: better to fall back to serial
                // than to write only part of the dump.
                return None;
            }
            file.extents[file.extent_count] = Extent { lba, blocks: per_cluster };
            file.extent_count += 1;
        }
        // SAFETY: forwarded from this function's own contract.
        cluster = unsafe { next_cluster(xhci, vol, cluster)? };
    }

    (file.extent_count > 0).then_some(file)
}
