// SPDX-License-Identifier: Apache-2.0
//! The on-disk format: blocks, the superblock, tree nodes, keys and items.
//!
//! Everything is little-endian, read and written by shifting, so the
//! big-endian PowerPC targets read the same volume. Every structure has a
//! fixed layout and is checked field by field when it is decoded; nothing
//! is trusted because it parsed. docs/NCFS.md is the prose version of this
//! file, table for table.

use super::Error;
use crate::blake3;

/// The block size. Fixed in format version 1.
pub const BLOCK: usize = 4096;
/// A superblock's magic.
pub const MAGIC: [u8; 8] = *b"NCFS\x1b\x00\x01\x00";
/// The format version this code reads and writes.
pub const VERSION: u32 = 1;
/// Superblock slots: generation `g` is written to `SUPER[g % 2]`.
pub const SUPER: [u64; 2] = [1, 2];
/// The signature area of a sealed (seed) volume.
pub const SIG_FIRST: u64 = 3;
pub const SIG_BLOCKS: u64 = 16;
/// The first block the allocator may hand out.
pub const FIRST_FREE: u64 = SIG_FIRST + SIG_BLOCKS;
/// The smallest volume: 1 MiB.
pub const MIN_BLOCKS: u64 = 256;
/// A node's magic.
pub const NODE_MAGIC: [u8; 4] = *b"NCND";
/// The node header's length.
pub const NODE_HEADER: usize = 64;
/// A leaf's item header: a key, then the data's offset and length.
pub const ITEM_HEADER: usize = KEY_LEN + 4;
/// An internal node's entry: a key, then a child pointer without its level.
pub const CHILD_ENTRY: usize = KEY_LEN + 8 + 8 + 32;
/// The most children an internal node holds.
pub const MAX_CHILDREN: usize = (BLOCK - NODE_HEADER) / CHILD_ENTRY;
/// The largest item: one that fills an empty leaf.
pub const MAX_ITEM: usize = BLOCK - NODE_HEADER - ITEM_HEADER;
/// The deepest tree a reader follows (levels 0..MAX_LEVEL).
pub const MAX_LEVEL: u8 = 8;
/// File data is stored in windows of this many bytes, one extent each.
pub const WINDOW: usize = 128 * 1024;
/// Blocks in a window.
pub const WINDOW_BLOCKS: u64 = (WINDOW / BLOCK) as u64;
/// Files up to this size are stored inside their extent item.
pub const INLINE_MAX: usize = 2048;
/// The longest name.
pub const NAME_MAX: usize = 255;
/// The root directory's inode number (FUSE's root id too).
pub const ROOT_INO: u64 = 1;
/// The default subvolume's id.
pub const DEFAULT_SUBVOL: u64 = 1;

/// Superblock flag: a sealed, read-only image (`ncinitramdisk`).
pub const FLAG_SEED: u64 = 1 << 0;
/// Features this code knows; a volume naming any other incompatible one is
/// refused, an unknown read-only-compatible one makes it read-only.
pub const INCOMPAT_KNOWN: u64 = INCOMPAT_LZ4 | INCOMPAT_ZSTD;
pub const INCOMPAT_LZ4: u64 = 1 << 0;
pub const INCOMPAT_ZSTD: u64 = 1 << 1;
pub const RO_COMPAT_KNOWN: u64 = 0;

/// Item kinds.
pub const KIND_INODE: u8 = 1;
pub const KIND_DIRENT: u8 = 2;
pub const KIND_DIRINDEX: u8 = 3;
pub const KIND_EXTENT: u8 = 4;
pub const KIND_ROOT: u8 = 16;

/// Directory entry types (the `d_type` values POSIX systems use).
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;

/// `st_mode` file types.
pub const S_IFMT: u32 = 0o170_000;
pub const S_IFSOCK: u32 = 0o140_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFREG: u32 = 0o100_000;
pub const S_IFBLK: u32 = 0o060_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFCHR: u32 = 0o020_000;
pub const S_IFIFO: u32 = 0o010_000;

/// The `d_type` of an `st_mode`.
pub const fn dtype(mode: u32) -> u8 {
    match mode & S_IFMT {
        S_IFDIR => DT_DIR,
        S_IFLNK => DT_LNK,
        S_IFCHR => DT_CHR,
        S_IFBLK => DT_BLK,
        S_IFIFO => DT_FIFO,
        S_IFSOCK => DT_SOCK,
        _ => DT_REG,
    }
}

pub(crate) fn rd16(b: &[u8], at: usize) -> u16 {
    u16::from(b[at]) | u16::from(b[at + 1]) << 8
}

pub(crate) fn rd32(b: &[u8], at: usize) -> u32 {
    u32::from(rd16(b, at)) | u32::from(rd16(b, at + 2)) << 16
}

pub(crate) fn rd64(b: &[u8], at: usize) -> u64 {
    u64::from(rd32(b, at)) | u64::from(rd32(b, at + 4)) << 32
}

pub(crate) fn wr16(b: &mut [u8], at: usize, v: u16) {
    b[at] = v as u8;
    b[at + 1] = (v >> 8) as u8;
}

pub(crate) fn wr32(b: &mut [u8], at: usize, v: u32) {
    wr16(b, at, v as u16);
    wr16(b, at + 2, (v >> 16) as u16);
}

pub(crate) fn wr64(b: &mut [u8], at: usize, v: u64) {
    wr32(b, at, v as u32);
    wr32(b, at + 4, (v >> 32) as u32);
}

fn hash32(b: &[u8], at: usize) -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(&b[at..at + 32]);
    h
}

/// A key: object, kind, offset — ordered in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Key {
    pub obj: u64,
    pub kind: u8,
    pub off: u64,
}

pub const KEY_LEN: usize = 17;

impl Key {
    pub const MIN: Key = Key { obj: 0, kind: 0, off: 0 };
    pub const MAX: Key = Key { obj: u64::MAX, kind: u8::MAX, off: u64::MAX };

    pub const fn new(obj: u64, kind: u8, off: u64) -> Key {
        Key { obj, kind, off }
    }

    pub fn read(b: &[u8], at: usize) -> Key {
        Key { obj: rd64(b, at), kind: b[at + 8], off: rd64(b, at + 9) }
    }

    pub fn write(&self, b: &mut [u8], at: usize) {
        wr64(b, at, self.obj);
        b[at + 8] = self.kind;
        wr64(b, at + 9, self.off);
    }

    /// The next key in order, or `None` after [`Key::MAX`].
    pub fn successor(&self) -> Option<Key> {
        if let Some(off) = self.off.checked_add(1) {
            return Some(Key { off, ..*self });
        }
        if let Some(kind) = self.kind.checked_add(1) {
            return Some(Key { obj: self.obj, kind, off: 0 });
        }
        self.obj.checked_add(1).map(|obj| Key { obj, kind: 0, off: 0 })
    }
}

/// A pointer to a tree node: where it is, when it was written, its BLAKE3
/// (of the whole block) and its level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ptr {
    pub block: u64,
    pub gen: u64,
    pub hash: [u8; 32],
    pub level: u8,
}

pub const PTR_LEN: usize = 49;

impl Ptr {
    pub fn read(b: &[u8], at: usize) -> Ptr {
        Ptr { block: rd64(b, at), gen: rd64(b, at + 8), hash: hash32(b, at + 16), level: b[at + 48] }
    }

    pub fn write(&self, b: &mut [u8], at: usize) {
        wr64(b, at, self.block);
        wr64(b, at + 8, self.gen);
        b[at + 16..at + 48].copy_from_slice(&self.hash);
        b[at + 48] = self.level;
    }
}

/// The superblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superblock {
    pub incompat: u64,
    pub ro_compat: u64,
    pub compat: u64,
    pub flags: u64,
    pub fsid: [u8; 16],
    pub label: [u8; 64],
    pub generation: u64,
    pub total_blocks: u64,
    pub created: i64,
    pub committed: i64,
    /// The tree of subvolumes.
    pub root_tree: Ptr,
    pub next_subvol: u64,
    pub default_subvol: u64,
    /// Blocks in use (informational: the allocator recounts them).
    pub used_blocks: u64,
    /// Blocks of the signature area in use (0: not sealed).
    pub sig_blocks: u16,
}

/// Where the superblock's checksum is.
const SB_SUM: usize = BLOCK - 32;

impl Superblock {
    pub fn encode(&self) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        b[..8].copy_from_slice(&MAGIC);
        wr32(&mut b, 8, VERSION);
        wr32(&mut b, 12, BLOCK as u32);
        wr64(&mut b, 16, self.incompat);
        wr64(&mut b, 24, self.ro_compat);
        wr64(&mut b, 32, self.compat);
        wr64(&mut b, 40, self.flags);
        b[48..64].copy_from_slice(&self.fsid);
        b[64..128].copy_from_slice(&self.label);
        wr64(&mut b, 128, self.generation);
        wr64(&mut b, 136, self.total_blocks);
        wr64(&mut b, 144, self.created as u64);
        wr64(&mut b, 152, self.committed as u64);
        self.root_tree.write(&mut b, 160);
        wr64(&mut b, 216, self.next_subvol);
        wr64(&mut b, 224, self.default_subvol);
        wr64(&mut b, 232, self.used_blocks);
        wr16(&mut b, 240, self.sig_blocks);
        let sum = blake3::hash(&b[..SB_SUM]);
        b[SB_SUM..].copy_from_slice(&sum);
        b
    }

    /// Decodes and checks one superblock copy.
    pub fn decode(b: &[u8]) -> Result<Superblock, Error> {
        if b.len() != BLOCK || b[..8] != MAGIC {
            return Err(Error::NoSuperblock);
        }
        let sum = blake3::hash(&b[..SB_SUM]);
        if !blake3::ct_eq(&sum, &hash32(b, SB_SUM)) {
            return Err(Error::NoSuperblock);
        }
        if rd32(b, 8) != VERSION || rd32(b, 12) != BLOCK as u32 {
            return Err(Error::Unsupported);
        }
        if b[242..SB_SUM].iter().any(|&x| x != 0) || b[209..216].iter().any(|&x| x != 0) {
            return Err(Error::NoSuperblock);
        }
        let mut fsid = [0u8; 16];
        fsid.copy_from_slice(&b[48..64]);
        let mut label = [0u8; 64];
        label.copy_from_slice(&b[64..128]);
        let sb = Superblock {
            incompat: rd64(b, 16),
            ro_compat: rd64(b, 24),
            compat: rd64(b, 32),
            flags: rd64(b, 40),
            fsid,
            label,
            generation: rd64(b, 128),
            total_blocks: rd64(b, 136),
            created: rd64(b, 144) as i64,
            committed: rd64(b, 152) as i64,
            root_tree: Ptr::read(b, 160),
            next_subvol: rd64(b, 216),
            default_subvol: rd64(b, 224),
            used_blocks: rd64(b, 232),
            sig_blocks: rd16(b, 240),
        };
        if sb.incompat & !INCOMPAT_KNOWN != 0 {
            return Err(Error::Unsupported);
        }
        if sb.total_blocks < MIN_BLOCKS
            || sb.root_tree.block < FIRST_FREE
            || sb.root_tree.block >= sb.total_blocks
            || sb.root_tree.level >= MAX_LEVEL
            || u64::from(sb.sig_blocks) > SIG_BLOCKS
            || sb.default_subvol == 0
            || sb.next_subvol <= sb.default_subvol
        {
            return Err(Error::NoSuperblock);
        }
        Ok(sb)
    }

    /// Mounting writable needs every read-only-compatible feature known
    /// and the volume not sealed.
    pub fn writable(&self) -> bool {
        self.ro_compat & !RO_COMPAT_KNOWN == 0 && self.flags & FLAG_SEED == 0
    }

    /// The label as text, up to its first NUL.
    pub fn label(&self) -> &str {
        let n = self.label.iter().position(|&c| c == 0).unwrap_or(self.label.len());
        core::str::from_utf8(&self.label[..n]).unwrap_or("")
    }
}

/// A node's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeHeader {
    pub level: u8,
    pub count: u16,
    pub block: u64,
    pub gen: u64,
    pub owner: u64,
    pub fsid: [u8; 16],
}

impl NodeHeader {
    pub fn read(b: &[u8]) -> Option<NodeHeader> {
        if b.len() != BLOCK || b[..4] != NODE_MAGIC || b[5] != 0 || b[48..NODE_HEADER].iter().any(|&x| x != 0) {
            return None;
        }
        let mut fsid = [0u8; 16];
        fsid.copy_from_slice(&b[32..48]);
        Some(NodeHeader { level: b[4], count: rd16(b, 6), block: rd64(b, 8), gen: rd64(b, 16), owner: rd64(b, 24), fsid })
    }

    pub fn write(&self, b: &mut [u8]) {
        b[..4].copy_from_slice(&NODE_MAGIC);
        b[4] = self.level;
        b[5] = 0;
        wr16(b, 6, self.count);
        wr64(b, 8, self.block);
        wr64(b, 16, self.gen);
        wr64(b, 24, self.owner);
        b[32..48].copy_from_slice(&self.fsid);
        b[48..NODE_HEADER].fill(0);
    }
}

/// Checks a node block against the pointer that led to it and against the
/// format's structural rules; on success the node can be read with
/// [`leaf_item`] or [`child`] without further bounds worries.
///
/// `owner` is the tree being read: 0 for the tree of subvolumes, a
/// subvolume's id otherwise. A node records the tree that wrote it, and a
/// snapshot reads nodes its source wrote, so only the class is checked: a
/// subvolume node is never taken for the tree of subvolumes or the reverse.
pub fn check_node(b: &[u8], ptr: &Ptr, fsid: &[u8; 16], owner: u64) -> Result<NodeHeader, Error> {
    let sum = blake3::hash(b);
    if !blake3::ct_eq(&sum, &ptr.hash) {
        return Err(Error::Checksum(ptr.block));
    }
    let h = NodeHeader::read(b).ok_or(Error::Corrupt(ptr.block))?;
    let class_ok = (h.owner == 0) == (owner == 0);
    if h.block != ptr.block || h.gen != ptr.gen || h.level != ptr.level || h.fsid != *fsid || !class_ok || h.level >= MAX_LEVEL {
        return Err(Error::Corrupt(ptr.block));
    }
    let n = usize::from(h.count);
    if h.level == 0 {
        // Item data packed from the end, in item order, no gaps: there is
        // nowhere to hide anything, and nothing overlaps.
        if NODE_HEADER + n * ITEM_HEADER > BLOCK {
            return Err(Error::Corrupt(ptr.block));
        }
        let mut end = BLOCK;
        let mut prev: Option<Key> = None;
        for i in 0..n {
            let at = NODE_HEADER + i * ITEM_HEADER;
            let k = Key::read(b, at);
            let off = usize::from(rd16(b, at + KEY_LEN));
            let len = usize::from(rd16(b, at + KEY_LEN + 2));
            if off + len != end || off < NODE_HEADER + n * ITEM_HEADER || prev.is_some_and(|p| p >= k) {
                return Err(Error::Corrupt(ptr.block));
            }
            end = off;
            prev = Some(k);
        }
        if b[NODE_HEADER + n * ITEM_HEADER..end].iter().any(|&x| x != 0) {
            return Err(Error::Corrupt(ptr.block));
        }
    } else {
        if n == 0 || n > MAX_CHILDREN {
            return Err(Error::Corrupt(ptr.block));
        }
        let mut prev: Option<Key> = None;
        for i in 0..n {
            let at = NODE_HEADER + i * CHILD_ENTRY;
            let k = Key::read(b, at);
            if prev.is_some_and(|p| p >= k) {
                return Err(Error::Corrupt(ptr.block));
            }
            prev = Some(k);
        }
        if b[NODE_HEADER + n * CHILD_ENTRY..].iter().any(|&x| x != 0) {
            return Err(Error::Corrupt(ptr.block));
        }
    }
    Ok(h)
}

/// Item `i` of a checked leaf.
pub fn leaf_item(b: &[u8], i: usize) -> (Key, &[u8]) {
    let at = NODE_HEADER + i * ITEM_HEADER;
    let off = usize::from(rd16(b, at + KEY_LEN));
    let len = usize::from(rd16(b, at + KEY_LEN + 2));
    (Key::read(b, at), &b[off..off + len])
}

/// Child `i` of a checked internal node at `level`.
pub fn child(b: &[u8], i: usize, level: u8) -> (Key, Ptr) {
    let at = NODE_HEADER + i * CHILD_ENTRY;
    let k = Key::read(b, at);
    let p = Ptr { block: rd64(b, at + KEY_LEN), gen: rd64(b, at + KEY_LEN + 8), hash: hash32(b, at + KEY_LEN + 16), level: level - 1 };
    (k, p)
}

/// Writes child entry `i`.
pub fn write_child(b: &mut [u8], i: usize, k: &Key, p: &Ptr) {
    let at = NODE_HEADER + i * CHILD_ENTRY;
    k.write(b, at);
    wr64(b, at + KEY_LEN, p.block);
    wr64(b, at + KEY_LEN + 8, p.gen);
    b[at + KEY_LEN + 16..at + KEY_LEN + 48].copy_from_slice(&p.hash);
}

/// In an internal node's keys, the child to descend into for `k`: the last
/// whose key is ≤ `k`, or the first.
pub fn child_index(keys: impl Iterator<Item = Key>, k: &Key) -> usize {
    let mut pick = 0;
    for (i, key) in keys.enumerate() {
        if key <= *k {
            pick = i;
        } else {
            break;
        }
    }
    pick
}

/// An inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Inode {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub btime: i64,
    pub flags: u64,
    pub generation: u64,
    /// A directory's parent.
    pub parent: u64,
    /// A directory's next index sequence number.
    pub next_index: u64,
    pub rdev: u64,
    /// Bytes its extents occupy on disk.
    pub disk_bytes: u64,
}

pub const INODE_LEN: usize = 112;
/// Inode flag: never compress this file's data.
pub const INODE_NOCOMPRESS: u64 = 1 << 0;
/// Inode flag: never share this file's extents with others.
pub const INODE_NODEDUP: u64 = 1 << 1;

impl Inode {
    pub fn encode(&self) -> [u8; INODE_LEN] {
        let mut b = [0u8; INODE_LEN];
        wr32(&mut b, 0, self.mode);
        wr32(&mut b, 4, self.uid);
        wr32(&mut b, 8, self.gid);
        wr32(&mut b, 12, self.nlink);
        wr64(&mut b, 16, self.size);
        wr64(&mut b, 24, self.atime as u64);
        wr64(&mut b, 32, self.mtime as u64);
        wr64(&mut b, 40, self.ctime as u64);
        wr64(&mut b, 48, self.btime as u64);
        wr64(&mut b, 56, self.flags);
        wr64(&mut b, 64, self.generation);
        wr64(&mut b, 72, self.parent);
        wr64(&mut b, 80, self.next_index);
        wr64(&mut b, 88, self.rdev);
        wr64(&mut b, 96, self.disk_bytes);
        b
    }

    pub fn decode(b: &[u8]) -> Option<Inode> {
        if b.len() != INODE_LEN || b[104..].iter().any(|&x| x != 0) {
            return None;
        }
        Some(Inode {
            mode: rd32(b, 0),
            uid: rd32(b, 4),
            gid: rd32(b, 8),
            nlink: rd32(b, 12),
            size: rd64(b, 16),
            atime: rd64(b, 24) as i64,
            mtime: rd64(b, 32) as i64,
            ctime: rd64(b, 40) as i64,
            btime: rd64(b, 48) as i64,
            flags: rd64(b, 56),
            generation: rd64(b, 64),
            parent: rd64(b, 72),
            next_index: rd64(b, 80),
            rdev: rd64(b, 88),
            disk_bytes: rd64(b, 96),
        })
    }

    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

    pub fn is_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
}

/// How an extent's bytes are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Compression {
    None = 0,
    Lz4 = 1,
    Zstd = 2,
}

impl Compression {
    pub fn from_u8(v: u8) -> Option<Compression> {
        match v {
            0 => Some(Compression::None),
            1 => Some(Compression::Lz4),
            2 => Some(Compression::Zstd),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Lz4 => "lz4",
            Compression::Zstd => "zstd",
        }
    }
}

/// An extent: one window of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extent<'a> {
    /// Stored in the item itself.
    Inline { compression: Compression, len: u32, data: &'a [u8] },
    /// Stored in blocks of its own.
    Regular(Region),
}

/// Where a regular extent's bytes are, and what they must hash to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Region {
    pub compression: Compression,
    /// Bytes of file content the extent holds.
    pub len: u32,
    pub block: u64,
    pub blocks: u32,
    /// Bytes stored in the blocks (compressed, or `len`).
    pub stored: u32,
    pub birth: u64,
    pub hash: [u8; 32],
}

pub const EXTENT_HEADER: usize = 8;
pub const REGION_LEN: usize = EXTENT_HEADER + 56;

impl<'a> Extent<'a> {
    pub fn decode(b: &'a [u8]) -> Option<Extent<'a>> {
        if b.len() < EXTENT_HEADER || rd16(b, 2) != 0 {
            return None;
        }
        let compression = Compression::from_u8(b[1])?;
        let len = rd32(b, 4);
        if len == 0 || len as usize > WINDOW {
            return None;
        }
        match b[0] {
            0 => {
                let data = &b[EXTENT_HEADER..];
                if data.len() > INLINE_MAX || (compression == Compression::None && data.len() != len as usize) {
                    return None;
                }
                Some(Extent::Inline { compression, len, data })
            }
            1 => {
                if b.len() != REGION_LEN {
                    return None;
                }
                let r = Region {
                    compression,
                    len,
                    block: rd64(b, 8),
                    blocks: rd32(b, 16),
                    stored: rd32(b, 20),
                    birth: rd64(b, 24),
                    hash: hash32(b, 32),
                };
                if r.blocks == 0 || u64::from(r.blocks) > WINDOW_BLOCKS {
                    return None;
                }
                // Exactly as many blocks as the stored bytes need.
                let fits = u64::from(r.stored) <= u64::from(r.blocks) * BLOCK as u64
                    && u64::from(r.stored) > (u64::from(r.blocks) - 1) * BLOCK as u64;
                if !fits || (compression == Compression::None && r.stored != len) {
                    return None;
                }
                Some(Extent::Regular(r))
            }
            _ => None,
        }
    }

    /// The bytes of file content this extent holds.
    pub fn len(&self) -> u32 {
        match self {
            Extent::Inline { len, .. } => *len,
            Extent::Regular(r) => r.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Writes an inline extent item into `out` (header and data).
pub fn encode_inline(compression: Compression, len: u32, data: &[u8], out: &mut [u8]) -> usize {
    out[0] = 0;
    out[1] = compression as u8;
    wr16(out, 2, 0);
    wr32(out, 4, len);
    out[EXTENT_HEADER..EXTENT_HEADER + data.len()].copy_from_slice(data);
    EXTENT_HEADER + data.len()
}

impl Region {
    pub fn encode(&self) -> [u8; REGION_LEN] {
        let mut b = [0u8; REGION_LEN];
        b[0] = 1;
        b[1] = self.compression as u8;
        wr32(&mut b, 4, self.len);
        wr64(&mut b, 8, self.block);
        wr32(&mut b, 16, self.blocks);
        wr32(&mut b, 20, self.stored);
        wr64(&mut b, 24, self.birth);
        b[32..64].copy_from_slice(&self.hash);
        b
    }
}

/// A subvolume: a tree of its own, the default one or a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootItem {
    pub root: Ptr,
    pub generation: u64,
    pub created: i64,
    pub flags: u64,
    /// The subvolume this one is a snapshot of (0: none).
    pub parent: u64,
    pub next_ino: u64,
    pub name_len: u8,
    pub name: [u8; NAME_MAX],
}

pub const ROOT_FIXED: usize = 105;
/// Subvolume flag: read-only (a snapshot unless made writable).
pub const SUBVOL_READONLY: u64 = 1 << 0;

impl RootItem {
    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }

    pub fn encode(&self, out: &mut [u8]) -> usize {
        out[..ROOT_FIXED].fill(0);
        self.root.write(out, 0);
        wr64(out, 56, self.generation);
        wr64(out, 64, self.created as u64);
        wr64(out, 72, self.flags);
        wr64(out, 80, self.parent);
        wr64(out, 88, self.next_ino);
        out[104] = self.name_len;
        let n = usize::from(self.name_len);
        out[ROOT_FIXED..ROOT_FIXED + n].copy_from_slice(&self.name[..n]);
        ROOT_FIXED + n
    }

    pub fn decode(b: &[u8]) -> Option<RootItem> {
        if b.len() < ROOT_FIXED || b[49..56].iter().any(|&x| x != 0) || b[96..104].iter().any(|&x| x != 0) {
            return None;
        }
        let n = usize::from(b[104]);
        if b.len() != ROOT_FIXED + n || n == 0 {
            return None;
        }
        let mut name = [0u8; NAME_MAX];
        name[..n].copy_from_slice(&b[ROOT_FIXED..]);
        let r = RootItem {
            root: Ptr::read(b, 0),
            generation: rd64(b, 56),
            created: rd64(b, 64) as i64,
            flags: rd64(b, 72),
            parent: rd64(b, 80),
            next_ino: rd64(b, 88),
            name_len: n as u8,
            name,
        };
        if r.root.level >= MAX_LEVEL || r.next_ino <= ROOT_INO {
            return None;
        }
        Some(r)
    }
}

/// A name a directory may hold: 1..=255 bytes, no `/`, no NUL, not `.` or
/// `..`.
pub fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && name.len() <= NAME_MAX && name != b"." && name != b".." && !name.iter().any(|&c| c == b'/' || c == 0)
}

/// The key offset a name is filed under in its directory.
pub fn name_hash(name: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    blake3::Hasher::new_derive_key("NCFS 2026-10 directory entry name").update(name).finalize_xof(0, &mut out);
    u64::from_le_bytes(out)
}

/// One record of a directory-entry item (`KIND_DIRENT`): the names filed
/// under one hash, almost always exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dirent<'a> {
    pub child: u64,
    /// Its `KIND_DIRINDEX` sequence number.
    pub seq: u64,
    pub dtype: u8,
    pub name: &'a [u8],
}

pub const DIRENT_FIXED: usize = 18;

/// The records of a directory-entry item, checked.
pub fn dirents(b: &[u8]) -> impl Iterator<Item = Option<Dirent<'_>>> {
    let mut at = 0;
    let mut broken = false;
    core::iter::from_fn(move || {
        if broken || at == b.len() {
            return None;
        }
        if at + DIRENT_FIXED > b.len() {
            broken = true;
            return Some(None);
        }
        let n = usize::from(b[at + 17]);
        if at + DIRENT_FIXED + n > b.len() {
            broken = true;
            return Some(None);
        }
        let d = Dirent { child: rd64(b, at), seq: rd64(b, at + 8), dtype: b[at + 16], name: &b[at + DIRENT_FIXED..at + DIRENT_FIXED + n] };
        at += DIRENT_FIXED + n;
        if !valid_name(d.name) {
            broken = true;
            return Some(None);
        }
        Some(Some(d))
    })
}

/// Appends a record to a directory-entry item.
#[cfg(feature = "alloc")]
pub fn push_dirent(out: &mut alloc::vec::Vec<u8>, d: &Dirent) {
    let mut fixed = [0u8; DIRENT_FIXED];
    wr64(&mut fixed, 0, d.child);
    wr64(&mut fixed, 8, d.seq);
    fixed[16] = d.dtype;
    fixed[17] = d.name.len() as u8;
    out.extend_from_slice(&fixed);
    out.extend_from_slice(d.name);
}

/// A directory-index item (`KIND_DIRINDEX`): child, type, name.
pub fn dirindex(b: &[u8]) -> Option<(u64, u8, &[u8])> {
    if b.len() < 10 || b.len() != 10 + usize::from(b[9]) {
        return None;
    }
    let name = &b[10..];
    valid_name(name).then(|| (rd64(b, 0), b[8], name))
}

#[cfg(feature = "alloc")]
pub fn encode_dirindex(child: u64, dtype: u8, name: &[u8]) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; 10];
    wr64(&mut v, 0, child);
    v[8] = dtype;
    v[9] = name.len() as u8;
    v.extend_from_slice(name);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sb() -> Superblock {
        let mut label = [0u8; 64];
        label[..4].copy_from_slice(b"test");
        Superblock {
            incompat: INCOMPAT_LZ4,
            ro_compat: 0,
            compat: 0,
            flags: 0,
            fsid: [7; 16],
            label,
            generation: 9,
            total_blocks: 1024,
            created: 1,
            committed: 2,
            root_tree: Ptr { block: 40, gen: 9, hash: [1; 32], level: 0 },
            next_subvol: 2,
            default_subvol: 1,
            used_blocks: 3,
            sig_blocks: 0,
        }
    }

    #[test]
    fn superblock_round_trips_and_is_checked() {
        let s = sb();
        let b = s.encode();
        assert_eq!(Superblock::decode(&b), Ok(s));
        assert_eq!(s.label(), "test");
        // Any flipped bit is caught by the checksum.
        for bit in [0usize, 100, 8 * 160 + 3, 8 * 4000, 8 * 4095 + 7] {
            let mut c = b;
            c[bit / 8] ^= 1 << (bit % 8);
            assert!(Superblock::decode(&c).is_err(), "bit {bit}");
        }
        // An unknown incompatible feature: refused rather than misread.
        let mut s2 = s;
        s2.incompat |= 1 << 40;
        assert_eq!(Superblock::decode(&s2.encode()), Err(Error::Unsupported));
        // An unknown read-only feature: readable, not writable.
        let mut s3 = s;
        s3.ro_compat = 1;
        assert!(!Superblock::decode(&s3.encode()).unwrap().writable());
    }

    #[test]
    fn keys_order_and_follow() {
        assert!(Key::new(1, 2, 3) < Key::new(1, 3, 0));
        assert!(Key::new(1, 255, u64::MAX) < Key::new(2, 0, 0));
        assert_eq!(Key::new(1, 2, u64::MAX).successor(), Some(Key::new(1, 3, 0)));
        assert_eq!(Key::new(1, 255, u64::MAX).successor(), Some(Key::new(2, 0, 0)));
        assert_eq!(Key::MAX.successor(), None);
        let mut b = [0u8; KEY_LEN];
        let k = Key::new(0x0102_0304_0506_0708, 9, 0x1112_1314_1516_1718);
        k.write(&mut b, 0);
        assert_eq!(Key::read(&b, 0), k);
    }

    #[test]
    fn items_round_trip() {
        let i = Inode { mode: S_IFREG | 0o644, nlink: 1, size: 12345, mtime: -5, ..Inode::default() };
        assert_eq!(Inode::decode(&i.encode()), Some(i));
        let r = Region { compression: Compression::Lz4, len: 100_000, block: 77, blocks: 9, stored: 33_000, birth: 4, hash: [3; 32] };
        assert_eq!(Extent::decode(&r.encode()), Some(Extent::Regular(r)));
        let mut bad = r;
        bad.blocks = 10; // more blocks than the stored bytes need
        assert_eq!(Extent::decode(&bad.encode()), None);
        let mut out = [0u8; 64];
        let n = encode_inline(Compression::None, 5, b"hello", &mut out);
        assert_eq!(Extent::decode(&out[..n]), Some(Extent::Inline { compression: Compression::None, len: 5, data: b"hello" }));
        assert!(valid_name(b"a.txt"));
        for bad in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
            assert!(!valid_name(bad));
        }
        assert_ne!(name_hash(b"a"), name_hash(b"b"));
    }

    #[test]
    fn layout_constants() {
        assert_eq!(MAX_CHILDREN, 62);
        assert_eq!(MAX_ITEM, 4011);
        const { assert!(REGION_LEN + ITEM_HEADER < MAX_ITEM) };
        const { assert!(EXTENT_HEADER + INLINE_MAX <= MAX_ITEM) };
    }
}
