// SPDX-License-Identifier: Apache-2.0
//! Reading a volume: no allocation, every buffer the caller's.
//!
//! This is the half the kernel runs before it has a heap — the
//! `ncinitramdisk` it boots from, the crash dumps on a disk — and the half
//! every other reader shares. A tree is walked from its root one node at a
//! time through a single block buffer; each node is checked against the
//! BLAKE3 its parent recorded before a byte of it is believed, and each
//! extent against the BLAKE3 in its item. Iteration needs no stack: a
//! search remembers the first key of the next leaf, and continues from
//! there.

use super::format::*;
use super::Error;
use crate::{blake3, lz4, zstd};

/// One block.
pub type Block = [u8; BLOCK];

/// What a volume is read from.
pub trait BlockDev {
    /// The device's size in blocks.
    fn blocks(&self) -> u64;
    /// Reads `buf.len() / BLOCK` consecutive blocks from `block` on.
    fn read(&mut self, block: u64, buf: &mut [u8]) -> Result<(), Error>;
}

/// A volume in memory: a boot module, or an image read whole.
#[derive(Debug, Clone, Copy)]
pub struct SliceDev<'a> {
    data: &'a [u8],
}

impl<'a> SliceDev<'a> {
    pub fn new(data: &'a [u8]) -> SliceDev<'a> {
        SliceDev { data }
    }
}

impl BlockDev for SliceDev<'_> {
    fn blocks(&self) -> u64 {
        (self.data.len() / BLOCK) as u64
    }

    fn read(&mut self, block: u64, buf: &mut [u8]) -> Result<(), Error> {
        let start = usize::try_from(block).ok().and_then(|b| b.checked_mul(BLOCK)).ok_or(Error::Io)?;
        let src = self.data.get(start..start + buf.len()).ok_or(Error::Io)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

impl<D: BlockDev + ?Sized> BlockDev for &mut D {
    fn blocks(&self) -> u64 {
        (**self).blocks()
    }

    fn read(&mut self, block: u64, buf: &mut [u8]) -> Result<(), Error> {
        (**self).read(block, buf)
    }
}

/// The volume's superblock: of the two slots, the valid one with the
/// higher generation. A slot torn by a power cut fails its checksum and
/// the other — the previous commit — is used.
pub fn read_superblock<D: BlockDev>(dev: &mut D, buf: &mut Block) -> Result<Superblock, Error> {
    let mut best: Option<Superblock> = None;
    for slot in SUPER {
        if dev.read(slot, buf).is_err() {
            continue;
        }
        if let Ok(sb) = Superblock::decode(buf) {
            if sb.total_blocks <= dev.blocks() && best.is_none_or(|b| sb.generation > b.generation) {
                best = Some(sb);
            }
        }
    }
    best.ok_or(Error::NoSuperblock)
}

/// Reads the node `ptr` points at into `buf` and checks it.
pub fn read_node<D: BlockDev>(dev: &mut D, sb: &Superblock, ptr: &Ptr, owner: u64, buf: &mut Block) -> Result<NodeHeader, Error> {
    if ptr.block < FIRST_FREE || ptr.block >= sb.total_blocks {
        return Err(Error::Corrupt(ptr.block));
    }
    dev.read(ptr.block, buf)?;
    check_node(buf, ptr, &sb.fsid, owner)
}

/// Where a search landed: item `index` of the leaf now in the buffer, and
/// the first key of the next leaf, if there is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub index: usize,
    pub count: usize,
    pub next: Option<Key>,
}

/// Finds the first item ≥ `key` in the tree `root`, leaving its leaf in
/// `buf`. `index == count` means the leaf holds nothing ≥ `key`; carry on
/// from `next`.
pub fn seek<D: BlockDev>(dev: &mut D, sb: &Superblock, root: &Ptr, owner: u64, key: &Key, buf: &mut Block) -> Result<Cursor, Error> {
    let mut ptr = *root;
    let mut next: Option<Key> = None;
    loop {
        let h = read_node(dev, sb, &ptr, owner, buf)?;
        let n = usize::from(h.count);
        if h.level == 0 {
            let mut index = n;
            for i in 0..n {
                if leaf_item(buf, i).0 >= *key {
                    index = i;
                    break;
                }
            }
            return Ok(Cursor { index, count: n, next });
        }
        let i = child_index((0..n).map(|i| child(buf, i, h.level).0), key);
        if i + 1 < n {
            let k = child(buf, i + 1, h.level).0;
            next = Some(next.map_or(k, |cur: Key| cur.min(k)));
        }
        let (_, p) = child(buf, i, h.level);
        if p.level + 1 != h.level {
            return Err(Error::Corrupt(ptr.block));
        }
        ptr = p;
    }
}

/// Visits every item with `start ≤ key < end`, in order, until `f` says
/// stop. The item's bytes are only valid during the call.
#[allow(clippy::too_many_arguments)]
pub fn range<D: BlockDev>(
    dev: &mut D,
    sb: &Superblock,
    root: &Ptr,
    owner: u64,
    start: Key,
    end: Key,
    buf: &mut Block,
    mut f: impl FnMut(Key, &[u8]) -> Result<bool, Error>,
) -> Result<(), Error> {
    let mut from = start;
    // A tree of up to 2^64 items cannot loop forever, but a corrupt one
    // could point a "next" key backwards; every step must move forward.
    loop {
        let c = seek(dev, sb, root, owner, &from, buf)?;
        for i in c.index..c.count {
            let (k, v) = leaf_item(buf, i);
            if k >= end {
                return Ok(());
            }
            if !f(k, v)? {
                return Ok(());
            }
        }
        match c.next {
            Some(n) if n > from && n < end => from = n,
            Some(n) if n <= from => return Err(Error::Corrupt(root.block)),
            _ => return Ok(()),
        }
    }
}

/// Copies the item with exactly `key` into `out`; `None` if there is none.
pub fn get<D: BlockDev>(dev: &mut D, sb: &Superblock, root: &Ptr, owner: u64, key: &Key, buf: &mut Block, out: &mut [u8]) -> Result<Option<usize>, Error> {
    let c = seek(dev, sb, root, owner, key, buf)?;
    if c.index == c.count {
        return Ok(None);
    }
    let (k, v) = leaf_item(buf, c.index);
    if k != *key {
        return Ok(None);
    }
    let dst = out.get_mut(..v.len()).ok_or(Error::Corrupt(root.block))?;
    dst.copy_from_slice(v);
    Ok(Some(v.len()))
}

/// The buffers file reads need: a node, a window's stored bytes and its
/// decoded bytes, ZSTD's tables. About 270 KiB — static memory in a kernel.
pub struct Scratch {
    pub node: Block,
    stored: [u8; WINDOW],
    window: [u8; WINDOW],
    zstd: zstd::Workspace,
    /// What `window` holds: (subvolume, inode, window start, length), so
    /// reading a file sequentially decodes each window once.
    cached: Option<(u64, u64, u64, usize)>,
}

impl core::fmt::Debug for Scratch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ncfs::Scratch")
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

impl Scratch {
    pub const fn new() -> Scratch {
        Scratch { node: [0; BLOCK], stored: [0; WINDOW], window: [0; WINDOW], zstd: zstd::Workspace::new(), cached: None }
    }
}

/// Decodes stored extent bytes into `out` (exactly `out.len()` bytes).
pub fn decode_extent(compression: Compression, stored: &[u8], out: &mut [u8], zws: &mut zstd::Workspace) -> Result<(), Error> {
    match compression {
        Compression::None => {
            if stored.len() != out.len() {
                return Err(Error::Corrupt(0));
            }
            out.copy_from_slice(stored);
            Ok(())
        }
        Compression::Lz4 => lz4::decompress_exact(stored, out).map_err(Error::Lz4),
        Compression::Zstd => match zws.decompress_into(stored, out) {
            Ok(n) if n == out.len() => Ok(()),
            Ok(_) => Err(Error::Zstd(zstd::Error::Short)),
            Err(e) => Err(Error::Zstd(e)),
        },
    }
}

/// An open volume, reading one subvolume.
pub struct Volume<D: BlockDev> {
    pub dev: D,
    pub sb: Superblock,
    pub subvol_id: u64,
    pub subvol: RootItem,
}

impl<D: BlockDev> core::fmt::Debug for Volume<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ncfs::Volume").field("generation", &self.sb.generation).field("subvol", &self.subvol_id).finish()
    }
}

impl<D: BlockDev> Volume<D> {
    /// Opens the volume on `dev` at its default subvolume.
    pub fn open(mut dev: D, buf: &mut Block) -> Result<Volume<D>, Error> {
        let sb = read_superblock(&mut dev, buf)?;
        let mut item = [0u8; MAX_ITEM];
        let key = Key::new(sb.default_subvol, KIND_ROOT, 0);
        let n = get(&mut dev, &sb, &sb.root_tree, 0, &key, buf, &mut item)?.ok_or(Error::Corrupt(sb.root_tree.block))?;
        let subvol = RootItem::decode(&item[..n]).ok_or(Error::Corrupt(sb.root_tree.block))?;
        Ok(Volume { dev, sb, subvol_id: sb.default_subvol, subvol })
    }

    /// Every subvolume, in id order, until `f` says stop.
    pub fn subvols(&mut self, buf: &mut Block, mut f: impl FnMut(u64, &RootItem) -> bool) -> Result<(), Error> {
        let sb = self.sb;
        range(&mut self.dev, &sb, &sb.root_tree, 0, Key::new(0, KIND_ROOT, 0), Key::MAX, buf, |k, v| {
            if k.kind != KIND_ROOT {
                return Ok(true);
            }
            let r = RootItem::decode(v).ok_or(Error::Corrupt(sb.root_tree.block))?;
            Ok(f(k.obj, &r))
        })
    }

    /// Switches to the subvolume called `name` (a snapshot, say).
    pub fn open_subvol(&mut self, name: &[u8], buf: &mut Block) -> Result<(), Error> {
        let mut found = None;
        self.subvols(buf, |id, r| {
            if r.name() == name {
                found = Some((id, *r));
                false
            } else {
                true
            }
        })?;
        let (id, r) = found.ok_or(Error::NotFound)?;
        self.subvol_id = id;
        self.subvol = r;
        Ok(())
    }

    fn get_item(&mut self, key: &Key, buf: &mut Block, out: &mut [u8]) -> Result<Option<usize>, Error> {
        let (sb, root, owner) = (self.sb, self.subvol.root, self.subvol_id);
        get(&mut self.dev, &sb, &root, owner, key, buf, out)
    }

    pub fn inode(&mut self, ino: u64, buf: &mut Block) -> Result<Inode, Error> {
        let mut item = [0u8; INODE_LEN];
        let root = self.subvol.root.block;
        match self.get_item(&Key::new(ino, KIND_INODE, 0), buf, &mut item) {
            Ok(Some(INODE_LEN)) => Inode::decode(&item).ok_or(Error::Corrupt(root)),
            Ok(Some(_)) | Err(Error::Corrupt(_)) => Err(Error::Corrupt(root)),
            Ok(None) => Err(Error::NotFound),
            Err(e) => Err(e),
        }
    }

    /// The entry `name` in directory `dir`: its inode and type.
    pub fn lookup(&mut self, dir: u64, name: &[u8], buf: &mut Block) -> Result<Option<(u64, u8)>, Error> {
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        let key = Key::new(dir, KIND_DIRENT, name_hash(name));
        let (sb, root, owner) = (self.sb, self.subvol.root, self.subvol_id);
        let c = seek(&mut self.dev, &sb, &root, owner, &key, buf)?;
        if c.index == c.count {
            return Ok(None);
        }
        let (k, v) = leaf_item(buf, c.index);
        if k != key {
            return Ok(None);
        }
        for d in dirents(v) {
            let d = d.ok_or(Error::Corrupt(root.block))?;
            if d.name == name {
                return Ok(Some((d.child, d.dtype)));
            }
        }
        Ok(None)
    }

    /// The inode an absolute path names. Symbolic links in the middle of
    /// the path are followed (at most 16 of them); the last component is
    /// not (`lstat`).
    pub fn resolve(&mut self, path: &[u8], s: &mut Scratch) -> Result<u64, Error> {
        self.walk_path(path, s, false)
    }

    /// The same, following a symbolic link in the last component too
    /// (`stat`, `open`).
    pub fn resolve_follow(&mut self, path: &[u8], s: &mut Scratch) -> Result<u64, Error> {
        self.walk_path(path, s, true)
    }

    fn walk_path(&mut self, path: &[u8], s: &mut Scratch, follow_last: bool) -> Result<u64, Error> {
        let mut link = [0u8; 1024];
        let mut stack = [0u8; 4096];
        if path.len() > stack.len() {
            return Err(Error::InvalidName);
        }
        // The path still to walk, kept at the end of `stack`.
        let mut start = stack.len() - path.len();
        stack[start..].copy_from_slice(path);
        let mut dir = ROOT_INO;
        let mut hops = 0;
        loop {
            while start < stack.len() && stack[start] == b'/' {
                start += 1;
            }
            if start == stack.len() {
                return Ok(dir);
            }
            let end = stack[start..].iter().position(|&c| c == b'/').map_or(stack.len(), |p| start + p);
            let last = stack[end..].iter().all(|&c| c == b'/');
            let name_len = end - start;
            let mut name = [0u8; NAME_MAX];
            if name_len > NAME_MAX {
                return Err(Error::InvalidName);
            }
            name[..name_len].copy_from_slice(&stack[start..end]);
            let name = &name[..name_len];
            start = end;
            if name == b"." {
                continue;
            }
            if name == b".." {
                dir = self.inode(dir, &mut s.node)?.parent;
                continue;
            }
            let (child, dtype) = self.lookup(dir, name, &mut s.node)?.ok_or(Error::NotFound)?;
            if dtype == DT_LNK && (!last || follow_last) {
                hops += 1;
                if hops > 16 {
                    return Err(Error::Loop);
                }
                let ino = self.inode(child, &mut s.node)?;
                let n = self.read_link(child, &ino, &mut link, s)?;
                // The target goes in front of what is left of the path.
                if n + 1 > start {
                    return Err(Error::InvalidName);
                }
                start -= 1;
                stack[start] = b'/';
                start -= n;
                stack[start..start + n].copy_from_slice(&link[..n]);
                if link[0] == b'/' {
                    dir = ROOT_INO;
                }
                continue;
            }
            if !last && dtype != DT_DIR {
                return Err(Error::NotADirectory);
            }
            dir = child;
        }
    }

    /// Lists a directory from `cookie` on (0 at first): `f` gets each
    /// entry's inode, type, name and the cookie that continues after it,
    /// and returns whether to go on.
    pub fn read_dir(&mut self, dir: u64, cookie: u64, buf: &mut Block, mut f: impl FnMut(u64, u8, &[u8], u64) -> bool) -> Result<(), Error> {
        let (sb, root, owner) = (self.sb, self.subvol.root, self.subvol_id);
        range(&mut self.dev, &sb, &root, owner, Key::new(dir, KIND_DIRINDEX, cookie), Key::new(dir, KIND_DIRINDEX + 1, 0), buf, |k, v| {
            let (child, dtype, name) = dirindex(v).ok_or(Error::Corrupt(root.block))?;
            Ok(f(child, dtype, name, k.off + 1))
        })
    }

    /// Reads file bytes from `offset` into `out`; returns how many (fewer
    /// only at the end of the file).
    pub fn read(&mut self, ino: u64, inode: &Inode, offset: u64, out: &mut [u8], s: &mut Scratch) -> Result<usize, Error> {
        if offset >= inode.size {
            return Ok(0);
        }
        let end = inode.size.min(offset.saturating_add(out.len() as u64));
        let mut pos = offset;
        while pos < end {
            let w = pos - pos % WINDOW as u64;
            let in_w = (pos - w) as usize;
            let take = ((end - pos) as usize).min(WINDOW - in_w);
            let dst = &mut out[(pos - offset) as usize..(pos - offset) as usize + take];
            let have = self.window(ino, w, s)?;
            // Bytes past the extent (or a missing extent: a hole) are zeros.
            let from = in_w.min(have);
            let to = (in_w + take).min(have);
            dst[..to - from].copy_from_slice(&s.window[from..to]);
            dst[to - from..].fill(0);
            pos += take as u64;
        }
        Ok((end - offset) as usize)
    }

    /// Decodes the window at `w` of file `ino` into `s.window`; returns its
    /// length (0 for a hole).
    fn window(&mut self, ino: u64, w: u64, s: &mut Scratch) -> Result<usize, Error> {
        if let Some((sv, i, ww, len)) = s.cached {
            if sv == self.subvol_id && i == ino && ww == w {
                return Ok(len);
            }
        }
        s.cached = None;
        let (sb, root, owner) = (self.sb, self.subvol.root, self.subvol_id);
        let key = Key::new(ino, KIND_EXTENT, w);
        let c = seek(&mut self.dev, &sb, &root, owner, &key, &mut s.node)?;
        if c.index == c.count || leaf_item(&s.node, c.index).0 != key {
            return Ok(0);
        }
        let len = {
            let (_, v) = leaf_item(&s.node, c.index);
            match Extent::decode(v).ok_or(Error::Corrupt(root.block))? {
                Extent::Inline { compression, len, data } => {
                    let len = len as usize;
                    s.stored[..data.len()].copy_from_slice(data);
                    let n = data.len();
                    decode_extent(compression, &s.stored[..n], &mut s.window[..len], &mut s.zstd)?;
                    len
                }
                Extent::Regular(r) => {
                    if r.block < FIRST_FREE || r.block.checked_add(u64::from(r.blocks)).is_none_or(|e| e > sb.total_blocks) {
                        return Err(Error::Corrupt(r.block));
                    }
                    let blocks = r.blocks as usize * BLOCK;
                    self.dev.read(r.block, &mut s.stored[..blocks])?;
                    let stored = &s.stored[..r.stored as usize];
                    if !blake3::ct_eq(&blake3::hash(stored), &r.hash) {
                        return Err(Error::Checksum(r.block));
                    }
                    decode_extent(r.compression, stored, &mut s.window[..r.len as usize], &mut s.zstd)?;
                    r.len as usize
                }
            }
        };
        s.cached = Some((self.subvol_id, ino, w, len));
        Ok(len)
    }

    /// Where a file's bytes lie on the device when they need no decoding:
    /// one raw extent holding the whole file. Checked against its BLAKE3
    /// before it is returned, so a caller with the device in memory can
    /// use the bytes in place: (first block, length).
    pub fn contiguous(&mut self, ino: u64, inode: &Inode, s: &mut Scratch) -> Result<Option<(u64, usize)>, Error> {
        if inode.size == 0 || inode.size > WINDOW as u64 {
            return Ok(None);
        }
        let (sb, root, owner) = (self.sb, self.subvol.root, self.subvol_id);
        let key = Key::new(ino, KIND_EXTENT, 0);
        let c = seek(&mut self.dev, &sb, &root, owner, &key, &mut s.node)?;
        if c.index == c.count || leaf_item(&s.node, c.index).0 != key {
            return Ok(None);
        }
        let r = match Extent::decode(leaf_item(&s.node, c.index).1).ok_or(Error::Corrupt(root.block))? {
            Extent::Regular(r) if r.compression == Compression::None && u64::from(r.len) == inode.size => r,
            _ => return Ok(None),
        };
        if r.block < FIRST_FREE || r.block.checked_add(u64::from(r.blocks)).is_none_or(|e| e > sb.total_blocks) {
            return Err(Error::Corrupt(r.block));
        }
        let n = r.blocks as usize * BLOCK;
        self.dev.read(r.block, &mut s.stored[..n])?;
        if !blake3::ct_eq(&blake3::hash(&s.stored[..r.stored as usize]), &r.hash) {
            return Err(Error::Checksum(r.block));
        }
        Ok(Some((r.block, r.len as usize)))
    }

    /// A symbolic link's target.
    pub fn read_link(&mut self, ino: u64, inode: &Inode, out: &mut [u8], s: &mut Scratch) -> Result<usize, Error> {
        if !inode.is_symlink() {
            return Err(Error::NotASymlink);
        }
        if inode.size == 0 || inode.size as usize > out.len() {
            return Err(Error::Corrupt(self.subvol.root.block));
        }
        self.read(ino, inode, 0, out, s)
    }
}

/// Reads a whole volume's superblock without opening it: for tools that
/// identify a device.
pub fn probe<D: BlockDev>(dev: &mut D) -> Option<Superblock> {
    let mut buf = [0u8; BLOCK];
    read_superblock(dev, &mut buf).ok()
}
