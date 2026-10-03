// SPDX-License-Identifier: Apache-2.0
//! Writing a volume: copy-on-write trees, reference counts, atomic commits.
//!
//! # Copy on write
//!
//! Nothing the last commit can see is ever overwritten. Changing an item
//! copies its leaf and every node above it into memory; at commit the
//! copies are written to free blocks, children before parents, each parent
//! recording its children's new BLAKE3, and only then — after a barrier —
//! does the superblock in the other slot name the new root. A power cut at
//! any point leaves the old commit intact and readable; the half-written
//! new one is unreferenced space. Blocks the new commit stops using are
//! *pinned* until it is durable, so the commit before it stays whole until
//! the moment it is replaced.
//!
//! # Sharing: snapshots and deduplication
//!
//! A snapshot is a second pointer to a subvolume's root, made in constant
//! time; a deduplicated extent is a second pointer to the same blocks.
//! Every node and extent carries a reference count — the number of pointers
//! to it — and copying a shared node first adds one to each of its
//! children (O. Rodeh, "B-trees, Shadowing, and Clones", 2008). The counts
//! are not stored: they are counted from the trees when a volume is opened
//! for writing, so there is no allocation map to tear or to disagree with
//! the trees. A read-only mount needs none of it.
//!
//! # Files
//!
//! A file's bytes live in 128 KiB windows, one extent item each, compressed
//! on their own (LZ4 here, ZSTD through an [`Encoder`] the host lends) when
//! that saves a block, shared with an identical window elsewhere when
//! deduplication finds one (by the BLAKE3 the extent carries anyway, then
//! byte for byte), and left out entirely when they are all zeros — a hole.
//! Files of up to 2 KiB live inside their extent item.

use super::format::*;
use super::read::{self, Block, BlockDev};
use super::Error;
use crate::{blake3, lz4, zstd};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

/// A device that can be written.
pub trait BlockDevMut: BlockDev {
    /// Writes `data` (whole blocks) from `block` on.
    fn write(&mut self, block: u64, data: &[u8]) -> Result<(), Error>;
    /// A barrier: everything written before it is durable when it returns.
    fn flush(&mut self) -> Result<(), Error>;
}

impl<D: BlockDevMut + ?Sized> BlockDevMut for &mut D {
    fn write(&mut self, block: u64, data: &[u8]) -> Result<(), Error> {
        (**self).write(block, data)
    }

    fn flush(&mut self) -> Result<(), Error> {
        (**self).flush()
    }
}

/// The time, in nanoseconds since the Unix epoch.
pub trait Clock {
    fn now(&mut self) -> i64;
}

/// A clock that always says the same thing (tests, reproducible images).
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub i64);

impl Clock for FixedClock {
    fn now(&mut self) -> i64 {
        self.0
    }
}

/// A compressor for codecs this crate only decodes (ZSTD): the host tool
/// lends the reference library. `None` when it cannot or will not.
pub trait Encoder {
    fn encode(&mut self, compression: Compression, input: &[u8]) -> Option<Vec<u8>>;
}

/// How new data is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// The codec new extents try (kept only when it saves a block).
    pub compression: Compression,
    /// Share identical extents.
    pub dedup: bool,
    /// Flush file data to extents once this much is buffered.
    pub max_dirty: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options { compression: Compression::Lz4, dedup: true, max_dirty: 64 << 20 }
    }
}

/// What `mkfs` needs.
#[derive(Debug, Clone)]
pub struct Format {
    pub label: Vec<u8>,
    pub fsid: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeRef {
    Disk(Ptr),
    Mem(usize),
}

#[derive(Debug, Clone)]
enum Mem {
    Leaf(Vec<(Key, Vec<u8>)>),
    Node(u8, Vec<(Key, NodeRef)>),
}

impl Mem {
    fn level(&self) -> u8 {
        match self {
            Mem::Leaf(_) => 0,
            Mem::Node(l, _) => *l,
        }
    }

    fn size(&self) -> usize {
        match self {
            Mem::Leaf(items) => NODE_HEADER + items.iter().map(|(_, v)| ITEM_HEADER + v.len()).sum::<usize>(),
            Mem::Node(_, ch) => NODE_HEADER + ch.len() * CHILD_ENTRY,
        }
    }

    fn len(&self) -> usize {
        match self {
            Mem::Leaf(items) => items.len(),
            Mem::Node(_, ch) => ch.len(),
        }
    }

    fn overfull(&self) -> bool {
        match self {
            Mem::Leaf(_) => self.size() > BLOCK,
            Mem::Node(_, ch) => ch.len() > MAX_CHILDREN,
        }
    }

    fn underfull(&self) -> bool {
        match self {
            Mem::Leaf(_) => self.size() < BLOCK / 4,
            Mem::Node(_, ch) => ch.len() < MAX_CHILDREN / 4,
        }
    }

    fn first_key(&self) -> Option<Key> {
        match self {
            Mem::Leaf(items) => items.first().map(|i| i.0),
            Mem::Node(_, ch) => ch.first().map(|c| c.0),
        }
    }

    /// Splits an overfull node into pieces that each fit.
    fn split(self) -> Vec<Mem> {
        match self {
            Mem::Leaf(items) => {
                let total: usize = items.iter().map(|(_, v)| ITEM_HEADER + v.len()).sum();
                let cap = BLOCK - NODE_HEADER;
                // Two balanced halves when they fit; greedy packing otherwise.
                let mut acc = 0;
                let mut cut = None;
                let mut best = usize::MAX;
                for (i, (_, v)) in items.iter().enumerate() {
                    acc += ITEM_HEADER + v.len();
                    let (l, r) = (acc, total - acc);
                    if i + 1 < items.len() && l <= cap && r <= cap && l.max(r) < best {
                        best = l.max(r);
                        cut = Some(i + 1);
                    }
                }
                let mut pieces = Vec::new();
                if let Some(c) = cut {
                    let mut items = items;
                    let right = items.split_off(c);
                    pieces.push(Mem::Leaf(items));
                    pieces.push(Mem::Leaf(right));
                    return pieces;
                }
                let mut cur = Vec::new();
                let mut size = 0;
                for it in items {
                    let s = ITEM_HEADER + it.1.len();
                    if size + s > cap && !cur.is_empty() {
                        pieces.push(Mem::Leaf(core::mem::take(&mut cur)));
                        size = 0;
                    }
                    size += s;
                    cur.push(it);
                }
                pieces.push(Mem::Leaf(cur));
                pieces
            }
            Mem::Node(level, ch) => {
                let parts = ch.len().div_ceil(MAX_CHILDREN).max(2);
                let per = ch.len().div_ceil(parts);
                let mut pieces = Vec::new();
                let mut ch = ch;
                while !ch.is_empty() {
                    let rest = ch.split_off(per.min(ch.len()));
                    pieces.push(Mem::Node(level, ch));
                    ch = rest;
                }
                pieces
            }
        }
    }
}

/// A reference count, and how many blocks the counted thing spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ref {
    count: u32,
    blocks: u32,
}

/// What makes two extents interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DedupKey {
    compression: u8,
    len: u32,
    stored: u32,
    hash: [u8; 32],
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u64,
    pub dtype: u8,
    pub name: Vec<u8>,
    /// Pass it back to continue after this entry.
    pub cookie: u64,
}

/// Attributes to change; `None` leaves one as it is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<i64>,
    pub mtime: Option<i64>,
}

/// Space, in blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    pub total: u64,
    pub used: u64,
    pub free: u64,
}

/// The tree of subvolumes has id 0; each subvolume's tree has its own.
const ROOT_TREE: u64 = 0;
/// Decoded clean nodes kept in memory.
const CACHE_NODES: usize = 4096;

/// A volume open for writing.
pub struct Writer<D: BlockDevMut> {
    dev: D,
    sb: Superblock,
    /// The generation being built.
    gen: u64,
    roots: BTreeMap<u64, NodeRef>,
    subvols: BTreeMap<u64, RootItem>,
    dirty: BTreeSet<u64>,
    /// The subvolume file operations act on.
    cur: u64,
    arena: Vec<Option<Mem>>,
    cache: BTreeMap<u64, (Ptr, Mem)>,
    refs: BTreeMap<u64, Ref>,
    used: u64,
    free: BTreeMap<u64, u64>,
    cursor: u64,
    pinned: Vec<(u64, u64)>,
    fresh: BTreeSet<u64>,
    dedup: BTreeMap<DedupKey, (u64, u64)>,
    dedup_rev: BTreeMap<u64, DedupKey>,
    windows: BTreeMap<(u64, u64, u64), Vec<u8>>,
    dirty_bytes: usize,
    /// The last window decoded from disk, for reads in small pieces.
    last: Option<((u64, u64, u64), Vec<u8>)>,
    opts: Options,
    clock: Box<dyn Clock + Send>,
    encoder: Option<Box<dyn Encoder + Send>>,
    lz4: Box<lz4::Table>,
    zstd: Box<zstd::Workspace>,
    buf: Box<Block>,
    /// An I/O error in a commit: the in-memory state no longer matches the
    /// disk, so every further operation is refused; reopen the volume.
    failed: bool,
}

impl<D: BlockDevMut> core::fmt::Debug for Writer<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ncfs::Writer").field("generation", &self.gen).field("subvol", &self.cur).finish_non_exhaustive()
    }
}

/// The disk extent an item points at, if any: what a shared leaf's copy
/// must count again.
fn item_ref(k: &Key, v: &[u8]) -> Option<(u64, u64)> {
    match k.kind {
        KIND_EXTENT => match Extent::decode(v) {
            Some(Extent::Regular(r)) => Some((r.block, u64::from(r.blocks))),
            _ => None,
        },
        KIND_ROOT => RootItem::decode(v).map(|r| (r.root.block, 1)),
        _ => None,
    }
}

fn encode_mem(m: &Mem, h: &NodeHeader, out: &mut Block) {
    out.fill(0);
    h.write(out);
    match m {
        Mem::Leaf(items) => {
            let mut end = BLOCK;
            for (i, (k, v)) in items.iter().enumerate() {
                let at = NODE_HEADER + i * ITEM_HEADER;
                k.write(out, at);
                end -= v.len();
                wr16(out, at + KEY_LEN, end as u16);
                wr16(out, at + KEY_LEN + 2, v.len() as u16);
                out[end..end + v.len()].copy_from_slice(v);
            }
        }
        Mem::Node(_, ch) => {
            for (i, (k, r)) in ch.iter().enumerate() {
                if let NodeRef::Disk(p) = r {
                    write_child(out, i, k, p);
                }
            }
        }
    }
}

fn decode_node(b: &Block, h: &NodeHeader) -> Mem {
    let n = usize::from(h.count);
    if h.level == 0 {
        Mem::Leaf((0..n).map(|i| leaf_item(b, i)).map(|(k, v)| (k, v.to_vec())).collect())
    } else {
        Mem::Node(h.level, (0..n).map(|i| child(b, i, h.level)).map(|(k, p)| (k, NodeRef::Disk(p))).collect())
    }
}

impl<D: BlockDevMut> Writer<D> {
    fn new(dev: D, sb: Superblock, opts: Options, clock: Box<dyn Clock + Send>) -> Writer<D> {
        Writer {
            dev,
            gen: sb.generation + 1,
            sb,
            roots: BTreeMap::new(),
            subvols: BTreeMap::new(),
            dirty: BTreeSet::new(),
            cur: sb.default_subvol,
            arena: Vec::new(),
            cache: BTreeMap::new(),
            refs: BTreeMap::new(),
            used: 0,
            free: BTreeMap::new(),
            cursor: FIRST_FREE,
            pinned: Vec::new(),
            fresh: BTreeSet::new(),
            dedup: BTreeMap::new(),
            dedup_rev: BTreeMap::new(),
            windows: BTreeMap::new(),
            dirty_bytes: 0,
            last: None,
            opts,
            clock,
            encoder: None,
            lz4: Box::new(lz4::Table::new()),
            zstd: Box::new(zstd::Workspace::new()),
            buf: Box::new([0; BLOCK]),
            failed: false,
        }
    }

    /// Makes a new, empty volume on `dev` and opens it.
    pub fn format(mut dev: D, f: &Format, opts: Options, mut clock: Box<dyn Clock + Send>) -> Result<Writer<D>, Error> {
        let total = dev.blocks();
        if total < MIN_BLOCKS {
            return Err(Error::NoSpace);
        }
        if f.label.len() > 64 {
            return Err(Error::InvalidName);
        }
        let zero = [0u8; BLOCK];
        for b in 0..FIRST_FREE {
            dev.write(b, &zero)?;
        }
        let now = clock.now();
        let mut label = [0u8; 64];
        label[..f.label.len()].copy_from_slice(&f.label);
        let sb = Superblock {
            incompat: 0,
            ro_compat: 0,
            compat: 0,
            flags: 0,
            fsid: f.fsid,
            label,
            generation: 0,
            total_blocks: total,
            created: now,
            committed: now,
            root_tree: Ptr::default(),
            next_subvol: DEFAULT_SUBVOL + 1,
            default_subvol: DEFAULT_SUBVOL,
            used_blocks: 0,
            sig_blocks: 0,
        };
        let mut w = Writer::new(dev, sb, opts, clock);
        w.free.insert(FIRST_FREE, total - FIRST_FREE);
        let leaf = w.push(Mem::Leaf(Vec::new()));
        w.roots.insert(ROOT_TREE, NodeRef::Mem(leaf));
        let leaf = w.push(Mem::Leaf(Vec::new()));
        w.roots.insert(DEFAULT_SUBVOL, NodeRef::Mem(leaf));
        let mut name = [0u8; NAME_MAX];
        name[..7].copy_from_slice(b"default");
        w.subvols.insert(
            DEFAULT_SUBVOL,
            RootItem { root: Ptr::default(), generation: 1, created: now, flags: 0, parent: 0, next_ino: ROOT_INO + 1, name_len: 7, name },
        );
        let root = Inode {
            mode: S_IFDIR | 0o755,
            nlink: 2,
            atime: now,
            mtime: now,
            ctime: now,
            btime: now,
            generation: 1,
            parent: ROOT_INO,
            ..Inode::default()
        };
        w.put_inode_in(DEFAULT_SUBVOL, ROOT_INO, &root)?;
        w.commit()?;
        Ok(w)
    }

    /// Opens the volume on `dev` for writing: reads the superblock, counts
    /// every reference from the trees, and finds the free space.
    pub fn open(mut dev: D, opts: Options, clock: Box<dyn Clock + Send>) -> Result<Writer<D>, Error> {
        let mut buf = [0u8; BLOCK];
        let sb = read::read_superblock(&mut dev, &mut buf)?;
        if !sb.writable() {
            return Err(Error::ReadOnly);
        }
        let mut w = Writer::new(dev, sb, opts, clock);
        w.scan()?;
        Ok(w)
    }

    /// Lends a compressor for codecs this crate only decodes (ZSTD).
    pub fn set_encoder(&mut self, e: Box<dyn Encoder + Send>) {
        self.encoder = Some(e);
    }

    pub fn options(&mut self) -> &mut Options {
        &mut self.opts
    }

    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    /// The device, for tests and tools that inspect what was written.
    pub fn device(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Commits and hands the device back.
    pub fn close(mut self) -> Result<D, Error> {
        self.commit()?;
        Ok(self.dev)
    }

    fn ok(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Io)
        } else {
            Ok(())
        }
    }

    // -------------------------------------------------------------------
    // Reference counts, the free map, allocation.

    fn scan(&mut self) -> Result<(), Error> {
        let root = self.sb.root_tree;
        self.roots.insert(ROOT_TREE, NodeRef::Disk(root));
        self.walk(&root, ROOT_TREE)?;
        // The free map: everything that is neither reserved nor referenced.
        let mut at = FIRST_FREE;
        let refs: Vec<(u64, Ref)> = self.refs.iter().map(|(b, r)| (*b, *r)).collect();
        for (b, r) in refs {
            if b < at {
                // Two references overlap: a corrupt volume is never written.
                return Err(Error::Corrupt(b));
            }
            if b > at {
                self.free.insert(at, b - at);
            }
            at = b + u64::from(r.blocks);
            if at > self.sb.total_blocks {
                return Err(Error::Corrupt(b));
            }
        }
        if at < self.sb.total_blocks {
            self.free.insert(at, self.sb.total_blocks - at);
        }
        if !self.subvols.contains_key(&self.sb.default_subvol) {
            return Err(Error::Corrupt(root.block));
        }
        Ok(())
    }

    fn walk(&mut self, p: &Ptr, owner: u64) -> Result<(), Error> {
        let seen = self.refs.contains_key(&p.block);
        self.count(p.block, 1)?;
        if seen {
            // A shared node: its children were counted on the first visit.
            return Ok(());
        }
        let node = self.load(p, owner)?;
        match node {
            Mem::Node(level, ch) => {
                for (_, c) in ch {
                    if let NodeRef::Disk(cp) = c {
                        if cp.level + 1 != level {
                            return Err(Error::Corrupt(p.block));
                        }
                        self.walk(&cp, owner)?;
                    }
                }
            }
            Mem::Leaf(items) => {
                for (k, v) in items {
                    if owner == ROOT_TREE && k.kind == KIND_ROOT {
                        let r = RootItem::decode(&v).ok_or(Error::Corrupt(p.block))?;
                        if k.obj == ROOT_TREE || k.obj >= self.sb.next_subvol || k.off != 0 {
                            return Err(Error::Corrupt(p.block));
                        }
                        self.subvols.insert(k.obj, r);
                        self.roots.insert(k.obj, NodeRef::Disk(r.root));
                        self.walk(&r.root, k.obj)?;
                    } else if owner != ROOT_TREE && k.kind == KIND_EXTENT {
                        match Extent::decode(&v).ok_or(Error::Corrupt(p.block))? {
                            Extent::Regular(r) => {
                                if r.block < FIRST_FREE || r.block + u64::from(r.blocks) > self.sb.total_blocks {
                                    return Err(Error::Corrupt(p.block));
                                }
                                self.count(r.block, u64::from(r.blocks))?;
                                self.index(&r);
                            }
                            Extent::Inline { .. } => {}
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// One more reference to `blocks` blocks at `block`, at mount.
    fn count(&mut self, block: u64, blocks: u64) -> Result<(), Error> {
        match self.refs.get_mut(&block) {
            Some(r) => {
                if u64::from(r.blocks) != blocks {
                    return Err(Error::Corrupt(block));
                }
                r.count += 1;
            }
            None => {
                self.refs.insert(block, Ref { count: 1, blocks: blocks as u32 });
                self.used += blocks;
            }
        }
        Ok(())
    }

    fn index(&mut self, r: &Region) {
        if self.opts.dedup {
            let k = DedupKey { compression: r.compression as u8, len: r.len, stored: r.stored, hash: r.hash };
            self.dedup.entry(k).or_insert((r.block, r.birth));
            self.dedup_rev.insert(r.block, k);
        }
    }

    fn incref(&mut self, block: u64) -> Result<(), Error> {
        let r = self.refs.get_mut(&block).ok_or(Error::Corrupt(block))?;
        r.count += 1;
        Ok(())
    }

    fn decref(&mut self, block: u64) -> Result<(), Error> {
        let r = self.refs.get_mut(&block).ok_or(Error::Corrupt(block))?;
        r.count -= 1;
        if r.count > 0 {
            return Ok(());
        }
        let blocks = u64::from(r.blocks);
        self.refs.remove(&block);
        self.used -= blocks;
        self.cache.remove(&block);
        if let Some(k) = self.dedup_rev.remove(&block) {
            if self.dedup.get(&k).is_some_and(|(b, _)| *b == block) {
                self.dedup.remove(&k);
            }
        }
        if self.fresh.remove(&block) {
            // Never committed: nothing can see it, free at once.
            self.free_insert(block, blocks);
        } else {
            self.pinned.push((block, blocks));
        }
        Ok(())
    }

    fn free_insert(&mut self, start: u64, len: u64) {
        let (mut s, mut l) = (start, len);
        if let Some((&ps, &pl)) = self.free.range(..s).next_back() {
            if ps + pl == s {
                self.free.remove(&ps);
                s = ps;
                l += pl;
            }
        }
        if let Some(&nl) = self.free.get(&(s + l)) {
            self.free.remove(&(s + l));
            l += nl;
        }
        self.free.insert(s, l);
    }

    /// `n` contiguous free blocks, counted once and marked as written in
    /// this transaction.
    fn alloc(&mut self, n: u64) -> Result<u64, Error> {
        let pick = self
            .free
            .range(self.cursor..)
            .find(|(_, &l)| l >= n)
            .or_else(|| self.free.range(..self.cursor).find(|(_, &l)| l >= n))
            .map(|(&s, &l)| (s, l));
        let (s, l) = pick.ok_or(Error::NoSpace)?;
        self.free.remove(&s);
        if l > n {
            self.free.insert(s + n, l - n);
        }
        self.cursor = s + n;
        self.refs.insert(s, Ref { count: 1, blocks: n as u32 });
        self.used += n;
        self.fresh.insert(s);
        Ok(s)
    }

    /// Blocks in use, free, and in all.
    pub fn space(&self) -> Space {
        let free: u64 = self.free.values().sum();
        Space { total: self.sb.total_blocks, used: self.used, free }
    }

    // -------------------------------------------------------------------
    // Nodes.

    fn push(&mut self, m: Mem) -> usize {
        self.arena.push(Some(m));
        self.arena.len() - 1
    }

    /// Reads, checks and caches the node `p` points at.
    fn ensure_cached(&mut self, p: &Ptr, owner: u64) -> Result<(), Error> {
        if matches!(self.cache.get(&p.block), Some((cp, _)) if cp == p) {
            return Ok(());
        }
        let sb = self.sb;
        let h = read::read_node(&mut self.dev, &sb, p, owner, &mut self.buf)?;
        let m = decode_node(&self.buf, &h);
        self.cache_put(*p, m);
        Ok(())
    }

    fn load(&mut self, p: &Ptr, owner: u64) -> Result<Mem, Error> {
        self.ensure_cached(p, owner)?;
        self.cache.get(&p.block).map(|(_, m)| m.clone()).ok_or(Error::Corrupt(p.block))
    }

    fn cache_put(&mut self, p: Ptr, m: Mem) {
        if self.cache.len() >= CACHE_NODES {
            // Forget an arbitrary half: cheap, and the trees stay correct.
            let keys: Vec<u64> = self.cache.keys().step_by(2).copied().collect();
            for k in keys {
                self.cache.remove(&k);
            }
        }
        self.cache.insert(p.block, (p, m));
    }

    fn arena(&mut self, i: usize) -> Result<&mut Mem, Error> {
        self.arena.get_mut(i).and_then(|m| m.as_mut()).ok_or(Error::Corrupt(0))
    }

    /// Copies the node `p` into memory for changing it.
    fn cow(&mut self, p: &Ptr, owner: u64) -> Result<usize, Error> {
        let node = self.load(p, owner)?;
        let shared = self.refs.get(&p.block).map_or(0, |r| r.count) > 1;
        if shared {
            // The copy points at everything the original does.
            match &node {
                Mem::Node(_, ch) => {
                    for (_, c) in ch {
                        if let NodeRef::Disk(cp) = c {
                            self.incref(cp.block)?;
                        }
                    }
                }
                Mem::Leaf(items) => {
                    for (k, v) in items {
                        if let Some((b, _)) = item_ref(k, v) {
                            self.incref(b)?;
                        }
                    }
                }
            }
        }
        self.decref(p.block)?;
        Ok(self.push(node))
    }

    fn mem_root(&mut self, t: u64) -> Result<usize, Error> {
        match *self.roots.get(&t).ok_or(Error::NotFound)? {
            NodeRef::Mem(i) => Ok(i),
            NodeRef::Disk(p) => {
                let i = self.cow(&p, t)?;
                self.roots.insert(t, NodeRef::Mem(i));
                Ok(i)
            }
        }
    }

    /// Child `pos` of in-memory node `parent`, copied into memory.
    fn mem_child(&mut self, t: u64, parent: usize, pos: usize) -> Result<usize, Error> {
        let r = match self.arena(parent)? {
            Mem::Node(_, ch) => ch.get(pos).map(|c| c.1).ok_or(Error::Corrupt(0))?,
            Mem::Leaf(_) => return Err(Error::Corrupt(0)),
        };
        match r {
            NodeRef::Mem(i) => Ok(i),
            NodeRef::Disk(p) => {
                let i = self.cow(&p, t)?;
                if let Mem::Node(_, ch) = self.arena(parent)? {
                    ch[pos].1 = NodeRef::Mem(i);
                }
                Ok(i)
            }
        }
    }

    // -------------------------------------------------------------------
    // Trees.

    /// Calls `f` with the node `r` (from memory or disk).
    fn with_node<R>(&mut self, r: NodeRef, owner: u64, f: impl FnOnce(&Mem) -> R) -> Result<R, Error> {
        match r {
            NodeRef::Mem(i) => {
                let m = self.arena.get(i).and_then(|m| m.as_ref()).ok_or(Error::Corrupt(0))?;
                Ok(f(m))
            }
            NodeRef::Disk(p) => {
                self.ensure_cached(&p, owner)?;
                let (_, m) = self.cache.get(&p.block).ok_or(Error::Corrupt(p.block))?;
                Ok(f(m))
            }
        }
    }

    fn tree_get(&mut self, t: u64, key: &Key) -> Result<Option<Vec<u8>>, Error> {
        let mut r = *self.roots.get(&t).ok_or(Error::NotFound)?;
        loop {
            enum Step {
                Found(Option<Vec<u8>>),
                Down(NodeRef),
            }
            let step = self.with_node(r, t, |m| match m {
                Mem::Leaf(items) => Step::Found(items.binary_search_by(|(k, _)| k.cmp(key)).ok().map(|i| items[i].1.clone())),
                Mem::Node(_, ch) => Step::Down(ch[child_index(ch.iter().map(|c| c.0), key)].1),
            })?;
            match step {
                Step::Found(v) => return Ok(v),
                Step::Down(c) => r = c,
            }
        }
    }

    /// Items with `start ≤ key < end`, at most `limit` of them.
    fn tree_range(&mut self, t: u64, start: Key, end: Key, limit: usize) -> Result<Vec<(Key, Vec<u8>)>, Error> {
        let mut out = Vec::new();
        let r = *self.roots.get(&t).ok_or(Error::NotFound)?;
        self.range_in(r, t, &start, &end, limit, &mut out)?;
        Ok(out)
    }

    fn range_in(&mut self, r: NodeRef, t: u64, start: &Key, end: &Key, limit: usize, out: &mut Vec<(Key, Vec<u8>)>) -> Result<(), Error> {
        enum Got {
            Items(Vec<(Key, Vec<u8>)>),
            Children(Vec<NodeRef>),
        }
        let got = self.with_node(r, t, |m| match m {
            Mem::Leaf(items) => Got::Items(items.iter().filter(|(k, _)| k >= start && k < end).cloned().collect()),
            Mem::Node(_, ch) => {
                // Child i covers [key[i], key[i+1]); the first covers
                // everything below its successor.
                let mut pick = Vec::new();
                for (i, (k, c)) in ch.iter().enumerate() {
                    let upper = ch.get(i + 1).map(|n| n.0);
                    let below_end = i == 0 || *k < *end;
                    let above_start = upper.is_none_or(|u| u > *start);
                    if below_end && above_start {
                        pick.push(*c);
                    }
                }
                Got::Children(pick)
            }
        })?;
        match got {
            Got::Items(items) => {
                for it in items {
                    if out.len() >= limit {
                        break;
                    }
                    out.push(it);
                }
            }
            Got::Children(cs) => {
                for c in cs {
                    if out.len() >= limit {
                        break;
                    }
                    self.range_in(c, t, start, end, limit, out)?;
                }
            }
        }
        Ok(())
    }

    /// Changes the leaf holding `key` with `f`, then restores the tree's
    /// shape.
    fn modify<R>(&mut self, t: u64, key: &Key, f: impl FnOnce(&mut Vec<(Key, Vec<u8>)>) -> R) -> Result<R, Error> {
        self.ok()?;
        if t != ROOT_TREE {
            self.dirty.insert(t);
        }
        let root = self.mem_root(t)?;
        let mut path: Vec<(usize, usize)> = Vec::new();
        let mut cur = root;
        loop {
            let pos = match self.arena(cur)? {
                Mem::Leaf(_) => break,
                Mem::Node(_, ch) => child_index(ch.iter().map(|c| c.0), key),
            };
            let child = self.mem_child(t, cur, pos)?;
            path.push((cur, pos));
            cur = child;
        }
        let r = match self.arena(cur)? {
            Mem::Leaf(items) => f(items),
            Mem::Node(..) => return Err(Error::Corrupt(0)),
        };
        self.fixup(t, &path, cur)?;
        Ok(r)
    }

    /// Splits overfull nodes, removes empty ones, merges small neighbours,
    /// keeps every separator equal to its child's first key, and grows or
    /// shrinks the root.
    fn fixup(&mut self, t: u64, path: &[(usize, usize)], leaf: usize) -> Result<(), Error> {
        let mut child = leaf;
        for &(parent, pos) in path.iter().rev() {
            let pieces = self.split_node(child)?;
            let empty = self.arena(child)?.len() == 0;
            let mut first = Vec::new();
            for &p in &pieces {
                first.push(self.arena(p)?.first_key());
            }
            if let Mem::Node(_, ch) = self.arena(parent)? {
                if empty {
                    ch.remove(pos);
                } else {
                    ch[pos].0 = first[0].unwrap_or(ch[pos].0);
                    for (j, &p) in pieces.iter().enumerate().skip(1) {
                        ch.insert(pos + j, (first[j].unwrap_or_default(), NodeRef::Mem(p)));
                    }
                }
            }
            if empty {
                self.arena[child] = None;
            } else if pieces.len() == 1 && self.arena(child)?.underfull() {
                self.merge(t, parent, pos)?;
            }
            child = parent;
        }
        let pieces = self.split_node(child)?;
        if pieces.len() > 1 {
            let level = self.arena(child)?.level() + 1;
            let mut ch = Vec::new();
            for &p in &pieces {
                ch.push((self.arena(p)?.first_key().unwrap_or_default(), NodeRef::Mem(p)));
            }
            let i = self.push(Mem::Node(level, ch));
            self.roots.insert(t, NodeRef::Mem(i));
        }
        // An internal root with one child hands over to it; one with none
        // becomes an empty leaf.
        while let NodeRef::Mem(r) = *self.roots.get(&t).ok_or(Error::NotFound)? {
            let next = match self.arena(r)? {
                Mem::Node(_, ch) if ch.len() == 1 => Some(ch[0].1),
                Mem::Node(_, ch) if ch.is_empty() => None,
                _ => break,
            };
            self.arena[r] = None;
            let next = match next {
                Some(n) => n,
                None => NodeRef::Mem(self.push(Mem::Leaf(Vec::new()))),
            };
            self.roots.insert(t, next);
        }
        Ok(())
    }

    fn split_node(&mut self, i: usize) -> Result<Vec<usize>, Error> {
        if !self.arena(i)?.overfull() {
            return Ok(vec![i]);
        }
        let m = self.arena[i].take().ok_or(Error::Corrupt(0))?;
        let mut pieces = m.split().into_iter();
        let first = pieces.next().ok_or(Error::Corrupt(0))?;
        self.arena[i] = Some(first);
        let mut out = vec![i];
        for p in pieces {
            out.push(self.push(p));
        }
        Ok(out)
    }

    /// Merges child `pos` of `parent` with a neighbour when both fit in one
    /// node.
    fn merge(&mut self, t: u64, parent: usize, pos: usize) -> Result<(), Error> {
        let n = self.arena(parent)?.len();
        let (l, r) = if pos + 1 < n {
            (pos, pos + 1)
        } else if pos > 0 {
            (pos - 1, pos)
        } else {
            return Ok(());
        };
        let li = self.mem_child(t, parent, l)?;
        let ri = self.mem_child(t, parent, r)?;
        let fits = {
            let a = self.arena.get(li).and_then(|m| m.as_ref()).ok_or(Error::Corrupt(0))?;
            let b = self.arena.get(ri).and_then(|m| m.as_ref()).ok_or(Error::Corrupt(0))?;
            match (a, b) {
                (Mem::Leaf(_), Mem::Leaf(y)) => a.size() + y.iter().map(|(_, v)| ITEM_HEADER + v.len()).sum::<usize>() <= BLOCK,
                (Mem::Node(_, x), Mem::Node(_, y)) => x.len() + y.len() <= MAX_CHILDREN,
                _ => return Err(Error::Corrupt(0)),
            }
        };
        if !fits {
            return Ok(());
        }
        let right = self.arena[ri].take().ok_or(Error::Corrupt(0))?;
        match (self.arena(li)?, right) {
            (Mem::Leaf(x), Mem::Leaf(y)) => x.extend(y),
            (Mem::Node(_, x), Mem::Node(_, y)) => x.extend(y),
            _ => return Err(Error::Corrupt(0)),
        }
        let first = self.arena(li)?.first_key();
        if let Mem::Node(_, ch) = self.arena(parent)? {
            ch.remove(r);
            if let Some(k) = first {
                ch[l].0 = k;
            }
        }
        Ok(())
    }

    /// Inserts or replaces; returns the value replaced. Reference counts
    /// are the caller's business.
    fn tree_insert(&mut self, t: u64, key: Key, value: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        if value.len() > MAX_ITEM {
            return Err(Error::TooBig);
        }
        self.modify(t, &key, |items| match items.binary_search_by(|(k, _)| k.cmp(&key)) {
            Ok(i) => Some(core::mem::replace(&mut items[i].1, value)),
            Err(i) => {
                items.insert(i, (key, value));
                None
            }
        })
    }

    /// Removes; returns the value removed.
    fn tree_remove(&mut self, t: u64, key: Key) -> Result<Option<Vec<u8>>, Error> {
        if self.tree_get(t, &key)?.is_none() {
            return Ok(None);
        }
        self.modify(t, &key, |items| match items.binary_search_by(|(k, _)| k.cmp(&key)) {
            Ok(i) => Some(items.remove(i).1),
            Err(_) => None,
        })
    }

    /// Writes an in-memory tree out, children first; returns its root.
    fn write_tree(&mut self, r: NodeRef, owner: u64) -> Result<Ptr, Error> {
        let i = match r {
            NodeRef::Disk(p) => return Ok(p),
            NodeRef::Mem(i) => i,
        };
        let mut m = self.arena.get_mut(i).and_then(|m| m.take()).ok_or(Error::Corrupt(0))?;
        if let Mem::Node(_, ch) = &mut m {
            for c in ch.iter_mut() {
                if let NodeRef::Mem(_) = c.1 {
                    c.1 = NodeRef::Disk(self.write_tree(c.1, owner)?);
                }
            }
        }
        let block = self.alloc(1)?;
        let level = m.level();
        let h = NodeHeader { level, count: m.len() as u16, block, gen: self.gen, owner, fsid: self.sb.fsid };
        encode_mem(&m, &h, &mut self.buf);
        let hash = blake3::hash(&self.buf[..]);
        self.dev.write(block, &self.buf[..])?;
        let p = Ptr { block, gen: self.gen, hash, level };
        self.cache_put(p, m);
        Ok(p)
    }

    // -------------------------------------------------------------------
    // Commit.

    /// Makes everything so far durable, atomically.
    pub fn commit(&mut self) -> Result<(), Error> {
        self.ok()?;
        let r = self.commit_inner();
        if r.is_err() {
            self.failed = true;
        }
        r
    }

    fn commit_inner(&mut self) -> Result<(), Error> {
        self.flush_windows()?;
        let root_dirty = matches!(self.roots.get(&ROOT_TREE), Some(NodeRef::Mem(_)));
        if self.dirty.is_empty() && !root_dirty && self.sb.generation != 0 {
            return Ok(());
        }
        let dirty: Vec<u64> = core::mem::take(&mut self.dirty).into_iter().collect();
        for id in dirty {
            let Some(r) = self.roots.get(&id).copied() else { continue };
            let ptr = self.write_tree(r, id)?;
            self.roots.insert(id, NodeRef::Disk(ptr));
            let item = {
                let it = self.subvols.get_mut(&id).ok_or(Error::Corrupt(0))?;
                it.root = ptr;
                it.generation = self.gen;
                *it
            };
            let mut v = [0u8; ROOT_FIXED + NAME_MAX];
            let n = item.encode(&mut v);
            // The pointer moved with the copy: no counts change here.
            self.tree_insert(ROOT_TREE, Key::new(id, KIND_ROOT, 0), v[..n].to_vec())?;
        }
        let root = *self.roots.get(&ROOT_TREE).ok_or(Error::Corrupt(0))?;
        let ptr = self.write_tree(root, ROOT_TREE)?;
        self.roots.insert(ROOT_TREE, NodeRef::Disk(ptr));
        // Everything the new superblock will name is durable before it is.
        self.dev.flush()?;
        let mut sb = self.sb;
        sb.generation = self.gen;
        sb.root_tree = ptr;
        sb.committed = self.clock.now();
        sb.used_blocks = self.used;
        let bytes = sb.encode();
        self.dev.write(SUPER[(self.gen % 2) as usize], &bytes)?;
        self.dev.flush()?;
        self.sb = sb;
        // The previous commit is no longer the fallback: its blocks go back.
        for (b, n) in core::mem::take(&mut self.pinned) {
            self.free_insert(b, n);
        }
        self.fresh.clear();
        self.arena.clear();
        self.gen += 1;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Subvolumes and snapshots.

    /// Every subvolume: id and item.
    pub fn subvols(&self) -> Vec<(u64, RootItem)> {
        self.subvols.iter().map(|(i, r)| (*i, *r)).collect()
    }

    fn subvol_by_name(&self, name: &[u8]) -> Option<u64> {
        self.subvols.iter().find(|(_, r)| r.name() == name).map(|(i, _)| *i)
    }

    /// Makes file operations act on the subvolume called `name`.
    pub fn select(&mut self, name: &[u8]) -> Result<u64, Error> {
        let id = self.subvol_by_name(name).ok_or(Error::NotFound)?;
        self.cur = id;
        Ok(id)
    }

    pub fn current(&self) -> u64 {
        self.cur
    }

    /// A snapshot of subvolume `source` called `name`, in constant time.
    pub fn snapshot(&mut self, source: u64, name: &[u8], readonly: bool) -> Result<u64, Error> {
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        if self.subvol_by_name(name).is_some() {
            return Err(Error::Exists);
        }
        if !self.subvols.contains_key(&source) {
            return Err(Error::NotFound);
        }
        // The source's current state, on disk, is what is shared.
        self.commit()?;
        let src = *self.subvols.get(&source).ok_or(Error::NotFound)?;
        let id = self.sb.next_subvol;
        self.sb.next_subvol += 1;
        let mut item = src;
        item.flags = if readonly { SUBVOL_READONLY } else { 0 };
        item.parent = source;
        item.created = self.clock.now();
        item.generation = self.gen;
        item.name = [0; NAME_MAX];
        item.name[..name.len()].copy_from_slice(name);
        item.name_len = name.len() as u8;
        self.incref(src.root.block)?;
        self.subvols.insert(id, item);
        self.roots.insert(id, NodeRef::Disk(src.root));
        let mut v = [0u8; ROOT_FIXED + NAME_MAX];
        let n = item.encode(&mut v);
        self.tree_insert(ROOT_TREE, Key::new(id, KIND_ROOT, 0), v[..n].to_vec())?;
        self.commit()?;
        Ok(id)
    }

    /// Deletes a subvolume (not the default one); the space only it used
    /// returns to the free map at the next commit.
    pub fn delete_subvol(&mut self, id: u64) -> Result<(), Error> {
        if id == self.sb.default_subvol || id == ROOT_TREE {
            return Err(Error::Busy);
        }
        if !self.subvols.contains_key(&id) {
            return Err(Error::NotFound);
        }
        self.commit()?;
        let item = self.subvols.remove(&id).ok_or(Error::NotFound)?;
        self.roots.remove(&id);
        self.windows.retain(|(s, _, _), _| *s != id);
        self.tree_remove(ROOT_TREE, Key::new(id, KIND_ROOT, 0))?;
        self.drop_tree(&item.root, id)?;
        if self.cur == id {
            self.cur = self.sb.default_subvol;
        }
        self.commit()
    }

    fn drop_tree(&mut self, p: &Ptr, owner: u64) -> Result<(), Error> {
        let count = self.refs.get(&p.block).ok_or(Error::Corrupt(p.block))?.count;
        if count == 1 {
            match self.load(p, owner)? {
                Mem::Node(_, ch) => {
                    for (_, c) in ch {
                        if let NodeRef::Disk(cp) = c {
                            self.drop_tree(&cp, owner)?;
                        }
                    }
                }
                Mem::Leaf(items) => {
                    for (k, v) in items {
                        if let Some((b, _)) = item_ref(&k, &v) {
                            self.decref(b)?;
                        }
                    }
                }
            }
        }
        self.decref(p.block)
    }

    /// Makes `id` the subvolume mounted by default from the next commit on
    /// (a rollback to a snapshot).
    pub fn set_default(&mut self, id: u64) -> Result<(), Error> {
        if !self.subvols.contains_key(&id) {
            return Err(Error::NotFound);
        }
        self.sb.default_subvol = id;
        // A commit with nothing changed writes no superblock: copying the
        // tree of subvolumes' root makes this one count.
        self.mem_root(ROOT_TREE)?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Inodes and directories.

    fn writable(&self) -> Result<(), Error> {
        self.ok()?;
        match self.subvols.get(&self.cur) {
            Some(r) if r.flags & SUBVOL_READONLY != 0 => Err(Error::ReadOnly),
            Some(_) => Ok(()),
            None => Err(Error::NotFound),
        }
    }

    fn now(&mut self) -> i64 {
        self.clock.now()
    }

    fn inode_in(&mut self, sv: u64, ino: u64) -> Result<Inode, Error> {
        let v = self.tree_get(sv, &Key::new(ino, KIND_INODE, 0))?.ok_or(Error::NotFound)?;
        Inode::decode(&v).ok_or(Error::Corrupt(0))
    }

    fn put_inode_in(&mut self, sv: u64, ino: u64, i: &Inode) -> Result<(), Error> {
        self.tree_insert(sv, Key::new(ino, KIND_INODE, 0), i.encode().to_vec())?;
        Ok(())
    }

    pub fn inode(&mut self, ino: u64) -> Result<Inode, Error> {
        let sv = self.cur;
        self.inode_in(sv, ino)
    }

    fn put_inode(&mut self, ino: u64, i: &Inode) -> Result<(), Error> {
        let sv = self.cur;
        self.put_inode_in(sv, ino, i)
    }

    pub fn lookup(&mut self, dir: u64, name: &[u8]) -> Result<Option<(u64, u8)>, Error> {
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        let sv = self.cur;
        let Some(v) = self.tree_get(sv, &Key::new(dir, KIND_DIRENT, name_hash(name)))? else { return Ok(None) };
        for d in dirents(&v) {
            let d = d.ok_or(Error::Corrupt(0))?;
            if d.name == name {
                return Ok(Some((d.child, d.dtype)));
            }
        }
        Ok(None)
    }

    /// The inode an absolute path names (symbolic links are not followed).
    pub fn resolve(&mut self, path: &[u8]) -> Result<u64, Error> {
        let mut ino = ROOT_INO;
        for part in path.split(|&c| c == b'/').filter(|p| !p.is_empty()) {
            if part == b"." {
                continue;
            }
            if part == b".." {
                ino = self.inode(ino)?.parent;
                continue;
            }
            let (child, _) = self.lookup(ino, part)?.ok_or(Error::NotFound)?;
            ino = child;
        }
        Ok(ino)
    }

    fn new_ino(&mut self) -> Result<u64, Error> {
        let sv = self.cur;
        let it = self.subvols.get_mut(&sv).ok_or(Error::NotFound)?;
        let ino = it.next_ino;
        it.next_ino = ino.checked_add(1).ok_or(Error::NoSpace)?;
        self.dirty.insert(sv);
        Ok(ino)
    }

    fn add_entry(&mut self, dir: u64, name: &[u8], child: u64, dtype: u8) -> Result<(), Error> {
        let sv = self.cur;
        let mut d = self.inode(dir)?;
        let seq = d.next_index;
        d.next_index += 1;
        let key = Key::new(dir, KIND_DIRENT, name_hash(name));
        let mut v = self.tree_get(sv, &key)?.unwrap_or_default();
        push_dirent(&mut v, &Dirent { child, seq, dtype, name });
        if v.len() > MAX_ITEM {
            // More names under one 64-bit hash than an item holds.
            return Err(Error::NoSpace);
        }
        self.tree_insert(sv, key, v)?;
        self.tree_insert(sv, Key::new(dir, KIND_DIRINDEX, seq), encode_dirindex(child, dtype, name))?;
        let now = self.now();
        d.mtime = now;
        d.ctime = now;
        self.put_inode(dir, &d)
    }

    /// Removes `name` from `dir`; returns what it named.
    fn remove_entry(&mut self, dir: u64, name: &[u8]) -> Result<(u64, u8), Error> {
        let sv = self.cur;
        let key = Key::new(dir, KIND_DIRENT, name_hash(name));
        let v = self.tree_get(sv, &key)?.ok_or(Error::NotFound)?;
        let mut rest = Vec::new();
        let mut found = None;
        for d in dirents(&v) {
            let d = d.ok_or(Error::Corrupt(0))?;
            if d.name == name && found.is_none() {
                found = Some((d.child, d.dtype, d.seq));
            } else {
                push_dirent(&mut rest, &d);
            }
        }
        let (child, dtype, seq) = found.ok_or(Error::NotFound)?;
        if rest.is_empty() {
            self.tree_remove(sv, key)?;
        } else {
            self.tree_insert(sv, key, rest)?;
        }
        self.tree_remove(sv, Key::new(dir, KIND_DIRINDEX, seq))?;
        let mut d = self.inode(dir)?;
        let now = self.now();
        d.mtime = now;
        d.ctime = now;
        self.put_inode(dir, &d)?;
        Ok((child, dtype))
    }

    fn new_inode(&mut self, dir: u64, name: &[u8], mode: u32, uid: u32, gid: u32, rdev: u64) -> Result<(u64, Inode), Error> {
        self.writable()?;
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        if !self.inode(dir)?.is_dir() {
            return Err(Error::NotADirectory);
        }
        if self.lookup(dir, name)?.is_some() {
            return Err(Error::Exists);
        }
        let ino = self.new_ino()?;
        let now = self.now();
        let is_dir = mode & S_IFMT == S_IFDIR;
        let i = Inode {
            mode,
            uid,
            gid,
            nlink: if is_dir { 2 } else { 1 },
            atime: now,
            mtime: now,
            ctime: now,
            btime: now,
            generation: self.gen,
            parent: if is_dir { dir } else { 0 },
            rdev,
            ..Inode::default()
        };
        self.put_inode(ino, &i)?;
        self.add_entry(dir, name, ino, dtype(mode))?;
        if is_dir {
            let mut d = self.inode(dir)?;
            d.nlink += 1;
            self.put_inode(dir, &d)?;
        }
        Ok((ino, i))
    }

    /// A new file (or device node, FIFO, socket): `mode` carries the type.
    pub fn create(&mut self, dir: u64, name: &[u8], mode: u32, uid: u32, gid: u32, rdev: u64) -> Result<(u64, Inode), Error> {
        let mode = if mode & S_IFMT == 0 { mode | S_IFREG } else { mode };
        if mode & S_IFMT == S_IFDIR || mode & S_IFMT == S_IFLNK {
            return Err(Error::InvalidName);
        }
        self.new_inode(dir, name, mode, uid, gid, rdev)
    }

    pub fn mkdir(&mut self, dir: u64, name: &[u8], mode: u32, uid: u32, gid: u32) -> Result<(u64, Inode), Error> {
        self.new_inode(dir, name, S_IFDIR | (mode & 0o7777), uid, gid, 0)
    }

    pub fn symlink(&mut self, dir: u64, name: &[u8], target: &[u8], uid: u32, gid: u32) -> Result<(u64, Inode), Error> {
        if target.is_empty() || target.len() > 1024 || target.contains(&0) {
            return Err(Error::InvalidName);
        }
        let (ino, _) = self.new_inode(dir, name, S_IFLNK | 0o777, uid, gid, 0)?;
        self.write(ino, 0, target)?;
        Ok((ino, self.inode(ino)?))
    }

    /// Another name for a file.
    pub fn link(&mut self, ino: u64, dir: u64, name: &[u8]) -> Result<Inode, Error> {
        self.writable()?;
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        let mut i = self.inode(ino)?;
        if i.is_dir() {
            return Err(Error::IsADirectory);
        }
        if !self.inode(dir)?.is_dir() {
            return Err(Error::NotADirectory);
        }
        if self.lookup(dir, name)?.is_some() {
            return Err(Error::Exists);
        }
        self.add_entry(dir, name, ino, dtype(i.mode))?;
        i.nlink += 1;
        i.ctime = self.now();
        self.put_inode(ino, &i)?;
        Ok(i)
    }

    /// Deletes an inode and everything it owns.
    fn destroy(&mut self, ino: u64) -> Result<(), Error> {
        let sv = self.cur;
        self.last = None;
        let extents = self.tree_range(sv, Key::new(ino, KIND_EXTENT, 0), Key::new(ino, KIND_EXTENT + 1, 0), usize::MAX)?;
        for (k, v) in extents {
            self.tree_remove(sv, k)?;
            if let Some(Extent::Regular(r)) = Extent::decode(&v) {
                self.decref(r.block)?;
            }
        }
        self.drop_windows(sv, ino, 0);
        self.tree_remove(sv, Key::new(ino, KIND_INODE, 0))?;
        Ok(())
    }

    fn drop_windows(&mut self, sv: u64, ino: u64, from: u64) {
        let keys: Vec<(u64, u64, u64)> = self.windows.range((sv, ino, from)..=(sv, ino, u64::MAX)).map(|(k, _)| *k).collect();
        for k in keys {
            if let Some(b) = self.windows.remove(&k) {
                self.dirty_bytes -= b.len();
            }
        }
    }

    pub fn unlink(&mut self, dir: u64, name: &[u8]) -> Result<(), Error> {
        self.writable()?;
        let (ino, dt) = self.lookup(dir, name)?.ok_or(Error::NotFound)?;
        if dt == DT_DIR {
            return Err(Error::IsADirectory);
        }
        self.remove_entry(dir, name)?;
        let mut i = self.inode(ino)?;
        i.nlink = i.nlink.saturating_sub(1);
        if i.nlink == 0 {
            self.destroy(ino)
        } else {
            i.ctime = self.now();
            self.put_inode(ino, &i)
        }
    }

    fn is_empty_dir(&mut self, ino: u64) -> Result<bool, Error> {
        let sv = self.cur;
        Ok(self.tree_range(sv, Key::new(ino, KIND_DIRINDEX, 0), Key::new(ino, KIND_DIRINDEX + 1, 0), 1)?.is_empty())
    }

    pub fn rmdir(&mut self, dir: u64, name: &[u8]) -> Result<(), Error> {
        self.writable()?;
        let (ino, dt) = self.lookup(dir, name)?.ok_or(Error::NotFound)?;
        if dt != DT_DIR {
            return Err(Error::NotADirectory);
        }
        if !self.is_empty_dir(ino)? {
            return Err(Error::NotEmpty);
        }
        self.remove_entry(dir, name)?;
        self.destroy(ino)?;
        let mut d = self.inode(dir)?;
        d.nlink = d.nlink.saturating_sub(1);
        self.put_inode(dir, &d)
    }

    /// Moves `name` in `dir` to `new_name` in `new_dir`, replacing what is
    /// there (unless `noreplace`): a file by a file, an empty directory by a
    /// directory. One transaction: after a crash, the old names or the new.
    pub fn rename(&mut self, dir: u64, name: &[u8], new_dir: u64, new_name: &[u8], noreplace: bool) -> Result<(), Error> {
        self.writable()?;
        if !valid_name(new_name) {
            return Err(Error::InvalidName);
        }
        let (ino, dt) = self.lookup(dir, name)?.ok_or(Error::NotFound)?;
        if dir == new_dir && name == new_name {
            return Ok(());
        }
        if !self.inode(new_dir)?.is_dir() {
            return Err(Error::NotADirectory);
        }
        if dt == DT_DIR {
            // Not into itself or below it.
            let mut d = new_dir;
            loop {
                if d == ino {
                    return Err(Error::InvalidName);
                }
                if d == ROOT_INO {
                    break;
                }
                d = self.inode(d)?.parent;
            }
        }
        if let Some((target, tdt)) = self.lookup(new_dir, new_name)? {
            if noreplace {
                return Err(Error::Exists);
            }
            if target == ino {
                return Ok(());
            }
            match (dt == DT_DIR, tdt == DT_DIR) {
                (true, true) => self.rmdir(new_dir, new_name)?,
                (false, false) => self.unlink(new_dir, new_name)?,
                (true, false) => return Err(Error::NotADirectory),
                (false, true) => return Err(Error::IsADirectory),
            }
        }
        self.remove_entry(dir, name)?;
        self.add_entry(new_dir, new_name, ino, dt)?;
        let now = self.now();
        let mut i = self.inode(ino)?;
        i.ctime = now;
        if dt == DT_DIR && dir != new_dir {
            i.parent = new_dir;
            let mut a = self.inode(dir)?;
            a.nlink = a.nlink.saturating_sub(1);
            self.put_inode(dir, &a)?;
            let mut b = self.inode(new_dir)?;
            b.nlink += 1;
            self.put_inode(new_dir, &b)?;
        }
        self.put_inode(ino, &i)
    }

    /// Up to `limit` entries of a directory from `cookie` on (0 at first).
    pub fn read_dir(&mut self, dir: u64, cookie: u64, limit: usize) -> Result<Vec<DirEntry>, Error> {
        let sv = self.cur;
        if !self.inode(dir)?.is_dir() {
            return Err(Error::NotADirectory);
        }
        let items = self.tree_range(sv, Key::new(dir, KIND_DIRINDEX, cookie), Key::new(dir, KIND_DIRINDEX + 1, 0), limit)?;
        let mut out = Vec::new();
        for (k, v) in items {
            let (ino, dtype, name) = dirindex(&v).ok_or(Error::Corrupt(0))?;
            out.push(DirEntry { ino, dtype, name: name.to_vec(), cookie: k.off + 1 });
        }
        Ok(out)
    }

    pub fn setattr(&mut self, ino: u64, a: &SetAttr) -> Result<Inode, Error> {
        self.writable()?;
        if let Some(size) = a.size {
            self.truncate(ino, size)?;
        }
        let mut i = self.inode(ino)?;
        if let Some(m) = a.mode {
            i.mode = (i.mode & S_IFMT) | (m & 0o7777);
        }
        if let Some(u) = a.uid {
            i.uid = u;
        }
        if let Some(g) = a.gid {
            i.gid = g;
        }
        if let Some(t) = a.atime {
            i.atime = t;
        }
        if let Some(t) = a.mtime {
            i.mtime = t;
        }
        i.ctime = self.now();
        self.put_inode(ino, &i)?;
        Ok(i)
    }

    /// Sets an inode's flags (`INODE_NOCOMPRESS`, `INODE_NODEDUP`).
    pub fn set_flags(&mut self, ino: u64, flags: u64) -> Result<(), Error> {
        self.writable()?;
        let mut i = self.inode(ino)?;
        i.flags = flags;
        self.put_inode(ino, &i)
    }

    // -------------------------------------------------------------------
    // File data.

    /// The current bytes of one window (a copy): buffered, stored, or empty.
    fn window_content(&mut self, sv: u64, ino: u64, w: u64) -> Result<Vec<u8>, Error> {
        if let Some(b) = self.windows.get(&(sv, ino, w)) {
            return Ok(b.clone());
        }
        if let Some((k, b)) = &self.last {
            if *k == (sv, ino, w) {
                return Ok(b.clone());
            }
        }
        let Some(v) = self.tree_get(sv, &Key::new(ino, KIND_EXTENT, w))? else { return Ok(Vec::new()) };
        let out = match Extent::decode(&v).ok_or(Error::Corrupt(0))? {
            Extent::Inline { compression, len, data } => {
                let mut out = vec![0u8; len as usize];
                read::decode_extent(compression, data, &mut out, &mut self.zstd)?;
                out
            }
            Extent::Regular(r) => self.read_region(&r)?,
        };
        self.last = Some(((sv, ino, w), out.clone()));
        Ok(out)
    }

    fn read_region(&mut self, r: &Region) -> Result<Vec<u8>, Error> {
        if r.block < FIRST_FREE || r.block + u64::from(r.blocks) > self.sb.total_blocks {
            return Err(Error::Corrupt(r.block));
        }
        let mut stored = vec![0u8; r.blocks as usize * BLOCK];
        self.dev.read(r.block, &mut stored)?;
        stored.truncate(r.stored as usize);
        if !blake3::ct_eq(&blake3::hash(&stored), &r.hash) {
            return Err(Error::Checksum(r.block));
        }
        let mut out = vec![0u8; r.len as usize];
        read::decode_extent(r.compression, &stored, &mut out, &mut self.zstd)?;
        Ok(out)
    }

    /// Writes `data` at `offset`; the file grows as needed.
    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, Error> {
        self.writable()?;
        let sv = self.cur;
        let mut i = self.inode(ino)?;
        if i.is_dir() {
            return Err(Error::IsADirectory);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset.checked_add(data.len() as u64).filter(|&e| e <= i64::MAX as u64).ok_or(Error::TooBig)?;
        let mut pos = offset;
        while pos < end {
            let w = pos - pos % WINDOW as u64;
            let in_w = (pos - w) as usize;
            let take = ((end - pos) as usize).min(WINDOW - in_w);
            if !self.windows.contains_key(&(sv, ino, w)) {
                let content = self.window_content(sv, ino, w)?;
                self.dirty_bytes += content.len();
                self.windows.insert((sv, ino, w), content);
            }
            self.last = None;
            let buf = self.windows.get_mut(&(sv, ino, w)).ok_or(Error::Corrupt(0))?;
            if buf.len() < in_w + take {
                self.dirty_bytes += in_w + take - buf.len();
                buf.resize(in_w + take, 0);
            }
            let src = (pos - offset) as usize;
            buf[in_w..in_w + take].copy_from_slice(&data[src..src + take]);
            pos += take as u64;
        }
        i.size = i.size.max(end);
        let now = self.now();
        i.mtime = now;
        i.ctime = now;
        self.put_inode(ino, &i)?;
        if self.dirty_bytes > self.opts.max_dirty {
            self.flush_windows()?;
        }
        Ok(data.len())
    }

    /// Reads up to `len` bytes from `offset`.
    pub fn read(&mut self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, Error> {
        let sv = self.cur;
        let i = self.inode(ino)?;
        if i.is_dir() {
            return Err(Error::IsADirectory);
        }
        if offset >= i.size {
            return Ok(Vec::new());
        }
        let end = i.size.min(offset.saturating_add(len as u64));
        let mut out = vec![0u8; (end - offset) as usize];
        let mut pos = offset;
        while pos < end {
            let w = pos - pos % WINDOW as u64;
            let in_w = (pos - w) as usize;
            let take = ((end - pos) as usize).min(WINDOW - in_w);
            let content = self.window_content(sv, ino, w)?;
            let from = in_w.min(content.len());
            let to = (in_w + take).min(content.len());
            let dst = (pos - offset) as usize;
            out[dst..dst + (to - from)].copy_from_slice(&content[from..to]);
            pos += take as u64;
        }
        Ok(out)
    }

    pub fn readlink(&mut self, ino: u64) -> Result<Vec<u8>, Error> {
        let i = self.inode(ino)?;
        if !i.is_symlink() {
            return Err(Error::NotASymlink);
        }
        self.read(ino, 0, i.size as usize)
    }

    /// Changes a file's size: shorter drops what is past the end, longer
    /// reads as zeros.
    pub fn truncate(&mut self, ino: u64, size: u64) -> Result<(), Error> {
        self.writable()?;
        let sv = self.cur;
        let mut i = self.inode(ino)?;
        if i.is_dir() {
            return Err(Error::IsADirectory);
        }
        if size > i64::MAX as u64 {
            return Err(Error::TooBig);
        }
        self.last = None;
        if size < i.size {
            let first_gone = size.div_ceil(WINDOW as u64) * WINDOW as u64;
            let gone = self.tree_range(sv, Key::new(ino, KIND_EXTENT, first_gone), Key::new(ino, KIND_EXTENT + 1, 0), usize::MAX)?;
            for (k, v) in gone {
                self.tree_remove(sv, k)?;
                if let Some(Extent::Regular(r)) = Extent::decode(&v) {
                    self.decref(r.block)?;
                }
            }
            self.drop_windows(sv, ino, first_gone);
            if !size.is_multiple_of(WINDOW as u64) {
                let w = size - size % WINDOW as u64;
                let mut buf = self.window_content(sv, ino, w)?;
                buf.truncate((size - w) as usize);
                let new = buf.len();
                let old = self.windows.insert((sv, ino, w), buf).map_or(0, |b| b.len());
                self.dirty_bytes = self.dirty_bytes + new - old;
            }
        }
        i.size = size;
        let now = self.now();
        i.mtime = now;
        i.ctime = now;
        self.put_inode(ino, &i)
    }

    /// Writes every buffered window out as an extent.
    pub fn flush_windows(&mut self) -> Result<(), Error> {
        let windows = core::mem::take(&mut self.windows);
        self.dirty_bytes = 0;
        for ((sv, ino, w), mut buf) in windows {
            let Ok(i) = self.inode_in(sv, ino) else { continue };
            let limit = i.size.saturating_sub(w).min(WINDOW as u64) as usize;
            buf.truncate(limit);
            self.store_window(sv, ino, w, &buf, i.flags)?;
        }
        Ok(())
    }

    fn store_window(&mut self, sv: u64, ino: u64, w: u64, buf: &[u8], flags: u64) -> Result<(), Error> {
        self.last = None;
        let key = Key::new(ino, KIND_EXTENT, w);
        let value = if buf.iter().all(|&b| b == 0) {
            // All zeros: a hole, nothing stored.
            None
        } else if w == 0 && buf.len() <= INLINE_MAX {
            let mut v = vec![0u8; EXTENT_HEADER + buf.len()];
            encode_inline(Compression::None, buf.len() as u32, buf, &mut v);
            Some(v)
        } else {
            Some(self.store_region(buf, flags)?.encode().to_vec())
        };
        let old = match value {
            Some(v) => self.tree_insert(sv, key, v)?,
            None => self.tree_remove(sv, key)?,
        };
        if let Some(Extent::Regular(r)) = old.as_deref().and_then(Extent::decode) {
            self.decref(r.block)?;
        }
        Ok(())
    }

    /// Stores one window's bytes in blocks of their own — compressed when
    /// that saves a block, shared when an identical extent exists.
    fn store_region(&mut self, data: &[u8], flags: u64) -> Result<Region, Error> {
        let raw_blocks = data.len().div_ceil(BLOCK);
        let mut compression = Compression::None;
        let mut stored: Vec<u8> = Vec::new();
        let want = if flags & INODE_NOCOMPRESS != 0 { Compression::None } else { self.opts.compression };
        match want {
            Compression::None => {}
            Compression::Lz4 => {
                let mut out = vec![0u8; (raw_blocks - 1) * BLOCK];
                if let Some(n) = lz4::compress(data, &mut out, &mut self.lz4) {
                    out.truncate(n);
                    stored = out;
                    compression = Compression::Lz4;
                }
            }
            Compression::Zstd => {
                if let Some(z) = self.encoder.as_mut().and_then(|e| e.encode(Compression::Zstd, data)) {
                    if z.len().div_ceil(BLOCK) < raw_blocks {
                        stored = z;
                        compression = Compression::Zstd;
                    }
                }
            }
        }
        if compression == Compression::None {
            stored = data.to_vec();
        } else {
            self.sb.incompat |= if compression == Compression::Lz4 { INCOMPAT_LZ4 } else { INCOMPAT_ZSTD };
        }
        let hash = blake3::hash(&stored);
        let dk = DedupKey { compression: compression as u8, len: data.len() as u32, stored: stored.len() as u32, hash };
        let blocks = stored.len().div_ceil(BLOCK) as u32;
        if self.opts.dedup && flags & INODE_NODEDUP == 0 {
            if let Some(&(block, birth)) = self.dedup.get(&dk) {
                let r = Region { compression, len: data.len() as u32, block, blocks, stored: stored.len() as u32, birth, hash };
                // Equal hashes are not taken on faith: the bytes must match.
                if self.refs.contains_key(&block) && self.read_stored(&r)? == stored {
                    self.incref(block)?;
                    return Ok(r);
                }
            }
        }
        let block = self.alloc(u64::from(blocks))?;
        let mut padded = stored;
        let n = padded.len();
        padded.resize(blocks as usize * BLOCK, 0);
        self.dev.write(block, &padded)?;
        padded.truncate(n);
        let r = Region { compression, len: data.len() as u32, block, blocks, stored: n as u32, birth: self.gen, hash };
        self.index(&r);
        Ok(r)
    }

    fn read_stored(&mut self, r: &Region) -> Result<Vec<u8>, Error> {
        let mut stored = vec![0u8; r.blocks as usize * BLOCK];
        self.dev.read(r.block, &mut stored)?;
        stored.truncate(r.stored as usize);
        Ok(stored)
    }
}
