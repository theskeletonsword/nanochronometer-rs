// SPDX-License-Identifier: Apache-2.0
//! `fsck` and scrub: every rule of the format, every reference, and — with
//! `scrub` — every byte of data against its BLAKE3.
//!
//! Read-only, and independent of the writer: it walks the volume with the
//! reader's primitives and checks what the writer promises, so a writer bug
//! shows here instead of being agreed with. A copy-on-write volume never
//! needs this after a crash; it is for bit rot (scrub), for forensics, and
//! for the tests, which run it after every simulated power cut.

use super::format::*;
use super::read::{self, Block, BlockDev};
use super::Error;
use crate::blake3;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// What a check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub generation: u64,
    pub subvols: usize,
    /// Distinct tree nodes.
    pub nodes: u64,
    /// Distinct data extents.
    pub extents: u64,
    pub inodes: u64,
    pub directories: u64,
    /// Bytes of extent data whose BLAKE3 was verified (scrub).
    pub verified_bytes: u64,
    /// Blocks referenced: nodes and extents.
    pub used_blocks: u64,
    pub errors: Vec<String>,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

struct Checker<'a, D: BlockDev> {
    dev: &'a mut D,
    sb: Superblock,
    buf: Block,
    /// Every referenced range: start → blocks.
    ranges: BTreeMap<u64, u64>,
    nodes: BTreeSet<u64>,
    extents: BTreeMap<u64, Region>,
    report: Report,
}

impl<D: BlockDev> Checker<'_, D> {
    fn err(&mut self, msg: String) {
        if self.report.errors.len() < 1000 {
            self.report.errors.push(msg);
        }
    }

    fn claim(&mut self, block: u64, blocks: u64, what: &str) {
        if block < FIRST_FREE || block.checked_add(blocks).is_none_or(|e| e > self.sb.total_blocks) {
            self.err(format!("{what} at block {block} (+{blocks}) is outside the volume's free area"));
            return;
        }
        match self.ranges.get(&block) {
            Some(&b) if b != blocks => self.err(format!("{what} at block {block}: referenced as {b} and as {blocks} blocks")),
            Some(_) => {}
            None => {
                self.ranges.insert(block, blocks);
            }
        }
    }

    /// Walks a tree, checking every node against its pointer and its
    /// parent's separators; returns its items in order.
    fn tree(&mut self, root: &Ptr, owner: u64, items: &mut Vec<(Key, Vec<u8>)>) {
        self.node(root, owner, None, None, items);
    }

    fn node(&mut self, p: &Ptr, owner: u64, low: Option<Key>, high: Option<Key>, items: &mut Vec<(Key, Vec<u8>)>) {
        self.claim(p.block, 1, "node");
        let first_visit = self.nodes.insert(p.block);
        let sb = self.sb;
        let h = match read::read_node(self.dev, &sb, p, owner, &mut self.buf) {
            Ok(h) => h,
            Err(e) => {
                self.err(format!("node {} (tree {owner}): {e}", p.block));
                return;
            }
        };
        if first_visit {
            self.report.nodes += 1;
        }
        let n = usize::from(h.count);
        let in_range = |k: &Key| low.is_none_or(|l| *k >= l) && high.is_none_or(|h| *k < h);
        if h.level == 0 {
            let start = items.len();
            for i in 0..n {
                let (k, v) = leaf_item(&self.buf, i);
                if !in_range(&k) {
                    self.report.errors.push(format!("node {}: item {k:?} outside its parent's range", p.block));
                }
                items.push((k, v.to_vec()));
            }
            if let Some(l) = low {
                // Below a parent, a leaf is never empty and starts at its
                // separator.
                if n == 0 || items[start].0 != l {
                    self.err(format!("node {}: empty, or its first key is not its separator", p.block));
                }
            }
        } else {
            let children: Vec<(Key, Ptr)> = (0..n).map(|i| child(&self.buf, i, h.level)).collect();
            if let Some(l) = low {
                if children[0].0 != l {
                    self.err(format!("node {}: first key does not match its separator", p.block));
                }
            }
            for (i, (k, c)) in children.iter().enumerate() {
                if !in_range(k) {
                    self.err(format!("node {}: child key {k:?} outside its parent's range", p.block));
                }
                let next = children.get(i + 1).map(|x| x.0).or(high);
                self.node(c, owner, Some(*k), next, items);
            }
        }
    }

    fn subvol(&mut self, id: u64, r: &RootItem, scrub: bool) {
        let mut items = Vec::new();
        self.tree(&r.root, id, &mut items);
        let ctx = |s: &str| format!("subvolume {id}: {s}");
        let mut inodes: BTreeMap<u64, Inode> = BTreeMap::new();
        for (k, v) in &items {
            if k.kind == KIND_INODE {
                match Inode::decode(v) {
                    Some(i) if k.off == 0 => {
                        inodes.insert(k.obj, i);
                    }
                    _ => self.err(ctx(&format!("inode {} is malformed", k.obj))),
                }
            }
        }
        self.report.inodes += inodes.len() as u64;
        let root_ok = inodes.get(&ROOT_INO).is_some_and(|i| i.is_dir() && i.parent == ROOT_INO);
        if !root_ok {
            self.err(ctx("no root directory"));
        }
        if let Some(max) = inodes.keys().next_back() {
            if *max >= r.next_ino {
                self.err(ctx(&format!("inode {max} is not below next_ino {}", r.next_ino)));
            }
        }
        // Entries: by DIRENT, and the same by DIRINDEX.
        let mut links: BTreeMap<u64, u32> = BTreeMap::new();
        let mut subdirs: BTreeMap<u64, u32> = BTreeMap::new();
        let mut index: BTreeMap<(u64, u64), (u64, u8, Vec<u8>)> = BTreeMap::new();
        let mut by_dirent: BTreeSet<(u64, u64)> = BTreeSet::new();
        for (k, v) in &items {
            match k.kind {
                KIND_DIRINDEX => match dirindex(v) {
                    Some((c, t, name)) => {
                        index.insert((k.obj, k.off), (c, t, name.to_vec()));
                    }
                    None => self.err(ctx(&format!("directory {} index {} is malformed", k.obj, k.off))),
                },
                KIND_DIRENT | KIND_INODE | KIND_EXTENT => {}
                other => self.err(ctx(&format!("unknown item kind {other} in {:?}", k))),
            }
        }
        for (k, v) in &items {
            if k.kind != KIND_INODE && !inodes.contains_key(&k.obj) {
                self.err(ctx(&format!("item {k:?} belongs to no inode")));
            }
            match k.kind {
                KIND_DIRENT => {
                    if !inodes.get(&k.obj).is_some_and(|i| i.is_dir()) {
                        self.err(ctx(&format!("entry under {}, which is not a directory", k.obj)));
                    }
                    let mut any = false;
                    for d in dirents(v) {
                        let Some(d) = d else {
                            self.err(ctx(&format!("directory {} entry item is malformed", k.obj)));
                            break;
                        };
                        any = true;
                        if name_hash(d.name) != k.off {
                            self.err(ctx(&format!("entry {:?} in {} filed under the wrong hash", String::from_utf8_lossy(d.name), k.obj)));
                        }
                        match inodes.get(&d.child) {
                            None => self.err(ctx(&format!("entry {:?} in {} names missing inode {}", String::from_utf8_lossy(d.name), k.obj, d.child))),
                            Some(c) => {
                                if dtype(c.mode) != d.dtype {
                                    self.err(ctx(&format!("entry {:?}: type {} but inode {} is {}", String::from_utf8_lossy(d.name), d.dtype, d.child, dtype(c.mode))));
                                }
                                if c.is_dir() {
                                    *subdirs.entry(k.obj).or_default() += 1;
                                    if c.parent != k.obj {
                                        self.err(ctx(&format!("directory {} is in {} but says its parent is {}", d.child, k.obj, c.parent)));
                                    }
                                }
                            }
                        }
                        *links.entry(d.child).or_default() += 1;
                        match index.get(&(k.obj, d.seq)) {
                            Some((c, t, n)) if *c == d.child && *t == d.dtype && n.as_slice() == d.name => {}
                            _ => self.err(ctx(&format!("entry {:?} in {} has no matching index {}", String::from_utf8_lossy(d.name), k.obj, d.seq))),
                        }
                        by_dirent.insert((k.obj, d.seq));
                        if inodes.get(&k.obj).is_some_and(|dir| d.seq >= dir.next_index) {
                            self.err(ctx(&format!("index {} in {} is not below next_index", d.seq, k.obj)));
                        }
                    }
                    if !any {
                        self.err(ctx(&format!("empty entry item in {}", k.obj)));
                    }
                }
                KIND_EXTENT => {
                    let Some(i) = inodes.get(&k.obj).copied() else { continue };
                    if i.is_dir() || k.off % WINDOW as u64 != 0 {
                        self.err(ctx(&format!("extent {:?} on a directory or off a window boundary", k)));
                        continue;
                    }
                    match Extent::decode(v) {
                        None => self.err(ctx(&format!("extent {:?} is malformed", k))),
                        Some(e) => {
                            if k.off + u64::from(e.len()) > i.size {
                                self.err(ctx(&format!("extent {:?} reaches past the file's size {}", k, i.size)));
                            }
                            match e {
                                Extent::Inline { .. } if k.off != 0 => self.err(ctx(&format!("inline extent {:?} not at offset 0", k))),
                                Extent::Inline { compression, len, data } => {
                                    let mut out = vec![0u8; len as usize];
                                    let mut z = crate::zstd::Workspace::new();
                                    if read::decode_extent(compression, data, &mut out, &mut z).is_err() {
                                        self.err(ctx(&format!("inline extent {:?} does not decode", k)));
                                    }
                                }
                                Extent::Regular(r) => {
                                    self.claim(r.block, u64::from(r.blocks), "extent");
                                    if self.extents.insert(r.block, r).is_none() {
                                        self.report.extents += 1;
                                        if scrub {
                                            self.scrub(&r, &format!("subvolume {id} inode {} at {}", k.obj, k.off));
                                        }
                                    } else if self.extents.get(&r.block) != Some(&r) {
                                        self.err(ctx(&format!("extent at block {} described two ways", r.block)));
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        for key in index.keys() {
            if !by_dirent.contains(key) {
                self.err(ctx(&format!("index {} in {} has no entry", key.1, key.0)));
            }
        }
        for (ino, i) in &inodes {
            if i.is_dir() {
                self.report.directories += 1;
                let want = 2 + subdirs.get(ino).copied().unwrap_or(0);
                if i.nlink != want {
                    self.err(ctx(&format!("directory {ino}: nlink {} but {want} expected", i.nlink)));
                }
                if *ino != ROOT_INO && links.get(ino).copied().unwrap_or(0) != 1 {
                    self.err(ctx(&format!("directory {ino} has {} names", links.get(ino).copied().unwrap_or(0))));
                }
            } else {
                let n = links.get(ino).copied().unwrap_or(0);
                if n == 0 || i.nlink != n {
                    self.err(ctx(&format!("inode {ino}: nlink {} but {n} entries", i.nlink)));
                }
            }
        }
    }

    fn scrub(&mut self, r: &Region, what: &str) {
        let mut stored = vec![0u8; r.blocks as usize * BLOCK];
        if self.dev.read(r.block, &mut stored).is_err() {
            self.err(format!("{what}: cannot read extent at block {}", r.block));
            return;
        }
        stored.truncate(r.stored as usize);
        if !blake3::ct_eq(&blake3::hash(&stored), &r.hash) {
            self.err(format!("{what}: extent at block {} fails its BLAKE3 (bit rot or a lost write)", r.block));
            return;
        }
        let mut out = vec![0u8; r.len as usize];
        let mut z = crate::zstd::Workspace::new();
        if read::decode_extent(r.compression, &stored, &mut out, &mut z).is_err() {
            self.err(format!("{what}: extent at block {} does not decode", r.block));
            return;
        }
        self.report.verified_bytes += u64::from(r.stored);
    }
}

/// Checks a volume. `scrub` reads and verifies every data extent too.
pub fn check<D: BlockDev>(dev: &mut D, scrub: bool) -> Result<Report, Error> {
    let mut buf = [0u8; BLOCK];
    let sb = read::read_superblock(dev, &mut buf)?;
    let mut c = Checker { dev, sb, buf, ranges: BTreeMap::new(), nodes: BTreeSet::new(), extents: BTreeMap::new(), report: Report::default() };
    c.report.generation = sb.generation;
    let mut items = Vec::new();
    c.tree(&sb.root_tree, 0, &mut items);
    let mut subvols = Vec::new();
    for (k, v) in &items {
        if k.kind != KIND_ROOT || k.off != 0 || k.obj == 0 || k.obj >= sb.next_subvol {
            c.err(format!("tree of subvolumes: unexpected item {k:?}"));
            continue;
        }
        match RootItem::decode(v) {
            Some(r) => subvols.push((k.obj, r)),
            None => c.err(format!("subvolume {} item is malformed", k.obj)),
        }
    }
    if !subvols.iter().any(|(id, _)| *id == sb.default_subvol) {
        c.err(format!("the default subvolume {} does not exist", sb.default_subvol));
    }
    let mut names = BTreeSet::new();
    for (id, r) in &subvols {
        if !names.insert(r.name().to_vec()) {
            c.err(format!("two subvolumes are called {:?}", String::from_utf8_lossy(r.name())));
        }
        c.subvol(*id, r, scrub);
    }
    c.report.subvols = subvols.len();
    // No two referenced ranges overlap.
    let mut end = FIRST_FREE;
    let ranges: Vec<(u64, u64)> = c.ranges.iter().map(|(a, b)| (*a, *b)).collect();
    for (b, n) in ranges {
        if b < end {
            c.err(format!("block {b} is referenced by two different things"));
        }
        end = end.max(b + n);
        c.report.used_blocks += n;
    }
    Ok(c.report)
}
