// SPDX-License-Identifier: Apache-2.0
//! NCFS end to end: files, directories, links, snapshots, deduplication,
//! compression, corruption found, and the power cut at every write of a
//! commit — torn writes and reordered writes included.

use super::check::check;
use super::format::*;
use super::read::{BlockDev, Scratch, SliceDev, Volume};
use super::write::{BlockDevMut, Encoder, FixedClock, Format, Options, SetAttr, Writer};
use super::Error;
use std::boxed::Box;
use std::collections::BTreeMap;
use std::vec::Vec;
use std::{format, vec};

/// Memory that remembers what was written since it started recording, so
/// a test can rebuild any state a power cut could leave.
#[derive(Clone)]
pub(crate) struct MemDev {
    pub data: Vec<u8>,
    pub log: Option<Vec<Op>>,
}

#[derive(Clone, Debug)]
pub(crate) enum Op {
    Write(u64, Vec<u8>),
    Flush,
}

impl MemDev {
    pub fn new(blocks: u64) -> MemDev {
        MemDev { data: vec![0; blocks as usize * BLOCK], log: None }
    }
}

impl BlockDev for MemDev {
    fn blocks(&self) -> u64 {
        (self.data.len() / BLOCK) as u64
    }

    fn read(&mut self, block: u64, buf: &mut [u8]) -> Result<(), Error> {
        let at = block as usize * BLOCK;
        buf.copy_from_slice(self.data.get(at..at + buf.len()).ok_or(Error::Io)?);
        Ok(())
    }
}

impl BlockDevMut for MemDev {
    fn write(&mut self, block: u64, data: &[u8]) -> Result<(), Error> {
        let at = block as usize * BLOCK;
        self.data.get_mut(at..at + data.len()).ok_or(Error::Io)?.copy_from_slice(data);
        if let Some(log) = &mut self.log {
            log.push(Op::Write(block, data.to_vec()));
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Error> {
        if let Some(log) = &mut self.log {
            log.push(Op::Flush);
        }
        Ok(())
    }
}

const NOW: i64 = 1_700_000_000_123_456_789;

fn clock() -> Box<FixedClock> {
    Box::new(FixedClock(NOW))
}

fn fresh(blocks: u64) -> Writer<MemDev> {
    Writer::format(MemDev::new(blocks), &Format { label: b"test".to_vec(), fsid: [0x5A; 16] }, Options::default(), clock()).unwrap()
}

fn reopen(dev: MemDev) -> Writer<MemDev> {
    Writer::open(dev, Options::default(), clock()).unwrap()
}

/// Text-like data that compresses.
fn text(n: usize, seed: u32) -> Vec<u8> {
    let words: [&[u8]; 8] = [b"nano", b"chronometer ", b"ncfs ", b"blake3\n", b"snapshot ", b"extent ", b"window ", b"0123456789 "];
    let mut out = Vec::new();
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    while out.len() < n {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        out.extend_from_slice(words[(x >> 16) as usize % words.len()]);
    }
    out.truncate(n);
    out
}

/// Data that does not.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Everything visible in a subvolume, through the reader: path → (mode,
/// nlink, bytes or link target).
type Tree = BTreeMap<Vec<u8>, (u32, u32, Vec<u8>)>;

fn tree_of(data: &[u8], subvol: Option<&[u8]>) -> Result<Tree, Error> {
    let mut s = Box::new(Scratch::new());
    let mut v = Volume::open(SliceDev::new(data), &mut s.node)?;
    if let Some(name) = subvol {
        v.open_subvol(name, &mut s.node)?;
    }
    let mut out = Tree::new();
    walk(&mut v, &mut s, ROOT_INO, b"", &mut out)?;
    Ok(out)
}

fn walk(v: &mut Volume<SliceDev>, s: &mut Scratch, dir: u64, prefix: &[u8], out: &mut Tree) -> Result<(), Error> {
    let mut entries = Vec::new();
    v.read_dir(dir, 0, &mut s.node, |ino, _, name, _| {
        entries.push((ino, name.to_vec()));
        true
    })?;
    for (ino, name) in entries {
        let mut path = prefix.to_vec();
        path.push(b'/');
        path.extend_from_slice(&name);
        let i = v.inode(ino, &mut s.node)?;
        let content = if i.is_dir() {
            Vec::new()
        } else {
            let mut buf = vec![0u8; i.size as usize];
            let n = v.read(ino, &i, 0, &mut buf, s)?;
            assert_eq!(n, i.size as usize);
            buf
        };
        out.insert(path.clone(), (i.mode, i.nlink, content));
        if i.is_dir() {
            walk(v, s, ino, &path, out)?;
        }
    }
    Ok(())
}

fn assert_clean(data: &[u8]) {
    let r = check(&mut SliceDev::new(data), true).unwrap();
    assert!(r.is_clean(), "{:#?}", r.errors);
}

fn file(w: &mut Writer<MemDev>, dir: u64, name: &str, data: &[u8]) -> u64 {
    let (ino, _) = w.create(dir, name.as_bytes(), S_IFREG | 0o644, 1000, 1000, 0).unwrap();
    w.write(ino, 0, data).unwrap();
    ino
}

#[test]
fn mkfs_makes_an_empty_volume() {
    let mut w = fresh(1024);
    let sb = *w.superblock();
    assert_eq!((sb.generation, sb.label(), sb.default_subvol), (1, "test", DEFAULT_SUBVOL));
    let dev = w.device().clone();
    assert_eq!(tree_of(&dev.data, None).unwrap(), Tree::new());
    assert_clean(&dev.data);
    let mut s = Box::new(Scratch::new());
    let mut v = Volume::open(SliceDev::new(&dev.data), &mut s.node).unwrap();
    let root = v.inode(ROOT_INO, &mut s.node).unwrap();
    assert!(root.is_dir());
    assert_eq!((root.nlink, root.mtime), (2, NOW), "timestamps are nanoseconds");
    // Slot B holds generation 1; slot A is still empty.
    assert!(Superblock::decode(&dev.data[BLOCK..2 * BLOCK]).is_err());
    assert_eq!(Superblock::decode(&dev.data[2 * BLOCK..3 * BLOCK]).unwrap().generation, 1);
}

#[test]
fn files_directories_and_links_round_trip() {
    let mut w = fresh(4096);
    let sizes = [0usize, 1, 100, INLINE_MAX, INLINE_MAX + 1, BLOCK, 100_000, WINDOW, WINDOW + 1, 3 * WINDOW + 777];
    let (docs, _) = w.mkdir(ROOT_INO, b"docs", 0o755, 0, 0).unwrap();
    let (deep, _) = w.mkdir(docs, b"deep", 0o700, 0, 0).unwrap();
    let mut want = Tree::new();
    for (i, &n) in sizes.iter().enumerate() {
        let data = if i % 2 == 0 { text(n, i as u32) } else { noise(n, i as u64) };
        file(&mut w, docs, &format!("f{i}"), &data);
        want.insert(format!("/docs/f{i}").into_bytes(), (S_IFREG | 0o644, 1, data));
    }
    let big = text(1 << 20, 99);
    let ino = file(&mut w, deep, "big.txt", &big);
    w.link(ino, ROOT_INO, b"hardlink").unwrap();
    w.symlink(ROOT_INO, b"shortcut", b"docs/deep", 0, 0).unwrap();
    w.symlink(ROOT_INO, b"abs", b"/docs", 0, 0).unwrap();
    w.commit().unwrap();
    let dev = w.device().clone();
    assert_clean(&dev.data);
    let t = tree_of(&dev.data, None).unwrap();
    for (p, (mode, nlink, data)) in &want {
        let got = &t[p];
        assert_eq!((got.0, got.1), (*mode, *nlink), "{}", String::from_utf8_lossy(p));
        assert!(got.2 == *data, "{} differs", String::from_utf8_lossy(p));
    }
    assert_eq!(t[&b"/docs/deep/big.txt"[..]].2, big);
    assert_eq!(t[&b"/hardlink"[..]].1, 2, "two names, nlink 2");
    assert_eq!(t[&b"/shortcut"[..]].2, b"docs/deep");
    assert_eq!(t[&b"/docs"[..]].1, 3, "a directory counts its subdirectories");
    // Paths through symbolic links, `.` and `..`.
    let mut s = Box::new(Scratch::new());
    let mut v = Volume::open(SliceDev::new(&dev.data), &mut s.node).unwrap();
    for p in [&b"/shortcut/big.txt"[..], b"/abs/deep/big.txt", b"/docs/./deep/../deep/big.txt", b"//docs//deep/big.txt"] {
        assert_eq!(v.resolve(p, &mut s).unwrap(), ino, "{}", String::from_utf8_lossy(p));
    }
    assert_eq!(v.resolve(b"/docs/f0/x", &mut s), Err(Error::NotADirectory));
    assert_eq!(v.resolve(b"/nope", &mut s), Err(Error::NotFound));
    // Reads at every awkward offset agree with the bytes.
    let i = v.inode(ino, &mut s.node).unwrap();
    for (off, len) in [(0usize, 10usize), (WINDOW - 5, 10), (WINDOW, WINDOW), (big.len() - 3, 100), (5, 3 * WINDOW)] {
        let mut buf = vec![0u8; len];
        let n = v.read(ino, &i, off as u64, &mut buf, &mut s).unwrap();
        let end = (off + len).min(big.len());
        assert_eq!(&buf[..n], &big[off..end]);
    }
}

#[test]
fn overwrites_truncates_and_appends_match_a_model() {
    let mut w = fresh(4096);
    let ino = file(&mut w, ROOT_INO, "f", b"");
    let mut model: Vec<u8> = Vec::new();
    let mut x = 7u64;
    for step in 0..60 {
        x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let off = (x >> 20) as usize % (5 * WINDOW);
        match step % 4 {
            0 | 1 => {
                let data = if step % 3 == 0 { noise(1 + (x >> 50) as usize % 70_000, x) } else { text(1 + (x >> 48) as usize % 200_000, step) };
                w.write(ino, off as u64, &data).unwrap();
                if model.len() < off + data.len() {
                    model.resize(off + data.len(), 0);
                }
                model[off..off + data.len()].copy_from_slice(&data);
            }
            2 => {
                w.truncate(ino, off as u64).unwrap();
                model.resize(off, 0);
            }
            _ => {
                // Extend with a hole.
                let size = model.len() + (x >> 40) as usize % WINDOW;
                w.truncate(ino, size as u64).unwrap();
                model.resize(size, 0);
            }
        }
        assert_eq!(w.read(ino, 0, usize::MAX).unwrap(), model, "step {step}, before commit");
        if step % 7 == 0 {
            w.commit().unwrap();
            let dev = w.device().clone();
            assert_eq!(tree_of(&dev.data, None).unwrap()[&b"/f"[..]].2, model, "step {step}, committed");
        }
    }
    w.commit().unwrap();
    assert_clean(&w.device().data);
}

#[test]
fn renames_follow_posix() {
    let mut w = fresh(2048);
    let (a, _) = w.mkdir(ROOT_INO, b"a", 0o755, 0, 0).unwrap();
    let (b, _) = w.mkdir(ROOT_INO, b"b", 0o755, 0, 0).unwrap();
    let (sub, _) = w.mkdir(a, b"sub", 0o755, 0, 0).unwrap();
    file(&mut w, a, "x", b"x1");
    file(&mut w, b, "y", b"y1");
    // A file replaces a file.
    w.rename(a, b"x", b, b"y", false).unwrap();
    assert_eq!(w.lookup(a, b"x").unwrap(), None);
    let (y, _) = w.lookup(b, b"y").unwrap().unwrap();
    assert_eq!(w.read(y, 0, 10).unwrap(), b"x1");
    // noreplace refuses.
    file(&mut w, a, "z", b"z");
    assert_eq!(w.rename(a, b"z", b, b"y", true), Err(Error::Exists));
    // A directory cannot move into itself.
    assert_eq!(w.rename(ROOT_INO, b"a", sub, b"a2", false), Err(Error::InvalidName));
    // A directory replaces an empty directory, not a full one, not a file.
    w.mkdir(b, b"empty", 0o755, 0, 0).unwrap();
    assert_eq!(w.rename(a, b"sub", b, b"y", false), Err(Error::NotADirectory));
    w.rename(a, b"sub", b, b"empty", false).unwrap();
    assert_eq!(w.inode(sub).unwrap().parent, b);
    assert_eq!(w.inode(a).unwrap().nlink, 2);
    assert_eq!(w.inode(b).unwrap().nlink, 3);
    file(&mut w, sub, "inside", b"i");
    w.mkdir(a, b"target", 0o755, 0, 0).unwrap();
    file(&mut w, ROOT_INO, "loose", b"l");
    assert_eq!(w.rename(ROOT_INO, b"loose", a, b"target", false), Err(Error::IsADirectory));
    assert_eq!(w.rmdir(b, b"empty"), Err(Error::NotEmpty));
    assert_eq!(w.resolve(b"/b/empty/inside").unwrap(), w.lookup(sub, b"inside").unwrap().unwrap().0);
    assert_eq!(w.resolve(b"/b/empty/..").unwrap(), b);
    w.commit().unwrap();
    assert_clean(&w.device().data);
}

#[test]
fn thousands_of_entries_split_and_merge_the_tree() {
    let mut w = fresh(8192);
    let (d, _) = w.mkdir(ROOT_INO, b"many", 0o755, 0, 0).unwrap();
    for i in 0..3000 {
        file(&mut w, d, &format!("entry-{i:05}"), format!("{i}").as_bytes());
    }
    w.commit().unwrap();
    let dev = w.device().clone();
    let r = check(&mut SliceDev::new(&dev.data), true).unwrap();
    assert!(r.is_clean(), "{:#?}", r.errors);
    assert!(r.nodes > 100, "a deep tree: {} nodes", r.nodes);
    // Listed in creation order, in pages.
    let mut names = Vec::new();
    let mut cookie = 0;
    loop {
        let page = w.read_dir(d, cookie, 97).unwrap();
        if page.is_empty() {
            break;
        }
        cookie = page.last().unwrap().cookie;
        names.extend(page.into_iter().map(|e| e.name));
    }
    assert_eq!(names.len(), 3000);
    assert_eq!(names[1234], b"entry-01234");
    for i in (0..3000).filter(|i| i % 30 != 0) {
        w.unlink(d, format!("entry-{i:05}").as_bytes()).unwrap();
    }
    w.commit().unwrap();
    let dev = w.device().clone();
    let r2 = check(&mut SliceDev::new(&dev.data), true).unwrap();
    assert!(r2.is_clean(), "{:#?}", r2.errors);
    assert!(r2.nodes * 4 < r.nodes, "deleting merges nodes: {} then {}", r.nodes, r2.nodes);
    let t = tree_of(&dev.data, None).unwrap();
    assert_eq!(t.len(), 1 + 100);
    assert_eq!(t[&b"/many/entry-02970"[..]].2, b"2970");
    // And the space comes back.
    let before = w.space().used;
    w.rmdir(ROOT_INO, b"many").unwrap_err();
    for i in (0..3000).filter(|i| i % 30 == 0) {
        w.unlink(d, format!("entry-{i:05}").as_bytes()).unwrap();
    }
    w.rmdir(ROOT_INO, b"many").unwrap();
    w.commit().unwrap();
    w.commit().unwrap();
    assert!(w.space().used < before);
    assert_eq!(tree_of(&w.device().data, None).unwrap(), Tree::new());
}

#[test]
fn snapshots_are_frozen_shared_and_reclaimed() {
    let mut w = fresh(8192);
    let (d, _) = w.mkdir(ROOT_INO, b"etc", 0o755, 0, 0).unwrap();
    for i in 0..300 {
        file(&mut w, d, &format!("conf{i}"), &text(5000 + i, i as u32));
    }
    file(&mut w, ROOT_INO, "big", &noise(4 * WINDOW, 3));
    w.commit().unwrap();
    let used_before = w.space().used;
    let before = tree_of(&w.device().data, None).unwrap();
    let snap = w.snapshot(DEFAULT_SUBVOL, b"before-upgrade", true).unwrap();
    // Constant time and space: one more reference, no copies.
    assert!(w.space().used <= used_before + 4, "{} vs {}", w.space().used, used_before);
    // Change the live system.
    for i in 0..300 {
        if i % 2 == 0 {
            w.unlink(d, format!("conf{i}").as_bytes()).unwrap();
        } else {
            let (ino, _) = w.lookup(d, format!("conf{i}").as_bytes()).unwrap().unwrap();
            w.write(ino, 10, b"CHANGED").unwrap();
        }
    }
    let (big, _) = w.lookup(ROOT_INO, b"big").unwrap().unwrap();
    w.truncate(big, 100).unwrap();
    w.commit().unwrap();
    let dev = w.device().clone();
    assert_clean(&dev.data);
    assert_eq!(tree_of(&dev.data, Some(b"before-upgrade")).unwrap(), before, "the snapshot is frozen");
    let after = tree_of(&dev.data, None).unwrap();
    assert_eq!(after.len(), 1 + 150 + 1);
    assert_eq!(&after[&b"/etc/conf1"[..]].2[10..17], b"CHANGED");
    // A read-only snapshot refuses writes.
    w.select(b"before-upgrade").unwrap();
    assert_eq!(w.create(ROOT_INO, b"new", 0o644, 0, 0, 0), Err(Error::ReadOnly));
    w.select(b"default").unwrap();
    // A writable clone diverges on its own.
    let clone = w.snapshot(snap, b"clone", false).unwrap();
    w.select(b"clone").unwrap();
    file(&mut w, ROOT_INO, "only-in-clone", b"c");
    w.commit().unwrap();
    w.select(b"default").unwrap();
    assert!(w.lookup(ROOT_INO, b"only-in-clone").unwrap().is_none());
    let dev = w.device().clone();
    assert_clean(&dev.data);
    assert!(tree_of(&dev.data, Some(b"clone")).unwrap().contains_key(&b"/only-in-clone"[..]));
    // Deleting both returns the space only they held.
    let used_with = w.space().used;
    w.delete_subvol(clone).unwrap();
    w.delete_subvol(snap).unwrap();
    w.commit().unwrap();
    assert!(w.space().used < used_with);
    assert_eq!(w.delete_subvol(DEFAULT_SUBVOL), Err(Error::Busy));
    let dev = w.device().clone();
    assert_clean(&dev.data);
    assert_eq!(tree_of(&dev.data, None).unwrap(), after);
    // Remounting counts exactly what the writer counted.
    let space = w.space();
    let w2 = reopen(dev);
    assert_eq!(w2.space(), space);
}

#[test]
fn rollback_makes_a_snapshot_the_default() {
    let mut w = fresh(2048);
    file(&mut w, ROOT_INO, "state", b"good");
    let good = w.snapshot(DEFAULT_SUBVOL, b"good", false).unwrap();
    let (ino, _) = w.lookup(ROOT_INO, b"state").unwrap().unwrap();
    w.write(ino, 0, b"BAD!").unwrap();
    w.set_default(good).unwrap();
    w.commit().unwrap();
    let dev = w.device().clone();
    assert_eq!(tree_of(&dev.data, None).unwrap()[&b"/state"[..]].2, b"good");
    assert_eq!(tree_of(&dev.data, Some(b"default")).unwrap()[&b"/state"[..]].2, b"BAD!");
}

#[test]
fn identical_windows_are_stored_once() {
    let mut w = fresh(4096);
    let data = noise(2 * WINDOW, 42);
    file(&mut w, ROOT_INO, "a", &data);
    w.commit().unwrap();
    let one = w.space().used;
    file(&mut w, ROOT_INO, "b", &data);
    w.commit().unwrap();
    let two = w.space().used;
    assert!(two - one < 8, "the second copy costs metadata only: {one} then {two}");
    // Changing one copy leaves the other alone.
    let (b, _) = w.lookup(ROOT_INO, b"b").unwrap().unwrap();
    w.write(b, 5, b"XX").unwrap();
    w.commit().unwrap();
    let dev = w.device().clone();
    let t = tree_of(&dev.data, None).unwrap();
    assert_eq!(t[&b"/a"[..]].2, data);
    assert_eq!(&t[&b"/b"[..]].2[5..7], b"XX");
    assert_clean(&dev.data);
    // Without dedup, the same bytes take their own blocks.
    w.options().dedup = false;
    file(&mut w, ROOT_INO, "c", &data);
    w.commit().unwrap();
    assert!(w.space().used - two >= 64);
}

#[test]
fn compression_saves_blocks_and_zeros_are_holes() {
    let mut w = fresh(4096);
    let t = text(1 << 20, 5);
    file(&mut w, ROOT_INO, "text", &t);
    w.commit().unwrap();
    let used = w.space().used;
    assert!(used < 180, "1 MiB of text in {used} blocks");
    assert_ne!(w.superblock().incompat & INCOMPAT_LZ4, 0);
    let z = vec![0u8; 4 << 20];
    file(&mut w, ROOT_INO, "zeros", &z);
    w.commit().unwrap();
    assert!(w.space().used - used < 4, "4 MiB of zeros is a hole");
    // A file that refuses compression.
    let (ino, _) = w.create(ROOT_INO, b"raw", 0o644, 0, 0, 0).unwrap();
    w.set_flags(ino, INODE_NOCOMPRESS).unwrap();
    w.write(ino, 0, &t[..WINDOW]).unwrap();
    w.commit().unwrap();
    let dev = w.device().clone();
    let tr = tree_of(&dev.data, None).unwrap();
    assert_eq!(tr[&b"/text"[..]].2, t);
    assert_eq!(tr[&b"/zeros"[..]].2, z);
    assert_eq!(tr[&b"/raw"[..]].2, &t[..WINDOW]);
    assert_clean(&dev.data);
}

/// A ZSTD "encoder" that knows one answer: the reference library's frame
/// for this text (made for the zstd decoder's own tests).
struct OneFrame;

fn zstd_text() -> Vec<u8> {
    let words: [&[u8]; 9] = [b"nano", b"chronometer", b"ncfs", b"blake3", b"snapshot", b"extent", b"  ", b"\n", b"0123456789"];
    let mut out = Vec::new();
    let mut x: u32 = 0x9E37_79B9;
    while out.len() < 5000 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        out.extend_from_slice(words[(x >> 16) as usize % words.len()]);
    }
    out.truncate(5000);
    out
}

const ZSTD_FRAME: &str = "28b52ffd648812ad180022c81316804d3a802db36d19af39ee0cac92160018ee4467d503dfb66dbfdfb66dbfdfffb67ffbdff6ffdbefb7ffedff7731cb25362b52b7fe8ba72ecf72b204398c82188400f8c11cf52892a5417828354b8156a851d3a65259e61120084481a0e4d479128030480c8bd028cdb014cf218294931991a450e94bc208a92c0ec53302997eba29342b5a765f5f4230666cce4863ab45166d2f1208a9549916af18290421c2b3c1ce597fe25805750056bdb59c62222df15d84a89d0a07589046c6d320b65efe5f430a828e2cfe0c00b4bc923cd1b266257414c3bc58f44a2aaa4b3bab284e2ddc787095135a7f0296b961bc670884cdd7062bcb8bb08c1e88982cdad341293f541a6a3f206da17361b1eb9d749af4f05046fbb873223d22acf24c55606c5ad82026bf1a0755645fcc7aa3e62e36e5bd110b3b71bdb8deed64c58084d2604a6d065867541d86f194a7c2e082c5e2183d9ad048cef62c23d2e96bd0c4f0bc7b1cb5a459e9ffc29481c87068e9ee655423fdb8c0411dee75a7c416f740254ee7af0a421a45ca35845f60d2a5fde684bf101346d70ce31f4615be3aa200dbf88a48f315ae75ce475963c38db47179afe7a7af4a989dd96abf1810f8c4ab4702394a191c58dedd63a3a93194d5c2a66f4572a630c51e6fcd58393bcee8073fbd207b206cafddde7b378d7c2e652efc8b38c882b008319045c00735e0bcb39da3be19693acc098973519ae2bb645a41cafb22401a00d2e891d8f56bb9dfbb3be8c7371da300ad61258226ff6bd145c221b0deb68d96c9f1c42ec3d15f508acf76de29c46399120553921fd1ff4785d8310bc20b0045a9eb4ce1f6a62ea1fa8779a96ce1261a9ec22780a04f7bc7a9368ff6b4bbde8bdd54e718f235e50cf5cfd01136e14fba02da925b8ee9b02a66ea1d166607fbeddbd87ac267cf001daeaa0b2ff75a1eb9c8605fa5966fc1a65f994158f9b15d72dd1127f630658b590fc075c1080a2d2bafa86ee7b84ff38fde49b10a27f589c12d2e009f1118c70eced8da1098f5e480796b73e101af0816dac08d24460819012f4dd51beab0762b5a2b7836f1ce791260088495c03ff907e96faeab0a9ec02377";

impl Encoder for OneFrame {
    fn encode(&mut self, c: Compression, input: &[u8]) -> Option<Vec<u8>> {
        (c == Compression::Zstd && input == zstd_text()).then(|| (0..ZSTD_FRAME.len()).step_by(2).map(|i| u8::from_str_radix(&ZSTD_FRAME[i..i + 2], 16).unwrap()).collect())
    }
}

#[test]
fn zstd_extents_read_back() {
    let mut w = fresh(1024);
    w.options().compression = Compression::Zstd;
    w.set_encoder(Box::new(OneFrame));
    let (ino, _) = w.create(ROOT_INO, b"z", 0o644, 0, 0, 0).unwrap();
    // In the second window, so it is not stored inline.
    w.write(ino, WINDOW as u64, &zstd_text()).unwrap();
    w.commit().unwrap();
    assert_ne!(w.superblock().incompat & INCOMPAT_ZSTD, 0);
    let dev = w.device().clone();
    let got = &tree_of(&dev.data, None).unwrap()[&b"/z"[..]].2;
    assert_eq!(&got[..WINDOW], &vec![0u8; WINDOW][..]);
    assert_eq!(&got[WINDOW..], &zstd_text()[..]);
    assert_clean(&dev.data);
}

#[test]
fn corruption_is_found_where_it_is() {
    let mut w = fresh(2048);
    let data = noise(3 * WINDOW, 9);
    file(&mut w, ROOT_INO, "victim", &data);
    w.commit().unwrap();
    file(&mut w, ROOT_INO, "second", b"two commits");
    w.commit().unwrap();
    let dev = w.device().clone();
    // A flipped bit in the data: the read fails with the block's number.
    let mut bad = dev.clone();
    let mut extents = Vec::new();
    {
        let mut s = Box::new(Scratch::new());
        let mut v = Volume::open(SliceDev::new(&dev.data), &mut s.node).unwrap();
        let ino = v.resolve(b"/victim", &mut s).unwrap();
        let sb = v.sb;
        let root = v.subvol.root;
        super::read::range(&mut SliceDev::new(&dev.data), &sb, &root, 1, Key::new(ino, KIND_EXTENT, 0), Key::new(ino, KIND_EXTENT + 1, 0), &mut s.node, |_, val| {
            if let Some(Extent::Regular(r)) = Extent::decode(val) {
                extents.push(r);
            }
            Ok(true)
        })
        .unwrap();
    }
    let r = extents[1];
    bad.data[r.block as usize * BLOCK + 100] ^= 0x10;
    let mut s = Box::new(Scratch::new());
    let mut v = Volume::open(SliceDev::new(&bad.data), &mut s.node).unwrap();
    let ino = v.resolve(b"/victim", &mut s).unwrap();
    let i = v.inode(ino, &mut s.node).unwrap();
    let mut buf = vec![0u8; WINDOW];
    assert_eq!(v.read(ino, &i, 0, &mut buf, &mut s), Ok(WINDOW), "other windows still read");
    assert_eq!(v.read(ino, &i, WINDOW as u64, &mut buf, &mut s), Err(Error::Checksum(r.block)));
    let report = check(&mut SliceDev::new(&bad.data), true).unwrap();
    assert_eq!(report.errors.len(), 1, "{:#?}", report.errors);
    assert!(report.errors[0].contains("BLAKE3"));
    // A flipped bit in the active superblock: the previous commit mounts.
    let sb = Superblock::decode(&dev.data[SUPER[(w.superblock().generation % 2) as usize] as usize * BLOCK..][..BLOCK]).unwrap();
    let mut torn = dev.clone();
    torn.data[SUPER[(sb.generation % 2) as usize] as usize * BLOCK + 300] ^= 1;
    let t = tree_of(&torn.data, None).unwrap();
    assert!(t.contains_key(&b"/victim"[..]) && !t.contains_key(&b"/second"[..]), "fell back one generation");
    // A flipped bit in a tree node: refused, never misread.
    let mut nodebad = dev.clone();
    let root = sb.root_tree.block as usize;
    nodebad.data[root * BLOCK + 200] ^= 4;
    assert!(matches!(tree_of(&nodebad.data, None), Err(Error::Checksum(_))));
}

/// Applies a power cut to `base` after `ops`: everything before the last
/// flush before the cut landed; of the writes since, `keep` says which;
/// the write at the cut, if `torn`, landed half.
fn crash_image(base: &[u8], ops: &[Op], cut: usize, keep: &dyn Fn(usize) -> bool, torn: bool) -> Vec<u8> {
    let mut data = base.to_vec();
    let last_flush = ops[..cut].iter().rposition(|o| matches!(o, Op::Flush)).map_or(0, |i| i + 1);
    for (i, op) in ops[..cut].iter().enumerate() {
        if let Op::Write(b, d) = op {
            if i < last_flush || keep(i) {
                data[*b as usize * BLOCK..*b as usize * BLOCK + d.len()].copy_from_slice(d);
            }
        }
    }
    if torn {
        if let Some(Op::Write(b, d)) = ops.get(cut) {
            let half = d.len() / 2;
            data[*b as usize * BLOCK..*b as usize * BLOCK + half].copy_from_slice(&d[..half]);
        }
    }
    data
}

fn power_cut_everywhere(prepare: &dyn Fn(&mut Writer<MemDev>), change: &dyn Fn(&mut Writer<MemDev>)) -> usize {
    let mut w = fresh(4096);
    prepare(&mut w);
    w.commit().unwrap();
    let base = w.device().data.clone();
    let before = tree_of(&base, None).unwrap();
    w.device().log = Some(Vec::new());
    change(&mut w);
    w.commit().unwrap();
    let ops = w.device().log.take().unwrap();
    let after = tree_of(&w.device().data, None).unwrap();
    assert_ne!(before, after);
    // Every state a commit made durable — a change may commit more than
    // once (deleting a subvolume commits first) — is a state a cut may
    // leave; nothing else is.
    let mut committed = vec![before.clone()];
    for (i, op) in ops.iter().enumerate() {
        let follows_super = i > 0 && matches!(&ops[i - 1], Op::Write(b, _) if SUPER.contains(b));
        if matches!(op, Op::Flush) && follows_super {
            committed.push(tree_of(&crash_image(&base, &ops, i + 1, &|_| true, false), None).unwrap());
        }
    }
    assert_eq!(committed.last(), Some(&after));
    let mut images = 0;
    let mut x = 0x1234_5678_9ABC_DEF1u64;
    for cut in 0..=ops.len() {
        type Keep = Box<dyn Fn(usize) -> bool>;
        let mut variants: Vec<(Keep, bool)> = vec![(Box::new(|_| true), false), (Box::new(|_| true), true), (Box::new(|_| false), false)];
        for _ in 0..3 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mask = x;
            variants.push((Box::new(move |i| (mask >> (i % 64)) & 1 == 1), mask & 1 == 0));
        }
        for (keep, torn) in &variants {
            let img = crash_image(&base, &ops, cut, keep.as_ref(), *torn);
            let t = tree_of(&img, None).unwrap_or_else(|e| panic!("cut {cut}/{}: does not mount: {e}", ops.len()));
            assert!(committed.contains(&t), "cut {cut}/{}: a state no commit made", ops.len());
            let r = check(&mut SliceDev::new(&img), true).unwrap();
            assert!(r.is_clean(), "cut {cut}: {:#?}", r.errors);
            images += 1;
        }
        // The volume opens for writing after any cut, and the next commit is
        // whole.
        let img = crash_image(&base, &ops, cut, &|_| true, true);
        let mut w2 = reopen(MemDev { data: img, log: None });
        file(&mut w2, ROOT_INO, "after-the-crash", b"fine");
        w2.commit().unwrap();
        assert_clean(&w2.device().data);
    }
    images
}

#[test]
fn power_cut_at_every_write_of_a_commit() {
    let n = power_cut_everywhere(
        &|w| {
            let (d, _) = w.mkdir(ROOT_INO, b"sys", 0o755, 0, 0).unwrap();
            for i in 0..80 {
                file(w, d, &format!("lib{i}.ncdyn"), &text(3000 + 37 * i, i as u32));
            }
            file(w, ROOT_INO, "kernel", &noise(2 * WINDOW, 1));
        },
        &|w| {
            let d = w.resolve(b"/sys").unwrap();
            for i in 0..80 {
                if i % 3 == 0 {
                    w.unlink(d, format!("lib{i}.ncdyn").as_bytes()).unwrap();
                } else if i % 3 == 1 {
                    w.rename(d, format!("lib{i}.ncdyn").as_bytes(), d, format!("new{i}.ncdyn").as_bytes(), false).unwrap();
                }
            }
            file(w, d, "fresh.ncdyn", &noise(WINDOW + 5, 2));
            let k = w.resolve(b"/kernel").unwrap();
            w.write(k, 1000, b"patched").unwrap();
        },
    );
    assert!(n > 100, "{n} crash images");
}

#[test]
fn power_cut_while_snapshotting_and_deleting() {
    power_cut_everywhere(
        &|w| {
            for i in 0..40 {
                file(w, ROOT_INO, &format!("f{i}"), &text(9000, i));
            }
            w.snapshot(DEFAULT_SUBVOL, b"old", true).unwrap();
        },
        &|w| {
            for i in 0..40 {
                w.unlink(ROOT_INO, format!("f{i}").as_bytes()).unwrap();
            }
            let old = w.subvols().into_iter().find(|(_, r)| r.name() == b"old").unwrap().0;
            w.delete_subvol(old).unwrap();
            file(w, ROOT_INO, "only", b"x");
        },
    );
}

#[test]
fn the_kernel_reader_needs_no_heap_and_little_stack() {
    // The reader's whole state for a file read: one Scratch, lent.
    assert!(core::mem::size_of::<Scratch>() < 300 * 1024);
    assert!(core::mem::size_of::<Volume<SliceDev>>() < 1024);
    let mut w = fresh(1024);
    file(&mut w, ROOT_INO, "hello", b"Hello from NCFS");
    w.commit().unwrap();
    let dev = w.device().clone();
    let mut s = Box::new(Scratch::new());
    let mut v = Volume::open(SliceDev::new(&dev.data), &mut s.node).unwrap();
    let ino = v.resolve(b"/hello", &mut s).unwrap();
    let i = v.inode(ino, &mut s.node).unwrap();
    let mut out = [0u8; 64];
    let n = v.read(ino, &i, 0, &mut out, &mut s).unwrap();
    assert_eq!(&out[..n], b"Hello from NCFS");
}

#[test]
fn setattr_and_names() {
    let mut w = fresh(1024);
    let ino = file(&mut w, ROOT_INO, "f", b"0123456789");
    let i = w.setattr(ino, &SetAttr { mode: Some(0o600), uid: Some(5), size: Some(4), mtime: Some(-1), ..SetAttr::default() }).unwrap();
    assert_eq!((i.mode, i.uid, i.size, i.mtime), (S_IFREG | 0o600, 5, 4, -1));
    assert_eq!(w.read(ino, 0, 100).unwrap(), b"0123");
    for bad in [&b""[..], b".", b"..", b"a/b", b"a\0"] {
        assert_eq!(w.create(ROOT_INO, bad, 0o644, 0, 0, 0), Err(Error::InvalidName));
    }
    let long = vec![b'x'; 256];
    assert_eq!(w.create(ROOT_INO, &long, 0o644, 0, 0, 0), Err(Error::InvalidName));
    // Any bytes but '/' and NUL are a name, UTF-8 or not.
    w.create(ROOT_INO, "Marín Kitagawa.png".as_bytes(), 0o644, 0, 0, 0).unwrap();
    w.create(ROOT_INO, b"\xff\xfe", 0o644, 0, 0, 0).unwrap();
    assert_eq!(w.create(ROOT_INO, b"f", 0o644, 0, 0, 0), Err(Error::Exists));
    w.commit().unwrap();
    assert_clean(&w.device().data);
}
