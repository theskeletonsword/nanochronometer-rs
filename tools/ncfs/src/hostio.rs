// SPDX-License-Identifier: Apache-2.0
//! Copying between the host and a volume: `put`, `get`, and `build`, which
//! makes an image from a directory (an `ncinitramdisk`, a root filesystem).

use crate::dev::FileDev;
use nanochrono_core::ncfs::format::*;
use nanochrono_core::ncfs::write::{SetAttr, Writer};
use nanochrono_core::ncfs::{Error, Scratch, Volume};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// What a copy did.
#[derive(Debug, Default, Clone, Copy)]
pub struct Tally {
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub bytes: u64,
}

fn mtime_ns(m: &fs::Metadata) -> i64 {
    m.mtime().saturating_mul(1_000_000_000).saturating_add(m.mtime_nsec())
}

fn atime_ns(m: &fs::Metadata) -> i64 {
    m.atime().saturating_mul(1_000_000_000).saturating_add(m.atime_nsec())
}

fn err(path: &Path, e: impl std::fmt::Display) -> String {
    format!("{}: {e}", path.display())
}

/// Copies `src` (a file, a link or a whole tree) into directory `dir` of
/// the volume, as `name`; keeps modes, owners and timestamps to the
/// nanosecond.
pub fn put(w: &mut Writer<FileDev>, src: &Path, dir: u64, name: &[u8], t: &mut Tally) -> Result<(), String> {
    let meta = fs::symlink_metadata(src).map_err(|e| err(src, e))?;
    let ft = meta.file_type();
    if let Some((old, kind)) = w.lookup(dir, name).map_err(|e| err(src, e))? {
        // A directory merges into one already there; anything else is
        // replaced.
        if !(ft.is_dir() && kind == DT_DIR) {
            remove(w, dir, name).map_err(|e| err(src, e))?;
        } else {
            return put_children(w, src, old, t);
        }
    }
    let (uid, gid) = (meta.uid(), meta.gid());
    let mode = meta.permissions().mode() & 0o7777;
    if ft.is_symlink() {
        let target = fs::read_link(src).map_err(|e| err(src, e))?;
        w.symlink(dir, name, target.as_os_str().as_bytes(), uid, gid).map_err(|e| err(src, e))?;
        t.links += 1;
    } else if ft.is_dir() {
        let (ino, _) = w.mkdir(dir, name, mode, uid, gid).map_err(|e| err(src, e))?;
        t.dirs += 1;
        put_children(w, src, ino, t)?;
        w.setattr(ino, &SetAttr { atime: Some(atime_ns(&meta)), mtime: Some(mtime_ns(&meta)), ..SetAttr::default() }).map_err(|e| err(src, e))?;
    } else if ft.is_file() {
        let (ino, _) = w.create(dir, name, S_IFREG | mode, uid, gid, 0).map_err(|e| err(src, e))?;
        let data = fs::read(src).map_err(|e| err(src, e))?;
        for (i, chunk) in data.chunks(1 << 20).enumerate() {
            w.write(ino, (i << 20) as u64, chunk).map_err(|e| err(src, e))?;
        }
        w.setattr(ino, &SetAttr { atime: Some(atime_ns(&meta)), mtime: Some(mtime_ns(&meta)), ..SetAttr::default() }).map_err(|e| err(src, e))?;
        t.files += 1;
        t.bytes += data.len() as u64;
    } else {
        // FIFOs, sockets and device nodes are recorded as what they are.
        use std::os::unix::fs::FileTypeExt;
        let kind = if ft.is_fifo() {
            S_IFIFO
        } else if ft.is_socket() {
            S_IFSOCK
        } else if ft.is_block_device() {
            S_IFBLK
        } else {
            S_IFCHR
        };
        w.create(dir, name, kind | mode, uid, gid, meta.rdev()).map_err(|e| err(src, e))?;
        t.files += 1;
    }
    Ok(())
}

fn put_children(w: &mut Writer<FileDev>, src: &Path, ino: u64, t: &mut Tally) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(src).map_err(|e| err(src, e))?.collect::<Result<_, _>>().map_err(|e| err(src, e))?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        put(w, &e.path(), ino, e.file_name().as_bytes(), t)?;
    }
    Ok(())
}

/// Removes `name` from `dir`, recursively for a directory.
pub fn remove(w: &mut Writer<FileDev>, dir: u64, name: &[u8]) -> Result<(), Error> {
    let (ino, kind) = w.lookup(dir, name)?.ok_or(Error::NotFound)?;
    if kind != DT_DIR {
        return w.unlink(dir, name);
    }
    loop {
        let page = w.read_dir(ino, 0, 256)?;
        if page.is_empty() {
            break;
        }
        for e in page {
            remove(w, ino, &e.name)?;
        }
    }
    w.rmdir(dir, name)
}

/// Copies `ino` (named `name` in its directory) out of the volume to the
/// host path `dest`.
pub fn get(v: &mut Volume<FileDev>, s: &mut Scratch, ino: u64, dest: &Path, t: &mut Tally) -> Result<(), String> {
    let i = v.inode(ino, &mut s.node).map_err(|e| err(dest, e))?;
    if i.is_dir() {
        fs::create_dir_all(dest).map_err(|e| err(dest, e))?;
        let mut entries = Vec::new();
        v.read_dir(ino, 0, &mut s.node, |c, _, name, _| {
            entries.push((c, name.to_vec()));
            true
        })
        .map_err(|e| err(dest, e))?;
        for (c, name) in entries {
            get(v, s, c, &dest.join(std::ffi::OsStr::from_bytes(&name)), t)?;
        }
        fs::set_permissions(dest, fs::Permissions::from_mode(i.mode & 0o7777)).map_err(|e| err(dest, e))?;
        t.dirs += 1;
    } else if i.is_symlink() {
        let mut target = vec![0u8; i.size as usize];
        v.read_link(ino, &i, &mut target, s).map_err(|e| err(dest, e))?;
        let _ = fs::remove_file(dest);
        std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&target), dest).map_err(|e| err(dest, e))?;
        t.links += 1;
    } else if i.is_file() {
        let mut out = fs::File::create(dest).map_err(|e| err(dest, e))?;
        let mut buf = vec![0u8; 1 << 20];
        let mut off = 0u64;
        while off < i.size {
            let n = v.read(ino, &i, off, &mut buf, s).map_err(|e| err(dest, e))?;
            std::io::Write::write_all(&mut out, &buf[..n]).map_err(|e| err(dest, e))?;
            off += n as u64;
        }
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(i.mtime.max(0) as u64);
        let _ = out.set_modified(mtime);
        fs::set_permissions(dest, fs::Permissions::from_mode(i.mode & 0o7777)).map_err(|e| err(dest, e))?;
        t.files += 1;
        t.bytes += i.size;
    }
    Ok(())
}

/// The bytes and entries under `src`, to size an image for it.
pub fn measure(src: &Path) -> Result<(u64, u64), String> {
    let meta = fs::symlink_metadata(src).map_err(|e| err(src, e))?;
    if meta.file_type().is_dir() {
        let mut total = (0, 1);
        for e in fs::read_dir(src).map_err(|e| err(src, e))? {
            let e = e.map_err(|e| err(src, e))?;
            let (b, n) = measure(&e.path())?;
            total = (total.0 + b, total.1 + n);
        }
        Ok(total)
    } else if meta.file_type().is_file() {
        Ok((meta.len(), 1))
    } else {
        Ok((0, 1))
    }
}
