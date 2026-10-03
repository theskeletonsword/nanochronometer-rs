// SPDX-License-Identifier: Apache-2.0
//! `ncfs mount`: an NCFS volume through FUSE, in ring 3.
//!
//! The recommended way to reach a volume from Linux — to read the crash
//! dumps a machine left on its disk, to audit an image, to copy files in
//! and out — because a bug or a hostile image can crash this process and
//! nothing else. (The `nanochrono` kernel module's ring-0 mount is for when
//! FUSE is not there.) Read-write mounts commit on `fsync`, when a written
//! file is closed, every few seconds while busy, and at unmount; each
//! commit is atomic, so a cut power or a killed process leaves the last
//! one. Read-only mounts use the kernel's reader and open sealed images.

use crate::dev::{FileDev, SystemClock};
use fuser::{
    AccessFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenFlags,
    RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyStatfs, ReplyWrite, Request, TimeOrNow, WriteFlags,
};
use nanochrono_core::ncfs::format::*;
use nanochrono_core::ncfs::write::{Options, SetAttr, Writer};
use nanochrono_core::ncfs::{Error, Scratch, Volume};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);
/// Commit at least this often while writes keep coming.
const COMMIT_EVERY: Duration = Duration::from_secs(5);

enum Back {
    Rw { w: Box<Writer<FileDev>>, dirty: bool, last: Instant },
    Ro { v: Box<Volume<FileDev>>, s: Box<Scratch> },
}

type Entry = (u64, u8, Vec<u8>, u64);

impl Back {
    fn inode(&mut self, ino: u64) -> Result<Inode, Error> {
        match self {
            Back::Rw { w, .. } => w.inode(ino),
            Back::Ro { v, s } => v.inode(ino, &mut s.node),
        }
    }

    fn lookup(&mut self, dir: u64, name: &[u8]) -> Result<Option<(u64, u8)>, Error> {
        match self {
            Back::Rw { w, .. } => w.lookup(dir, name),
            Back::Ro { v, s } => v.lookup(dir, name, &mut s.node),
        }
    }

    fn entries(&mut self, dir: u64, cookie: u64, limit: usize) -> Result<Vec<Entry>, Error> {
        match self {
            Back::Rw { w, .. } => Ok(w.read_dir(dir, cookie, limit)?.into_iter().map(|e| (e.ino, e.dtype, e.name, e.cookie)).collect()),
            Back::Ro { v, s } => {
                let mut out = Vec::new();
                v.read_dir(dir, cookie, &mut s.node, |ino, t, name, next| {
                    out.push((ino, t, name.to_vec(), next));
                    out.len() < limit
                })?;
                Ok(out)
            }
        }
    }

    fn read(&mut self, ino: u64, off: u64, len: usize) -> Result<Vec<u8>, Error> {
        match self {
            Back::Rw { w, .. } => w.read(ino, off, len),
            Back::Ro { v, s } => {
                let i = v.inode(ino, &mut s.node)?;
                if i.is_dir() {
                    return Err(Error::IsADirectory);
                }
                let mut buf = vec![0u8; len.min(i.size.saturating_sub(off) as usize)];
                let n = v.read(ino, &i, off, &mut buf, s)?;
                buf.truncate(n);
                Ok(buf)
            }
        }
    }

    fn readlink(&mut self, ino: u64) -> Result<Vec<u8>, Error> {
        match self {
            Back::Rw { w, .. } => w.readlink(ino),
            Back::Ro { v, s } => {
                let i = v.inode(ino, &mut s.node)?;
                let mut buf = vec![0u8; i.size as usize];
                let n = v.read_link(ino, &i, &mut buf, s)?;
                buf.truncate(n);
                Ok(buf)
            }
        }
    }

    /// The writer, for an operation that changes the volume.
    fn writer(&mut self) -> Result<&mut Writer<FileDev>, Error> {
        match self {
            Back::Rw { w, dirty, .. } => {
                *dirty = true;
                Ok(w)
            }
            Back::Ro { .. } => Err(Error::ReadOnly),
        }
    }

    fn sync(&mut self) -> Result<(), Error> {
        if let Back::Rw { w, dirty, last } = self {
            if *dirty {
                w.commit()?;
                *dirty = false;
                *last = Instant::now();
            }
        }
        Ok(())
    }

    fn maybe_sync(&mut self) {
        if let Back::Rw { dirty: true, last, .. } = self {
            if last.elapsed() >= COMMIT_EVERY {
                let _ = self.sync();
            }
        }
    }

    fn space(&mut self) -> (u64, u64) {
        match self {
            Back::Rw { w, .. } => {
                let s = w.space();
                (s.total, s.free)
            }
            Back::Ro { v, .. } => (v.sb.total_blocks, 0),
        }
    }
}

fn errno(e: Error) -> Errno {
    match e {
        Error::NotFound => Errno::ENOENT,
        Error::Exists => Errno::EEXIST,
        Error::NotADirectory => Errno::ENOTDIR,
        Error::IsADirectory => Errno::EISDIR,
        Error::NotEmpty => Errno::ENOTEMPTY,
        Error::InvalidName | Error::NotASymlink => Errno::EINVAL,
        Error::Loop => Errno::ELOOP,
        Error::NoSpace => Errno::ENOSPC,
        Error::ReadOnly => Errno::EROFS,
        Error::TooBig => Errno::EFBIG,
        Error::Busy => Errno::EBUSY,
        _ => Errno::EIO,
    }
}

fn time(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

fn ns(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(e) => -(e.duration().as_nanos() as i64),
    }
}

fn kind(mode: u32) -> FileType {
    match mode & S_IFMT {
        S_IFDIR => FileType::Directory,
        S_IFLNK => FileType::Symlink,
        S_IFCHR => FileType::CharDevice,
        S_IFBLK => FileType::BlockDevice,
        S_IFIFO => FileType::NamedPipe,
        S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

fn dkind(t: u8) -> FileType {
    match t {
        DT_DIR => FileType::Directory,
        DT_LNK => FileType::Symlink,
        DT_CHR => FileType::CharDevice,
        DT_BLK => FileType::BlockDevice,
        DT_FIFO => FileType::NamedPipe,
        DT_SOCK => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

fn attr(ino: u64, i: &Inode) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size: i.size,
        blocks: i.size.div_ceil(512),
        atime: time(i.atime),
        mtime: time(i.mtime),
        ctime: time(i.ctime),
        crtime: time(i.btime),
        kind: kind(i.mode),
        perm: (i.mode & 0o7777) as u16,
        nlink: i.nlink,
        uid: i.uid,
        gid: i.gid,
        rdev: i.rdev as u32,
        flags: 0,
        blksize: BLOCK as u32,
    }
}

/// The filesystem FUSE calls.
pub struct NcfsFuse {
    back: Mutex<Back>,
}

impl NcfsFuse {
    fn with<R>(&self, f: impl FnOnce(&mut Back) -> R) -> R {
        let mut b = self.back.lock().unwrap_or_else(|p| p.into_inner());
        let r = f(&mut b);
        b.maybe_sync();
        r
    }

    fn entry(&self, reply: ReplyEntry, made: Result<(u64, Inode), Error>) {
        match made {
            Ok((ino, i)) => reply.entry(&TTL, &attr(ino, &i), Generation(0)),
            Err(e) => reply.error(errno(e)),
        }
    }
}

impl Filesystem for NcfsFuse {
    fn destroy(&mut self) {
        let b = self.back.get_mut().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = b.sync() {
            eprintln!("ncfs: the last commit failed: {e}");
        }
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let r = self.with(|b| {
            let (ino, _) = b.lookup(parent.0, name.as_bytes())?.ok_or(Error::NotFound)?;
            Ok((ino, b.inode(ino)?))
        });
        self.entry(reply, r);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.with(|b| b.inode(ino.0)) {
            Ok(i) => reply.attr(&TTL, &attr(ino.0, &i)),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let t = |x: Option<TimeOrNow>| {
            x.map(|v| match v {
                TimeOrNow::SpecificTime(s) => ns(s),
                TimeOrNow::Now => ns(SystemTime::now()),
            })
        };
        let a = SetAttr { mode, uid, gid, size, atime: t(atime), mtime: t(mtime) };
        match self.with(|b| b.writer()?.setattr(ino.0, &a)) {
            Ok(i) => reply.attr(&TTL, &attr(ino.0, &i)),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.with(|b| b.readlink(ino.0)) {
            Ok(t) => reply.data(&t),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn mknod(&self, req: &Request, parent: INodeNo, name: &OsStr, mode: u32, umask: u32, rdev: u32, reply: ReplyEntry) {
        let r = self.with(|b| b.writer()?.create(parent.0, name.as_bytes(), mode & !umask, req.uid(), req.gid(), u64::from(rdev)));
        self.entry(reply, r);
    }

    fn mkdir(&self, req: &Request, parent: INodeNo, name: &OsStr, mode: u32, umask: u32, reply: ReplyEntry) {
        let r = self.with(|b| b.writer()?.mkdir(parent.0, name.as_bytes(), mode & !umask, req.uid(), req.gid()));
        self.entry(reply, r);
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.with(|b| b.writer()?.unlink(parent.0, name.as_bytes())) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.with(|b| b.writer()?.rmdir(parent.0, name.as_bytes())) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn symlink(&self, req: &Request, parent: INodeNo, link_name: &OsStr, target: &Path, reply: ReplyEntry) {
        let r = self.with(|b| b.writer()?.symlink(parent.0, link_name.as_bytes(), target.as_os_str().as_bytes(), req.uid(), req.gid()));
        self.entry(reply, r);
    }

    fn rename(&self, _req: &Request, parent: INodeNo, name: &OsStr, newparent: INodeNo, newname: &OsStr, flags: RenameFlags, reply: ReplyEmpty) {
        if flags.contains(RenameFlags::RENAME_EXCHANGE) {
            reply.error(Errno::EINVAL);
            return;
        }
        let noreplace = flags.contains(RenameFlags::RENAME_NOREPLACE);
        match self.with(|b| b.writer()?.rename(parent.0, name.as_bytes(), newparent.0, newname.as_bytes(), noreplace)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn link(&self, _req: &Request, ino: INodeNo, newparent: INodeNo, newname: &OsStr, reply: ReplyEntry) {
        let r = self.with(|b| b.writer()?.link(ino.0, newparent.0, newname.as_bytes()).map(|i| (ino.0, i)));
        self.entry(reply, r);
    }

    fn read(&self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, size: u32, _flags: OpenFlags, _lock: Option<LockOwner>, reply: ReplyData) {
        match self.with(|b| b.read(ino.0, offset, size as usize)) {
            Ok(d) => reply.data(&d),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.with(|b| b.writer()?.write(ino.0, offset, data)) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn flush(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _lock: LockOwner, reply: ReplyEmpty) {
        reply.ok();
    }

    fn release(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _flags: OpenFlags, _lock: Option<LockOwner>, _flush: bool, reply: ReplyEmpty) {
        // A written file closed: commit, so `cp` then a power cut keeps it.
        match self.with(|b| b.sync()) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn fsync(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _datasync: bool, reply: ReplyEmpty) {
        match self.with(|b| b.sync()) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
        // Offsets: 1 after ".", 2 after "..", then each entry's cookie + 2.
        let r = self.with(|b| {
            let parent = b.inode(ino.0)?.parent;
            let rest = b.entries(ino.0, offset.saturating_sub(2), 512)?;
            Ok::<_, Error>((parent, rest))
        });
        let (parent, rest) = match r {
            Ok(x) => x,
            Err(e) => {
                reply.error(errno(e));
                return;
            }
        };
        if offset < 1 && reply.add(ino, 1, FileType::Directory, ".") {
            reply.ok();
            return;
        }
        if offset < 2 && reply.add(INodeNo(parent.max(1)), 2, FileType::Directory, "..") {
            reply.ok();
            return;
        }
        for (child, t, name, cookie) in rest {
            if reply.add(INodeNo(child), cookie + 2, dkind(t), OsStr::from_bytes(&name)) {
                break;
            }
        }
        reply.ok();
    }

    fn fsyncdir(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _datasync: bool, reply: ReplyEmpty) {
        match self.with(|b| b.sync()) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let (total, free) = self.with(|b| b.space());
        reply.statfs(total, free, free, 0, u64::MAX >> 1, BLOCK as u32, NAME_MAX as u32, BLOCK as u32);
    }

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        // Permissions are the kernel's (`default_permissions`).
        reply.ok();
    }

    fn create(&self, req: &Request, parent: INodeNo, name: &OsStr, mode: u32, umask: u32, _flags: i32, reply: ReplyCreate) {
        match self.with(|b| b.writer()?.create(parent.0, name.as_bytes(), mode & !umask, req.uid(), req.gid(), 0)) {
            Ok((ino, i)) => reply.created(&TTL, &attr(ino, &i), Generation(0), FileHandle(0), FopenFlags::empty()),
            Err(e) => reply.error(errno(e)),
        }
    }
}

/// Mounts `image` at `mountpoint` until it is unmounted (`fusermount3 -u`).
pub fn mount(image: &Path, mountpoint: &Path, read_only: bool, subvol: Option<&str>, opts: Options) -> Result<(), String> {
    let back = if read_only {
        let dev = FileDev::open(image, false).map_err(|e| format!("{}: {e}", image.display()))?;
        let mut s = Box::new(Scratch::new());
        let mut v = Box::new(Volume::open(dev, &mut s.node).map_err(|e| format!("{}: {e}", image.display()))?);
        if let Some(name) = subvol {
            v.open_subvol(name.as_bytes(), &mut s.node).map_err(|e| format!("subvolume {name}: {e}"))?;
        }
        Back::Ro { v, s }
    } else {
        let dev = FileDev::open(image, true).map_err(|e| format!("{}: {e}", image.display()))?;
        let mut w = Box::new(Writer::open(dev, opts, Box::new(SystemClock)).map_err(|e| format!("{}: {e} (try --ro)", image.display()))?);
        if let Some(name) = subvol {
            w.select(name.as_bytes()).map_err(|e| format!("subvolume {name}: {e}"))?;
        }
        Back::Rw { w, dirty: false, last: Instant::now() }
    };
    let mut cfg = Config::default();
    cfg.mount_options = vec![
        MountOption::FSName(format!("ncfs:{}", image.display())),
        MountOption::Subtype(String::from("ncfs")),
        MountOption::DefaultPermissions,
        if read_only { MountOption::RO } else { MountOption::RW },
    ];
    cfg.n_threads = Some(1);
    fuser::mount(NcfsFuse { back: Mutex::new(back) }, mountpoint, &cfg).map_err(|e| format!("{}: {e}", mountpoint.display()))
}
