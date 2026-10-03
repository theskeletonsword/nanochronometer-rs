// SPDX-License-Identifier: Apache-2.0
//! NCFS as the filesystem the package manager installs into.
//!
//! [`crate::ncpkg::fs::Fs`] names four promises; NCFS keeps them by
//! construction: a create is committed before it returns (durable), a
//! rename is one change to the tree (atomic — after a crash the old name or
//! the new), commits happen in order, and `sync` is a commit (a barrier).
//! So `ncpkg install` runs unchanged against an NCFS image on a host (the
//! staging root of an ISO) and, once the kernel has a heap, against the
//! system's own volume.

use super::format::*;
use super::write::{BlockDevMut, Writer};
use super::Error;
use crate::ncpkg::fs::{Fs, FsError, NodeKind, Stat};
use alloc::string::String;
use alloc::vec::Vec;

/// An NCFS volume as an `ncpkg` root.
#[derive(Debug)]
pub struct PkgFs<D: BlockDevMut> {
    pub writer: Writer<D>,
}

impl<D: BlockDevMut> PkgFs<D> {
    pub fn new(writer: Writer<D>) -> PkgFs<D> {
        PkgFs { writer }
    }

    pub fn into_inner(self) -> Writer<D> {
        self.writer
    }

    fn split(path: &str) -> Result<(&str, &str), FsError> {
        if !path.starts_with('/') || path == "/" {
            return Err(FsError::Invalid);
        }
        let cut = path.rfind('/').ok_or(FsError::Invalid)?;
        let (dir, name) = (&path[..cut], &path[cut + 1..]);
        if name.is_empty() {
            return Err(FsError::Invalid);
        }
        Ok((if dir.is_empty() { "/" } else { dir }, name))
    }

    fn dir(&mut self, path: &str) -> Result<u64, FsError> {
        let ino = self.writer.resolve(path.as_bytes()).map_err(map)?;
        if !self.writer.inode(ino).map_err(map)?.is_dir() {
            return Err(FsError::NotADirectory);
        }
        Ok(ino)
    }
}

fn map(e: Error) -> FsError {
    match e {
        Error::NotFound => FsError::NotFound,
        Error::Exists => FsError::AlreadyExists,
        Error::NotEmpty => FsError::NotEmpty,
        Error::NotADirectory => FsError::NotADirectory,
        Error::IsADirectory => FsError::IsADirectory,
        Error::NoSpace => FsError::NoSpace,
        Error::ReadOnly => FsError::ReadOnly,
        Error::InvalidName | Error::Loop | Error::TooBig => FsError::Invalid,
        _ => FsError::Io,
    }
}

impl<D: BlockDevMut> Fs for PkgFs<D> {
    fn read(&mut self, path: &str) -> Result<Vec<u8>, FsError> {
        let ino = self.writer.resolve(path.as_bytes()).map_err(map)?;
        let i = self.writer.inode(ino).map_err(map)?;
        if i.is_dir() {
            return Err(FsError::IsADirectory);
        }
        self.writer.read(ino, 0, i.size as usize).map_err(map)
    }

    fn create(&mut self, path: &str, data: &[u8]) -> Result<(), FsError> {
        let (dir, name) = Self::split(path)?;
        let d = self.dir(dir)?;
        let (ino, _) = self.writer.create(d, name.as_bytes(), S_IFREG | 0o644, 0, 0, 0).map_err(map)?;
        self.writer.write(ino, 0, data).map_err(map)?;
        // Durable when it returns.
        self.writer.commit().map_err(map)
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        let (fd, fname) = Self::split(from)?;
        let (td, tname) = Self::split(to)?;
        let (a, b) = (self.dir(fd)?, self.dir(td)?);
        self.writer.rename(a, fname.as_bytes(), b, tname.as_bytes(), true).map_err(map)
    }

    fn replace(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        let (fd, fname) = Self::split(from)?;
        let (td, tname) = Self::split(to)?;
        let (a, b) = (self.dir(fd)?, self.dir(td)?);
        if let Some((_, t)) = self.writer.lookup(b, tname.as_bytes()).map_err(map)? {
            if t == DT_DIR {
                return Err(FsError::IsADirectory);
            }
        }
        self.writer.rename(a, fname.as_bytes(), b, tname.as_bytes(), false).map_err(map)
    }

    fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        let (dir, name) = Self::split(path)?;
        let d = self.dir(dir)?;
        self.writer.unlink(d, name.as_bytes()).map_err(map)
    }

    fn create_dir(&mut self, path: &str) -> Result<(), FsError> {
        let (dir, name) = Self::split(path)?;
        let d = self.dir(dir)?;
        self.writer.mkdir(d, name.as_bytes(), 0o755, 0, 0).map_err(map).map(|_| ())
    }

    fn remove_dir(&mut self, path: &str) -> Result<(), FsError> {
        let (dir, name) = Self::split(path)?;
        let d = self.dir(dir)?;
        self.writer.rmdir(d, name.as_bytes()).map_err(map)
    }

    fn stat(&mut self, path: &str) -> Result<Option<Stat>, FsError> {
        match self.writer.resolve(path.as_bytes()) {
            Ok(ino) => {
                let i = self.writer.inode(ino).map_err(map)?;
                let kind = if i.is_dir() { NodeKind::Dir } else { NodeKind::File };
                Ok(Some(Stat { kind, size: i.size }))
            }
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(map(e)),
        }
    }

    fn list(&mut self, path: &str) -> Result<Vec<String>, FsError> {
        let d = self.dir(path)?;
        let mut out = Vec::new();
        let mut cookie = 0;
        loop {
            let page = self.writer.read_dir(d, cookie, 256).map_err(map)?;
            if page.is_empty() {
                break;
            }
            for e in page {
                cookie = e.cookie;
                out.push(String::from_utf8(e.name).map_err(|_| FsError::Invalid)?);
            }
        }
        Ok(out)
    }

    fn sync(&mut self) -> Result<(), FsError> {
        self.writer.commit().map_err(map)
    }
}
