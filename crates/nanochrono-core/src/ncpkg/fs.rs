// SPDX-License-Identifier: Apache-2.0
//! The filesystem the package manager installs into.
//!
//! On NanoChronometer that is NCFS; on a host it is a directory standing
//! for the system's root (`ncpkg --root /mnt/ncfs`, an NCFS volume mounted
//! through FUSE, or the staging tree an ISO's root image is built from); in
//! the tests it is memory that can be told to fail at any step.
//!
//! The manager's crash safety rests on four promises every implementation
//! keeps:
//!
//! 1. [`Fs::create`] is durable when it returns: the bytes, and the entry
//!    naming them.
//! 2. [`Fs::rename`] and [`Fs::replace`] are atomic: after a crash, the
//!    name points at the old file or the new one, never at neither or at a
//!    torn one. (`replace` may overwrite; `rename` never does.)
//! 3. Operations take effect in the order they are made, and [`Fs::sync`]
//!    is a barrier: everything before it is durable.
//! 4. Paths are absolute, built from [`super::path`]'s alphabet; an
//!    implementation refuses anything else rather than resolve it.

use super::path;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    AlreadyExists,
    NotEmpty,
    NotADirectory,
    IsADirectory,
    NoSpace,
    ReadOnly,
    Denied,
    /// A path outside the installer's alphabet, or one crossing a link.
    Invalid,
    /// Any other I/O failure.
    Io,
}

impl FsError {
    pub const fn message(self) -> &'static str {
        match self {
            FsError::NotFound => "no such file or directory",
            FsError::AlreadyExists => "already exists",
            FsError::NotEmpty => "directory not empty",
            FsError::NotADirectory => "not a directory",
            FsError::IsADirectory => "is a directory",
            FsError::NoSpace => "no space left on the volume",
            FsError::ReadOnly => "read-only filesystem",
            FsError::Denied => "permission denied",
            FsError::Invalid => "invalid path",
            FsError::Io => "input/output error",
        }
    }
}

impl core::fmt::Display for FsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub kind: NodeKind,
    pub size: u64,
}

/// The operations the manager needs. See the module docs for the promises.
pub trait Fs {
    fn read(&mut self, path: &str) -> Result<Vec<u8>, FsError>;
    /// Creates a new file holding `data`; [`FsError::AlreadyExists`] if the
    /// path exists. Durable when it returns.
    fn create(&mut self, path: &str, data: &[u8]) -> Result<(), FsError>;
    /// Moves `from` to `to`, which must not exist. Atomic.
    fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError>;
    /// Moves `from` over `to`, replacing it if it exists. Atomic.
    fn replace(&mut self, from: &str, to: &str) -> Result<(), FsError>;
    fn remove_file(&mut self, path: &str) -> Result<(), FsError>;
    /// One directory; its parent must exist.
    fn create_dir(&mut self, path: &str) -> Result<(), FsError>;
    /// An empty directory.
    fn remove_dir(&mut self, path: &str) -> Result<(), FsError>;
    /// `None` if nothing is there.
    fn stat(&mut self, path: &str) -> Result<Option<Stat>, FsError>;
    /// The names in a directory.
    fn list(&mut self, path: &str) -> Result<Vec<String>, FsError>;
    /// Everything before it is durable.
    fn sync(&mut self) -> Result<(), FsError>;
}

/// The parent of an absolute path (`/a/b` → `/a`; `/a` → `/`).
pub fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

/// `dir` and `name` joined.
pub fn join(dir: &str, name: &str) -> String {
    let mut s = String::from(dir.trim_end_matches('/'));
    s.push('/');
    s.push_str(name);
    s
}

pub fn exists(fs: &mut dyn Fs, path: &str) -> Result<bool, FsError> {
    Ok(fs.stat(path)?.is_some())
}

/// Creates `path` and any missing ancestors; returns the directories it
/// created, parents first.
pub fn create_dir_all(fs: &mut dyn Fs, path: &str) -> Result<Vec<String>, FsError> {
    let mut missing = Vec::new();
    let mut p = path;
    while p != "/" {
        match fs.stat(p)? {
            Some(s) if s.kind == NodeKind::Dir => break,
            Some(_) => return Err(FsError::NotADirectory),
            None => missing.push(p.to_string()),
        }
        p = parent(p);
    }
    missing.reverse();
    for d in &missing {
        fs.create_dir(d)?;
    }
    Ok(missing)
}

/// Removes `path` and everything under it; nothing there is not an error.
pub fn remove_tree(fs: &mut dyn Fs, path: &str) -> Result<(), FsError> {
    match fs.stat(path)? {
        None => Ok(()),
        Some(s) if s.kind == NodeKind::File => fs.remove_file(path),
        Some(_) => {
            for name in fs.list(path)? {
                remove_tree(fs, &join(path, &name))?;
            }
            fs.remove_dir(path)
        }
    }
}

/// Writes `data` to `path` atomically, replacing what was there: a
/// temporary file beside it, then [`Fs::replace`].
pub fn write_atomic(fs: &mut dyn Fs, path: &str, data: &[u8]) -> Result<(), FsError> {
    let tmp = {
        let mut t = String::from(path);
        t.push_str(".tmp");
        t
    };
    match fs.remove_file(&tmp) {
        Ok(()) | Err(FsError::NotFound) => {}
        Err(e) => return Err(e),
    }
    fs.create(&tmp, data)?;
    fs.replace(&tmp, path)
}

// ---------------------------------------------------------------------------
// Memory, for the tests (and a RAM root)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    File(Vec<u8>),
    Dir,
}

/// A filesystem in memory. Each mutating operation is atomic and durable
/// the moment it returns — the model of a crash between two operations —
/// and [`MemFs::crash_after`] makes the `n`-th mutation fail and every
/// later one too, as a power cut would; a `create` cut short leaves half
/// its bytes behind, as a torn write would.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemFs {
    nodes: BTreeMap<String, Node>,
    /// Mutations allowed before the crash; `None` never crashes.
    budget: Option<usize>,
    crashed: bool,
    /// Mutations made so far.
    pub mutations: usize,
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFs {
    pub fn new() -> MemFs {
        let mut nodes = BTreeMap::new();
        nodes.insert(String::from("/"), Node::Dir);
        MemFs { nodes, budget: None, crashed: false, mutations: 0 }
    }

    /// The next `n` mutations succeed; the one after fails, and so does
    /// everything after it.
    pub fn crash_after(&mut self, n: usize) {
        self.budget = Some(n);
        self.crashed = false;
    }

    /// Power back on: everything durable is still there.
    pub fn reboot(&mut self) {
        self.budget = None;
        self.crashed = false;
    }

    pub fn crashed(&self) -> bool {
        self.crashed
    }

    /// Every path and, for files, its contents: for comparing whole trees.
    pub fn snapshot(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        self.nodes
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    match v {
                        Node::File(d) => Some(d.clone()),
                        Node::Dir => None,
                    },
                )
            })
            .collect()
    }

    fn check(path: &str) -> Result<(), FsError> {
        if path == "/" || path::is_system_path(path) {
            Ok(())
        } else {
            Err(FsError::Invalid)
        }
    }

    /// Spends one mutation; `Err` once the budget is gone.
    fn mutate(&mut self) -> Result<(), FsError> {
        if self.crashed {
            return Err(FsError::Io);
        }
        if let Some(b) = self.budget {
            if b == 0 {
                self.crashed = true;
                return Err(FsError::Io);
            }
            self.budget = Some(b - 1);
        }
        self.mutations += 1;
        Ok(())
    }

    fn parent_is_dir(&self, path: &str) -> Result<(), FsError> {
        match self.nodes.get(parent(path)) {
            Some(Node::Dir) => Ok(()),
            Some(Node::File(_)) => Err(FsError::NotADirectory),
            None => Err(FsError::NotFound),
        }
    }

    fn has_children(&self, path: &str) -> bool {
        let prefix = join(path, "");
        self.nodes.range(prefix.clone()..).next().is_some_and(|(k, _)| k.starts_with(&prefix))
    }
}

impl Fs for MemFs {
    fn read(&mut self, path: &str) -> Result<Vec<u8>, FsError> {
        Self::check(path)?;
        match self.nodes.get(path) {
            Some(Node::File(d)) => Ok(d.clone()),
            Some(Node::Dir) => Err(FsError::IsADirectory),
            None => Err(FsError::NotFound),
        }
    }

    fn create(&mut self, path: &str, data: &[u8]) -> Result<(), FsError> {
        Self::check(path)?;
        self.parent_is_dir(path)?;
        if self.nodes.contains_key(path) {
            return Err(FsError::AlreadyExists);
        }
        if let Err(e) = self.mutate() {
            // A torn write: the entry exists with part of the data.
            if self.crashed && self.budget == Some(0) && !data.is_empty() {
                self.nodes.insert(String::from(path), Node::File(data[..data.len() / 2].to_vec()));
                self.budget = None;
            }
            return Err(e);
        }
        self.nodes.insert(String::from(path), Node::File(data.to_vec()));
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        Self::check(from)?;
        Self::check(to)?;
        if self.nodes.contains_key(to) {
            return Err(FsError::AlreadyExists);
        }
        self.replace(from, to)
    }

    fn replace(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        Self::check(from)?;
        Self::check(to)?;
        self.parent_is_dir(to)?;
        match (self.nodes.get(from), self.nodes.get(to)) {
            (None, _) => return Err(FsError::NotFound),
            (Some(Node::Dir), _) => return Err(FsError::IsADirectory),
            (_, Some(Node::Dir)) => return Err(FsError::IsADirectory),
            _ => {}
        }
        self.mutate()?;
        let node = self.nodes.remove(from).ok_or(FsError::NotFound)?;
        self.nodes.insert(String::from(to), node);
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        Self::check(path)?;
        match self.nodes.get(path) {
            Some(Node::File(_)) => {}
            Some(Node::Dir) => return Err(FsError::IsADirectory),
            None => return Err(FsError::NotFound),
        }
        self.mutate()?;
        self.nodes.remove(path);
        Ok(())
    }

    fn create_dir(&mut self, path: &str) -> Result<(), FsError> {
        Self::check(path)?;
        self.parent_is_dir(path)?;
        if self.nodes.contains_key(path) {
            return Err(FsError::AlreadyExists);
        }
        self.mutate()?;
        self.nodes.insert(String::from(path), Node::Dir);
        Ok(())
    }

    fn remove_dir(&mut self, path: &str) -> Result<(), FsError> {
        Self::check(path)?;
        match self.nodes.get(path) {
            Some(Node::Dir) => {}
            Some(Node::File(_)) => return Err(FsError::NotADirectory),
            None => return Err(FsError::NotFound),
        }
        if path == "/" || self.has_children(path) {
            return Err(FsError::NotEmpty);
        }
        self.mutate()?;
        self.nodes.remove(path);
        Ok(())
    }

    fn stat(&mut self, path: &str) -> Result<Option<Stat>, FsError> {
        Self::check(path)?;
        Ok(self.nodes.get(path).map(|n| match n {
            Node::File(d) => Stat { kind: NodeKind::File, size: d.len() as u64 },
            Node::Dir => Stat { kind: NodeKind::Dir, size: 0 },
        }))
    }

    fn list(&mut self, path: &str) -> Result<Vec<String>, FsError> {
        Self::check(path)?;
        match self.nodes.get(path) {
            Some(Node::Dir) => {}
            Some(Node::File(_)) => return Err(FsError::NotADirectory),
            None => return Err(FsError::NotFound),
        }
        let prefix = join(path, "");
        Ok(self
            .nodes
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .filter_map(|(k, _)| {
                let rest = &k[prefix.len()..];
                (!rest.is_empty() && !rest.contains('/')).then(|| rest.to_string())
            })
            .collect())
    }

    fn sync(&mut self) -> Result<(), FsError> {
        if self.crashed {
            return Err(FsError::Io);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// A directory on a host
// ---------------------------------------------------------------------------

/// A host directory standing for the system's root. Every path is checked
/// against the installer's alphabet and walked component by component,
/// refusing symbolic links, so nothing resolves outside the root. Each
/// operation is made durable before it returns (the file and its
/// directory are synced on Unix), which is slower than batching and is the
/// promise the manager's recovery relies on.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct StdFs {
    root: std::path::PathBuf,
}

#[cfg(feature = "std")]
impl StdFs {
    pub fn new(root: impl Into<std::path::PathBuf>) -> StdFs {
        StdFs { root: root.into() }
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    fn map_err(e: std::io::Error) -> FsError {
        use std::io::ErrorKind as K;
        match e.kind() {
            K::NotFound => FsError::NotFound,
            K::AlreadyExists => FsError::AlreadyExists,
            K::PermissionDenied => FsError::Denied,
            K::DirectoryNotEmpty => FsError::NotEmpty,
            K::NotADirectory => FsError::NotADirectory,
            K::IsADirectory => FsError::IsADirectory,
            K::StorageFull => FsError::NoSpace,
            K::ReadOnlyFilesystem => FsError::ReadOnly,
            _ => FsError::Io,
        }
    }

    /// The host path for `path`, after checking no existing component is a
    /// symbolic link.
    fn host(&self, path: &str) -> Result<std::path::PathBuf, FsError> {
        if path != "/" && !path::is_system_path(path) {
            return Err(FsError::Invalid);
        }
        let mut p = self.root.clone();
        for c in path.split('/').filter(|c| !c.is_empty()) {
            p.push(c);
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_symlink() => return Err(FsError::Invalid),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Self::map_err(e)),
            }
        }
        Ok(p)
    }

    fn sync_dir(dir: &std::path::Path) -> Result<(), FsError> {
        #[cfg(unix)]
        {
            std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(Self::map_err)?;
        }
        #[cfg(not(unix))]
        let _ = dir;
        Ok(())
    }

    fn sync_parent(p: &std::path::Path) -> Result<(), FsError> {
        match p.parent() {
            Some(d) => Self::sync_dir(d),
            None => Ok(()),
        }
    }
}

#[cfg(feature = "std")]
impl Fs for StdFs {
    fn read(&mut self, path: &str) -> Result<Vec<u8>, FsError> {
        std::fs::read(self.host(path)?).map_err(Self::map_err)
    }

    fn create(&mut self, path: &str, data: &[u8]) -> Result<(), FsError> {
        use std::io::Write;
        let p = self.host(path)?;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&p).map_err(Self::map_err)?;
        f.write_all(data).map_err(Self::map_err)?;
        f.sync_all().map_err(Self::map_err)?;
        Self::sync_parent(&p)
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        let (f, t) = (self.host(from)?, self.host(to)?);
        if std::fs::symlink_metadata(&t).is_ok() {
            return Err(FsError::AlreadyExists);
        }
        std::fs::rename(&f, &t).map_err(Self::map_err)?;
        Self::sync_parent(&t)?;
        Self::sync_parent(&f)
    }

    fn replace(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        let (f, t) = (self.host(from)?, self.host(to)?);
        if std::fs::symlink_metadata(&t).is_ok_and(|m| m.is_dir()) {
            return Err(FsError::IsADirectory);
        }
        std::fs::rename(&f, &t).map_err(Self::map_err)?;
        Self::sync_parent(&t)?;
        Self::sync_parent(&f)
    }

    fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        let p = self.host(path)?;
        std::fs::remove_file(&p).map_err(Self::map_err)?;
        Self::sync_parent(&p)
    }

    fn create_dir(&mut self, path: &str) -> Result<(), FsError> {
        let p = self.host(path)?;
        std::fs::create_dir(&p).map_err(Self::map_err)?;
        Self::sync_parent(&p)
    }

    fn remove_dir(&mut self, path: &str) -> Result<(), FsError> {
        let p = self.host(path)?;
        std::fs::remove_dir(&p).map_err(Self::map_err)?;
        Self::sync_parent(&p)
    }

    fn stat(&mut self, path: &str) -> Result<Option<Stat>, FsError> {
        match std::fs::symlink_metadata(self.host(path)?) {
            Ok(m) if m.is_dir() => Ok(Some(Stat { kind: NodeKind::Dir, size: 0 })),
            Ok(m) if m.is_file() => Ok(Some(Stat { kind: NodeKind::File, size: m.len() })),
            Ok(_) => Err(FsError::Invalid),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    fn list(&mut self, path: &str) -> Result<Vec<String>, FsError> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(self.host(path)?).map_err(Self::map_err)? {
            let e = e.map_err(Self::map_err)?;
            out.push(e.file_name().to_string_lossy().into_owned());
        }
        out.sort();
        Ok(out)
    }

    fn sync(&mut self) -> Result<(), FsError> {
        // Every operation above is already durable.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memfs_behaves_like_a_filesystem() {
        let mut fs = MemFs::new();
        assert_eq!(create_dir_all(&mut fs, "/a/b/c").unwrap(), ["/a", "/a/b", "/a/b/c"]);
        assert!(create_dir_all(&mut fs, "/a/b").unwrap().is_empty());
        fs.create("/a/b/f", b"one").unwrap();
        assert_eq!(fs.create("/a/b/f", b"two"), Err(FsError::AlreadyExists));
        assert_eq!(fs.create("/x/y", b""), Err(FsError::NotFound));
        assert_eq!(fs.create("/a/../etc", b""), Err(FsError::Invalid));
        fs.create("/a/g", b"two").unwrap();
        assert_eq!(fs.rename("/a/g", "/a/b/f"), Err(FsError::AlreadyExists));
        fs.replace("/a/g", "/a/b/f").unwrap();
        assert_eq!(fs.read("/a/b/f").unwrap(), b"two");
        assert_eq!(fs.list("/a/b").unwrap(), ["c", "f"]);
        assert_eq!(fs.remove_dir("/a/b"), Err(FsError::NotEmpty));
        write_atomic(&mut fs, "/a/w", b"v1").unwrap();
        write_atomic(&mut fs, "/a/w", b"v2").unwrap();
        assert_eq!(fs.read("/a/w").unwrap(), b"v2");
        remove_tree(&mut fs, "/a").unwrap();
        assert_eq!(fs.list("/").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn memfs_crashes_on_cue() {
        let mut fs = MemFs::new();
        fs.crash_after(2);
        fs.create_dir("/a").unwrap();
        fs.create("/a/one", b"1").unwrap();
        assert_eq!(fs.create("/a/two", b"22"), Err(FsError::Io));
        assert!(fs.crashed());
        assert_eq!(fs.create_dir("/b"), Err(FsError::Io));
        fs.reboot();
        // The torn write left half its bytes.
        assert_eq!(fs.read("/a/two").unwrap(), b"2");
        assert_eq!(fs.stat("/b").unwrap(), None);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stdfs_stays_inside_its_root() {
        let dir = std::env::temp_dir().join(std::format!("ncpkg-stdfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut fs = StdFs::new(&dir);
        create_dir_all(&mut fs, "/usr/lib").unwrap();
        fs.create("/usr/lib/a.ncdyn", b"lib").unwrap();
        assert_eq!(fs.stat("/usr/lib/a.ncdyn").unwrap(), Some(Stat { kind: NodeKind::File, size: 3 }));
        assert_eq!(fs.read("/usr/lib/a.ncdyn").unwrap(), b"lib");
        assert_eq!(fs.create("/usr/lib/a.ncdyn", b"x"), Err(FsError::AlreadyExists));
        assert_eq!(fs.read("/usr/../etc/passwd"), Err(FsError::Invalid));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc", dir.join("escape")).unwrap();
            assert_eq!(fs.read("/escape/passwd"), Err(FsError::Invalid));
        }
        fs.create("/usr/lib/b.tmp", b"new").unwrap();
        fs.replace("/usr/lib/b.tmp", "/usr/lib/a.ncdyn").unwrap();
        assert_eq!(fs.read("/usr/lib/a.ncdyn").unwrap(), b"new");
        assert_eq!(fs.list("/usr/lib").unwrap(), ["a.ncdyn"]);
        assert_eq!(fs.remove_dir("/usr/lib"), Err(FsError::NotEmpty));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
