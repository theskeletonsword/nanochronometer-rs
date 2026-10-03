// SPDX-License-Identifier: Apache-2.0
//! Installing and removing packages: what `sudo ncpkg install` and
//! `sudo ncpkg remove` do.
//!
//! # Install
//!
//! 1. **Lock** `/var/lib/ncpkg/lock`, and finish any transaction a crash
//!    interrupted (below).
//! 2. **Read** the package: the container ([`super::Package::parse`]), the
//!    manifest ([`Meta::parse`]), the two against each other.
//! 3. **Verify** the signatures ([`super::sig`]): one that is present and
//!    fails refuses the package; ring 0 needs a ring-0 signature (🌳 or
//!    🔵 ring 0) unless the owner turned on *Enable Ring0 Community Modules
//!    and Drivers*.
//! 4. **Check** the package fits: this machine's architecture, the kernel
//!    ABI, the system version; the id not a built-in app's; every file this
//!    machine installs decoded and matched against its SHA-512; every
//!    module's header saying the architecture and kind the manifest says,
//!    and asking for no capability the manifest does not declare.
//! 5. **Plan** in memory, against a copy of the database:
//!    * each library the package uses goes **global** (`/usr/lib`, its
//!      `ref_count` incremented) when the installed version satisfies the
//!      package or none is installed; the global copy is **upgraded** when
//!      the package ships a newer version every dependent accepts; a
//!      version the global copy cannot be reconciled with stays **private**
//!      in `/apps/<id>/lib` — or, for a `lib` package, whose whole point is
//!      the global copy, is a conflict;
//!    * no file may land on a path another package owns, a command on a
//!      name the shell or another package has, a plugin on a host that is
//!      not there;
//!    * an upgrade releases the old version's files and references first,
//!      in the same transaction.
//! 6. **Execute** the plan as one transaction (below).
//!
//! # Remove
//!
//! Lock and recover as above; refuse if another package's plugins extend
//! this one; move the package's files aside; decrement the `ref_count` of
//! each global library it used, and move aside the libraries that reach
//! zero — **only** those; then commit. Directories left empty go.
//!
//! # One transaction, whatever happens
//!
//! ```text
//! stage files ─► journal ─► db.json.new ─► steps ─► COMMIT ─► clean up
//!   (tx dir)     (atomic)     (durable)   (renames)  db.json.new → db.json
//! ```
//!
//! Nothing outside the transaction's own directory changes before the
//! journal is on disk. Each step is one atomic rename or `mkdir`. The
//! commit is one atomic replace of `db.json`, whose `last_tx` then names
//! this transaction. After a crash, recovery reads the journal and asks the
//! database: `last_tx` is this transaction → it committed, finish the
//! clean-up; it is not → undo the steps, newest first (a placed file back
//! to the stage, a backed-up file back where it was), and the system is
//! byte for byte what it was. Removed files are moved aside, not deleted,
//! until the commit — so a removal is as undoable as an install. The tests
//! cut the power at every single filesystem operation of an install, an
//! upgrade and a removal, and check exactly that.

use super::db::{self, Db, FileRec, LibUse, Library, LoadError, PluginRec, Resolved};
use super::fs::{self, Fs, FsError};
use super::journal::{self, Journal, Step};
use super::meta::{self, Meta, PkgType};
use super::sig::{self, Badge, Scratch, Trust, Verifier};
use super::version::{Req, Version};
use super::{FormatError, Package};
use crate::ncplu::{self, Arch, Kind as ModuleKind};
use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;

/// The lock: created exclusively for the length of an operation, holding
/// who took it.
pub const LOCK: &str = "/var/lib/ncpkg/lock";
/// Directories the installer never removes, even empty.
const KEEP: [&str; 13] = [
    "/", "/apps", "/usr", "/usr/bin", "/usr/lib", "/usr/lib/ncplu", "/var", "/var/cache", "/var/cache/ncpkg", "/var/cache/ncpkg/icons",
    "/var/lib", "/var/lib/ncpkg", "/var/lib/ncpkg/meta",
];

/// The system the manager installs for, and the owner's choices.
#[derive(Debug, Clone)]
pub struct Policy {
    /// This machine.
    pub arch: Arch,
    /// The running system's version (SemVer).
    pub system_version: String,
    /// The kernel export-table ABI ([`ncplu::ABI_VERSION`]).
    pub abi: u32,
    /// *Enable Ring0 Community Modules and Drivers*: off by default.
    pub community_ring0: bool,
    /// Refuse unsigned packages altogether (off: an unsigned ring-3 package
    /// installs as community code).
    pub require_signature: bool,
    /// The built-in apps' ids: reserved, and valid plugin hosts.
    pub builtin_apps: Vec<String>,
    /// Command names the shell owns.
    pub reserved_commands: Vec<String>,
    /// Unix seconds, for `installed_at`; 0 without a clock.
    pub now: u64,
    /// Per-operation randomness for transaction ids.
    pub nonce: u64,
    /// Who holds the lock (`pid 4242 on host`, `kernel, boot 7`).
    pub owner: String,
}

impl Policy {
    /// The built-in apps of NanoChronometer: never installed, never removed
    /// (the stopwatch is essential), and the hosts plugins extend.
    pub const BUILTIN_APPS: [&'static str; 9] = [
        "nc.stopwatch",
        "nc.terminal",
        "nc.tasks",
        "nc.settings",
        "nc.files",
        "nc.gallery",
        "nc.player",
        "nc.bench",
        "nc.packages",
    ];

    /// A policy for `arch` with the defaults: the built-in apps and the
    /// shell's commands reserved, signatures not required, the community
    /// switch off.
    pub fn new(arch: Arch, system_version: &str) -> Policy {
        Policy {
            arch,
            system_version: String::from(system_version),
            abi: ncplu::ABI_VERSION,
            community_ring0: false,
            require_signature: false,
            builtin_apps: Self::BUILTIN_APPS.iter().map(|s| String::from(*s)).collect(),
            reserved_commands: super::RESERVED_COMMANDS.iter().map(|s| String::from(*s)).collect(),
            now: 0,
            nonce: 0,
            owner: String::from("ncpkg"),
        }
    }
}

/// Install options.
#[derive(Debug, Clone, Copy, Default)]
pub struct InstallOptions {
    /// Install the same version again.
    pub reinstall: bool,
    /// Install an older version over a newer one.
    pub allow_downgrade: bool,
    /// Overwrite files that no package owns.
    pub force: bool,
}

/// Why an operation did not happen. Nothing changed, unless a crash left a
/// journal behind — then the next operation, or `ncpkg recover`, puts the
/// system back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Another operation holds the lock (or a crashed one left it).
    Locked(String),
    Fs(FsError, String),
    Format(FormatError),
    Meta(meta::Error),
    Db(db::DbError),
    Journal(String),
    WrongArch { arch: String, supported: Vec<String> },
    AbiMismatch { package: u32, system: u32 },
    SystemTooOld { requires: String, system: String },
    /// A signature present that does not verify.
    Tampered(Vec<String>),
    /// Signatures are required and the package has none that verifies.
    Unsigned,
    /// Ring 0 without a ring-0 signature or the community switch.
    Ring0NotAllowed,
    /// A file whose SHA-512 is not the manifest's.
    FileHash(String),
    /// A module whose header disagrees with the manifest.
    Module { path: String, reason: String },
    /// `icon.png` breaks the icon rules (super::icon).
    Icon(super::icon::IconError),
    AlreadyInstalled { id: String, version: String },
    Downgrade { id: String, installed: String, offered: String },
    NotInstalled(String),
    /// The id of a built-in app.
    Reserved(String),
    HostMissing { plugin: String, host: String },
    /// Installed packages extend this one with plugins.
    HasDependents { id: String, dependents: Vec<String> },
    MissingLibrary { name: String, requirement: String, installed: Option<String> },
    /// A `lib` package's library cannot replace the global copy without
    /// breaking the packages that use it.
    LibraryConflict { name: String, installed: String, offered: String, required_by: Vec<String> },
    FileConflict { path: String, owner: Option<String> },
    CommandConflict { command: String, owner: Option<String> },
    /// The plan broke a database invariant: a bug, refused rather than
    /// committed.
    Internal(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let list = |v: &[String]| v.join(", ");
        match self {
            Error::Locked(owner) => write!(f, "another ncpkg holds the lock ({owner}); if none runs, `ncpkg recover --force-unlock`"),
            Error::Fs(e, path) => write!(f, "{path}: {e}"),
            Error::Format(e) => write!(f, "not a valid package: {e}"),
            Error::Meta(e) => write!(f, "bad manifest: {e}"),
            Error::Db(e) => write!(f, "{e}"),
            Error::Journal(e) => write!(f, "{e}"),
            Error::WrongArch { arch, supported } => write!(f, "built for {}, not for this {arch} machine", list(supported)),
            Error::AbiMismatch { package, system } => write!(f, "built against kernel ABI {package}, this system has {system}"),
            Error::SystemTooOld { requires, system } => write!(f, "needs NanoChronometer {requires}, this is {system}"),
            Error::Tampered(roles) => write!(f, "signature present but invalid ({}): changed after signing", list(roles)),
            Error::Unsigned => write!(f, "unsigned, and this system requires signatures"),
            Error::Ring0NotAllowed => write!(
                f,
                "asks for ring 0 without a ring-0 signature (tree root or ring-0 blue check); \
                 allowed only with Settings > Security > Enable Ring0 Community Modules and Drivers"
            ),
            Error::FileHash(p) => write!(f, "{p}: SHA-512 does not match the manifest"),
            Error::Module { path, reason } => write!(f, "{path}: {reason}"),
            Error::Icon(e) => write!(f, "icon.png: {e}"),
            Error::AlreadyInstalled { id, version } => write!(f, "{id} {version} is already installed (--reinstall to install it again)"),
            Error::Downgrade { id, installed, offered } => write!(f, "{id} {installed} is installed; {offered} is older (--allow-downgrade)"),
            Error::NotInstalled(id) => write!(f, "{id} is not installed"),
            Error::Reserved(id) => write!(f, "{id} is a built-in app's id"),
            Error::HostMissing { plugin, host } => write!(f, "plugin {plugin} extends {host}, which is not installed"),
            Error::HasDependents { id, dependents } => write!(f, "{id} is extended by plugins of {}: remove those first", list(dependents)),
            Error::MissingLibrary { name, requirement, installed } => match installed {
                Some(v) => write!(f, "needs {name} {requirement}; {v} is installed and the package carries no copy"),
                None => write!(f, "needs {name} {requirement}, which is not installed and not in the package"),
            },
            Error::LibraryConflict { name, installed, offered, required_by } => write!(
                f,
                "{name} {offered} cannot replace the installed {installed}: {} need a version it is not",
                list(required_by)
            ),
            Error::FileConflict { path, owner: Some(o) } => write!(f, "{path} belongs to {o}"),
            Error::FileConflict { path, owner: None } => write!(f, "{path} exists and belongs to no package (--force overwrites it)"),
            Error::CommandConflict { command, owner: Some(o) } => write!(f, "command {command} belongs to {o}"),
            Error::CommandConflict { command, owner: None } => write!(f, "command {command} is a shell built-in"),
            Error::Internal(e) => write!(f, "internal error, nothing was changed: {e}"),
        }
    }
}

fn fs_err(e: FsError, path: &str) -> Error {
    Error::Fs(e, String::from(path))
}

/// What a plan does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Install,
    Upgrade,
    Downgrade,
    Reinstall,
    Remove,
}

impl Op {
    pub const fn name(self) -> &'static str {
        match self {
            Op::Install => "install",
            Op::Upgrade => "upgrade",
            Op::Downgrade => "downgrade",
            Op::Reinstall => "reinstall",
            Op::Remove => "remove",
        }
    }
}

/// What happens to one library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibChange {
    /// Installed in `/usr/lib` for the first time.
    NewGlobal,
    /// The global copy, shared.
    Share,
    /// The global copy replaced by this package's newer one.
    UpgradeGlobal { from: String },
    /// This package's own copy, beside the global one it cannot use.
    Private { global: Option<String> },
    /// One reference fewer; the copy stays for the others.
    Release,
    /// No references left: deleted from `/usr/lib`.
    Delete,
}

/// A library's fate in a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibPlan {
    pub name: String,
    pub change: LibChange,
    /// The version in use afterwards (or deleted).
    pub version: String,
    /// `ref_count` afterwards (0 for a private copy or a deletion).
    pub refs: u64,
}

/// Everything an operation will do, computed before anything changes, for
/// the confirmation prompt and then for [`Manager::execute`].
#[derive(Debug, Clone)]
pub struct Plan {
    pub op: Op,
    pub id: String,
    pub name: String,
    pub version: String,
    pub previous: Option<String>,
    pub kind: PkgType,
    pub badge: Badge,
    pub ring: u8,
    pub libraries: Vec<LibPlan>,
    pub warnings: Vec<String>,
    /// Files written, and their bytes.
    pub files: usize,
    pub bytes: u64,
    /// Files moved aside (replaced or removed).
    pub removed: usize,
    places: Vec<(String, Vec<u8>)>,
    backups: Vec<String>,
    mkdirs: Vec<String>,
    cleanup: Vec<String>,
    db: Db,
}

/// What an operation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Done {
        op: Op,
        id: String,
        version: String,
        tx: String,
        /// The commit happened but the clean-up did not finish; the next
        /// operation (or `ncpkg recover`) finishes it.
        cleanup_pending: bool,
    },
    /// The confirmation said no; nothing changed.
    Cancelled,
}

/// What recovery found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// No interrupted transaction.
    Clean,
    /// It had committed: its clean-up is finished.
    Finished { tx: String, op: String, package: String },
    /// It had not: every step it took is undone.
    Undone { tx: String, op: String, package: String },
}

/// A problem `ncpkg check` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub path: String,
    pub what: String,
}

/// The package manager over one filesystem.
pub struct Manager<'f> {
    fs: &'f mut dyn Fs,
    policy: Policy,
}

impl core::fmt::Debug for Manager<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Manager").field("policy", &self.policy).finish_non_exhaustive()
    }
}

fn hex(d: &[u8; 64]) -> String {
    let mut out = [0u8; 128];
    crate::sha512::to_hex(d, &mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// Ancestors of `path` the installer may remove once empty, deepest first.
fn removable_ancestors(path: &str, out: &mut BTreeSet<String>) {
    let mut p = fs::parent(path);
    while !KEEP.contains(&p) {
        out.insert(String::from(p));
        p = fs::parent(p);
    }
}

fn depth(p: &str) -> usize {
    p.bytes().filter(|&b| b == b'/').count()
}

impl<'f> Manager<'f> {
    pub fn new(fs: &'f mut dyn Fs, policy: Policy) -> Manager<'f> {
        Manager { fs, policy }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn policy_mut(&mut self) -> &mut Policy {
        &mut self.policy
    }

    // -- locking and recovery -------------------------------------------------

    fn lock(&mut self) -> Result<(), Error> {
        fs::create_dir_all(self.fs, db::DIR).map_err(|e| fs_err(e, db::DIR))?;
        match self.fs.create(LOCK, self.policy.owner.as_bytes()) {
            Ok(()) => Ok(()),
            Err(FsError::AlreadyExists) => {
                let owner = self.fs.read(LOCK).unwrap_or_default();
                Err(Error::Locked(String::from_utf8_lossy(&owner).into_owned()))
            }
            Err(e) => Err(fs_err(e, LOCK)),
        }
    }

    fn unlock(&mut self) {
        let _ = self.fs.remove_file(LOCK);
    }

    /// Runs `body` under the lock, after finishing any transaction a crash
    /// interrupted.
    fn locked<T>(&mut self, body: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        self.lock()?;
        let result = self.recover_locked().and_then(|_| body(self));
        self.unlock();
        result
    }

    /// Finishes or undoes an interrupted transaction. `force_unlock` first
    /// removes a lock a crashed operation left — only when no other ncpkg
    /// is running.
    pub fn recover(&mut self, force_unlock: bool) -> Result<Recovery, Error> {
        if force_unlock {
            match self.fs.remove_file(LOCK) {
                Ok(()) | Err(FsError::NotFound) => {}
                Err(e) => return Err(fs_err(e, LOCK)),
            }
        }
        self.lock()?;
        let result = self.recover_locked();
        self.unlock();
        result
    }

    fn remove_if_exists(&mut self, path: &str) -> Result<(), Error> {
        match self.fs.remove_file(path) {
            Ok(()) | Err(FsError::NotFound) => Ok(()),
            Err(e) => Err(fs_err(e, path)),
        }
    }

    fn exists(&mut self, path: &str) -> Result<bool, Error> {
        fs::exists(self.fs, path).map_err(|e| fs_err(e, path))
    }

    fn recover_locked(&mut self) -> Result<Recovery, Error> {
        let tmp = format!("{}.tmp", journal::PATH);
        let bytes = match self.fs.read(journal::PATH) {
            Ok(b) => Some(b),
            Err(FsError::NotFound) => None,
            Err(e) => return Err(fs_err(e, journal::PATH)),
        };
        // A journal that was being written when the power went: nothing
        // outside the transaction directory was touched yet.
        self.remove_if_exists(&tmp)?;
        let Some(bytes) = bytes else {
            self.remove_if_exists(db::NEXT)?;
            fs::remove_tree(self.fs, journal::TX_DIR).map_err(|e| fs_err(e, journal::TX_DIR))?;
            return Ok(Recovery::Clean);
        };
        let j = Journal::parse(&bytes).map_err(Error::Journal)?;
        // A commit on a filesystem whose replace is not atomic, cut between
        // removing the old database and naming the new one.
        if !self.exists(db::PATH)? && self.exists(db::NEXT)? {
            self.fs.replace(db::NEXT, db::PATH).map_err(|e| fs_err(e, db::PATH))?;
        }
        let current = self.load_db_raw()?;
        if current.last_tx == j.tx {
            self.finish(&j)?;
            Ok(Recovery::Finished { tx: j.tx, op: j.op, package: j.package })
        } else {
            self.undo(&j)?;
            Ok(Recovery::Undone { tx: j.tx, op: j.op, package: j.package })
        }
    }

    /// Undoes `j`'s steps, newest first. Each undo checks the step was done
    /// and is not undone already, so a crash during recovery is recovered
    /// from the same way.
    fn undo(&mut self, j: &Journal) -> Result<(), Error> {
        for step in j.steps.iter().rev() {
            match step {
                // A placed file went stage → destination, a backed-up one
                // original → backups: either way, `to` goes back to `from`
                // — if it is there and `from` is free, which also makes a
                // second undo after a crash during the first do nothing.
                Step::Place { from, to } | Step::Backup { from, to } => {
                    if self.exists(to)? && !self.exists(from)? {
                        self.fs.rename(to, from).map_err(|e| fs_err(e, to))?;
                    }
                }
                Step::Mkdir(p) => match self.fs.remove_dir(p) {
                    Ok(()) | Err(FsError::NotFound) | Err(FsError::NotEmpty) => {}
                    Err(e) => return Err(fs_err(e, p)),
                },
            }
        }
        self.remove_if_exists(db::NEXT)?;
        self.remove_tx_dir(j)?;
        self.fs.sync().map_err(|e| fs_err(e, "/"))?;
        self.remove_if_exists(journal::PATH)?;
        self.fs.sync().map_err(|e| fs_err(e, "/"))
    }

    /// The transaction's directory, and the parent of all of them if that
    /// leaves it empty.
    fn remove_tx_dir(&mut self, j: &Journal) -> Result<(), Error> {
        let dir = j.tx_dir();
        fs::remove_tree(self.fs, &dir).map_err(|e| fs_err(e, &dir))?;
        match self.fs.remove_dir(journal::TX_DIR) {
            Ok(()) | Err(FsError::NotFound) | Err(FsError::NotEmpty) => Ok(()),
            Err(e) => Err(fs_err(e, journal::TX_DIR)),
        }
    }

    /// The clean-up after a commit: the backups and the stage go, then the
    /// directories left empty, then the journal.
    fn finish(&mut self, j: &Journal) -> Result<(), Error> {
        self.remove_tx_dir(j)?;
        for d in &j.cleanup {
            match self.fs.remove_dir(d) {
                Ok(()) | Err(FsError::NotFound) | Err(FsError::NotEmpty) => {}
                Err(e) => return Err(fs_err(e, d)),
            }
        }
        self.remove_if_exists(db::NEXT)?;
        self.fs.sync().map_err(|e| fs_err(e, "/"))?;
        self.remove_if_exists(journal::PATH)?;
        self.fs.sync().map_err(|e| fs_err(e, "/"))
    }

    fn load_db_raw(&mut self) -> Result<Db, Error> {
        Db::load(self.fs, self.policy.arch.name()).map_err(|e| match e {
            LoadError::Fs(e) => fs_err(e, db::PATH),
            LoadError::Db(e) => Error::Db(e),
        })
    }

    /// The database, read-only (no lock, no recovery): for `list` and
    /// `info`.
    pub fn load_db(&mut self) -> Result<Db, Error> {
        self.load_db_raw()
    }

    // -- install --------------------------------------------------------------

    /// Reads, verifies and plans an install without changing anything —
    /// what `ncpkg install` shows before it asks.
    pub fn plan_install(&mut self, bytes: &[u8], verifier: &mut dyn Verifier, opts: &InstallOptions) -> Result<Plan, Error> {
        let db = self.load_db_raw()?;
        self.plan_install_with(&db, bytes, verifier, opts)
    }

    fn plan_install_with(&mut self, db: &Db, bytes: &[u8], verifier: &mut dyn Verifier, opts: &InstallOptions) -> Result<Plan, Error> {
        let pkg = Package::parse(bytes).map_err(Error::Format)?;
        let meta = Meta::parse(pkg.meta()).map_err(Error::Meta)?;
        meta.check_container(&pkg).map_err(Error::Meta)?;
        let mut scratch = Box::new(Scratch::new());
        let trust = meta.verify(verifier, &mut scratch);
        Planner { m: self, pkg, meta, trust, opts: *opts }.plan(db)
    }

    /// Installs a package: plans, asks `confirm`, executes. See the module
    /// docs.
    pub fn install(
        &mut self,
        bytes: &[u8],
        verifier: &mut dyn Verifier,
        opts: &InstallOptions,
        confirm: &mut dyn FnMut(&Plan) -> bool,
    ) -> Result<Outcome, Error> {
        self.locked(|m| {
            let db = m.load_db_raw()?;
            let plan = m.plan_install_with(&db, bytes, verifier, opts)?;
            if !confirm(&plan) {
                return Ok(Outcome::Cancelled);
            }
            m.execute(plan)
        })
    }

    // -- remove ---------------------------------------------------------------

    pub fn plan_remove(&mut self, id: &str) -> Result<Plan, Error> {
        let db = self.load_db_raw()?;
        self.plan_remove_with(&db, id)
    }

    fn plan_remove_with(&mut self, db: &Db, id: &str) -> Result<Plan, Error> {
        let old = db.packages.get(id).ok_or_else(|| Error::NotInstalled(String::from(id)))?;
        let dependents: Vec<String> =
            db.packages.iter().filter(|(other, p)| *other != id && p.plugins.iter().any(|pl| pl.host == id)).map(|(o, _)| o.clone()).collect();
        if !dependents.is_empty() {
            return Err(Error::HasDependents { id: String::from(id), dependents });
        }
        let mut ndb = db.clone();
        ndb.packages.remove(id);
        let mut backups: Vec<String> = old.files.iter().map(|f| f.path.clone()).collect();
        let mut libraries = Vec::new();
        for u in old.libraries.iter().filter(|u| u.resolved == Resolved::Global) {
            let Some(lib) = ndb.libraries.get_mut(&u.name) else { continue };
            lib.required_by.retain(|r| r != id);
            lib.ref_count = lib.required_by.len() as u64;
            if lib.provided_by.as_deref() == Some(id) {
                lib.provided_by = None;
            }
            if lib.required_by.is_empty() {
                backups.push(lib.path.clone());
                libraries.push(LibPlan { name: u.name.clone(), change: LibChange::Delete, version: lib.version.clone(), refs: 0 });
                ndb.libraries.remove(&u.name);
            } else {
                libraries.push(LibPlan { name: u.name.clone(), change: LibChange::Release, version: lib.version.clone(), refs: lib.ref_count });
            }
        }
        for u in old.libraries.iter().filter(|u| u.resolved == Resolved::Private) {
            libraries.push(LibPlan { name: u.name.clone(), change: LibChange::Delete, version: u.version.clone(), refs: 0 });
        }
        let mut cleanup = BTreeSet::new();
        for b in &backups {
            removable_ancestors(b, &mut cleanup);
        }
        let mut cleanup: Vec<String> = cleanup.into_iter().collect();
        cleanup.sort_by(|a, b| depth(b).cmp(&depth(a)).then_with(|| a.cmp(b)));
        ndb.generation += 1;
        ndb.last_tx = format!("{:016x}-{:016x}", ndb.generation, self.policy.nonce);
        ndb.check().map_err(|e| Error::Internal(e.reason))?;
        Ok(Plan {
            op: Op::Remove,
            id: String::from(id),
            name: old.name.clone(),
            version: old.version.clone(),
            previous: None,
            kind: PkgType::from_name(&old.kind).unwrap_or(PkgType::Gui),
            badge: Badge::Unsigned,
            ring: old.ring,
            libraries,
            warnings: Vec::new(),
            files: 0,
            bytes: 0,
            removed: backups.len(),
            places: Vec::new(),
            backups,
            mkdirs: Vec::new(),
            cleanup,
            db: ndb,
        })
    }

    /// Removes an installed package. See the module docs.
    pub fn remove(&mut self, id: &str, confirm: &mut dyn FnMut(&Plan) -> bool) -> Result<Outcome, Error> {
        self.locked(|m| {
            let db = m.load_db_raw()?;
            let plan = m.plan_remove_with(&db, id)?;
            if !confirm(&plan) {
                return Ok(Outcome::Cancelled);
            }
            m.execute(plan)
        })
    }

    // -- the transaction ------------------------------------------------------

    fn execute(&mut self, plan: Plan) -> Result<Outcome, Error> {
        let tx = plan.db.last_tx.clone();
        let tx_dir = format!("{}/{tx}", journal::TX_DIR);
        let stage = format!("{tx_dir}/stage");
        let backup = format!("{tx_dir}/backup");
        let mut steps = Vec::with_capacity(plan.backups.len() + plan.mkdirs.len() + plan.places.len());
        for (i, path) in plan.backups.iter().enumerate() {
            steps.push(Step::Backup { from: path.clone(), to: format!("{backup}/{i}") });
        }
        for d in &plan.mkdirs {
            steps.push(Step::Mkdir(d.clone()));
        }
        for (i, (dest, _)) in plan.places.iter().enumerate() {
            steps.push(Step::Place { from: format!("{stage}/{i}"), to: dest.clone() });
        }
        let journal = Journal { tx: tx.clone(), op: String::from(plan.op.name()), package: plan.id.clone(), steps, cleanup: plan.cleanup.clone() };

        // Staging: nothing outside the transaction directory changes, so a
        // failure here only needs that directory gone.
        let staged: Result<(), Error> = (|| {
            for dir in [&stage, &backup] {
                fs::create_dir_all(self.fs, dir).map_err(|e| fs_err(e, dir))?;
            }
            for (i, (_, data)) in plan.places.iter().enumerate() {
                let p = format!("{stage}/{i}");
                self.fs.create(&p, data).map_err(|e| fs_err(e, &p))?;
            }
            self.fs.sync().map_err(|e| fs_err(e, &stage))?;
            fs::write_atomic(self.fs, journal::PATH, journal.to_json().as_bytes()).map_err(|e| fs_err(e, journal::PATH))
        })();
        if let Err(e) = staged {
            let _ = fs::remove_tree(self.fs, &tx_dir);
            let _ = self.fs.remove_file(&format!("{}.tmp", journal::PATH));
            return Err(e);
        }

        // From here the journal exists: on any failure before the commit,
        // recovery undoes what was done.
        let mut committed = false;
        let applied: Result<(), Error> = (|| {
            db::write_next(self.fs, &plan.db).map_err(|e| fs_err(e, db::NEXT))?;
            self.fs.sync().map_err(|e| fs_err(e, db::NEXT))?;
            for step in &journal.steps {
                match step {
                    Step::Mkdir(d) => self.fs.create_dir(d).map_err(|e| fs_err(e, d))?,
                    Step::Backup { from, to } | Step::Place { from, to } => self.fs.rename(from, to).map_err(|e| fs_err(e, from))?,
                }
            }
            self.fs.sync().map_err(|e| fs_err(e, "/"))?;
            self.fs.replace(db::NEXT, db::PATH).map_err(|e| fs_err(e, db::PATH))?;
            committed = true;
            self.fs.sync().map_err(|e| fs_err(e, db::PATH))
        })();
        if let Err(e) = applied {
            if !committed {
                // Undo now if the filesystem still answers; if not, the
                // journal stays for the next run.
                let _ = self.recover_locked();
                return Err(e);
            }
        }
        let cleanup_pending = self.finish(&journal).is_err();
        Ok(Outcome::Done { op: plan.op, id: plan.id, version: plan.version, tx, cleanup_pending })
    }

    // -- check ----------------------------------------------------------------

    /// `ncpkg check`: the database's invariants, then every file it records
    /// — present, the right size, the right SHA-512.
    pub fn check(&mut self) -> Result<Vec<Problem>, Error> {
        let db = self.load_db_raw()?;
        let mut problems = Vec::new();
        let mut check_file = |fs: &mut dyn Fs, path: &str, size: u64, sha512: &str| match fs.read(path) {
            Ok(data) => {
                if data.len() as u64 != size || hex(&crate::sha512::digest(&data)) != sha512 {
                    problems.push(Problem { path: String::from(path), what: String::from("changed since it was installed") });
                }
            }
            Err(e) => problems.push(Problem { path: String::from(path), what: e.to_string() }),
        };
        for p in db.packages.values() {
            for f in &p.files {
                check_file(self.fs, &f.path, f.size, &f.sha512);
            }
        }
        for l in db.libraries.values() {
            check_file(self.fs, &l.path, l.size, &l.sha512);
        }
        if self.exists(journal::PATH)? {
            problems.push(Problem { path: String::from(journal::PATH), what: String::from("an interrupted transaction: run ncpkg recover") });
        }
        Ok(problems)
    }
}

/// Planning one install, against a copy of the database.
struct Planner<'m, 'f, 'p> {
    m: &'m mut Manager<'f>,
    pkg: Package<'p>,
    meta: Meta<'p>,
    trust: Trust,
    opts: InstallOptions,
}

impl Planner<'_, '_, '_> {
    /// Decodes a package file and checks it against the manifest's SHA-512.
    fn decode(&self, path: &str) -> Result<Vec<u8>, Error> {
        let entry = self.pkg.find(path).ok_or(Error::Format(FormatError::NotFound))?;
        let data = entry.read().map_err(Error::Format)?;
        let listed = self.meta.file(path).ok_or(Error::Meta(meta::Error { kind: meta::ErrorKind::Container, field: "signed.files" }))?;
        if !crate::sha512::ct_eq(&crate::sha512::digest(&data), &listed.sha512) {
            return Err(Error::FileHash(String::from(path)));
        }
        Ok(data)
    }

    /// Checks a module's header against what the manifest says it is, and
    /// returns its capabilities and flags.
    fn module(&self, path: &str, data: &[u8], kind: ModuleKind) -> Result<(u32, u32), Error> {
        let bad = |reason: &str| Error::Module { path: String::from(path), reason: String::from(reason) };
        let img = ncplu::Image::parse(data).map_err(|e| bad(e.message()))?;
        if img.arch() != self.m.policy.arch {
            return Err(bad("the module is built for another architecture than its directory says"));
        }
        if img.kind() != kind {
            return Err(bad("the module is not the kind of module the manifest says"));
        }
        Ok((img.capabilities, img.flags))
    }

    fn plan(self, db: &Db) -> Result<Plan, Error> {
        let policy = self.m.policy.clone();
        let meta = self.meta;
        let arch = policy.arch;
        let id = meta.id();

        if !meta.supports(arch) {
            return Err(Error::WrongArch { arch: String::from(arch.name()), supported: meta.arches().map(|a| String::from(a.name())).collect() });
        }
        if meta.abi() != policy.abi {
            return Err(Error::AbiMismatch { package: meta.abi(), system: policy.abi });
        }
        if let Some(req) = meta.system() {
            let fits = Version::parse(&policy.system_version).zip(Req::parse(req)).is_some_and(|(v, r)| r.matches(&v));
            if !fits {
                return Err(Error::SystemTooOld { requires: String::from(req), system: policy.system_version.clone() });
            }
        }
        if policy.builtin_apps.iter().any(|b| b == id) {
            return Err(Error::Reserved(String::from(id)));
        }
        if self.trust.tampered() {
            let roles = sig::Role::ALL.into_iter().filter(|r| self.trust.failed(*r)).map(|r| String::from(r.name())).collect();
            return Err(Error::Tampered(roles));
        }
        let badge = self.trust.badge();
        if policy.require_signature && badge == Badge::Unsigned {
            return Err(Error::Unsigned);
        }
        let ring = meta.ring();
        let mut warnings = Vec::new();
        if ring == 0 && !self.trust.ring0_signed() {
            if !policy.community_ring0 {
                return Err(Error::Ring0NotAllowed);
            }
            warnings.push(String::from("ring 0 without a ring-0 signature, allowed by Enable Ring0 Community Modules and Drivers"));
        }
        if ring == 0 && meta.creator().is_none() {
            warnings.push(String::from("an anonymous ring-0 package: no creator named"));
        }

        let new_version = meta.version_parsed();
        let old = db.packages.get(id);
        let op = match old {
            None => Op::Install,
            Some(o) => {
                let ov = Version::parse(&o.version).ok_or_else(|| Error::Internal(String::from("installed version unreadable")))?;
                match new_version.precedence(&ov) {
                    Ordering::Equal if self.opts.reinstall => Op::Reinstall,
                    Ordering::Equal => return Err(Error::AlreadyInstalled { id: String::from(id), version: o.version.clone() }),
                    Ordering::Greater => Op::Upgrade,
                    Ordering::Less if self.opts.allow_downgrade => Op::Downgrade,
                    Ordering::Less => {
                        return Err(Error::Downgrade { id: String::from(id), installed: o.version.clone(), offered: String::from(meta.version()) })
                    }
                }
            }
        };

        let mut ndb = db.clone();
        let mut backups: Vec<String> = Vec::new();
        // An upgrade releases the old version first: its files go aside and
        // its references are dropped, so the new version is planned as if
        // it arrived alone — in the same transaction.
        if let Some(o) = old {
            backups.extend(o.files.iter().map(|f| f.path.clone()));
            for u in o.libraries.iter().filter(|u| u.resolved == Resolved::Global) {
                if let Some(l) = ndb.libraries.get_mut(&u.name) {
                    l.required_by.retain(|r| r != id);
                }
            }
            ndb.packages.remove(id);
        }

        let mut places: Vec<(String, Vec<u8>)> = Vec::new();
        let mut owned: Vec<FileRec> = Vec::new();
        let place = |places: &mut Vec<(String, Vec<u8>)>, owned: Option<&mut Vec<FileRec>>, dest: String, data: Vec<u8>| {
            if let Some(o) = owned {
                o.push(FileRec { path: dest.clone(), size: data.len() as u64, sha512: hex(&crate::sha512::digest(&data)) });
            }
            places.push((dest, data));
        };

        // The app and its commands.
        let mut commands = Vec::new();
        let mut capabilities = Vec::new();
        if let Some(app) = meta.app() {
            let src = format!("ncapp/{}/{}", arch.name(), app.entry);
            let data = self.decode(&src)?;
            let (module_caps, module_flags) = self.module(&src, &data, ModuleKind::App)?;
            if module_caps & !app.capabilities != 0 {
                return Err(Error::Module { path: src, reason: String::from("the module asks for capabilities the manifest does not declare") });
            }
            if module_flags & ncplu::FLAG_WANTS_PRIVILEGED != 0 && ring != 0 {
                return Err(Error::Module { path: src, reason: String::from("the module imports kernel-tier symbols but the manifest asks for ring 3") });
            }
            capabilities = meta::CAPABILITIES.iter().filter(|(_, b)| app.capabilities & b != 0).map(|(n, _)| String::from(*n)).collect();
            place(&mut places, Some(&mut owned), format!("/apps/{id}/{}", app.entry), data);
            for c in app.commands() {
                if policy.reserved_commands.iter().any(|r| r == c) {
                    return Err(Error::CommandConflict { command: String::from(c), owner: None });
                }
                let launcher = format!("#!ncapp /apps/{id}/{}\n", app.entry);
                place(&mut places, Some(&mut owned), db::command_path(c), launcher.into_bytes());
                commands.push(String::from(c));
            }
        }

        // Resources, for every architecture alike.
        for f in meta.files().filter(|f| f.path.starts_with("res/")) {
            let data = self.decode(f.path)?;
            place(&mut places, Some(&mut owned), format!("/apps/{id}/{}", f.path), data);
        }

        // The icon, checked and decoded, into the cache the desktop reads.
        let mut icon = None;
        if meta.icon().is_some() {
            let data = self.decode(super::ICON)?;
            super::icon::check_decodes(&data).map_err(Error::Icon)?;
            let dest = super::icon::cache_path(id);
            icon = Some(dest.clone());
            place(&mut places, Some(&mut owned), dest, data);
        }

        // Plugins, registered under their host.
        let mut plugins = Vec::new();
        for p in meta.plugins() {
            let host_known = policy.builtin_apps.iter().any(|b| b == p.host) || ndb.packages.contains_key(p.host);
            if !host_known {
                return Err(Error::HostMissing { plugin: String::from(p.file), host: String::from(p.host) });
            }
            let src = format!("plugins/{}/{}", arch.name(), p.file);
            let data = self.decode(&src)?;
            self.module(&src, &data, ModuleKind::Plugin)?;
            let dest = format!("/usr/lib/ncplu/{}/{id}/{}", p.host, p.file);
            plugins.push(PluginRec { host: String::from(p.host), path: dest.clone(), provides: p.provides().map(String::from).collect() });
            place(&mut places, Some(&mut owned), dest, data);
        }

        // Libraries.
        let mut uses = Vec::new();
        let mut libraries = Vec::new();
        for u in meta.uses() {
            let requirement = u.requirement;
            let shipped = match u.shipped {
                Some(s) => {
                    let src = format!("lib/{}/{}", arch.name(), s.file);
                    let data = self.decode(&src)?;
                    self.module(&src, &data, ModuleKind::Library)?;
                    Some((s, data))
                }
                None => None,
            };
            let global = ndb.libraries.get(u.name).cloned();
            let accepts = |dependents: &[String], v: &Version<'_>, ndb: &Db| {
                dependents.iter().all(|d| {
                    ndb.packages
                        .get(d)
                        .and_then(|p| p.libraries.iter().find(|x| x.name == u.name))
                        .and_then(|x| Req::parse(&x.requirement))
                        .is_some_and(|r| r.matches(v))
                })
            };
            // What to do, and which version the package ends up with.
            enum Choice {
                Share,
                Global { replaces: Option<String> },
                Private,
            }
            let choice = match (&global, &shipped) {
                (Some(g), _) => {
                    let gv = Version::parse(&g.version).ok_or_else(|| Error::Internal(format!("library {} version unreadable", u.name)))?;
                    let free = g.required_by.is_empty();
                    let upgrade = shipped.as_ref().filter(|(s, _)| s.share).is_some_and(|(s, data)| {
                        let sv = Version::parse(s.version).unwrap_or(gv);
                        let newer = sv.precedence(&gv) == Ordering::Greater;
                        let same = sv.precedence(&gv) == Ordering::Equal && hex(&crate::sha512::digest(data)) == g.sha512;
                        requirement.matches(&sv) && !same && (free || (newer && accepts(&g.required_by, &sv, &ndb)))
                    });
                    if upgrade {
                        Choice::Global { replaces: Some(g.version.clone()) }
                    } else if requirement.matches(&gv) {
                        Choice::Share
                    } else if let Some((s, _)) = &shipped {
                        if meta.kind() == PkgType::Lib {
                            return Err(Error::LibraryConflict {
                                name: String::from(u.name),
                                installed: g.version.clone(),
                                offered: String::from(s.version),
                                required_by: g.required_by.clone(),
                            });
                        }
                        Choice::Private
                    } else {
                        return Err(Error::MissingLibrary { name: String::from(u.name), requirement: requirement.to_string(), installed: Some(g.version.clone()) });
                    }
                }
                (None, Some((s, _))) => {
                    if s.share {
                        Choice::Global { replaces: None }
                    } else {
                        Choice::Private
                    }
                }
                (None, None) => {
                    return Err(Error::MissingLibrary { name: String::from(u.name), requirement: requirement.to_string(), installed: None });
                }
            };
            let global_path = db::global_lib_path(u.name);
            match choice {
                Choice::Share => {
                    let l = ndb.libraries.get_mut(u.name).ok_or_else(|| Error::Internal(String::from("shared library vanished")))?;
                    l.required_by.push(String::from(id));
                    uses.push(LibUse { name: String::from(u.name), requirement: requirement.to_string(), resolved: Resolved::Global, version: l.version.clone() });
                    libraries.push(LibPlan { name: String::from(u.name), change: LibChange::Share, version: l.version.clone(), refs: 0 });
                }
                Choice::Global { replaces } => {
                    let (s, data) = shipped.ok_or_else(|| Error::Internal(String::from("no shipped copy to install")))?;
                    let mut required_by = global.as_ref().map(|g| g.required_by.clone()).unwrap_or_default();
                    // Every package that shares the copy now uses the new
                    // version, and its record says so.
                    for d in &required_by {
                        if let Some(u2) = ndb.packages.get_mut(d).and_then(|p| p.libraries.iter_mut().find(|x| x.name == u.name)) {
                            u2.version = String::from(s.version);
                        }
                    }
                    required_by.push(String::from(id));
                    if replaces.is_some() {
                        backups.push(global_path.clone());
                    }
                    ndb.libraries.insert(
                        String::from(u.name),
                        Library {
                            version: String::from(s.version),
                            path: global_path.clone(),
                            size: data.len() as u64,
                            sha512: hex(&crate::sha512::digest(&data)),
                            provided_by: Some(String::from(id)),
                            ref_count: 0,
                            required_by,
                        },
                    );
                    place(&mut places, None, global_path, data);
                    uses.push(LibUse { name: String::from(u.name), requirement: requirement.to_string(), resolved: Resolved::Global, version: String::from(s.version) });
                    let change = match replaces {
                        Some(from) => LibChange::UpgradeGlobal { from },
                        None => LibChange::NewGlobal,
                    };
                    libraries.push(LibPlan { name: String::from(u.name), change, version: String::from(s.version), refs: 0 });
                }
                Choice::Private => {
                    let (s, data) = shipped.ok_or_else(|| Error::Internal(String::from("no shipped copy to keep private")))?;
                    place(&mut places, Some(&mut owned), db::private_lib_path(id, u.name), data);
                    uses.push(LibUse { name: String::from(u.name), requirement: requirement.to_string(), resolved: Resolved::Private, version: String::from(s.version) });
                    libraries.push(LibPlan {
                        name: String::from(u.name),
                        change: LibChange::Private { global: global.as_ref().map(|g| g.version.clone()) },
                        version: String::from(s.version),
                        refs: 0,
                    });
                }
            }
        }

        // Libraries no package uses any more (an upgrade dropped them) go.
        let unused: Vec<String> = ndb.libraries.iter().filter(|(_, l)| l.required_by.is_empty()).map(|(n, _)| n.clone()).collect();
        for name in unused {
            if let Some(l) = ndb.libraries.remove(&name) {
                backups.push(l.path.clone());
                libraries.push(LibPlan { name, change: LibChange::Delete, version: l.version, refs: 0 });
            }
        }
        for l in ndb.libraries.values_mut() {
            l.required_by.sort();
            l.required_by.dedup();
            l.ref_count = l.required_by.len() as u64;
            if l.provided_by.as_deref().is_some_and(|p| p == id) && !l.required_by.iter().any(|r| r == id) {
                l.provided_by = None;
            }
        }
        for lp in &mut libraries {
            if matches!(lp.change, LibChange::Share | LibChange::NewGlobal | LibChange::UpgradeGlobal { .. }) {
                lp.refs = ndb.libraries.get(&lp.name).map_or(0, |l| l.ref_count);
            }
        }
        // The provider of a global copy that is gone (its package removed
        // or upgraded) is nobody.
        for l in ndb.libraries.values_mut() {
            if l.provided_by.as_deref().is_some_and(|p| p != id && !ndb.packages.contains_key(p)) {
                l.provided_by = None;
            }
        }

        // The manifest, kept for audits and `ncpkg info`.
        place(&mut places, Some(&mut owned), format!("{}/{id}.meta", db::META_DIR), self.pkg.meta().to_vec());

        // Nothing lands on what another package owns, or on what nobody
        // owns unless --force.
        let mut seen = BTreeSet::new();
        let aside: BTreeSet<String> = backups.iter().cloned().collect();
        // Who owns what, once: the other packages' files.
        let owners: alloc::collections::BTreeMap<String, String> =
            ndb.packages.iter().flat_map(|(pid, p)| p.files.iter().map(move |f| (f.path.clone(), pid.clone()))).collect();
        for (dest, _) in &places {
            if !seen.insert(dest.clone()) {
                return Err(Error::Internal(format!("{dest} planned twice")));
            }
            if aside.contains(dest) {
                continue;
            }
            if let Some(owner) = owners.get(dest) {
                if dest.starts_with("/usr/bin/") {
                    let command = dest.rsplit('/').next().unwrap_or(dest);
                    return Err(Error::CommandConflict { command: String::from(command), owner: Some(String::from(owner)) });
                }
                return Err(Error::FileConflict { path: dest.clone(), owner: Some(String::from(owner)) });
            }
            let ours_global = ndb.libraries.values().any(|l| &l.path == dest && l.provided_by.as_deref() == Some(id));
            if !ours_global && db.libraries.values().any(|l| &l.path == dest) {
                return Err(Error::FileConflict { path: dest.clone(), owner: Some(String::from("the shared libraries")) });
            }
            if self.m.exists(dest)? {
                if !self.opts.force {
                    return Err(Error::FileConflict { path: dest.clone(), owner: None });
                }
                warnings.push(format!("{dest} belonged to no package and is overwritten"));
                backups.push(dest.clone());
            }
        }

        // Directories to create, parents first, and to clean up after.
        let mut mkdirs: Vec<String> = Vec::new();
        for (dest, _) in &places {
            let mut missing = Vec::new();
            let mut p = fs::parent(dest);
            while p != "/" && !mkdirs.iter().any(|m| m == p) && !self.m.exists(p)? {
                missing.push(String::from(p));
                p = fs::parent(p);
            }
            missing.reverse();
            mkdirs.extend(missing);
        }
        let mut cleanup = BTreeSet::new();
        for b in &backups {
            removable_ancestors(b, &mut cleanup);
        }
        let mut cleanup: Vec<String> = cleanup.into_iter().collect();
        cleanup.sort_by(|a, b| depth(b).cmp(&depth(a)).then_with(|| a.cmp(b)));

        let perms = meta.permissions();
        let record = db::Package {
            name: meta.name().to_string(),
            version: String::from(meta.version()),
            kind: String::from(meta.kind().name()),
            arch: String::from(arch.name()),
            license: String::from(meta.license_or_default()),
            creator: meta.creator().map(|c| c.name.to_string()),
            installed_at: policy.now,
            badge: String::from(badge.id()),
            roles: self.trust.roles().map(|r| String::from(r.name())).collect(),
            self_key: self.trust.self_key.map(|k| String::from_utf8_lossy(&k).into_owned()),
            ring,
            capabilities,
            devices: perms.devices().map(|d| String::from(d.name())).collect(),
            network: String::from(perms.network.name()),
            fs: perms.fs().map(|g| (String::from(g.path), String::from(g.access.name()))).collect(),
            manifest_sha512: hex(&crate::sha512::digest(self.pkg.meta())),
            files: owned,
            libraries: uses,
            plugins,
            commands,
            icon,
        };
        ndb.packages.insert(String::from(id), record);
        ndb.generation += 1;
        ndb.last_tx = format!("{:016x}-{:016x}", ndb.generation, policy.nonce);
        ndb.check().map_err(|e| Error::Internal(e.reason))?;

        let bytes = places.iter().map(|(_, d)| d.len() as u64).sum();
        Ok(Plan {
            op,
            id: String::from(id),
            name: meta.name().to_string(),
            version: String::from(meta.version()),
            previous: old.map(|o| o.version.clone()),
            kind: meta.kind(),
            badge,
            ring,
            libraries,
            warnings,
            files: places.len(),
            bytes,
            removed: backups.len(),
            places,
            backups,
            mkdirs,
            cleanup,
            db: ndb,
        })
    }
}

