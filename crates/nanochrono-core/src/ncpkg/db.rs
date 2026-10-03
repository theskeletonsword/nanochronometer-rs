// SPDX-License-Identifier: Apache-2.0
//! The package database, `/var/lib/ncpkg/db.json`.
//!
//! What is installed, which files each package owns, and the shared
//! libraries in `/usr/lib` with their reference counts:
//!
//! ```json
//! {
//!   "format": "ncpkg-db/1",
//!   "generation": 7,
//!   "last_tx": "0000000000000007-9f3c2a1b5d4e6f70",
//!   "arch": "x86_64",
//!   "packages": {
//!     "org.example.player-plus": {
//!       "name": "Player Plus", "version": "2.0.1", "type": "gui", "arch": "x86_64",
//!       "license": "MIT", "creator": "Ada", "installed_at": 1759363200,
//!       "badge": "creator", "roles": ["creator-ring3"], "self_key": null, "ring": 3,
//!       "capabilities": ["screen", "input"], "devices": ["audio"], "network": "client",
//!       "fs": [{"path": "$HOME/Music", "access": "r"}],
//!       "manifest_sha512": "…",
//!       "files": [{"path": "/apps/org.example.player-plus/main.ncapp", "size": 52144, "sha512": "…"}],
//!       "libraries": [{"name": "libavcodec", "requirement": ">=61.0.0, <62.0.0", "resolved": "global", "version": "61.3.100"}],
//!       "plugins": [{"host": "nc.player", "path": "/usr/lib/ncplu/nc.player/org.example.player-plus/vgm.ncplu", "provides": ["audio/x-adx"]}],
//!       "commands": []
//!     }
//!   },
//!   "libraries": {
//!     "libavcodec": {
//!       "version": "61.3.100", "path": "/usr/lib/libavcodec.ncdyn", "size": 4211840, "sha512": "…",
//!       "provided_by": "org.example.player-plus",
//!       "ref_count": 2, "required_by": ["org.example.player-plus", "org.example.recorder"]
//!     }
//!   }
//! }
//! ```
//!
//! `required_by` is the truth and `ref_count` its length, kept beside it so
//! the file reads at a glance; [`Db::check`] refuses a database where they
//! disagree, or where any cross-reference fails (a package that says it
//! uses a global library the library does not list, a file two packages
//! claim, a library nobody requires). A database that fails the check is
//! never written over: the manager stops and says why.
//!
//! `generation` counts committed transactions and `last_tx` names the last
//! one — which is how recovery tells, after a crash, whether the
//! transaction in the journal reached its commit (see [`super::manager`]).

use super::fs::{self, Fs, FsError};
use super::path;
use super::version::Version;
use crate::json::{self, Json, Kind, Style, Value};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub const FORMAT: &str = "ncpkg-db/1";
pub const DIR: &str = "/var/lib/ncpkg";
pub const PATH: &str = "/var/lib/ncpkg/db.json";
/// The next database, written before a transaction's steps and swapped in
/// at its commit.
pub const NEXT: &str = "/var/lib/ncpkg/db.json.new";
/// Copies of installed manifests, `<id>.meta`.
pub const META_DIR: &str = "/var/lib/ncpkg/meta";

/// How a package's library was provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// The shared copy in `/usr/lib`, counted in its `required_by`.
    Global,
    /// The package's own copy in `/apps/<id>/lib`, because the global one
    /// is a version it does not accept (or it may not be shared).
    Private,
}

impl Resolved {
    pub const fn name(self) -> &'static str {
        match self {
            Resolved::Global => "global",
            Resolved::Private => "private",
        }
    }
}

/// A file a package owns, as installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRec {
    pub path: String,
    pub size: u64,
    pub sha512: String,
}

/// A library a package uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibUse {
    pub name: String,
    /// What the package accepts, as text (`>=61.0.0, <62.0.0`, `^1.2.0`).
    pub requirement: String,
    pub resolved: Resolved,
    /// The version it got.
    pub version: String,
}

/// A plugin a package registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRec {
    pub host: String,
    pub path: String,
    pub provides: Vec<String>,
}

/// An installed package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// `gui`, `cli` or `lib`.
    pub kind: String,
    pub arch: String,
    pub license: String,
    pub creator: Option<String>,
    /// Unix seconds, from the installer's clock; 0 if it had none.
    pub installed_at: u64,
    /// [`super::sig::Badge::id`] at install time.
    pub badge: String,
    /// The signature roles that verified.
    pub roles: Vec<String>,
    pub self_key: Option<String>,
    pub ring: u8,
    pub capabilities: Vec<String>,
    pub devices: Vec<String>,
    pub network: String,
    /// NCFS grants: (path template, `r` or `rw`).
    pub fs: Vec<(String, String)>,
    pub manifest_sha512: String,
    /// Every path the package owns, exclusively: removed with it.
    pub files: Vec<FileRec>,
    pub libraries: Vec<LibUse>,
    pub plugins: Vec<PluginRec>,
    /// Command names linked into `/usr/bin`.
    pub commands: Vec<String>,
    /// The icon in the cache (`/var/cache/ncpkg/icons/<id>.png`), if the
    /// package has one; it is among `files`.
    pub icon: Option<String>,
}

/// A shared library in `/usr/lib`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Library {
    pub version: String,
    pub path: String,
    pub size: u64,
    pub sha512: String,
    /// The package whose copy is on disk; `None` once it was removed while
    /// others still needed the library.
    pub provided_by: Option<String>,
    /// `required_by.len()`, stored for the reader.
    pub ref_count: u64,
    /// Sorted, unique.
    pub required_by: Vec<String>,
}

/// The whole database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Db {
    pub generation: u64,
    pub last_tx: String,
    pub arch: String,
    pub packages: BTreeMap<String, Package>,
    pub libraries: BTreeMap<String, Library>,
}

/// Why a database was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbError {
    pub reason: String,
}

impl DbError {
    fn new(reason: impl Into<String>) -> DbError {
        DbError { reason: reason.into() }
    }
}

impl core::fmt::Display for DbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "package database: {}", self.reason)
    }
}

/// The path of the global copy of library `name`.
pub fn global_lib_path(name: &str) -> String {
    format!("/usr/lib/{name}.ncdyn")
}

impl Db {
    pub fn empty(arch: &str) -> Db {
        Db { generation: 0, last_tx: String::new(), arch: String::from(arch), packages: BTreeMap::new(), libraries: BTreeMap::new() }
    }

    /// Loads [`PATH`]; an absent database is an empty one.
    pub fn load(fs: &mut dyn Fs, arch: &str) -> Result<Db, LoadError> {
        match fs.read(PATH) {
            Ok(bytes) => {
                let db = Db::parse(&bytes).map_err(LoadError::Db)?;
                if db.arch != arch {
                    return Err(LoadError::Db(DbError::new(format!("it belongs to a {} system, this is {arch}", db.arch))));
                }
                Ok(db)
            }
            Err(FsError::NotFound) => Ok(Db::empty(arch)),
            Err(e) => Err(LoadError::Fs(e)),
        }
    }

    /// Parses and [checks](Db::check) a database.
    pub fn parse(bytes: &[u8]) -> Result<Db, DbError> {
        let root = json::parse(bytes, &json::Limits::DATABASE).map_err(|e| DbError::new(format!("not valid JSON: {e}")))?;
        let mut r = Reader::new("db");
        let [format, generation, last_tx, arch, packages, libraries] =
            r.object(root, ["format", "generation", "last_tx", "arch", "packages", "libraries"])?;
        if r.string(format, "format")? != FORMAT {
            return Err(DbError::new("not an ncpkg-db/1 database"));
        }
        let mut db = Db {
            generation: r.uint(generation, "generation")?,
            last_tx: r.string(last_tx, "last_tx")?,
            arch: r.string(arch, "arch")?,
            packages: BTreeMap::new(),
            libraries: BTreeMap::new(),
        };
        let packages = r.need(packages, "packages")?;
        if packages.kind() != Kind::Object {
            return Err(DbError::new("packages is not an object"));
        }
        for (id, p) in packages.members() {
            let id = id.to_string();
            let pkg = read_package(&mut Reader::new("package"), p).map_err(|e| DbError::new(format!("package {id}: {}", e.reason)))?;
            if db.packages.insert(id.clone(), pkg).is_some() {
                return Err(DbError::new(format!("package {id} appears twice")));
            }
        }
        let libraries = r.need(libraries, "libraries")?;
        if libraries.kind() != Kind::Object {
            return Err(DbError::new("libraries is not an object"));
        }
        for (name, l) in libraries.members() {
            let name = name.to_string();
            let lib = read_library(&mut Reader::new("library"), l).map_err(|e| DbError::new(format!("library {name}: {}", e.reason)))?;
            if db.libraries.insert(name.clone(), lib).is_some() {
                return Err(DbError::new(format!("library {name} appears twice")));
            }
        }
        db.check()?;
        Ok(db)
    }

    /// Every invariant in the module docs.
    pub fn check(&self) -> Result<(), DbError> {
        if path::arch_dir(&self.arch).is_none() {
            return Err(DbError::new(format!("unknown architecture {:?}", self.arch)));
        }
        let mut owner: BTreeMap<&str, &str> = BTreeMap::new();
        for (id, p) in &self.packages {
            let bad = |what: &str| DbError::new(format!("package {id}: {what}"));
            if !path::is_package_id(id) {
                return Err(bad("not a package id"));
            }
            if Version::parse(&p.version).is_none() {
                return Err(bad("bad version"));
            }
            if !matches!(p.kind.as_str(), "gui" | "cli" | "lib") {
                return Err(bad("bad type"));
            }
            if p.arch != self.arch {
                return Err(bad("installed for another architecture"));
            }
            if p.ring != 0 && p.ring != 3 {
                return Err(bad("bad ring"));
            }
            for f in &p.files {
                if !path::is_system_path(&f.path) || crate::sha512::from_hex(f.sha512.as_bytes()).is_none() {
                    return Err(bad(&format!("bad file record {}", f.path)));
                }
                if let Some(other) = owner.insert(&f.path, id) {
                    return Err(DbError::new(format!("{} is claimed by both {other} and {id}", f.path)));
                }
            }
            let owns = |path: &str| p.files.iter().any(|f| f.path == path);
            let mut seen = BTreeSet::new();
            for u in &p.libraries {
                if !seen.insert(u.name.as_str()) {
                    return Err(bad(&format!("uses {} twice", u.name)));
                }
                match u.resolved {
                    Resolved::Global => {
                        let lib = self.libraries.get(&u.name).ok_or_else(|| bad(&format!("uses global {}, which is not installed", u.name)))?;
                        if lib.required_by.binary_search(id).is_err() {
                            return Err(bad(&format!("uses global {}, which does not count it", u.name)));
                        }
                        if lib.version != u.version {
                            return Err(bad(&format!("records {} {} but {} is installed", u.name, u.version, lib.version)));
                        }
                    }
                    Resolved::Private => {
                        if !owns(&private_lib_path(id, &u.name)) {
                            return Err(bad(&format!("its private {} is not among its files", u.name)));
                        }
                    }
                }
            }
            for pl in &p.plugins {
                if !owns(&pl.path) {
                    return Err(bad(&format!("plugin {} is not among its files", pl.path)));
                }
            }
            for c in &p.commands {
                if !owns(&command_path(c)) {
                    return Err(bad(&format!("command {c} is not among its files")));
                }
            }
            if let Some(icon) = &p.icon {
                if !owns(icon) || *icon != super::icon::cache_path(id) {
                    return Err(bad("its icon is not its cache file"));
                }
            }
        }
        for (name, l) in &self.libraries {
            let bad = |what: &str| DbError::new(format!("library {name}: {what}"));
            if !path::is_name(name) || l.path != global_lib_path(name) {
                return Err(bad("bad name or path"));
            }
            if Version::parse(&l.version).is_none() || crate::sha512::from_hex(l.sha512.as_bytes()).is_none() {
                return Err(bad("bad version or digest"));
            }
            if l.required_by.is_empty() {
                return Err(bad("required by nobody, yet still installed"));
            }
            if l.ref_count != l.required_by.len() as u64 {
                return Err(bad(&format!("ref_count {} but required by {}", l.ref_count, l.required_by.len())));
            }
            if l.required_by.windows(2).any(|w| w[0] >= w[1]) {
                return Err(bad("required_by is not sorted and unique"));
            }
            for id in &l.required_by {
                let uses = self.packages.get(id).is_some_and(|p| p.libraries.iter().any(|u| &u.name == name && u.resolved == Resolved::Global));
                if !uses {
                    return Err(bad(&format!("counts {id}, which does not use it")));
                }
            }
            if let Some(p) = &l.provided_by {
                if !self.packages.contains_key(p) {
                    return Err(bad(&format!("provided by {p}, which is not installed")));
                }
            }
            if let Some(other) = owner.get(l.path.as_str()) {
                return Err(bad(&format!("its file is also claimed by {other}")));
            }
        }
        Ok(())
    }

    /// The package owning `path`, if any.
    pub fn owner_of(&self, path: &str) -> Option<&str> {
        self.packages.iter().find(|(_, p)| p.files.iter().any(|f| f.path == path)).map(|(id, _)| id.as_str())
    }

    /// Recomputes every library's `required_by` and `ref_count` from what
    /// the packages say they use, dropping libraries nobody uses: the
    /// repair for a database whose counts drifted. Returns the libraries
    /// dropped (their files are the caller's to delete).
    pub fn rebuild_refs(&mut self) -> Vec<String> {
        for l in self.libraries.values_mut() {
            l.required_by.clear();
        }
        for (id, p) in &self.packages {
            for u in p.libraries.iter().filter(|u| u.resolved == Resolved::Global) {
                if let Some(l) = self.libraries.get_mut(&u.name) {
                    l.required_by.push(id.clone());
                }
            }
        }
        let mut dropped = Vec::new();
        self.libraries.retain(|name, l| {
            l.required_by.sort();
            l.required_by.dedup();
            l.ref_count = l.required_by.len() as u64;
            if let Some(p) = &l.provided_by {
                if !self.packages.contains_key(p) {
                    l.provided_by = None;
                }
            }
            let keep = !l.required_by.is_empty();
            if !keep {
                dropped.push(name.clone());
            }
            keep
        });
        dropped
    }

    /// The database as the file holds it: indented, members in a fixed
    /// order, packages and libraries sorted.
    pub fn to_json(&self) -> String {
        let packages = Json::Obj(self.packages.iter().map(|(id, p)| (id.clone(), package_json(p))).collect());
        let libraries = Json::Obj(self.libraries.iter().map(|(n, l)| (n.clone(), library_json(l))).collect());
        Json::obj([
            ("format", Json::str(FORMAT)),
            ("generation", Json::uint(self.generation)),
            ("last_tx", Json::str(&self.last_tx)),
            ("arch", Json::str(&self.arch)),
            ("packages", packages),
            ("libraries", libraries),
        ])
        .write(Style::PRETTY)
    }
}

/// Where a package's private copy of `lib` lives.
pub fn private_lib_path(id: &str, lib: &str) -> String {
    format!("/apps/{id}/lib/{lib}.ncdyn")
}

/// Where command `name`'s launcher lives.
pub fn command_path(name: &str) -> String {
    format!("/usr/bin/{name}")
}

/// Why loading failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Fs(FsError),
    Db(DbError),
}

fn strings(v: &[String]) -> Json {
    Json::Arr(v.iter().map(|s| Json::str(s)).collect())
}

fn opt(v: &Option<String>) -> Json {
    v.as_ref().map_or(Json::Null, |s| Json::str(s))
}

fn package_json(p: &Package) -> Json {
    Json::obj([
        ("name", Json::str(&p.name)),
        ("version", Json::str(&p.version)),
        ("type", Json::str(&p.kind)),
        ("arch", Json::str(&p.arch)),
        ("license", Json::str(&p.license)),
        ("creator", opt(&p.creator)),
        ("installed_at", Json::uint(p.installed_at)),
        ("badge", Json::str(&p.badge)),
        ("roles", strings(&p.roles)),
        ("self_key", opt(&p.self_key)),
        ("ring", Json::Int(i64::from(p.ring))),
        ("capabilities", strings(&p.capabilities)),
        ("devices", strings(&p.devices)),
        ("network", Json::str(&p.network)),
        ("fs", Json::Arr(p.fs.iter().map(|(path, access)| Json::obj([("path", Json::str(path)), ("access", Json::str(access))])).collect())),
        ("manifest_sha512", Json::str(&p.manifest_sha512)),
        (
            "files",
            Json::Arr(
                p.files
                    .iter()
                    .map(|f| Json::obj([("path", Json::str(&f.path)), ("size", Json::uint(f.size)), ("sha512", Json::str(&f.sha512))]))
                    .collect(),
            ),
        ),
        (
            "libraries",
            Json::Arr(
                p.libraries
                    .iter()
                    .map(|u| {
                        Json::obj([
                            ("name", Json::str(&u.name)),
                            ("requirement", Json::str(&u.requirement)),
                            ("resolved", Json::str(u.resolved.name())),
                            ("version", Json::str(&u.version)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "plugins",
            Json::Arr(
                p.plugins
                    .iter()
                    .map(|pl| Json::obj([("host", Json::str(&pl.host)), ("path", Json::str(&pl.path)), ("provides", strings(&pl.provides))]))
                    .collect(),
            ),
        ),
        ("commands", strings(&p.commands)),
        ("icon", opt(&p.icon)),
    ])
}

fn library_json(l: &Library) -> Json {
    Json::obj([
        ("version", Json::str(&l.version)),
        ("path", Json::str(&l.path)),
        ("size", Json::uint(l.size)),
        ("sha512", Json::str(&l.sha512)),
        ("provided_by", opt(&l.provided_by)),
        ("ref_count", Json::uint(l.ref_count)),
        ("required_by", strings(&l.required_by)),
    ])
}

/// Field-by-field reading with the context for error messages.
struct Reader {
    what: &'static str,
}

impl Reader {
    fn new(what: &'static str) -> Reader {
        Reader { what }
    }

    fn err(&self, field: &str, problem: &str) -> DbError {
        DbError::new(format!("{}.{field}: {problem}", self.what))
    }

    fn object<'a, const N: usize>(&mut self, v: Value<'a>, keys: [&str; N]) -> Result<[Option<Value<'a>>; N], DbError> {
        if v.kind() != Kind::Object {
            return Err(DbError::new(format!("{} is not an object", self.what)));
        }
        let mut out = [None; N];
        for (k, val) in v.members() {
            let i = keys.iter().position(|key| k.eq_str(key)).ok_or_else(|| self.err(&k.to_string(), "unknown field"))?;
            if out[i].is_some() {
                return Err(self.err(keys[i], "appears twice"));
            }
            out[i] = Some(val);
        }
        Ok(out)
    }

    fn need<'a>(&self, v: Option<Value<'a>>, field: &str) -> Result<Value<'a>, DbError> {
        v.ok_or_else(|| self.err(field, "missing"))
    }

    fn string(&self, v: Option<Value<'_>>, field: &str) -> Result<String, DbError> {
        Ok(self.need(v, field)?.as_str().ok_or_else(|| self.err(field, "not a string"))?.to_string())
    }

    fn opt_string(&self, v: Option<Value<'_>>, field: &str) -> Result<Option<String>, DbError> {
        let v = self.need(v, field)?;
        if v.is_null() {
            return Ok(None);
        }
        Ok(Some(v.as_str().ok_or_else(|| self.err(field, "not a string or null"))?.to_string()))
    }

    fn uint(&self, v: Option<Value<'_>>, field: &str) -> Result<u64, DbError> {
        self.need(v, field)?.as_u64().ok_or_else(|| self.err(field, "not a non-negative integer"))
    }

    fn strings(&self, v: Option<Value<'_>>, field: &str) -> Result<Vec<String>, DbError> {
        let v = self.need(v, field)?;
        if v.kind() != Kind::Array {
            return Err(self.err(field, "not an array"));
        }
        v.elements().map(|e| e.as_str().map(|s| s.to_string()).ok_or_else(|| self.err(field, "not a string"))).collect()
    }

    fn array<'a>(&self, v: Option<Value<'a>>, field: &str) -> Result<Vec<Value<'a>>, DbError> {
        let v = self.need(v, field)?;
        if v.kind() != Kind::Array {
            return Err(self.err(field, "not an array"));
        }
        Ok(v.elements().collect())
    }
}

fn read_package(r: &mut Reader, v: Value<'_>) -> Result<Package, DbError> {
    let [name, version, kind, arch, license, creator, installed_at, badge, roles, self_key, ring, capabilities, devices, network, fsv, manifest_sha512, files, libraries, plugins, commands, icon] = r.object(
        v,
        [
            "name", "version", "type", "arch", "license", "creator", "installed_at", "badge", "roles", "self_key", "ring",
            "capabilities", "devices", "network", "fs", "manifest_sha512", "files", "libraries", "plugins", "commands", "icon",
        ],
    )?;
    let ring = r.uint(ring, "ring")?;
    let mut fs_grants = Vec::new();
    for g in r.array(fsv, "fs")? {
        let mut gr = Reader::new("package.fs");
        let [path, access] = gr.object(g, ["path", "access"])?;
        fs_grants.push((gr.string(path, "path")?, gr.string(access, "access")?));
    }
    let mut file_recs = Vec::new();
    for f in r.array(files, "files")? {
        let mut fr = Reader::new("package.files");
        let [path, size, sha512] = fr.object(f, ["path", "size", "sha512"])?;
        file_recs.push(FileRec { path: fr.string(path, "path")?, size: fr.uint(size, "size")?, sha512: fr.string(sha512, "sha512")? });
    }
    let mut uses = Vec::new();
    for u in r.array(libraries, "libraries")? {
        let mut ur = Reader::new("package.libraries");
        let [name, requirement, resolved, version] = ur.object(u, ["name", "requirement", "resolved", "version"])?;
        let resolved = match ur.string(resolved, "resolved")?.as_str() {
            "global" => Resolved::Global,
            "private" => Resolved::Private,
            _ => return Err(ur.err("resolved", "not global or private")),
        };
        uses.push(LibUse { name: ur.string(name, "name")?, requirement: ur.string(requirement, "requirement")?, resolved, version: ur.string(version, "version")? });
    }
    let mut plugin_recs = Vec::new();
    for p in r.array(plugins, "plugins")? {
        let mut pr = Reader::new("package.plugins");
        let [host, path, provides] = pr.object(p, ["host", "path", "provides"])?;
        plugin_recs.push(PluginRec { host: pr.string(host, "host")?, path: pr.string(path, "path")?, provides: pr.strings(provides, "provides")? });
    }
    Ok(Package {
        name: r.string(name, "name")?,
        version: r.string(version, "version")?,
        kind: r.string(kind, "type")?,
        arch: r.string(arch, "arch")?,
        license: r.string(license, "license")?,
        creator: r.opt_string(creator, "creator")?,
        installed_at: r.uint(installed_at, "installed_at")?,
        badge: r.string(badge, "badge")?,
        roles: r.strings(roles, "roles")?,
        self_key: r.opt_string(self_key, "self_key")?,
        ring: u8::try_from(ring).map_err(|_| r.err("ring", "out of range"))?,
        capabilities: r.strings(capabilities, "capabilities")?,
        devices: r.strings(devices, "devices")?,
        network: r.string(network, "network")?,
        fs: fs_grants,
        manifest_sha512: r.string(manifest_sha512, "manifest_sha512")?,
        files: file_recs,
        libraries: uses,
        plugins: plugin_recs,
        commands: r.strings(commands, "commands")?,
        icon: r.opt_string(icon, "icon")?,
    })
}

fn read_library(r: &mut Reader, v: Value<'_>) -> Result<Library, DbError> {
    let [version, path, size, sha512, provided_by, ref_count, required_by] =
        r.object(v, ["version", "path", "size", "sha512", "provided_by", "ref_count", "required_by"])?;
    Ok(Library {
        version: r.string(version, "version")?,
        path: r.string(path, "path")?,
        size: r.uint(size, "size")?,
        sha512: r.string(sha512, "sha512")?,
        provided_by: r.opt_string(provided_by, "provided_by")?,
        ref_count: r.uint(ref_count, "ref_count")?,
        required_by: r.strings(required_by, "required_by")?,
    })
}

/// Writes `db` to [`NEXT`] (durably), for the commit to swap in.
pub fn write_next(fs: &mut dyn Fs, db: &Db) -> Result<(), FsError> {
    match fs.remove_file(NEXT) {
        Ok(()) | Err(FsError::NotFound) => {}
        Err(e) => return Err(e),
    }
    fs::create_dir_all(fs, DIR)?;
    fs.create(NEXT, db.to_json().as_bytes())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn hexd(data: &[u8]) -> String {
        let mut out = [0u8; 128];
        crate::sha512::to_hex(&crate::sha512::digest(data), &mut out);
        String::from_utf8(out.to_vec()).unwrap()
    }

    fn sample() -> Db {
        let mut db = Db::empty("x86_64");
        db.generation = 3;
        db.last_tx = String::from("0000000000000003-00000000000000aa");
        let pkg = |name: &str, files: &[&str], libs: &[(&str, Resolved)]| Package {
            name: String::from(name),
            version: String::from("1.0.0"),
            kind: String::from("gui"),
            arch: String::from("x86_64"),
            license: String::from("MIT"),
            creator: None,
            installed_at: 0,
            badge: String::from("unsigned"),
            roles: Vec::new(),
            self_key: None,
            ring: 3,
            capabilities: Vec::new(),
            devices: Vec::new(),
            network: String::from("none"),
            fs: Vec::new(),
            manifest_sha512: hexd(b"m"),
            files: files.iter().map(|f| FileRec { path: String::from(*f), size: 1, sha512: hexd(f.as_bytes()) }).collect(),
            libraries: libs.iter().map(|(n, r)| LibUse { name: String::from(*n), requirement: String::from("^1.0.0"), resolved: *r, version: String::from("1.2.0") }).collect(),
            plugins: Vec::new(),
            commands: Vec::new(),
            icon: None,
        };
        db.packages.insert(String::from("org.a.one"), pkg("One", &["/apps/org.a.one/main.ncapp"], &[("libfoo", Resolved::Global)]));
        db.packages.insert(
            String::from("org.b.two"),
            pkg("Two", &["/apps/org.b.two/main.ncapp", "/apps/org.b.two/lib/libbar.ncdyn"], &[("libfoo", Resolved::Global), ("libbar", Resolved::Private)]),
        );
        db.libraries.insert(
            String::from("libfoo"),
            Library {
                version: String::from("1.2.0"),
                path: global_lib_path("libfoo"),
                size: 10,
                sha512: hexd(b"libfoo"),
                provided_by: Some(String::from("org.a.one")),
                ref_count: 2,
                required_by: alloc::vec![String::from("org.a.one"), String::from("org.b.two")],
            },
        );
        db
    }

    #[test]
    fn round_trips_through_its_file() {
        let db = sample();
        db.check().unwrap();
        let text = db.to_json();
        assert!(text.contains("\"ref_count\": 2"));
        assert_eq!(Db::parse(text.as_bytes()).unwrap(), db);
    }

    #[test]
    fn every_invariant_is_checked() {
        let breakers: &[(&str, fn(&mut Db))] = &[
            ("count disagrees", |d| d.libraries.get_mut("libfoo").unwrap().ref_count = 3),
            ("unsorted required_by", |d| d.libraries.get_mut("libfoo").unwrap().required_by.reverse()),
            ("counted but not using", |d| d.packages.get_mut("org.a.one").unwrap().libraries.clear()),
            ("using but not counted", |d| {
                let l = d.libraries.get_mut("libfoo").unwrap();
                l.required_by.remove(0);
                l.ref_count = 1;
            }),
            ("nobody requires it", |d| {
                for p in d.packages.values_mut() {
                    p.libraries.retain(|u| u.name != "libfoo");
                }
                let l = d.libraries.get_mut("libfoo").unwrap();
                l.required_by.clear();
                l.ref_count = 0;
            }),
            ("provider gone", |d| d.libraries.get_mut("libfoo").unwrap().provided_by = Some(String::from("org.c.gone"))),
            ("file claimed twice", |d| {
                let f = d.packages["org.a.one"].files[0].clone();
                d.packages.get_mut("org.b.two").unwrap().files.push(f);
            }),
            ("private copy missing", |d| d.packages.get_mut("org.b.two").unwrap().files.pop().map(|_| ()).unwrap()),
            ("version mismatch", |d| d.libraries.get_mut("libfoo").unwrap().version = String::from("1.3.0")),
            ("wrong arch", |d| d.packages.get_mut("org.a.one").unwrap().arch = String::from("aarch64")),
            ("global path elsewhere", |d| d.libraries.get_mut("libfoo").unwrap().path = String::from("/lib/libfoo.ncdyn")),
        ];
        for (what, breaker) in breakers {
            let mut db = sample();
            breaker(&mut db);
            assert!(db.check().is_err(), "{what}");
            assert!(Db::parse(db.to_json().as_bytes()).is_err(), "{what} (through the file)");
        }
    }

    #[test]
    fn rebuilding_refs_repairs_drifted_counts() {
        let mut db = sample();
        db.libraries.get_mut("libfoo").unwrap().required_by = alloc::vec![String::from("org.b.two")];
        db.libraries.get_mut("libfoo").unwrap().ref_count = 7;
        assert!(db.check().is_err());
        assert!(db.rebuild_refs().is_empty());
        db.check().unwrap();
        assert_eq!(db.libraries["libfoo"].ref_count, 2);
        db.packages.clear();
        assert_eq!(db.rebuild_refs(), ["libfoo"]);
        assert!(db.libraries.is_empty());
    }

    #[test]
    fn unknown_fields_and_other_formats_are_refused() {
        let text = sample().to_json();
        assert!(Db::parse(text.replacen("ncpkg-db/1", "ncpkg-db/2", 1).as_bytes()).is_err());
        assert!(Db::parse(text.replacen("\"generation\"", "\"colour\": 1,\n  \"generation\"", 1).as_bytes()).is_err());
        assert!(Db::parse(text.replacen("\"ring\": 3", "\"ring\": 3, \"ring\": 0", 1).as_bytes()).is_err());
    }
}
