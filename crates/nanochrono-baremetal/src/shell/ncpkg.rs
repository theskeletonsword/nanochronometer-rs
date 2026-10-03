// SPDX-License-Identifier: Apache-2.0
//! `ncpkg`: the package manager, freestanding — its read-only half.
//!
//! `info` reads a package's manifest; `verify` checks every file in it
//! against the SHA-512 the manifest lists; `list` and `files` read the
//! package database an installed system carries in `/var/lib/ncpkg/db.json`
//! (as does an initrd built on a host with `ncpkg --root`). All of it is
//! `nanochrono_core::ncpkg` — the parser the host's `ncpkg` and its tests
//! run — with no allocator: the manifest and the database are navigated in
//! place.
//!
//! `install`, `remove` and `recover` change the system. Their engine
//! (`nanochrono_core::ncpkg::manager`) needs a writable root and a heap;
//! this session has neither until NCFS is mounted, so they say so and what
//! to do instead, rather than pretend.

use super::{Out, Shell};
use core::fmt::Write;
use nanochrono_core::json::{self, Value};
use nanochrono_core::ncpkg::meta::{self, Meta, PkgType};
use nanochrono_core::ncpkg::{self, Method};

const USAGE: &str = "\
usage: ncpkg <command> [args]
  info <file.ncpkg>      what a package is, asks for and carries
  verify <file.ncpkg>    check every file against the manifest's SHA-512
  list                   installed packages, and the shared libraries in /usr/lib
  files <id>             the files an installed package owns
  install <file.ncpkg>   install it (needs a writable root: NCFS)
  remove <id>            remove it (needs a writable root: NCFS)
  recover                finish or undo an interrupted transaction
";

/// The manager's database, where the shell reads it.
const DB: &str = "/var/lib/ncpkg/db.json";

/// The window `verify` decodes compressed files through: one command runs
/// at a time.
static mut WINDOW: [u8; nanochrono_core::inflate::WINDOW] = [0; nanochrono_core::inflate::WINDOW];

pub fn run(shell: &mut Shell, out: &mut Out<'_>, argv: &[&str], _now_ns: u64) -> i32 {
    match argv.get(1).copied() {
        Some("info") => info(shell, out, argv.get(2).copied()),
        Some("verify") => verify(shell, out, argv.get(2).copied()),
        Some("list") => list(out),
        Some("files") => files(out, argv.get(2).copied()),
        Some(cmd @ ("install" | "remove" | "recover")) => {
            let _ = writeln!(out, "ncpkg: {cmd}: this session's root is read-only (NCFS is not mounted yet),\r");
            let _ = writeln!(out, "       so nothing can be installed or removed here. From a host, into a root\r");
            let _ = writeln!(out, "       this system boots from:  ncpkg --root <dir> {cmd} ...\r");
            1
        }
        Some("help" | "--help" | "-h") => {
            let _ = out.write_str(USAGE);
            0
        }
        None => {
            let _ = out.write_str(USAGE);
            2
        }
        Some(other) => {
            let _ = writeln!(out, "ncpkg: unknown command `{other}` (ncpkg help)\r");
            2
        }
    }
}

fn bytes_at(shell: &Shell, out: &mut Out<'_>, arg: Option<&str>) -> Option<&'static [u8]> {
    let Some(arg) = arg else {
        let _ = writeln!(out, "ncpkg: which package? (ncpkg help)\r");
        return None;
    };
    let path = crate::vfs::resolve(shell.cwd.as_str(), arg);
    match crate::vfs::lookup(path.as_str()) {
        Some(crate::vfs::Node { content: crate::vfs::Content::Bytes(b), .. }) => Some(b),
        Some(_) => {
            let _ = writeln!(out, "ncpkg: {arg}: not a file\r");
            None
        }
        None => {
            let _ = writeln!(out, "ncpkg: {arg}: no such file\r");
            None
        }
    }
}

/// The container and the manifest, both checked.
fn open<'a>(out: &mut Out<'_>, arg: &str, bytes: &'a [u8]) -> Option<(ncpkg::Package<'a>, Meta<'a>)> {
    let pkg = match ncpkg::Package::parse(bytes) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(out, "ncpkg: {arg}: {e}\r");
            return None;
        }
    };
    let meta = match Meta::parse(pkg.meta()).and_then(|m| m.check_container(&pkg).map(|_| m)) {
        Ok(m) => m,
        Err(e) => {
            let _ = writeln!(out, "ncpkg: {arg}: {e}\r");
            return None;
        }
    };
    Some((pkg, meta))
}

fn size(out: &mut Out<'_>, n: u64) {
    let _ = match n {
        0..=1023 => write!(out, "{n} B"),
        1024..=1_048_575 => write!(out, "{:.1} KiB", n as f64 / 1024.0),
        _ => write!(out, "{:.1} MiB", n as f64 / 1_048_576.0),
    };
}

fn info(shell: &mut Shell, out: &mut Out<'_>, arg: Option<&str>) -> i32 {
    let Some(bytes) = bytes_at(shell, out, arg) else { return 1 };
    let arg = arg.unwrap_or("");
    let Some((pkg, meta)) = open(out, arg, bytes) else { return 1 };
    let here = nanochrono_core::ncplu::Arch::native();
    let _ = writeln!(out, "{} {}  ({})\r", meta.name(), meta.version(), meta.id());
    let _ = writeln!(out, "  type          {}\r", meta.kind().name());
    if let Some(s) = meta.summary() {
        let _ = writeln!(out, "  summary       {s}\r");
    }
    let licence = meta.license_or_default();
    let explained = meta::license_explain(licence);
    let none_given = if meta.license().is_none() { " (none given)" } else { "" };
    if explained.is_empty() {
        let _ = writeln!(out, "  licence       {licence}{none_given}\r");
    } else {
        let _ = writeln!(out, "  licence       {licence}{none_given}: {explained}\r");
    }
    match meta.creator() {
        Some(c) => {
            let _ = write!(out, "  creator       {}", c.name);
            if let Some(e) = c.email {
                let _ = write!(out, " <{e}>");
            }
            let _ = writeln!(out, "\r");
        }
        None => {
            let _ = writeln!(out, "  creator       anonymous\r");
        }
    }
    let _ = write!(out, "  arch         ");
    for a in meta.arches() {
        let _ = write!(out, " {}", a.name());
    }
    let fits = if here.is_some_and(|a| meta.supports(a)) { "runs here" } else { "not for this machine" };
    let _ = writeln!(out, "  ({fits}: {})\r", here.map_or("?", |a| a.name()));
    let ring = meta.ring();
    let _ = writeln!(out, "  ring          {ring}{}\r", if ring == 0 { " (needs a ring-0 signature, or the community switch)" } else { "" });
    if let Some(app) = meta.app() {
        let _ = write!(out, "  capabilities ");
        for (name, bit) in meta::CAPABILITIES {
            if app.capabilities & bit != 0 {
                let _ = write!(out, " {name}");
            }
        }
        let _ = writeln!(out, "\r");
        let mut commands = app.commands().peekable();
        if commands.peek().is_some() {
            let _ = write!(out, "  commands     ");
            for c in commands {
                let _ = write!(out, " {c}");
            }
            let _ = writeln!(out, "\r");
        }
    }
    let perms = meta.permissions();
    let _ = write!(out, "  permissions   network {}", perms.network.name());
    for d in perms.devices() {
        let _ = write!(out, ", {}", d.node());
    }
    for g in perms.fs() {
        let _ = write!(out, ", {} ({})", g.path, g.access.name());
    }
    let _ = writeln!(out, "\r");
    for u in meta.uses() {
        match u.shipped {
            Some(s) => {
                let _ = writeln!(out, "  library       {} {} (carried; accepts {})\r", u.name, s.version, u.requirement);
            }
            None => {
                let _ = writeln!(out, "  library       {} (needs {}; not carried)\r", u.name, u.requirement);
            }
        }
    }
    for p in meta.plugins() {
        let _ = write!(out, "  plugin        {} for {}", p.file, p.host);
        let mut provides = p.provides().peekable();
        if provides.peek().is_some() {
            let _ = write!(out, ":");
            for t in provides {
                let _ = write!(out, " {t}");
            }
        }
        let _ = writeln!(out, "\r");
    }
    let (stored, unpacked) = pkg.files().fold((0u64, 0u64), |(s, u), e| (s + e.stored.len() as u64, u + e.size));
    let _ = write!(out, "  files         {}, ", meta.file_count());
    size(out, stored);
    let _ = write!(out, " stored, ");
    size(out, unpacked);
    let _ = writeln!(out, " unpacked\r");
    let mut sigs = meta.signatures().peekable();
    if sigs.peek().is_none() {
        let _ = writeln!(out, "  signatures    none: community code, ring 3\r");
    }
    for s in sigs {
        let _ = writeln!(out, "  signature     {} ({}, key {})\r", s.role.name(), s.alg, s.key);
    }
    if meta.signatures().next().is_some() {
        let _ = writeln!(out, "                checked by `ncpkg install`; this kernel checks each app's own signature when it runs\r");
    }
    if meta.kind() == PkgType::Lib {
        let _ = writeln!(out, "  (a library package: nothing to run, its libraries go to /usr/lib)\r");
    }
    0
}

fn verify(shell: &mut Shell, out: &mut Out<'_>, arg: Option<&str>) -> i32 {
    let Some(bytes) = bytes_at(shell, out, arg) else { return 1 };
    let arg = arg.unwrap_or("");
    let Some((pkg, meta)) = open(out, arg, bytes) else { return 1 };
    // SAFETY: one command runs at a time, and only this one uses WINDOW.
    let window = unsafe { &mut *core::ptr::addr_of_mut!(WINDOW) };
    let (mut good, mut bad) = (0, 0);
    for e in pkg.files() {
        let listed = meta.file(e.path);
        let result = e.sha512(window);
        let ok = matches!((listed, result), (Some(l), Ok(d)) if nanochrono_core::sha512::ct_eq(&l.sha512, &d));
        let how = if e.method == Method::Deflate { "deflate" } else { "stored " };
        match (ok, result) {
            (true, _) => {
                good += 1;
                let _ = writeln!(out, "  ok        {how} {}\r", e.path);
            }
            (false, Err(err)) => {
                bad += 1;
                let _ = writeln!(out, "  BROKEN    {how} {}: {err}\r", e.path);
            }
            (false, Ok(_)) => {
                bad += 1;
                let _ = writeln!(out, "  MISMATCH  {how} {}\r", e.path);
            }
        }
    }
    if bad == 0 {
        let _ = writeln!(out, "{arg}: all {good} files match the manifest\r");
        0
    } else {
        let _ = writeln!(out, "{arg}: {bad} of {} files do not match: damaged or altered\r", good + bad);
        1
    }
}

/// The database, if this tree has one.
fn database(out: &mut Out<'_>) -> Option<Value<'static>> {
    let Some(crate::vfs::Node { content: crate::vfs::Content::Bytes(bytes), .. }) = crate::vfs::lookup(DB) else {
        let _ = writeln!(out, "no package database ({DB}): nothing is installed in this tree.\r");
        let _ = writeln!(out, "An initrd built on a host with `ncpkg --root <dir> install ...` carries one.\r");
        return None;
    };
    match json::parse(bytes, &json::Limits::DATABASE) {
        Ok(v) if v.get("format").and_then(|f| f.as_str()).is_some_and(|f| f.eq_str("ncpkg-db/1")) => Some(v),
        Ok(_) => {
            let _ = writeln!(out, "ncpkg: {DB}: not an ncpkg-db/1 database\r");
            None
        }
        Err(e) => {
            let _ = writeln!(out, "ncpkg: {DB}: {e}\r");
            None
        }
    }
}

/// A string member, for display: the string, or `?` if it is missing.
struct Field<'a>(Option<json::Str<'a>>);

impl core::fmt::Display for Field<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(s) => core::fmt::Display::fmt(&s, f),
            None => f.pad("?"),
        }
    }
}

fn field<'a>(v: Value<'a>, key: &str) -> Field<'a> {
    Field(v.get(key).and_then(|x| x.as_str()))
}

fn list(out: &mut Out<'_>) -> i32 {
    let Some(db) = database(out) else { return 0 };
    let packages = db.get("packages");
    let n = packages.map_or(0, |p| p.len());
    let _ = writeln!(out, "{n} package{} installed\r", if n == 1 { "" } else { "s" });
    for (id, p) in packages.into_iter().flat_map(|p| p.members()) {
        let _ = writeln!(out, "  {:<40} {:<12} {:<4} {}\r", id, field(p, "version"), field(p, "type"), field(p, "badge"));
    }
    let libs = db.get("libraries");
    let n = libs.map_or(0, |l| l.len());
    let _ = writeln!(out, "{n} shared librar{} in /usr/lib\r", if n == 1 { "y" } else { "ies" });
    for (name, l) in libs.into_iter().flat_map(|l| l.members()) {
        let refs = l.get("ref_count").and_then(|r| r.as_u64()).unwrap_or(0);
        let _ = write!(out, "  {:<24} {:<14} refs {refs}:", name, field(l, "version"));
        for r in l.get("required_by").into_iter().flat_map(|r| r.elements()) {
            if let Some(s) = r.as_str() {
                let _ = write!(out, " {s}");
            }
        }
        let _ = writeln!(out, "\r");
    }
    0
}

fn files(out: &mut Out<'_>, id: Option<&str>) -> i32 {
    let Some(id) = id else {
        let _ = writeln!(out, "usage: ncpkg files <id>\r");
        return 2;
    };
    let Some(db) = database(out) else { return 1 };
    let Some(p) = db.get("packages").and_then(|p| p.get(id)) else {
        let _ = writeln!(out, "ncpkg: {id} is not installed\r");
        return 1;
    };
    for f in p.get("files").into_iter().flat_map(|f| f.elements()) {
        let s = f.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
        let _ = writeln!(out, "  {:>10}  {}\r", s, field(f, "path"));
    }
    0
}
