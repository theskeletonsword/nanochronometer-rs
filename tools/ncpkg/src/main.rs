// SPDX-License-Identifier: Apache-2.0
//! `ncpkg` on a host: build, sign and check `.ncpkg` packages, and install
//! and remove them in a NanoChronometer root — an NCFS volume mounted
//! through FUSE, or the staging tree an ISO's root image is made from.
//!
//! The format, the manifest, the database and the transaction engine are
//! `nanochrono_core::ncpkg`, the same code the system runs; this is the
//! command line, the cryptography (`crypto`) and the TOML front end
//! (`source`). `docs/NCPKG.md` is the reference.
//!
//! ```text
//! ncpkg build mypkg/ -o mypkg.ncpkg
//! ncpkg sign mypkg.ncpkg --role creator-ring3 --keys ~/keys/creator-ring3
//! ncpkg sign mypkg.ncpkg --role self --key ~/keys/me.ncpkg-key
//! ncpkg verify mypkg.ncpkg --roots ~/keys/roots
//! sudo ncpkg install mypkg.ncpkg --root /mnt/ncfs --roots ~/keys/roots
//! sudo ncpkg remove org.example.app --root /mnt/ncfs
//! ```

mod crypto;
mod source;

use clap::{Args, Parser, Subcommand};
use nanochrono_core::json::{self, Json};
use nanochrono_core::ncpkg::fs::StdFs;
use nanochrono_core::ncpkg::manager::{Error, InstallOptions, LibChange, Manager, Outcome, Plan, Policy, Recovery};
use nanochrono_core::ncpkg::meta::{self, Meta};
use nanochrono_core::ncpkg::sig::{self, Role, Scratch, Verifier};
use nanochrono_core::ncpkg::{base64, Package};
use nanochrono_core::ncplu::Arch;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "ncpkg", version, about = "NanoChronometer packages: build, sign, verify, install, remove")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Trust {
    /// A directory of root public keys: creator-ring3.pub, creator-ring0.pub,
    /// verify-ring3.pub, verify-ring0.pub (each an ncplu-sign root_pubkeys.bin).
    #[arg(long, env = "NCPKG_ROOTS")]
    roots: Option<PathBuf>,
    /// The owner's enrolled self-signing keys: one fingerprint per line.
    #[arg(long)]
    owner_keys: Option<PathBuf>,
}

#[derive(Args)]
struct System {
    /// The system's root: an NCFS mount, or a staging tree.
    #[arg(long, env = "NCPKG_ROOT")]
    root: PathBuf,
    /// The machine the root is for (default: its database's, else this host's).
    #[arg(long)]
    arch: Option<String>,
    /// The NanoChronometer version the root runs.
    #[arg(long)]
    system_version: Option<String>,
    /// Refuse unsigned packages.
    #[arg(long)]
    require_signature: bool,
    /// Enable Ring0 Community Modules and Drivers (off by default).
    #[arg(long)]
    community_ring0: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build a package from a source directory (ncpkg.toml, ncapp/, lib/, plugins/, res/).
    Build {
        src: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Store every file uncompressed.
        #[arg(long)]
        store: bool,
    },
    /// What a package file is and holds.
    Inspect { package: PathBuf },
    /// Check every file against the manifest, and every signature.
    Verify {
        package: PathBuf,
        #[command(flatten)]
        trust: Trust,
    },
    /// Make a self-signing key: ed25519, p256, p384, p521, mldsa65, mldsa87, or a pair (mldsa65+ed25519).
    Keygen {
        #[arg(long)]
        alg: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a package in place: a root role with an ncplu-sign key directory, or `self` with a key file.
    Sign {
        package: PathBuf,
        #[arg(long)]
        role: String,
        /// An ncplu-sign keygen directory (root roles).
        #[arg(long, conflicts_with = "key")]
        keys: Option<PathBuf>,
        /// A key file from `ncpkg keygen` (role self).
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Write the exact bytes a signature in ROLE signs, for an offline signer or an HSM.
    Message {
        package: PathBuf,
        #[arg(long)]
        role: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Attach a signature made elsewhere (OpenSSL, an HSM), after checking it.
    Attach {
        package: PathBuf,
        #[arg(long)]
        role: String,
        #[arg(long)]
        alg: String,
        /// The raw signature bytes.
        #[arg(long)]
        sig: PathBuf,
        /// The public key: a root's NCROOT01 file, or for `self` the raw key bytes.
        #[arg(long)]
        pubkey: PathBuf,
    },
    /// Install a package into a root.
    Install {
        package: PathBuf,
        #[command(flatten)]
        sys: System,
        #[command(flatten)]
        trust: Trust,
        /// Do not ask.
        #[arg(short, long)]
        yes: bool,
        #[arg(long)]
        reinstall: bool,
        #[arg(long)]
        allow_downgrade: bool,
        /// Overwrite files no package owns.
        #[arg(long)]
        force: bool,
    },
    /// Remove an installed package.
    Remove {
        id: String,
        #[command(flatten)]
        sys: System,
        #[arg(short, long)]
        yes: bool,
    },
    /// Installed packages and shared libraries.
    List {
        #[command(flatten)]
        sys: System,
    },
    /// An installed package (with --root), or a package file.
    Info {
        what: String,
        #[arg(long, env = "NCPKG_ROOT")]
        root: Option<PathBuf>,
    },
    /// The files an installed package owns.
    Files {
        id: String,
        #[command(flatten)]
        sys: System,
    },
    /// Check the database and every installed file's SHA-512.
    Check {
        #[command(flatten)]
        sys: System,
    },
    /// Finish or undo an interrupted transaction.
    Recover {
        #[command(flatten)]
        sys: System,
        /// Also remove a lock a crashed ncpkg left (only when none is running).
        #[arg(long)]
        force_unlock: bool,
    },
}

/// A failure, with the exit status it means.
struct Fail(u8, String);

impl From<String> for Fail {
    fn from(s: String) -> Fail {
        Fail(1, s)
    }
}

impl From<&Error> for Fail {
    fn from(e: &Error) -> Fail {
        let code = match e {
            Error::Locked(_) => 5,
            Error::Tampered(_)
            | Error::Unsigned
            | Error::Ring0NotAllowed
            | Error::WrongArch { .. }
            | Error::AbiMismatch { .. }
            | Error::SystemTooOld { .. }
            | Error::Reserved(_)
            | Error::FileHash(_)
            | Error::Module { .. } => 3,
            Error::FileConflict { .. }
            | Error::CommandConflict { .. }
            | Error::LibraryConflict { .. }
            | Error::HasDependents { .. }
            | Error::HostMissing { .. }
            | Error::MissingLibrary { .. }
            | Error::AlreadyInstalled { .. }
            | Error::Downgrade { .. } => 4,
            _ => 1,
        };
        Fail(code, e.to_string())
    }
}

fn read(path: &Path) -> Result<Vec<u8>, Fail> {
    std::fs::read(path).map_err(|e| Fail(1, format!("{}: {e}", path.display())))
}

/// Writes beside the target, then renames over it.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), Fail> {
    let tmp = path.with_extension("ncpkg.tmp");
    std::fs::write(&tmp, data).and_then(|_| std::fs::rename(&tmp, path)).map_err(|e| Fail(1, format!("{}: {e}", path.display())))
}

fn open(bytes: &[u8]) -> Result<(Package<'_>, Meta<'_>), Fail> {
    let pkg = Package::parse(bytes).map_err(|e| Fail(3, format!("not a valid package: {e}")))?;
    let meta = Meta::parse(pkg.meta()).map_err(|e| Fail(3, format!("bad manifest: {e}")))?;
    meta.check_container(&pkg).map_err(|e| Fail(3, format!("bad manifest: {e}")))?;
    Ok((pkg, meta))
}

fn role(name: &str) -> Result<Role, Fail> {
    Role::from_name(name).ok_or_else(|| Fail(2, format!("unknown role {name:?}: creator-ring3, creator-ring0, verify-ring3, verify-ring0 or self")))
}

fn human(n: u64) -> String {
    match n {
        0..=1023 => format!("{n} B"),
        1024..=1_048_575 => format!("{:.1} KiB", n as f64 / 1024.0),
        _ => format!("{:.1} MiB", n as f64 / 1_048_576.0),
    }
}

/// Unix seconds as `YYYY-MM-DD hh:mm:ss UTC` (the civil-from-days
/// algorithm, so no date crate for one line of output).
fn utc(secs: u64) -> String {
    if secs == 0 {
        return String::from("unknown (no clock at install time)");
    }
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, rem / 60 % 60, rem % 60)
}

fn arch_of(sys: &System) -> Result<Arch, Fail> {
    if let Some(a) = &sys.arch {
        return nanochrono_core::ncpkg::path::arch_dir(a).ok_or_else(|| Fail(2, format!("unknown architecture {a:?}")));
    }
    // The database says which machine the root is for.
    let db = sys.root.join("var/lib/ncpkg/db.json");
    if let Ok(text) = std::fs::read(&db) {
        if let Some(a) = json::parse(&text, &json::Limits::DATABASE).ok().and_then(|v| v.get("arch")).and_then(|a| a.as_str()).and_then(|a| a.as_plain()).and_then(nanochrono_core::ncpkg::path::arch_dir) {
            return Ok(a);
        }
    }
    Arch::native().ok_or_else(|| Fail(2, String::from("this host is none of the nine architectures: pass --arch")))
}

fn policy(sys: &System) -> Result<Policy, Fail> {
    let mut p = Policy::new(arch_of(sys)?, sys.system_version.as_deref().unwrap_or(nanochrono_core::VERSION));
    p.require_signature = sys.require_signature;
    p.community_ring0 = sys.community_ring0;
    p.now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| Fail(1, format!("no randomness: {e}")))?;
    p.nonce = u64::from_le_bytes(nonce);
    p.owner = format!("ncpkg pid {} ({})", std::process::id(), sys.root.display());
    Ok(p)
}

fn confirm(yes: bool) -> impl FnMut(&Plan) -> bool {
    move |plan: &Plan| {
        print_plan(plan);
        if yes {
            return true;
        }
        if !std::io::stdin().is_terminal() {
            eprintln!("ncpkg: not a terminal, and no --yes: nothing done");
            return false;
        }
        print!("Proceed? [y/N] ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        matches!(line.trim(), "y" | "Y" | "yes")
    }
}

fn print_plan(p: &Plan) {
    let what = match (&p.previous, p.op) {
        (Some(prev), _) => format!("{} from {prev}", p.op.name()),
        (None, op) => String::from(op.name()),
    };
    println!("{} {} {} ({}): {what}", p.id, p.name, p.version, p.kind.name());
    if p.op != nanochrono_core::ncpkg::manager::Op::Remove {
        let symbol = p.badge.symbol();
        println!("  trust      {}{}{} · ring {}", symbol, if symbol.is_empty() { "" } else { " " }, p.badge.label(), p.ring);
    }
    for l in &p.libraries {
        let how = match &l.change {
            LibChange::NewGlobal => format!("new in /usr/lib (refs {})", l.refs),
            LibChange::Share => format!("shared, /usr/lib (refs {})", l.refs),
            LibChange::UpgradeGlobal { from } => format!("/usr/lib copy upgraded from {from} (refs {})", l.refs),
            LibChange::Private { global: Some(g) } => format!("private copy (/usr/lib has {g}, which it does not accept)"),
            LibChange::Private { global: None } => String::from("private copy (not shared)"),
            LibChange::Release => format!("one reference fewer (refs {})", l.refs),
            LibChange::Delete => String::from("removed (no references left)"),
        };
        println!("  library    {} {}: {how}", l.name, l.version);
    }
    if p.files > 0 {
        println!("  files      {} to write ({}), {} to replace or remove", p.files, human(p.bytes), p.removed);
    } else {
        println!("  files      {} to remove", p.removed);
    }
    for w in &p.warnings {
        println!("  warning    {w}");
    }
}

fn verify_cmd(path: &Path, trust: &Trust) -> Result<(), Fail> {
    let bytes = read(path)?;
    let (pkg, meta) = open(&bytes)?;
    let mut bad = 0;
    for e in pkg.files() {
        let listed = meta.file(e.path).ok_or_else(|| Fail(3, format!("{}: not in the manifest", e.path)))?;
        let ok = e.read().map(|d| nanochrono_core::sha512::digest(&d) == listed.sha512);
        match ok {
            Ok(true) => println!("  ok        {} {}", e.method.name(), e.path),
            Ok(false) => {
                bad += 1;
                println!("  MISMATCH  {} {}", e.method.name(), e.path);
            }
            Err(err) => {
                bad += 1;
                println!("  BROKEN    {} {}: {err}", e.method.name(), e.path);
            }
        }
    }
    let mut v = crypto::HostVerifier::load(trust.roots.as_deref(), trust.owner_keys.as_deref())?;
    let trust_result = meta.verify(&mut v, &mut Box::new(Scratch::new()));
    for s in meta.signatures() {
        let state = if trust_result.has(s.role) {
            "valid"
        } else if trust_result.failed(s.role) {
            bad += 1;
            "INVALID: changed after signing"
        } else if s.role.is_root() && v.root_fingerprint(s.role).is_none() {
            "not checked: no root for this role (--roots)"
        } else {
            "not checked: a key this host does not trust for the role"
        };
        println!("  signature {} ({}, key {}): {state}", s.role.name(), s.alg, s.key);
    }
    let badge = trust_result.badge();
    println!("{}: {} {} — {} files, badge: {}", path.display(), meta.id(), meta.version(), meta.file_count(), badge.label());
    if bad > 0 {
        return Err(Fail(3, format!("{bad} problem{}", if bad == 1 { "" } else { "s" })));
    }
    Ok(())
}

fn inspect(path: &Path) -> Result<(), Fail> {
    let bytes = read(path)?;
    let (pkg, meta) = open(&bytes)?;
    println!("{} {} ({})  {}", meta.name(), meta.version(), meta.id(), meta.kind().name());
    if let Some(s) = meta.summary() {
        println!("  {s}");
    }
    let lic = meta.license_or_default();
    let explain = meta::license_explain(lic);
    println!("  licence     {lic}{}{}", if meta.license().is_none() { " (none given)" } else { "" }, if explain.is_empty() { String::new() } else { format!(": {explain}") });
    match meta.creator() {
        Some(c) => println!("  creator     {}{}", c.name, c.email.map(|e| format!(" <{e}>")).unwrap_or_default()),
        None => println!("  creator     anonymous"),
    }
    println!("  arch        {}", meta.arches().map(|a| a.name()).collect::<Vec<_>>().join(" "));
    println!("  abi         {}{}", meta.abi(), meta.system().map(|s| format!(", system {s}")).unwrap_or_default());
    println!("  ring        {}", meta.ring());
    if let Some(app) = meta.app() {
        let caps: Vec<&str> = meta::CAPABILITIES.iter().filter(|(_, b)| app.capabilities & b != 0).map(|(n, _)| *n).collect();
        println!("  app         {} · capabilities: {}", app.entry, if caps.is_empty() { String::from("none") } else { caps.join(" ") });
        let cmds: Vec<&str> = app.commands().collect();
        if !cmds.is_empty() {
            println!("  commands    {}", cmds.join(" "));
        }
    }
    let p = meta.permissions();
    let devices: Vec<&str> = p.devices().map(|d| d.node()).collect();
    let fs: Vec<String> = p.fs().map(|g| format!("{} ({})", g.path, g.access.name())).collect();
    println!("  permissions network {}{}{}", p.network.name(), if devices.is_empty() { String::new() } else { format!("; {}", devices.join(" ")) }, if fs.is_empty() { String::new() } else { format!("; {}", fs.join(", ")) });
    for u in meta.uses() {
        match u.shipped {
            Some(s) => println!("  library     {} {} (carried{}; accepts {})", u.name, s.version, if s.share { "" } else { ", never shared" }, u.requirement),
            None => println!("  library     {} (needs {})", u.name, u.requirement),
        }
    }
    for pl in meta.plugins() {
        println!("  plugin      {} for {}: {}", pl.file, pl.host, pl.provides().collect::<Vec<_>>().join(" "));
    }
    for s in meta.signatures() {
        println!("  signature   {} {} key {}", s.role.name(), s.alg, s.key);
    }
    println!("  files:");
    let (mut stored, mut size) = (0u64, 0u64);
    for e in pkg.files() {
        stored += e.stored.len() as u64;
        size += e.size;
        println!("    {:<8} {:>10} {:>10}  {}", e.method.name(), e.stored.len(), e.size, e.path);
    }
    println!("  {} files, {} stored, {} unpacked; package {}", meta.file_count(), human(stored), human(size), human(bytes.len() as u64));
    Ok(())
}

/// Replaces `role`'s signature (or adds it) and rewrites the package in place.
fn put_signature(path: &Path, role: Role, entry: Json) -> Result<(), Fail> {
    let bytes = read(path)?;
    let (pkg, meta) = open(&bytes)?;
    let root = json::parse(meta.text(), &json::Limits::MANIFEST).map_err(|e| Fail(1, e.to_string()))?;
    let mut sigs: Vec<Json> = Vec::new();
    for s in root.get("signatures").into_iter().flat_map(|s| s.elements()) {
        if s.get("role").and_then(|r| r.as_str()).is_some_and(|r| r.eq_str(role.name())) {
            continue;
        }
        sigs.push(s.to_json().ok_or_else(|| Fail(1, String::from("unreadable signature entry")))?);
    }
    sigs.push(entry);
    let signed = std::str::from_utf8(meta.signed_bytes()).map_err(|_| Fail(1, String::from("manifest not UTF-8")))?;
    let manifest = meta::build::splice(signed, &sigs);
    // The new manifest must still parse, and keep the signed bytes exactly.
    let check = Meta::parse(manifest.as_bytes()).map_err(|e| Fail(1, format!("internal: the signed manifest does not parse: {e}")))?;
    if check.signed_bytes() != meta.signed_bytes() {
        return Err(Fail(1, String::from("internal: signing changed the signed bytes")));
    }
    let out = pkg.with_meta(manifest.as_bytes()).map_err(|e| Fail(1, e.to_string()))?;
    write_atomic(path, &out)
}

fn sign_cmd(path: &Path, role_name: &str, keys: Option<&Path>, key: Option<&Path>) -> Result<(), Fail> {
    let role = role(role_name)?;
    let secret = match (role.is_root(), keys, key) {
        (true, Some(dir), None) => crypto::SecretKey::load_root_dir(dir)?,
        (true, _, _) => return Err(Fail(2, format!("{}: a root role signs with --keys <ncplu-sign key directory>", role.name()))),
        (false, None, Some(k)) => crypto::SecretKey::load(k)?,
        (false, _, _) => return Err(Fail(2, String::from("self: sign with --key <file from ncpkg keygen>"))),
    };
    let bytes = read(path)?;
    let (_, meta) = open(&bytes)?;
    let message = sig::Message::new(role, meta.signed_bytes());
    let signature = secret.sign(message.as_bytes())?;
    let public = secret.public();
    let pubkey = (!role.is_root()).then(|| base64::encode_string(&public));
    let fp = secret.fingerprint();
    let entry = meta::build::signature(role.name(), &secret.alg, &fp, pubkey.as_deref(), &base64::encode_string(&signature));
    put_signature(path, role, entry)?;
    println!("{}: signed as {} ({}, key {fp})", path.display(), role.name(), secret.alg);
    Ok(())
}

fn attach_cmd(path: &Path, role_name: &str, alg: &str, sig_path: &Path, pubkey_path: &Path) -> Result<(), Fail> {
    let role = role(role_name)?;
    if role.is_root() && alg != sig::ROOT_ALG {
        return Err(Fail(2, format!("root roles use {}", sig::ROOT_ALG)));
    }
    let public = if role.is_root() { crypto::read_root_pub(pubkey_path)? } else { read(pubkey_path)? };
    let signature = read(sig_path)?;
    let bytes = read(path)?;
    let (_, meta) = open(&bytes)?;
    let message = sig::Message::new(role, meta.signed_bytes());
    match crypto::verify_all(alg, &public, message.as_bytes(), &signature) {
        Some(true) => {}
        Some(false) => return Err(Fail(3, String::from("the signature does not verify over this package's message (ncpkg message)"))),
        None => return Err(Fail(2, format!("unknown algorithm {alg:?}"))),
    }
    let fp = crypto::fingerprint(&public);
    let pubkey = (!role.is_root()).then(|| base64::encode_string(&public));
    let entry = meta::build::signature(role.name(), alg, &fp, pubkey.as_deref(), &base64::encode_string(&signature));
    put_signature(path, role, entry)?;
    println!("{}: attached {} ({alg}, key {fp})", path.display(), role.name());
    Ok(())
}

fn install_cmd(path: &Path, sys: &System, trust: &Trust, yes: bool, opts: InstallOptions) -> Result<(), Fail> {
    let bytes = read(path)?;
    let mut verifier = crypto::HostVerifier::load(trust.roots.as_deref(), trust.owner_keys.as_deref())?;
    let mut fs = StdFs::new(&sys.root);
    let mut m = Manager::new(&mut fs, policy(sys)?);
    match m.install(&bytes, &mut verifier as &mut dyn Verifier, &opts, &mut confirm(yes)).map_err(|e| Fail::from(&e))? {
        Outcome::Done { op, id, version, tx, cleanup_pending } => {
            println!("{} {id} {version} (transaction {tx})", op.name());
            if cleanup_pending {
                println!("note: committed, but the clean-up did not finish; `ncpkg recover` finishes it");
            }
            Ok(())
        }
        Outcome::Cancelled => Err(Fail(1, String::from("nothing done"))),
    }
}

fn remove_cmd(id: &str, sys: &System, yes: bool) -> Result<(), Fail> {
    let mut fs = StdFs::new(&sys.root);
    let mut m = Manager::new(&mut fs, policy(sys)?);
    match m.remove(id, &mut confirm(yes)).map_err(|e| Fail::from(&e))? {
        Outcome::Done { tx, cleanup_pending, .. } => {
            println!("removed {id} (transaction {tx})");
            if cleanup_pending {
                println!("note: committed, but the clean-up did not finish; `ncpkg recover` finishes it");
            }
            Ok(())
        }
        Outcome::Cancelled => Err(Fail(1, String::from("nothing done"))),
    }
}

fn list_cmd(sys: &System) -> Result<(), Fail> {
    let mut fs = StdFs::new(&sys.root);
    let db = Manager::new(&mut fs, policy(sys)?).load_db().map_err(|e| Fail::from(&e))?;
    println!("{} package{} ({}, generation {})", db.packages.len(), if db.packages.len() == 1 { "" } else { "s" }, db.arch, db.generation);
    for (id, p) in &db.packages {
        println!("  {id:<40} {:<14} {:<4} ring {} {}", p.version, p.kind, p.ring, p.badge);
    }
    println!("{} shared librar{} in /usr/lib", db.libraries.len(), if db.libraries.len() == 1 { "y" } else { "ies" });
    for (name, l) in &db.libraries {
        println!("  {name:<24} {:<14} refs {}: {}", l.version, l.ref_count, l.required_by.join(" "));
    }
    Ok(())
}

fn info_cmd(what: &str, root: Option<&Path>) -> Result<(), Fail> {
    if let Some(root) = root {
        let sys = System { root: root.to_path_buf(), arch: None, system_version: None, require_signature: false, community_ring0: false };
        let mut fs = StdFs::new(root);
        let db = Manager::new(&mut fs, policy(&sys)?).load_db().map_err(|e| Fail::from(&e))?;
        if let Some(p) = db.packages.get(what) {
            println!("{what} {} {} ({}, {})", p.name, p.version, p.kind, p.arch);
            println!("  licence     {}", p.license);
            println!("  creator     {}", p.creator.as_deref().unwrap_or("anonymous"));
            println!("  trust       {} ({}) · ring {}", p.badge, if p.roles.is_empty() { String::from("no valid signature") } else { p.roles.join(", ") }, p.ring);
            println!("  installed   {}", utc(p.installed_at));
            let or_none = |v: String| if v.is_empty() { String::from("none") } else { v };
            println!(
                "  permissions network {}; devices {}; fs {}",
                p.network,
                or_none(p.devices.join(" ")),
                or_none(p.fs.iter().map(|(a, b)| format!("{a} ({b})")).collect::<Vec<_>>().join(", "))
            );
            for u in &p.libraries {
                println!("  library     {} {} ({}, accepts {})", u.name, u.version, u.resolved.name(), u.requirement);
            }
            for pl in &p.plugins {
                println!("  plugin      {} for {}", pl.path, pl.host);
            }
            for c in &p.commands {
                println!("  command     /usr/bin/{c}");
            }
            println!("  files       {}", p.files.len());
            return Ok(());
        }
    }
    let path = Path::new(what);
    if path.exists() {
        return inspect(path);
    }
    Err(Fail(1, format!("{what}: not installed{} and no such file", if root.is_some() { "" } else { " (no --root)" })))
}

fn run(cli: Cli) -> Result<(), Fail> {
    match cli.cmd {
        Cmd::Build { src, output, store } => {
            let built = source::build(&src, !store)?;
            let out = output.unwrap_or_else(|| PathBuf::from(format!("{}-{}.ncpkg", built.id, built.version)));
            write_atomic(&out, &built.bytes)?;
            println!("{}: {} {} — {} files ({} compressed), {}", out.display(), built.id, built.version, built.files, built.compressed, human(built.bytes.len() as u64));
            Ok(())
        }
        Cmd::Inspect { package } => inspect(&package),
        Cmd::Verify { package, trust } => verify_cmd(&package, &trust),
        Cmd::Keygen { alg, out } => {
            let key = crypto::SecretKey::generate(&alg)?;
            if out.exists() {
                return Err(Fail(1, format!("{}: exists; not overwriting a key", out.display())));
            }
            std::fs::write(&out, key.to_file()).map_err(|e| Fail(1, format!("{}: {e}", out.display())))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600));
            }
            println!("{}: {alg} key {}", out.display(), key.fingerprint());
            println!("keep it out of any repository; enrol the fingerprint on a machine to show it as an owner key");
            Ok(())
        }
        Cmd::Sign { package, role, keys, key } => sign_cmd(&package, &role, keys.as_deref(), key.as_deref()),
        Cmd::Message { package, role: r, output } => {
            let bytes = read(&package)?;
            let (_, meta) = open(&bytes)?;
            let message = sig::Message::new(role(&r)?, meta.signed_bytes());
            std::fs::write(&output, message.as_bytes()).map_err(|e| Fail(1, format!("{}: {e}", output.display())))?;
            println!("{}: {} bytes to sign as {r}", output.display(), message.as_bytes().len());
            Ok(())
        }
        Cmd::Attach { package, role, alg, sig, pubkey } => attach_cmd(&package, &role, &alg, &sig, &pubkey),
        Cmd::Install { package, sys, trust, yes, reinstall, allow_downgrade, force } => {
            install_cmd(&package, &sys, &trust, yes, InstallOptions { reinstall, allow_downgrade, force })
        }
        Cmd::Remove { id, sys, yes } => remove_cmd(&id, &sys, yes),
        Cmd::List { sys } => list_cmd(&sys),
        Cmd::Info { what, root } => info_cmd(&what, root.as_deref()),
        Cmd::Files { id, sys } => {
            let mut fs = StdFs::new(&sys.root);
            let db = Manager::new(&mut fs, policy(&sys)?).load_db().map_err(|e| Fail::from(&e))?;
            let p = db.packages.get(&id).ok_or_else(|| Fail(1, format!("{id} is not installed")))?;
            for f in &p.files {
                println!("{:>10}  {}", f.size, f.path);
            }
            Ok(())
        }
        Cmd::Check { sys } => {
            let mut fs = StdFs::new(&sys.root);
            let problems = Manager::new(&mut fs, policy(&sys)?).check().map_err(|e| Fail::from(&e))?;
            for p in &problems {
                println!("  {}: {}", p.path, p.what);
            }
            if problems.is_empty() {
                println!("database consistent; every installed file matches");
                Ok(())
            } else {
                Err(Fail(6, format!("{} problem{}", problems.len(), if problems.len() == 1 { "" } else { "s" })))
            }
        }
        Cmd::Recover { sys, force_unlock } => {
            let mut fs = StdFs::new(&sys.root);
            match Manager::new(&mut fs, policy(&sys)?).recover(force_unlock).map_err(|e| Fail::from(&e))? {
                Recovery::Clean => println!("no interrupted transaction"),
                Recovery::Finished { tx, op, package } => println!("{op} of {package} had committed (transaction {tx}): clean-up finished"),
                Recovery::Undone { tx, op, package } => println!("{op} of {package} had not committed (transaction {tx}): undone"),
            }
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail(code, msg)) => {
            eprintln!("ncpkg: {msg}");
            ExitCode::from(code)
        }
    }
}
