// SPDX-License-Identifier: Apache-2.0
//! The package manager, end to end: real packages (real module headers,
//! real manifests, signatures checked by a stand-in verifier) installed
//! into a filesystem in memory — and the power cut at every operation.

use super::db::{Db, Resolved};
use super::fs::{Fs, MemFs};
use super::manager::{Error, InstallOptions, LibChange, Manager, Op, Outcome, Plan, Policy, Recovery};
use super::meta::build;
use super::sig::{self, Badge, Role, Verdict, Verifier};
use super::{base64, path, Builder};
use crate::json::{Json, Style};
use crate::ncplu::{self, Arch, Kind, CAP_INPUT, CAP_SCREEN, CAP_TIMER};
use std::string::{String, ToString};
use std::vec::Vec;
use std::{format, vec};

/// A signature, for these tests, is the message's SHA-512 repeated to the
/// algorithm's length: bound to the message like a real one, checkable
/// without keys. The roots in `roots` are the ones this "kernel" embeds.
struct FakeVerifier {
    roots: Vec<Role>,
}

impl FakeVerifier {
    fn all() -> FakeVerifier {
        FakeVerifier { roots: vec![Role::CreatorRing3, Role::CreatorRing0, Role::VerifyRing3, Role::VerifyRing0] }
    }
}

fn fake_sig(message: &[u8], n: usize) -> Vec<u8> {
    crate::sha512::digest(message).iter().cycle().take(n).copied().collect()
}

impl Verifier for FakeVerifier {
    fn verify(&mut self, role: Role, _alg: &str, _key: &str, _pubkey: &[u8], message: &[u8], sig: &[u8]) -> Verdict {
        if role.is_root() && !self.roots.contains(&role) {
            return Verdict::UnknownKey;
        }
        if fake_sig(message, sig.len()) == sig {
            Verdict::Valid
        } else {
            Verdict::Invalid
        }
    }
}

#[derive(Clone)]
struct Spec {
    id: &'static str,
    version: &'static str,
    kind: &'static str,
    arches: Vec<Arch>,
    ring: u8,
    caps: u32,
    module_caps: u32,
    module_kind: Kind,
    commands: Vec<&'static str>,
    /// (name, version, share)
    libs: Vec<(&'static str, &'static str, bool)>,
    /// (lib, requirement)
    depends: Vec<(&'static str, &'static str)>,
    /// (file, host)
    plugins: Vec<(&'static str, &'static str)>,
    res: Vec<(&'static str, Vec<u8>)>,
    sign: Vec<Role>,
    tamper: bool,
    creator: bool,
    system: Option<&'static str>,
    /// A wrong SHA-512 for this path in the manifest.
    bad_hash: Option<&'static str>,
    /// `icon.png`, the package's icon.
    icon: Option<Vec<u8>>,
}

impl Spec {
    fn gui(id: &'static str, version: &'static str) -> Spec {
        Spec {
            id,
            version,
            kind: "gui",
            arches: vec![Arch::X86_64, Arch::Aarch64],
            ring: 3,
            caps: CAP_SCREEN | CAP_INPUT,
            module_caps: CAP_SCREEN,
            module_kind: Kind::App,
            commands: Vec::new(),
            libs: Vec::new(),
            depends: Vec::new(),
            plugins: Vec::new(),
            res: vec![("res/icon.png", b"icon".to_vec())],
            sign: Vec::new(),
            tamper: false,
            creator: true,
            system: None,
            bad_hash: None,
            icon: None,
        }
    }

    fn lib(id: &'static str, version: &'static str) -> Spec {
        Spec { kind: "lib", res: Vec::new(), caps: 0, module_caps: 0, ..Spec::gui(id, version) }
    }
}

/// A module for `arch`/`kind` whose data section carries `marker`, so two
/// builds of "the same" library at different versions differ in bytes.
fn module(arch: Arch, kind: Kind, caps: u32, marker: &str) -> Vec<u8> {
    let mut m = ncplu::tests::module(arch, kind, caps);
    let img = ncplu::Image::parse(&m).unwrap();
    let data = (0..img.section_count()).map(|i| img.section(i).unwrap()).find(|s| s.kind == ncplu::SectionKind::Data).unwrap();
    let digest = crate::sha512::digest(marker.as_bytes());
    let n = data.file_size.min(16);
    let off = data.file_off;
    m[off..off + n].copy_from_slice(&digest[..n]);
    m
}

fn build_pkg(s: &Spec) -> Vec<u8> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for &arch in &s.arches {
        if s.kind != "lib" {
            files.push((format!("ncapp/{}/main.ncapp", arch.name()), module(arch, s.module_kind, s.module_caps, s.id)));
        }
        for (name, ver, _) in &s.libs {
            files.push((format!("lib/{}/{name}.ncdyn", arch.name()), module(arch, Kind::Library, 0, &format!("{name}{ver}"))));
        }
        for (file, _) in &s.plugins {
            files.push((format!("plugins/{}/{file}", arch.name()), module(arch, Kind::Plugin, 0, file)));
        }
    }
    for (p, d) in &s.res {
        files.push((p.to_string(), d.clone()));
    }
    if let Some(icon) = &s.icon {
        files.push((String::from("icon.png"), icon.clone()));
    }
    files.sort_by(|a, b| path::cmp_folded(&a.0, &b.0));
    let entries = files
        .iter()
        .map(|(p, d)| {
            let mut f = super::meta::tests::file(p, d);
            if s.bad_hash == Some(p.as_str()) {
                *f.get_mut("sha512").unwrap() = Json::Str("0".repeat(128));
            }
            f
        })
        .collect();
    let mut signed = Json::obj([
        ("id", Json::str(s.id)),
        ("name", Json::str(&format!("Test {}", s.id))),
        ("version", Json::str(s.version)),
        ("type", Json::str(s.kind)),
        ("arch", Json::Arr(s.arches.iter().map(|a| Json::str(a.name())).collect())),
        ("abi", Json::uint(u64::from(ncplu::ABI_VERSION))),
        ("files", Json::Arr(entries)),
    ]);
    if s.creator {
        signed.push("creator", Json::obj([("name", Json::str("Test Creator"))]));
    }
    if let Some(sys) = s.system {
        signed.push("system", Json::str(sys));
    }
    if s.kind != "lib" {
        let caps = super::meta::CAPABILITIES.iter().filter(|(_, b)| s.caps & b != 0).map(|(n, _)| Json::str(n)).collect();
        let mut app = Json::obj([("entry", Json::str("main.ncapp")), ("ring", Json::Int(i64::from(s.ring))), ("capabilities", Json::Arr(caps))]);
        if !s.commands.is_empty() {
            app.push("commands", Json::Arr(s.commands.iter().map(|c| Json::str(c)).collect()));
        }
        signed.push("app", app);
    }
    if !s.libs.is_empty() {
        signed.push(
            "libraries",
            Json::Arr(
                s.libs
                    .iter()
                    .map(|(n, v, share)| {
                        Json::obj([("name", Json::str(n)), ("version", Json::str(v)), ("file", Json::str(&format!("{n}.ncdyn"))), ("share", Json::Bool(*share))])
                    })
                    .collect(),
            ),
        );
    }
    if !s.depends.is_empty() {
        signed.push("depends", Json::Arr(s.depends.iter().map(|(l, r)| Json::obj([("lib", Json::str(l)), ("version", Json::str(r))])).collect()));
    }
    if !s.plugins.is_empty() {
        signed.push("plugins", Json::Arr(s.plugins.iter().map(|(f, h)| Json::obj([("file", Json::str(f)), ("host", Json::str(h))])).collect()));
    }
    let signed_text = signed.write(Style::CANONICAL);
    let sigs: Vec<Json> = s
        .sign
        .iter()
        .enumerate()
        .map(|(i, role)| {
            let msg = sig::Message::new(*role, signed_text.as_bytes());
            let (alg, n, pubkey) = if role.is_root() { (sig::ROOT_ALG, 4759, None) } else { ("ed25519", 64, Some("AAAA")) };
            let mut bytes = fake_sig(msg.as_bytes(), n);
            if s.tamper && i == 0 {
                bytes[0] ^= 1;
            }
            build::signature(role.name(), alg, "0123-4567-89ab-cdef", pubkey, &base64::encode_string(&bytes))
        })
        .collect();
    let mut b = Builder::new(build::splice(&signed_text, &sigs).into_bytes());
    for (p, d) in files {
        b.add_stored(&p, d).unwrap();
    }
    b.finish().unwrap()
}

fn policy() -> Policy {
    let mut p = Policy::new(Arch::X86_64, "4.1.0");
    p.now = 1_700_000_000;
    p.nonce = 0xABC;
    p
}

fn install_with(fs: &mut MemFs, policy: Policy, pkg: &[u8], opts: InstallOptions) -> Result<Outcome, Error> {
    Manager::new(fs, policy).install(pkg, &mut FakeVerifier::all(), &opts, &mut |_: &Plan| true)
}

fn install(fs: &mut MemFs, pkg: &[u8]) -> Result<Outcome, Error> {
    install_with(fs, policy(), pkg, InstallOptions::default())
}

fn remove(fs: &mut MemFs, id: &str) -> Result<Outcome, Error> {
    Manager::new(fs, policy()).remove(id, &mut |_: &Plan| true)
}

fn db(fs: &mut MemFs) -> Db {
    Manager::new(fs, policy()).load_db().unwrap()
}

fn plan(fs: &mut MemFs, pkg: &[u8]) -> Result<Plan, Error> {
    Manager::new(fs, policy()).plan_install(pkg, &mut FakeVerifier::all(), &InstallOptions::default())
}

fn exists(fs: &mut MemFs, p: &str) -> bool {
    fs.stat(p).unwrap().is_some()
}

#[test]
fn install_places_every_file_and_records_it() {
    let mut fs = MemFs::new();
    let mut s = Spec::gui("org.example.player", "1.0.0");
    s.libs = vec![("libfoo", "1.2.0", true)];
    s.plugins = vec![("vgm.ncplu", "nc.player")];
    s.commands = vec!["player"];
    s.sign = vec![Role::CreatorRing3];
    let out = install(&mut fs, &build_pkg(&s)).unwrap();
    assert!(matches!(out, Outcome::Done { op: Op::Install, cleanup_pending: false, .. }), "{out:?}");

    for p in [
        "/apps/org.example.player/main.ncapp",
        "/apps/org.example.player/res/icon.png",
        "/usr/lib/libfoo.ncdyn",
        "/usr/lib/ncplu/nc.player/org.example.player/vgm.ncplu",
        "/usr/bin/player",
        "/var/lib/ncpkg/meta/org.example.player.meta",
        "/var/lib/ncpkg/db.json",
    ] {
        assert!(exists(&mut fs, p), "{p} missing");
    }
    // Only this machine's architecture is installed.
    let app = fs.read("/apps/org.example.player/main.ncapp").unwrap();
    assert_eq!(ncplu::Image::parse(&app).unwrap().arch(), Arch::X86_64);
    assert_eq!(fs.read("/usr/bin/player").unwrap(), b"#!ncapp /apps/org.example.player/main.ncapp\n");
    // No transaction left behind.
    for p in ["/var/lib/ncpkg/journal.json", "/var/lib/ncpkg/db.json.new", "/var/lib/ncpkg/lock", "/var/lib/ncpkg/tx"] {
        assert!(!exists(&mut fs, p), "{p} left behind");
    }

    let d = db(&mut fs);
    let p = &d.packages["org.example.player"];
    assert_eq!((p.version.as_str(), p.kind.as_str(), p.badge.as_str(), p.ring), ("1.0.0", "gui", "creator", 3));
    assert_eq!(p.roles, ["creator-ring3"]);
    assert_eq!(p.capabilities, ["screen", "input"]);
    assert_eq!(p.license, "Proprietary", "no licence given reads as proprietary");
    assert_eq!(p.installed_at, 1_700_000_000);
    assert_eq!(p.libraries[0].resolved, Resolved::Global);
    let lib = &d.libraries["libfoo"];
    assert_eq!((lib.ref_count, lib.required_by.as_slice(), lib.provided_by.as_deref()), (1, &[String::from("org.example.player")][..], Some("org.example.player")));
    assert_eq!(d.generation, 1);
    assert!(Manager::new(&mut fs, policy()).check().unwrap().is_empty());
}

#[test]
fn shared_libraries_are_counted_and_freed_at_zero() {
    let mut fs = MemFs::new();
    let mut a = Spec::gui("org.example.a", "1.0.0");
    a.libs = vec![("libfoo", "1.2.0", true)];
    let mut b = Spec::gui("org.example.b", "1.0.0");
    b.libs = vec![("libfoo", "1.2.0", true)];
    install(&mut fs, &build_pkg(&a)).unwrap();
    install(&mut fs, &build_pkg(&b)).unwrap();
    let d = db(&mut fs);
    assert_eq!(d.libraries["libfoo"].ref_count, 2);
    assert_eq!(d.libraries["libfoo"].required_by, ["org.example.a", "org.example.b"]);
    assert_eq!(d.libraries["libfoo"].provided_by.as_deref(), Some("org.example.a"));

    remove(&mut fs, "org.example.a").unwrap();
    let d = db(&mut fs);
    assert_eq!(d.libraries["libfoo"].ref_count, 1);
    assert_eq!(d.libraries["libfoo"].provided_by, None, "its provider is gone; the copy stays");
    assert!(exists(&mut fs, "/usr/lib/libfoo.ncdyn"));
    assert!(!exists(&mut fs, "/apps/org.example.a"));

    remove(&mut fs, "org.example.b").unwrap();
    let d = db(&mut fs);
    assert!(d.libraries.is_empty() && d.packages.is_empty());
    assert!(!exists(&mut fs, "/usr/lib/libfoo.ncdyn"), "ref_count reached zero");
    assert!(!exists(&mut fs, "/apps/org.example.b"));
    assert!(exists(&mut fs, "/usr/lib"), "the system directories stay");
}

#[test]
fn an_incompatible_version_stays_private() {
    let mut fs = MemFs::new();
    let mut a = Spec::gui("org.example.a", "1.0.0");
    a.libs = vec![("libfoo", "1.2.0", true)];
    let mut b = Spec::gui("org.example.b", "1.0.0");
    b.libs = vec![("libfoo", "2.0.0", true)];
    install(&mut fs, &build_pkg(&a)).unwrap();
    let p = plan(&mut fs, &build_pkg(&b)).unwrap();
    assert_eq!(p.libraries[0].change, LibChange::Private { global: Some(String::from("1.2.0")) });
    install(&mut fs, &build_pkg(&b)).unwrap();
    let d = db(&mut fs);
    assert_eq!(d.libraries["libfoo"].version, "1.2.0");
    assert_eq!(d.libraries["libfoo"].ref_count, 1);
    assert_eq!(d.packages["org.example.b"].libraries[0].resolved, Resolved::Private);
    assert!(exists(&mut fs, "/apps/org.example.b/lib/libfoo.ncdyn"));
    // Removing the private user leaves the global copy alone.
    remove(&mut fs, "org.example.b").unwrap();
    assert!(exists(&mut fs, "/usr/lib/libfoo.ncdyn"));
    assert_eq!(db(&mut fs).libraries["libfoo"].ref_count, 1);
}

#[test]
fn share_false_always_stays_private() {
    let mut fs = MemFs::new();
    let mut a = Spec::gui("org.example.a", "1.0.0");
    a.libs = vec![("libpatched", "1.0.0", false)];
    install(&mut fs, &build_pkg(&a)).unwrap();
    let d = db(&mut fs);
    assert!(d.libraries.is_empty());
    assert!(exists(&mut fs, "/apps/org.example.a/lib/libpatched.ncdyn"));
}

#[test]
fn a_newer_compatible_copy_upgrades_the_global_one() {
    let mut fs = MemFs::new();
    let mut a = Spec::gui("org.example.a", "1.0.0");
    a.libs = vec![("libfoo", "1.2.0", true)];
    let mut b = Spec::gui("org.example.b", "1.0.0");
    b.libs = vec![("libfoo", "1.4.0", true)];
    install(&mut fs, &build_pkg(&a)).unwrap();
    let old = fs.read("/usr/lib/libfoo.ncdyn").unwrap();
    let p = plan(&mut fs, &build_pkg(&b)).unwrap();
    assert_eq!(p.libraries[0].change, LibChange::UpgradeGlobal { from: String::from("1.2.0") });
    assert_eq!(p.libraries[0].refs, 2);
    install(&mut fs, &build_pkg(&b)).unwrap();
    assert_ne!(fs.read("/usr/lib/libfoo.ncdyn").unwrap(), old);
    let d = db(&mut fs);
    assert_eq!((d.libraries["libfoo"].version.as_str(), d.libraries["libfoo"].ref_count), ("1.4.0", 2));
    assert_eq!(d.packages["org.example.a"].libraries[0].version, "1.4.0");
    assert_eq!(d.libraries["libfoo"].provided_by.as_deref(), Some("org.example.b"));
    // B leaves; A keeps the newer copy (no downgrade on removal).
    remove(&mut fs, "org.example.b").unwrap();
    let d = db(&mut fs);
    assert_eq!((d.libraries["libfoo"].version.as_str(), d.libraries["libfoo"].ref_count), ("1.4.0", 1));
}

#[test]
fn a_dependent_that_refuses_the_newer_copy_blocks_the_upgrade() {
    let mut fs = MemFs::new();
    let mut a = Spec::gui("org.example.a", "1.0.0");
    a.libs = vec![("libfoo", "1.2.0", true)];
    a.depends = vec![("libfoo", "=1.2.0")];
    let mut b = Spec::gui("org.example.b", "1.0.0");
    b.libs = vec![("libfoo", "1.4.0", true)];
    b.depends = vec![("libfoo", "^1.0")];
    install(&mut fs, &build_pkg(&a)).unwrap();
    let p = plan(&mut fs, &build_pkg(&b)).unwrap();
    assert_eq!(p.libraries[0].change, LibChange::Share, "B accepts 1.2.0, and A refuses 1.4.0");
    install(&mut fs, &build_pkg(&b)).unwrap();
    let d = db(&mut fs);
    assert_eq!((d.libraries["libfoo"].version.as_str(), d.libraries["libfoo"].ref_count), ("1.2.0", 2));
}

#[test]
fn library_packages_provide_and_conflict() {
    let mut fs = MemFs::new();
    let mut l1 = Spec::lib("org.ffmpeg.libs", "6.1.0");
    l1.libs = vec![("libavcodec", "60.31.102", true)];
    install(&mut fs, &build_pkg(&l1)).unwrap();
    // An app that needs the library without carrying it.
    let mut app = Spec::gui("org.example.recorder", "1.0.0");
    app.depends = vec![("libavcodec", "^60.0")];
    let p = plan(&mut fs, &build_pkg(&app)).unwrap();
    assert_eq!(p.libraries[0].change, LibChange::Share);
    install(&mut fs, &build_pkg(&app)).unwrap();
    assert_eq!(db(&mut fs).libraries["libavcodec"].ref_count, 2);
    // Another library package with a version the app refuses: a conflict,
    // not a private copy nobody would find.
    let mut l2 = Spec::lib("org.ffmpeg.libs7", "7.1.0");
    l2.libs = vec![("libavcodec", "61.19.100", true)];
    match plan(&mut fs, &build_pkg(&l2)) {
        Err(Error::LibraryConflict { name, installed, offered, required_by }) => {
            assert_eq!((name.as_str(), installed.as_str(), offered.as_str()), ("libavcodec", "60.31.102", "61.19.100"));
            assert_eq!(required_by, ["org.example.recorder", "org.ffmpeg.libs"]);
        }
        other => panic!("{other:?}"),
    }
    // Removing the library package keeps the library for the app.
    remove(&mut fs, "org.ffmpeg.libs").unwrap();
    let d = db(&mut fs);
    assert_eq!(d.libraries["libavcodec"].ref_count, 1);
    assert_eq!(d.libraries["libavcodec"].provided_by, None);
    remove(&mut fs, "org.example.recorder").unwrap();
    assert!(!exists(&mut fs, "/usr/lib/libavcodec.ncdyn"));
}

#[test]
fn a_missing_library_is_refused() {
    let mut fs = MemFs::new();
    let mut app = Spec::gui("org.example.app", "1.0.0");
    app.depends = vec![("libbar", "^1")];
    assert!(matches!(plan(&mut fs, &build_pkg(&app)), Err(Error::MissingLibrary { installed: None, .. })));
    let mut lib = Spec::lib("org.example.libbar", "2.0.0");
    lib.libs = vec![("libbar", "2.0.0", true)];
    install(&mut fs, &build_pkg(&lib)).unwrap();
    assert!(matches!(plan(&mut fs, &build_pkg(&app)), Err(Error::MissingLibrary { installed: Some(_), .. })));
}

#[test]
fn upgrades_replace_the_old_version_in_one_transaction() {
    let mut fs = MemFs::new();
    let mut v1 = Spec::gui("org.example.app", "1.0.0");
    v1.libs = vec![("libfoo", "1.0.0", true), ("libold", "1.0.0", true)];
    v1.res = vec![("res/icon.png", b"v1".to_vec()), ("res/x.txt", b"x".to_vec())];
    v1.commands = vec!["app-v1"];
    install(&mut fs, &build_pkg(&v1)).unwrap();

    let mut v2 = Spec::gui("org.example.app", "1.1.0");
    v2.libs = vec![("libfoo", "1.1.0", true)];
    v2.res = vec![("res/icon.png", b"v2".to_vec()), ("res/z.txt", b"z".to_vec())];
    v2.commands = vec!["app"];
    let p = plan(&mut fs, &build_pkg(&v2)).unwrap();
    assert_eq!((p.op, p.previous.as_deref()), (Op::Upgrade, Some("1.0.0")));
    assert!(p.libraries.iter().any(|l| l.name == "libold" && l.change == LibChange::Delete));
    assert!(p.libraries.iter().any(|l| l.name == "libfoo" && matches!(l.change, LibChange::UpgradeGlobal { .. })));
    install(&mut fs, &build_pkg(&v2)).unwrap();

    assert_eq!(fs.read("/apps/org.example.app/res/icon.png").unwrap(), b"v2");
    assert!(exists(&mut fs, "/apps/org.example.app/res/z.txt"));
    assert!(!exists(&mut fs, "/apps/org.example.app/res/x.txt"));
    assert!(!exists(&mut fs, "/usr/bin/app-v1") && exists(&mut fs, "/usr/bin/app"));
    assert!(!exists(&mut fs, "/usr/lib/libold.ncdyn"));
    let d = db(&mut fs);
    assert_eq!(d.packages["org.example.app"].version, "1.1.0");
    assert_eq!((d.libraries["libfoo"].version.as_str(), d.libraries["libfoo"].ref_count), ("1.1.0", 1));
    assert!(!d.libraries.contains_key("libold"));
    assert!(Manager::new(&mut fs, policy()).check().unwrap().is_empty());

    // The same version again, and an older one: only when asked.
    assert!(matches!(install(&mut fs, &build_pkg(&v2)), Err(Error::AlreadyInstalled { .. })));
    assert!(matches!(install(&mut fs, &build_pkg(&v1)), Err(Error::Downgrade { .. })));
    let again = install_with(&mut fs, policy(), &build_pkg(&v2), InstallOptions { reinstall: true, ..Default::default() }).unwrap();
    assert!(matches!(again, Outcome::Done { op: Op::Reinstall, .. }));
    let down = install_with(&mut fs, policy(), &build_pkg(&v1), InstallOptions { allow_downgrade: true, ..Default::default() }).unwrap();
    assert!(matches!(down, Outcome::Done { op: Op::Downgrade, .. }));
    assert_eq!(db(&mut fs).packages["org.example.app"].version, "1.0.0");
    assert_eq!(db(&mut fs).libraries["libfoo"].version, "1.0.0", "a library nobody else uses follows its only user down");
}

#[test]
fn conflicts_are_refused() {
    let mut fs = MemFs::new();
    let mut a = Spec::gui("org.example.a", "1.0.0");
    a.commands = vec!["tool"];
    install(&mut fs, &build_pkg(&a)).unwrap();

    let mut b = Spec::gui("org.example.b", "1.0.0");
    b.commands = vec!["tool"];
    assert!(matches!(plan(&mut fs, &build_pkg(&b)), Err(Error::CommandConflict { owner: Some(_), .. })));
    b.commands = vec!["ls"];
    assert!(matches!(plan(&mut fs, &build_pkg(&b)), Err(Error::CommandConflict { owner: None, .. })));

    let stopwatch = Spec::gui("nc.stopwatch", "9.0.0");
    assert!(matches!(plan(&mut fs, &build_pkg(&stopwatch)), Err(Error::Reserved(_))), "the stopwatch is essential");

    let mut orphan = Spec::gui("org.example.ext", "1.0.0");
    orphan.plugins = vec![("x.ncplu", "org.example.nothere")];
    assert!(matches!(plan(&mut fs, &build_pkg(&orphan)), Err(Error::HostMissing { .. })));
    orphan.plugins = vec![("x.ncplu", "org.example.a")];
    install(&mut fs, &build_pkg(&orphan)).unwrap();
    assert!(matches!(remove(&mut fs, "org.example.a"), Err(Error::HasDependents { .. })));
    remove(&mut fs, "org.example.ext").unwrap();
    remove(&mut fs, "org.example.a").unwrap();

    // A file nobody owns is not overwritten unless asked.
    super::fs::create_dir_all(&mut fs, "/apps/org.example.c/res").unwrap();
    fs.create("/apps/org.example.c/res/icon.png", b"mine").unwrap();
    let c = Spec::gui("org.example.c", "1.0.0");
    assert!(matches!(install(&mut fs, &build_pkg(&c)), Err(Error::FileConflict { owner: None, .. })));
    assert_eq!(fs.read("/apps/org.example.c/res/icon.png").unwrap(), b"mine");
    install_with(&mut fs, policy(), &build_pkg(&c), InstallOptions { force: true, ..Default::default() }).unwrap();
    assert_eq!(fs.read("/apps/org.example.c/res/icon.png").unwrap(), b"icon");
    assert!(matches!(remove(&mut fs, "org.example.nothere"), Err(Error::NotInstalled(_))));
}

#[test]
fn signatures_decide_rings() {
    let mut fs = MemFs::new();
    // A signature present and broken: refused, whatever else is valid.
    let mut t = Spec::gui("org.example.t", "1.0.0");
    t.sign = vec![Role::CreatorRing3, Role::SelfSigned];
    t.tamper = true;
    assert!(matches!(plan(&mut fs, &build_pkg(&t)), Err(Error::Tampered(r)) if r == ["creator-ring3"]));

    // Ring 0 needs a ring-0 signature.
    let mut r0 = Spec::gui("org.example.r0", "1.0.0");
    r0.ring = 0;
    assert!(matches!(plan(&mut fs, &build_pkg(&r0)), Err(Error::Ring0NotAllowed)));
    // A ring-3 signature never grants ring 0, however trusted.
    r0.sign = vec![Role::CreatorRing3, Role::VerifyRing3];
    assert!(matches!(plan(&mut fs, &build_pkg(&r0)), Err(Error::Ring0NotAllowed)));
    // The creator's ring-0 root does (🌳)...
    r0.sign = vec![Role::CreatorRing0];
    let p = plan(&mut fs, &build_pkg(&r0)).unwrap();
    assert_eq!((p.badge, p.ring), (Badge::TreeRoot, 0));
    // ...and so does a ring-0 certification of a third party (🔵).
    r0.sign = vec![Role::VerifyRing0];
    assert_eq!(plan(&mut fs, &build_pkg(&r0)).unwrap().badge, Badge::VerifiedRing0);
    // A root this verifier does not embed counts for nothing.
    let mut v = FakeVerifier { roots: vec![Role::CreatorRing3] };
    let refused = Manager::new(&mut fs, policy()).plan_install(&build_pkg(&r0), &mut v, &InstallOptions::default());
    assert!(matches!(refused, Err(Error::Ring0NotAllowed)));
    // The community switch lets an unsigned ring-0 package in, with a
    // warning — and an anonymous one is flagged.
    r0.sign = Vec::new();
    r0.creator = false;
    let mut community = policy();
    community.community_ring0 = true;
    let p = Manager::new(&mut fs, community).plan_install(&build_pkg(&r0), &mut FakeVerifier::all(), &InstallOptions::default()).unwrap();
    assert_eq!(p.badge, Badge::Unsigned);
    assert_eq!(p.warnings.len(), 2, "{:?}", p.warnings);

    // A system that requires signatures.
    let mut strict = policy();
    strict.require_signature = true;
    let unsigned = Spec::gui("org.example.u", "1.0.0");
    let refused = Manager::new(&mut fs, strict.clone()).plan_install(&build_pkg(&unsigned), &mut FakeVerifier::all(), &InstallOptions::default());
    assert!(matches!(refused, Err(Error::Unsigned)));
    let mut selfsigned = unsigned.clone();
    selfsigned.sign = vec![Role::SelfSigned];
    let p = Manager::new(&mut fs, strict).plan_install(&build_pkg(&selfsigned), &mut FakeVerifier::all(), &InstallOptions::default()).unwrap();
    assert_eq!(p.badge, Badge::SelfSigned);
}

#[test]
fn packages_that_do_not_fit_are_refused() {
    let mut fs = MemFs::new();
    let mut s = Spec::gui("org.example.arm", "1.0.0");
    s.arches = vec![Arch::Aarch64];
    assert!(matches!(plan(&mut fs, &build_pkg(&s)), Err(Error::WrongArch { .. })));
    let mut s = Spec::gui("org.example.new", "1.0.0");
    s.system = Some(">=5.0.0");
    assert!(matches!(plan(&mut fs, &build_pkg(&s)), Err(Error::SystemTooOld { .. })));
    let mut s = Spec::gui("org.example.lie", "1.0.0");
    s.module_kind = Kind::Library;
    assert!(matches!(plan(&mut fs, &build_pkg(&s)), Err(Error::Module { .. })));
    let mut s = Spec::gui("org.example.greedy", "1.0.0");
    s.module_caps = CAP_SCREEN | CAP_TIMER;
    assert!(matches!(plan(&mut fs, &build_pkg(&s)), Err(Error::Module { .. })), "the module wants more than the manifest declares");
    let mut s = Spec::gui("org.example.bad", "1.0.0");
    s.bad_hash = Some("ncapp/x86_64/main.ncapp");
    assert!(matches!(plan(&mut fs, &build_pkg(&s)), Err(Error::FileHash(_))));
    let mut abi = policy();
    abi.abi = 99;
    let refused = Manager::new(&mut fs, abi).plan_install(&build_pkg(&Spec::gui("org.example.x", "1.0.0")), &mut FakeVerifier::all(), &InstallOptions::default());
    assert!(matches!(refused, Err(Error::AbiMismatch { .. })));
    // Nothing above touched the filesystem.
    assert_eq!(fs.mutations, 0);
}

#[test]
fn a_held_lock_stops_everything_and_recover_can_break_it() {
    let mut fs = MemFs::new();
    super::fs::create_dir_all(&mut fs, "/var/lib/ncpkg").unwrap();
    fs.create("/var/lib/ncpkg/lock", b"pid 42 elsewhere").unwrap();
    let pkg = build_pkg(&Spec::gui("org.example.a", "1.0.0"));
    assert_eq!(install(&mut fs, &pkg), Err(Error::Locked(String::from("pid 42 elsewhere"))));
    assert_eq!(Manager::new(&mut fs, policy()).recover(true).unwrap(), Recovery::Clean);
    install(&mut fs, &pkg).unwrap();
}

#[test]
fn a_declined_confirmation_changes_nothing() {
    let mut fs = MemFs::new();
    let before = fs.snapshot();
    let pkg = build_pkg(&Spec::gui("org.example.a", "1.0.0"));
    let out = Manager::new(&mut fs, policy()).install(&pkg, &mut FakeVerifier::all(), &InstallOptions::default(), &mut |_: &Plan| false).unwrap();
    assert_eq!(out, Outcome::Cancelled);
    // Only the database directory the lock lives in was created.
    let after = fs.snapshot();
    assert!(after.keys().all(|k| before.contains_key(k) || "/var/lib/ncpkg".starts_with(k.as_str())), "{after:?}");
}

/// Runs `op` on a copy of `base` with the power cut after `n` filesystem
/// mutations, for every `n` until `op` completes; after each cut, boots,
/// recovers, and requires the tree to be exactly `base` (undone) or exactly
/// what an uninterrupted run leaves (finished).
fn crash_everywhere(base: &MemFs, op: &dyn Fn(&mut MemFs) -> Result<Outcome, Error>) -> (usize, usize) {
    let mut clean = base.clone();
    op(&mut clean).expect("the uninterrupted run succeeds");
    let mutations = clean.mutations - base.mutations;
    let done = clean.snapshot();
    let before = base.snapshot();
    let (mut undone, mut finished) = (0, 0);
    for n in 0.. {
        let mut fs = base.clone();
        fs.crash_after(n);
        let result = op(&mut fs);
        if !fs.crashed() {
            assert!(result.is_ok(), "no crash at {n}, yet {result:?}");
            assert_eq!(fs.snapshot(), done);
            break;
        }
        fs.reboot();
        let recovery = Manager::new(&mut fs, policy()).recover(true).unwrap_or_else(|e| panic!("recovery after a cut at {n}: {e}"));
        let now = fs.snapshot();
        if now == before {
            undone += 1;
        } else if now == done {
            finished += 1;
        } else {
            let extra: Vec<_> = now.keys().filter(|k| !before.contains_key(*k) && !done.contains_key(*k)).collect();
            let missing: Vec<_> = before.keys().filter(|k| !now.contains_key(*k) && !done.contains_key(*k)).collect();
            panic!("cut at {n} ({recovery:?}) left a third state: extra {extra:?}, missing {missing:?}");
        }
        // And the database is sound either way.
        assert!(Manager::new(&mut fs, policy()).check().unwrap().is_empty(), "cut at {n}");
    }
    assert!(undone > 0 && finished > 0, "undone {undone}, finished {finished}");
    // One cut per filesystem operation of the uninterrupted run.
    assert_eq!(undone + finished, mutations);
    (undone, finished)
}

fn populated() -> MemFs {
    let mut fs = MemFs::new();
    let mut a = Spec::gui("org.example.a", "1.0.0");
    a.libs = vec![("libfoo", "1.2.0", true), ("libbar", "1.0.0", true)];
    a.commands = vec!["a"];
    install(&mut fs, &build_pkg(&a)).unwrap();
    fs
}

#[test]
fn power_cut_at_every_step_of_an_install() {
    let mut b = Spec::gui("org.example.b", "1.0.0");
    b.libs = vec![("libfoo", "1.4.0", true), ("libbaz", "2.0.0", true), ("libbar", "2.0.0", true)];
    b.plugins = vec![("p.ncplu", "org.example.a")];
    b.commands = vec!["b"];
    let pkg = build_pkg(&b);
    let (undone, finished) = crash_everywhere(&populated(), &|fs| install(fs, &pkg));
    // Most cuts land before the commit (staging, the steps); the rest in
    // the clean-up after it.
    assert!(undone > finished, "{undone} undone, {finished} finished");
}

#[test]
fn power_cut_at_every_step_of_an_upgrade() {
    let mut v2 = Spec::gui("org.example.a", "2.0.0");
    v2.libs = vec![("libfoo", "1.3.0", true)];
    v2.res = vec![("res/icon.png", b"new icon".to_vec()), ("res/more.txt", b"more".to_vec())];
    v2.commands = vec!["a2"];
    let pkg = build_pkg(&v2);
    crash_everywhere(&populated(), &|fs| install(fs, &pkg));
}

#[test]
fn power_cut_at_every_step_of_a_removal() {
    let mut fs = populated();
    let mut b = Spec::gui("org.example.b", "1.0.0");
    b.libs = vec![("libfoo", "1.2.0", true)];
    install(&mut fs, &build_pkg(&b)).unwrap();
    crash_everywhere(&fs, &|fs| remove(fs, "org.example.a"));
}

#[cfg(unix)]
#[test]
fn on_a_real_directory() {
    use super::fs::StdFs;
    let dir = std::env::temp_dir().join(format!("ncpkg-manager-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut fs = StdFs::new(&dir);
    let mut a = Spec::gui("org.example.a", "1.0.0");
    a.libs = vec![("libfoo", "1.2.0", true)];
    a.commands = vec!["a"];
    let pkg = build_pkg(&a);
    let mut m = Manager::new(&mut fs, policy());
    m.install(&pkg, &mut FakeVerifier::all(), &InstallOptions::default(), &mut |_: &Plan| true).unwrap();
    assert!(dir.join("usr/lib/libfoo.ncdyn").is_file());
    assert!(dir.join("apps/org.example.a/main.ncapp").is_file());
    let text = std::fs::read_to_string(dir.join("var/lib/ncpkg/db.json")).unwrap();
    assert!(text.contains("\"ref_count\": 1"), "{text}");
    assert!(m.check().unwrap().is_empty());
    m.remove("org.example.a", &mut |_: &Plan| true).unwrap();
    assert!(!dir.join("usr/lib/libfoo.ncdyn").exists());
    assert!(!dir.join("apps/org.example.a").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The same manager, installing into an NCFS volume: the filesystem the
/// system itself will install into, its promises kept by copy-on-write.
#[test]
fn on_an_ncfs_volume() {
    use crate::ncfs::pkgfs::PkgFs;
    use crate::ncfs::tests::MemDev;
    use crate::ncfs::write::{FixedClock, Format, Options, Writer};
    use crate::ncfs::{Scratch, SliceDev, Volume};
    let w = Writer::format(MemDev::new(8192), &Format { label: b"root".to_vec(), fsid: [1; 16] }, Options::default(), std::boxed::Box::new(FixedClock(0))).unwrap();
    let mut fs = PkgFs::new(w);
    let mut a = Spec::gui("org.example.a", "1.0.0");
    a.libs = vec![("libfoo", "1.2.0", true)];
    a.commands = vec!["a"];
    a.icon = Some(super::icon::tests::png(64, [9, 8, 7, 255]));
    let pkg = build_pkg(&a);
    let mut m = Manager::new(&mut fs, policy());
    m.install(&pkg, &mut FakeVerifier::all(), &InstallOptions::default(), &mut |_: &Plan| true).unwrap();
    assert!(m.check().unwrap().is_empty());
    drop(m);
    // What the kernel's reader sees on the committed volume.
    let data = fs.writer.device().data.clone();
    let mut s = std::boxed::Box::new(Scratch::new());
    let mut v = Volume::open(SliceDev::new(&data), &mut s.node).unwrap();
    for p in ["/usr/lib/libfoo.ncdyn", "/apps/org.example.a/main.ncapp", "/usr/bin/a", "/var/lib/ncpkg/db.json", "/var/cache/ncpkg/icons/org.example.a.png"] {
        v.resolve(p.as_bytes(), &mut s).unwrap_or_else(|e| panic!("{p}: {e}"));
    }
    let db_ino = v.resolve(b"/var/lib/ncpkg/db.json", &mut s).unwrap();
    let i = v.inode(db_ino, &mut s.node).unwrap();
    let mut text = vec![0u8; i.size as usize];
    v.read(db_ino, &i, 0, &mut text, &mut s).unwrap();
    assert!(String::from_utf8(text).unwrap().contains("\"ref_count\": 1"));
    let r = crate::ncfs::check::check(&mut SliceDev::new(&data), true).unwrap();
    assert!(r.is_clean(), "{:#?}", r.errors);
    let mut m = Manager::new(&mut fs, policy());
    m.remove("org.example.a", &mut |_: &Plan| true).unwrap();
    assert!(m.check().unwrap().is_empty());
    drop(m);
    fs.writer.commit().unwrap();
    let data = fs.writer.device().data.clone();
    let mut v = Volume::open(SliceDev::new(&data), &mut s.node).unwrap();
    assert_eq!(v.resolve(b"/usr/lib/libfoo.ncdyn", &mut s), Err(crate::ncfs::Error::NotFound));
    assert_eq!(v.resolve(b"/apps/org.example.a", &mut s), Err(crate::ncfs::Error::NotFound));
}
