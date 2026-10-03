// SPDX-License-Identifier: Apache-2.0
//! The package manifest, `ncpkg.meta`: its schema and a validating reader.
//!
//! The manifest is JSON (RFC 8259, read by [`crate::json`]) with three
//! members and nothing else:
//!
//! ```json
//! {
//!   "format": "ncpkg/2",
//!   "signed": { "id": "org.example.player-plus", "version": "2.0.1", "type": "gui", … },
//!   "signatures": [ { "role": "creator-ring3", "alg": "mldsa87+p521", "key": "…", "sig": "…" } ]
//! }
//! ```
//!
//! `signed` is everything the signatures cover ([`super::sig`]): what the
//! package is, who made it, the ring it asks for, the libraries it ships and
//! needs, the plugins it registers, the NCFS permissions it wants and every
//! file it carries with its SHA-512. `docs/NCPKG.md` is the full field
//! reference; [`Meta::parse`] is its executable form.
//!
//! The reader is strict, because a lenient one is how two programs come to
//! read different things in one signed document:
//!
//! * no unknown keys and no duplicate keys, at any level;
//! * machine fields (ids, versions, paths, names) are plain ASCII without
//!   escapes, so they have one spelling;
//! * every cross-reference holds: each architecture listed has its app,
//!   libraries and plugins; no file is listed for an architecture that is
//!   not; every file is listed exactly once, in order; a shipped library
//!   satisfies the package's own requirement for it; one signature per
//!   role, with the algorithm its role requires.
//!
//! [`Meta::check_container`] then ties the manifest to the container: the
//! same files, in the same order, with the same sizes. The SHA-512s are
//! checked as each file is decoded (by the installer, or by the kernel
//! before it runs an app straight from a package).
//!
//! `no_std`, allocation-free: a [`Meta`] borrows the manifest's bytes.

use super::path::{self, Area};
use super::sig::{self, Role, SigEntry};
use super::version::{Req, Version};
use super::Package;
use crate::json::{self, Kind, Str, Value};
use crate::ncplu::{Arch, CAP_INPUT, CAP_LOG, CAP_PMU, CAP_RNG, CAP_SCREEN, CAP_TIMER};

/// The `format` member this reads.
pub const FORMAT: &str = "ncpkg/2";
/// What an absent `license` means: all rights reserved — not "tainted",
/// not suspicious, just not licensed to copy.
pub const DEFAULT_LICENSE: &str = "Proprietary";

pub const MAX_LIBRARIES: usize = 64;
pub const MAX_DEPENDS: usize = 64;
pub const MAX_PLUGINS: usize = 64;
pub const MAX_COMMANDS: usize = 16;
pub const MAX_FS_GRANTS: usize = 32;

/// What a package installs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgType {
    /// A graphical app (`.ncapp`), ring 3 unless signed for ring 0.
    Gui,
    /// Terminal commands (`.ncapp`), linked into `/usr/bin`.
    Cli,
    /// Only shared libraries (`.ncdyn`), for `/usr/lib`.
    Lib,
}

impl PkgType {
    pub const fn name(self) -> &'static str {
        match self {
            PkgType::Gui => "gui",
            PkgType::Cli => "cli",
            PkgType::Lib => "lib",
        }
    }

    pub fn from_name(s: &str) -> Option<PkgType> {
        match s {
            "gui" => Some(PkgType::Gui),
            "cli" => Some(PkgType::Cli),
            "lib" => Some(PkgType::Lib),
            _ => None,
        }
    }
}

/// An NCFS access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    ReadWrite,
}

impl Access {
    pub const fn name(self) -> &'static str {
        match self {
            Access::Read => "r",
            Access::ReadWrite => "rw",
        }
    }
}

/// How far a package may reach over the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// No sockets at all (the default).
    None,
    /// Outbound connections only.
    Client,
    /// Outbound, and listening.
    Server,
}

impl Network {
    pub const fn name(self) -> &'static str {
        match self {
            Network::None => "none",
            Network::Client => "client",
            Network::Server => "server",
        }
    }

    fn from_name(s: &str) -> Option<Network> {
        match s {
            "none" => Some(Network::None),
            "client" => Some(Network::Client),
            "server" => Some(Network::Server),
            _ => None,
        }
    }
}

/// Device classes a package may ask for, each a node under `/dev`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    Audio,
    Camera,
    Microphone,
    /// The display, exclusively (a full-screen game, a video player).
    Display,
    Gpu,
    Usb,
    Serial,
    Bluetooth,
    /// `/dev/nchv`: NCHV, NanoChronometer's hypervisor (`nchv.ncdri`) —
    /// what a QEMU port accelerates with, as `/dev/kvm` is on Linux.
    Nchv,
}

impl Device {
    pub const ALL: [Device; 9] = [
        Device::Audio,
        Device::Camera,
        Device::Microphone,
        Device::Display,
        Device::Gpu,
        Device::Usb,
        Device::Serial,
        Device::Bluetooth,
        Device::Nchv,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Device::Audio => "audio",
            Device::Camera => "camera",
            Device::Microphone => "microphone",
            Device::Display => "display",
            Device::Gpu => "gpu",
            Device::Usb => "usb",
            Device::Serial => "serial",
            Device::Bluetooth => "bluetooth",
            Device::Nchv => "nchv",
        }
    }

    pub fn from_name(s: &str) -> Option<Device> {
        Device::ALL.into_iter().find(|d| d.name() == s)
    }

    /// The node it opens.
    pub const fn node(self) -> &'static str {
        match self {
            Device::Audio => "/dev/audio",
            Device::Camera => "/dev/camera",
            Device::Microphone => "/dev/microphone",
            Device::Display => "/dev/display",
            Device::Gpu => "/dev/gpu",
            Device::Usb => "/dev/usb",
            Device::Serial => "/dev/serial",
            Device::Bluetooth => "/dev/bluetooth",
            Device::Nchv => "/dev/nchv",
        }
    }
}

/// The app capability names, as the module header's `CAP_*` bits
/// ([`crate::ncplu`]).
pub const CAPABILITIES: [(&str, u32); 6] = [
    ("screen", CAP_SCREEN),
    ("input", CAP_INPUT),
    ("log", CAP_LOG),
    ("timer", CAP_TIMER),
    ("pmu", CAP_PMU),
    ("rng", CAP_RNG),
];

/// Why a manifest was refused, and the field that broke the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    /// A dotted path to the field (`signed.app.entry`).
    pub field: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Json(json::Error),
    WrongType,
    Missing,
    UnknownKey,
    DuplicateKey,
    /// A value the schema does not allow.
    BadValue,
    /// `format` names another version.
    BadFormat,
    TooMany,
    /// Two entries that may not share a value (names, roles, paths).
    Duplicate,
    /// Fields that contradict each other.
    Inconsistent,
    /// The manifest and the container disagree.
    Container,
    /// A signature algorithm that is not a finished standard (a draft
    /// such as Dilithium or SPHINCS+, a KEM, a retired scheme).
    RefusedAlg,
}

impl Error {
    const fn new(kind: ErrorKind, field: &'static str) -> Error {
        Error { kind, field }
    }

    pub const fn message(&self) -> &'static str {
        match self.kind {
            ErrorKind::Json(_) => "the manifest is not valid JSON",
            ErrorKind::WrongType => "a field has the wrong JSON type",
            ErrorKind::Missing => "a required field is missing",
            ErrorKind::UnknownKey => "an unknown field",
            ErrorKind::DuplicateKey => "a field appears twice",
            ErrorKind::BadValue => "a field's value is not allowed",
            ErrorKind::BadFormat => "not an ncpkg/2 manifest",
            ErrorKind::TooMany => "a list is longer than allowed",
            ErrorKind::Duplicate => "two entries share a value they may not",
            ErrorKind::Inconsistent => "fields contradict each other",
            ErrorKind::Container => "the manifest does not match the files in the package",
            ErrorKind::RefusedAlg => "a signature algorithm that is not a finished standard (drafts such as Dilithium or SPHINCS+ are refused: ML-DSA, SLH-DSA)",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.kind {
            ErrorKind::Json(e) => write!(f, "{}: {e}", self.field),
            _ => write!(f, "{}: {}", self.field, self.message()),
        }
    }
}

type R<T> = Result<T, Error>;

/// The members of object `v`, by position in `allowed`; unknown and
/// duplicate keys refused.
fn object<'a, const N: usize>(v: Value<'a>, allowed: [&str; N], field: &'static str) -> R<[Option<Value<'a>>; N]> {
    if v.kind() != Kind::Object {
        return Err(Error::new(ErrorKind::WrongType, field));
    }
    let mut out = [None; N];
    for (k, val) in v.members() {
        let i = allowed.iter().position(|a| k.eq_str(a)).ok_or(Error::new(ErrorKind::UnknownKey, field))?;
        if out[i].is_some() {
            return Err(Error::new(ErrorKind::DuplicateKey, field));
        }
        out[i] = Some(val);
    }
    Ok(out)
}

fn required<'a>(v: Option<Value<'a>>, field: &'static str) -> R<Value<'a>> {
    v.ok_or(Error::new(ErrorKind::Missing, field))
}

/// A machine field: a string without escapes.
fn plain<'a>(v: Value<'a>, field: &'static str) -> R<&'a str> {
    let s = v.as_str().ok_or(Error::new(ErrorKind::WrongType, field))?;
    s.as_plain().ok_or(Error::new(ErrorKind::BadValue, field))
}

/// Human text: 1..=`max` characters, no control characters (`\n` and `\t`
/// too when `multiline`).
fn text<'a>(v: Value<'a>, field: &'static str, max: usize, multiline: bool) -> R<Str<'a>> {
    let s = v.as_str().ok_or(Error::new(ErrorKind::WrongType, field))?;
    let mut n = 0;
    for c in s.chars() {
        n += 1;
        let control = c.is_control() && !(multiline && (c == '\n' || c == '\t'));
        if control || n > max || c == '\u{FFFD}' {
            return Err(Error::new(ErrorKind::BadValue, field));
        }
    }
    if n == 0 {
        return Err(Error::new(ErrorKind::BadValue, field));
    }
    Ok(s)
}

fn array<'a>(v: Value<'a>, field: &'static str, max: usize) -> R<Value<'a>> {
    if v.kind() != Kind::Array {
        return Err(Error::new(ErrorKind::WrongType, field));
    }
    if v.elements().count() > max {
        return Err(Error::new(ErrorKind::TooMany, field));
    }
    Ok(v)
}

fn boolean(v: Value<'_>, field: &'static str) -> R<bool> {
    v.as_bool().ok_or(Error::new(ErrorKind::WrongType, field))
}

/// An SPDX license expression, kept to what packages use: identifiers
/// (`MIT`, `GPL-2.0-only`, `LicenseRef-Acme`) joined by ` OR ` / ` AND `.
fn is_license(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.split(" OR ").all(|alt| {
            alt.split(" AND ").all(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-')))
        })
}

fn is_url(s: &str) -> bool {
    (s.starts_with("https://") || s.starts_with("http://"))
        && s.len() <= 512
        && s.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// An NCFS permission path: an absolute path, or one of the variables the
/// system expands per package and user, each optionally followed by
/// components.
fn is_fs_template(s: &str) -> bool {
    let rest = ["$APPDATA", "$HOME", "$MEDIA", "$TMP"].iter().find_map(|v| s.strip_prefix(v));
    let rest = match rest {
        Some(r) => r,
        None if s.starts_with('/') => s,
        None => return false,
    };
    s.len() <= 255 && (rest.is_empty() || (rest.starts_with('/') && rest.len() > 1 && rest[1..].split('/').all(path::is_component)))
}

fn is_tag(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'+' | b'-' | b'/' | b'_'))
}

const SIGNED_KEYS: [&str; 18] = [
    "id", "name", "version", "type", "summary", "description", "license", "creator", "homepage", "arch", "abi", "system",
    "app", "libraries", "depends", "plugins", "permissions", "files",
];

/// A validated manifest.
#[derive(Debug, Clone, Copy)]
pub struct Meta<'a> {
    text: &'a [u8],
    signed: Value<'a>,
    signatures: Value<'a>,
    id: &'a str,
    name: Str<'a>,
    version: &'a str,
    kind: PkgType,
    summary: Option<Str<'a>>,
    description: Option<Str<'a>>,
    license: Option<&'a str>,
    creator: Option<Value<'a>>,
    homepage: Option<&'a str>,
    arch_mask: u16,
    abi: u32,
    system: Option<&'a str>,
    app: Option<Value<'a>>,
    libraries: Option<Value<'a>>,
    depends: Option<Value<'a>>,
    plugins: Option<Value<'a>>,
    permissions: Option<Value<'a>>,
    files: Value<'a>,
    file_count: usize,
}

/// The app section.
#[derive(Debug, Clone, Copy)]
pub struct App<'a> {
    /// The module's file name under `ncapp/<arch>/`.
    pub entry: &'a str,
    /// 3 (the default) or 0.
    pub ring: u8,
    /// `CAP_*` bits the app declares.
    pub capabilities: u32,
    commands: Option<Value<'a>>,
    categories: Option<Value<'a>>,
}

impl<'a> App<'a> {
    pub fn commands(&self) -> impl Iterator<Item = &'a str> + 'a {
        let v = self.commands;
        v.into_iter().flat_map(|v| v.elements()).filter_map(|e| e.as_str()?.as_plain())
    }

    pub fn categories(&self) -> impl Iterator<Item = Str<'a>> + 'a {
        let v = self.categories;
        v.into_iter().flat_map(|v| v.elements()).filter_map(|e| e.as_str())
    }
}

/// A shared library the package ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Library<'a> {
    pub name: &'a str,
    pub version: &'a str,
    /// File name under `lib/<arch>/`.
    pub file: &'a str,
    /// May be installed in `/usr/lib` for every package (the default);
    /// `false` keeps it private to this package whatever happens.
    pub share: bool,
}

/// A requirement on a shared library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Depend<'a> {
    pub lib: &'a str,
    pub req: &'a str,
}

/// What a package accepts for one library it uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement<'a> {
    /// Stated in `depends`.
    Explicit(&'a str),
    /// Not stated, but shipped: compatible updates of the shipped version
    /// (`^version`).
    Caret(&'a str),
}

impl Requirement<'_> {
    pub fn matches(&self, v: &Version<'_>) -> bool {
        match self {
            Requirement::Explicit(r) => Req::parse(r).is_some_and(|r| r.matches(v)),
            Requirement::Caret(shipped) => {
                // `^` and the shipped version, its build metadata dropped
                // (a requirement compares none).
                let core = shipped.split('+').next().unwrap_or(shipped);
                let mut buf = [0u8; 1 + super::version::MAX_LEN];
                buf[0] = b'^';
                let n = core.len().min(super::version::MAX_LEN);
                buf[1..1 + n].copy_from_slice(&core.as_bytes()[..n]);
                core::str::from_utf8(&buf[..1 + n]).ok().and_then(Req::parse).is_some_and(|r| r.matches(v))
            }
        }
    }
}

impl core::fmt::Display for Requirement<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Requirement::Explicit(r) => f.write_str(r),
            Requirement::Caret(v) => write!(f, "^{v}"),
        }
    }
}

/// One library a package uses: what it accepts and the copy it ships, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Use<'a> {
    pub name: &'a str,
    pub requirement: Requirement<'a>,
    pub shipped: Option<Library<'a>>,
}

/// A plugin the package registers with a host app.
#[derive(Debug, Clone, Copy)]
pub struct Plugin<'a> {
    /// File name under `plugins/<arch>/`.
    pub file: &'a str,
    /// The app it extends: a built-in app or an installed package.
    pub host: &'a str,
    provides: Option<Value<'a>>,
}

impl<'a> Plugin<'a> {
    /// What it adds (MIME types, codec names), for the host to route by.
    pub fn provides(&self) -> impl Iterator<Item = &'a str> + 'a {
        let v = self.provides;
        v.into_iter().flat_map(|v| v.elements()).filter_map(|e| e.as_str()?.as_plain())
    }
}

/// One NCFS grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsGrant<'a> {
    pub path: &'a str,
    pub access: Access,
}

/// The permissions a package asks for.
#[derive(Debug, Clone, Copy)]
pub struct Permissions<'a> {
    fs: Option<Value<'a>>,
    devices: Option<Value<'a>>,
    pub network: Network,
}

impl<'a> Permissions<'a> {
    pub fn fs(&self) -> impl Iterator<Item = FsGrant<'a>> + 'a {
        let v = self.fs;
        v.into_iter().flat_map(|v| v.elements()).filter_map(|e| {
            let path = e.get("path")?.as_str()?.as_plain()?;
            let access = if e.get("access")?.as_str()?.eq_str("rw") { Access::ReadWrite } else { Access::Read };
            Some(FsGrant { path, access })
        })
    }

    pub fn devices(&self) -> impl Iterator<Item = Device> + 'a {
        let v = self.devices;
        v.into_iter().flat_map(|v| v.elements()).filter_map(|e| Device::from_name(e.as_str()?.as_plain()?))
    }
}

/// A file the manifest lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRef<'a> {
    pub path: &'a str,
    pub size: u64,
    pub sha512: [u8; 64],
}

/// The author, when named.
#[derive(Debug, Clone, Copy)]
pub struct Creator<'a> {
    pub name: Str<'a>,
    pub email: Option<&'a str>,
    pub url: Option<&'a str>,
}

fn file_ref(e: Value<'_>) -> Option<FileRef<'_>> {
    Some(FileRef {
        path: e.get("path")?.as_str()?.as_plain()?,
        size: e.get("size")?.as_u64()?,
        sha512: crate::sha512::from_hex(e.get("sha512")?.as_str()?.raw())?,
    })
}

fn library(e: Value<'_>) -> Option<Library<'_>> {
    Some(Library {
        name: e.get("name")?.as_str()?.as_plain()?,
        version: e.get("version")?.as_str()?.as_plain()?,
        file: e.get("file")?.as_str()?.as_plain()?,
        share: e.get("share").and_then(|v| v.as_bool()).unwrap_or(true),
    })
}

fn depend(e: Value<'_>) -> Option<Depend<'_>> {
    Some(Depend { lib: e.get("lib")?.as_str()?.as_plain()?, req: e.get("version")?.as_str()?.as_plain()? })
}

fn signature(e: Value<'_>) -> Option<SigEntry<'_>> {
    Some(SigEntry {
        role: Role::from_name(e.get("role")?.as_str()?.as_plain()?)?,
        alg: e.get("alg")?.as_str()?.as_plain()?,
        key: e.get("key")?.as_str()?.as_plain()?,
        pubkey: e.get("pubkey").and_then(|v| v.as_str()),
        sig: e.get("sig")?.as_str()?,
    })
}

impl<'a> Meta<'a> {
    /// Validates a manifest. See the module docs for the rules.
    pub fn parse(input: &'a [u8]) -> R<Meta<'a>> {
        let root = json::parse(input, &json::Limits::MANIFEST).map_err(|e| Error::new(ErrorKind::Json(e), "ncpkg.meta"))?;
        let [format, signed, signatures] = object(root, ["format", "signed", "signatures"], "manifest")?;
        if plain(required(format, "format")?, "format")? != FORMAT {
            return Err(Error::new(ErrorKind::BadFormat, "format"));
        }
        let signed = required(signed, "signed")?;
        let signatures = array(required(signatures, "signatures")?, "signatures", sig::MAX_SIGNATURES)?;
        let f = object(signed, SIGNED_KEYS, "signed")?;
        let [id, name, version, kind, summary, description, license, creator, homepage, arch, abi, system, app, libraries, depends, plugins, permissions, files] = f;

        let id = plain(required(id, "signed.id")?, "signed.id")?;
        if !path::is_package_id(id) {
            return Err(Error::new(ErrorKind::BadValue, "signed.id"));
        }
        let name = text(required(name, "signed.name")?, "signed.name", 128, false)?;
        let version = plain(required(version, "signed.version")?, "signed.version")?;
        if Version::parse(version).is_none() {
            return Err(Error::new(ErrorKind::BadValue, "signed.version"));
        }
        let kind = PkgType::from_name(plain(required(kind, "signed.type")?, "signed.type")?)
            .ok_or(Error::new(ErrorKind::BadValue, "signed.type"))?;
        let summary = summary.map(|v| text(v, "signed.summary", 256, false)).transpose()?;
        let description = description.map(|v| text(v, "signed.description", 4096, true)).transpose()?;
        let license = license.map(|v| plain(v, "signed.license")).transpose()?;
        if license.is_some_and(|l| !is_license(l)) {
            return Err(Error::new(ErrorKind::BadValue, "signed.license"));
        }
        if let Some(c) = creator {
            let [name, email, url] = object(c, ["name", "email", "url"], "signed.creator")?;
            text(required(name, "signed.creator.name")?, "signed.creator.name", 128, false)?;
            if let Some(e) = email.map(|v| plain(v, "signed.creator.email")).transpose()? {
                if e.len() > 254 || !e.contains('@') || !e.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(Error::new(ErrorKind::BadValue, "signed.creator.email"));
                }
            }
            if url.map(|v| plain(v, "signed.creator.url")).transpose()?.is_some_and(|u| !is_url(u)) {
                return Err(Error::new(ErrorKind::BadValue, "signed.creator.url"));
            }
        }
        let homepage = homepage.map(|v| plain(v, "signed.homepage")).transpose()?;
        if homepage.is_some_and(|u| !is_url(u)) {
            return Err(Error::new(ErrorKind::BadValue, "signed.homepage"));
        }

        let arch = array(required(arch, "signed.arch")?, "signed.arch", 9)?;
        let mut arch_mask = 0u16;
        for a in arch.elements() {
            let a = path::arch_dir(plain(a, "signed.arch")?).ok_or(Error::new(ErrorKind::BadValue, "signed.arch"))?;
            let bit = 1u16 << a as u16;
            if arch_mask & bit != 0 {
                return Err(Error::new(ErrorKind::Duplicate, "signed.arch"));
            }
            arch_mask |= bit;
        }
        if arch_mask == 0 {
            return Err(Error::new(ErrorKind::Missing, "signed.arch"));
        }
        let abi = required(abi, "signed.abi")?.as_u64().ok_or(Error::new(ErrorKind::WrongType, "signed.abi"))?;
        let abi = u32::try_from(abi).ok().filter(|&a| a > 0).ok_or(Error::new(ErrorKind::BadValue, "signed.abi"))?;
        let system = system.map(|v| plain(v, "signed.system")).transpose()?;
        if system.is_some_and(|s| Req::parse(s).is_none()) {
            return Err(Error::new(ErrorKind::BadValue, "signed.system"));
        }

        // The app: required for gui and cli, forbidden for lib.
        let mut entry: Option<&'a str> = None;
        match (kind, app) {
            (PkgType::Lib, Some(_)) => return Err(Error::new(ErrorKind::Inconsistent, "signed.app")),
            (PkgType::Lib, None) => {}
            (_, None) => return Err(Error::new(ErrorKind::Missing, "signed.app")),
            (_, Some(a)) => {
                let [e, ring, caps, commands, categories] =
                    object(a, ["entry", "ring", "capabilities", "commands", "categories"], "signed.app")?;
                let e = plain(required(e, "signed.app.entry")?, "signed.app.entry")?;
                if !path::is_file_name(e, ".ncapp") {
                    return Err(Error::new(ErrorKind::BadValue, "signed.app.entry"));
                }
                entry = Some(e);
                if let Some(r) = ring {
                    match r.as_u64() {
                        Some(0 | 3) => {}
                        _ => return Err(Error::new(ErrorKind::BadValue, "signed.app.ring")),
                    }
                }
                if let Some(c) = caps {
                    let mut seen = 0u32;
                    for c in array(c, "signed.app.capabilities", CAPABILITIES.len())?.elements() {
                        let name = plain(c, "signed.app.capabilities")?;
                        let bit = CAPABILITIES.iter().find(|(n, _)| *n == name).map(|(_, b)| *b);
                        let bit = bit.ok_or(Error::new(ErrorKind::BadValue, "signed.app.capabilities"))?;
                        if seen & bit != 0 {
                            return Err(Error::new(ErrorKind::Duplicate, "signed.app.capabilities"));
                        }
                        seen |= bit;
                    }
                }
                let mut n_commands = 0;
                if let Some(c) = commands {
                    let c = array(c, "signed.app.commands", MAX_COMMANDS)?;
                    for (i, cmd) in c.elements().enumerate() {
                        let cmd = plain(cmd, "signed.app.commands")?;
                        if !path::is_name(cmd) {
                            return Err(Error::new(ErrorKind::BadValue, "signed.app.commands"));
                        }
                        if c.elements().take(i).any(|o| o.as_str().is_some_and(|o| o.eq_str(cmd))) {
                            return Err(Error::new(ErrorKind::Duplicate, "signed.app.commands"));
                        }
                        n_commands += 1;
                    }
                }
                if kind == PkgType::Cli && n_commands == 0 {
                    return Err(Error::new(ErrorKind::Missing, "signed.app.commands"));
                }
                if let Some(c) = categories {
                    for c in array(c, "signed.app.categories", 8)?.elements() {
                        text(c, "signed.app.categories", 32, false)?;
                    }
                }
            }
        }

        // Libraries shipped: unique names and files; a lib package shares.
        let mut lib_files: [&str; MAX_LIBRARIES] = [""; MAX_LIBRARIES];
        let mut n_libs = 0;
        if let Some(l) = libraries {
            let l = array(l, "signed.libraries", MAX_LIBRARIES)?;
            for e in l.elements() {
                let [name, version, file, share] = object(e, ["name", "version", "file", "share"], "signed.libraries")?;
                let name = plain(required(name, "signed.libraries.name")?, "signed.libraries.name")?;
                let version = plain(required(version, "signed.libraries.version")?, "signed.libraries.version")?;
                let file = plain(required(file, "signed.libraries.file")?, "signed.libraries.file")?;
                let share = share.map(|v| boolean(v, "signed.libraries.share")).transpose()?.unwrap_or(true);
                if !path::is_name(name) {
                    return Err(Error::new(ErrorKind::BadValue, "signed.libraries.name"));
                }
                if Version::parse(version).is_none() {
                    return Err(Error::new(ErrorKind::BadValue, "signed.libraries.version"));
                }
                if !path::is_file_name(file, ".ncdyn") {
                    return Err(Error::new(ErrorKind::BadValue, "signed.libraries.file"));
                }
                if kind == PkgType::Lib && !share {
                    return Err(Error::new(ErrorKind::Inconsistent, "signed.libraries.share"));
                }
                let dup_name = l.elements().take(n_libs).any(|o| o.get("name").and_then(|v| v.as_str()).is_some_and(|o| o.eq_str(name)));
                let dup_file = lib_files[..n_libs].iter().any(|f| path::cmp_folded(f, file).is_eq());
                if dup_name || dup_file {
                    return Err(Error::new(ErrorKind::Duplicate, "signed.libraries"));
                }
                lib_files[n_libs] = file;
                n_libs += 1;
            }
        }
        if kind == PkgType::Lib && n_libs == 0 {
            return Err(Error::new(ErrorKind::Missing, "signed.libraries"));
        }

        if let Some(d) = depends {
            let d = array(d, "signed.depends", MAX_DEPENDS)?;
            for (i, e) in d.elements().enumerate() {
                let [lib, req] = object(e, ["lib", "version"], "signed.depends")?;
                let lib = plain(required(lib, "signed.depends.lib")?, "signed.depends.lib")?;
                let req = plain(required(req, "signed.depends.version")?, "signed.depends.version")?;
                if !path::is_name(lib) {
                    return Err(Error::new(ErrorKind::BadValue, "signed.depends.lib"));
                }
                let parsed = Req::parse(req).ok_or(Error::new(ErrorKind::BadValue, "signed.depends.version"))?;
                if d.elements().take(i).any(|o| o.get("lib").and_then(|v| v.as_str()).is_some_and(|o| o.eq_str(lib))) {
                    return Err(Error::new(ErrorKind::Duplicate, "signed.depends"));
                }
                // A package must accept the copy it ships itself.
                let shipped = libraries.into_iter().flat_map(|l| l.elements()).filter_map(library).find(|l| l.name == lib);
                if let Some(s) = shipped {
                    if !Version::parse(s.version).is_some_and(|v| parsed.matches(&v)) {
                        return Err(Error::new(ErrorKind::Inconsistent, "signed.depends.version"));
                    }
                }
            }
        }

        let mut plugin_files: [&str; MAX_PLUGINS] = [""; MAX_PLUGINS];
        let mut n_plugins = 0;
        if let Some(p) = plugins {
            for e in array(p, "signed.plugins", MAX_PLUGINS)?.elements() {
                let [file, host, provides] = object(e, ["file", "host", "provides"], "signed.plugins")?;
                let file = plain(required(file, "signed.plugins.file")?, "signed.plugins.file")?;
                let host = plain(required(host, "signed.plugins.host")?, "signed.plugins.host")?;
                if !path::is_file_name(file, ".ncplu") {
                    return Err(Error::new(ErrorKind::BadValue, "signed.plugins.file"));
                }
                if !path::is_package_id(host) || host == id {
                    return Err(Error::new(ErrorKind::BadValue, "signed.plugins.host"));
                }
                if let Some(pr) = provides {
                    for t in array(pr, "signed.plugins.provides", 64)?.elements() {
                        if !is_tag(plain(t, "signed.plugins.provides")?) {
                            return Err(Error::new(ErrorKind::BadValue, "signed.plugins.provides"));
                        }
                    }
                }
                if plugin_files[..n_plugins].iter().any(|f| path::cmp_folded(f, file).is_eq()) {
                    return Err(Error::new(ErrorKind::Duplicate, "signed.plugins"));
                }
                plugin_files[n_plugins] = file;
                n_plugins += 1;
            }
        }

        if let Some(p) = permissions {
            let [fs, devices, network] = object(p, ["fs", "devices", "network"], "signed.permissions")?;
            if let Some(fs) = fs {
                for g in array(fs, "signed.permissions.fs", MAX_FS_GRANTS)?.elements() {
                    let [gpath, access] = object(g, ["path", "access"], "signed.permissions.fs")?;
                    if !is_fs_template(plain(required(gpath, "signed.permissions.fs.path")?, "signed.permissions.fs.path")?) {
                        return Err(Error::new(ErrorKind::BadValue, "signed.permissions.fs.path"));
                    }
                    match plain(required(access, "signed.permissions.fs.access")?, "signed.permissions.fs.access")? {
                        "r" | "rw" => {}
                        _ => return Err(Error::new(ErrorKind::BadValue, "signed.permissions.fs.access")),
                    }
                }
            }
            if let Some(d) = devices {
                let mut seen = 0u16;
                for dev in array(d, "signed.permissions.devices", Device::ALL.len())?.elements() {
                    let dev = Device::from_name(plain(dev, "signed.permissions.devices")?)
                        .ok_or(Error::new(ErrorKind::BadValue, "signed.permissions.devices"))?;
                    let bit = 1u16 << dev as u16;
                    if seen & bit != 0 {
                        return Err(Error::new(ErrorKind::Duplicate, "signed.permissions.devices"));
                    }
                    seen |= bit;
                }
            }
            if let Some(n) = network {
                Network::from_name(plain(n, "signed.permissions.network")?)
                    .ok_or(Error::new(ErrorKind::BadValue, "signed.permissions.network"))?;
            }
        }

        // Files: valid paths, in order, each where the rest of the manifest
        // says it should be; and every architecture complete.
        let files = array(required(files, "signed.files")?, "signed.files", super::MAX_FILES - 1)?;
        let mut app_seen = 0u16;
        let mut lib_seen = [0u16; MAX_LIBRARIES];
        let mut plugin_seen = [0u16; MAX_PLUGINS];
        let mut prev: Option<&str> = None;
        let mut file_count = 0;
        for e in files.elements() {
            let [p, size, sha] = object(e, ["path", "size", "sha512"], "signed.files")?;
            let p = plain(required(p, "signed.files.path")?, "signed.files.path")?;
            let size = required(size, "signed.files.size")?.as_u64().ok_or(Error::new(ErrorKind::WrongType, "signed.files.size"))?;
            let sha = required(sha, "signed.files.sha512")?.as_str().ok_or(Error::new(ErrorKind::WrongType, "signed.files.sha512"))?;
            if size > super::MAX_FILE {
                return Err(Error::new(ErrorKind::BadValue, "signed.files.size"));
            }
            if crate::sha512::from_hex(sha.raw()).is_none() {
                return Err(Error::new(ErrorKind::BadValue, "signed.files.sha512"));
            }
            if let Some(q) = prev {
                if !path::cmp_folded(q, p).is_lt() {
                    return Err(Error::new(ErrorKind::Duplicate, "signed.files"));
                }
            }
            prev = Some(p);
            file_count += 1;
            let area = path::package_path(p).ok_or(Error::new(ErrorKind::BadValue, "signed.files.path"))?;
            let leaf = p.rsplit('/').next().unwrap_or("");
            let depth = p.split('/').count();
            match area {
                Area::Meta => return Err(Error::new(ErrorKind::BadValue, "signed.files.path")),
                Area::Res | Area::Icon => {}
                Area::App(a) | Area::Lib(a) | Area::Plugin(a) => {
                    let bit = 1u16 << a as u16;
                    if arch_mask & bit == 0 || depth != 3 {
                        return Err(Error::new(ErrorKind::Inconsistent, "signed.files"));
                    }
                    match area {
                        Area::App(_) if Some(leaf) == entry => app_seen |= bit,
                        Area::Lib(_) => match lib_files[..n_libs].iter().position(|f| *f == leaf) {
                            Some(i) => lib_seen[i] |= bit,
                            None => return Err(Error::new(ErrorKind::Inconsistent, "signed.files")),
                        },
                        Area::Plugin(_) => match plugin_files[..n_plugins].iter().position(|f| *f == leaf) {
                            Some(i) => plugin_seen[i] |= bit,
                            None => return Err(Error::new(ErrorKind::Inconsistent, "signed.files")),
                        },
                        _ => return Err(Error::new(ErrorKind::Inconsistent, "signed.files")),
                    }
                }
            }
        }
        if (entry.is_some() && app_seen != arch_mask)
            || lib_seen[..n_libs].iter().any(|&m| m != arch_mask)
            || plugin_seen[..n_plugins].iter().any(|&m| m != arch_mask)
        {
            return Err(Error::new(ErrorKind::Inconsistent, "signed.arch"));
        }

        // Signatures: one per role, each in its role's algorithm.
        let mut roles = 0u8;
        for s in signatures.elements() {
            let [role, alg, key, pubkey, sigv] = object(s, ["role", "alg", "key", "pubkey", "sig"], "signatures")?;
            let role = Role::from_name(plain(required(role, "signatures.role")?, "signatures.role")?)
                .ok_or(Error::new(ErrorKind::BadValue, "signatures.role"))?;
            let alg = plain(required(alg, "signatures.alg")?, "signatures.alg")?;
            let key = plain(required(key, "signatures.key")?, "signatures.key")?;
            let sigv = plain(required(sigv, "signatures.sig")?, "signatures.sig")?;
            let bit = 1u8 << role as u8;
            if roles & bit != 0 {
                return Err(Error::new(ErrorKind::Duplicate, "signatures.role"));
            }
            roles |= bit;
            if !sig::is_fingerprint(key) {
                return Err(Error::new(ErrorKind::BadValue, "signatures.key"));
            }
            if alg.split('+').any(|half| sig::refusal(half).is_some()) {
                // A draft, a KEM, a stateful or retired scheme: named, and
                // refused as such rather than as merely unknown.
                return Err(Error::new(ErrorKind::RefusedAlg, "signatures.alg"));
            }
            let (a, b) = sig::parse_alg(alg).ok_or(Error::new(ErrorKind::BadValue, "signatures.alg"))?;
            if role.is_root() && (alg != sig::ROOT_ALG || pubkey.is_some()) {
                return Err(Error::new(ErrorKind::BadValue, "signatures.alg"));
            }
            if role == Role::SelfSigned {
                let pk = plain(required(pubkey, "signatures.pubkey")?, "signatures.pubkey")?;
                match super::base64::decoded_len(pk.as_bytes()) {
                    Some(n) if n > 0 && n <= sig::MAX_PUBKEY_BYTES => {}
                    _ => return Err(Error::new(ErrorKind::BadValue, "signatures.pubkey")),
                }
            }
            let n = super::base64::decoded_len(sigv.as_bytes()).ok_or(Error::new(ErrorKind::BadValue, "signatures.sig"))?;
            let fixed = match (a.sig_len(), b.map(|b| b.sig_len())) {
                (Some(x), None) => Some(x),
                (Some(x), Some(Some(y))) => Some(x + y),
                _ => None,
            };
            if n == 0 || n > sig::MAX_SIG_BYTES || fixed.is_some_and(|f| f != n) {
                return Err(Error::new(ErrorKind::BadValue, "signatures.sig"));
            }
        }

        Ok(Meta {
            text: input,
            signed,
            signatures,
            id,
            name,
            version,
            kind,
            summary,
            description,
            license,
            creator,
            homepage,
            arch_mask,
            abi,
            system,
            app,
            libraries,
            depends,
            plugins,
            permissions,
            files,
            file_count,
        })
    }

    /// The manifest's whole text.
    pub fn text(&self) -> &'a [u8] {
        self.text
    }

    /// The exact bytes the signatures cover.
    pub fn signed_bytes(&self) -> &'a [u8] {
        self.signed.raw()
    }

    pub fn id(&self) -> &'a str {
        self.id
    }

    pub fn name(&self) -> Str<'a> {
        self.name
    }

    pub fn version(&self) -> &'a str {
        self.version
    }

    pub fn version_parsed(&self) -> Version<'a> {
        Version::parse(self.version).unwrap_or(Version { major: 0, minor: 0, patch: 0, pre: "", build: "" })
    }

    pub fn kind(&self) -> PkgType {
        self.kind
    }

    pub fn summary(&self) -> Option<Str<'a>> {
        self.summary
    }

    pub fn description(&self) -> Option<Str<'a>> {
        self.description
    }

    /// The SPDX expression as written, `None` when absent.
    pub fn license(&self) -> Option<&'a str> {
        self.license
    }

    /// The licence, with an absent one read as [`DEFAULT_LICENSE`].
    pub fn license_or_default(&self) -> &'a str {
        self.license.unwrap_or(DEFAULT_LICENSE)
    }

    pub fn creator(&self) -> Option<Creator<'a>> {
        let c = self.creator?;
        Some(Creator {
            name: c.get("name")?.as_str()?,
            email: c.get("email").and_then(|v| v.as_str()?.as_plain()),
            url: c.get("url").and_then(|v| v.as_str()?.as_plain()),
        })
    }

    pub fn homepage(&self) -> Option<&'a str> {
        self.homepage
    }

    /// The architectures the package carries code for.
    pub fn arches(&self) -> impl Iterator<Item = Arch> + '_ {
        (0u16..16).filter(move |i| self.arch_mask & (1 << i) != 0).filter_map(Arch::from_u16)
    }

    pub fn supports(&self, arch: Arch) -> bool {
        self.arch_mask & (1 << arch as u16) != 0
    }

    pub fn abi(&self) -> u32 {
        self.abi
    }

    /// The requirement on the system's version, if stated.
    pub fn system(&self) -> Option<&'a str> {
        self.system
    }

    pub fn app(&self) -> Option<App<'a>> {
        let a = self.app?;
        let entry = a.get("entry")?.as_str()?.as_plain()?;
        let ring = a.get("ring").and_then(|r| r.as_u64()).unwrap_or(3) as u8;
        let capabilities = a
            .get("capabilities")
            .into_iter()
            .flat_map(|c| c.elements())
            .filter_map(|c| {
                let name = c.as_str()?.as_plain()?;
                CAPABILITIES.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
            })
            .fold(0, |acc, b| acc | b);
        Some(App {
            entry,
            ring,
            capabilities,
            commands: a.get("commands"),
            categories: a.get("categories"),
        })
    }

    /// The ring the package asks for: its app's, or 3 for a library.
    pub fn ring(&self) -> u8 {
        self.app().map_or(3, |a| a.ring)
    }

    pub fn libraries(&self) -> impl Iterator<Item = Library<'a>> + 'a {
        let v = self.libraries;
        v.into_iter().flat_map(|v| v.elements()).filter_map(library)
    }

    pub fn depends(&self) -> impl Iterator<Item = Depend<'a>> + 'a {
        let v = self.depends;
        v.into_iter().flat_map(|v| v.elements()).filter_map(depend)
    }

    /// Every library the package uses — stated in `depends`, shipped, or
    /// both — with what it accepts and the copy it carries.
    pub fn uses(&self) -> impl Iterator<Item = Use<'a>> + 'a {
        let me = *self;
        let stated = self.depends().map(move |d| Use {
            name: d.lib,
            requirement: Requirement::Explicit(d.req),
            shipped: me.libraries().find(|l| l.name == d.lib),
        });
        let implied = self.libraries().filter(move |l| !me.depends().any(|d| d.lib == l.name)).map(|l| Use {
            name: l.name,
            requirement: Requirement::Caret(l.version),
            shipped: Some(l),
        });
        stated.chain(implied)
    }

    pub fn plugins(&self) -> impl Iterator<Item = Plugin<'a>> + 'a {
        let v = self.plugins;
        v.into_iter().flat_map(|v| v.elements()).filter_map(|e| {
            Some(Plugin { file: e.get("file")?.as_str()?.as_plain()?, host: e.get("host")?.as_str()?.as_plain()?, provides: e.get("provides") })
        })
    }

    pub fn permissions(&self) -> Permissions<'a> {
        let p = self.permissions;
        Permissions {
            fs: p.and_then(|p| p.get("fs")),
            devices: p.and_then(|p| p.get("devices")),
            network: p
                .and_then(|p| p.get("network"))
                .and_then(|n| Network::from_name(n.as_str()?.as_plain()?))
                .unwrap_or(Network::None),
        }
    }

    pub fn files(&self) -> impl Iterator<Item = FileRef<'a>> + 'a {
        self.files.elements().filter_map(file_ref)
    }

    pub fn file_count(&self) -> usize {
        self.file_count
    }

    /// The listed file at `path`.
    pub fn file(&self, path: &str) -> Option<FileRef<'a>> {
        self.files().find(|f| f.path == path)
    }

    /// The package's icon, `icon.png`, when it has one.
    pub fn icon(&self) -> Option<FileRef<'a>> {
        self.file(path::ICON)
    }

    pub fn signatures(&self) -> impl Iterator<Item = SigEntry<'a>> + 'a {
        self.signatures.elements().filter_map(signature)
    }

    /// Checks every signature with `verifier`.
    pub fn verify(&self, verifier: &mut dyn sig::Verifier, scratch: &mut sig::Scratch) -> sig::Trust {
        sig::evaluate(self.signed_bytes(), self.signatures(), verifier, scratch)
    }

    /// The manifest and the container hold the same files, in the same
    /// order, with the same sizes.
    pub fn check_container(&self, pkg: &Package<'_>) -> R<()> {
        if pkg.file_count() != self.file_count + 1 {
            return Err(Error::new(ErrorKind::Container, "signed.files"));
        }
        for (listed, stored) in self.files().zip(pkg.files()) {
            if listed.path != stored.path || listed.size != stored.size {
                return Err(Error::new(ErrorKind::Container, "signed.files"));
            }
        }
        Ok(())
    }
}

/// What a licence identifier means, in one line for newcomers; dual
/// licences explain themselves as a choice. `""` for an identifier this
/// does not know (it is shown as written).
pub fn license_explain(license: &str) -> &'static str {
    let license = license.trim();
    if let Some((a, b)) = license.split_once(" OR ") {
        return match (license_explain(a), license_explain(b)) {
            ("", _) | (_, "") => "",
            _ => "a choice of licences: either one's terms apply",
        };
    }
    match license {
        "CC0-1.0" | "Unlicense" => "public domain: do anything, no conditions",
        "MIT" | "BSD-2-Clause" | "ISC" | "Zlib" => "do anything, keep the copyright notice",
        "Apache-2.0" => "do anything, keep notices, patents granted",
        "BSD-3-Clause" => "do anything, keep the notice, no endorsement",
        "MPL-2.0" => "changed files stay MPL; the rest may be anything",
        "GPL-2.0" | "GPL-2.0-only" | "GPL-2.0-or-later" | "GPL-3.0" | "GPL-3.0-only" | "GPL-3.0-or-later" => {
            "share alike: derivatives stay GPL"
        }
        "AGPL-3.0" | "AGPL-3.0-only" | "AGPL-3.0-or-later" => "share alike, including over a network",
        "LGPL-2.1" | "LGPL-2.1-only" | "LGPL-2.1-or-later" | "LGPL-3.0" | "LGPL-3.0-only" | "LGPL-3.0-or-later" => {
            "share alike for the library itself"
        }
        "Proprietary" => "all rights reserved: no licence to copy",
        _ => "",
    }
}

/// Building manifests (the packer, the signer, tests).
#[cfg(feature = "alloc")]
pub mod build {
    use crate::json::{Json, Style};
    use alloc::string::String;
    use alloc::vec::Vec;

    /// The manifest text: `format`, the `signed` object in canonical form
    /// (sorted keys, compact) and the signatures.
    pub fn compose(signed: &Json, signatures: &[Json]) -> String {
        splice(&signed.write(Style::CANONICAL), signatures)
    }

    /// The manifest text around `signed`, kept byte for byte: what a signer
    /// writes after adding a signature to an existing manifest.
    pub fn splice(signed: &str, signatures: &[Json]) -> String {
        let mut out = String::from("{\"format\":\"");
        out.push_str(super::FORMAT);
        out.push_str("\",\"signed\":");
        out.push_str(signed);
        out.push_str(",\"signatures\":");
        out.push_str(&Json::Arr(Vec::from(signatures)).write(Style::CANONICAL));
        out.push('}');
        out
    }

    /// One signature entry.
    pub fn signature(role: &str, alg: &str, key: &str, pubkey: Option<&str>, sig: &str) -> Json {
        let mut s = Json::obj([("role", Json::str(role)), ("alg", Json::str(alg)), ("key", Json::str(key))]);
        if let Some(pk) = pubkey {
            s.push("pubkey", Json::str(pk));
        }
        s.push("sig", Json::str(sig));
        s
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::json::Json;
    use std::string::{String, ToString};
    use std::vec::Vec;

    fn hex(d: &[u8; 64]) -> String {
        let mut out = [0u8; 128];
        crate::sha512::to_hex(d, &mut out);
        String::from_utf8(out.to_vec()).unwrap()
    }

    pub(crate) fn file(path: &str, data: &[u8]) -> Json {
        Json::obj([("path", Json::str(path)), ("size", Json::uint(data.len() as u64)), ("sha512", Json::Str(hex(&crate::sha512::digest(data))))])
    }

    /// A full gui manifest's `signed` object: two architectures, a shared
    /// library with a stated requirement, a plugin, permissions.
    pub(crate) fn gui_signed() -> Json {
        Json::obj([
            ("id", Json::str("org.example.player-plus")),
            ("name", Json::str("Player Plus \u{2014} \"extra\" codecs")),
            ("version", Json::str("2.0.1")),
            ("type", Json::str("gui")),
            ("summary", Json::str("More formats for the player")),
            ("license", Json::str("MIT OR Apache-2.0")),
            ("creator", Json::obj([("name", Json::str("Ada")), ("email", Json::str("ada@example.org"))])),
            ("arch", Json::Arr(std::vec![Json::str("x86_64"), Json::str("aarch64")])),
            ("abi", Json::Int(1)),
            ("system", Json::str(">=4.0.0")),
            (
                "app",
                Json::obj([
                    ("entry", Json::str("main.ncapp")),
                    ("ring", Json::Int(3)),
                    ("capabilities", Json::Arr(std::vec![Json::str("screen"), Json::str("input")])),
                ]),
            ),
            (
                "libraries",
                Json::Arr(std::vec![Json::obj([
                    ("name", Json::str("libavcodec")),
                    ("version", Json::str("61.3.100")),
                    ("file", Json::str("libavcodec.ncdyn")),
                ])]),
            ),
            ("depends", Json::Arr(std::vec![Json::obj([("lib", Json::str("libavcodec")), ("version", Json::str(">=61.0.0, <62.0.0"))])])),
            (
                "plugins",
                Json::Arr(std::vec![Json::obj([
                    ("file", Json::str("vgm.ncplu")),
                    ("host", Json::str("nc.player")),
                    ("provides", Json::Arr(std::vec![Json::str("audio/x-adx")])),
                ])]),
            ),
            (
                "permissions",
                Json::obj([
                    ("fs", Json::Arr(std::vec![Json::obj([("path", Json::str("$HOME/Music")), ("access", Json::str("r"))])])),
                    ("devices", Json::Arr(std::vec![Json::str("audio")])),
                    ("network", Json::str("client")),
                ]),
            ),
            (
                "files",
                Json::Arr(std::vec![
                    file("icon.png", b"png"),
                    file("lib/aarch64/libavcodec.ncdyn", b"arm lib"),
                    file("lib/x86_64/libavcodec.ncdyn", b"x86 lib"),
                    file("ncapp/aarch64/main.ncapp", b"arm app"),
                    file("ncapp/x86_64/main.ncapp", b"x86 app"),
                    file("plugins/aarch64/vgm.ncplu", b"arm plugin"),
                    file("plugins/x86_64/vgm.ncplu", b"x86 plugin"),
                    file("res/icon.png", b"png"),
                ]),
            ),
        ])
    }

    fn manifest(signed: &Json) -> String {
        build::compose(signed, &[])
    }

    fn parse_err(signed: &Json) -> Error {
        let text = manifest(signed);
        Meta::parse(text.as_bytes()).err().unwrap_or_else(|| panic!("accepted: {text}"))
    }

    #[test]
    fn a_full_manifest_reads_back() {
        let text = manifest(&gui_signed());
        let m = Meta::parse(text.as_bytes()).unwrap();
        assert_eq!(m.id(), "org.example.player-plus");
        assert_eq!(m.name().to_string(), "Player Plus \u{2014} \"extra\" codecs");
        assert_eq!(m.version(), "2.0.1");
        assert_eq!(m.kind(), PkgType::Gui);
        assert_eq!(m.license_or_default(), "MIT OR Apache-2.0");
        assert_eq!(m.creator().unwrap().email, Some("ada@example.org"));
        assert_eq!(m.arches().collect::<Vec<_>>(), [Arch::X86_64, Arch::Aarch64]);
        assert!(m.supports(Arch::Aarch64) && !m.supports(Arch::Riscv64));
        let app = m.app().unwrap();
        assert_eq!((app.entry, app.ring, app.capabilities), ("main.ncapp", 3, CAP_SCREEN | CAP_INPUT));
        assert_eq!(m.icon().unwrap().sha512, crate::sha512::digest(b"png"));
        let uses: Vec<Use<'_>> = m.uses().collect();
        assert_eq!(uses.len(), 1);
        assert_eq!(uses[0].requirement, Requirement::Explicit(">=61.0.0, <62.0.0"));
        assert_eq!(uses[0].shipped.unwrap().file, "libavcodec.ncdyn");
        let plugin = m.plugins().next().unwrap();
        assert_eq!((plugin.host, plugin.provides().collect::<Vec<_>>()), ("nc.player", std::vec!["audio/x-adx"]));
        let perms = m.permissions();
        assert_eq!(perms.network, Network::Client);
        assert_eq!(perms.devices().collect::<Vec<_>>(), [Device::Audio]);
        assert_eq!(perms.fs().next().unwrap(), FsGrant { path: "$HOME/Music", access: Access::Read });
        assert_eq!(m.file_count(), 8);
        assert_eq!(m.file("res/icon.png").unwrap().sha512, crate::sha512::digest(b"png"));
        assert_eq!(m.signatures().count(), 0);
        // The signed bytes are the canonical `signed` object, exactly.
        assert_eq!(m.signed_bytes(), gui_signed().write(crate::json::Style::CANONICAL).as_bytes());
    }

    #[test]
    fn an_absent_licence_reads_as_proprietary() {
        let mut s = gui_signed();
        if let Json::Obj(m) = &mut s {
            m.retain(|(k, _)| k != "license");
        }
        let text = manifest(&s);
        let m = Meta::parse(text.as_bytes()).unwrap();
        assert_eq!(m.license(), None);
        assert_eq!(m.license_or_default(), "Proprietary");
        assert!(license_explain("Proprietary").contains("rights reserved"));
        assert!(license_explain("MIT OR Apache-2.0").contains("choice"));
    }

    fn with(mut s: Json, path: &[&str], value: Option<Json>) -> Json {
        fn go(j: &mut Json, path: &[&str], value: Option<Json>) {
            let Json::Obj(members) = j else { panic!("not an object at {path:?}") };
            if path.len() == 1 {
                members.retain(|(k, _)| k != path[0]);
                if let Some(v) = value {
                    members.push((path[0].to_string(), v));
                }
                return;
            }
            let next = members.iter_mut().find(|(k, _)| k == path[0]).map(|(_, v)| v).expect("path");
            go(next, &path[1..], value);
        }
        go(&mut s, path, value);
        s
    }

    #[test]
    fn each_rule_has_its_error() {
        let base = gui_signed();
        let cases: Vec<(&str, Json, ErrorKind, &str)> = std::vec![
            ("no id", with(base.clone(), &["id"], None), ErrorKind::Missing, "signed.id"),
            ("bad id", with(base.clone(), &["id"], Some(Json::str("Player"))), ErrorKind::BadValue, "signed.id"),
            ("bad version", with(base.clone(), &["version"], Some(Json::str("2.0"))), ErrorKind::BadValue, "signed.version"),
            ("bad type", with(base.clone(), &["type"], Some(Json::str("game"))), ErrorKind::BadValue, "signed.type"),
            ("unknown key", with(base.clone(), &["colour"], Some(Json::str("red"))), ErrorKind::UnknownKey, "signed"),
            ("name with a newline", with(base.clone(), &["name"], Some(Json::str("a\nb"))), ErrorKind::BadValue, "signed.name"),
            ("no arch", with(base.clone(), &["arch"], Some(Json::Arr(Vec::new()))), ErrorKind::Missing, "signed.arch"),
            ("alias arch", with(base.clone(), &["arch"], Some(Json::Arr(std::vec![Json::str("arm64")]))), ErrorKind::BadValue, "signed.arch"),
            ("abi zero", with(base.clone(), &["abi"], Some(Json::Int(0))), ErrorKind::BadValue, "signed.abi"),
            ("gui without app", with(base.clone(), &["app"], None), ErrorKind::Missing, "signed.app"),
            ("ring 1", with(base.clone(), &["app", "ring"], Some(Json::Int(1))), ErrorKind::BadValue, "signed.app.ring"),
            ("unknown capability", with(base.clone(), &["app", "capabilities"], Some(Json::Arr(std::vec![Json::str("root")]))), ErrorKind::BadValue, "signed.app.capabilities"),
            ("entry not an ncapp", with(base.clone(), &["app", "entry"], Some(Json::str("main.exe"))), ErrorKind::BadValue, "signed.app.entry"),
            ("app.icon is gone: the icon is icon.png", with(base.clone(), &["app", "icon"], Some(Json::str("res/icon.png"))), ErrorKind::UnknownKey, "signed.app"),
            ("shipped copy refused by its own requirement", with(base.clone(), &["depends"], Some(Json::Arr(std::vec![Json::obj([("lib", Json::str("libavcodec")), ("version", Json::str("^62"))])]))), ErrorKind::Inconsistent, "signed.depends.version"),
            ("plugin hosted by itself", with(base.clone(), &["plugins"], Some(Json::Arr(std::vec![Json::obj([("file", Json::str("vgm.ncplu")), ("host", Json::str("org.example.player-plus"))])]))), ErrorKind::BadValue, "signed.plugins.host"),
            ("unknown device", with(base.clone(), &["permissions", "devices"], Some(Json::Arr(std::vec![Json::str("kmem")]))), ErrorKind::BadValue, "signed.permissions.devices"),
            ("relative fs path", with(base.clone(), &["permissions", "fs"], Some(Json::Arr(std::vec![Json::obj([("path", Json::str("Music")), ("access", Json::str("r"))])]))), ErrorKind::BadValue, "signed.permissions.fs.path"),
            ("fs path climbing out", with(base.clone(), &["permissions", "fs"], Some(Json::Arr(std::vec![Json::obj([("path", Json::str("$HOME/../etc")), ("access", Json::str("r"))])]))), ErrorKind::BadValue, "signed.permissions.fs.path"),
            ("bad network", with(base.clone(), &["permissions", "network"], Some(Json::str("all"))), ErrorKind::BadValue, "signed.permissions.network"),
        ];
        for (what, signed, kind, field) in cases {
            let e = parse_err(&signed);
            assert_eq!((e.kind, e.field), (kind, field), "{what}: {e}");
        }
    }

    #[test]
    fn files_and_architectures_must_agree() {
        let base = gui_signed();
        let files = |list: Vec<Json>| with(base.clone(), &["files"], Some(Json::Arr(list)));
        let all = || match base.get("files") {
            Some(Json::Arr(v)) => v.clone(),
            _ => unreachable!(),
        };
        // An architecture missing its plugin.
        let mut v = all();
        v.retain(|f| f.get("path") != Some(&Json::str("plugins/aarch64/vgm.ncplu")));
        assert_eq!(parse_err(&files(v)).kind, ErrorKind::Inconsistent);
        // A file for an architecture not listed.
        let mut v = all();
        v.insert(4, file("ncapp/riscv64/main.ncapp", b"rv"));
        assert_eq!(parse_err(&files(v)).kind, ErrorKind::Inconsistent);
        // An undeclared library.
        let mut v = all();
        v.insert(2, file("lib/aarch64/libzz.ncdyn", b"?"));
        assert_eq!(parse_err(&files(v)).kind, ErrorKind::Inconsistent);
        // Out of order.
        let mut v = all();
        v.swap(0, 1);
        assert_eq!(parse_err(&files(v)).kind, ErrorKind::Duplicate);
        // Twice, differing only in case.
        let mut v = all();
        v.push(file("res/ICON.png", b"png"));
        assert_eq!(parse_err(&files(v)).kind, ErrorKind::Duplicate);
        // Upper-case hex.
        let mut v = all();
        v[7] = Json::obj([("path", Json::str("res/icon.png")), ("size", Json::Int(3)), ("sha512", Json::Str("A".repeat(128)))]);
        assert_eq!(parse_err(&files(v)).kind, ErrorKind::BadValue);
    }

    #[test]
    fn library_packages() {
        let lib = Json::obj([
            ("id", Json::str("org.ffmpeg.libs")),
            ("name", Json::str("FFmpeg libraries")),
            ("version", Json::str("7.1.0")),
            ("type", Json::str("lib")),
            ("arch", Json::Arr(std::vec![Json::str("x86_64")])),
            ("abi", Json::Int(1)),
            ("libraries", Json::Arr(std::vec![Json::obj([("name", Json::str("libavcodec")), ("version", Json::str("61.19.100")), ("file", Json::str("libavcodec.ncdyn"))])])),
            ("files", Json::Arr(std::vec![file("lib/x86_64/libavcodec.ncdyn", b"lib")])),
        ]);
        let text = manifest(&lib);
        let m = Meta::parse(text.as_bytes()).unwrap();
        assert_eq!(m.kind(), PkgType::Lib);
        assert_eq!(m.ring(), 3);
        assert_eq!(m.uses().next().unwrap().requirement, Requirement::Caret("61.19.100"));
        assert!(m.uses().next().unwrap().requirement.matches(&Version::parse("61.20.0").unwrap()));
        assert!(!m.uses().next().unwrap().requirement.matches(&Version::parse("62.0.0").unwrap()));
        let with_app = with(lib.clone(), &["app"], Some(Json::obj([("entry", Json::str("main.ncapp"))])));
        assert_eq!(parse_err(&with_app).kind, ErrorKind::Inconsistent);
        let private = with(lib.clone(), &["libraries"], Some(Json::Arr(std::vec![Json::obj([("name", Json::str("libavcodec")), ("version", Json::str("61.19.100")), ("file", Json::str("libavcodec.ncdyn")), ("share", Json::Bool(false))])])));
        assert_eq!(parse_err(&private).kind, ErrorKind::Inconsistent);
        let empty = with(lib, &["libraries"], None);
        assert_eq!(parse_err(&empty).kind, ErrorKind::Missing);
    }

    #[test]
    fn signatures_are_checked_for_shape() {
        let signed = gui_signed();
        let sig = |role: &str, alg: &str, n: usize, pubkey: Option<&str>| {
            build::signature(role, alg, "0123-4567-89ab-cdef", pubkey, &super::super::base64::encode_string(&std::vec![7u8; n]))
        };
        let ok = build::compose(&signed, &[sig("creator-ring3", "mldsa87+p521", 4759, None), sig("self", "ed25519", 64, Some("AAAA"))]);
        let m = Meta::parse(ok.as_bytes()).unwrap();
        assert_eq!(m.signatures().count(), 2);
        let bad = [
            build::compose(&signed, &[sig("creator-ring3", "ed25519", 64, None)]),
            build::compose(&signed, &[sig("creator-ring3", "mldsa87+p521", 100, None)]),
            build::compose(&signed, &[sig("creator-ring0", "mldsa87+p521", 4759, Some("AAAA"))]),
            build::compose(&signed, &[sig("self", "ed25519", 64, None)]),
            build::compose(&signed, &[sig("self", "ed25519", 63, Some("AAAA"))]),
            build::compose(&signed, &[sig("verify-ring3", "mldsa87+p521", 4759, None), sig("verify-ring3", "mldsa87+p521", 4759, None)]),
            build::compose(&signed, &[sig("root", "mldsa87+p521", 4759, None)]),
        ];
        for text in &bad {
            assert!(Meta::parse(text.as_bytes()).is_err(), "{}", &text[text.find("signatures").unwrap()..][..120]);
        }
    }

    #[test]
    fn the_manifest_is_bound_to_the_container() {
        let signed = gui_signed();
        let text = manifest(&signed);
        let mut b = super::super::Builder::new(text.clone().into_bytes());
        for (p, d) in [
            ("icon.png", &b"png"[..]),
            ("lib/aarch64/libavcodec.ncdyn", &b"arm lib"[..]),
            ("lib/x86_64/libavcodec.ncdyn", b"x86 lib"),
            ("ncapp/aarch64/main.ncapp", b"arm app"),
            ("ncapp/x86_64/main.ncapp", b"x86 app"),
            ("plugins/aarch64/vgm.ncplu", b"arm plugin"),
            ("plugins/x86_64/vgm.ncplu", b"x86 plugin"),
            ("res/icon.png", b"png"),
        ] {
            b.add_stored(p, d.to_vec()).unwrap();
        }
        let bytes = b.finish().unwrap();
        let pkg = Package::parse(&bytes).unwrap();
        let m = Meta::parse(pkg.meta()).unwrap();
        m.check_container(&pkg).unwrap();
        // One file fewer in the container than in the manifest.
        let mut b = super::super::Builder::new(text.into_bytes());
        b.add_stored("res/icon.png", b"png".to_vec()).unwrap();
        let bytes = b.finish().unwrap();
        let pkg = Package::parse(&bytes).unwrap();
        assert_eq!(Meta::parse(pkg.meta()).unwrap().check_container(&pkg).err().unwrap().kind, ErrorKind::Container);
    }

    #[test]
    fn duplicate_keys_are_refused_at_every_level() {
        let text = manifest(&gui_signed());
        let dup_top = text.replacen("{\"format\":\"ncpkg/2\",", "{\"format\":\"ncpkg/2\",\"format\":\"ncpkg/2\",", 1);
        assert_eq!(Meta::parse(dup_top.as_bytes()).err().unwrap().kind, ErrorKind::DuplicateKey);
        let dup_id = text.replacen("\"id\":", "\"id\":\"org.evil.app\",\"id\":", 1);
        assert_eq!(Meta::parse(dup_id.as_bytes()).err().unwrap().kind, ErrorKind::DuplicateKey);
        let escaped_dup = text.replacen("\"id\":", "\"\\u0069d\":\"org.evil.app\",\"id\":", 1);
        assert_eq!(Meta::parse(escaped_dup.as_bytes()).err().unwrap().kind, ErrorKind::DuplicateKey);
        let escaped_value = text.replacen("\"version\":\"2.0.1\"", "\"version\":\"2.0.\\u0031\"", 1);
        assert_eq!(Meta::parse(escaped_value.as_bytes()).err().unwrap().kind, ErrorKind::BadValue);
        let wrong_format = text.replacen("ncpkg/2", "ncpkg/3", 1);
        assert_eq!(Meta::parse(wrong_format.as_bytes()).err().unwrap().kind, ErrorKind::BadFormat);
    }

    #[test]
    fn corrupted_manifests_never_panic() {
        let base = build::compose(
            &gui_signed(),
            &[build::signature("self", "ed25519", "0123-4567-89ab-cdef", Some("AAAA"), &super::super::base64::encode_string(&[1u8; 64]))],
        )
        .into_bytes();
        let mut x = 0x1357_9BDF_2468_ACE0u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut accepted = 0;
        for _ in 0..10_000 {
            let mut b = base.clone();
            for _ in 0..(next() % 3 + 1) {
                let r = next();
                let at = (r >> 8) as usize % b.len();
                match r % 3 {
                    0 => {
                        let set = b"{}[]\",:0123456789abcdefx-/. ";
                        b[at] = set[(r >> 32) as usize % set.len()];
                    }
                    1 => {
                        b.remove(at);
                    }
                    _ => b.insert(at, b"\"0,}]"[(r >> 32) as usize % 5]),
                }
            }
            if let Ok(m) = Meta::parse(&b) {
                accepted += 1;
                let _ = (m.app(), m.creator(), m.permissions().network, m.ring());
                let _ = m.uses().count() + m.plugins().count() + m.files().count() + m.signatures().count();
            }
        }
        // Most mutations break the manifest; some land in free text.
        let _ = accepted;
    }
}
