// SPDX-License-Identifier: Apache-2.0
//! The file tree a session sees: one read-only namespace, assembled at boot
//! from what the loader handed over and what the kernel knows.
//!
//! * `/etc`, `/usr/share/doc`: files built into the image.
//! * Every boot module at the path its string names (`crate::boot`):
//!   `/usr/lib/libfoo.ncdyn` is where a shared library of the ecosystem is
//!   found by the loader, `/apps/X.NCPKG` a package, `/boot/drivers/X.NCDRI`
//!   a driver. A module with no path goes under `/boot/`. An initrd built
//!   with the host's `ncpkg --root` brings installed packages: `/apps/<id>/`,
//!   `/usr/lib`, and the database in `/var/lib/ncpkg/db.json`.
//! * A cpio archive (`newc`, what `cpio -o -H newc` and the Linux initramfs
//!   tools write) passed as a module named `initrd` or `*.cpio`, or as the
//!   device tree's initrd, unpacked into the same tree.
//! * An NCFS image — the `ncinitramdisk`, sealed or not — merged into the
//!   tree by `crate::initramdisk`, its seal judged and every file checked
//!   against its BLAKE3.
//! * `/proc`: files generated when read — `version`, `cmdline`, `uptime`,
//!   `meminfo`, `cpuinfo`, `cpuctl`, `modules`, `kmsg`.
//! * `/dev`: `null`, `zero` and `random` (NC_RNG).
//!
//! Nothing is copied: a file is a slice of the module or the image it lives
//! in, which the loader's memory and the image keep valid for the whole run.
//! Untrusted input (a cpio archive) is parsed with every offset checked; a
//! malformed archive stops where it breaks, it never reads past its end.

use crate::text::Text;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};

/// What a file holds.
#[derive(Clone, Copy)]
pub enum Content {
    Bytes(&'static [u8]),
    /// Generated when read.
    Proc(Proc),
    Dev(Dev),
    /// An explicit directory (others exist implicitly, as path prefixes).
    Dir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proc {
    Version,
    Cmdline,
    Uptime,
    Meminfo,
    Cpuinfo,
    Cpuctl,
    Modules,
    Kmsg,
    Initramdisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dev {
    Null,
    Zero,
    Random,
}

#[derive(Clone, Copy)]
pub struct Node {
    pub path: Text<128>,
    pub content: Content,
}

impl Node {
    /// The size, where it is known without generating the file.
    pub fn size(&self) -> Option<usize> {
        match self.content {
            Content::Bytes(b) => Some(b.len()),
            _ => None,
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.content, Content::Dir)
    }
}

const MAX_NODES: usize = 1024;
static mut NODES: [Option<Node>; MAX_NODES] = [None; MAX_NODES];
static COUNT: AtomicUsize = AtomicUsize::new(0);

fn add(path: &str, content: Content) {
    let n = COUNT.load(Ordering::Relaxed);
    if n >= MAX_NODES || path.len() > 127 {
        return;
    }
    let mut p = Text::<128>::new();
    p.str(path);
    // SAFETY: built at boot, on one core, before anything reads the table;
    // slots below the published count never change.
    unsafe { (*core::ptr::addr_of_mut!(NODES))[n] = Some(Node { path: p, content }) };
    COUNT.store(n + 1, Ordering::Relaxed);
}

/// A directory, for code that builds the tree at boot (`initramdisk`).
pub(crate) fn add_dir(path: &str) {
    add(path, Content::Dir);
}

/// A file whose bytes live for the whole session.
pub(crate) fn add_file(path: &str, bytes: &'static [u8]) {
    add(path, Content::Bytes(bytes));
}

fn nodes() -> &'static [Option<Node>] {
    let n = COUNT.load(Ordering::Relaxed);
    // SAFETY: see `add`.
    let all: &'static [Option<Node>; MAX_NODES] = unsafe { &*core::ptr::addr_of!(NODES) };
    &all[..n]
}

const MOTD: &str = "\
Welcome to NanoChronometer — a chronometer with no operating system under it.

  nanochrono --help     the same commands as the hosted CLI
  help                  every shell command
  top                   what the machine is doing, live
  gui                   the NanoChronometer GUI

";

const OS_RELEASE: &str = concat!(
    "NAME=\"NanoChronometer\"\n",
    "ID=nanochronometer\n",
    "VERSION=\"",
    env!("CARGO_PKG_VERSION"),
    "\"\n",
    "PRETTY_NAME=\"NanoChronometer ",
    env!("CARGO_PKG_VERSION"),
    " (freestanding)\"\n",
    "HOME_URL=\"https://github.com/nanochronometer/nanochronometer\"\n",
);

const ECOSYSTEM: &str = "\
The NanoChronometer ecosystem's file types

  .ncpkg   a package: one compressed download for every architecture, like
           an XAPK. ncpkg.meta (the signed manifest), ncapp/<arch>/ (the app),
           lib/<arch>/ (.ncdyn), plugins/<arch>/ (.ncplu), res/ (shared
           assets). Types: gui, cli, lib. `ncpkg info <file>` reads one.
  .ncapp   one app for one architecture, in ring 3 (gui or cli).
  .ncdyn   a shared library, loaded at run time: in /usr/lib, counted by
           ncpkg (ref_count), or private to a package whose version differs.
  .ncplu   a plugin of one app: a codec pack for the players, loaded by them.
  .ncar    a static library archive (llvm-ar), linked into an .ncapp.
  .ncdri   a driver module for what the kernel does not build in. No licence
           header needed: none means proprietary, never \"tainted\".
  NCFS     the system's own filesystem (planned); mountable from Linux (FUSE
           or the nanochrono module) and Windows (the GUI or the .sys).

  /dev/nchv  NCHV, the hypervisor (nchv.ncdri, after bhyve; planned): the
           accelerator a QEMU port uses, and what NCVBS stands on.
";

/// Builds the tree: the built-in files, `/proc`, `/dev`, and every module.
///
/// # Safety
/// Once, at boot, after the modules are recorded (`crate::boot`).
pub unsafe fn init() {
    if COUNT.load(Ordering::Relaxed) != 0 {
        return;
    }
    for dir in ["/", "/etc", "/proc", "/dev", "/boot", "/usr", "/usr/lib", "/usr/share", "/apps", "/mnt"] {
        add(dir, Content::Dir);
    }
    add("/etc/motd", Content::Bytes(MOTD.as_bytes()));
    add("/etc/os-release", Content::Bytes(OS_RELEASE.as_bytes()));
    add("/etc/hostname", Content::Bytes(b"nanochronometer\n"));
    add("/usr/share/doc/ECOSYSTEM", Content::Bytes(ECOSYSTEM.as_bytes()));
    for (name, p) in [
        ("version", Proc::Version),
        ("cmdline", Proc::Cmdline),
        ("uptime", Proc::Uptime),
        ("meminfo", Proc::Meminfo),
        ("cpuinfo", Proc::Cpuinfo),
        ("cpuctl", Proc::Cpuctl),
        ("modules", Proc::Modules),
        ("kmsg", Proc::Kmsg),
        ("ncinitramdisk", Proc::Initramdisk),
    ] {
        let mut path = Text::<32>::new();
        path.str("/proc/").str(name);
        add(path.as_str(), Content::Proc(p));
    }
    add("/dev/null", Content::Dev(Dev::Null));
    add("/dev/zero", Content::Dev(Dev::Zero));
    add("/dev/random", Content::Dev(Dev::Random));

    for module in crate::boot::modules() {
        // SAFETY: a module the loader reported.
        let bytes = unsafe { module.bytes() };
        let name = module.name.split_ascii_whitespace().next().unwrap_or("");
        if name == "initrd" || name.ends_with(".cpio") || bytes.starts_with(b"070701") {
            unpack_cpio(bytes);
            continue;
        }
        if crate::initramdisk::is_image(name, bytes) {
            // SAFETY: at boot, once per image, while the tree is built.
            unsafe { crate::initramdisk::mount(bytes, add_dir, add_file) };
            continue;
        }
        let mut path = Text::<128>::new();
        if name.starts_with('/') {
            path.str(name);
        } else if name.is_empty() {
            path.str("/boot/module").num(COUNT.load(Ordering::Relaxed) as u64);
        } else {
            path.str("/boot/").str(name);
        }
        add(path.as_str(), Content::Bytes(bytes));
    }
}

/// Unpacks a `newc` cpio archive into the tree. Stops at the trailer, or at
/// the first entry that does not parse.
fn unpack_cpio(archive: &'static [u8]) {
    let mut at = 0usize;
    let hex = |b: &[u8]| -> Option<usize> {
        let mut v = 0usize;
        for &c in b {
            v = v.checked_mul(16)? + (c as char).to_digit(16)? as usize;
        }
        Some(v)
    };
    while let Some(head) = archive.get(at..at + 110) {
        if &head[..6] != b"070701" && &head[..6] != b"070702" {
            return;
        }
        let field = |i: usize| hex(&head[6 + i * 8..14 + i * 8]);
        let (Some(mode), Some(size), Some(namesize)) = (field(1), field(6), field(11)) else { return };
        let name_at = at + 110;
        let Some(raw) = archive.get(name_at..name_at + namesize.saturating_sub(1)) else { return };
        let data_at = (name_at + namesize + 3) & !3;
        let Some(data) = archive.get(data_at..data_at + size) else { return };
        let Ok(name) = core::str::from_utf8(raw) else { return };
        if name == "TRAILER!!!" {
            return;
        }
        let name = name.trim_start_matches("./").trim_start_matches('/');
        if !name.is_empty() && name != "." {
            let mut path = Text::<128>::new();
            path.str("/").str(name);
            match mode & 0o170000 {
                0o040000 => add(path.as_str(), Content::Dir),
                0o100000 => add(path.as_str(), Content::Bytes(data)),
                _ => {}
            }
        }
        at = (data_at + size + 3) & !3;
    }
}

/// Makes `path` absolute against `cwd` and resolves `.` and `..`.
pub fn resolve(cwd: &str, path: &str) -> Text<128> {
    let mut parts: [&str; 32] = [""; 32];
    let mut n: usize = 0;
    let full_iter = if path.starts_with('/') { "".split('/') } else { cwd.split('/') };
    for part in full_iter.chain(path.split('/')) {
        match part {
            "" | "." => {}
            ".." => n = n.saturating_sub(1),
            p => {
                if n < parts.len() {
                    parts[n] = p;
                    n += 1;
                }
            }
        }
    }
    let mut out = Text::<128>::new();
    if n == 0 {
        out.str("/");
    }
    for p in &parts[..n] {
        out.str("/").str(p);
    }
    out
}

/// The node at an absolute path; an implicit directory (a prefix of some
/// file's path) comes back as `Dir`.
pub fn lookup(path: &str) -> Option<Node> {
    for node in nodes().iter().flatten() {
        if node.path.as_str() == path {
            return Some(*node);
        }
    }
    let prefix_len = path.trim_end_matches('/').len();
    let implicit = nodes().iter().flatten().any(|n| {
        let p = n.path.as_str();
        p.len() > prefix_len + 1 && p.starts_with(path.trim_end_matches('/')) && p.as_bytes()[prefix_len] == b'/'
    });
    implicit.then(|| {
        let mut p = Text::<128>::new();
        p.str(path);
        Node { path: p, content: Content::Dir }
    })
}

/// Calls `entry(name, node)` for each immediate child of directory `dir`,
/// once per name (an implicit directory as `Dir`), in table order.
pub fn list(dir: &str, mut entry: impl FnMut(&str, Node)) {
    let base = dir.trim_end_matches('/');
    let mut seen: [Text<64>; 128] = [Text::new(); 128];
    let mut n_seen = 0;
    for node in nodes().iter().flatten() {
        let p = node.path.as_str();
        let Some(rest) = p.strip_prefix(base).and_then(|r| r.strip_prefix('/')) else { continue };
        if rest.is_empty() {
            continue;
        }
        let (name, deeper) = match rest.split_once('/') {
            Some((first, _)) => (first, true),
            None => (rest, false),
        };
        if seen[..n_seen].iter().any(|s| s.as_str() == name) {
            continue;
        }
        if n_seen < seen.len() {
            seen[n_seen].clear();
            seen[n_seen].str(name);
            n_seen += 1;
        }
        if deeper {
            let mut q = Text::<128>::new();
            q.str(base).str("/").str(name);
            entry(name, Node { path: q, content: Content::Dir });
        } else {
            entry(name, *node);
        }
    }
}

/// Every file whose path ends with `suffix` (case-insensitive), for the
/// launcher and the module loader: `.ncpkg`, `.ncapp`, `.ncdri`, `.ncdyn`.
pub fn find_suffix(suffix: &str, mut found: impl FnMut(Node)) {
    for node in nodes().iter().flatten() {
        let p = node.path.as_bytes_lower_ends_with(suffix);
        if p && !node.is_dir() {
            found(*node);
        }
    }
}

trait LowerEnds {
    fn as_bytes_lower_ends_with(&self, suffix: &str) -> bool;
}

impl LowerEnds for Text<128> {
    fn as_bytes_lower_ends_with(&self, suffix: &str) -> bool {
        let p = self.as_str().as_bytes();
        let s = suffix.as_bytes();
        p.len() >= s.len() && p[p.len() - s.len()..].eq_ignore_ascii_case(s)
    }
}

/// Writes a file's contents to `out` (text; a binary file's bytes are
/// written as they are, invalid UTF-8 replaced).
pub fn read(node: &Node, out: &mut dyn Write) {
    match node.content {
        Content::Bytes(b) => write_bytes(out, b),
        Content::Proc(p) => crate::system::proc_file(p, out),
        Content::Dev(Dev::Null) | Content::Dir => {}
        Content::Dev(Dev::Zero) => {
            let _ = out.write_str("\0\0\0\0\0\0\0\0");
        }
        Content::Dev(Dev::Random) => {
            let mut bytes = [0u8; 16];
            let _ = crate::rng::fill(&mut bytes, nanochrono_core::rng::Mode::Fast);
            for b in bytes {
                let _ = write!(out, "{b:02x}");
            }
            let _ = out.write_str("\n");
        }
    }
}

/// Bytes as text: valid UTF-8 runs as they are, anything else as `·`.
pub fn write_bytes(out: &mut dyn Write, mut b: &[u8]) {
    while !b.is_empty() {
        match core::str::from_utf8(b) {
            Ok(s) => {
                let _ = out.write_str(s);
                return;
            }
            Err(e) => {
                let (good, rest) = b.split_at(e.valid_up_to());
                // SAFETY: `valid_up_to` bytes are valid UTF-8.
                let _ = out.write_str(unsafe { core::str::from_utf8_unchecked(good) });
                let _ = out.write_str("·");
                b = rest.get(e.error_len().unwrap_or(rest.len()).max(1)..).unwrap_or(&[]);
            }
        }
    }
}
