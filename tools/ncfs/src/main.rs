// SPDX-License-Identifier: Apache-2.0
//! `ncfs`: NCFS volumes on a host — make, inspect, fill, check, snapshot,
//! build images from directories, and mount through FUSE.
//!
//! The filesystem is nanochrono-core's (`ncfs`): the same reader the kernel
//! boots with, the same copy-on-write engine, the same `fsck`. This is the
//! command line around it, the host's files and devices, and the reference
//! library's ZSTD for the images built here.

mod dev;
#[cfg(feature = "fuse")]
mod fuse;
mod hostio;

use clap::{Parser, Subcommand, ValueEnum};
use dev::{timestamp, FileDev, SystemClock, Zstd};
use nanochrono_core::ncfs::check::check;
use nanochrono_core::ncfs::seal::{self, OwnedSeal};
use nanochrono_core::ncpkg::sig::{Role, Verdict, Verifier};
use ncpkg::crypto;
use nanochrono_core::ncfs::format::*;
use nanochrono_core::ncfs::write::{Format, Options, Writer};
use nanochrono_core::ncfs::{Error, Scratch, Volume};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "ncfs", version, about = "NCFS volumes on a host: make, inspect, fill, check, snapshot, build, mount")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Codec {
    Lz4,
    Zstd,
    None,
}

#[derive(Subcommand)]
enum Cmd {
    /// Makes an empty volume: in a new image file (--size), an existing one,
    /// or on a block device.
    Mkfs {
        image: PathBuf,
        /// Size of a new image: bytes, or with K, M, G, T.
        #[arg(long)]
        size: Option<String>,
        #[arg(long, default_value = "ncfs")]
        label: String,
        /// Overwrite a volume that is already there.
        #[arg(long)]
        force: bool,
    },
    /// Label, generation, features, space and subvolumes.
    Info { image: PathBuf },
    /// Lists a directory.
    Ls {
        image: PathBuf,
        #[arg(default_value = "/")]
        path: String,
        #[arg(short = 'l')]
        long: bool,
        #[arg(short = 'R')]
        recursive: bool,
        /// Read a snapshot (any subvolume) instead of the default.
        #[arg(long)]
        snapshot: Option<String>,
    },
    /// Writes a file's bytes to standard output.
    Cat {
        image: PathBuf,
        path: String,
        #[arg(long)]
        snapshot: Option<String>,
    },
    /// Copies a file or a tree out of the volume.
    Get {
        image: PathBuf,
        path: String,
        dest: PathBuf,
        #[arg(long)]
        snapshot: Option<String>,
    },
    /// Copies files or trees into the volume: SOURCE... DEST.
    Put {
        image: PathBuf,
        #[arg(num_args = 2.., required = true)]
        paths: Vec<String>,
        #[arg(long, value_enum, default_value = "lz4")]
        compress: Codec,
        /// ZSTD level (1..=22).
        #[arg(long, default_value_t = 19)]
        level: i32,
        #[arg(long)]
        no_dedup: bool,
        #[arg(long)]
        snapshot: Option<String>,
    },
    Mkdir {
        image: PathBuf,
        path: String,
        /// Make missing parents too.
        #[arg(short = 'p')]
        parents: bool,
    },
    Rm {
        image: PathBuf,
        path: String,
        #[arg(short = 'r')]
        recursive: bool,
    },
    Mv { image: PathBuf, from: String, to: String },
    /// A link: symbolic with -s, hard without.
    Ln {
        image: PathBuf,
        #[arg(short = 's')]
        symbolic: bool,
        target: String,
        path: String,
    },
    /// Snapshots and subvolumes.
    Snapshot {
        image: PathBuf,
        #[command(subcommand)]
        op: SnapOp,
    },
    /// fsck: every rule of the format; with --scrub, every byte of data
    /// against its BLAKE3.
    Check {
        image: PathBuf,
        #[arg(long)]
        scrub: bool,
    },
    /// An image made from a directory: sized to fit, ZSTD-compressed,
    /// shrunk to what it holds (an ncinitramdisk, a root filesystem).
    Build {
        dir: PathBuf,
        #[arg(short = 'o', long)]
        output: PathBuf,
        /// A fixed size instead of fitting the contents.
        #[arg(long)]
        size: Option<String>,
        #[arg(long, default_value = "ncfs")]
        label: String,
        #[arg(long, value_enum, default_value = "zstd")]
        compress: Codec,
        #[arg(long, default_value_t = 19)]
        level: i32,
        /// Leave free space (bytes, K, M, G) instead of shrinking to fit.
        #[arg(long)]
        free: Option<String>,
        /// Seal and sign the image in this role when it is built.
        #[arg(long)]
        seal_role: Option<String>,
        #[arg(long)]
        seal_keys: Option<PathBuf>,
        #[arg(long)]
        seal_key: Option<PathBuf>,
    },
    /// Cuts an image file down to what it holds.
    Shrink { image: PathBuf },
    /// Seals a volume (read-only from then on) and signs its superblock,
    /// which covers every byte: what makes an ncinitramdisk trusted.
    Seal {
        image: PathBuf,
        /// creator-ring0 (🌳), verify-ring0, creator-ring3, verify-ring3, self.
        #[arg(long)]
        role: String,
        /// A root's ncplu-sign key directory (root roles).
        #[arg(long)]
        keys: Option<PathBuf>,
        /// An `ncpkg keygen` key file (self).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Write the message to sign to this file instead (an offline
        /// signer, an HSM).
        #[arg(long)]
        message: Option<PathBuf>,
        /// Attach a signature made elsewhere (with --alg and --pubkey).
        #[arg(long)]
        sig: Option<PathBuf>,
        #[arg(long)]
        alg: Option<String>,
        /// The signer's public key(s): a root's NCROOT01 file, or raw bytes.
        #[arg(long)]
        pubkey: Option<PathBuf>,
    },
    /// Checks a sealed volume's signatures against trusted roots.
    Verify {
        image: PathBuf,
        /// A directory of <role>.pub root files.
        #[arg(long)]
        roots: Option<PathBuf>,
        /// Enrolled self-signing key fingerprints, one per line.
        #[arg(long)]
        owner_keys: Option<PathBuf>,
    },
    /// Mounts through FUSE until unmounted (fusermount3 -u MOUNTPOINT).
    #[cfg(feature = "fuse")]
    Mount {
        image: PathBuf,
        mountpoint: PathBuf,
        /// Read-only, through the kernel's reader (sealed images too).
        #[arg(long)]
        ro: bool,
        #[arg(long)]
        snapshot: Option<String>,
        #[arg(long, value_enum, default_value = "lz4")]
        compress: Codec,
    },
}

#[derive(Subcommand)]
enum SnapOp {
    /// A snapshot of a subvolume, in constant time.
    Create {
        name: String,
        /// The subvolume to snapshot (default: the default one).
        #[arg(long)]
        from: Option<String>,
        /// A writable clone instead of a read-only snapshot.
        #[arg(long)]
        writable: bool,
    },
    List,
    Delete { name: String },
    /// The subvolume mounted by default from now on (a rollback).
    Default { name: String },
}

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mul) = match s.as_bytes().last() {
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1u64 << 10),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1 << 20),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1 << 30),
        Some(b'T' | b't') => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    num.parse::<u64>().ok().and_then(|n| n.checked_mul(mul)).ok_or_else(|| format!("{s}: not a size"))
}

fn options(codec: Codec, dedup: bool) -> Options {
    Options {
        compression: match codec {
            Codec::Lz4 => Compression::Lz4,
            Codec::Zstd => Compression::Zstd,
            Codec::None => Compression::None,
        },
        dedup,
        ..Options::default()
    }
}

fn open_writer(image: &Path, codec: Codec, level: i32, dedup: bool) -> Result<Writer<FileDev>, String> {
    let dev = FileDev::open(image, true).map_err(|e| format!("{}: {e}", image.display()))?;
    let mut w = Writer::open(dev, options(codec, dedup), Box::new(SystemClock)).map_err(|e| format!("{}: {e}", image.display()))?;
    w.set_encoder(Box::new(Zstd { level }));
    Ok(w)
}

fn open_reader(image: &Path, snapshot: Option<&str>) -> Result<(Volume<FileDev>, Box<Scratch>), String> {
    let dev = FileDev::open(image, false).map_err(|e| format!("{}: {e}", image.display()))?;
    let mut s = Box::new(Scratch::new());
    let mut v = Volume::open(dev, &mut s.node).map_err(|e| format!("{}: {e}", image.display()))?;
    if let Some(name) = snapshot {
        v.open_subvol(name.as_bytes(), &mut s.node).map_err(|e| format!("subvolume {name}: {e}"))?;
    }
    Ok((v, s))
}

/// Splits `/a/b/c` into (`/a/b`, `c`).
fn split(path: &str) -> Result<(&str, &str), String> {
    let p = path.trim_end_matches('/');
    let cut = p.rfind('/').ok_or_else(|| format!("{path}: an absolute path, please"))?;
    let (dir, name) = (&p[..cut], &p[cut + 1..]);
    if name.is_empty() {
        return Err(format!("{path}: no name"));
    }
    Ok((if dir.is_empty() { "/" } else { dir }, name))
}

fn mode_string(mode: u32) -> String {
    let t = match mode & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        S_IFCHR => 'c',
        S_IFBLK => 'b',
        S_IFIFO => 'p',
        S_IFSOCK => 's',
        _ => '-',
    };
    let mut s = String::from(t);
    for (i, c) in "rwxrwxrwx".chars().enumerate() {
        s.push(if mode & (0o400 >> i) != 0 { c } else { '-' });
    }
    s
}

fn ls(v: &mut Volume<FileDev>, s: &mut Scratch, ino: u64, path: &str, long: bool, recursive: bool, out: &mut impl std::io::Write) -> Result<(), String> {
    let mut entries = Vec::new();
    v.read_dir(ino, 0, &mut s.node, |c, t, name, _| {
        entries.push((c, t, name.to_vec()));
        true
    })
    .map_err(|e| format!("{path}: {e}"))?;
    entries.sort_by(|a, b| a.2.cmp(&b.2));
    if recursive {
        let _ = writeln!(out, "{path}:");
    }
    let mut dirs = Vec::new();
    for (c, t, name) in &entries {
        let shown = String::from_utf8_lossy(name);
        if long {
            let i = v.inode(*c, &mut s.node).map_err(|e| format!("{shown}: {e}"))?;
            let mut line = format!("{} {:>3} {:>5} {:>5} {:>12} {} {shown}", mode_string(i.mode), i.nlink, i.uid, i.gid, i.size, timestamp(i.mtime));
            if i.is_symlink() {
                let mut target = vec![0u8; i.size as usize];
                if v.read_link(*c, &i, &mut target, s).is_ok() {
                    line.push_str(&format!(" -> {}", String::from_utf8_lossy(&target)));
                }
            }
            let _ = writeln!(out, "{line}");
        } else {
            let _ = writeln!(out, "{shown}{}", if *t == DT_DIR { "/" } else { "" });
        }
        if *t == DT_DIR {
            dirs.push((*c, format!("{}/{shown}", path.trim_end_matches('/'))));
        }
    }
    if recursive {
        for (c, p) in dirs {
            let _ = writeln!(out);
            ls(v, s, c, &p, long, true, out)?;
        }
    }
    Ok(())
}

fn info(image: &Path) -> Result<(), String> {
    let (mut v, mut s) = open_reader(image, None)?;
    let sb = v.sb;
    let fsid: String = sb.fsid.iter().enumerate().map(|(i, b)| format!("{}{b:02x}", if [4, 6, 8, 10].contains(&i) { "-" } else { "" })).collect();
    let mut features = Vec::new();
    if sb.incompat & INCOMPAT_LZ4 != 0 {
        features.push("lz4");
    }
    if sb.incompat & INCOMPAT_ZSTD != 0 {
        features.push("zstd");
    }
    println!("label        {}", sb.label());
    println!("fsid         {fsid}");
    println!("generation   {}", sb.generation);
    println!("created      {}", timestamp(sb.created));
    println!("committed    {}", timestamp(sb.committed));
    println!("size         {} blocks of {} ({} MiB)", sb.total_blocks, BLOCK, (sb.total_blocks * BLOCK as u64) >> 20);
    println!("used         {} blocks ({:.1}%)", sb.used_blocks, 100.0 * sb.used_blocks as f64 / sb.total_blocks as f64);
    println!("features     {}", if features.is_empty() { String::from("-") } else { features.join(", ") });
    println!(
        "sealed       {}",
        if sb.flags & FLAG_SEED != 0 { format!("yes ({} signature blocks)", sb.sig_blocks) } else { String::from("no") }
    );
    println!("subvolumes");
    let default = sb.default_subvol;
    v.subvols(&mut s.node, |id, r| {
        println!(
            "  {id:>4} {:<24} {}{} created {}{}",
            String::from_utf8_lossy(r.name()),
            if r.flags & SUBVOL_READONLY != 0 { "read-only" } else { "writable " },
            if id == default { " default" } else { "        " },
            timestamp(r.created),
            if r.parent != 0 { format!(", snapshot of {}", r.parent) } else { String::new() }
        );
        true
    })
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.cmd {
        Cmd::Mkfs { image, size, label, force } => {
            if label.len() > 64 {
                return Err(String::from("a label is at most 64 bytes"));
            }
            let exists = image.exists();
            if exists && !force {
                if let Ok(mut d) = FileDev::open(&image, false) {
                    if nanochrono_core::ncfs::read::probe(&mut d).is_some() {
                        return Err(format!("{}: already an NCFS volume (--force to overwrite)", image.display()));
                    }
                }
            }
            let dev = match (size, exists) {
                (Some(s), _) => FileDev::create(&image, parse_size(&s)?),
                (None, true) => FileDev::open(&image, true),
                (None, false) => return Err(format!("{}: does not exist; give --size to make it", image.display())),
            }
            .map_err(|e| format!("{}: {e}", image.display()))?;
            let mut fsid = [0u8; 16];
            getrandom::fill(&mut fsid).map_err(|e| e.to_string())?;
            let w = Writer::format(dev, &Format { label: label.into_bytes(), fsid }, Options::default(), Box::new(SystemClock)).map_err(|e| e.to_string())?;
            let sb = w.superblock();
            println!("{}: NCFS, {} blocks ({} MiB), label {:?}", image.display(), sb.total_blocks, (sb.total_blocks * BLOCK as u64) >> 20, sb.label());
        }
        Cmd::Info { image } => info(&image)?,
        Cmd::Ls { image, path, long, recursive, snapshot } => {
            let (mut v, mut s) = open_reader(&image, snapshot.as_deref())?;
            let ino = v.resolve(path.as_bytes(), &mut s).map_err(|e| format!("{path}: {e}"))?;
            let i = v.inode(ino, &mut s.node).map_err(|e| format!("{path}: {e}"))?;
            let mut out = std::io::stdout().lock();
            if i.is_dir() {
                ls(&mut v, &mut s, ino, &path, long, recursive, &mut out)?;
            } else {
                let _ = writeln!(out, "{} {:>12} {} {path}", mode_string(i.mode), i.size, timestamp(i.mtime));
            }
        }
        Cmd::Cat { image, path, snapshot } => {
            let (mut v, mut s) = open_reader(&image, snapshot.as_deref())?;
            let ino = v.resolve_follow(path.as_bytes(), &mut s).map_err(|e| format!("{path}: {e}"))?;
            let i = v.inode(ino, &mut s.node).map_err(|e| format!("{path}: {e}"))?;
            if i.is_dir() {
                return Err(format!("{path}: {}", Error::IsADirectory));
            }
            let mut out = std::io::stdout().lock();
            let mut buf = vec![0u8; 1 << 20];
            let mut off = 0;
            while off < i.size {
                let n = v.read(ino, &i, off, &mut buf, &mut s).map_err(|e| format!("{path}: {e}"))?;
                out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                off += n as u64;
            }
        }
        Cmd::Get { image, path, dest, snapshot } => {
            let (mut v, mut s) = open_reader(&image, snapshot.as_deref())?;
            let ino = v.resolve(path.as_bytes(), &mut s).map_err(|e| format!("{path}: {e}"))?;
            let dest = if dest.is_dir() && !path.trim_end_matches('/').is_empty() {
                dest.join(path.trim_end_matches('/').rsplit('/').next().unwrap_or(""))
            } else {
                dest
            };
            let mut t = hostio::Tally::default();
            hostio::get(&mut v, &mut s, ino, &dest, &mut t)?;
            eprintln!("{} files, {} directories, {} links, {} bytes", t.files, t.dirs, t.links, t.bytes);
        }
        Cmd::Put { image, mut paths, compress, level, no_dedup, snapshot } => {
            let dest = paths.pop().unwrap_or_default();
            let mut w = open_writer(&image, compress, level, !no_dedup)?;
            if let Some(name) = snapshot {
                w.select(name.as_bytes()).map_err(|e| format!("subvolume {name}: {e}"))?;
            }
            let into = w.resolve(dest.as_bytes()).ok().filter(|&d| w.inode(d).is_ok_and(|i| i.is_dir()));
            let mut t = hostio::Tally::default();
            for src in &paths {
                let src = Path::new(src);
                let base = src.file_name().map(|n| n.as_bytes().to_vec());
                let (dir, name) = match (into, base) {
                    (Some(d), Some(b)) => (d, b),
                    _ => {
                        if paths.len() > 1 {
                            return Err(format!("{dest}: not a directory in the volume"));
                        }
                        let (d, n) = split(&dest)?;
                        let d = w.resolve(d.as_bytes()).map_err(|e| format!("{d}: {e}"))?;
                        (d, n.as_bytes().to_vec())
                    }
                };
                hostio::put(&mut w, src, dir, &name, &mut t)?;
            }
            w.commit().map_err(|e| e.to_string())?;
            eprintln!("{} files, {} directories, {} links, {} bytes", t.files, t.dirs, t.links, t.bytes);
        }
        Cmd::Mkdir { image, path, parents } => {
            let mut w = open_writer(&image, Codec::Lz4, 3, true)?;
            let mut cur = ROOT_INO;
            let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
            for (i, part) in parts.iter().enumerate() {
                match w.lookup(cur, part.as_bytes()).map_err(|e| format!("{part}: {e}"))? {
                    Some((ino, DT_DIR)) if parents || i + 1 < parts.len() => cur = ino,
                    Some(_) => return Err(format!("{path}: {}", Error::Exists)),
                    None if parents || i + 1 == parts.len() => cur = w.mkdir(cur, part.as_bytes(), 0o755, 0, 0).map_err(|e| format!("{part}: {e}"))?.0,
                    None => return Err(format!("{path}: {}", Error::NotFound)),
                }
            }
            w.commit().map_err(|e| e.to_string())?;
        }
        Cmd::Rm { image, path, recursive } => {
            let mut w = open_writer(&image, Codec::Lz4, 3, true)?;
            let (d, n) = split(&path)?;
            let dir = w.resolve(d.as_bytes()).map_err(|e| format!("{d}: {e}"))?;
            match w.lookup(dir, n.as_bytes()).map_err(|e| e.to_string())? {
                None => return Err(format!("{path}: {}", Error::NotFound)),
                Some((_, DT_DIR)) if recursive => hostio::remove(&mut w, dir, n.as_bytes()),
                Some((_, DT_DIR)) => w.rmdir(dir, n.as_bytes()),
                Some(_) => w.unlink(dir, n.as_bytes()),
            }
            .map_err(|e| format!("{path}: {e}"))?;
            w.commit().map_err(|e| e.to_string())?;
        }
        Cmd::Mv { image, from, to } => {
            let mut w = open_writer(&image, Codec::Lz4, 3, true)?;
            let (fd, fname) = split(&from)?;
            let a = w.resolve(fd.as_bytes()).map_err(|e| format!("{fd}: {e}"))?;
            let (b, tname) = match w.resolve(to.as_bytes()) {
                Ok(d) if w.inode(d).is_ok_and(|i| i.is_dir()) => (d, fname.to_string()),
                _ => {
                    let (td, tn) = split(&to)?;
                    (w.resolve(td.as_bytes()).map_err(|e| format!("{td}: {e}"))?, tn.to_string())
                }
            };
            w.rename(a, fname.as_bytes(), b, tname.as_bytes(), false).map_err(|e| format!("{from}: {e}"))?;
            w.commit().map_err(|e| e.to_string())?;
        }
        Cmd::Ln { image, symbolic, target, path } => {
            let mut w = open_writer(&image, Codec::Lz4, 3, true)?;
            let (d, n) = split(&path)?;
            let dir = w.resolve(d.as_bytes()).map_err(|e| format!("{d}: {e}"))?;
            if symbolic {
                w.symlink(dir, n.as_bytes(), target.as_bytes(), 0, 0).map_err(|e| format!("{path}: {e}"))?;
            } else {
                let ino = w.resolve(target.as_bytes()).map_err(|e| format!("{target}: {e}"))?;
                w.link(ino, dir, n.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
            }
            w.commit().map_err(|e| e.to_string())?;
        }
        Cmd::Snapshot { image, op } => {
            let mut w = open_writer(&image, Codec::Lz4, 3, true)?;
            let id_of = |w: &Writer<FileDev>, name: &str| w.subvols().into_iter().find(|(_, r)| r.name() == name.as_bytes()).map(|(i, _)| i).ok_or_else(|| format!("no subvolume {name:?}"));
            match op {
                SnapOp::Create { name, from, writable } => {
                    let src = match from {
                        Some(f) => id_of(&w, &f)?,
                        None => w.superblock().default_subvol,
                    };
                    let id = w.snapshot(src, name.as_bytes(), !writable).map_err(|e| format!("{name}: {e}"))?;
                    println!("subvolume {id} {name:?}: a {} snapshot of {src}", if writable { "writable" } else { "read-only" });
                }
                SnapOp::List => {
                    let default = w.superblock().default_subvol;
                    for (id, r) in w.subvols() {
                        println!(
                            "{id:>4} {:<24} {} {}{}",
                            String::from_utf8_lossy(r.name()),
                            if r.flags & SUBVOL_READONLY != 0 { "ro" } else { "rw" },
                            timestamp(r.created),
                            if id == default { "  (default)" } else { "" }
                        );
                    }
                }
                SnapOp::Delete { name } => {
                    let id = id_of(&w, &name)?;
                    w.delete_subvol(id).map_err(|e| format!("{name}: {e}"))?;
                }
                SnapOp::Default { name } => {
                    let id = id_of(&w, &name)?;
                    w.set_default(id).map_err(|e| format!("{name}: {e}"))?;
                    w.commit().map_err(|e| e.to_string())?;
                }
            }
        }
        Cmd::Check { image, scrub } => {
            let mut dev = FileDev::open(&image, false).map_err(|e| format!("{}: {e}", image.display()))?;
            let r = check(&mut dev, scrub).map_err(|e| format!("{}: {e}", image.display()))?;
            println!(
                "generation {}: {} subvolumes, {} nodes, {} extents, {} inodes ({} directories), {} blocks in use{}",
                r.generation,
                r.subvols,
                r.nodes,
                r.extents,
                r.inodes,
                r.directories,
                r.used_blocks,
                if scrub { format!(", {} bytes of data verified", r.verified_bytes) } else { String::new() }
            );
            for e in &r.errors {
                println!("error: {e}");
            }
            if !r.is_clean() {
                return Ok(ExitCode::from(3));
            }
            println!("clean");
        }
        Cmd::Build { dir, output, size, label, compress, level, free, seal_role, seal_keys, seal_key } => {
            if label.len() > 64 {
                return Err(String::from("a label is at most 64 bytes"));
            }
            let (bytes, entries) = hostio::measure(&dir)?;
            let fixed = size.as_deref().map(parse_size).transpose()?;
            // Room for every byte uncompressed, a block per entry, and the
            // trees, with a margin; shrunk to fit afterwards.
            let estimate = (bytes + entries * 2 * BLOCK as u64) * 5 / 4 + (MIN_BLOCKS * BLOCK as u64) * 4;
            let dev = FileDev::create(&output, fixed.unwrap_or(estimate)).map_err(|e| format!("{}: {e}", output.display()))?;
            let mut fsid = [0u8; 16];
            getrandom::fill(&mut fsid).map_err(|e| e.to_string())?;
            let mut w = Writer::format(dev, &Format { label: label.into_bytes(), fsid }, options(compress, true), Box::new(SystemClock)).map_err(|e| e.to_string())?;
            w.set_encoder(Box::new(Zstd { level }));
            let mut t = hostio::Tally::default();
            let mut entries: Vec<_> = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?.collect::<Result<_, _>>().map_err(|e| e.to_string())?;
            entries.sort_by_key(|e| e.file_name());
            for e in entries {
                hostio::put(&mut w, &e.path(), ROOT_INO, e.file_name().as_bytes(), &mut t)?;
            }
            w.commit().map_err(|e| e.to_string())?;
            if fixed.is_none() {
                let spare = free.as_deref().map(parse_size).transpose()?.unwrap_or(0) / BLOCK as u64;
                let n = (w.high_water() + 16 + spare).max(MIN_BLOCKS);
                w.shrink(n).map_err(|e| e.to_string())?;
                w.device().truncate(n).map_err(|e| e.to_string())?;
            }
            let sb = *w.superblock();
            drop(w);
            let r = check(&mut FileDev::open(&output, false).map_err(|e| e.to_string())?, true).map_err(|e| e.to_string())?;
            if !r.is_clean() {
                return Err(format!("the image fails its own check: {:?}", r.errors));
            }
            if let Some(role) = seal_role {
                seal_cmd(&output, &role, seal_keys.as_deref(), seal_key.as_deref(), None, None, None, None)?;
            }
            eprintln!(
                "{}: {} files, {} directories, {} links, {} bytes in {} KiB ({} blocks)",
                output.display(),
                t.files,
                t.dirs,
                t.links,
                t.bytes,
                (sb.total_blocks * BLOCK as u64) >> 10,
                sb.total_blocks
            );
        }
        Cmd::Shrink { image } => {
            let mut w = open_writer(&image, Codec::Lz4, 3, true)?;
            let n = (w.high_water() + 16).max(MIN_BLOCKS);
            w.shrink(n).map_err(|e| e.to_string())?;
            w.device().truncate(n).map_err(|e| e.to_string())?;
            println!("{}: {} blocks ({} KiB)", image.display(), n, (n * BLOCK as u64) >> 10);
        }
        Cmd::Seal { image, role, keys, key, message, sig, alg, pubkey } => {
            seal_cmd(&image, &role, keys.as_deref(), key.as_deref(), message.as_deref(), sig.as_deref(), alg.as_deref(), pubkey.as_deref())?;
        }
        Cmd::Verify { image, roots, owner_keys } => return verify_cmd(&image, roots.as_deref(), owner_keys.as_deref()),
        #[cfg(feature = "fuse")]
        Cmd::Mount { image, mountpoint, ro, snapshot, compress } => {
            let mut opts = options(compress, true);
            if matches!(compress, Codec::Zstd) {
                // FUSE writes through LZ4: ZSTD's encoder is for images built
                // in one go.
                opts.compression = Compression::Lz4;
            }
            fuse::mount(&image, &mountpoint, ro, snapshot.as_deref(), opts)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn role(name: &str) -> Result<Role, String> {
    Role::from_name(name).ok_or_else(|| format!("{name}: not a role (creator-ring3, creator-ring0, verify-ring3, verify-ring0, self)"))
}

#[allow(clippy::too_many_arguments)]
fn seal_cmd(
    image: &Path,
    role_name: &str,
    keys: Option<&Path>,
    key: Option<&Path>,
    message: Option<&Path>,
    sig: Option<&Path>,
    alg: Option<&str>,
    pubkey: Option<&Path>,
) -> Result<(), String> {
    let role = role(role_name)?;
    let mut dev = FileDev::open(image, true).map_err(|e| format!("{}: {e}", image.display()))?;
    let sb = seal::seal(&mut dev).map_err(|e| format!("{}: {e}", image.display()))?;
    let m = seal::message(role, &sb);
    if let Some(out) = message {
        std::fs::write(out, m.as_bytes()).map_err(|e| format!("{}: {e}", out.display()))?;
        println!("{}: sealed; the message for {} is in {}", image.display(), role.name(), out.display());
        return Ok(());
    }
    let (alg, public, signature) = match sig {
        Some(sig_path) => {
            let alg = alg.ok_or("--sig needs --alg")?.to_string();
            let pk_path = pubkey.ok_or("--sig needs --pubkey")?;
            let public = if role.is_root() { crypto::read_root_pub(pk_path)? } else { std::fs::read(pk_path).map_err(|e| format!("{}: {e}", pk_path.display()))? };
            let signature = std::fs::read(sig_path).map_err(|e| format!("{}: {e}", sig_path.display()))?;
            match crypto::verify_all(&alg, &public, m.as_bytes(), &signature) {
                Some(true) => {}
                Some(false) => return Err(String::from("the signature does not verify over this volume's message (ncfs seal --message)")),
                None => return Err(format!("unknown algorithm {alg:?}")),
            }
            (alg, public, signature)
        }
        None => {
            let secret = match (role.is_root(), keys, key) {
                (true, Some(dir), None) => crypto::SecretKey::load_root_dir(dir)?,
                (true, _, _) => return Err(format!("{}: a root role signs with --keys <ncplu-sign key directory>", role.name())),
                (false, None, Some(k)) => crypto::SecretKey::load(k)?,
                (false, _, _) => return Err(String::from("self: sign with --key <file from ncpkg keygen>")),
            };
            let signature = secret.sign(m.as_bytes())?;
            (secret.alg.clone(), secret.public(), signature)
        }
    };
    let fp = crypto::fingerprint(&public);
    let entry = OwnedSeal { role, alg: alg.clone(), key: fp.clone(), pubkey: if role.is_root() { Vec::new() } else { public }, sig: signature };
    seal::add(&mut dev, entry).map_err(|e| format!("{}: {e}", image.display()))?;
    println!("{}: sealed and signed as {} ({alg}, key {fp})", image.display(), role.name());
    Ok(())
}

fn verify_cmd(image: &Path, roots: Option<&Path>, owner_keys: Option<&Path>) -> Result<ExitCode, String> {
    let mut dev = FileDev::open(image, false).map_err(|e| format!("{}: {e}", image.display()))?;
    let mut sb = [0u8; BLOCK];
    let mut area = vec![0u8; seal::AREA];
    let area: &mut [u8; seal::AREA] = area.as_mut_slice().try_into().map_err(|_| "internal")?;
    if !seal::read(&mut dev, &mut sb, area).map_err(|e| format!("{}: {e}", image.display()))? {
        println!("{}: not sealed", image.display());
        return Ok(ExitCode::from(4));
    }
    let mut verifier = crypto::HostVerifier::load(roots, owner_keys)?;
    let seals = seal::parse(&area[..]).map_err(|e| format!("{}: signature area: {e}", image.display()))?;
    for s in seals.iter() {
        let m = seal::message(s.role, &sb);
        let verdict = verifier.verify(s.role, s.alg, s.key, s.pubkey, m.as_bytes(), s.sig);
        let shown = match verdict {
            Verdict::Valid => "valid",
            Verdict::Invalid => "INVALID: the volume changed after it was signed",
            Verdict::UnknownKey => "not a root this host trusts for the role",
            Verdict::Unsupported => "an algorithm this build cannot check",
        };
        println!("{:<14} {:<26} key {}  {shown}", s.role.name(), s.alg, s.key);
    }
    let trust = seal::judge(&sb, &area[..], &mut verifier).map_err(|e| e.to_string())?;
    let badge = trust.badge();
    println!("badge: {} {}", badge.symbol(), badge.label());
    if trust.tampered() {
        return Ok(ExitCode::from(3));
    }
    if !trust.ring0_signed() {
        println!("no valid ring-0 signature: the kernel boots this only with the community switch");
        return Ok(ExitCode::from(4));
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    // Rust ignores SIGPIPE, which turns `ncfs ls | head` into a panic on the
    // first write after the pipe closes; a command-line tool should simply
    // stop.
    // SAFETY: setting a signal's disposition to its default at start-up.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ncfs: {e}");
            ExitCode::FAILURE
        }
    }
}
