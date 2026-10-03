// SPDX-License-Identifier: Apache-2.0
//! The `ncinitramdisk`: a sealed NCFS image the boot loader hands over
//! (`module2 /boot/ncinitramdisk.ncfs ncinitramdisk`), merged into the file
//! tree at boot.
//!
//! The image is read with `nanochrono_core::ncfs`'s reader — the code the
//! host tools and the FUSE mount use — with no heap: a static scratch for
//! the reader, a static arena for what decompresses. A file stored raw in
//! one extent is not copied at all: the tree points into the module's own
//! memory, after its BLAKE3 has been checked.
//!
//! # Trust
//!
//! A sealed image's superblock is signed, and its BLAKE3 pointers make that
//! one signature cover every byte (`ncfs::seal`). With `plugin-verify`, the
//! kernel checks the seal against the roots it embeds — `creator-ring0`
//! against the creator's root (🌳), `verify-ring0` against the owner's tree
//! root — and:
//!
//! | The image | Default | `ncinitramdisk=strict` |
//! |---|---|---|
//! | sealed, a ring-0 signature verifies | mounted, verified | mounted, verified |
//! | sealed, a signature fails | **refused** (changed after signing) | refused |
//! | sealed, no signature this kernel can check | mounted, flagged unverified | refused |
//! | not sealed | mounted, flagged unsealed | refused |
//!
//! Every file is checked against its BLAKE3 as it is unpacked, sealed or
//! not; a file that fails is left out and counted.

use crate::text::Text;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};
use nanochrono_core::ncfs::format::*;
use nanochrono_core::ncfs::{seal, Error, Inode, Scratch, SliceDev, Volume};
use nanochrono_core::ncpkg::sig::{Badge, Role, Verdict, Verifier};

/// What decompresses goes here, for the whole session.
#[cfg(target_pointer_width = "64")]
pub const ARENA_LEN: usize = 8 << 20;
#[cfg(not(target_pointer_width = "64"))]
pub const ARENA_LEN: usize = 2 << 20;

static mut ARENA: [u8; ARENA_LEN] = [0; ARENA_LEN];
static ARENA_USED: AtomicUsize = AtomicUsize::new(0);
static mut SCRATCH: Scratch = Scratch::new();
static mut SEAL_AREA: [u8; seal::AREA] = [0; seal::AREA];

/// The seal, as this kernel judged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seal {
    Unsealed,
    /// Sealed, but no signature this kernel can check (no `plugin-verify`,
    /// or a root it does not embed).
    Unverified,
    /// A ring-0 signature verified.
    Verified(Badge),
}

/// What happened to the image at boot.
#[derive(Clone, Copy)]
pub enum Status {
    /// No image was handed over.
    Absent,
    Mounted(Report),
    Refused(&'static str),
}

#[derive(Clone, Copy)]
pub struct Report {
    pub seal: Seal,
    pub label: Text<64>,
    pub generation: u64,
    pub files: usize,
    pub dirs: usize,
    pub links: usize,
    /// Bytes served straight from the module's memory.
    pub in_place: usize,
    /// Bytes decompressed into the arena.
    pub decoded: usize,
    /// Left out: too long a path, no room, a failed checksum.
    pub skipped: usize,
}

static mut STATUS: Status = Status::Absent;

/// The image's status, for `/proc/ncinitramdisk` and the self-test.
pub fn status() -> Status {
    // SAFETY: written once at boot, before anything reads it.
    unsafe { *core::ptr::addr_of!(STATUS) }
}

/// Whether a module is an NCFS image: by its name, or by a superblock's
/// magic in either slot.
pub fn is_image(name: &str, bytes: &[u8]) -> bool {
    let magic_at = |b: usize| bytes.get(b * BLOCK..b * BLOCK + 8) == Some(&MAGIC[..]);
    name == "ncinitramdisk" || name.ends_with(".ncfs") || magic_at(SUPER[0] as usize) || magic_at(SUPER[1] as usize)
}

/// The roots this kernel embeds, as a verifier for seals.
struct KernelVerifier;

impl Verifier for KernelVerifier {
    #[cfg(all(target_arch = "x86_64", feature = "plugin-verify"))]
    fn verify(&mut self, role: Role, alg: &str, key: &str, _pubkey: &[u8], message: &[u8], sig: &[u8]) -> Verdict {
        use crate::ncplu::Tier;
        let tier = match role {
            Role::CreatorRing0 => Tier::Creator,
            Role::VerifyRing0 => Tier::TreeRoot,
            _ => return Verdict::UnknownKey,
        };
        if alg != nanochrono_core::ncpkg::sig::ROOT_ALG {
            return Verdict::Unsupported;
        }
        let Some(fp) = crate::ncplu::root_fingerprint(tier) else { return Verdict::UnknownKey };
        let mut shown = Text::<20>::new();
        for (i, b) in fp.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                shown.str("-");
            }
            let _ = write!(shown, "{b:02x}");
        }
        if shown.as_str() != key {
            return Verdict::UnknownKey;
        }
        if crate::ncplu::verify_root_message(tier, message, sig) {
            Verdict::Valid
        } else {
            Verdict::Invalid
        }
    }

    #[cfg(not(all(target_arch = "x86_64", feature = "plugin-verify")))]
    fn verify(&mut self, role: Role, _alg: &str, _key: &str, _pubkey: &[u8], _message: &[u8], _sig: &[u8]) -> Verdict {
        if role.is_root() {
            Verdict::UnknownKey
        } else {
            Verdict::Unsupported
        }
    }
}

/// Room in the arena, or `None` when it is full.
fn arena_take(n: usize) -> Option<&'static mut [u8]> {
    let at = ARENA_USED.load(Ordering::Relaxed);
    let end = at.checked_add(n).filter(|&e| e <= ARENA_LEN)?;
    ARENA_USED.store(end, Ordering::Relaxed);
    // SAFETY: boot, one core; each range is handed out once and never again.
    Some(unsafe { &mut (&mut *core::ptr::addr_of_mut!(ARENA))[at..end] })
}

/// A file's bytes: in place when it is one raw extent, decoded into the
/// arena otherwise.
fn contents(v: &mut Volume<SliceDev<'static>>, image: &'static [u8], ino: u64, i: &Inode, s: &mut Scratch, r: &mut Report) -> Result<&'static [u8], Error> {
    let size = usize::try_from(i.size).map_err(|_| Error::TooBig)?;
    if size == 0 {
        return Ok(&[]);
    }
    if let Some((block, len)) = v.contiguous(ino, i, s)? {
        // Checked against its BLAKE3 by `contiguous`.
        let at = block as usize * BLOCK;
        r.in_place += len;
        return image.get(at..at + len).ok_or(Error::Corrupt(block));
    }
    let dst = arena_take(size).ok_or(Error::NoSpace)?;
    let n = v.read(ino, i, 0, dst, s)?;
    if n != size {
        return Err(Error::Corrupt(0));
    }
    r.decoded += size;
    Ok(dst)
}

/// Mounts the image into the file tree.
///
/// # Safety
/// Once, at boot, on one core, while the tree is being built.
pub unsafe fn mount(image: &'static [u8], add_dir: fn(&str), add_file: fn(&str, &'static [u8])) {
    // SAFETY: boot, one core: nothing else touches these statics now.
    let (s, area) = unsafe { (&mut *core::ptr::addr_of_mut!(SCRATCH), &mut *core::ptr::addr_of_mut!(SEAL_AREA)) };
    let status = match mount_inner(image, s, area, add_dir, add_file) {
        Ok(r) => Status::Mounted(r),
        Err(why) => Status::Refused(why),
    };
    match status {
        Status::Mounted(r) => crate::println!(
            "ncinitramdisk: {} files, {} directories, {} links; {} bytes in place, {} decompressed; {}",
            r.files,
            r.dirs,
            r.links,
            r.in_place,
            r.decoded,
            seal_name(r.seal)
        ),
        Status::Refused(why) => crate::println!("ncinitramdisk: refused: {why}"),
        Status::Absent => {}
    }
    // SAFETY: as above.
    unsafe { *core::ptr::addr_of_mut!(STATUS) = status };
}

fn seal_name(s: Seal) -> &'static str {
    match s {
        Seal::Unsealed => "unsealed",
        Seal::Unverified => "sealed, unverified",
        Seal::Verified(Badge::TreeRoot) => "sealed, verified: tree root (creator, ring 0)",
        Seal::Verified(Badge::VerifiedRing0) => "sealed, verified: blue check (certified, ring 0)",
        Seal::Verified(_) => "sealed, verified",
    }
}

fn mount_inner(image: &'static [u8], s: &mut Scratch, area: &mut [u8; seal::AREA], add_dir: fn(&str), add_file: fn(&str, &'static [u8])) -> Result<Report, &'static str> {
    let strict = crate::boot::option("ncinitramdisk") == Some("strict");
    let mut sb = [0u8; BLOCK];
    let sealed = seal::read(&mut SliceDev::new(image), &mut sb, area).map_err(|_| "no valid NCFS superblock")?;
    let seal_state = if sealed {
        let trust = seal::judge(&sb, &area[..], &mut KernelVerifier).map_err(|_| "a malformed signature area")?;
        if trust.tampered() {
            return Err("a signature does not verify: the image changed after it was signed");
        }
        if trust.ring0_signed() {
            Seal::Verified(trust.badge())
        } else {
            Seal::Unverified
        }
    } else {
        Seal::Unsealed
    };
    if strict && !matches!(seal_state, Seal::Verified(_)) {
        return Err("not verified, and ncinitramdisk=strict");
    }
    let mut v = Volume::open(SliceDev::new(image), &mut s.node).map_err(|_| "the volume does not open")?;
    let mut r = Report {
        seal: seal_state,
        label: {
            let mut t = Text::new();
            t.str(v.sb.label());
            t
        },
        generation: v.sb.generation,
        files: 0,
        dirs: 0,
        links: 0,
        in_place: 0,
        decoded: 0,
        skipped: 0,
    };
    // Depth first, with an explicit stack: (directory, its path).
    let mut stack: [(u64, Text<128>); 16] = [(0, Text::new()); 16];
    let mut depth = 1;
    stack[0] = (ROOT_INO, Text::new());
    while depth > 0 {
        depth -= 1;
        let (dir, path) = stack[depth];
        // Entries are read a page at a time: the scratch's node buffer is
        // reused for every lookup below.
        let mut cookie = 0;
        loop {
            let mut page: [(u64, u8, Text<64>, u64); 16] = [(0, 0, Text::new(), 0); 16];
            let mut n = 0;
            let listed = v.read_dir(dir, cookie, &mut s.node, |ino, t, name, next| {
                let mut nm = Text::<64>::new();
                if name.len() < 64 {
                    if let Ok(text) = core::str::from_utf8(name) {
                        nm.str(text);
                    }
                }
                page[n] = (ino, t, nm, next);
                n += 1;
                n < page.len()
            });
            if listed.is_err() {
                r.skipped += 1;
                break;
            }
            if n == 0 {
                break;
            }
            for &(ino, t, name, next) in &page[..n] {
                cookie = next;
                let mut child = path;
                child.str("/").str(name.as_str());
                if name.as_str().is_empty() || child.len() >= 127 {
                    r.skipped += 1;
                    continue;
                }
                match t {
                    DT_DIR => {
                        add_dir(child.as_str());
                        r.dirs += 1;
                        if depth < stack.len() {
                            stack[depth] = (ino, child);
                            depth += 1;
                        } else {
                            r.skipped += 1;
                        }
                    }
                    DT_REG | DT_LNK => {
                        // A link stands for what it names (the tree has no
                        // links of its own).
                        let target = if t == DT_LNK {
                            r.links += 1;
                            v.resolve_follow(child.as_str().as_bytes(), s).ok()
                        } else {
                            r.files += 1;
                            Some(ino)
                        };
                        let Some(target) = target else {
                            r.skipped += 1;
                            continue;
                        };
                        match v.inode(target, &mut s.node) {
                            Ok(i) if i.is_file() => match contents(&mut v, image, target, &i, s, &mut r) {
                                Ok(bytes) => add_file(child.as_str(), bytes),
                                Err(_) => r.skipped += 1,
                            },
                            _ => r.skipped += 1,
                        }
                    }
                    _ => r.skipped += 1,
                }
            }
        }
    }
    Ok(r)
}

/// `/proc/ncinitramdisk`.
pub fn report(out: &mut dyn Write) {
    match status() {
        Status::Absent => {
            let _ = writeln!(out, "no ncinitramdisk was handed over");
        }
        Status::Refused(why) => {
            let _ = writeln!(out, "refused: {why}");
        }
        Status::Mounted(r) => {
            let _ = writeln!(out, "label       {}", r.label.as_str());
            let _ = writeln!(out, "generation  {}", r.generation);
            let _ = writeln!(out, "seal        {}", seal_name(r.seal));
            let _ = writeln!(out, "files       {} ({} links, {} directories)", r.files, r.links, r.dirs);
            let _ = writeln!(out, "in place    {} bytes (raw, checked, not copied)", r.in_place);
            let _ = writeln!(out, "decoded     {} of {} bytes of arena", r.decoded, ARENA_LEN);
            let _ = writeln!(out, "skipped     {}", r.skipped);
        }
    }
}
