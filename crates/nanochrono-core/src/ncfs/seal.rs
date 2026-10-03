// SPDX-License-Identifier: Apache-2.0
//! Sealed volumes: an NCFS image with its superblock signed.
//!
//! Every pointer in NCFS carries the BLAKE3 of what it points at, so the
//! superblock — which carries the root tree's pointer — determines every
//! byte of the volume. Signing those 4096 bytes signs the whole image: a
//! changed file changes an extent's hash, which changes a leaf's, and so
//! on up to the superblock, which no longer matches its signature. That is
//! how the `ncinitramdisk` the kernel boots from is trusted, with one
//! signature check however large the image is (the files are checked
//! against their hashes as they are read, as on any volume).
//!
//! A sealed volume has [`FLAG_SEED`] set and is read-only forever: the
//! writer refuses it. Its signatures live in the signature area (blocks 3
//! to 18), which is not part of the superblock, so signatures can be added
//! without changing what the others signed. Each signs
//!
//! ```text
//! "NCFS-SEAL-1" 0x00  role-name  0x00  SHA-512(the sealed superblock block)
//! ```
//!
//! — [`crate::ncpkg::sig`]'s framing under its own domain, so a package's
//! signature can never pass for a volume's. The roles, the algorithms, the
//! badges and what they grant are the packages' (docs/NCPKG.md §4): an
//! image of ring-0 code wants `creator-ring0` (🌳) or `verify-ring0`.
//!
//! # The signature area
//!
//! Binary, little-endian, every byte accounted for:
//!
//! ```text
//! 0   8  magic "NCFSSEAL"
//! 8   2  version: 1
//! 10  2  signatures: 1..=8
//! 12  4  bytes used, this header included
//! 16  …  per signature: role (u8, its index in Role::ALL), algorithm
//!        length (u8), key fingerprint (19 ASCII bytes), public-key length
//!        (u16), signature length (u32), then the algorithm's name, the
//!        public key(s) (a self-signature only), the signature
//! …      zeros to the end of the area
//! ```

use super::format::*;
use super::read::BlockDev;
use super::Error;
use crate::ncpkg::sig::{self, Message, Role, Trust, Verifier};

/// The domain a seal signature is framed in.
pub const DOMAIN: &[u8] = b"NCFS-SEAL-1\0";
pub const MAGIC: [u8; 8] = *b"NCFSSEAL";
pub const VERSION: u16 = 1;
/// The signature area's size.
pub const AREA: usize = SIG_BLOCKS as usize * BLOCK;
const HEADER: usize = 16;
const ENTRY_FIXED: usize = 1 + 1 + 19 + 2 + 4;

/// One signature of a seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seal<'a> {
    pub role: Role,
    pub alg: &'a str,
    pub key: &'a str,
    /// The public key(s): a self-signature's only.
    pub pubkey: &'a [u8],
    pub sig: &'a [u8],
}

/// The checked signatures of an area.
#[derive(Debug, Clone, Copy)]
pub struct Seals<'a> {
    area: &'a [u8],
    count: usize,
}

impl<'a> Seals<'a> {
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = Seal<'a>> + 'a {
        let area = self.area;
        let mut at = HEADER;
        (0..self.count).filter_map(move |_| {
            let (s, next) = entry(area, at)?;
            at = next;
            Some(s)
        })
    }
}

fn rd16(b: &[u8], at: usize) -> usize {
    usize::from(b[at]) | usize::from(b[at + 1]) << 8
}

fn rd32(b: &[u8], at: usize) -> usize {
    rd16(b, at) | rd16(b, at + 2) << 16
}

/// The entry at `at`, and where the next begins.
fn entry(area: &[u8], at: usize) -> Option<(Seal<'_>, usize)> {
    let f = area.get(at..at + ENTRY_FIXED)?;
    let role = *Role::ALL.get(usize::from(f[0]))?;
    let alg_len = usize::from(f[1]);
    let key = core::str::from_utf8(&f[2..21]).ok()?;
    let pk_len = rd16(f, 21);
    let sig_len = rd32(f, 23);
    let mut p = at + ENTRY_FIXED;
    let alg = core::str::from_utf8(area.get(p..p + alg_len)?).ok()?;
    p += alg_len;
    let pubkey = area.get(p..p + pk_len)?;
    p += pk_len;
    let sig = area.get(p..p + sig_len)?;
    p += sig_len;
    Some((Seal { role, alg, key, pubkey, sig }, p))
}

/// Parses and checks a signature area: the header, every entry against
/// the packages' rules for its role, one signature per role, and nothing
/// but zeros after what is used.
pub fn parse(area: &[u8]) -> Result<Seals<'_>, Error> {
    let bad = Error::Corrupt(SIG_FIRST);
    if area.len() != AREA || area[..8] != MAGIC || rd16(area, 8) != usize::from(VERSION) {
        return Err(bad);
    }
    let count = rd16(area, 10);
    let used = rd32(area, 12);
    if count == 0 || count > sig::MAX_SIGNATURES || !(HEADER..=AREA).contains(&used) {
        return Err(bad);
    }
    let mut at = HEADER;
    let mut roles = 0u8;
    for _ in 0..count {
        let (s, next) = entry(&area[..used], at).ok_or(bad)?;
        let bit = 1u8 << Role::ALL.iter().position(|r| *r == s.role).unwrap_or(7);
        if roles & bit != 0 || !sig::is_fingerprint(s.key) {
            return Err(bad);
        }
        roles |= bit;
        if s.alg.split('+').any(|half| sig::refusal(half).is_some()) {
            return Err(bad);
        }
        let (a, b) = sig::parse_alg(s.alg).ok_or(bad)?;
        if s.role.is_root() && (s.alg != sig::ROOT_ALG || !s.pubkey.is_empty()) {
            return Err(bad);
        }
        if s.role == Role::SelfSigned && (s.pubkey.is_empty() || s.pubkey.len() > sig::MAX_PUBKEY_BYTES) {
            return Err(bad);
        }
        let fixed = match (a.sig_len(), b.map(|b| b.sig_len())) {
            (Some(x), None) => Some(x),
            (Some(x), Some(Some(y))) => Some(x + y),
            _ => None,
        };
        if s.sig.is_empty() || s.sig.len() > sig::MAX_SIG_BYTES || fixed.is_some_and(|f| f != s.sig.len()) {
            return Err(bad);
        }
        at = next;
    }
    if at != used || area[used..].iter().any(|&x| x != 0) {
        return Err(bad);
    }
    Ok(Seals { area, count })
}

/// What a seal signature in `role` signs.
pub fn message(role: Role, superblock: &[u8]) -> Message {
    Message::in_domain(DOMAIN, role, superblock)
}

/// Judges a seal: each signature over `superblock` (the sealed superblock
/// block, all 4096 bytes) with `verifier`. A signature present and failing
/// shows in [`Trust::tampered`]; the caller refuses such a volume.
pub fn judge(superblock: &[u8], area: &[u8], verifier: &mut dyn Verifier) -> Result<Trust, Error> {
    let seals = parse(area)?;
    let mut trust = Trust::NONE;
    for s in seals.iter() {
        let m = message(s.role, superblock);
        let verdict = verifier.verify(s.role, s.alg, s.key, s.pubkey, m.as_bytes(), s.sig);
        trust.record(s.role, verdict, s.key, verifier);
    }
    Ok(trust)
}

/// Reads a sealed volume's superblock block (the copy that mounts) and its
/// signature area into the caller's buffers; `Ok(false)` when the volume
/// is not sealed.
pub fn read<D: BlockDev>(dev: &mut D, superblock: &mut [u8; BLOCK], area: &mut [u8; AREA]) -> Result<bool, Error> {
    let mut buf = [0u8; BLOCK];
    let sb = super::read::read_superblock(dev, &mut buf)?;
    dev.read(SUPER[(sb.generation % 2) as usize], superblock)?;
    if Superblock::decode(superblock)? != sb {
        return Err(Error::NoSuperblock);
    }
    if sb.flags & FLAG_SEED == 0 {
        return Ok(false);
    }
    if u64::from(sb.sig_blocks) != SIG_BLOCKS {
        return Err(Error::Corrupt(SUPER[(sb.generation % 2) as usize]));
    }
    dev.read(SIG_FIRST, area)?;
    Ok(true)
}

#[cfg(feature = "alloc")]
mod writing {
    use super::*;
    use crate::ncfs::write::BlockDevMut;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    /// An owned signature, to write.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct OwnedSeal {
        pub role: Role,
        pub alg: String,
        pub key: String,
        pub pubkey: Vec<u8>,
        pub sig: Vec<u8>,
    }

    impl OwnedSeal {
        pub fn view(&self) -> Seal<'_> {
            Seal { role: self.role, alg: &self.alg, key: &self.key, pubkey: &self.pubkey, sig: &self.sig }
        }
    }

    /// The signature area holding `seals`, checked as a reader would.
    pub fn encode(seals: &[OwnedSeal]) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; HEADER];
        out[..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&(seals.len() as u16).to_le_bytes());
        for s in seals {
            let role = Role::ALL.iter().position(|r| *r == s.role).unwrap_or(0) as u8;
            if s.key.len() != 19 || s.alg.len() > 255 || s.pubkey.len() > usize::from(u16::MAX) {
                return Err(Error::InvalidName);
            }
            out.push(role);
            out.push(s.alg.len() as u8);
            out.extend_from_slice(s.key.as_bytes());
            out.extend_from_slice(&(s.pubkey.len() as u16).to_le_bytes());
            out.extend_from_slice(&(s.sig.len() as u32).to_le_bytes());
            out.extend_from_slice(s.alg.as_bytes());
            out.extend_from_slice(&s.pubkey);
            out.extend_from_slice(&s.sig);
        }
        let used = out.len();
        if used > AREA {
            return Err(Error::TooBig);
        }
        out[12..16].copy_from_slice(&(used as u32).to_le_bytes());
        out.resize(AREA, 0);
        parse(&out)?;
        Ok(out)
    }

    /// Seals the volume on `dev` (if it is not sealed already) and returns
    /// the sealed superblock block — what every signature signs. The
    /// sealed copy goes to the next slot, then the other slot is cleared,
    /// so a sealed volume has exactly one superblock.
    pub fn seal<D: BlockDevMut>(dev: &mut D) -> Result<[u8; BLOCK], Error> {
        let mut buf = [0u8; BLOCK];
        let mut sb = crate::ncfs::read::read_superblock(dev, &mut buf)?;
        if sb.flags & FLAG_SEED == 0 {
            sb.flags |= FLAG_SEED;
            sb.sig_blocks = SIG_BLOCKS as u16;
            sb.generation += 1;
            let zero = [0u8; BLOCK];
            for b in 0..SIG_BLOCKS {
                dev.write(SIG_FIRST + b, &zero)?;
            }
            dev.write(SUPER[(sb.generation % 2) as usize], &sb.encode())?;
            dev.flush()?;
            dev.write(SUPER[((sb.generation + 1) % 2) as usize], &zero)?;
            dev.flush()?;
        }
        let mut out = [0u8; BLOCK];
        dev.read(SUPER[(sb.generation % 2) as usize], &mut out)?;
        Ok(out)
    }

    /// The signatures a sealed volume carries (none yet: empty).
    pub fn signatures<D: BlockDev>(dev: &mut D) -> Result<Vec<OwnedSeal>, Error> {
        let mut area = vec![0u8; AREA];
        dev.read(SIG_FIRST, &mut area)?;
        if area.iter().all(|&b| b == 0) {
            return Ok(Vec::new());
        }
        let seals = parse(&area)?;
        Ok(seals
            .iter()
            .map(|s| OwnedSeal { role: s.role, alg: String::from(s.alg), key: String::from(s.key), pubkey: s.pubkey.to_vec(), sig: s.sig.to_vec() })
            .collect())
    }

    /// Adds (or replaces, for its role) one signature.
    pub fn add<D: BlockDevMut>(dev: &mut D, new: OwnedSeal) -> Result<(), Error> {
        let mut seals = signatures(dev)?;
        seals.retain(|s| s.role != new.role);
        seals.push(new);
        seals.sort_by_key(|s| Role::ALL.iter().position(|r| *r == s.role));
        let area = encode(&seals)?;
        dev.write(SIG_FIRST, &area)?;
        dev.flush()
    }
}

#[cfg(feature = "alloc")]
pub use writing::{add, encode, seal, signatures, OwnedSeal};

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::ncfs::tests::MemDev;
    use crate::ncfs::write::{FixedClock, Format, Options, Writer};
    use crate::ncpkg::sig::{Badge, Verdict};
    use std::boxed::Box;
    use std::string::String;
    use std::vec::Vec;

    /// A signature here is the message's SHA-512 repeated to length: bound
    /// to the message like a real one, checkable without keys.
    struct Fake;

    fn fake(message: &[u8], n: usize) -> Vec<u8> {
        crate::sha512::digest(message).iter().cycle().take(n).copied().collect()
    }

    impl Verifier for Fake {
        fn verify(&mut self, _role: Role, _alg: &str, _key: &str, _pk: &[u8], message: &[u8], sig: &[u8]) -> Verdict {
            if fake(message, sig.len()) == sig {
                Verdict::Valid
            } else {
                Verdict::Invalid
            }
        }
    }

    fn volume() -> MemDev {
        let mut w = Writer::format(MemDev::new(512), &Format { label: b"initramdisk".to_vec(), fsid: [3; 16] }, Options::default(), Box::new(FixedClock(5))).unwrap();
        let (ino, _) = w.create(1, b"init.ncapp", 0o755, 0, 0, 0).unwrap();
        w.write(ino, 0, b"\x7fNCAPP the first process").unwrap();
        w.close().unwrap()
    }

    fn root_seal(sb: &[u8], role: Role) -> OwnedSeal {
        let n = 4627 + 132;
        OwnedSeal { role, alg: String::from(sig::ROOT_ALG), key: String::from("0123-4567-89ab-cdef"), pubkey: Vec::new(), sig: fake(message(role, sb).as_bytes(), n) }
    }

    #[test]
    fn a_sealed_volume_is_signed_read_only_and_tamper_evident() {
        let mut dev = volume();
        let sb = seal(&mut dev).unwrap();
        assert_eq!(seal(&mut dev).unwrap(), sb, "sealing twice changes nothing");
        add(&mut dev, root_seal(&sb, Role::CreatorRing0)).unwrap();
        // Adding a second signature leaves the first valid.
        add(&mut dev, root_seal(&sb, Role::VerifyRing3)).unwrap();
        let mut s = [0u8; BLOCK];
        let mut area = Box::new([0u8; AREA]);
        assert!(read(&mut dev, &mut s, &mut area).unwrap());
        assert_eq!(s, sb);
        let t = judge(&s, &area[..], &mut Fake).unwrap();
        assert!(!t.tampered());
        assert_eq!(t.badge(), Badge::TreeRoot);
        assert!(t.ring0_signed());
        // Exactly one superblock is left, and it is sealed.
        assert!(Superblock::decode(&dev.data[SUPER[0] as usize * BLOCK..][..BLOCK]).is_ok() != Superblock::decode(&dev.data[SUPER[1] as usize * BLOCK..][..BLOCK]).is_ok());
        // The writer will not touch it; the reader still reads it.
        assert_eq!(Writer::open(dev.clone(), Options::default(), Box::new(FixedClock(6))).err(), Some(Error::ReadOnly));
        let mut sc = Box::new(crate::ncfs::Scratch::new());
        let mut v = crate::ncfs::Volume::open(crate::ncfs::SliceDev::new(&dev.data), &mut sc.node).unwrap();
        assert!(v.resolve(b"/init.ncapp", &mut sc).is_ok());
        // A changed superblock no longer matches what was signed.
        let mut bad = s;
        bad[300] ^= 1;
        assert!(judge(&bad, &area[..], &mut Fake).unwrap().tampered());
    }

    #[test]
    fn the_area_is_checked_byte_for_byte() {
        let sb = [7u8; BLOCK];
        let good = encode(&[root_seal(&sb, Role::CreatorRing0)]).unwrap();
        assert!(parse(&good).is_ok());
        let mut trailing = good.clone();
        trailing[AREA - 1] = 1;
        assert!(parse(&trailing).is_err(), "nothing hides after the signatures");
        let twice = encode(&[root_seal(&sb, Role::CreatorRing0), root_seal(&sb, Role::CreatorRing0)]);
        assert!(twice.is_err(), "one signature per role");
        let mut draft = root_seal(&sb, Role::SelfSigned);
        draft.alg = String::from("dilithium5");
        draft.pubkey = std::vec![1; 32];
        assert!(encode(&[draft]).is_err(), "drafts are refused here too");
        let mut short = root_seal(&sb, Role::CreatorRing0);
        short.sig.pop();
        assert!(encode(&[short]).is_err(), "the hybrid's length is fixed");
        assert!(parse(&std::vec![0u8; AREA]).is_err(), "an empty area is no seal");
    }
}
