// SPDX-License-Identifier: Apache-2.0
//! Package signatures: who vouches for a package, and for which ring.
//!
//! # Roles
//!
//! Four roots, each a hybrid **ML-DSA-87 + ECDSA P-521** key pair held by
//! the creator of NanoChronometer, and the author's own key:
//!
//! | Role | Badge | Means | Grants |
//! |---|---|---|---|
//! | `creator-ring3` | ✅ green check | made by the creator | ring 3 |
//! | `creator-ring0` | 🌳 tree root | made by the creator | ring 0 |
//! | `verify-ring3` | 🔵 blue check | a third party's, certified by the creator | ring 3 |
//! | `verify-ring0` | 🔵 blue check, ring 0 | a third party's, certified for ring 0 | ring 0, without the community switch |
//! | `self` | none | the author's own key: Ed25519, ECDSA P-256/384/521, RSA-PSS, ML-DSA-65/87, or two of them | ring 3; ring 0 only with **Enable Ring0 Community Modules and Drivers** |
//!
//! A signature grants only its own ring. A ring-3 signature never grants
//! ring 0, however trusted its key: the music player the creator certified
//! for ring 3 cannot ship a kernel-mode update under that certificate. Four
//! separate roots make that structural, not a check someone can forget:
//! the ring-0 roots never sign ring-3 work and vice versa.
//!
//! # What is signed
//!
//! Every signature signs the same thing, framed by its role:
//!
//! ```text
//! "NCPKG-SIG-2" 0x00  role-name  0x00  SHA-512(signed bytes)
//! ```
//!
//! where *signed bytes* are the exact bytes of the manifest's `signed`
//! object as they stand in `ncpkg.meta` — no re-serialisation, so no two
//! programs can disagree about what was signed. The `signed` object lists
//! every file of the package with its SHA-512, so a signature covers every
//! byte the package installs. Putting the role in the message means a
//! signature cannot be moved from one role to another even under the same
//! key. A hybrid signature is both halves, each over the whole message,
//! concatenated (ML-DSA first); **both** must verify.
//!
//! # Who verifies
//!
//! This module frames messages and decides what the results mean; the
//! cryptography belongs to the platform, behind [`Verifier`]: the host tool
//! links RustCrypto, the kernel its `plugin-verify` feature. A signature
//! that is present and does **not** verify makes the package refused
//! outright — that is a package changed after signing, not an unsigned one.

use crate::json::Str;

/// Domain separation for package signatures.
pub const DOMAIN: &[u8] = b"NCPKG-SIG-2\0";
/// The most signatures one manifest may carry.
pub const MAX_SIGNATURES: usize = 8;
/// The largest decoded signature: SLH-DSA-256f is 49 856 bytes, and one
/// half of a hybrid besides.
pub const MAX_SIG_BYTES: usize = 64 * 1024;
/// The largest decoded public key set (ML-DSA-87 + P-521 is 2725 bytes).
pub const MAX_PUBKEY_BYTES: usize = 4096;
/// The hybrid every root uses.
pub const ROOT_ALG: &str = "mldsa87+p521";

/// The roles a signature can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    CreatorRing3,
    CreatorRing0,
    VerifyRing3,
    VerifyRing0,
    SelfSigned,
}

impl Role {
    pub const ALL: [Role; 5] = [Role::CreatorRing3, Role::CreatorRing0, Role::VerifyRing3, Role::VerifyRing0, Role::SelfSigned];

    pub const fn name(self) -> &'static str {
        match self {
            Role::CreatorRing3 => "creator-ring3",
            Role::CreatorRing0 => "creator-ring0",
            Role::VerifyRing3 => "verify-ring3",
            Role::VerifyRing0 => "verify-ring0",
            Role::SelfSigned => "self",
        }
    }

    pub fn from_name(name: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.name() == name)
    }

    /// One of the four creator-held roots (not `self`).
    pub const fn is_root(self) -> bool {
        !matches!(self, Role::SelfSigned)
    }

    /// A valid signature in this role allows ring 0.
    pub const fn grants_ring0(self) -> bool {
        matches!(self, Role::CreatorRing0 | Role::VerifyRing0)
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// An SLH-DSA parameter set (FIPS 205): the hash family, the security
/// category, and small (`s`) or fast (`f`) — small signatures that are slow
/// to make, or larger ones that are quick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlhDsa {
    Sha2_128s,
    Sha2_128f,
    Sha2_192s,
    Sha2_192f,
    Sha2_256s,
    Sha2_256f,
    Shake128s,
    Shake128f,
    Shake192s,
    Shake192f,
    Shake256s,
    Shake256f,
}

impl SlhDsa {
    pub const ALL: [SlhDsa; 12] = [
        SlhDsa::Sha2_128s,
        SlhDsa::Sha2_128f,
        SlhDsa::Sha2_192s,
        SlhDsa::Sha2_192f,
        SlhDsa::Sha2_256s,
        SlhDsa::Sha2_256f,
        SlhDsa::Shake128s,
        SlhDsa::Shake128f,
        SlhDsa::Shake192s,
        SlhDsa::Shake192f,
        SlhDsa::Shake256s,
        SlhDsa::Shake256f,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            SlhDsa::Sha2_128s => "slhdsa-sha2-128s",
            SlhDsa::Sha2_128f => "slhdsa-sha2-128f",
            SlhDsa::Sha2_192s => "slhdsa-sha2-192s",
            SlhDsa::Sha2_192f => "slhdsa-sha2-192f",
            SlhDsa::Sha2_256s => "slhdsa-sha2-256s",
            SlhDsa::Sha2_256f => "slhdsa-sha2-256f",
            SlhDsa::Shake128s => "slhdsa-shake-128s",
            SlhDsa::Shake128f => "slhdsa-shake-128f",
            SlhDsa::Shake192s => "slhdsa-shake-192s",
            SlhDsa::Shake192f => "slhdsa-shake-192f",
            SlhDsa::Shake256s => "slhdsa-shake-256s",
            SlhDsa::Shake256f => "slhdsa-shake-256f",
        }
    }

    /// `n`, the security parameter in bytes: 16, 24 or 32.
    pub const fn n(self) -> usize {
        match self {
            SlhDsa::Sha2_128s | SlhDsa::Sha2_128f | SlhDsa::Shake128s | SlhDsa::Shake128f => 16,
            SlhDsa::Sha2_192s | SlhDsa::Sha2_192f | SlhDsa::Shake192s | SlhDsa::Shake192f => 24,
            _ => 32,
        }
    }

    /// FIPS 205, table 2.
    pub const fn sig_len(self) -> usize {
        match self {
            SlhDsa::Sha2_128s | SlhDsa::Shake128s => 7856,
            SlhDsa::Sha2_128f | SlhDsa::Shake128f => 17088,
            SlhDsa::Sha2_192s | SlhDsa::Shake192s => 16224,
            SlhDsa::Sha2_192f | SlhDsa::Shake192f => 35664,
            SlhDsa::Sha2_256s | SlhDsa::Shake256s => 29792,
            SlhDsa::Sha2_256f | SlhDsa::Shake256f => 49856,
        }
    }
}

/// A signing algorithm component. Only finished standards: Ed25519 (RFC
/// 8032), ECDSA and RSA-PSS (FIPS 186-5), ML-DSA (FIPS 204) and SLH-DSA
/// (FIPS 205). Drafts and pre-standard submissions are refused by name —
/// see [`refusal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsa(SlhDsa),
    Ed25519,
    P256,
    P384,
    P521,
    /// RSASSA-PSS with SHA-512 (FIPS 186-5), a modulus of 2048 bits or more
    /// and a public exponent of 65537 or more. Verified only: keys are made
    /// and used elsewhere (OpenSSL, an HSM).
    RsaPss,
}

impl Alg {
    /// Every accepted component, for listings.
    pub fn all() -> impl Iterator<Item = Alg> {
        [Alg::MlDsa44, Alg::MlDsa65, Alg::MlDsa87]
            .into_iter()
            .chain(SlhDsa::ALL.into_iter().map(Alg::SlhDsa))
            .chain([Alg::Ed25519, Alg::P256, Alg::P384, Alg::P521, Alg::RsaPss])
    }

    pub const fn name(self) -> &'static str {
        match self {
            Alg::MlDsa44 => "mldsa44",
            Alg::MlDsa65 => "mldsa65",
            Alg::MlDsa87 => "mldsa87",
            Alg::SlhDsa(p) => p.name(),
            Alg::Ed25519 => "ed25519",
            Alg::P256 => "p256",
            Alg::P384 => "p384",
            Alg::P521 => "p521",
            Alg::RsaPss => "rsa-pss",
        }
    }

    pub fn from_name(name: &str) -> Option<Alg> {
        Alg::all().find(|a| a.name() == name)
    }

    /// Post-quantum (lattice or hash based) rather than classical.
    pub const fn is_pq(self) -> bool {
        matches!(self, Alg::MlDsa44 | Alg::MlDsa65 | Alg::MlDsa87 | Alg::SlhDsa(_))
    }

    /// The standard it is defined by.
    pub const fn standard(self) -> &'static str {
        match self {
            Alg::MlDsa44 | Alg::MlDsa65 | Alg::MlDsa87 => "FIPS 204",
            Alg::SlhDsa(_) => "FIPS 205",
            Alg::Ed25519 => "RFC 8032",
            Alg::P256 | Alg::P384 | Alg::P521 | Alg::RsaPss => "FIPS 186-5",
        }
    }

    /// The signature's size, where the algorithm fixes it (RSA's follows
    /// its modulus).
    pub const fn sig_len(self) -> Option<usize> {
        match self {
            Alg::MlDsa44 => Some(2420),
            Alg::MlDsa65 => Some(3309),
            Alg::MlDsa87 => Some(4627),
            Alg::SlhDsa(p) => Some(p.sig_len()),
            Alg::Ed25519 | Alg::P256 => Some(64),
            Alg::P384 => Some(96),
            Alg::P521 => Some(132),
            Alg::RsaPss => None,
        }
    }
}

/// Why an algorithm name is refused, when it names something that is not a
/// finished standard: a pre-standard submission, a key-encapsulation scheme,
/// a stateful scheme, or a retired one. `None` for a name this does not
/// recognise either way (it is then simply unknown).
pub fn refusal(name: &str) -> Option<&'static str> {
    // Case-insensitive without allocating: the kernel reads manifests
    // without a heap.
    let n = name.as_bytes();
    let starts = |p: &str| n.len() >= p.len() && n[..p.len()].eq_ignore_ascii_case(p.as_bytes());
    let contains = |p: &str| n.windows(p.len()).any(|w| w.eq_ignore_ascii_case(p.as_bytes()));
    let is = |p: &str| n.eq_ignore_ascii_case(p.as_bytes());
    if starts("dilithium") || starts("crystals-dilithium") {
        Some("CRYSTALS-Dilithium is the pre-standard submission; use ML-DSA (FIPS 204)")
    } else if starts("sphincs") {
        Some("SPHINCS+ is the pre-standard submission; use SLH-DSA (FIPS 205)")
    } else if starts("kyber") || starts("crystals-kyber") || starts("mlkem") || starts("ml-kem") {
        Some("a key-encapsulation mechanism, not a signature (ML-KEM is FIPS 203, for key exchange)")
    } else if starts("falcon") || starts("fndsa") || starts("fn-dsa") {
        Some("FN-DSA (Falcon) is not a finished standard")
    } else if starts("xmss") || starts("lms") || starts("hss") {
        Some("a stateful hash-based scheme (SP 800-208); use SLH-DSA (FIPS 205), which is stateless")
    } else if is("dsa") || starts("dsa-") {
        Some("DSA was withdrawn by FIPS 186-5")
    } else if starts("rainbow") || starts("picnic") || starts("gemss") || starts("sike") || starts("sidh") {
        Some("a broken or withdrawn post-quantum candidate")
    } else if contains("sha1") || contains("md5") {
        Some("SHA-1 and MD5 signatures are retired")
    } else if starts("rsa") && !is("rsa-pss") {
        Some("RSA signs here as RSASSA-PSS with SHA-512 (`rsa-pss`), 2048-bit modulus or more")
    } else {
        None
    }
}
/// An algorithm field: one component, or two joined by `+` (a hybrid: two
/// different halves, and a post-quantum half first when there is one —
/// two post-quantum families together, lattice and hash, are allowed).
pub fn parse_alg(text: &str) -> Option<(Alg, Option<Alg>)> {
    match text.split_once('+') {
        None => Some((Alg::from_name(text)?, None)),
        Some((a, b)) => {
            let (a, b) = (Alg::from_name(a)?, Alg::from_name(b)?);
            if a == b || (b.is_pq() && !a.is_pq()) {
                return None;
            }
            Some((a, Some(b)))
        }
    }
}

/// A key fingerprint as the tools print it: the first 8 bytes of SHA-512
/// over the public key(s), as `xxxx-xxxx-xxxx-xxxx` in lower-case hex.
pub fn is_fingerprint(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 19
        && b.iter().enumerate().all(|(i, &c)| if i % 5 == 4 { c == b'-' } else { c.is_ascii_digit() || (b'a'..=b'f').contains(&c) })
}

/// Formats a fingerprint from the SHA-512 of the public key(s).
pub fn fingerprint(digest: &[u8; 64]) -> [u8; 19] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [b'-'; 19];
    let mut o = 0;
    for (i, b) in digest[..8].iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            o += 1;
        }
        out[o] = HEX[usize::from(b >> 4)];
        out[o + 1] = HEX[usize::from(b & 15)];
        o += 2;
    }
    out
}

/// The message a signature in `role` signs, given the manifest's signed
/// bytes.
#[derive(Clone, Copy)]
pub struct Message {
    buf: [u8; 96],
    len: usize,
}

impl core::fmt::Debug for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Message").field("len", &self.len).finish()
    }
}

impl Message {
    pub fn new(role: Role, signed: &[u8]) -> Message {
        let mut buf = [0u8; 96];
        let mut n = 0;
        for part in [DOMAIN, role.name().as_bytes(), b"\0"] {
            buf[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        buf[n..n + 64].copy_from_slice(&crate::sha512::digest(signed));
        Message { buf, len: n + 64 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// One entry of the manifest's `signatures` array.
#[derive(Debug, Clone, Copy)]
pub struct SigEntry<'a> {
    pub role: Role,
    /// The algorithm field (`mldsa87+p521`, `ed25519`, …).
    pub alg: &'a str,
    /// The fingerprint of the signing key.
    pub key: &'a str,
    /// Base64 public key(s): self-signatures only.
    pub pubkey: Option<Str<'a>>,
    /// Base64 signature bytes.
    pub sig: Str<'a>,
}

/// What a verifier makes of one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// It verifies (both halves of a hybrid).
    Valid,
    /// It does not verify: the package changed after it was signed, or the
    /// signature was made by a different key than the role's.
    Invalid,
    /// This verifier holds no key for the role (a root not embedded).
    UnknownKey,
    /// An algorithm this verifier cannot check.
    Unsupported,
}

/// The platform's cryptography and trust store.
pub trait Verifier {
    /// Checks `sig` (decoded) over `message`. For the roots, the key is the
    /// verifier's own root for `role`, and `key` is the fingerprint the
    /// manifest claims; for `self`, `pubkey` holds the decoded public
    /// key(s) the manifest carries.
    fn verify(&mut self, role: Role, alg: &str, key: &str, pubkey: &[u8], message: &[u8], sig: &[u8]) -> Verdict;

    /// Whether the machine's owner enrolled this self-signing key (by
    /// fingerprint) — the owner-key list, kept like shim's MOK list.
    fn enrolled(&mut self, _fingerprint: &str) -> bool {
        false
    }
}

/// The badge a package shows, from its strongest valid signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Badge {
    /// 🌳 made by the creator, ring 0.
    TreeRoot,
    /// ✅ made by the creator.
    Creator,
    /// 🔵 a third party's, certified by the creator for ring 0.
    VerifiedRing0,
    /// 🔵 a third party's, certified by the creator.
    Verified,
    /// Signed by its author's own key, which the owner enrolled.
    OwnerKey,
    /// Signed by its author's own key.
    SelfSigned,
    Unsigned,
}

impl Badge {
    pub const fn label(self) -> &'static str {
        match self {
            Badge::TreeRoot => "tree root (creator, ring 0)",
            Badge::Creator => "green check (creator)",
            Badge::VerifiedRing0 => "blue check (certified, ring 0)",
            Badge::Verified => "blue check (certified)",
            Badge::OwnerKey => "owner key",
            Badge::SelfSigned => "self-signed",
            Badge::Unsigned => "unsigned",
        }
    }

    /// The short word the database stores.
    pub const fn id(self) -> &'static str {
        match self {
            Badge::TreeRoot => "tree-root",
            Badge::Creator => "creator",
            Badge::VerifiedRing0 => "verified-ring0",
            Badge::Verified => "verified",
            Badge::OwnerKey => "owner-key",
            Badge::SelfSigned => "self-signed",
            Badge::Unsigned => "unsigned",
        }
    }

    pub const fn symbol(self) -> &'static str {
        match self {
            Badge::TreeRoot => "🌳",
            Badge::Creator => "✅",
            Badge::VerifiedRing0 | Badge::Verified => "🔵",
            Badge::OwnerKey | Badge::SelfSigned | Badge::Unsigned => "",
        }
    }
}

/// What the signatures on a package established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trust {
    valid: u8,
    invalid: u8,
    unchecked: u8,
    /// The self-signing key's fingerprint, when its signature verified.
    pub self_key: Option<[u8; 19]>,
    /// That key is on the owner's enrolled list.
    pub self_enrolled: bool,
}

impl Trust {
    pub const NONE: Trust = Trust { valid: 0, invalid: 0, unchecked: 0, self_key: None, self_enrolled: false };

    /// A valid signature in `role`.
    pub fn has(&self, role: Role) -> bool {
        self.valid & role.bit() != 0
    }

    /// A signature in `role` that is present and does not verify.
    pub fn failed(&self, role: Role) -> bool {
        self.invalid & role.bit() != 0
    }

    /// Any signature present and not verifying: the package is refused.
    pub fn tampered(&self) -> bool {
        self.invalid != 0
    }

    /// A signature present that this verifier could not judge.
    pub fn unchecked(&self, role: Role) -> bool {
        self.unchecked & role.bit() != 0
    }

    /// The valid roles, strongest first.
    pub fn roles(&self) -> impl Iterator<Item = Role> + '_ {
        Role::ALL.into_iter().filter(move |r| self.has(*r))
    }

    /// Whether a valid signature allows ring 0 (the community switch is the
    /// policy's business, not the signatures').
    pub fn ring0_signed(&self) -> bool {
        self.has(Role::CreatorRing0) || self.has(Role::VerifyRing0)
    }

    pub fn badge(&self) -> Badge {
        if self.has(Role::CreatorRing0) {
            Badge::TreeRoot
        } else if self.has(Role::CreatorRing3) {
            Badge::Creator
        } else if self.has(Role::VerifyRing0) {
            Badge::VerifiedRing0
        } else if self.has(Role::VerifyRing3) {
            Badge::Verified
        } else if self.has(Role::SelfSigned) && self.self_enrolled {
            Badge::OwnerKey
        } else if self.has(Role::SelfSigned) {
            Badge::SelfSigned
        } else {
            Badge::Unsigned
        }
    }
}

/// Room to decode one signature and its public key, lent by the caller so
/// a kernel without an allocator can verify too.
pub struct Scratch {
    pub sig: [u8; MAX_SIG_BYTES],
    pub pubkey: [u8; MAX_PUBKEY_BYTES],
}

impl core::fmt::Debug for Scratch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Scratch")
    }
}

impl Scratch {
    pub const fn new() -> Scratch {
        Scratch { sig: [0; MAX_SIG_BYTES], pubkey: [0; MAX_PUBKEY_BYTES] }
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks every signature of a validated manifest with `verifier`.
pub fn evaluate<'a>(
    signed: &[u8],
    signatures: impl Iterator<Item = SigEntry<'a>>,
    verifier: &mut dyn Verifier,
    scratch: &mut Scratch,
) -> Trust {
    let mut trust = Trust::NONE;
    for s in signatures {
        let bit = s.role.bit();
        let Some(sig) = super::base64::decode(s.sig.raw(), &mut scratch.sig) else {
            trust.invalid |= bit;
            continue;
        };
        let pubkey: &[u8] = match s.pubkey {
            Some(pk) => match super::base64::decode(pk.raw(), &mut scratch.pubkey) {
                Some(p) => p,
                None => {
                    trust.invalid |= bit;
                    continue;
                }
            },
            None => &[],
        };
        let message = Message::new(s.role, signed);
        match verifier.verify(s.role, s.alg, s.key, pubkey, message.as_bytes(), sig) {
            Verdict::Valid => {
                trust.valid |= bit;
                if s.role == Role::SelfSigned {
                    let mut fp = [0u8; 19];
                    fp.copy_from_slice(s.key.as_bytes().get(..19).unwrap_or(&[b'0'; 19]));
                    trust.self_key = Some(fp);
                    trust.self_enrolled = verifier.enrolled(s.key);
                }
            }
            Verdict::Invalid => trust.invalid |= bit,
            Verdict::UnknownKey | Verdict::Unsupported => trust.unchecked |= bit,
        }
    }
    trust
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_finished_standards() {
        for good in ["mldsa44", "mldsa65", "mldsa87", "slhdsa-sha2-128s", "slhdsa-shake-256f", "ed25519", "p384", "rsa-pss"] {
            assert!(Alg::from_name(good).is_some(), "{good}");
            assert_eq!(refusal(good), None, "{good}");
        }
        for (draft, why) in [
            ("dilithium5", "ML-DSA"),
            ("Dilithium3", "ML-DSA"),
            ("sphincs+-sha2-128s", "SLH-DSA"),
            ("sphincsplus", "SLH-DSA"),
            ("kyber768", "key-encapsulation"),
            ("mlkem768", "key-encapsulation"),
            ("falcon-512", "FN-DSA"),
            ("xmss", "stateful"),
            ("dsa", "withdrawn"),
            ("rsa-pkcs1-sha1", "retired"),
            ("rsa2048", "RSASSA-PSS"),
        ] {
            assert!(Alg::from_name(draft).is_none(), "{draft}");
            assert!(refusal(draft).is_some_and(|r| r.contains(why)), "{draft}: {:?}", refusal(draft));
        }
        assert_eq!(Alg::all().count(), 20);
        for p in SlhDsa::ALL {
            assert_eq!(Alg::from_name(p.name()), Some(Alg::SlhDsa(p)));
            assert!(p.sig_len() <= MAX_SIG_BYTES);
        }
        // Two post-quantum families together (lattice and hash) are a
        // valid hybrid; classical first is not.
        assert_eq!(parse_alg("mldsa65+slhdsa-sha2-128s"), Some((Alg::MlDsa65, Some(Alg::SlhDsa(SlhDsa::Sha2_128s)))));
        assert_eq!(parse_alg("ed25519+slhdsa-sha2-128s"), None);
    }

    #[test]
    fn roles_and_algorithms() {
        for r in Role::ALL {
            assert_eq!(Role::from_name(r.name()), Some(r));
        }
        assert!(Role::CreatorRing0.grants_ring0() && Role::VerifyRing0.grants_ring0());
        assert!(!Role::CreatorRing3.grants_ring0() && !Role::VerifyRing3.grants_ring0() && !Role::SelfSigned.grants_ring0());
        assert_eq!(parse_alg(ROOT_ALG), Some((Alg::MlDsa87, Some(Alg::P521))));
        assert_eq!(parse_alg("ed25519"), Some((Alg::Ed25519, None)));
        assert_eq!(parse_alg("mldsa65+ed25519"), Some((Alg::MlDsa65, Some(Alg::Ed25519))));
        assert_eq!(parse_alg("ed25519+mldsa65"), None, "post-quantum half first");
        assert_eq!(parse_alg("p256+p256"), None);
        assert_eq!(parse_alg("rsa2048"), None);
        assert_eq!(parse_alg("ed25519+p256+p384"), None);
    }

    #[test]
    fn messages_are_framed_by_role() {
        let a = Message::new(Role::CreatorRing3, b"{}");
        let b = Message::new(Role::CreatorRing0, b"{}");
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert!(a.as_bytes().starts_with(b"NCPKG-SIG-2\0creator-ring3\0"));
        assert_eq!(&a.as_bytes()[a.as_bytes().len() - 64..], &crate::sha512::digest(b"{}")[..]);
    }

    #[test]
    fn fingerprints() {
        let fp = fingerprint(&crate::sha512::digest(b"key"));
        let text = core::str::from_utf8(&fp).unwrap();
        assert!(is_fingerprint(text), "{text}");
        assert!(!is_fingerprint("ABCD-0000-0000-0000"));
        assert!(!is_fingerprint("abcd0000-0000-0000"));
    }

    #[test]
    fn badges_follow_the_strongest_valid_role() {
        let mut t = Trust::NONE;
        assert_eq!(t.badge(), Badge::Unsigned);
        t.valid = Role::SelfSigned.bit();
        assert_eq!(t.badge(), Badge::SelfSigned);
        t.self_enrolled = true;
        assert_eq!(t.badge(), Badge::OwnerKey);
        t.valid |= Role::VerifyRing3.bit();
        assert_eq!(t.badge(), Badge::Verified);
        assert!(!t.ring0_signed());
        t.valid |= Role::VerifyRing0.bit();
        assert_eq!(t.badge(), Badge::VerifiedRing0);
        assert!(t.ring0_signed());
        t.valid |= Role::CreatorRing3.bit();
        assert_eq!(t.badge(), Badge::Creator);
        t.valid |= Role::CreatorRing0.bit();
        assert_eq!(t.badge(), Badge::TreeRoot);
    }
}
