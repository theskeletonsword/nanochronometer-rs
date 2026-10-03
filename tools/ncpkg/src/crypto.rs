// SPDX-License-Identifier: Apache-2.0
//! Keys, signatures, and the verifier this tool hands the package manager.
//!
//! What gets signed is nanochrono-core's business (`ncpkg::sig::Message`:
//! the domain, the role, the SHA-512 of the manifest's signed bytes); this
//! module does the arithmetic:
//!
//! | Algorithm | Public key | Signature | Over the message |
//! |---|---|---|---|
//! | `mldsa87` / `mldsa65` / `mldsa44` | 2592 / 1952 / 1312 bytes | 4627 / 3309 / 2420 | ML-DSA (FIPS 204), empty context |
//! | `slhdsa-{sha2,shake}-{128,192,256}{s,f}` | 32 / 48 / 64 | 7856 … 49 856 | SLH-DSA (FIPS 205), empty context, hedged |
//! | `ed25519` | 32 | 64 | Ed25519 (strict verification) |
//! | `p256` / `p384` / `p521` | SEC1 uncompressed, 65 / 97 / 133 | r ‖ s, 64 / 96 / 132 | ECDSA with SHA-256 / -384 / -512 |
//! | `rsa-pss` | DER SubjectPublicKeyInfo, ≥ 2048 bits | the modulus' length | RSASSA-PSS, SHA-512, verified only |
//!
//! A hybrid (`mldsa87+p521`, the roots' algorithm; `mldsa65+ed25519`…) is
//! the two halves concatenated in the order named, public keys and
//! signatures alike; both must verify. A key's fingerprint is the first 8
//! bytes of SHA-512 over its public key(s) — the roots' as `ncplu-sign`
//! prints them.
//!
//! Root keys are `ncplu-sign keygen` directories (`mldsa.seed`,
//! `p521.scalar`, `root_pubkeys.bin`). Self-signing keys are this tool's
//! own JSON key files (`ncpkg keygen`). Neither ever belongs in the
//! repository.

use nanochrono_core::json::{self, Json, Style};
use nanochrono_core::ncpkg::base64;
use nanochrono_core::ncpkg::sig::{self, Alg, Role, SlhDsa, Verdict, Verifier};
use std::path::Path;

pub const ROOT_MAGIC: &[u8; 8] = b"NCROOT01";
const MLDSA87_PK: usize = 2592;
const P521_PK: usize = 133;

/// The public key's length for a component, `None` for RSA (whatever is
/// left, so RSA must come last in a hybrid — it can only be second).
pub fn pk_len(a: Alg) -> Option<usize> {
    match a {
        Alg::MlDsa44 => Some(1312),
        Alg::SlhDsa(p) => Some(2 * p.n()),
        Alg::MlDsa65 => Some(1952),
        Alg::MlDsa87 => Some(2592),
        Alg::Ed25519 => Some(32),
        Alg::P256 => Some(65),
        Alg::P384 => Some(97),
        Alg::P521 => Some(133),
        Alg::RsaPss => None,
    }
}

/// Splits a buffer holding one or two components' worth.
fn split(buf: &[u8], first: Option<usize>, second: bool) -> Option<(&[u8], &[u8])> {
    if !second {
        return Some((buf, &[]));
    }
    let n = first?;
    (buf.len() > n).then(|| buf.split_at(n))
}

pub fn fingerprint(public: &[u8]) -> String {
    String::from_utf8_lossy(&sig::fingerprint(&nanochrono_core::sha512::digest(public))).into_owned()
}

macro_rules! mldsa_verify {
    ($p:ty, $pk:expr, $msg:expr, $sig:expr) => {{
        use ml_dsa::signature::Verifier as _;
        (|| {
            let enc = ml_dsa::EncodedVerifyingKey::<$p>::try_from($pk).ok()?;
            let vk = ml_dsa::VerifyingKey::<$p>::decode(&enc);
            let enc_sig = ml_dsa::EncodedSignature::<$p>::try_from($sig).ok()?;
            let sig = ml_dsa::Signature::<$p>::decode(&enc_sig)?;
            Some(vk.verify($msg, &sig).is_ok())
        })()
        .unwrap_or(false)
    }};
}

macro_rules! ecdsa_verify {
    ($curve:ident, $pk:expr, $msg:expr, $sig:expr) => {{
        use signature::Verifier as _;
        (|| {
            let vk = $curve::ecdsa::VerifyingKey::from_sec1_bytes($pk).ok()?;
            let sig = $curve::ecdsa::Signature::from_slice($sig).ok()?;
            Some(vk.verify($msg, &sig).is_ok())
        })()
        .unwrap_or(false)
    }};
}

macro_rules! ecdsa_generate {
    ($curve:ident, $n:expr) => {{
        // A random scalar in [1, n): almost every draw is one.
        loop {
            let mut scalar = [0u8; $n];
            random(&mut scalar)?;
            let arr = hybrid_array::Array::try_from(&scalar[..]).map_err(|_| "scalar size")?;
            if let Ok(sk) = $curve::ecdsa::SigningKey::from_bytes(&arr) {
                let public = sk.verifying_key().to_sec1_point(false).as_bytes().to_vec();
                break (scalar.to_vec(), public);
            }
        }
    }};
}

macro_rules! ecdsa_sign {
    ($curve:ident, $secret:expr, $msg:expr) => {{
        use signature::Signer as _;
        let arr = hybrid_array::Array::try_from(&$secret[..]).map_err(|_| "bad ECDSA key size")?;
        let sk = $curve::ecdsa::SigningKey::from_bytes(&arr).map_err(|e| format!("bad ECDSA key: {e}"))?;
        let sig: $curve::ecdsa::Signature = sk.sign($msg);
        sig.to_bytes().to_vec()
    }};
}

macro_rules! mldsa_sign {
    ($p:ty, $seed:expr, $msg:expr) => {{
        use ml_dsa::Signer as _;
        let seed = hybrid_array::Array::try_from(&$seed[..]).map_err(|_| "bad ML-DSA seed size")?;
        ml_dsa::SigningKey::<$p>::from_seed(&seed).sign($msg).encode().to_vec()
    }};
}

macro_rules! ecdsa_public {
    ($curve:ident, $secret:expr) => {{
        let arr = hybrid_array::Array::try_from(&$secret[..]).map_err(|_| String::from("bad ECDSA key size"))?;
        let sk = $curve::ecdsa::SigningKey::from_bytes(&arr).map_err(|e| format!("bad ECDSA key: {e}"))?;
        sk.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }};
}

/// Runs `$f::<P>` for the SLH-DSA parameter set `$p`: the twelve FIPS 205
/// sets as the crate's types.
macro_rules! slh_dispatch {
    ($p:expr, $f:ident ( $($arg:expr),* )) => {
        match $p {
            SlhDsa::Sha2_128s => $f::<slh_dsa::Sha2_128s>($($arg),*),
            SlhDsa::Sha2_128f => $f::<slh_dsa::Sha2_128f>($($arg),*),
            SlhDsa::Sha2_192s => $f::<slh_dsa::Sha2_192s>($($arg),*),
            SlhDsa::Sha2_192f => $f::<slh_dsa::Sha2_192f>($($arg),*),
            SlhDsa::Sha2_256s => $f::<slh_dsa::Sha2_256s>($($arg),*),
            SlhDsa::Sha2_256f => $f::<slh_dsa::Sha2_256f>($($arg),*),
            SlhDsa::Shake128s => $f::<slh_dsa::Shake128s>($($arg),*),
            SlhDsa::Shake128f => $f::<slh_dsa::Shake128f>($($arg),*),
            SlhDsa::Shake192s => $f::<slh_dsa::Shake192s>($($arg),*),
            SlhDsa::Shake192f => $f::<slh_dsa::Shake192f>($($arg),*),
            SlhDsa::Shake256s => $f::<slh_dsa::Shake256s>($($arg),*),
            SlhDsa::Shake256f => $f::<slh_dsa::Shake256f>($($arg),*),
        }
    };
}

fn slh_verify<P: slh_dsa::ParameterSet>(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(vk), Ok(sig)) = (slh_dsa::VerifyingKey::<P>::try_from(pk), slh_dsa::Signature::<P>::try_from(sig)) else {
        return false;
    };
    vk.try_verify_with_context(msg, &[], &sig).is_ok()
}

/// Generates a key from fresh seeds; returns (secret, public).
fn slh_generate<P: slh_dsa::ParameterSet>(n: usize) -> Result<(Vec<u8>, Vec<u8>), String> {
    use signature::Keypair as _;
    let mut seeds = vec![0u8; 3 * n];
    random(&mut seeds)?;
    let sk = slh_dsa::SigningKey::<P>::slh_keygen_internal(&seeds[..n], &seeds[n..2 * n], &seeds[2 * n..]);
    Ok((sk.to_bytes().to_vec(), sk.verifying_key().to_bytes().to_vec()))
}

/// Hedged signing (FIPS 205 §10.2): fresh randomness in each signature.
fn slh_sign<P: slh_dsa::ParameterSet>(secret: &[u8], msg: &[u8], n: usize) -> Result<Vec<u8>, String> {
    let sk = slh_dsa::SigningKey::<P>::try_from(secret).map_err(|_| String::from("bad SLH-DSA key"))?;
    let mut rnd = vec![0u8; n];
    random(&mut rnd)?;
    let sig = sk.try_sign_with_context(msg, &[], Some(&rnd)).map_err(|_| String::from("SLH-DSA signing failed"))?;
    Ok(sig.to_bytes().to_vec())
}

fn slh_public<P: slh_dsa::ParameterSet>(secret: &[u8]) -> Result<Vec<u8>, String> {
    use signature::Keypair as _;
    let sk = slh_dsa::SigningKey::<P>::try_from(secret).map_err(|_| String::from("bad SLH-DSA key"))?;
    Ok(sk.verifying_key().to_bytes().to_vec())
}

/// One component over `msg`.
pub fn verify_one(alg: Alg, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match alg {
        Alg::MlDsa44 => mldsa_verify!(ml_dsa::MlDsa44, pk, msg, sig),
        Alg::SlhDsa(p) => slh_dispatch!(p, slh_verify(pk, msg, sig)),
        Alg::MlDsa65 => mldsa_verify!(ml_dsa::MlDsa65, pk, msg, sig),
        Alg::MlDsa87 => mldsa_verify!(ml_dsa::MlDsa87, pk, msg, sig),
        Alg::Ed25519 => (|| {
            let pk: [u8; 32] = pk.try_into().ok()?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).ok()?;
            let sig = ed25519_dalek::Signature::from_slice(sig).ok()?;
            Some(vk.verify_strict(msg, &sig).is_ok())
        })()
        .unwrap_or(false),
        Alg::P256 => ecdsa_verify!(p256, pk, msg, sig),
        Alg::P384 => ecdsa_verify!(p384, pk, msg, sig),
        Alg::P521 => ecdsa_verify!(p521, pk, msg, sig),
        Alg::RsaPss => (|| {
            use rsa::pkcs8::DecodePublicKey;
            use rsa::signature::Verifier as _;
            use rsa::traits::PublicKeyParts;
            let key = rsa::RsaPublicKey::from_public_key_der(pk).ok()?;
            // Not retired (SP 800-131A, FIPS 186-5): a 2048-bit modulus or
            // more, and a public exponent of at least 65537.
            if key.size() < 256 || key.e() < &rsa::BigUint::from(65537u32) {
                return Some(false);
            }
            let vk = rsa::pss::VerifyingKey::<sha2_010::Sha512>::new(key);
            let sig = rsa::pss::Signature::try_from(sig).ok()?;
            Some(vk.verify(msg, &sig).is_ok())
        })()
        .unwrap_or(false),
    }
}

/// Every component of `alg` over `msg`, `public` and `sig` split as the
/// module docs say.
pub fn verify_all(alg: &str, public: &[u8], msg: &[u8], sig: &[u8]) -> Option<bool> {
    let (a, b) = sig::parse_alg(alg)?;
    let (pa, pb) = split(public, pk_len(a), b.is_some())?;
    let first_sig = match a.sig_len() {
        Some(n) => Some(n),
        // RSA first in a hybrid cannot be split; parse_alg puts the
        // post-quantum half first and RSA is classical, so only an
        // RSA-plus-classical pair could, and those cannot be split either.
        None if b.is_none() => None,
        None => return Some(false),
    };
    let (sa, sb) = split(sig, first_sig, b.is_some())?;
    let ok_a = verify_one(a, pa, msg, sa);
    let ok_b = b.map_or(true, |b| verify_one(b, pb, msg, sb));
    Some(ok_a && ok_b)
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

fn random(buf: &mut [u8]) -> Result<(), String> {
    getrandom::fill(buf).map_err(|e| format!("no randomness from the operating system: {e}"))
}

/// A secret key component: the algorithm, the secret, the public key.
#[derive(Clone)]
pub struct Part {
    pub alg: Alg,
    pub secret: Vec<u8>,
    pub public: Vec<u8>,
}

impl Part {
    fn generate(alg: Alg) -> Result<Part, String> {
        let (secret, public) = match alg {
            Alg::SlhDsa(p) => slh_dispatch!(p, slh_generate(p.n()))?,
            Alg::MlDsa44 | Alg::MlDsa65 | Alg::MlDsa87 => {
                let mut seed = [0u8; 32];
                random(&mut seed)?;
                let public = mldsa_public(alg, &seed)?;
                (seed.to_vec(), public)
            }
            Alg::Ed25519 => {
                let mut seed = [0u8; 32];
                random(&mut seed)?;
                let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
                (seed.to_vec(), sk.verifying_key().to_bytes().to_vec())
            }
            Alg::P256 => ecdsa_generate!(p256, 32),
            Alg::P384 => ecdsa_generate!(p384, 48),
            Alg::P521 => ecdsa_generate!(p521, 66),
            Alg::RsaPss => {
                return Err(String::from(
                    "RSA keys are verified, not made, by this tool: sign with OpenSSL or an HSM and `ncpkg attach`",
                ))
            }
        };
        Ok(Part { alg, secret, public })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        Ok(match self.alg {
            Alg::SlhDsa(p) => slh_dispatch!(p, slh_sign(&self.secret, msg, p.n()))?,
            Alg::MlDsa44 => mldsa_sign!(ml_dsa::MlDsa44, &self.secret, msg),
            Alg::MlDsa65 => mldsa_sign!(ml_dsa::MlDsa65, &self.secret, msg),
            Alg::MlDsa87 => mldsa_sign!(ml_dsa::MlDsa87, &self.secret, msg),
            Alg::Ed25519 => {
                use signature::Signer as _;
                let seed: [u8; 32] = self.secret.as_slice().try_into().map_err(|_| "bad Ed25519 key")?;
                ed25519_dalek::SigningKey::from_bytes(&seed).sign(msg).to_bytes().to_vec()
            }
            Alg::P256 => ecdsa_sign!(p256, &self.secret, msg),
            Alg::P384 => ecdsa_sign!(p384, &self.secret, msg),
            Alg::P521 => ecdsa_sign!(p521, &self.secret, msg),
            Alg::RsaPss => return Err(String::from("RSA signing is not done by this tool")),
        })
    }
}




fn mldsa_public(alg: Alg, seed: &[u8; 32]) -> Result<Vec<u8>, String> {
    use signature::Keypair as _;
    let seed = hybrid_array::Array::try_from(&seed[..]).map_err(|_| "bad ML-DSA seed size")?;
    Ok(match alg {
        Alg::MlDsa44 => ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&seed).verifying_key().encode().to_vec(),
        Alg::MlDsa65 => ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed).verifying_key().encode().to_vec(),
        _ => ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(&seed).verifying_key().encode().to_vec(),
    })
}

/// A signing key: one component, or a hybrid of two.
#[derive(Clone)]
pub struct SecretKey {
    pub alg: String,
    pub parts: Vec<Part>,
}

impl SecretKey {
    pub fn generate(alg: &str) -> Result<SecretKey, String> {
        let (a, b) = sig::parse_alg(alg).ok_or_else(|| format!("unknown or ill-formed algorithm {alg:?}"))?;
        let mut parts = vec![Part::generate(a)?];
        if let Some(b) = b {
            parts.push(Part::generate(b)?);
        }
        Ok(SecretKey { alg: String::from(alg), parts })
    }

    /// The public key(s), concatenated.
    pub fn public(&self) -> Vec<u8> {
        self.parts.iter().flat_map(|p| p.public.clone()).collect()
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public())
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for p in &self.parts {
            out.extend(p.sign(msg)?);
        }
        Ok(out)
    }

    /// The JSON key file.
    pub fn to_file(&self) -> String {
        Json::obj([
            ("format", Json::str("ncpkg-key/1")),
            ("alg", Json::str(&self.alg)),
            ("secret", Json::Arr(self.parts.iter().map(|p| Json::Str(base64::encode_string(&p.secret))).collect())),
            ("public", Json::Str(base64::encode_string(&self.public()))),
            ("fingerprint", Json::Str(self.fingerprint())),
        ])
        .write(Style::PRETTY)
    }

    pub fn load(path: &Path) -> Result<SecretKey, String> {
        let text = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let v = json::parse(&text, &json::Limits::MANIFEST).map_err(|e| format!("{}: {e}", path.display()))?;
        let bad = || format!("{}: not an ncpkg key file", path.display());
        if !v.get("format").and_then(|f| f.as_str()).is_some_and(|f| f.eq_str("ncpkg-key/1")) {
            return Err(bad());
        }
        let alg = v.get("alg").and_then(|a| a.as_str()).ok_or_else(bad)?.to_string();
        let (a, b) = sig::parse_alg(&alg).ok_or_else(bad)?;
        let secrets: Vec<Vec<u8>> = v
            .get("secret")
            .ok_or_else(bad)?
            .elements()
            .map(|s| s.as_str().and_then(|s| base64::decode_vec(s.raw())))
            .collect::<Option<_>>()
            .ok_or_else(bad)?;
        let algs: Vec<Alg> = std::iter::once(a).chain(b).collect();
        if secrets.len() != algs.len() {
            return Err(bad());
        }
        let mut parts = Vec::new();
        for (alg, secret) in algs.into_iter().zip(secrets) {
            let public = match alg {
                Alg::SlhDsa(p) => slh_dispatch!(p, slh_public(&secret))?,
                Alg::MlDsa44 | Alg::MlDsa65 | Alg::MlDsa87 => mldsa_public(alg, secret.as_slice().try_into().map_err(|_| bad())?)?,
                Alg::Ed25519 => {
                    let seed: [u8; 32] = secret.as_slice().try_into().map_err(|_| bad())?;
                    ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes().to_vec()
                }
                Alg::P256 => ecdsa_public!(p256, secret),
                Alg::P384 => ecdsa_public!(p384, secret),
                Alg::P521 => ecdsa_public!(p521, secret),
                Alg::RsaPss => return Err(bad()),
            };
            parts.push(Part { alg, secret, public });
        }
        Ok(SecretKey { alg, parts })
    }

    /// An `ncplu-sign keygen` directory: the roots' ML-DSA-87 + P-521.
    pub fn load_root_dir(dir: &Path) -> Result<SecretKey, String> {
        let read = |name: &str, n: usize| -> Result<Vec<u8>, String> {
            let p = dir.join(name);
            let d = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            if d.len() != n {
                return Err(format!("{}: expected {n} bytes, got {}", p.display(), d.len()));
            }
            Ok(d)
        };
        let seed = read("mldsa.seed", 32)?;
        let scalar = read("p521.scalar", 66)?;
        let mldsa = Part { alg: Alg::MlDsa87, public: mldsa_public(Alg::MlDsa87, seed.as_slice().try_into().unwrap())?, secret: seed };
        let p521 = Part { alg: Alg::P521, public: ecdsa_public!(p521, scalar), secret: scalar };
        Ok(SecretKey { alg: String::from(sig::ROOT_ALG), parts: vec![mldsa, p521] })
    }
}


/// Reads a root public-key file (`NCROOT01`, ML-DSA-87, P-521) into the
/// concatenated public keys.
pub fn read_root_pub(path: &Path) -> Result<Vec<u8>, String> {
    let d = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if d.len() != ROOT_MAGIC.len() + MLDSA87_PK + P521_PK || &d[..8] != ROOT_MAGIC {
        return Err(format!("{}: not a root public-key file (NCROOT01)", path.display()));
    }
    Ok(d[8..].to_vec())
}

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

/// The roots this host trusts, one per role, and the owner's enrolled
/// self-signing keys.
#[derive(Default)]
pub struct HostVerifier {
    roots: [Option<Vec<u8>>; 4],
    owner_keys: Vec<String>,
}

fn root_index(role: Role) -> Option<usize> {
    match role {
        Role::CreatorRing3 => Some(0),
        Role::CreatorRing0 => Some(1),
        Role::VerifyRing3 => Some(2),
        Role::VerifyRing0 => Some(3),
        Role::SelfSigned => None,
    }
}

impl HostVerifier {
    /// `dir` holds `<role>.pub` files (`creator-ring3.pub`, …), each a root
    /// public-key file; roles without one are simply not trusted.
    pub fn load(roots: Option<&Path>, owner_keys: Option<&Path>) -> Result<HostVerifier, String> {
        let mut v = HostVerifier::default();
        if let Some(dir) = roots {
            let mut any = false;
            for role in [Role::CreatorRing3, Role::CreatorRing0, Role::VerifyRing3, Role::VerifyRing0] {
                let p = dir.join(format!("{}.pub", role.name()));
                if p.exists() {
                    v.roots[root_index(role).unwrap()] = Some(read_root_pub(&p)?);
                    any = true;
                }
            }
            if !any {
                return Err(format!("{}: no <role>.pub root files (creator-ring3.pub, creator-ring0.pub, verify-ring3.pub, verify-ring0.pub)", dir.display()));
            }
        }
        if let Some(path) = owner_keys {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            v.owner_keys = text.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect();
        }
        Ok(v)
    }

    /// The fingerprint of the root this verifier holds for `role`.
    pub fn root_fingerprint(&self, role: Role) -> Option<String> {
        root_index(role).and_then(|i| self.roots[i].as_deref()).map(fingerprint)
    }
}

impl Verifier for HostVerifier {
    fn verify(&mut self, role: Role, alg: &str, key: &str, pubkey: &[u8], message: &[u8], sig: &[u8]) -> Verdict {
        let public: &[u8] = match root_index(role) {
            Some(i) => match &self.roots[i] {
                Some(pk) => pk,
                None => return Verdict::UnknownKey,
            },
            None => pubkey,
        };
        if fingerprint(public) != key {
            // A root signature by a key that is not this host's root for the
            // role counts for nothing (it is not evidence of tampering); a
            // self-signature whose fingerprint does not name its own key is
            // simply wrong.
            return if role.is_root() { Verdict::UnknownKey } else { Verdict::Invalid };
        }
        match verify_all(alg, public, message, sig) {
            None => Verdict::Unsupported,
            Some(true) => Verdict::Valid,
            Some(false) => Verdict::Invalid,
        }
    }

    fn enrolled(&mut self, fingerprint: &str) -> bool {
        self.owner_keys.iter().any(|k| k == fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_algorithm_signs_and_verifies() {
        for alg in [
            "ed25519", "p256", "p384", "p521", "mldsa44", "mldsa65", "mldsa87", "slhdsa-sha2-128f", "slhdsa-shake-128f",
            "mldsa87+p521", "mldsa65+ed25519", "p384+ed25519", "mldsa65+slhdsa-sha2-128f",
        ] {
            let key = SecretKey::generate(alg).unwrap();
            let msg = b"NCPKG-SIG-2\0self\0message";
            let sig = key.sign(msg).unwrap();
            assert_eq!(verify_all(alg, &key.public(), msg, &sig), Some(true), "{alg}");
            let mut bad = sig.clone();
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert_eq!(verify_all(alg, &key.public(), msg, &bad), Some(false), "{alg} tampered");
            assert_eq!(verify_all(alg, &key.public(), b"other message", &sig), Some(false), "{alg} other message");
            // The key file round-trips.
            let dir = std::env::temp_dir().join(format!("ncpkg-key-{}-{}", std::process::id(), alg.replace('+', "_")));
            std::fs::write(&dir, key.to_file()).unwrap();
            let back = SecretKey::load(&dir).unwrap();
            assert_eq!(back.public(), key.public());
            assert_eq!(verify_all(alg, &key.public(), msg, &back.sign(msg).unwrap()), Some(true));
            std::fs::remove_file(&dir).unwrap();
        }
        assert!(SecretKey::generate("rsa-pss").is_err());
        assert!(SecretKey::generate("dilithium5").is_err());
        assert!(SecretKey::generate("sphincs+-sha2-128s").is_err());
        assert_eq!(verify_all("nope", &[], b"", &[]), None);
    }

    /// Every SLH-DSA parameter set, `s` included — slow without
    /// optimisation: `cargo test --release -- --ignored`.
    #[test]
    #[ignore]
    fn every_slh_dsa_parameter_set() {
        for p in SlhDsa::ALL {
            let key = SecretKey::generate(p.name()).unwrap();
            assert_eq!(key.public().len(), 2 * p.n());
            let sig = key.sign(b"m").unwrap();
            assert_eq!(sig.len(), p.sig_len(), "{}", p.name());
            assert_eq!(verify_all(p.name(), &key.public(), b"m", &sig), Some(true), "{}", p.name());
        }
    }
}
