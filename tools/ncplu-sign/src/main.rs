// SPDX-License-Identifier: Apache-2.0
//! Developer keys and plugin signing for NanoChronometer `.ncplu` plugins.
//!
//! The hybrid scheme is ML-DSA-87 (FIPS 204, post-quantum) plus P-521 ECDSA
//! (classical). Both sign the same message: the 64-byte SHA-512 digest of the
//! signed region of the plugin, computed exactly as `tools/ncplu.py` and the
//! kernel loader compute it.
//!
//!   ncplu-sign keygen --out KEYDIR
//!       Writes the private keys (mldsa.seed, p521.scalar) into KEYDIR and the
//!       root public-key file root_pubkeys.bin. Point the kernel build at that
//!       file with NCPLU_ROOT_PUBKEYS=KEYDIR/root_pubkeys.bin. KEYDIR must live
//!       OUTSIDE the repository; the private keys never belong in the tree.
//!
//!   ncplu-sign sign PLUGIN.ncplu --keys KEYDIR
//!       Fills the plugin's reserved signature block with both signatures.
//!
//!   ncplu-sign verify PLUGIN.ncplu --root KEYDIR/root_pubkeys.bin
//!       Checks a plugin the way the kernel does: the header digest, then both
//!       signatures against the root. Exit status 0 = Official, 1 = Community.
//!
//!   ncplu-sign fingerprint KEYDIR/root_pubkeys.bin
//!       The root's fingerprint — the kernel prints the same one at boot, so
//!       you can see which key a kernel trusts.
//!
//! The kernel embeds only the public keys and verifies; this tool is the only
//! thing that ever touches the private half.

use std::path::{Path, PathBuf};
use std::process::exit;

use ml_dsa::{MlDsa87, Signer as _};
use signature::{Keypair as _, Verifier as _};
use sha2::{Digest, Sha512};

const MLDSA_PUB_LEN: usize = 2592;
const MLDSA_SIG_LEN: usize = 4627;
const P521_PUB_LEN: usize = 133;
const P521_SIG_LEN: usize = 132;

const ROOT_MAGIC: &[u8; 8] = b"NCROOT01";
const SIG_MAGIC: &[u8; 4] = b"NCS1";
const SIGNATURE_LEN: usize = 8 + MLDSA_SIG_LEN + P521_SIG_LEN;

// .ncplu header offsets used here (see ncplu.rs / ncplu.py).
const H_MAGIC: &[u8; 8] = b"NCPLU\x1b\0\0";
const H_TOTAL_SIZE: usize = 16;
const H_SIGNATURE_OFF: usize = 72;
const H_SIGNATURE_LEN: usize = 76;
const H_DIGEST: usize = 88;

fn die(msg: &str) -> ! {
    eprintln!("ncplu-sign: {msg}");
    exit(1);
}

fn le32(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize
}
fn le64(b: &[u8], at: usize) -> usize {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) as usize
}

/// The digest both signatures cover: SHA-512 over the file up to the signature
/// block, with the header's digest field (bytes 88..152) taken as zero.
fn signed_digest(image: &[u8], sig_off: usize) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(&image[..88]);
    h.update([0u8; 64]);
    h.update(&image[152..sig_off]);
    h.finalize().into()
}

/// The root's fingerprint: the first 8 bytes of SHA-512 over both public
/// keys, as four groups of hex. The kernel computes the same.
fn fingerprint(mldsa_vk: &[u8], p521_vk: &[u8]) -> String {
    let mut h = Sha512::new();
    h.update(mldsa_vk);
    h.update(p521_vk);
    let d = h.finalize();
    format!(
        "{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

/// Reads a root_pubkeys.bin: magic, ML-DSA-87 key, P-521 SEC1 key.
fn read_root(path: &Path) -> (Vec<u8>, Vec<u8>) {
    let data = std::fs::read(path).unwrap_or_else(|e| die(&format!("{path:?}: {e}")));
    if data.len() != ROOT_MAGIC.len() + MLDSA_PUB_LEN + P521_PUB_LEN || &data[..8] != ROOT_MAGIC {
        die(&format!("{path:?} is not a root_pubkeys.bin"));
    }
    let mldsa = data[8..8 + MLDSA_PUB_LEN].to_vec();
    let p521 = data[8 + MLDSA_PUB_LEN..].to_vec();
    (mldsa, p521)
}

fn random(buf: &mut [u8]) {
    getrandom::getrandom(buf).unwrap_or_else(|e| die(&format!("no OS randomness: {e}")));
}

fn keygen(out: &Path) {
    std::fs::create_dir_all(out).unwrap_or_else(|e| die(&format!("cannot make {out:?}: {e}")));

    // ML-DSA-87: a random 32-byte seed is the private key; the signing key is
    // derived from it deterministically, so the seed is all that is stored.
    let mut seed = [0u8; 32];
    random(&mut seed);
    let seed_arr = hybrid_array::Array::try_from(&seed[..]).unwrap();
    let mldsa_sk = ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed_arr);
    let mldsa_vk = mldsa_sk.verifying_key().encode();
    assert_eq!(mldsa_vk.len(), MLDSA_PUB_LEN);

    // P-521: a random 66-byte scalar in [1, n). Almost every draw is valid
    // (the order is close to 2^521); the loop covers the rare miss.
    let p521_sk = loop {
        let mut scalar = [0u8; 66];
        random(&mut scalar);
        let arr = hybrid_array::Array::try_from(&scalar[..]).unwrap();
        if let Ok(sk) = p521::ecdsa::SigningKey::from_bytes(&arr) {
            break sk;
        }
    };
    let p521_scalar = p521_sk.to_bytes();
    let p521_point = p521_sk.verifying_key().to_sec1_point(false);
    let p521_vk = p521_point.as_bytes();
    assert_eq!(p521_vk.len(), P521_PUB_LEN);

    write(out.join("mldsa.seed"), &seed);
    write(out.join("p521.scalar"), &p521_scalar);

    let mut root = Vec::with_capacity(ROOT_MAGIC.len() + MLDSA_PUB_LEN + P521_PUB_LEN);
    root.extend_from_slice(ROOT_MAGIC);
    root.extend_from_slice(&mldsa_vk);
    root.extend_from_slice(p521_vk);
    write(out.join("root_pubkeys.bin"), &root);

    eprintln!("keys written to {out:?}");
    eprintln!("  private: mldsa.seed, p521.scalar  (keep these OUT of the repo, and back them up)");
    eprintln!("  public:  root_pubkeys.bin");
    eprintln!("  root fingerprint: {}", fingerprint(&mldsa_vk, p521_vk));
    eprintln!("build the kernel with:");
    eprintln!(
        "  NCPLU_ROOT_PUBKEYS={} cargo build --features simd,plugin-verify ...",
        out.join("root_pubkeys.bin").display()
    );
}

fn sign(plugin: &Path, keys: &Path) {
    let mut image = std::fs::read(plugin).unwrap_or_else(|e| die(&format!("{plugin:?}: {e}")));
    if image.len() < 160 || &image[..8] != H_MAGIC {
        die("not an .ncplu (bad magic)");
    }
    let total = le64(&image, H_TOTAL_SIZE);
    let sig_off = le32(&image, H_SIGNATURE_OFF);
    let sig_len = le32(&image, H_SIGNATURE_LEN);
    if sig_len != SIGNATURE_LEN || sig_off + SIGNATURE_LEN != total || total > image.len() {
        die("plugin has no reserved signature block (repack with tools/ncplu.py)");
    }

    let digest = signed_digest(&image, sig_off);

    // ML-DSA-87 over the digest.
    let seed = read_exact::<32>(&keys.join("mldsa.seed"));
    let seed_arr = hybrid_array::Array::try_from(&seed[..]).unwrap();
    let mldsa_sk = ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed_arr);
    let mldsa_sig = mldsa_sk.sign(&digest).encode();
    assert_eq!(mldsa_sig.len(), MLDSA_SIG_LEN);

    // P-521 ECDSA over the digest (hashed again with SHA-512 internally).
    let scalar = read_exact::<66>(&keys.join("p521.scalar"));
    let scalar_arr = hybrid_array::Array::try_from(&scalar[..]).unwrap();
    let p521_sk = p521::ecdsa::SigningKey::from_bytes(&scalar_arr)
        .unwrap_or_else(|e| die(&format!("bad p521 key: {e}")));
    let p521_sig: p521::ecdsa::Signature = p521_sk.sign(&digest);
    let p521_sig = p521_sig.to_bytes();
    assert_eq!(p521_sig.len(), P521_SIG_LEN);

    // Fill the reserved block: magic, reserved, ML-DSA sig, P-521 sig.
    let mut block = Vec::with_capacity(SIGNATURE_LEN);
    block.extend_from_slice(SIG_MAGIC);
    block.extend_from_slice(&[0u8; 4]);
    block.extend_from_slice(&mldsa_sig);
    block.extend_from_slice(&p521_sig);
    assert_eq!(block.len(), SIGNATURE_LEN);
    image[sig_off..sig_off + SIGNATURE_LEN].copy_from_slice(&block);

    std::fs::write(plugin, &image).unwrap_or_else(|e| die(&format!("write {plugin:?}: {e}")));
    eprintln!("signed {plugin:?}: ML-DSA-87 + P-521 over the digest");
}

/// The kernel's check, on the host. Returns whether the plugin is Official.
fn verify(plugin: &Path, root: &Path) -> bool {
    let image = std::fs::read(plugin).unwrap_or_else(|e| die(&format!("{plugin:?}: {e}")));
    if image.len() < 160 || &image[..8] != H_MAGIC {
        die("not an .ncplu (bad magic)");
    }
    let (mldsa_vk, p521_vk) = read_root(root);
    println!("root fingerprint : {}", fingerprint(&mldsa_vk, &p521_vk));

    let total = le64(&image, H_TOTAL_SIZE);
    let sig_off = le32(&image, H_SIGNATURE_OFF);
    let sig_len = le32(&image, H_SIGNATURE_LEN);
    if total != image.len() || sig_off.checked_add(sig_len) != Some(total) {
        println!("layout           : signature block does not end the file -> Community");
        return false;
    }

    let digest = signed_digest(&image, sig_off);
    if image[H_DIGEST..H_DIGEST + 64] != digest[..] {
        println!("digest           : MISMATCH -> the kernel refuses to load it (corrupt)");
        return false;
    }
    println!("digest           : ok (SHA-512 {:02x}{:02x}{:02x}{:02x}...)", digest[0], digest[1], digest[2], digest[3]);

    let block = &image[sig_off..];
    if sig_len != SIGNATURE_LEN || &block[..4] != SIG_MAGIC {
        println!("signature        : none -> Community");
        return false;
    }
    let mldsa_ok = (|| {
        let enc_vk = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(&mldsa_vk[..]).ok()?;
        let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&enc_vk);
        let enc_sig = ml_dsa::EncodedSignature::<MlDsa87>::try_from(&block[8..8 + MLDSA_SIG_LEN]).ok()?;
        let sig = ml_dsa::Signature::<MlDsa87>::decode(&enc_sig)?;
        Some(vk.verify(&digest, &sig).is_ok())
    })()
    .unwrap_or(false);
    let p521_ok = (|| {
        let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(&p521_vk).ok()?;
        let sig = p521::ecdsa::Signature::from_slice(&block[8 + MLDSA_SIG_LEN..SIGNATURE_LEN]).ok()?;
        Some(vk.verify(&digest, &sig).is_ok())
    })()
    .unwrap_or(false);
    let mark = |ok: bool| if ok { "valid" } else { "INVALID" };
    println!("ML-DSA-87        : {}", mark(mldsa_ok));
    println!("P-521            : {}", mark(p521_ok));
    let official = mldsa_ok && p521_ok;
    println!("tier             : {}", if official { "Official" } else { "Community" });
    official
}

fn write(path: PathBuf, data: &[u8]) {
    std::fs::write(&path, data).unwrap_or_else(|e| die(&format!("write {path:?}: {e}")));
}

fn read_exact<const N: usize>(path: &Path) -> [u8; N] {
    let data = std::fs::read(path).unwrap_or_else(|e| die(&format!("{path:?}: {e}")));
    if data.len() != N {
        die(&format!("{path:?}: expected {N} bytes, got {}", data.len()));
    }
    data.try_into().unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    };
    match args.get(1).map(String::as_str) {
        Some("keygen") => {
            let out = flag("--out").unwrap_or_else(|| die("keygen needs --out KEYDIR"));
            keygen(Path::new(&out));
        }
        Some("sign") => {
            let plugin = args.get(2).filter(|a| !a.starts_with('-'));
            let plugin = plugin.unwrap_or_else(|| die("sign needs PLUGIN.ncplu"));
            let keys = flag("--keys").unwrap_or_else(|| die("sign needs --keys KEYDIR"));
            sign(Path::new(plugin), Path::new(&keys));
        }
        Some("verify") => {
            let plugin = args.get(2).filter(|a| !a.starts_with('-'));
            let plugin = plugin.unwrap_or_else(|| die("verify needs PLUGIN.ncplu"));
            let root = flag("--root").unwrap_or_else(|| die("verify needs --root root_pubkeys.bin"));
            exit(if verify(Path::new(plugin), Path::new(&root)) { 0 } else { 1 });
        }
        Some("fingerprint") => {
            let root = args.get(2).unwrap_or_else(|| die("fingerprint needs root_pubkeys.bin"));
            let (mldsa_vk, p521_vk) = read_root(Path::new(root));
            println!("{}", fingerprint(&mldsa_vk, &p521_vk));
        }
        _ => {
            eprintln!("usage:");
            eprintln!("  ncplu-sign keygen --out KEYDIR");
            eprintln!("  ncplu-sign sign PLUGIN.ncplu --keys KEYDIR");
            eprintln!("  ncplu-sign verify PLUGIN.ncplu --root KEYDIR/root_pubkeys.bin");
            eprintln!("  ncplu-sign fingerprint KEYDIR/root_pubkeys.bin");
            exit(2);
        }
    }
}
