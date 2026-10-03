// SPDX-License-Identifier: Apache-2.0
//! `ncpkg build`: a source directory into a package.
//!
//! ```text
//! mypkg/
//!   ncpkg.toml                  the manifest's `signed` part, in TOML
//!   icon.png                    the package's icon (optional; square PNG,
//!                               16..=512 px, 256 recommended)
//!   ncapp/x86_64/main.ncapp     one module per architecture (tools/ncplu.py pack)
//!   ncapp/aarch64/main.ncapp
//!   lib/x86_64/libfoo.ncdyn     libraries, per architecture
//!   plugins/x86_64/x.ncplu      plugins, per architecture
//!   res/…                       anything else, shared
//! ```
//!
//! `ncpkg.toml` holds every field of the manifest's `signed` object except
//! `files`, which is made from the tree (each file's size and SHA-512), and
//! two that may be left out: `abi` (the kernel ABI this tool knows) and
//! `arch` (the architecture directories present). The result is checked
//! with the same validator the installer runs before it is written, and its
//! `signed` part is canonical JSON — the same sources make the same bytes.

use nanochrono_core::json::Json;
use nanochrono_core::ncpkg::meta::{self, Meta};
use nanochrono_core::ncpkg::{icon, path, Builder, Method};
use nanochrono_core::ncplu::{Arch, ABI_VERSION};
use std::path::Path;

pub struct Built {
    pub bytes: Vec<u8>,
    pub id: String,
    pub version: String,
    pub files: usize,
    pub compressed: usize,
}

fn toml_to_json(v: &toml::Value, at: &str) -> Result<Json, String> {
    Ok(match v {
        toml::Value::String(s) => Json::Str(s.clone()),
        toml::Value::Integer(i) => Json::Int(*i),
        toml::Value::Boolean(b) => Json::Bool(*b),
        toml::Value::Array(a) => Json::Arr(a.iter().enumerate().map(|(i, x)| toml_to_json(x, &format!("{at}[{i}]"))).collect::<Result<_, _>>()?),
        toml::Value::Table(t) => {
            let mut members = Vec::new();
            for (k, x) in t {
                let field = if at.is_empty() { k.clone() } else { format!("{at}.{k}") };
                members.push((k.clone(), toml_to_json(x, &field)?));
            }
            Json::Obj(members)
        }
        toml::Value::Float(_) => return Err(format!("{at}: the manifest has no fractional numbers")),
        toml::Value::Datetime(_) => return Err(format!("{at}: the manifest has no dates")),
    })
}

/// Every file under `dir`, as `rel/…` package paths. Symbolic links are
/// refused (a package holds files, not pointers out of its tree); dotfiles
/// (`.gitkeep`, `.DS_Store`) are left out.
fn walk(dir: &Path, rel: &str, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?.collect::<Result<_, _>>().map_err(|e| format!("{}: {e}", dir.display()))?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let p = e.path();
        let kind = std::fs::symlink_metadata(&p).map_err(|err| format!("{}: {err}", p.display()))?.file_type();
        let child = format!("{rel}/{name}");
        if kind.is_symlink() {
            return Err(format!("{}: a symbolic link; a package holds files", p.display()));
        } else if kind.is_dir() {
            walk(&p, &child, out)?;
        } else {
            out.push((child, std::fs::read(&p).map_err(|err| format!("{}: {err}", p.display()))?));
        }
    }
    Ok(())
}

pub fn build(src: &Path, compress: bool) -> Result<Built, String> {
    let toml_path = src.join("ncpkg.toml");
    let text = std::fs::read_to_string(&toml_path).map_err(|e| format!("{}: {e}", toml_path.display()))?;
    let table: toml::Table = text.parse().map_err(|e| format!("{}: {e}", toml_path.display()))?;
    let mut signed = toml_to_json(&toml::Value::Table(table), "")?;
    if signed.get("files").is_some() {
        return Err(String::from("ncpkg.toml: `files` is made from the tree; leave it out"));
    }

    let mut files = Vec::new();
    // The icon, checked the way the installer will check it: a package that
    // builds is one whose icon installs.
    let icon_path = src.join(path::ICON);
    if let Ok(meta) = std::fs::symlink_metadata(&icon_path) {
        if !meta.file_type().is_file() {
            return Err(format!("{}: not a regular file", icon_path.display()));
        }
        let data = std::fs::read(&icon_path).map_err(|e| format!("{}: {e}", icon_path.display()))?;
        icon::check_decodes(&data).map_err(|e| format!("{}: {e}", icon_path.display()))?;
        files.push((String::from(path::ICON), data));
    }
    for top in ["ncapp", "lib", "plugins", "res"] {
        walk(&src.join(top), top, &mut files)?;
    }
    files.sort_by(|a, b| path::cmp_folded(&a.0, &b.0));
    for w in files.windows(2) {
        if path::cmp_folded(&w[0].0, &w[1].0).is_eq() {
            return Err(format!("{} and {}: the same path but for case; a package installs on case-insensitive volumes too", w[0].0, w[1].0));
        }
    }
    for (p, _) in &files {
        if path::package_path(p).is_none() {
            return Err(format!(
                "{p}: not a package path (icon.png, ncapp/<arch>/…, lib/<arch>/…, plugins/<arch>/… or res/…; \
                 letters, digits and ._+- only; canonical architecture names)"
            ));
        }
    }

    if signed.get("arch").is_none() {
        let mut arches: Vec<Arch> = files
            .iter()
            .filter_map(|(p, _)| {
                let mut parts = p.split('/');
                let top = parts.next()?;
                if matches!(top, "ncapp" | "lib" | "plugins") {
                    path::arch_dir(parts.next()?)
                } else {
                    None
                }
            })
            .collect();
        arches.sort_by_key(|a| *a as u16);
        arches.dedup();
        signed.push("arch", Json::Arr(arches.iter().map(|a| Json::str(a.name())).collect()));
    }
    if signed.get("abi").is_none() {
        signed.push("abi", Json::uint(u64::from(ABI_VERSION)));
    }
    let hex = |d: &[u8]| {
        let mut out = [0u8; 128];
        nanochrono_core::sha512::to_hex(&nanochrono_core::sha512::digest(d), &mut out);
        String::from_utf8_lossy(&out).into_owned()
    };
    signed.push(
        "files",
        Json::Arr(files.iter().map(|(p, d)| Json::obj([("path", Json::str(p)), ("size", Json::uint(d.len() as u64)), ("sha512", Json::Str(hex(d)))])).collect()),
    );

    let manifest = meta::build::compose(&signed, &[]);
    let m = Meta::parse(manifest.as_bytes()).map_err(|e| format!("ncpkg.toml: {e}"))?;
    let (id, version) = (String::from(m.id()), String::from(m.version()));

    let mut b = Builder::new(manifest.into_bytes());
    let (mut n, mut compressed) = (0, 0);
    for (p, d) in files {
        n += 1;
        let size = d.len() as u64;
        if compress && d.len() >= 64 {
            let z = miniz_oxide::deflate::compress_to_vec(&d, 9);
            // Worth it only if it saves a twentieth or more: PNGs and other
            // compressed assets go in as they are.
            if z.len() + d.len() / 20 < d.len() {
                b.add_raw(&p, Method::Deflate, z, size).map_err(|e| format!("{p}: {e}"))?;
                compressed += 1;
                continue;
            }
        }
        b.add_stored(&p, d).map_err(|e| format!("{p}: {e}"))?;
    }
    let bytes = b.finish().map_err(|e| e.to_string())?;
    Ok(Built { bytes, id, version, files: n, compressed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanochrono_core::ncpkg::Package;
    use nanochrono_core::png;

    /// A square RGBA PNG of `w` × `h` (stored DEFLATE blocks).
    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut raw = Vec::new();
        for y in 0..h {
            raw.push(0);
            for x in 0..w {
                raw.extend_from_slice(&[x as u8, y as u8, 0x80, 0xFF]);
            }
        }
        let mut z = vec![0x78, 0x01];
        for (i, block) in raw.chunks(65535).enumerate() {
            let last = (i + 1) * 65535 >= raw.len();
            z.push(u8::from(last));
            z.extend_from_slice(&(block.len() as u16).to_le_bytes());
            z.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
            z.extend_from_slice(block);
        }
        let (mut a, mut b) = (1u32, 0u32);
        for &x in &raw {
            a = (a + u32::from(x)) % 65521;
            b = (b + a) % 65521;
        }
        z.extend_from_slice(&((b << 16) | a).to_be_bytes());
        let mut out = png::SIGNATURE.to_vec();
        let mut chunk = |kind: &[u8], data: &[u8]| {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(kind);
            out.extend_from_slice(data);
            out.extend_from_slice(&png::crc32(&[kind, data]).to_be_bytes());
        };
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&w.to_be_bytes());
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        chunk(b"IHDR", &ihdr);
        chunk(b"IDAT", &z);
        chunk(b"IEND", &[]);
        out
    }

    fn tree(icon: Option<Vec<u8>>) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ncpkg-build-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("lib/x86_64")).unwrap();
        std::fs::create_dir_all(dir.join("res")).unwrap();
        std::fs::write(
            dir.join("ncpkg.toml"),
            "id = \"org.example.icontest\"\nname = \"Icon test\"\nversion = \"1.0.0\"\ntype = \"lib\"\n\n\
             [[libraries]]\nname = \"libfoo\"\nversion = \"1.0.0\"\nfile = \"libfoo.ncdyn\"\n",
        )
        .unwrap();
        std::fs::write(dir.join("lib/x86_64/libfoo.ncdyn"), b"not checked when building").unwrap();
        std::fs::write(dir.join("res/notes.txt"), b"shared by every architecture").unwrap();
        if let Some(icon) = icon {
            std::fs::write(dir.join("icon.png"), icon).unwrap();
        }
        dir
    }

    #[test]
    fn the_icon_at_the_root_goes_in() {
        let dir = tree(Some(png(64, 64)));
        let built = build(&dir, true).unwrap();
        let pkg = Package::parse(&built.bytes).unwrap();
        assert!(pkg.find("icon.png").is_some(), "icon.png is in the container");
        let m = Meta::parse(pkg.meta()).unwrap();
        assert!(m.icon().is_some(), "and listed in the manifest");
        assert_eq!(built.files, 3);
        std::fs::remove_dir_all(&dir).unwrap();

        let dir = tree(None);
        let built = build(&dir, true).unwrap();
        let pkg = Package::parse(&built.bytes).unwrap();
        assert!(pkg.find("icon.png").is_none());
        assert_eq!(built.files, 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_bad_icon_is_refused_when_building() {
        for (bad, why) in [(png(64, 32), "not square"), (png(8, 8), "16 to 512"), (b"GIF89a".to_vec(), "PNG")] {
            let dir = tree(Some(bad));
            let err = build(&dir, false).err().expect("refused");
            assert!(err.contains("icon.png") && err.to_lowercase().contains(&why.to_lowercase()), "{err}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}
