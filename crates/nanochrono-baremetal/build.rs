// SPDX-License-Identifier: Apache-2.0
//! Assembles `boot32.S` and hands it to the linker.
//!
//! The file cannot be `global_asm!`: a multiboot header has to land in the
//! first 32 KiB of the image, which needs a named section the linker script
//! places, and the 32-bit entry code runs before Rust's ABI assumptions hold.
//! So it is assembled separately — by the same LLVM that builds the crate,
//! through `cc`'s bundled driver, so no external assembler is required.

fn main() {
    // Every architecture, before the x86-only assembly below returns early.
    logo_assets();
    desktop_assets();
    root_keys();

    // Matched on what the target *is*, not what it is called: there are two
    // x86 bare-metal targets here — the stable `x86_64-unknown-none` and the
    // SIMD-capable `x86_64-nanochrono-none` — and a third would be added the
    // same way.
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    println!("cargo:rerun-if-changed=boot/boot32.S");
    println!("cargo:rerun-if-changed=boot/boot_i386.S");
    // Every linker script, the ones .cargo/config.toml passes too: Cargo
    // does not see those, and an edited script must relink the kernel.
    for script in ["x86_64", "i386", "aarch64", "arm32", "powerpc", "powerpc64", "riscv32", "riscv64"] {
        println!("cargo:rerun-if-changed=boot/{script}.ld");
    }

    // `x86_any`: code that is the same on 32- and 64-bit x86 (port I/O,
    // CPUID, the 8042, PCI, ACPI) says so once instead of listing both.
    println!("cargo::rustc-check-cfg=cfg(x86_any)");
    if arch == "x86_64" || arch == "x86" {
        println!("cargo:rustc-cfg=x86_any");
    }

    // Only for a freestanding x86 target. A host build must not link a second
    // `_start`, and the other architectures enter with the ABI already valid,
    // so their stubs are `global_asm!` in the crate. x86_64 needs long mode
    // built for it; i386 is already in the flat protected mode it runs in.
    let (stub, clang_target, script) = match (arch.as_str(), os.as_str()) {
        ("x86_64", "none") => ("boot/boot32.S", "x86_64-unknown-none", "boot/x86_64.ld"),
        ("x86", "none") => ("boot/boot_i386.S", "i686-unknown-none-elf", "boot/i386.ld"),
        _ => return,
    };

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let obj = out.join("boot.o");

    // `cc` is not used to compile C — there is none in this project. It is
    // used as a portable way to reach the host's assembler with the right
    // target flags.
    let status = std::process::Command::new(cc_binary())
        .args(["-c", "-o"])
        .arg(&obj)
        .arg(format!("--target={clang_target}"))
        .arg("-nostdlib")
        .arg(stub)
        .status()
        .unwrap_or_else(|_| panic!("failed to run the assembler for {stub}"));
    assert!(status.success(), "assembling {stub} failed");

    // `-bins` rather than plain `rustc-link-arg`: the boot object is 32-bit
    // non-PIC code and the linker script places a kernel image. Applying
    // either to the static archive or the shared object is wrong, and the
    // shared object refuses to link at all with them.
    println!("cargo:rustc-link-arg-bins={}", obj.display());
    println!("cargo:rustc-link-arg-bins=-T{script}");
}

/// The assembler to drive. `clang` understands `--target` for any
/// architecture it was built with, which is what makes cross-assembly work
/// without a second toolchain.
fn cc_binary() -> String {
    std::env::var("CC").unwrap_or_else(|_| "clang".to_string())
}

/// The heights the kernel embeds the logo at: four for the header (the
/// largest that fits is drawn), one for the boot screen.
const LOGO_HEIGHTS: [u32; 5] = [28, 36, 44, 52, 128];

/// Decodes `assets/nanochronometer_logo_dark.png` — the logo PNG itself, the
/// variant made for dark backgrounds — and writes it into `OUT_DIR` as raw
/// RGBA at each of `LOGO_HEIGHTS`, for `src/logo.rs` to `include_bytes!`.
///
/// Done here, on the host, so the kernel carries no PNG decoder: an inflate
/// implementation in ring 0 is a lot of code and attack surface for a
/// picture. Each file is an 8-byte header (width, height, little-endian
/// `u32`) followed by straight, non-premultiplied RGBA.
fn logo_assets() {
    let source = std::path::Path::new("../../assets/nanochronometer_logo_dark.png");
    println!("cargo:rerun-if-changed={}", source.display());
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let file = std::fs::File::open(source).expect("assets/nanochronometer_logo_dark.png");
    let mut decoder = png::Decoder::new(std::io::BufReader::new(file));
    // Palette and low bit depths expanded, 16-bit stripped: always 8-bit.
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().expect("decoding the logo PNG");
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).expect("decoding the logo PNG");
    let (sw, sh) = (info.width as usize, info.height as usize);
    let rgba: Vec<[f64; 4]> = match info.color_type {
        png::ColorType::Rgba => buf.chunks_exact(4).map(|p| [p[0], p[1], p[2], p[3]].map(f64::from)).collect(),
        png::ColorType::Rgb => buf.chunks_exact(3).map(|p| [p[0] as f64, p[1] as f64, p[2] as f64, 255.0]).collect(),
        png::ColorType::GrayscaleAlpha => buf.chunks_exact(2).map(|p| [p[0], p[0], p[0], p[1]].map(f64::from)).collect(),
        png::ColorType::Grayscale => buf.iter().map(|&g| [g as f64, g as f64, g as f64, 255.0]).collect(),
        png::ColorType::Indexed => unreachable!("EXPAND turns palettes into RGB(A)"),
    };

    for h in LOGO_HEIGHTS {
        let w = ((sw as f64) * h as f64 / sh as f64).round() as u32;
        let mut bytes = Vec::with_capacity(8 + (w * h * 4) as usize);
        bytes.extend_from_slice(&w.to_le_bytes());
        bytes.extend_from_slice(&h.to_le_bytes());
        // Area average over each destination pixel's footprint, weighted by
        // alpha so transparent pixels do not darken the edges.
        let (fx, fy) = (sw as f64 / w as f64, sh as f64 / h as f64);
        for y in 0..h as usize {
            let (y0, y1) = (y as f64 * fy, (y + 1) as f64 * fy);
            for x in 0..w as usize {
                let (x0, x1) = (x as f64 * fx, (x + 1) as f64 * fx);
                let mut acc = [0.0f64; 4];
                let mut area = 0.0;
                for sy in y0.floor() as usize..(y1.ceil() as usize).min(sh) {
                    let wy = (y1.min(sy as f64 + 1.0) - y0.max(sy as f64)).max(0.0);
                    for sx in x0.floor() as usize..(x1.ceil() as usize).min(sw) {
                        let wx = (x1.min(sx as f64 + 1.0) - x0.max(sx as f64)).max(0.0);
                        let wgt = wx * wy;
                        let p = rgba[sy * sw + sx];
                        let a = p[3] / 255.0;
                        acc[0] += p[0] * a * wgt;
                        acc[1] += p[1] * a * wgt;
                        acc[2] += p[2] * a * wgt;
                        acc[3] += p[3] * wgt;
                        area += wgt;
                    }
                }
                let alpha = acc[3] / area.max(1e-9);
                let cover = (acc[3] / 255.0).max(1e-9);
                let px = [acc[0] / cover, acc[1] / cover, acc[2] / cover, alpha];
                bytes.extend(px.map(|c| c.round().clamp(0.0, 255.0) as u8));
            }
        }
        std::fs::write(out.join(format!("logo_{h}.rgba")), bytes).expect("writing the logo");
    }
}

/// The largest wallpaper the kernel embeds: the largest mode its back buffer
/// covers (`framebuffer::SHADOW_W`/`SHADOW_H`). A larger picture is reduced
/// here, on the host, keeping its shape.
const WALLPAPER_MAX: (u32, u32) = (1920, 1200);

/// The desktop's pictures, embedded so the kernel needs no filesystem to
/// show them: every wallpaper and every icon.
///
/// * Wallpapers: each PNG or JPEG in `assets/wallpapers/` (generated by
///   `tools/gen-wallpapers.py`, or any picture dropped there), in file-name
///   order, and in the directory `NC_WALLPAPERS` names when it is set — a
///   way to embed pictures of one's own without adding them to the tree.
///   Each is decoded here and stored as QOI (`nanochrono_core::qoi`): the
///   kernel streams it straight into the screen-sized copy it scales to, so
///   it carries no PNG or JPEG decoder. A name comes from the file name, minus
///   any leading `NN-` and the extension.
/// * Icons: `assets/icons/apps/<name>_<size>.rgba` (`tools/gen-app-icons.py`)
///   and NanoChronometer's own stopwatch, `assets/icons/baremetal/
///   nanochronometer_icon_<size>.rgba` (`tools/gen-icons.py`), as raw RGBA in
///   the logo's format, so they are blitted from the image as they are.
///
/// Writes `desktop_assets.rs` into `OUT_DIR`, which `src/assets.rs`
/// includes.
fn desktop_assets() {
    use std::fmt::Write as _;
    use std::path::{Path, PathBuf};

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let mut rs = String::from("// Generated by build.rs (desktop_assets). Do not edit.\n\n");

    // --- wallpapers --------------------------------------------------------
    let pictures = |dir: &Path| -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
                matches!(ext.as_str(), "png" | "jpg" | "jpeg")
            })
            .collect();
        files.sort();
        files
    };
    let tree = Path::new("../../assets/wallpapers");
    println!("cargo:rerun-if-changed={}", tree.display());
    println!("cargo:rerun-if-env-changed=NC_WALLPAPERS");
    let mut files = pictures(tree);
    if let Some(dir) = std::env::var_os("NC_WALLPAPERS") {
        let dir = PathBuf::from(dir);
        println!("cargo:rerun-if-changed={}", dir.display());
        let extra = pictures(&dir);
        if extra.is_empty() {
            println!("cargo:warning=NC_WALLPAPERS={}: no PNG or JPEG there", dir.display());
        }
        files.extend(extra);
    }
    rs += "pub static WALLPAPERS: &[Wallpaper] = &[\n";
    let mut thumbs = String::from("pub static THUMBNAILS: &[Image] = &[\n");
    for (i, file) in files.iter().enumerate() {
        println!("cargo:rerun-if-changed={}", file.display());
        let (w, h, rgb) = match decode_picture(file) {
            Ok(p) => p,
            Err(why) => {
                println!("cargo:warning=wallpaper {}: {why}; not embedded", file.display());
                continue;
            }
        };
        let (w, h, rgb) = reduce_to_fit(w, h, rgb, WALLPAPER_MAX);
        // A 16:9 thumbnail for Settings, cropped to cover like the desktop
        // shows it: drawn from the image as it is, not decoded at run time.
        let (tw, th) = (176u32, 99u32);
        let (cw, ch) = if w as u64 * th as u64 > h as u64 * tw as u64 {
            ((h as u64 * tw as u64 / th as u64) as u32, h)
        } else {
            (w, (w as u64 * th as u64 / tw as u64) as u32)
        };
        let (cx, cy) = ((w - cw) / 2, (h - ch) / 2);
        let mut cropped = Vec::with_capacity((cw * ch * 3) as usize);
        for y in cy..cy + ch {
            let row = (y * w + cx) as usize * 3;
            cropped.extend_from_slice(&rgb[row..row + cw as usize * 3]);
        }
        let (sw, sh, small) = reduce_to_fit(cw, ch, cropped, (tw, th));
        let mut thumb = Vec::with_capacity(8 + (sw * sh * 4) as usize);
        thumb.extend_from_slice(&sw.to_le_bytes());
        thumb.extend_from_slice(&sh.to_le_bytes());
        for p in small.chunks_exact(3) {
            thumb.extend_from_slice(&[p[0], p[1], p[2], 255]);
        }
        std::fs::write(out.join(format!("thumb_{i}.rgba")), thumb).expect("writing a thumbnail");
        let _ = writeln!(thumbs, "    Image::parse(include_bytes!(concat!(env!(\"OUT_DIR\"), \"/thumb_{i}.rgba\"))),");
        let qoi = nanochrono_core::qoi::encode(&rgb, w, h, 3);
        std::fs::write(out.join(format!("wallpaper_{i}.qoi")), qoi).expect("writing a wallpaper");
        let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("wallpaper");
        // "01-aurora" -> "Aurora"; "My photo" stays as it is.
        let bare = stem.trim_start_matches(|c: char| c.is_ascii_digit());
        let bare = bare.strip_prefix(['-', '_', ' ']).unwrap_or(bare);
        let bare = if bare.is_empty() { stem } else { bare };
        let mut name: String = bare.replace(['-', '_'], " ");
        if let Some(first) = name.get(..1) {
            name = first.to_uppercase() + &name[1..];
        }
        let _ = writeln!(
            rs,
            "    Wallpaper {{ name: {name:?}, width: {w}, height: {h}, \
             qoi: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/wallpaper_{i}.qoi\")) }},"
        );
    }
    rs += "];\n\n";
    rs += &thumbs;
    rs += "];\n\n";

    // --- icons -------------------------------------------------------------
    // name -> [(size, file)], every size found.
    let mut sets: std::collections::BTreeMap<String, Vec<(u32, PathBuf)>> = Default::default();
    let apps = Path::new("../../assets/icons/apps");
    println!("cargo:rerun-if-changed={}", apps.display());
    if let Ok(entries) = std::fs::read_dir(apps) {
        for path in entries.filter_map(|e| e.ok().map(|e| e.path())) {
            if path.extension().and_then(|e| e.to_str()) != Some("rgba") {
                continue;
            }
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
            if let Some((name, size)) = stem.rsplit_once('_') {
                if let Ok(size) = size.parse::<u32>() {
                    sets.entry(name.to_string()).or_default().push((size, path.clone()));
                }
            }
        }
    }
    for size in [16u32, 32, 48, 64, 128] {
        let path = PathBuf::from(format!("../../assets/icons/baremetal/nanochronometer_icon_{size}.rgba"));
        if path.exists() {
            sets.entry("nanochronometer".into()).or_default().push((size, path));
        }
    }
    rs += "pub static ICONS: &[IconSet] = &[\n";
    for (name, mut sizes) in sets {
        sizes.sort();
        let _ = write!(rs, "    IconSet {{ name: {name:?}, sizes: &[");
        for (size, path) in sizes {
            println!("cargo:rerun-if-changed={}", path.display());
            let bytes = std::fs::read(&path).expect("reading an icon");
            let fits = bytes.len() >= 8 && {
                let w = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
                let h = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
                bytes.len() == 8 + w * h * 4
            };
            if !fits {
                println!("cargo:warning=icon {}: not width, height and RGBA; skipped", path.display());
                continue;
            }
            let copy = format!("icon_{name}_{size}.rgba");
            std::fs::write(out.join(&copy), bytes).expect("writing an icon");
            let _ = write!(rs, "Image::parse(include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{copy}\"))), ");
        }
        rs += "] },\n";
    }
    rs += "];\n";
    std::fs::write(out.join("desktop_assets.rs"), rs).expect("writing desktop_assets.rs");
}

/// A PNG or JPEG as 8-bit RGB, whatever it was stored as. Alpha is laid over
/// black: a wallpaper is opaque.
fn decode_picture(path: &std::path::Path) -> Result<(u32, u32, Vec<u8>), String> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if ext == "png" {
        let mut decoder = png::Decoder::new(std::io::BufReader::new(file));
        decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
        let mut reader = decoder.read_info().map_err(|e| e.to_string())?;
        let mut buf = vec![0; reader.output_buffer_size()];
        let info = reader.next_frame(&mut buf).map_err(|e| e.to_string())?;
        buf.truncate(info.buffer_size());
        let over_black = |c: u8, a: u8| ((c as u32 * a as u32 + 127) / 255) as u8;
        let rgb: Vec<u8> = match info.color_type {
            png::ColorType::Rgb => buf,
            png::ColorType::Rgba => buf.chunks_exact(4).flat_map(|p| [0, 1, 2].map(|i| over_black(p[i], p[3]))).collect(),
            png::ColorType::Grayscale => buf.iter().flat_map(|&g| [g, g, g]).collect(),
            png::ColorType::GrayscaleAlpha => buf.chunks_exact(2).flat_map(|p| [over_black(p[0], p[1]); 3]).collect(),
            png::ColorType::Indexed => return Err("indexed colour survived EXPAND".into()),
        };
        Ok((info.width, info.height, rgb))
    } else {
        let mut decoder = jpeg_decoder::Decoder::new(std::io::BufReader::new(file));
        let pixels = decoder.decode().map_err(|e| e.to_string())?;
        let info = decoder.info().ok_or("no JPEG header")?;
        let rgb: Vec<u8> = match info.pixel_format {
            jpeg_decoder::PixelFormat::RGB24 => pixels,
            jpeg_decoder::PixelFormat::L8 => pixels.iter().flat_map(|&g| [g, g, g]).collect(),
            jpeg_decoder::PixelFormat::L16 => pixels.chunks_exact(2).flat_map(|p| [p[0]; 3]).collect(),
            jpeg_decoder::PixelFormat::CMYK32 => pixels
                .chunks_exact(4)
                .flat_map(|p| {
                    // Adobe's inverted CMYK, the form JPEG decoders hand back.
                    let k = p[3] as u32;
                    [0, 1, 2].map(|i| ((p[i] as u32 * k + 127) / 255) as u8)
                })
                .collect(),
        };
        Ok((info.width as u32, info.height as u32, rgb))
    }
}

/// `rgb` reduced by area averaging until it fits inside `max`, keeping its
/// aspect ratio; returned unchanged when it already fits.
fn reduce_to_fit(w: u32, h: u32, rgb: Vec<u8>, max: (u32, u32)) -> (u32, u32, Vec<u8>) {
    let scale = (max.0 as f64 / w as f64).min(max.1 as f64 / h as f64);
    if scale >= 1.0 {
        return (w, h, rgb);
    }
    let (dw, dh) = (((w as f64 * scale).round() as u32).max(1), ((h as f64 * scale).round() as u32).max(1));
    let (fx, fy) = (w as f64 / dw as f64, h as f64 / dh as f64);
    let mut out = Vec::with_capacity((dw * dh * 3) as usize);
    for y in 0..dh as usize {
        let (y0, y1) = (y as f64 * fy, (y + 1) as f64 * fy);
        for x in 0..dw as usize {
            let (x0, x1) = (x as f64 * fx, (x + 1) as f64 * fx);
            let mut acc = [0.0f64; 3];
            let mut area = 0.0;
            for sy in y0.floor() as usize..(y1.ceil() as usize).min(h as usize) {
                let wy = (y1.min(sy as f64 + 1.0) - y0.max(sy as f64)).max(0.0);
                for sx in x0.floor() as usize..(x1.ceil() as usize).min(w as usize) {
                    let wx = (x1.min(sx as f64 + 1.0) - x0.max(sx as f64)).max(0.0);
                    let i = (sy * w as usize + sx) * 3;
                    for c in 0..3 {
                        acc[c] += rgb[i + c] as f64 * wx * wy;
                    }
                    area += wx * wy;
                }
            }
            out.extend(acc.map(|v| (v / area.max(1e-9)).round().clamp(0.0, 255.0) as u8));
        }
    }
    (dw, dh, out)
}

/// Embeds the plugin-signature root **public** keys. Two roots, both read
/// from files outside the repository: the creator's (✅), named by
/// `NCPLU_ROOT_CREATOR`, and the machine owner's local tree root (🌳), named
/// by `NCPLU_ROOT_TREE`. `NCPLU_ROOT_PUBKEYS` is accepted as an older name
/// for the creator root. Private keys never appear here or in the tree; the
/// signer holds them (see tools/ncplu-sign).
///
/// Each file is `b"NCROOT01"` then the 2592-byte ML-DSA-87 verifying key then
/// the 133-byte P-521 SEC1 public key. A root that is absent or malformed is
/// simply not embedded; a plugin it would have vouched for then loads without
/// that badge — a safe default, never a hardcoded key.
fn root_keys() {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    const MAGIC: &[u8; 8] = b"NCROOT01";
    const MLDSA: usize = 2592;
    const P521: usize = 133;

    // Embeds one named root under `prefix`, returning whether it was present.
    let embed = |vars: &[&str], prefix: &str| -> bool {
        for var in vars {
            println!("cargo:rerun-if-env-changed={var}");
        }
        let path = vars.iter().find_map(std::env::var_os);
        let Some(path) = path else { return false };
        println!("cargo:rerun-if-changed={}", path.to_string_lossy());
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                println!("cargo:warning={prefix} root {path:?}: {e}; not embedded");
                return false;
            }
        };
        if data.len() != MAGIC.len() + MLDSA + P521 || &data[..8] != MAGIC {
            println!("cargo:warning={prefix} root {path:?} is not a root-key file; not embedded");
            return false;
        }
        std::fs::write(out.join(format!("{prefix}_mldsa.bin")), &data[8..8 + MLDSA]).unwrap();
        std::fs::write(out.join(format!("{prefix}_p521.bin")), &data[8 + MLDSA..]).unwrap();
        true
    };

    let creator = embed(&["NCPLU_ROOT_CREATOR", "NCPLU_ROOT_PUBKEYS"], "creator");
    let tree = embed(&["NCPLU_ROOT_TREE"], "tree");

    let one = |present: bool, prefix: &str, name: &str, n: usize| {
        if present {
            format!(
                "pub const {name}: Option<&[u8; {n}]> = Some(include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{prefix}.bin\")));\n"
            )
        } else {
            format!("pub const {name}: Option<&[u8; {n}]> = None;\n")
        }
    };
    let mut body = String::new();
    body += &one(creator, "creator_mldsa", "CREATOR_MLDSA", MLDSA);
    body += &one(creator, "creator_p521", "CREATOR_P521", P521);
    body += &one(tree, "tree_mldsa", "TREE_MLDSA", MLDSA);
    body += &one(tree, "tree_p521", "TREE_P521", P521);
    std::fs::write(out.join("ncplu_root_keys.rs"), body).unwrap();
}

