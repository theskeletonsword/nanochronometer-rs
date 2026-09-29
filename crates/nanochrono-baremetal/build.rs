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

    // Matched on what the target *is*, not what it is called: there are two
    // x86 bare-metal targets here — the stable `x86_64-unknown-none` and the
    // SIMD-capable `x86_64-nanochrono-none` — and a third would be added the
    // same way.
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    println!("cargo:rerun-if-changed=boot/boot32.S");
    println!("cargo:rerun-if-changed=boot/x86_64.ld");
    println!("cargo:rerun-if-changed=boot/aarch64.ld");

    println!("cargo:rerun-if-changed=boot/boot_i386.S");
    println!("cargo:rerun-if-changed=boot/i386.ld");

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
