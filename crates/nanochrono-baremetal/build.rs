// SPDX-License-Identifier: Apache-2.0
//! Assembles `boot32.S` and hands it to the linker.
//!
//! The file cannot be `global_asm!`: a multiboot header has to land in the
//! first 32 KiB of the image, which needs a named section the linker script
//! places, and the 32-bit entry code runs before Rust's ABI assumptions hold.
//! So it is assembled separately — by the same LLVM that builds the crate,
//! through `cc`'s bundled driver, so no external assembler is required.

fn main() {
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
