// SPDX-License-Identifier: Apache-2.0
//! Gives the shared library the name a program records when it links it.
//!
//! macOS: ld64 records a dylib's output path as its install name unless told
//! otherwise, and rustc does not tell it — the shipped `libnanochrono.dylib`
//! would name a directory on the machine that built it, and every program
//! linked against it would look there at run time. `@rpath/` hands the choice
//! to the program's own run-path list instead (for the release layout,
//! `-Wl,-rpath,@executable_path/../lib`). Set at link time, so ld64 signs the
//! arm64 slice with the name it keeps.
//!
//! ELF (Linux, Android): rustc sets no `DT_SONAME` on a cdylib. Without one a
//! program linked against the library by path records that path as its
//! `DT_NEEDED`, and Android's linker wants a SONAME on any library another
//! links against. `libnanochrono.so` is the name either way.

fn main() {
    let vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if vendor == "apple" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libnanochrono.dylib");
    } else if matches!(os.as_str(), "linux" | "android") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libnanochrono.so");
    }
}
