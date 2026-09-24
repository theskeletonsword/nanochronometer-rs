// SPDX-License-Identifier: Apache-2.0
//! Embeds the application icon and version metadata into the Windows binary.
//!
//! Windows does not read an icon from the filesystem at run time. Explorer,
//! the task bar and Alt-Tab all take it from a resource compiled into the
//! `.exe`, so an application that only sets its *window* icon — which this one
//! does, through `winit` — still shows the generic executable icon everywhere
//! the window is not.
//!
//! Nothing here runs when building for anything but Windows, and nothing is
//! linked into the binary from this file: `winresource` is a build dependency
//! that shells out to the resource compiler and hands the result to the
//! linker.

fn main() {
    // The icon lives here and nowhere else; a change to it should relink.
    println!("cargo:rerun-if-changed=../../assets/nanochrono.ico");
    println!("cargo:rerun-if-changed=build.rs");

    // The target, not the host: `#[cfg(windows)]` in a build script is true
    // only when *building on* Windows, so a cross-compiled .exe silently
    // shipped with the generic icon. winresource finds `windres` itself, or
    // takes it from `WINDRES` (llvm-mingw's `llvm-windres` works).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_windows_resources();
    }
}

fn embed_windows_resources() {
    // The path is relative to this crate's manifest directory, which is where
    // the resource compiler is invoked from.
    let mut resource = winresource::WindowsResource::new();
    resource.set_icon("../../assets/nanochrono.ico");
    resource.set("FileDescription", "NanoChronometer");
    resource.set("ProductName", "NanoChronometer");
    resource.set("OriginalFilename", "nanochrono-gui.exe");
    resource.set("LegalCopyright", "Licensed under the Apache License 2.0");

    // A failure here is not fatal. A binary with no icon still runs, and
    // stopping the build because a resource compiler is missing would make
    // the whole project unbuildable on a Windows box without the SDK — for
    // the sake of a picture. It is reported as a warning so it is visible.
    if let Err(error) = resource.compile() {
        println!("cargo:warning=could not embed the Windows icon: {error}");
    }
}
