// SPDX-License-Identifier: Apache-2.0
//! Embeds the application icon and version metadata into `nanochrono.exe`.
//!
//! The same resource the GUI carries (see `nanochrono-gui/build.rs`): a
//! console program still has an icon in Explorer, in the task bar while it
//! runs, and in a shortcut, and without a resource that icon is the generic
//! one. Only Windows targets are touched.

fn main() {
    println!("cargo:rerun-if-changed=../../assets/nanochrono.ico");
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("../../assets/nanochrono.ico");
        resource.set("FileDescription", "NanoChronometer command line");
        resource.set("ProductName", "NanoChronometer");
        resource.set("OriginalFilename", "nanochrono.exe");
        resource.set("LegalCopyright", "Licensed under the Apache License 2.0");
        // Not fatal, as in the GUI: a missing resource compiler costs a
        // picture, not the build.
        if let Err(error) = resource.compile() {
            println!("cargo:warning=could not embed the Windows icon: {error}");
        }
    }
}
