// SPDX-License-Identifier: Apache-2.0
//! Names and paths: inside a package, and on the system it installs into.
//!
//! Everything that becomes part of a path on NCFS — a file inside a
//! package, a package id, a library or command name — is checked here
//! against one deliberately small alphabet: ASCII letters, digits and
//! `._+-`, no component starting with a dot, nothing a Windows or FAT
//! volume reserves. That keeps `..` and absolute paths out by
//! construction, and makes a package unpack identically on NCFS, exFAT,
//! FAT32 and the host tool on any operating system. Names the installer
//! owns (ids, libraries, commands) are lower case besides, so two of them
//! can never collide on a case-insensitive volume.

use crate::ncplu::Arch;
use core::cmp::Ordering;

/// The manifest's own path inside a package.
pub const META: &str = "ncpkg.meta";
/// The package's icon, at its root: what the desktop and the dock show.
pub const ICON: &str = "icon.png";
/// The longest path inside a package, in bytes.
pub const MAX_PATH: usize = 255;
/// The most components in a path inside a package.
pub const MAX_DEPTH: usize = 8;
/// The longest single component, package id or name.
pub const MAX_NAME: usize = 128;

/// Where a file inside a package belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    /// `ncpkg.meta`.
    Meta,
    /// `icon.png`, the package's icon.
    Icon,
    /// `ncapp/<arch>/…`: the app for one architecture.
    App(Arch),
    /// `lib/<arch>/…`: `.ncdyn` libraries.
    Lib(Arch),
    /// `plugins/<arch>/…`: `.ncplu` plugins.
    Plugin(Arch),
    /// `res/…`: everything else, shared by every architecture.
    Res,
}

/// Names Windows (and so FAT and exFAT as Windows reads them) reserves,
/// with or without an extension.
fn reserved(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or("");
    let upper = |s: &str, w: &str| s.len() == w.len() && s.eq_ignore_ascii_case(w);
    if ["CON", "PRN", "AUX", "NUL", "CLOCK$"].iter().any(|w| upper(stem, w)) {
        return true;
    }
    let b = stem.as_bytes();
    b.len() == 4
        && (b[..3].eq_ignore_ascii_case(b"COM") || b[..3].eq_ignore_ascii_case(b"LPT"))
        && (b'1'..=b'9').contains(&b[3])
}

/// One path component: `[A-Za-z0-9._+-]`, 1..=128 bytes, not starting with
/// a dot, not ending with one, not a reserved device name.
pub fn is_component(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= MAX_NAME
        && !c.starts_with('.')
        && !c.ends_with('.')
        && c.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        && !reserved(c)
}

/// An architecture directory: the canonical name only (`aarch64`, never
/// the `arm64` alias), so one architecture has one directory.
pub fn arch_dir(name: &str) -> Option<Arch> {
    Arch::from_name(name.as_bytes()).filter(|a| a.name() == name)
}

/// Checks a path inside a package and says where it belongs.
pub fn package_path(p: &str) -> Option<Area> {
    if p == META {
        return Some(Area::Meta);
    }
    if p == ICON {
        return Some(Area::Icon);
    }
    if p.is_empty() || p.len() > MAX_PATH {
        return None;
    }
    let mut parts = p.split('/');
    let mut n = 0;
    for c in p.split('/') {
        n += 1;
        if n > MAX_DEPTH || !is_component(c) {
            return None;
        }
    }
    let top = parts.next()?;
    let area = match top {
        "res" => {
            if n < 2 {
                return None;
            }
            return Some(Area::Res);
        }
        "ncapp" | "lib" | "plugins" => {
            let arch = arch_dir(parts.next()?)?;
            if n < 3 {
                return None;
            }
            match top {
                "ncapp" => Area::App(arch),
                "lib" => Area::Lib(arch),
                _ => Area::Plugin(arch),
            }
        }
        _ => return None,
    };
    Some(area)
}

/// Orders paths by their ASCII-lower-cased bytes: the order a package's
/// files are stored in, and the equality two paths may not share.
pub fn cmp_folded(a: &str, b: &str) -> Ordering {
    a.bytes().map(|c| c.to_ascii_lowercase()).cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
}

/// A package id: reverse-DNS, lower case — `org.videolan.vlc-codecs`.
/// Segments of `[a-z0-9]` joined by `-` inside a segment and `.` between
/// them; at least two segments; 3..=128 bytes.
pub fn is_package_id(id: &str) -> bool {
    if id.len() < 3 || id.len() > MAX_NAME || !id.contains('.') {
        return false;
    }
    id.split('.').all(|seg| {
        !seg.is_empty()
            && !seg.starts_with('-')
            && !seg.ends_with('-')
            && seg.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

/// A library, command or plugin-provided name: lower case
/// `[a-z0-9][a-z0-9._+-]*`, at most 64 bytes, a valid component.
pub fn is_name(name: &str) -> bool {
    name.len() <= 64
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        && is_component(name)
}

/// A file name the manifest points at (`main.ncapp`): one component ending
/// in `extension`, with something before it.
pub fn is_file_name(name: &str, extension: &str) -> bool {
    is_component(name)
        && name.len() > extension.len()
        && name.as_bytes()[name.len() - extension.len()..].eq_ignore_ascii_case(extension.as_bytes())
}

/// An absolute path on the installed system, as the installer builds them:
/// `/` then components that pass [`is_component`].
pub fn is_system_path(p: &str) -> bool {
    p.len() > 1 && p.len() <= 1024 && p.starts_with('/') && p[1..].split('/').all(is_component)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_paths() {
        assert_eq!(package_path("ncpkg.meta"), Some(Area::Meta));
        assert_eq!(package_path("icon.png"), Some(Area::Icon));
        assert_eq!(package_path("Icon.png"), None, "the icon has one spelling");
        assert_eq!(package_path("ncapp/x86_64/main.ncapp"), Some(Area::App(Arch::X86_64)));
        assert_eq!(package_path("lib/aarch64/libfoo.ncdyn"), Some(Area::Lib(Arch::Aarch64)));
        assert_eq!(package_path("plugins/riscv64/x.ncplu"), Some(Area::Plugin(Arch::Riscv64)));
        assert_eq!(package_path("res/icons/app_64.png"), Some(Area::Res));
        for bad in [
            "", "/res/a", "res/", "res", "res//a", "res/../a", "res/./a", "res/.hidden", "res/a.", "res/a b",
            "res/a\\b", "res/é", "ncapp/main.ncapp", "ncapp/arm64/main.ncapp", "ncapp/x86_64", "other/a", "res/CON",
            "res/com1.txt", "res/Lpt9", "lib/x86_64/a/b/c/d/e/f/g", "META",
        ] {
            assert_eq!(package_path(bad), None, "{bad:?}");
        }
        let long = std::format!("res/{}", "a".repeat(252));
        assert_eq!(package_path(&long), None);
        assert!(package_path("res/console.png").is_some(), "CON only as a whole stem");
    }

    #[test]
    fn names() {
        for good in ["org.example.app", "io.nanochronometer.snake", "a.b", "org.x-y.z9"] {
            assert!(is_package_id(good), "{good}");
        }
        for bad in ["org", "Org.example", "org..x", "org.-x", "org.x-", ".org.x", "org.x.", "org_x.y", "a"] {
            assert!(!is_package_id(bad), "{bad}");
        }
        assert!(is_name("libavcodec"));
        assert!(is_name("libc++.so-compat"));
        assert!(!is_name("LibFoo"));
        assert!(!is_name("-lib"));
        assert!(!is_name(".lib"));
        assert!(is_file_name("main.ncapp", ".ncapp"));
        assert!(!is_file_name(".ncapp", ".ncapp"));
        assert!(!is_file_name("main.ncdyn", ".ncapp"));
        assert!(is_system_path("/usr/lib/libfoo.ncdyn"));
        assert!(!is_system_path("/usr/../etc"));
        assert!(!is_system_path("usr/lib"));
        assert!(!is_system_path("/"));
        assert_eq!(cmp_folded("Res/B", "res/a"), Ordering::Greater);
        assert_eq!(cmp_folded("RES/a", "res/A"), Ordering::Equal);
    }
}
