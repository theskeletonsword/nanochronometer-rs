# Third-party notices

NanoChronometer is Apache-2.0 ([`LICENSE`](../LICENSE)), and [`NOTICE`](../NOTICE)
names what it contains from others. Its binaries also contain third-party
code — Rust crates, and the runtimes the toolchains link in — so every release
download carries the licence texts of all of it:

| File in a download | What it holds |
|---|---|
| `LICENSE`, `NOTICE` | NanoChronometer's licence and attributions |
| `THIRD-PARTY-LICENSES.txt` | every crate linked into the programs and libraries: name, version, licence expression, and the licence and NOTICE files the crate ships, each distinct text given once |
| `licenses/MinGW-w64-runtime.txt` | Windows: the mingw-w64 runtime's notices, which its licence asks for in any binary distribution (the runtime is linked statically) |
| `licenses/Android-NDK-NOTICE.txt` | Android: the NDK's notices; the static CLI contains bionic, its C library |

The Android app carries `LICENSE`, `NOTICE` and `THIRD-PARTY-LICENSES.txt` in
its own assets, under `assets/licenses/`.

[`packaging/release/package.sh`](../packaging/release/package.sh) puts these
into every asset. The crate list comes from
[`tools/third-party-licenses.py`](../tools/third-party-licenses.py), which
reads `cargo metadata` for every release target and follows the shipped
packages' normal dependencies — build scripts, procedural macros and test
dependencies run on the build machine and are not shipped, so they are left
out:

```sh
tools/third-party-licenses.py > THIRD-PARTY-LICENSES.txt
```

When a crate carries no licence file of its own, the list says how it is used:
under Apache-2.0 where its licence offers that (the text is `LICENSE`),
otherwise with the standard text of its licence and the authors the crate
declares.
