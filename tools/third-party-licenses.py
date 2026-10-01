#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes the licence texts of every third-party crate a release links in.

The crates are those the shipped packages depend on for their code — not
build scripts, procedural macros or tests — on any of the release's targets:
nanochrono-cli, -gui, -ffi and -android for the desktop and Android triples,
and the bare-metal kernel and library. For each: its licence expression and
the licence and NOTICE files it carries, each distinct text written once.

    tools/third-party-licenses.py > THIRD-PARTY-LICENSES.txt

The Rust standard library, linked into every program, is under the same
Apache-2.0 licence as NanoChronometer (or MIT); the toolchains' runtimes have
notices of their own, which packaging/release/package.sh adds per platform.
"""

import hashlib
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTED_TARGETS = [
    "x86_64-unknown-linux-gnu", "i686-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "armv7-unknown-linux-gnueabihf", "riscv64gc-unknown-linux-gnu",
    "x86_64-pc-windows-gnullvm", "aarch64-pc-windows-gnullvm", "i686-pc-windows-gnullvm",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
    "aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android", "i686-linux-android",
]
HOSTED_ROOTS = {"nanochrono-cli", "nanochrono-gui", "nanochrono-ffi", "nanochrono-android"}
BAREMETAL = os.path.join(REPO, "crates", "nanochrono-baremetal", "Cargo.toml")
LICENCE_FILE = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicense)([-._ ].*)?$", re.I)

# The standard texts, for a crate that names its licence but carries no file
# of it; the copyright line is filled with the authors the crate declares.
TEMPLATES = {
    "MIT": """Copyright (c) {holders}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.""",
    "BSD-2-Clause": """Copyright (c) {holders}

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.""",
    "BSL-1.0": """Boost Software License - Version 1.0 - August 17th, 2003

Copyright (c) {holders}

Permission is hereby granted, free of charge, to any person or organization
obtaining a copy of the software and accompanying documentation covered by
this license (the "Software") to use, reproduce, display, distribute,
execute, and transmit the Software, and to prepare derivative works of the
Software, and to permit third-parties to whom the Software is furnished to
do so, all subject to the following:

The copyright notices in the Software and this entire statement, including
the above license grant, this restriction and the following disclaimer,
must be included in all copies of the Software, in whole or in part, and
all derivative works of the Software, unless such copies or derivative
works are solely in the form of machine-executable object code generated by
a source language processor.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.""",
}


def without_file(p):
    """What stands for the licence file of a crate that carries none."""
    alternatives = [a.strip() for a in re.split(r" OR |/", p.get("license") or "")]
    holders = ", ".join(re.sub(r"\s*<[^>]*>", "", a) for a in p.get("authors") or []) or f"the {p['name']} authors"
    if "Apache-2.0" in alternatives:
        return "Used under Apache-2.0, whose text is LICENSE beside this file."
    for lic in alternatives:
        if lic in TEMPLATES:
            return f"The {lic} licence, as the crate states it:\n\n" + TEMPLATES[lic].format(holders=holders)
    if "CC0-1.0" in alternatives:
        return "Dedicated to the public domain under CC0 1.0; no notice is required."
    sys.exit(f"{p['name']} {p['version']}: no licence file, and no text here for {p.get('license')!r}")


def metadata(manifest, platform=None):
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline",
           "--manifest-path", manifest]
    if platform:
        cmd += ["--filter-platform", platform]
    return json.loads(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)


def linked(meta, roots):
    """The packages reachable from `roots` through normal dependencies."""
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

    def proc_macro(p):
        return any("proc-macro" in t["kind"] for t in p["targets"])

    stack = [pid for pid, p in pkgs.items() if p["name"] in roots and pid in nodes]
    seen = set()
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes[pid]["deps"]:
            if not any(k["kind"] is None for k in dep["dep_kinds"]):
                continue  # build-dependencies and dev-dependencies only
            if not proc_macro(pkgs[dep["pkg"]]):
                stack.append(dep["pkg"])
    return [pkgs[pid] for pid in seen]


def ours(p):
    # The project's own crates; a vendored third-party copy (cpufeatures) is not.
    return p["source"] is None and p["name"].startswith("nanochrono")


def licence_files(p):
    root = os.path.dirname(p["manifest_path"])
    names = sorted(n for n in os.listdir(root)
                   if LICENCE_FILE.match(n) and os.path.isfile(os.path.join(root, n)))
    files = [os.path.join(root, n) for n in names]
    if p.get("license_file"):
        extra = os.path.normpath(os.path.join(root, p["license_file"]))
        if extra not in files and os.path.isfile(extra):
            files.append(extra)
    return files


def main():
    crates = {}
    for target in HOSTED_TARGETS:
        for p in linked(metadata(os.path.join(REPO, "Cargo.toml"), target), HOSTED_ROOTS):
            crates[(p["name"], p["version"])] = p
    for p in linked(metadata(BAREMETAL), {"nanochrono-baremetal"}):
        crates[(p["name"], p["version"])] = p
    crates = [crates[k] for k in sorted(crates) if not ours(crates[k])]

    version = metadata(os.path.join(REPO, "Cargo.toml"))["packages"]
    version = next(p["version"] for p in version if p["name"] == "nanochrono-ffi")
    out = sys.stdout
    out.write(f"Third-party licences — NanoChronometer {version}\n")
    out.write("=" * 72 + "\n\n")
    out.write(
        "The programs and libraries of this release contain code from the Rust\n"
        "crates below, each under its own licence. Every crate is listed with its\n"
        "licence expression, followed by the licence and NOTICE files it carries;\n"
        "a text already given for an earlier crate is referred to, not repeated.\n"
        "Where an expression offers a choice (\"MIT OR Apache-2.0\"), NanoChronometer\n"
        "uses the crate under any of the licences offered.\n\n"
        "The Rust standard library, linked into every program, is MIT OR\n"
        "Apache-2.0; the Apache-2.0 text is in LICENSE beside this file.\n\n")
    width = max(len(f"{p['name']} {p['version']}") for p in crates)
    for p in crates:
        out.write(f"  {p['name'] + ' ' + p['version']:<{width}}  {p.get('license') or 'see its licence file'}\n")
    out.write("\n")

    given = {}
    for p in crates:
        head = f"{p['name']} {p['version']}"
        out.write("-" * 72 + "\n")
        out.write(f"{head} — {p.get('license') or 'see below'}\n")
        if p.get("repository"):
            out.write(f"{p['repository']}\n")
        if p["source"] is None:
            out.write(f"(vendored in {os.path.relpath(os.path.dirname(p['manifest_path']), REPO)})\n")
        files = licence_files(p)
        if not files:
            out.write(f"\nThe crate carries no licence file. {without_file(p)}\n")
        for f in files:
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read().strip("\n")
            digest = hashlib.sha256("\n".join(l.rstrip() for l in text.splitlines()).encode()).hexdigest()
            name = os.path.basename(f)
            if digest in given:
                out.write(f"\n{name}: the same text as {given[digest]}, above.\n")
            else:
                given[digest] = f"{head}'s {name}"
                out.write(f"\n--- {name} ---\n\n{text}\n")
        out.write("\n")


if __name__ == "__main__":
    main()
