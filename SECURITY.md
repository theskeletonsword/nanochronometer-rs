# Security policy

NanoChronometer runs in places where a bug is a vulnerability: a bare-metal
kernel with a ring 0 / ring 3 boundary, loaders that decide what code reaches
ring 0, signature checks, file-system and package parsers, and optional kernel
drivers for Linux and Windows. If you find a way to break any of that, I want
to hear about it, and I will not treat you as an adversary for looking.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes |
| 4.x (latest release) | Yes |
| 3.x | Fixes only if the issue also affects 4.x |
| 2.x and earlier (C codebase) | No |

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a
security problem.**

Report it privately to the maintainer through GitHub:

> **<https://github.com/theskeletonsword/nanochronometer-rs/security/advisories/new>**

(Repository → *Security* → *Report a vulnerability*.) Only the maintainer sees
the report. If that form is unavailable to you, open an issue that says only
"security contact requested", with no details, and you will be given a private
channel.

Any vulnerability is welcome, however small or theoretical it looks. A useful
report includes:

- the component and version or commit (`git rev-parse HEAD`);
- the architecture and how it was run (hosted OS, QEMU machine and command
  line, real hardware);
- what an attacker controls and what they gain (code in ring 0, escaping
  ring 3, bypassing a signature, reading another module's memory, a crash);
- steps or a proof of concept to reproduce it — a kernel command line, a
  crafted `.ncapp` / `.ncdri` / `.ncpkg` / NCFS image, a serial log or a
  crash dump (`tools/nanodump.py` reads them);
- a suggested fix, if you have one (optional).

## What happens next

- **Acknowledgement** within 7 days.
- **Assessment** — whether it reproduces and how severe it is — within 14
  days, and updates at least every 14 days after that until it is closed.
- **Fix and disclosure**: coordinated with you. The target is a fix within 90
  days of the report; if it needs longer, we agree on a date together. A
  GitHub Security Advisory is published with the fix, and a CVE requested
  where one applies.
- **Credit** in the advisory and the release notes, under the name or handle
  you choose — or none, if you prefer to stay anonymous.

This is a project maintained by one person, not a company: there is no bug
bounty, but every report gets a real answer.

## Scope

In scope — anything in this repository and the release assets built from it:

- the bare-metal kernel (`crates/nanochrono-baremetal`): the nccall boundary
  and its per-ISA trap entries, ring 3 isolation, the red-zone and stack
  rules, the `.ncapp` / `.ncplu` / `.ncdri` loaders and the community-driver
  switch, signature verification (ML-DSA-87 + P-521), NCFS and
  ncinitramdisk, the EDID / DisplayID parser, the physical page allocator,
  the shell and the boot command line;
- the shared core (`crates/nanochrono-core`): the `.ncpkg` format, manifest,
  database and transaction engine, and every other parser;
- the hosted libraries, CLI, GUI, C SDK and Android app;
- the optional kernel drivers in `kernel/linux/` and `kernel/windows/`;
- the host tools (`tools/`), the signing tools, and the build and packaging
  scripts — including anything that would let a published artifact differ
  from what its source and `SHA256SUMS` say.

Out of scope:

- vulnerabilities in third-party dependencies or toolchains that are not
  caused by how NanoChronometer uses them — report those upstream (a note
  here is still welcome if we ship an affected version);
- findings that need an already-compromised ring 0, or physical access beyond
  what the threat model of the affected component assumes (say which you
  think applies — when in doubt, report it);
- denial of service by flooding someone else's infrastructure, social
  engineering, and phishing.

## Safe harbor

Security research done in good faith under this policy is **authorized**.
For research that follows the rules below:

- I will not pursue or support legal action against you, and I will not
  report you to any authority — including under computer-misuse laws (such
  as the U.S. Computer Fraud and Abuse Act or Chile's Ley 21.459 on
  computer crime) or anti-circumvention laws (such as the DMCA's §1201) —
  for testing NanoChronometer's own code and artifacts.
- I waive, for that research, any restriction in this project's terms that
  would otherwise get in the way of it; the Apache-2.0 licence already lets
  you run, study, modify and reverse-engineer the code.
- If someone else brings an action against you over research that followed
  this policy, I will make it known that your work was authorized.
- You are not expected to be perfect: an accidental, promptly reported
  departure from these rules does not void the safe harbor.

The rules:

1. Test on systems you own or are explicitly allowed to test: your own
   machines, virtual machines, QEMU guests, emulators.
2. Do not access, modify, keep or share data that is not yours. If you come
   across someone else's data, stop, and tell me in your report.
3. Do not degrade services or systems that belong to others, and do not
   leave persistence or backdoors anywhere.
4. Report promptly, and give a reasonable chance to fix the issue before
   any public disclosure — by default the 90-day window above, or the date
   we agree on.
5. Do not use a vulnerability for anything beyond what you need to
   demonstrate it.

This safe harbor covers only the NanoChronometer project and what the
maintainer controls. It cannot bind third parties — the owners of hardware,
networks or services you test on, or the authors of dependencies — and it
does not override the law where you are. If you are unsure whether something
you plan to do is covered, ask first through the private channel above.
