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

Report it privately to the maintainer through one of these two channels:

| Channel | Where |
|---|---|
| **Signal** (preferred) | **`@theskeletonsword.46`** |
| **GitHub private advisory** | <https://github.com/theskeletonsword/nanochronometer-rs/security/advisories/new> (Repository → *Security* → *Report a vulnerability*) |

Signal is end-to-end encrypted, which is what a working exploit, a signing
key or a crash dump with memory contents deserve. The GitHub form is the
backup: if I am busy with other things and do not answer on Signal, the
report waits there in a private advisory only the maintainer sees, and it is
picked up as soon as I am back. Either channel is fine; you do not need to
send the same report to both.

### Signal or GitHub, and nothing else, for vulnerabilities

I talk to friends and other contributors on Telegram, Instagram and TikTok —
to send memes and have fun, not to receive vulnerability reports. Those are
personal spaces, and a report does not belong in them: Telegram's ordinary
chats are not end-to-end encrypted, and neither are Instagram's or TikTok's
messages. A vulnerability sent through any of them **will not be handled**;
you will be asked to send it again on Signal or through GitHub. Memes are still welcome there.

Do not put vulnerability details in a public issue, pull request or
discussion either. If you can use neither channel, open an issue that says only
"security contact requested", with no details, and we will work it out.

### What a report must include

A report is handled when it comes with:

1. **A reproducible proof of concept** — the exact steps, input or code that
   triggers the problem: a kernel command line, a crafted `.ncapp` /
   `.ncdri` / `.ncpkg` / NCFS image, a program, a script.
2. **Demonstrable impact** — what an attacker controls and what they
   actually gain, shown rather than asserted: code running in ring 0, an
   escape from ring 3, a signature check bypassed, another module's memory
   read, a crash with the dump that proves it.

Also tell me:

- the component and the version or commit (`git rev-parse HEAD`);
- the architecture and how it ran (hosted OS, QEMU machine and command line,
  real hardware);
- a suggested fix, if you have one (optional).

Attachments are welcome to complement the report: **`.zip`** (a PoC project,
images, logs), **`.pdf`**, **`.md`** and **images** (screenshots of the stop
screen, the serial log). Crash dumps can be read with `tools/nanodump.py`.

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
- denial of service (DoS or DDoS) against anyone's systems or networks;
- social engineering or phishing against the maintainer, the maintainer's
  friends, or the project's contributors — these are not findings, they are
  forbidden (see the rules below).

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
6. **No DoS or DDoS** against other people: their machines, networks or
   services. Denial-of-service bugs in NanoChronometer itself are in scope —
   demonstrate them on your own machine or VM.
7. **No social engineering** — no phishing, pretexting, impersonation or
   pressure — against the maintainer, the maintainer's personal friends, or
   the project's contributors.
8. **Report on Signal or through a GitHub private advisory only.** Not on
   Instagram, Telegram or TikTok (see above).

This safe harbor covers only the NanoChronometer project and what the
maintainer controls. It cannot bind third parties — the owners of hardware,
networks or services you test on, or the authors of dependencies — and it
does not override the law where you are. If you are unsure whether something
you plan to do is covered, ask first on Signal or through GitHub.
