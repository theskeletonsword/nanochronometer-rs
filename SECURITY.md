# Security policy

NanoChronometer runs in places where a bug is a vulnerability: a bare-metal
kernel with a ring 0 / ring 3 boundary, loaders that decide what code reaches
ring 0, signature checks, file-system and package parsers, and optional kernel
drivers for Linux and Windows. If you find a way to break any of that, I want
to hear about it, and I will not treat you as an adversary for looking.

> **Not legal advice.** This policy was written by the maintainer, not by a
> lawyer, and nothing in it is legal advice — for the maintainer or for
> you. Before relying on it in a real legal dispute, have it reviewed by
> someone qualified in law in the jurisdictions involved.

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

The two channels above are a **closed list**. Every other service is
excluded, whether or not it is named here, whether or not it claims
end-to-end encryption, and whether or not I have an account on it. That
includes, without being limited to: Telegram, Instagram, TikTok, Discord,
WhatsApp, Snapchat, Threads, X/Twitter, Facebook/Messenger, Reddit, e-mail,
SMS and phone calls, and any service that appears after this was written.

Why: I talk to friends and other contributors on Telegram, Instagram and
TikTok — to send memes and have fun, not to receive vulnerability reports.
Those are personal spaces, and a report does not belong in them. Telegram's
ordinary chats are not end-to-end encrypted, and neither are Instagram's,
TikTok's, Discord's or Snapchat's messages. WhatsApp says it is end-to-end
encrypted, but I do not trust it with this either. A vulnerability sent
through any channel other than the two above **will not be handled** and
does not count as reported — not for the disclosure clock, not for credit,
not for the safe harbor. You will at most be asked to send it again on Signal
or through GitHub.

**If you keep talking about a vulnerability on one of those apps, I will
block you there until the patch is released.** I don't like blocking
people, and this is not about personal boundaries. It is about where the
vulnerability ends up: a message that is not end-to-end encrypted is stored
on the servers of whoever runs the app — Meta, Snap, Google, ByteDance,
Telegram — where their staff, a breach of their systems or a legal request
can reach it. An unpatched vulnerability in their backend is exactly what
attackers look for, and it would put everyone who uses NanoChronometer at
risk. Once the patch is out you are unblocked, and memes are welcome again.

**On Signal and GitHub, on the other hand, insist.** If I have not answered,
follow up, and keep following up until it is fixed: that is expected and
welcome, never a nuisance. Leaving a reported vulnerability unanswered
would fail the people who use this project; your persistence there helps
protect them from attackers.

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
   read, a crash with the dump that proves it. For a low or informational
   finding (see below), show what is wrong and where.

Also tell me:

- the component and the version or commit (`git rev-parse HEAD`);
- the architecture and how it ran (hosted OS, QEMU machine and command line,
  real hardware);
- a suggested fix, if you have one (optional).

Attachments are welcome to complement the report: **`.zip`** (a PoC project,
images, logs), **`.pdf`**, **`.md`** and **images** (screenshots of the stop
screen, the serial log). Crash dumps can be read with `tools/nanodump.py`.

## Severity: CVSS 4.0

Every report is scored with **CVSS v4.0** (FIRST's Common Vulnerability
Scoring System, version 4.0): the base metrics, plus threat and environmental
metrics where they apply. Include the vector you think fits
(`CVSS:4.0/AV:…/AC:…/AT:…/PR:…/UI:…/VC:…/VI:…/VA:…/SC:…/SI:…/SA:…`); the
final score is the maintainer's, and the reasoning is shared with you. The
score sets the order in which fixes are made, not whether a report is
accepted:

| CVSS 4.0 | Rating | |
|---|---|---|
| 9.0–10.0 | Critical | |
| 7.0–8.9 | High | |
| 4.0–6.9 | Medium | |
| 0.1–3.9 | Low | |
| 0.0 | None / informational | **accepted too** — see below |

**Low, informational and cosmetic findings are welcome.** A wrong message,
a misleading log line or error, a misdrawn screen, a document that promises
more than the code does, a hardening gap with no exploit yet: report them
the same way. They are fixed and credited like the rest.

## What happens next

- **Acknowledgement** within 7 days.
- **Assessment** — whether it reproduces and how severe it is — within 14
  days, and updates at least every 14 days after that until it is closed.
- **Fix**: the target is a fix within 90 days of the report; if it needs
  longer, you are told why and given a date. A GitHub Security Advisory is
  published with the fix, and a CVE requested where one applies.
- **Disclosure**: once the patch is released, the vulnerability is yours to
  publish — write-up, talk, video, posts, all of it. Not before (see
  *Embargo* below).
- **Credit** — see *Credit and contributor status* below.

## Embargo: nothing public before the patch

From the moment you find a vulnerability until the patch is released and
its advisory is published, **publishing it anywhere is strictly
forbidden**. That means no post, story, reel, video, stream, thread or
message about it on any social network — X/Twitter, Instagram, TikTok,
YouTube, Twitch, Discord servers, Telegram channels, Reddit, Mastodon,
Bluesky, Threads, LinkedIn, Facebook or anything else — and no blog, gist,
pastebin, forum, public issue or pull request, talk, CTF, mailing list or
paper either. Teasers count: "found a 0-day in NanoChronometer, details
soon" with a screenshot is a disclosure. Do not share it privately with
anyone outside the report either, and never sell or hand it to a broker.

After the patch: publish freely, and please link the advisory.

The one exception is a maintainer who has gone silent: if neither Signal
nor the GitHub advisory has had any answer at all for 90 days after the
report, the embargo lapses — tell me on both channels 14 days before you
publish.

**Breaking the embargo** has consequences, and they are real ones:

- **The safe harbor no longer applies to you.** Your research stops being
  authorized under this policy, and the promises in *Safe harbor* below —
  no legal action, no report to any authority, standing up for you if a
  third party complains — are withdrawn for that research. What the law
  says about how you got there is then between you and the law.
- **No credit and no contributor status** for that finding, and no entry in
  the advisory under your name.
- **You may be blocked** from the repository and the project's channels,
  and future reports or contributions from you may be refused.
- The fix is shipped as fast as possible and the advisory published at
  once, without waiting for you.
- Any other remedy the law gives the maintainer stays available. The
  Apache-2.0 licence lets you use, study and modify the code; it does not
  authorise breaking an embargo you agreed to by reporting, and it is not a
  shield for anything done to systems that are not yours.

## Scope

In scope — **everything that is NanoChronometer**: the code in this
repository and the release assets built from it. In particular:

- **inline assembly** — every `asm!` / `global_asm!` block and the boot
  files (`boot32.S`, `boot_i386.S`, the EFI loaders): trap entries, register
  save and restore, stack switches, the red zone;
- **memory-safety bugs — buffer overflows included.** The project is
  written in Rust, but nothing is 100% safe: `unsafe` blocks, FFI, inline
  assembly, raw pointers, DMA and MMIO, and logic errors that index past the
  end all count, as do out-of-bounds reads, use-after-free, double free,
  integer overflow leading to any of those, and uninitialised memory;
- the bare-metal kernel (`crates/nanochrono-baremetal`): the nccall boundary
  and its per-ISA trap entries, ring 3 isolation, the stack rules, the
  `.ncapp` / `.ncplu` / `.ncdri` loaders and the community-driver switch,
  signature verification (ML-DSA-87 + P-521), NCFS and ncinitramdisk, the
  EDID / DisplayID parser, the physical page allocator, the shell and the
  boot command line;
- **drivers**: the kernel's own bare-metal drivers, the `.ncdri` drivers in
  `sdk/drivers/`, and the optional kernel drivers in `kernel/linux/` and
  `kernel/windows/`;
- **the benchmarks, Crypto RAW included.** Crypto RAW (`--mode crypto-raw`,
  *CRYPTO RAW SPEED* on bare metal) is deliberately not a cipher — bare AES
  and SHA-256 rounds and carry-less multiplies, with no key schedule, mode or
  authentication, to measure the silicon's speed and nothing else. That it
  does not protect data is the design, not a finding. A memory-safety bug,
  a crash, wrong code reached at ring 0, or a way to make anything treat
  Crypto RAW's output as real cryptography *is* a finding;
- the shared core (`crates/nanochrono-core`): the `.ncpkg` format, manifest,
  database and transaction engine, and every other parser;
- the hosted libraries, CLI, GUI, C SDK and Android app;
- the host tools (`tools/`), the signing tools, and the build and packaging
  scripts — including anything that would let a published artifact differ
  from what its source and `SHA256SUMS` say;
- **NCFS**: the on-disk format, its parsers and the `tools/ncfs` FUSE mount
  — the recommended way to audit NCFS images from Linux without booting the
  kernel — and the `ncfs` filesystem type in the Linux module once it lands;
- cosmetic and informational issues (see *Severity* above).

Out of scope:

- **third-party dependencies** — the Cargo crates the project uses (for
  example the RustCrypto crates, `ring`, `rustls`), the C libraries, the
  toolchains and their runtimes, GRUB, QEMU, the firmware. Report those to
  their own maintainers. What *is* in scope is NanoChronometer's own use of
  them: calling one wrongly, or shipping a version with a published fix
  missing;
- findings that need an already-compromised ring 0, or physical access beyond
  what the threat model of the affected component assumes (say which you
  think applies — when in doubt, report it);
- denial of service (DoS or DDoS) against anyone's systems or networks;
- social engineering or phishing against the maintainer, the maintainer's
  friends, or the project's contributors — these are not findings, they are
  forbidden (see the rules below).

## Credit and contributor status

| Finding | What you get |
|---|---|
| **Low or above** (CVSS 4.0 from 0.1 up) | Credit in the advisory and the release notes, **and you are added as a contributor to NanoChronometer** |
| Informational or cosmetic (CVSS 0.0) | Thanks in the release notes; not contributor status |

Credit uses the name or handle you choose — or none, if you prefer to stay
anonymous. Both require following this policy, the embargo included.

## A vulnerability disclosure policy, not a bug bounty

This file is NanoChronometer's **vulnerability disclosure policy (VDP)**. It
is not a bug bounty: this is a project maintained by one person, there is
no money, and none is promised. What there is: a real answer to every
report, credit, contributor status, and the safe harbor below.

Reporting here is enough. **You do not need to notify any agency or CSIRT**
about a vulnerability in NanoChronometer — not Chile's ANCI (Agencia
Nacional de Ciberseguridad) or its CSIRT, not CISA, CERT/CC, ENISA, INCIBE,
the NCSC or any other — and please do not send them the details while the
embargo runs. The maintainer requests CVEs (through GitHub's CNA) and, if a
fix ever needs it, coordinates with a CSIRT. Duties the law places on you
yourself are unaffected: an operator of essential services whose own
systems suffer an incident still reports it as Chile's Ley 21.663, NIS2 or
its own law requires.

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
  departure from these rules does not void the safe harbor. Breaking the
  embargo is not an accident (see *Embargo* above).

### The legal frameworks this authorization is written for

- **The Budapest Convention** — the Council of Europe Convention on
  Cybercrime (ETS No. 185, 2001), to which Chile has been a party since
  2017. Its offences — illegal access, illegal interception, data and
  system interference (Articles 2–5) — are committed *without right*; this
  policy is the right-holder's authorization, so research that follows it
  is done *with right* as far as NanoChronometer is concerned. Writing and
  keeping a proof of concept for authorized testing is what Article 6(2)
  leaves outside the misuse-of-devices offence.
- **The United Nations Convention against Cybercrime** (adopted by the
  General Assembly in 2024), whose core offences are built the same way.
- **National laws** that implement or parallel them, among others: Chile's
  **Ley 21.459** on computer crime (which brought Chilean law in line with
  the Budapest Convention), the U.S. **Computer Fraud and Abuse Act**, the
  EU's **Directive 2013/40/EU** on attacks against information systems, the
  UK's **Computer Misuse Act 1990**, and anti-circumvention rules such as
  **DMCA §1201** and its security-research exemption.
- **Coordinated vulnerability disclosure** as described by **ISO/IEC 29147**
  and **ISO/IEC 30111**, the EU's **NIS2 Directive** (Article 12) and the
  **Cyber Resilience Act** — this policy follows that model.

### Personal data, and children's data above all

NanoChronometer is not built to collect personal data, and research on it
should never need any. If it ever touches some anyway:

- **GDPR** (Regulation (EU) 2016/679) and data-protection laws like it —
  Chile's **Ley 19.628** and **Ley 21.719** that reforms it, among others:
  stop as soon as you see personal data, access no more than the minimum
  that proves the issue, keep no copy, redact it from your report and
  attachments, delete what you have once the report is in, and say in the
  report that it happened.
- **COPPA** (the U.S. Children's Online Privacy Protection Act) and GDPR's
  rules on children — Article 8, often called **GDPR-K** — and laws like
  them: if the data may belong to a child, stop
  **immediately** — do not open, copy, keep or forward any of it — and tell
  me at once. That is never a detail to demonstrate impact with.

The safe harbor does not cover collecting, keeping or sharing personal
data; it cannot, since that data is not the maintainer's to authorize.

### If you are a minor

Reports from minors are welcome, and the safe harbor applies to you exactly
as it does to anyone else. The age that matters is the one your country
sets for consenting to the processing of your own data online: between 13
and 16 in the EU, depending on the member state (GDPR-K, Article 8), 13
under COPPA in the U.S.; check your own country's law. If you are below it:

- **You are never asked your age, your real name or proof of anything.**
  Report under a handle; a Signal username or a GitHub account is all the
  contact this needs, and it is all that is kept.
- **Credit and contributor status use a handle only**, or nothing at all —
  never a real name, a photo, a school or a location — unless a parent or
  guardian agrees to more.
- **Your contact data is deleted when the case closes**, if you or a parent
  or guardian ask; the advisory keeps only the handle you chose.
- **Involve a parent or guardian**, or a teacher you trust, before you test
  — above all before anything that touches the law. The safe harbor is
  written for adults' legal systems, and a grown-up on your side is worth
  more than any policy.
- If a parent or guardian contacts the maintainer about your report, they
  are answered, and what you sent is handled as they and you agree.

The rules are the same for everyone: the embargo, the closed list of
channels and the limits on data apply to minors too.

Why it works this way: since nobody is asked their age and nothing but a
handle and a contact is kept, there is next to no data about minors to
protect in the first place. Collecting less is the protection — data
minimisation, as GDPR Article 5(1)(c) puts it.

The rules:

1. Test on systems you own or are explicitly allowed to test: your own
   machines, virtual machines, QEMU guests, emulators.
2. Do not access, modify, keep or share data that is not yours. If you come
   across someone else's data, stop, and tell me in your report.
3. Do not degrade services or systems that belong to others, and do not
   leave persistence or backdoors anywhere.
4. Report promptly, and **keep the embargo**: nothing public — on social
   networks or anywhere else — until the patch is released (see *Embargo*
   above).
5. Do not use a vulnerability for anything beyond what you need to
   demonstrate it.
6. **No DoS or DDoS** against other people: their machines, networks or
   services. Denial-of-service bugs in NanoChronometer itself are in scope —
   demonstrate them on your own machine or VM.
7. **No social engineering** — no phishing, pretexting, impersonation or
   pressure — against the maintainer, the maintainer's personal friends, or
   the project's contributors.
8. **Report on Signal or through a GitHub private advisory only** — no other
   service, named or not (see the closed list above).

This safe harbor covers only the NanoChronometer project and what the
maintainer controls. It cannot bind third parties — the owners of hardware,
networks or services you test on, or the authors of dependencies — and it
does not override the law where you are. If you are unsure whether something
you plan to do is covered, ask first on Signal or through GitHub.

**This is not legal advice.** The safe harbor and everything else in this
policy were written by the maintainer, not by a lawyer. Before relying on
them in a real legal dispute — yours or the maintainer's — have them
reviewed by someone qualified in law in the jurisdictions involved.
