# `.ncpkg`: packages, the manifest, the database and `ncpkg`

The specification of NanoChronometer's package format and of the package
manager that installs it. The code is the executable form of this document:
`crates/nanochrono-core/src/ncpkg/` (format, manifest, signatures, database,
transactions — `no_std`, shared by the kernel and the host tools),
`tools/ncpkg/` (the host command line and its cryptography) and
`crates/nanochrono-baremetal/src/shell/ncpkg.rs` (the kernel's read-only
half). Where this text and the code disagree, the tests decide which is
wrong.

## 1. File types

| Extension | What | Module kind (`H_KIND`) |
|---|---|---|
| `.ncpkg` | A **package**: one compressed download for every architecture — a signed manifest, the app per architecture, libraries, plugins, assets. Types `gui`, `cli`, `lib`. | — (container, magic `NCPKG`) |
| `.ncapp` | An app for one architecture, in ring 3 (ring 0 only when signed for it): `gui` or `cli`. | `App` = 0 |
| `.ncdri` | A driver for hardware the kernel does not build in (Intel ME/HECI, Android MTP, NCHV). Essential drivers are built into the kernel. No licence header is required; none means proprietary, and nothing is marked "tainted". | `Driver` = 1 |
| `.ncdyn` | A shared library, loaded at run time: in `/usr/lib`, reference-counted, or private to one package. | `Library` = 2 |
| `.ncplu` | A plugin of one app — a codec pack for the players (FFmpeg, vgmstream) — loaded by its host app, never run alone. | `Plugin` = 3 |
| `.ncar` | A static library (`llvm-ar`), linked into an `.ncapp` when it is built; never installed. | — |
| NCFS | The system's own filesystem (planned), what packages install into. | — |

`.ncapp`, `.ncdri`, `.ncdyn` and `.ncplu` share one flat module format
([`nanochrono_core::ncplu`](../crates/nanochrono-core/src/ncplu.rs), packed by
`tools/ncplu.py`, signed by `tools/ncplu-sign`); the header says which kind a
module is and which architecture it is for. Its magic still reads `NCPLU`: the
format began as the plugin format, and modules packed before the split load
unchanged. Modules are written in anything that compiles to native code — C,
C++, Rust, assembly.

## 2. The container

```text
ncpkg.meta                     the manifest: JSON, signed (section 3)
ncapp/<arch>/main.ncapp        the app, one per architecture (gui, cli)
lib/<arch>/libfoo.ncdyn        shared libraries, per architecture
plugins/<arch>/vgm.ncplu       plugins for other apps, per architecture
res/…                          icons, data: stored once for every architecture
```

`<arch>` is one of `x86_64`, `i386`, `aarch64`, `arm32`, `riscv64`, `riscv32`,
`ppc64`, `ppc64le`, `ppc` — the canonical names only. A machine installs only
its own architecture's code; `res/` is shared. One download serves all nine.

### Binary layout (format version 2, little-endian)

Header, 64 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `NCPKG\x1b\0\0` |
| 8 | 2 | format version: 2 |
| 10 | 2 | header size: 64 |
| 12 | 4 | flags: 0 |
| 16 | 8 | total size |
| 24 | 4 | file count, the manifest included (1..=4096) |
| 28 | 4 | table offset: 64 |
| 32 | 4 | names offset: 64 + count × 40 |
| 36 | 4 | names length |
| 40 | 8 | data offset: names offset + names length |
| 48 | 8 | data length: total size − data offset |
| 56 | 8 | reserved: 0 |

Table entry, 40 bytes: name offset (4, in the names region), name length
(2, 1..=255), method (1: 0 stored, 1 raw DEFLATE), flags (1: 0), data offset
(8, in the data region), stored size (8), size once decoded (8), reserved
(8: 0).

### Rules a reader checks

* **One table.** No local headers to disagree with it, no second directory.
* **Every byte accounted for.** Header, table, names and data follow each
  other with no gaps; names and file bodies tile their regions exactly, in
  table order. There is nowhere to hide a payload. Bytes past *total size* (a
  sector-padded read) are not the package's.
* Entry 0 is `ncpkg.meta`, **stored uncompressed**, 1 byte to 1 MiB: a kernel
  without an allocator reads it in place.
* Every other path is `ncapp/<arch>/…`, `lib/<arch>/…`, `plugins/<arch>/…` or
  `res/…`; components are `[A-Za-z0-9._+-]`, never start or end with a dot,
  are never a name Windows/FAT reserves (`CON`, `COM1`…); at most 8 deep, 255
  bytes. Paths are in **strictly increasing case-folded order**: canonical,
  and no two equal on a case-insensitive volume (exFAT, FAT32).
* A stored file's sizes are equal; a DEFLATE file decodes to exactly its
  declared size (≤ 256 MiB each, ≤ 2 GiB together), ends in its last byte,
  and cannot claim more than DEFLATE's 1032:1 ratio. A decompression bomb
  stops at the size it promised.

The container carries no digest of its own: integrity and trust are the
manifest's, which names every file's SHA-512 and is what the signatures sign.

## 3. The manifest, `ncpkg.meta`

JSON (RFC 8259), exactly three members:

```json
{
  "format": "ncpkg/2",
  "signed": {
    "id": "org.example.player-plus",
    "name": "Player Plus",
    "version": "2.0.1",
    "type": "gui",
    "summary": "More formats for the player",
    "license": "MIT OR Apache-2.0",
    "creator": {"name": "Ada", "email": "ada@example.org"},
    "homepage": "https://example.org/player-plus",
    "arch": ["x86_64", "aarch64"],
    "abi": 1,
    "system": ">=4.0.0",
    "app": {
      "entry": "main.ncapp",
      "ring": 3,
      "capabilities": ["screen", "input", "timer"],
      "icon": "res/icon.png",
      "categories": ["Multimedia"]
    },
    "libraries": [
      {"name": "libavcodec", "version": "61.3.100", "file": "libavcodec.ncdyn"}
    ],
    "depends": [
      {"lib": "libavcodec", "version": ">=61.0.0, <62.0.0"}
    ],
    "plugins": [
      {"file": "vgm.ncplu", "host": "nc.player", "provides": ["audio/x-adx", "audio/x-brstm"]}
    ],
    "permissions": {
      "fs": [{"path": "$HOME/Music", "access": "r"}, {"path": "$APPDATA", "access": "rw"}],
      "devices": ["audio"],
      "network": "client"
    },
    "files": [
      {"path": "lib/aarch64/libavcodec.ncdyn", "size": 4198400, "sha512": "…"},
      {"path": "lib/x86_64/libavcodec.ncdyn", "size": 4211840, "sha512": "…"},
      {"path": "ncapp/aarch64/main.ncapp", "size": 51120, "sha512": "…"},
      {"path": "ncapp/x86_64/main.ncapp", "size": 52144, "sha512": "…"},
      {"path": "plugins/aarch64/vgm.ncplu", "size": 30912, "sha512": "…"},
      {"path": "plugins/x86_64/vgm.ncplu", "size": 31004, "sha512": "…"},
      {"path": "res/icon.png", "size": 3269, "sha512": "…"}
    ]
  },
  "signatures": [
    {"role": "creator-ring3", "alg": "mldsa87+p521", "key": "fbe6-0395-8a07-2150", "sig": "<base64>"},
    {"role": "self", "alg": "mldsa65+ed25519", "key": "2566-a587-ac5e-6d5a", "pubkey": "<base64>", "sig": "<base64>"}
  ]
}
```

### `signed` fields

| Field | Type | | Rule |
|---|---|---|---|
| `id` | string | required | reverse-DNS, lower case: `[a-z0-9]` segments, `-` inside, `.` between, ≥ 2 segments, 3..=128 bytes. A built-in app's id (`nc.stopwatch`, `nc.player`, …) is reserved. |
| `name` | string | required | 1..=128 characters, no control characters |
| `version` | string | required | SemVer 2.0.0 |
| `type` | string | required | `gui` \| `cli` \| `lib` |
| `summary` | string | | ≤ 256 characters |
| `description` | string | | ≤ 4096 characters; `\n` and `\t` allowed |
| `license` | string | | SPDX: identifiers joined by ` OR ` / ` AND `. **Absent means `Proprietary`** — all rights reserved, nothing more. |
| `creator` | object | | `name` (required), `email`, `url`. Absent: anonymous, flagged when it asks for ring 0. |
| `homepage` | string | | `http(s)://` URL |
| `arch` | array | required | the architectures the package carries code for; each must have its app, libraries and plugins in `files`, and no file may be for another |
| `abi` | integer | required | the kernel export-table ABI the modules were built against |
| `system` | string | | a version requirement on NanoChronometer |
| `app` | object | `gui`/`cli` | forbidden for `lib` |
| `libraries` | array | | `.ncdyn` the package carries (≤ 64); required for `lib` |
| `depends` | array | | `.ncdyn` the package needs (≤ 64) |
| `plugins` | array | | `.ncplu` the package registers with other apps (≤ 64) |
| `permissions` | object | | what it may reach on the system |
| `files` | array | required | every file of the container but the manifest, in container order |

`app`: `entry` (a file name ending `.ncapp`, the same under every
`ncapp/<arch>/`); `ring` 3 (default) or 0; `capabilities` — `screen`,
`input`, `log`, `timer`, `pmu`, `rng`, the module header's `CAP_*` groups,
and the installer refuses a module that asks for more than these;
`commands` (required non-empty for `cli`, ≤ 16 lower-case names, linked into
`/usr/bin`); `icon` (a `res/…` file); `categories` (≤ 8 short names).

`libraries[]`: `name` (lower case `[a-z0-9][a-z0-9._+-]*`, ≤ 64 — installed
as `/usr/lib/<name>.ncdyn`), `version` (SemVer), `file` (under
`lib/<arch>/`), `share` (default `true`; `false` keeps the copy private
whatever happens — a patched fork that must never replace the system's; not
allowed in a `lib` package).

`depends[]`: `lib` and `version`, a requirement in Cargo's syntax: `^1.2.3`
(also written `1.2.3`) is `>=1.2.3, <2.0.0` (`^0.2.3`: `<0.3.0`; `^0.0.3`:
`=0.0.3`); `~1.2.3` is `>=1.2.3, <1.3.0`; `=`, `>`, `>=`, `<`, `<=`;
`*`, `1.*`, `1.2.*`; comparators joined by `,` all hold. A pre-release
satisfies a requirement only if a comparator names a pre-release of the same
`major.minor.patch`. A library the package carries but does not list in
`depends` is required as `^<its version>`; a library it lists must accept the
copy it carries.

`plugins[]`: `file` (under `plugins/<arch>/`), `host` (the app it extends —
a built-in app, `nc.player`, or an installed package; never itself),
`provides` (MIME types or codec names the host routes by).

`permissions`: `fs` (≤ 32 grants: `path` is absolute or starts with
`$APPDATA`, `$HOME`, `$MEDIA` or `$TMP`; `access` is `r` or `rw`),
`devices` (`audio`, `camera`, `microphone`, `display`, `gpu`, `usb`,
`serial`, `bluetooth`, `nchv` — NCHV's `/dev/nchv`, what a QEMU port
accelerates with), `network` (`none`, the default; `client`; `server`).

`files[]`: `path`, `size`, `sha512` (128 lower-case hex digits).

### Strictness

* No unknown keys and no duplicate keys, at any level — not even spelled
  differently (`"id"` is `id`). Never "last one wins", which is how two
  parsers come to disagree about what a signed document says.
* Machine fields (ids, versions, paths, names, algorithms) are plain ASCII
  without escapes: one spelling each.
* `format` other than `ncpkg/2` is refused rather than half understood.

### Writing one: `ncpkg.toml`

Authors write the `signed` part in TOML beside the tree; `ncpkg build` adds
`files` (sizes and SHA-512s from the tree), `abi` (unless given) and `arch`
(unless given: the architecture directories present), checks the result with
the installer's own validator, and writes `signed` as **canonical JSON**
(sorted keys, compact) — the same sources make the same bytes.

```toml
id = "org.nanochronometer.snake"
name = "Snake"
version = "1.0.0"
type = "gui"
license = "Apache-2.0"

[creator]
name = "NanoChronometer"

[app]
entry = "main.ncapp"
capabilities = ["screen", "input", "log", "timer", "rng"]

# [[libraries]], [[depends]], [[plugins]], [permissions] as in the JSON.
```

## 4. Signatures

| Role | Badge | Means | Allows |
|---|---|---|---|
| `creator-ring3` | ✅ green check | made by the creator | ring 3 |
| `creator-ring0` | 🌳 tree root | made by the creator | ring 0 |
| `verify-ring3` | 🔵 blue check | a third party's, certified by the creator | ring 3 |
| `verify-ring0` | 🔵 blue check (ring 0) | a third party's, certified for ring 0 | ring 0 without the community switch |
| `self` | — | the author's own key | ring 3; ring 0 only with **Enable Ring0 Community Modules and Drivers** (off by default) |

The four roots are separate **ML-DSA-87 + ECDSA P-521** key pairs held by the
creator (an `ncplu-sign keygen` directory each). **A signature grants only its
own ring**: a ring-3 signature never allows ring 0, however trusted its key —
the music player certified for ring 3 cannot ship a kernel-mode update under
that certificate. One signature per role; at most 8.

**What is signed.** Every signature signs

```text
"NCPKG-SIG-2" 0x00  <role name>  0x00  SHA-512(<signed bytes>)
```

where *signed bytes* are the exact bytes of the `signed` value in
`ncpkg.meta`, never a re-serialisation. Since `signed` lists every file's
SHA-512, a signature covers every byte the package installs; since the role is
in the message, a signature cannot move between roles even under one key.

**Algorithms.** Roots: `mldsa87+p521`. Self-signatures: `mldsa87`, `mldsa65`,
`ed25519`, `p256`, `p384`, `p521`, `rsa-pss` (RSASSA-PSS, SHA-512, ≥ 2048
bits), or a pair joined by `+` — the post-quantum half first, both must
verify. `sig` is the halves' signatures concatenated (base64); a
self-signature carries `pubkey` (its public key(s), concatenated). `key` is
the signing key's fingerprint: the first 8 bytes of SHA-512 over its public
key(s), `xxxx-xxxx-xxxx-xxxx`.

| Algorithm | Public key | Signature |
|---|---|---|
| ML-DSA-87 / -65 | 2592 / 1952 bytes | 4627 / 3309 |
| Ed25519 | 32 | 64 |
| ECDSA P-256 / P-384 / P-521 (SHA-256/384/512) | SEC1 uncompressed 65 / 97 / 133 | r ‖ s 64 / 96 / 132 |
| RSA-PSS (verified, not made by `ncpkg`) | DER SubjectPublicKeyInfo | the modulus' length |

**Verdicts.** A signature that is present and **does not verify** refuses
the package: it was changed after signing. One by a key that is not this
system's root for its role counts for nothing (it is not evidence of
tampering). An owner may enrol self-signing keys by fingerprint (the
owner-key list, kept like shim's MOK list); an enrolled key shows as *owner
key* rather than *self-signed*.

**Packages and modules.** The package signatures decide what may be
**installed**, and in which ring. Each module inside is also signed on its
own (`tools/ncplu-sign`, its `NCS1` block) and the loader decides what
**runs** — and at which privilege — from that signature when it loads the
module. The two must agree; a manifest cannot raise a module's privilege.

## 5. Where things go

```text
/apps/<id>/<entry>                     the app, this machine's architecture
/apps/<id>/res/…                       its resources
/apps/<id>/lib/<name>.ncdyn            a private library (a version /usr/lib cannot satisfy)
/usr/lib/<name>.ncdyn                  a shared library, reference-counted
/usr/lib/ncplu/<host>/<id>/<file>      a plugin, registered with its host
/usr/bin/<command>                     a cli launcher: "#!ncapp /apps/<id>/<entry>"
/var/lib/ncpkg/db.json                 the database (section 7)
/var/lib/ncpkg/meta/<id>.meta          the installed manifest, for audits
/var/lib/ncpkg/journal.json            a transaction in progress (section 8)
/var/lib/ncpkg/tx/<tx>/{stage,backup}  its staged and set-aside files
/var/lib/ncpkg/lock                    held for the length of an operation
```

A library is looked up in the app's own `lib/` first, then `/usr/lib`. The
host app finds its plugins under `/usr/lib/ncplu/<host>/` (or in the
database).

## 6. Shared libraries: global, shared, upgraded, private

For each library a package uses — its `depends`, plus what it carries:

| `/usr/lib` has | The package | Then |
|---|---|---|
| nothing | carries a copy (`share`) | **new global** copy; `ref_count` 1 |
| nothing | carries a copy with `share: false` | **private** copy |
| nothing | carries none | refused: *missing library* |
| a version it accepts | carries an older or the same copy, or none | **share** it: `ref_count` + 1 |
| a version it accepts | carries a **newer** copy that every current user accepts | **upgrade** the global copy in place: `ref_count` + 1, every user now on the new version |
| a version it does not accept | carries a copy (`gui`, `cli`) | **private** copy in `/apps/<id>/lib`; the global copy and its count untouched |
| a version it does not accept | carries a copy (`lib`) | refused: *library conflict* — a `lib` package exists for the global copy |
| a version it does not accept | carries none | refused: *missing library* |

A global copy is never downgraded by an install or a removal. Removing a
package decrements the count of each global library it used and deletes from
`/usr/lib` **only** the libraries that reach zero; a library whose provider is
removed while others still need it stays, with `provided_by` empty. An
upgrade releases the old version's references and adds the new version's in
one transaction, and a library only the old version used goes.

## 7. The database, `/var/lib/ncpkg/db.json`

```json
{
  "format": "ncpkg-db/1",
  "generation": 7,
  "last_tx": "0000000000000007-9f3c2a1b5d4e6f70",
  "arch": "x86_64",
  "packages": {
    "org.example.player-plus": {
      "name": "Player Plus",
      "version": "2.0.1",
      "type": "gui",
      "arch": "x86_64",
      "license": "MIT OR Apache-2.0",
      "creator": "Ada",
      "installed_at": 1790989543,
      "badge": "creator",
      "roles": ["creator-ring3"],
      "self_key": null,
      "ring": 3,
      "capabilities": ["screen", "input", "timer"],
      "devices": ["audio"],
      "network": "client",
      "fs": [{"path": "$HOME/Music", "access": "r"}],
      "manifest_sha512": "…",
      "files": [
        {"path": "/apps/org.example.player-plus/main.ncapp", "size": 52144, "sha512": "…"},
        {"path": "/apps/org.example.player-plus/res/icon.png", "size": 3269, "sha512": "…"},
        {"path": "/usr/lib/ncplu/nc.player/org.example.player-plus/vgm.ncplu", "size": 31004, "sha512": "…"},
        {"path": "/var/lib/ncpkg/meta/org.example.player-plus.meta", "size": 2210, "sha512": "…"}
      ],
      "libraries": [
        {"name": "libavcodec", "requirement": ">=61.0.0, <62.0.0", "resolved": "global", "version": "61.3.100"}
      ],
      "plugins": [
        {"host": "nc.player", "path": "/usr/lib/ncplu/nc.player/org.example.player-plus/vgm.ncplu", "provides": ["audio/x-adx", "audio/x-brstm"]}
      ],
      "commands": []
    }
  },
  "libraries": {
    "libavcodec": {
      "version": "61.3.100",
      "path": "/usr/lib/libavcodec.ncdyn",
      "size": 4211840,
      "sha512": "…",
      "provided_by": "org.example.player-plus",
      "ref_count": 2,
      "required_by": ["org.example.player-plus", "org.example.recorder"]
    }
  }
}
```

`required_by` is the truth and `ref_count` its length, stored beside it so the
file reads at a glance. `files` lists every path a package owns exclusively —
removed with it; global libraries are the database's, not a package's.
`generation` counts committed transactions and `last_tx` names the last.

**Invariants**, checked every time the file is read; a database that breaks
one is never written over — the manager stops and says why (`ncpkg check`):

1. `format` is `ncpkg-db/1`; `arch` is an architecture; every package is for
   it. No unknown fields anywhere.
2. Every library: `ref_count == len(required_by) ≥ 1` (a library nobody
   requires is not installed); `required_by` sorted and unique; each package
   in it uses the library as `global`; `provided_by`, when set, is installed;
   `path` is `/usr/lib/<name>.ncdyn`.
3. Every package's `global` library exists, counts it, and is the version the
   package records; every `private` one is among the package's files; every
   plugin and command is among its files.
4. No path is owned by two packages, nor by a package and the shared
   libraries.

## 8. Transactions

```text
stage files ─► journal ─► db.json.new ─► steps ─► COMMIT ─► clean up
  (tx dir)     (atomic)     (durable)   (renames)  db.json.new → db.json
```

1. **Stage.** Every file to install is decoded, checked against its
   SHA-512, and written under `tx/<tx>/stage/`. Nothing outside the
   transaction's directory has changed.
2. **Journal.** `journal.json` (written to a temporary name and renamed)
   lists each step in order: `backup` (move an existing file into
   `tx/<tx>/backup/` — files replaced or removed are set aside, not
   deleted), `mkdir`, `place` (move a staged file into place).
3. **Next database.** `db.json.new`, durable, with `generation + 1` and
   `last_tx = <tx>`.
4. **Steps**, each one atomic rename or `mkdir`.
5. **Commit**: `db.json.new` replaces `db.json` atomically. From here on the
   database names this transaction.
6. **Clean up**: the backups and the stage go; directories left empty
   (`/apps/<id>`, `/usr/lib/ncplu/<host>/<id>`) go; the journal goes.

**Recovery**, at the start of every operation and by `ncpkg recover`: no
journal → remove leftovers (`journal.json.tmp`, `db.json.new`, `tx/`). A
journal → ask the database: `last_tx` is the journal's transaction → it
committed, finish the clean-up; it is not → undo the steps newest first (a
placed file back to the stage, a set-aside file back where it was, a created
directory away if empty), drop `db.json.new` and the transaction's
directory, then the journal. Each undo checks the step was done and is not
undone already, so a crash during recovery recovers the same way. After any
crash the system is **exactly** what it was, or **exactly** what the
completed operation leaves — the tests cut the power at every single
filesystem operation of an install, an upgrade and a removal (39 cut points
in the install test alone) and compare whole trees.

The filesystem promises this needs (`ncpkg::fs::Fs`): `create` durable when
it returns; `rename`/`replace` atomic; operations in order; `sync` a
barrier. NCFS gives them; the host's `StdFs` gives them with `fsync` on the
file and its directory, and refuses symbolic links anywhere under the root.

**The lock** (`/var/lib/ncpkg/lock`, created exclusively, holding who took
it) keeps two operations apart. A lock a crashed operation left is removed by
`ncpkg recover --force-unlock`, only when no other `ncpkg` runs.

## 9. `ncpkg`

```text
sudo ncpkg install <file.ncpkg> [--yes] [--reinstall] [--allow-downgrade] [--force]
sudo ncpkg remove <id> [--yes]
ncpkg list | info <id|file> | files <id> | check
sudo ncpkg recover [--force-unlock]
ncpkg build <dir> [-o file] [--store]          # host
ncpkg inspect <file> | verify <file>            # host
ncpkg keygen --alg <alg> --out <key>            # host: a self-signing key
ncpkg sign <file> --role <role> (--keys <dir> | --key <file>)
ncpkg message <file> --role <role> -o <msg>     # for an offline signer / HSM
ncpkg attach <file> --role <role> --alg <alg> --sig <sig> --pubkey <pub>
```

On a host every system command takes `--root <dir>` (or `NCPKG_ROOT`): an
NCFS volume mounted through FUSE, or the staging tree of an ISO's root image;
`--arch` (default: the root's database, else the host's), `--roots <dir>`
(`<role>.pub` root public keys), `--owner-keys <file>`,
`--require-signature`, `--community-ring0`.

### `install`, step by step

1. Take the lock; recover an interrupted transaction.
2. Parse the container (section 2) and the manifest (section 3); check them
   against each other: the same files, in order, with the same sizes.
3. Verify the signatures (section 4). One present and failing → refused.
   Signatures required and none valid → refused. Ring 0 without
   `creator-ring0`/`verify-ring0` and without the community switch →
   refused.
4. Check the package fits: this architecture is in `arch`; `abi` is the
   kernel's; `system` accepts the running version; `id` is not a built-in
   app's; an installed same version needs `--reinstall`, an older one
   `--allow-downgrade`.
5. Decode every file this machine installs and check its SHA-512; check each
   module's header: the right architecture, the right kind, no capability
   the manifest does not declare, no kernel-tier imports for a ring-3 app.
6. Plan against a copy of the database: release the old version (upgrade);
   resolve every library (section 6); place the app, resources, plugins
   (their host must be installed or built in), command launchers (not a shell
   built-in's name, not another package's), the manifest copy; refuse a file
   another package owns, or one nobody owns unless `--force`.
7. Show the plan; ask (`--yes` does not).
8. Execute it as one transaction (section 8). Release the lock.

### `remove`, step by step

1. Take the lock; recover.
2. The package must be installed, and no installed package's plugins may
   extend it (remove those first).
3. Plan: set aside every file it owns; for each global library it used,
   `ref_count − 1` and drop it from `required_by` — a library at zero is set
   aside too and leaves the database, the others stay; directories that end
   up empty are cleaned up after the commit.
4. Show, ask, execute as one transaction (section 8). Release the lock.

### Exit status

0 done; 1 error; 2 usage; 3 refused (signature, ring, architecture, ABI,
hash, module); 4 conflict (files, commands, libraries, dependents, versions);
5 locked; 6 `check` found problems.

## 10. Limits

| | |
|---|---|
| package | 1 GiB |
| files | 4096, the manifest included |
| one file, decoded | 256 MiB |
| all files, decoded | 2 GiB |
| manifest | 1 MiB, nesting 16 |
| path | 255 bytes, 8 components |
| libraries, depends, plugins | 64 each |
| commands | 16 |
| signatures | 8, one per role, ≤ 8192 bytes each |

## 11. Where it runs today

| | Host (`tools/ncpkg`) | Bare metal |
|---|---|---|
| build, sign, verify, inspect | yes | `ncpkg info`, `ncpkg verify` (SHA-512 of every file; signatures are judged at install) |
| install, remove, recover, check | yes, into `--root` | not yet: the session's root is read-only until NCFS is mounted, and the transaction engine needs a heap; it says so |
| list, files | yes | yes, from the `db.json` an installed root (an initrd built with `--root`) carries |
| run an app from a package | — | yes (x86-64): the app for this architecture, inflated, checked against the manifest's SHA-512, then loaded as any module |

The engine is `nanochrono-core` with its `alloc` feature (`std` implies it);
the kernel builds without it and reads packages with the allocation-free
half. When the kernel has NCFS and an allocator, `ncpkg install` on the
system itself is the same `Manager` over an NCFS-backed `Fs`.

## 12. The code

| File | What |
|---|---|
| `crates/nanochrono-core/src/ncpkg/mod.rs` | the container: parser, builder |
| `…/ncpkg/meta.rs` | the manifest: schema, validator, typed view, writer |
| `…/ncpkg/sig.rs` | roles, the signed message, trust and badges |
| `…/ncpkg/version.rs` | SemVer and requirements |
| `…/ncpkg/path.rs` | the path and name alphabet |
| `…/ncpkg/db.rs`, `journal.rs` | the database and the journal |
| `…/ncpkg/fs.rs` | the filesystem promises; memory (with power cuts) and host implementations |
| `…/ncpkg/manager.rs` | plan, install, remove, recover, check |
| `crates/nanochrono-core/src/json.rs`, `inflate.rs`, `sha512.rs` | strict JSON, DEFLATE, SHA-512 — `no_std`, no allocation |
| `tools/ncpkg/` | the host command line, the cryptography, `ncpkg.toml` |
| `crates/nanochrono-baremetal/src/shell/ncpkg.rs` | the kernel's `ncpkg` |
| `crates/nanochrono-baremetal/src/ncplu.rs` (`unpack`) | running an app straight from a package |

Tests: `cargo test -p nanochrono-core ncpkg` (format rules, fuzzed
containers, manifests and JSON, every database invariant, library
resolution, signatures and rings, the power cut at every step) and
`tools/ncpkg`'s `cargo test` (every signature algorithm and hybrid).
