# NCFS: the NanoChronometer filesystem

The specification of NCFS, NanoChronometer's own filesystem. The code is
the executable form of this document — `crates/nanochrono-core/src/ncfs/`
(`format.rs` table for table, `read.rs`, `write.rs`, `check.rs`,
`seal.rs`, `pkgfs.rs`) — and where the two disagree the tests decide which
is wrong.

## 1. What it is for

A filesystem for a system that can lose power at any instant and that
must be able to prove what it booted:

| Property | How |
|---|---|
| A power cut never damages it | Copy on write: nothing the last commit can see is overwritten. Two superblock slots, alternating; a torn superblock fails its checksum and the other — the previous commit — mounts. No journal to replay, no `fsck` after a crash. |
| Bit rot, lost and misdirected writes are found | Every pointer carries the **BLAKE3** of the block it points at; every node records its own address, generation and volume id. A block that is not what was written is refused when it is read. |
| One signature covers everything | The pointers make the volume a Merkle tree: the superblock determines every byte. A **sealed** volume has its superblock signed (ML-DSA-87 + P-521 for the roots) — the `ncinitramdisk`. |
| Snapshots | In constant time: a second pointer to a subvolume's root. Writable clones, rollback (a snapshot made the default). |
| Deduplication | Identical 128 KiB windows stored once, found by the BLAKE3 every extent carries anyway, confirmed byte for byte. |
| Transparent compression | Per window: LZ4 for what the system writes, ZSTD for images built on a host; kept only when it saves a block. All-zero windows are holes. |
| Nanosecond timestamps | `i64` nanoseconds since the epoch, as befits a NanoChronometer. |

NCFS borrows its shape from Btrfs (a B-tree of keyed items, copy-on-write
shadowing, subvolumes) and ZFS (checksums in the parent, a self-validating
tree, superblock rotation). No code of either is used: Btrfs is GPL, and
the design is small enough to write from its description.

## 2. Layout

Everything is in **4096-byte blocks**, numbered from 0; all integers are
little-endian, read and written by shifting so big-endian machines read the
same volume.

| Blocks | What |
|---|---|
| 0 | reserved (zeros): room for a boot record |
| 1, 2 | superblock slots A and B: generation *g* is written to slot *g* mod 2 |
| 3–18 | the signature area (64 KiB): empty unless the volume is sealed (§9) |
| 19 → | allocated: tree nodes and file extents |

The smallest volume is 256 blocks (1 MiB). The ESP of an installed system
is FAT32 (UEFI reads nothing else); NCFS is the root.

## 3. The superblock

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `NCFS\x1b\x00\x01\x00` |
| 8 | 4 | format version: 1 |
| 12 | 4 | block size: 4096 |
| 16 | 8 | incompatible features (bit 0 LZ4 extents, bit 1 ZSTD extents) |
| 24 | 8 | read-only-compatible features (none yet) |
| 32 | 8 | compatible features (none yet) |
| 40 | 8 | flags (bit 0 `SEED`: a sealed, read-only image) |
| 48 | 16 | volume id (fsid), random at `mkfs` |
| 64 | 64 | label, UTF-8, NUL-padded |
| 128 | 8 | generation: commits so far |
| 136 | 8 | total blocks |
| 144 | 8 | created (ns since the epoch) |
| 152 | 8 | committed (ns) |
| 160 | 49 | the tree of subvolumes: pointer (§4) |
| 209 | 7 | zero |
| 216 | 8 | next subvolume id |
| 224 | 8 | default subvolume id |
| 232 | 8 | blocks in use (informational) |
| 240 | 2 | signature blocks in use: 0, or 16 when sealed |
| 242 | … | zero |
| 4064 | 32 | BLAKE3 of bytes 0..4064 |

A reader takes, of the two slots, the one whose checksum holds, whose
version and features it knows, whose size fits the device, with the higher
generation. An unknown incompatible feature refuses the volume; an unknown
read-only-compatible one mounts it read-only.

## 4. Trees

A **pointer** is 49 bytes: block (8), generation (8), BLAKE3 of the whole
4096-byte block (32), level (1). Reading a node checks, before anything in
it is believed: the BLAKE3; the header's magic `NCND`, block number,
generation and level against the pointer; the volume id; and every
structural rule below.

**Node header** (64 bytes): magic (4), level (1, 0 = leaf), zero (1), item
count (2), the node's own block (8), generation (8), owner (8: 0 for the
tree of subvolumes, else the subvolume that wrote it), volume id (16), zero
(16). A snapshot reads nodes its source wrote, so readers check the owner's
*class* — subvolume node or not — never its exact id.

**Keys** are 17 bytes — object (u64), kind (u8), offset (u64) — and sort in
that order.

**Leaves** hold items: from offset 64, item headers of 21 bytes (key, data
offset u16, data length u16); the data packed from the end of the block in
item order, **with no gaps**, and zeros between the last header and the
first byte of data. There is nowhere to hide anything in a leaf.

**Internal nodes** hold up to 62 children: key (17), block (8), generation
(8), BLAKE3 (32). A child's key is the first key of its subtree; a search
takes the last child whose key is ≤ the key sought.

Every subvolume is one tree; the **tree of subvolumes** holds one `ROOT`
item per subvolume.

## 5. Items

| Kind | Key | Value |
|---|---|---|
| `INODE` (1) | (ino, 1, 0) | the inode, 112 bytes (below) |
| `DIRENT` (2) | (dir, 2, hash(name)) | the entries filed under that hash: child (8), index sequence (8), type (1), name length (1), name — almost always exactly one |
| `DIRINDEX` (3) | (dir, 3, sequence) | child (8), type (1), name length (1), name: the directory in creation order, for listings that survive changes |
| `EXTENT` (4) | (ino, 4, window start) | one window of the file (§6) |
| `ROOT` (16) | (subvolume, 16, 0) | in the tree of subvolumes: root pointer (49), zero (7), generation, created, flags (bit 0 read-only), parent subvolume, next inode number, zero (8), name length (1), name |

`hash(name)` is the first 8 bytes of BLAKE3 in key-derivation mode
(context `"NCFS 2026-10 directory entry name"`) over the name. Names are 1
to 255 bytes, anything but `/` and NUL, never `.` or `..` — UTF-8 or not.

**Inode**: mode (POSIX `st_mode`), uid, gid, nlink (4 each), size (8),
atime, mtime, ctime, btime (8 each, ns), flags (8: bit 0 never compress,
bit 1 never deduplicate), generation of creation (8), parent (8, a
directory's), next index sequence (8, a directory's), rdev (8), bytes on
disk (8), zero (8). The root directory is inode 1 (FUSE's root id too);
inode numbers are never reused.

## 6. File data

A file is cut into **windows of 128 KiB**; window *k* covers bytes
[*k*·128 KiB, (*k*+1)·128 KiB) and is one `EXTENT` item at offset
*k*·128 KiB, or none (a hole: zeros). An extent item is a header — kind
(1: 0 inline, 1 regular), compression (1: 0 none, 1 LZ4, 2 ZSTD), zero (2),
length of file content (4) — then:

* **inline**: the stored bytes, at most 2048 (window 0 of a small file);
* **regular**: first block (8), blocks (4), stored bytes (4), birth
  generation (8), BLAKE3 of the stored bytes (32). The blocks are exactly
  as many as the stored bytes need.

Writing a window: all zeros → no extent (a hole); otherwise compress with
the volume's codec and keep the result only if it needs fewer blocks; look
for an identical extent (same codec, lengths and BLAKE3 — then compared
byte for byte) and share it; else allocate and write. Reading a window:
read its blocks, check their BLAKE3, decode into exactly the declared
length. LZ4 blocks are the reference library's block format; ZSTD extents
are RFC 8878 frames. The kernel encodes LZ4 and decodes both.

## 7. Transactions

Changing an item copies its leaf and every node above it into memory (the
*shadow*); file data is buffered per window. A commit:

1. writes buffered windows as extents (new blocks);
2. writes every shadowed node to new blocks, children first, each parent
   recording its children's new BLAKE3 — each subvolume, then the tree of
   subvolumes;
3. **barrier** (flush): everything the new superblock will name is durable;
4. writes the superblock, generation *g*, to slot *g* mod 2;
5. **barrier**: the commit is durable; the blocks it stopped using — kept
   *pinned* until now so the previous commit stayed whole — return to the
   free space.

A cut anywhere leaves either the previous commit or this one, never a mix:
before step 4 completes, slot (*g*−1) mod 2 still holds the previous
superblock and nothing it references was overwritten. The tests cut the
power at every write of a commit, keep or drop each write since the last
barrier at random, tear the write at the cut in half — and require every
image to mount, pass `fsck`, and show exactly one committed state.

## 8. Sharing and space

Every node and extent has a **reference count**: the number of pointers to
it. A snapshot adds one to its source's root; copying a shared node first
adds one to each of its children (O. Rodeh, *B-trees, Shadowing, and
Clones*, 2008); deleting a subvolume subtracts down the tree and frees
what reaches zero. The counts are **not stored**: a writable mount counts
them from the trees (shared subtrees once), and builds the free space as
everything neither reserved nor referenced. There is no allocation map to
tear or to disagree with the trees, and a read-only mount — the kernel's
— needs none of it.

## 9. Sealed volumes

A sealed volume has `SEED` set, `sig_blocks` = 16, a single valid
superblock (sealing writes the next slot, then clears the other), and is
read-only forever. Its signatures live in the signature area, outside the
superblock, so adding one never changes what another signed. Each signs

```text
"NCFS-SEAL-1" 0x00  role  0x00  SHA-512(the sealed superblock block)
```

— `ncpkg`'s framing under its own domain, so a package signature can never
pass for a volume's. Roles, algorithms and badges are the packages'
(docs/NCPKG.md §4): ring-0 content wants `creator-ring0` 🌳 or
`verify-ring0`; drafts (Dilithium, SPHINCS+, …) are refused by name.

The area, binary: magic `NCFSSEAL` (8), version 1 (2), count 1..=8 (2),
bytes used (4); then per signature: role index (1), algorithm length (1),
key fingerprint (19, `xxxx-xxxx-xxxx-xxxx`), public-key length (2),
signature length (4), the algorithm's name, the public key(s) (a
self-signature only), the signature; zeros to the end. Every byte is
accounted for; one signature per role.

## 10. Limits

| | |
|---|---|
| block | 4096 bytes |
| volume | 2^64 blocks |
| file | 2^63 − 1 bytes |
| name | 255 bytes |
| item | 4011 bytes |
| inline file | 2048 bytes |
| window / extent | 128 KiB |
| tree depth | 8 levels |
| children per node | 62 |
| subvolumes | 2^64 |
| signatures on a sealed volume | 8 |

## 11. Where NCFS is read and written

| Where | How | Status |
|---|---|---|
| The kernel, at boot | the `ncinitramdisk`: `nanochrono-core::ncfs::read`, no heap, a static scratch; its seal checked against the embedded roots | **done** |
| The system's root | the writer over a disk driver, once the kernel has a heap and the NVMe/AHCI drivers write | planned |
| A host: `tools/ncfs` | `mkfs`, `build`, `put`/`get`, `snapshot`, `check --scrub`, `seal`/`verify` | **done** |
| Linux, ring 3 | `ncfs mount` through FUSE — **the recommended way** (a bug or a hostile image takes down a process, nothing else) | **done** |
| Linux, ring 0 | the `nanochrono` module (`kernel/linux`): a read-only `ncfs` filesystem type for `mount -t ncfs`, for when FUSE is absent | planned |
| Windows | the GUI's own reader (recommended, no driver signing); the `.sys` (`kernel/windows`) as a read-only filesystem for those who sign their drivers | planned |
| `ncpkg` | `pkgfs.rs`: NCFS as the `Fs` the package manager installs into, its promises (durable create, atomic rename) kept by copy-on-write | **done** |

## 12. Next

* A persisted free-space cache (validated by generation) so large volumes
  mount without counting every reference.
* Metadata duplicated on one device, and mirrors across devices, so a bad
  block heals from its copy instead of only being reported.
* Extended attributes; per-subvolume quotas.
* Encryption: per-subvolume keys sealed by NCTEE (docs/SYSTEM.md §7),
  AEAD per extent, the BLAKE3 tree over ciphertext.
* The writer in the kernel, and `ncpkg install` on the system itself.

## 13. The code

| File | What |
|---|---|
| `crates/nanochrono-core/src/ncfs/format.rs` | every on-disk structure, encoded and checked |
| `…/ncfs/read.rs` | the reader: no allocation, every buffer the caller's |
| `…/ncfs/write.rs` | `mkfs`, the copy-on-write engine, files, snapshots |
| `…/ncfs/check.rs` | `fsck` and scrub, independent of the writer |
| `…/ncfs/seal.rs` | sealed volumes: the signature area, the message, judging |
| `…/ncfs/pkgfs.rs` | NCFS as `ncpkg`'s filesystem |
| `crates/nanochrono-core/src/{blake3,lz4,zstd}.rs` | the hash and the codecs, `no_std` |
| `crates/nanochrono-baremetal/src/initramdisk.rs` | the kernel's `ncinitramdisk` |
| `tools/ncfs/` | the host tool and the FUSE mount |

Tests: `cargo test -p nanochrono-core ncfs` (the power cut at every write,
snapshots, deduplication, compression, corruption, 3000 entries splitting
and merging the tree, `ncpkg` installing into NCFS) and `tools/ncfs`'s.
