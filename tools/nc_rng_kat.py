#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Known-answer vectors for NC_RNG, from an implementation that shares no code
with it.

NC_RNG (crates/nanochrono-core/src/rng) carries its own Keccak-f[1600]; its
self-test is only worth something if the expected values come from somewhere
else. Here they come from Python's hashlib (OpenSSL's SHA-3), and the XDRBG-256
construction is re-implemented on top of it in a dozen lines. Run this and
paste the output into `keccak.rs` / `xdrbg.rs` when either changes:

    python3 tools/nc_rng_kat.py

XDRBG (Kelsey, Lucks, Müller, ToSC 2024) over SHAKE256, 64-byte state V:

    instantiate(seed, a): V <- SHAKE256(seed || a || enc(0, a), 64)
    reseed(seed, a):      V <- SHAKE256(V || seed || a || enc(1, a), 64)
    generate(n, a):       T <- SHAKE256(V || a || enc(2, a), 64 + n)
                          V <- T[:64]; out <- T[64:]
    enc(k, a) = one byte, k * 85 + len(a), len(a) <= 84

The output stage (crates/nanochrono-core/src/rng/stream.rs) expands an XDRBG
key with AES-256-CTR (VAES, AES-NI or the ARMv8 AES instructions) or ChaCha20,
with fast key erasure: each request draws a fresh nonce from a counter that
never goes back, uses keystream block(s) at the front as the next key, and
hands out only what follows. The vectors below pin both ciphers and that
layout, from `cryptography` (OpenSSL) rather than from the Rust code.
"""

import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

STATE = 64
BLOCK = 32


def enc(k: int, alpha: bytes) -> bytes:
    assert len(alpha) <= 84
    return bytes([k * 85 + len(alpha)])


class Xdrbg:
    def __init__(self, seed: bytes, alpha: bytes = b""):
        self.v = hashlib.shake_256(seed + alpha + enc(0, alpha)).digest(STATE)

    def reseed(self, seed: bytes, alpha: bytes = b"") -> None:
        self.v = hashlib.shake_256(self.v + seed + alpha + enc(1, alpha)).digest(STATE)

    def generate(self, n: int, alpha: bytes = b"") -> bytes:
        assert n <= BLOCK
        t = hashlib.shake_256(self.v + alpha + enc(2, alpha)).digest(STATE + n)
        self.v = t[:STATE]
        return t[STATE:]


# The stream stage's ChaCha20 nonce: the 64-bit request counter, then this.
CHACHA_DOMAIN = 0x4E43524E  # "NCRN" read little-endian
# Output per key before the stream rekeys, and the key-block counts.
AES_KEY_BLOCKS = 2      # 2 x 16 bytes of keystream become the next key
CHACHA_KEY_BLOCKS = 1   # the first 32 bytes of block 0; its rest is dropped


def aes_keystream(key: bytes, nonce: int, first: int, n: int) -> bytes:
    """Counter block i = nonce (u64 LE) || first + i (u64 LE), AES-256-ECB."""
    blocks = b"".join(struct.pack("<QQ", nonce, first + i) for i in range((n + 15) // 16))
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return (enc.update(blocks) + enc.finalize())[:n]


def chacha_keystream(key: bytes, nonce: int, first: int, n: int) -> bytes:
    """RFC 8439 ChaCha20: 32-bit block counter, 96-bit nonce = nonce (u64 LE) || domain."""
    full = struct.pack("<I", first) + struct.pack("<QI", nonce, CHACHA_DOMAIN)
    enc = Cipher(algorithms.ChaCha20(key, full), mode=None).encryptor()
    return enc.update(bytes(n))


class Stream:
    """Fast key erasure over either cipher."""

    def __init__(self, key: bytes, cipher: str):
        self.key, self.cipher, self.nonce = key, cipher, 0

    def generate(self, n: int) -> bytes:
        nonce = self.nonce
        self.nonce += 1
        if self.cipher == "aes":
            next_key = aes_keystream(self.key, nonce, 0, 32)
            out = aes_keystream(self.key, nonce, AES_KEY_BLOCKS, n)
        else:
            next_key = chacha_keystream(self.key, nonce, 0, 32)
            out = chacha_keystream(self.key, nonce, CHACHA_KEY_BLOCKS, n)
        self.key = next_key
        return out


def rust_bytes(name: str, data: bytes) -> str:
    rows = [data[i:i + 16] for i in range(0, len(data), 16)]
    body = "\n".join("    " + " ".join(f"0x{b:02x}," for b in row) for row in rows)
    return f"const {name}: [u8; {len(data)}] = [\n{body}\n];"


def main() -> None:
    a3 = bytes([0xA3]) * 200
    print("// keccak.rs")
    print(rust_bytes("SHA3_256_EMPTY", hashlib.sha3_256(b"").digest()))
    print(rust_bytes("SHA3_256_ABC", hashlib.sha3_256(b"abc").digest()))
    print(rust_bytes("SHA3_256_A3X200", hashlib.sha3_256(a3).digest()))
    print(rust_bytes("SHAKE256_EMPTY", hashlib.shake_256(b"").digest(32)))
    # 300 bytes crosses two rate boundaries on the squeeze side; the check is
    # on a digest of it so the constant stays short.
    long_out = hashlib.shake_256(b"abc").digest(300)
    print(rust_bytes("SHAKE256_ABC_300_SHA3", hashlib.sha3_256(long_out).digest()))

    print()
    print("// xdrbg.rs")
    drbg = Xdrbg(bytes(range(64)), b"NanoChronometer")
    first = drbg.generate(BLOCK)
    second = drbg.generate(BLOCK)
    drbg.reseed(bytes(range(64, 128)), b"NC_RNG")
    third = drbg.generate(BLOCK, b"alpha")
    print(rust_bytes("KAT_FIRST", first))
    print(rust_bytes("KAT_SECOND", second))
    print(rust_bytes("KAT_AFTER_RESEED", third))

    print()
    print("// stream.rs")
    key = bytes(range(32))
    fips = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    print(rust_bytes("AES256_FIPS197", fips.update(bytes.fromhex("00112233445566778899aabbccddeeff"))))
    # Nine blocks: two four-block VAES batches and a single, so every path runs.
    print(rust_bytes("AES_CTR_9_SHA3", hashlib.sha3_256(aes_keystream(key, 0x0706050403020100, 0, 144)).digest()))
    rfc = Cipher(algorithms.ChaCha20(key, struct.pack("<I", 1) + bytes.fromhex("000000090000004a00000000")),
                 mode=None).encryptor()
    print(rust_bytes("CHACHA20_RFC8439_BLOCK", rfc.update(bytes(64))))
    print(rust_bytes("CHACHA_5_SHA3", hashlib.sha3_256(chacha_keystream(key, 0x0706050403020100, 0, 320)).digest()))
    for cipher in ("aes", "chacha"):
        s = Stream(key, cipher)
        outs = s.generate(50) + s.generate(200) + s.generate(1)
        print(rust_bytes(f"STREAM_{cipher.upper()}_SHA3", hashlib.sha3_256(outs).digest()))


if __name__ == "__main__":
    main()
