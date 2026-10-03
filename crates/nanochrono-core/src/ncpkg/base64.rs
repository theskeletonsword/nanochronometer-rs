// SPDX-License-Identifier: Apache-2.0
//! Base64 (RFC 4648 §4, standard alphabet, padded), for the signatures and
//! public keys a manifest carries.
//!
//! Decoding is canonical: padding required, no whitespace, no characters
//! outside the alphabet, and the unused bits of the last character zero —
//! so a signature has exactly one spelling, and a manifest cannot be
//! altered without changing what the signature bytes decode to.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn value(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// The decoded length of `text`, if it is well-formed in length and padding.
pub fn decoded_len(text: &[u8]) -> Option<usize> {
    if text.len() % 4 != 0 {
        return None;
    }
    let pad = text.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    Some(text.len() / 4 * 3 - pad)
}

/// Decodes `text` into `out`, returning the decoded bytes; `None` for
/// anything but the canonical encoding, or if `out` is too small.
pub fn decode<'b>(text: &[u8], out: &'b mut [u8]) -> Option<&'b [u8]> {
    let n = decoded_len(text)?;
    let out = out.get_mut(..n)?;
    let mut o = 0;
    for (i, quad) in text.chunks_exact(4).enumerate() {
        let last = i == text.len() / 4 - 1;
        let pad = if last { quad.iter().filter(|&&c| c == b'=').count() } else { 0 };
        // Padding only at the very end, and only as a suffix.
        if (!last && quad.contains(&b'=')) || quad[..4 - pad].contains(&b'=') {
            return None;
        }
        let mut acc = 0u32;
        for &c in &quad[..4 - pad] {
            acc = (acc << 6) | value(c)?;
        }
        acc <<= 6 * pad as u32;
        let bytes = [(acc >> 16) as u8, (acc >> 8) as u8, acc as u8];
        let keep = 3 - pad;
        // The bits the padding leaves unused must be zero.
        if pad > 0 && bytes[keep..].iter().any(|&b| b != 0) {
            return None;
        }
        out.get_mut(o..o + keep)?.copy_from_slice(&bytes[..keep]);
        o += keep;
    }
    Some(&out[..o])
}

/// The encoded length of `n` bytes.
pub const fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Encodes `data` into `out`, returning the text.
pub fn encode<'b>(data: &[u8], out: &'b mut [u8]) -> Option<&'b str> {
    let out = out.get_mut(..encoded_len(data.len()))?;
    for (i, chunk) in data.chunks(3).enumerate() {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let acc = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let quad = &mut out[i * 4..i * 4 + 4];
        for (j, slot) in quad.iter_mut().enumerate() {
            *slot = if j <= chunk.len() { ALPHABET[((acc >> (18 - 6 * j)) & 63) as usize] } else { b'=' };
        }
    }
    core::str::from_utf8(out).ok()
}

#[cfg(feature = "alloc")]
pub fn encode_string(data: &[u8]) -> String {
    let mut out = alloc::vec![0u8; encoded_len(data.len())];
    let n = encode(data, &mut out).map(str::len).unwrap_or(0);
    out.truncate(n);
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(feature = "alloc")]
pub fn decode_vec(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = alloc::vec![0u8; decoded_len(text)?];
    let n = decode(text, &mut out)?.len();
    out.truncate(n);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors() {
        for (plain, coded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(encode_string(plain.as_bytes()), coded);
            assert_eq!(decode_vec(coded.as_bytes()).unwrap(), plain.as_bytes());
        }
        let all: std::vec::Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode_vec(encode_string(&all).as_bytes()).unwrap(), all);
    }

    #[test]
    fn only_the_canonical_spelling_decodes() {
        for bad in ["Zg", "Zg=", "Zh==", "Zm9=", "Z===", "Zg==Zg==", "Zm 9v", "Zm9v\n", "Zm9-", "====", "Zg=a"] {
            assert!(decode_vec(bad.as_bytes()).is_none(), "{bad:?}");
        }
        let mut small = [0u8; 2];
        assert!(decode(b"Zm9v", &mut small).is_none());
    }
}
