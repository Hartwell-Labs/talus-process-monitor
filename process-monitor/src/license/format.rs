//! Pretty license key format — the customer-facing encoding.
//!
//! Canonical (internal) form — what the Ed25519 signature covers:
//!     base64(JSON payload) "." base64(64-byte signature)
//!
//! Display (pretty) form — what customers receive and type:
//!     TALUS-XXXXX-XXXXX-…-XXXXX-SS
//!
//!   • XXXXX = Crockford base32 (0-9, A-Z minus I, L, O, U) of the canonical
//!     bytes, grouped in fives — no ambiguous characters.
//!   • SS    = last two hex chars of SHA-256 over the canonical bytes, so
//!     typos are caught before activation.
//!
//! The signature is PART of the encoded bytes, so the pretty form carries the
//! full signed key. Decoding is lossless. Old canonical keys stay valid.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "TALUS";
#[allow(dead_code)] // license-issuer WIP — używane przez scripts/issuer-daemon (odpalamy po integracji)
const GROUP: usize = 5;

/// True when the string looks like the pretty display form (the full JWT
/// encoded — many groups). Short keys (TALUS-XXXXX-XXXXX-XXXXX-XXXXX) are
/// NOT pretty: they resolve to the JWT through the license server.
pub fn is_pretty(key: &str) -> bool {
    let compact: String = key.trim().chars().filter(|c| !c.is_whitespace()).collect();
    let upper = compact.to_uppercase();
    upper.starts_with(&format!("{PREFIX}-")) && upper.matches('-').count() >= 6
}

/// True when the string looks like a SHORT key (server-resolved JWT):
/// exactly TALUS-XXXXX-XXXXX-XXXXX-XXXXX — 4 groups of 5.
pub fn is_short(key: &str) -> bool {
    let compact: String = key.trim().chars().filter(|c| !c.is_whitespace()).collect();
    let upper = compact.to_uppercase();
    upper.starts_with(&format!("{PREFIX}-")) && upper.matches('-').count() == 4
}

/// Canonical key string → pretty key string.
#[allow(dead_code)] // license-issuer WIP — pretty-print dla kluczy w CLI issuer
pub fn to_pretty(canonical_key: &str) -> String {
    let data = canonical_key.trim().as_bytes();
    let digest = Sha256::digest(data);
    let body = b32_encode(data);
    let grouped: Vec<String> = body
        .as_bytes()
        .chunks(GROUP)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    let checksum = hex_last2(&digest);
    format!("{PREFIX}-{}-{}", grouped.join("-"), checksum)
}

/// Pretty key string → canonical key string. Fails on checksum mismatch.
pub fn decode_pretty(pretty_key: &str) -> Result<String> {
    let cleaned: String = pretty_key
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    let rest = cleaned
        .strip_prefix(&format!("{PREFIX}-"))
        .ok_or_else(|| anyhow::anyhow!("not a pretty key"))?;
    let parts: Vec<&str> = rest.split('-').collect();
    if parts.len() < 2 {
        bail!("key too short");
    }
    let checksum = parts[parts.len() - 1];
    let body: String = parts[..parts.len() - 1].concat();
    for ch in body.chars() {
        if !ALPHABET.contains(&(ch as u8)) {
            bail!("invalid character '{ch}' in key");
        }
    }
    let data = b32_decode(&body)?;
    let digest = Sha256::digest(&data);
    let expected = hex_last2(&digest);
    if !checksum.eq_ignore_ascii_case(&expected) {
        bail!("checksum mismatch — retype the key");
    }
    String::from_utf8(data).context("decoded key is not valid UTF-8")
}

fn hex_last2(digest: &[u8]) -> String {
    let hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
    hex[hex.len() - 2..].to_uppercase()
}

#[allow(dead_code)] // license-issuer WIP — fallback kodowania bez base32 crate
fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        nbits += 8;
        while nbits >= 5 {
            out.push(ALPHABET[((acc >> (nbits - 5)) & 31) as usize] as char);
            nbits -= 5;
        }
    }
    if nbits > 0 {
        out.push(ALPHABET[((acc << (5 - nbits)) & 31) as usize] as char);
    }
    out
}

fn b32_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for ch in s.chars() {
        let idx = ALPHABET
            .iter()
            .position(|&c| c as char == ch)
            .ok_or_else(|| anyhow::anyhow!("invalid character"))?;
        acc = (acc << 5) | idx as u32;
        nbits += 5;
        if nbits >= 8 {
            out.push(((acc >> (nbits - 8)) & 0xff) as u8);
            nbits -= 8;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "eyJsaWNlbnNlX2lkIjoiVEFMVVMifQ.MEUCIQTest";

    #[test]
    fn short_key_classification() {
        assert!(is_short("talus-a2b3c-4d5e6-f7g8h-9j0k1"));
        assert!(is_short("  TALUS-A2B3C-4D5E6-F7G8H-9J0K1\n"));
        // Pretty full-JWT keys have many groups — not short.
        assert!(!is_short(&to_pretty(SAMPLE)));
        // Canonical has no TALUS prefix.
        assert!(!is_short(SAMPLE));
    }

    #[test]
    fn roundtrip() {
        assert!(is_pretty(&to_pretty(SAMPLE)));
        let decoded = decode_pretty(&to_pretty(SAMPLE)).unwrap();
        assert_eq!(decoded, SAMPLE);
    }

    #[test]
    fn checksum_catches_typos() {
        let pretty = to_pretty(SAMPLE);
        let corrupted = pretty.replace('A', "B");
        assert_ne!(corrupted, pretty);
        assert!(decode_pretty(&corrupted).is_err());
    }

    #[test]
    fn whitespace_and_case_tolerant() {
        let pretty = to_pretty(SAMPLE);
        let lowered = format!("  {}  ", pretty.to_lowercase()).replace('-', " - ");
        assert_eq!(decode_pretty(&lowered).unwrap(), SAMPLE);
    }
}
