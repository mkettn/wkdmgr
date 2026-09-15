//! WKD local-part hashing per draft-koch-openpgp-webkey-service section 3.1:
//! ASCII-lowercase the local part, SHA-1 it, then Z-Base-32 encode the digest.

use sha1::{Digest, Sha1};

/// Zooko's base32 alphabet (RFC6189 5.1.6), not the RFC4648 alphabet.
const ZBASE32_ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Z-Base-32 encode `data`, 5 bits at a time, MSB first, no padding.
pub fn zbase32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits_in_buffer: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let idx = (buffer >> bits_in_buffer) & 0x1f;
            out.push(ZBASE32_ALPHABET[idx as usize] as char);
        }
    }
    if bits_in_buffer > 0 {
        let idx = (buffer << (5 - bits_in_buffer)) & 0x1f;
        out.push(ZBASE32_ALPHABET[idx as usize] as char);
    }
    out
}

/// Split `address` into (local_part, domain), lowercasing the domain.
/// Returns an error if there is no exactly-one `@`.
pub fn split_address(address: &str) -> anyhow::Result<(String, String)> {
    let mut parts = address.splitn(2, '@');
    let local = parts.next().unwrap_or_default();
    let domain = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("address '{address}' is missing '@'"))?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        anyhow::bail!("address '{address}' is not a valid email address");
    }
    Ok((local.to_string(), domain.to_ascii_lowercase()))
}

/// Compute the WKD hash for the local part of an email address. Only the
/// ASCII characters of the local part are case-folded, per spec.
pub fn wkd_hash_local_part(local_part: &str) -> String {
    let lowered = local_part.to_ascii_lowercase();
    let digest = Sha1::digest(lowered.as_bytes());
    zbase32_encode(&digest)
}

/// Compute the WKD hash for a full email address, returning
/// `(hash, domain)`. The domain is lowercased; the local part is
/// ASCII-lowercased before hashing.
pub fn wkd_hash_for_address(address: &str) -> anyhow::Result<(String, String)> {
    let (local, domain) = split_address(address)?;
    Ok((wkd_hash_local_part(&local), domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector taken directly from the WKD draft's own worked example
    /// (section 3.1): Joe.Doe@Example.ORG hashes to
    /// iy9q119eutrkn8s1mk4r39qejnbu3n5q.
    #[test]
    fn spec_example_joe_doe() {
        let (hash, domain) = wkd_hash_for_address("Joe.Doe@Example.ORG").unwrap();
        assert_eq!(hash, "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
        assert_eq!(domain, "example.org");
    }

    #[test]
    fn local_part_is_only_ascii_lowercased() {
        // Non-ASCII characters must be left unchanged per spec, even though
        // this local part is unrealistic for a real deployment.
        let mixed = wkd_hash_local_part("ÀBC");
        let expected = {
            let digest = Sha1::digest("Àbc".as_bytes());
            zbase32_encode(&digest)
        };
        assert_eq!(mixed, expected);
    }

    #[test]
    fn hash_is_32_chars() {
        let (hash, _) = wkd_hash_for_address("test@example.com").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn rejects_missing_at() {
        assert!(wkd_hash_for_address("not-an-email").is_err());
    }

    #[test]
    fn domain_lowercased_local_part_case_preserved_before_hash() {
        // local part case affects the hash (it's lowercased internally,
        // but distinct inputs before lowering must still normalize the
        // same way): Alice and alice hash identically.
        let (h1, _) = wkd_hash_for_address("Alice@Example.com").unwrap();
        let (h2, _) = wkd_hash_for_address("alice@EXAMPLE.COM").unwrap();
        assert_eq!(h1, h2);
    }
}
