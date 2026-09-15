//! OpenPGP key parsing, validation, ownership checking, and minimization
//! for WKD publication.

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::packet::Packet;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::Serialize as _;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("failed to parse key material: {0}")]
    ParseFailed(String),
    #[error("key has no valid, non-expired self-signature on its primary key: {0}")]
    InvalidPrimaryKey(String),
    #[error("key has no valid User ID matching {0}")]
    NoMatchingUserId(String),
}

/// Parse an uploaded key (ASCII-armored or binary). Rejects anything that
/// fails to parse.
pub fn parse_cert(bytes: &[u8]) -> Result<Cert, KeyError> {
    Cert::from_bytes(bytes).map_err(|e| KeyError::ParseFailed(e.to_string()))
}

/// Parse key material submitted through the API: either ASCII-armored
/// text, or base64-encoded binary OpenPGP data (per the `POST /api/keys`
/// contract's `key` field).
pub fn parse_key_material(input: &str) -> Result<Cert, KeyError> {
    let trimmed = input.trim();
    if let Ok(cert) = Cert::from_bytes(trimmed.as_bytes()) {
        return Ok(cert);
    }
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| {
            KeyError::ParseFailed(format!(
                "key is neither valid OpenPGP armor nor valid base64: {e}"
            ))
        })?;
    Cert::from_bytes(&decoded).map_err(|e| KeyError::ParseFailed(e.to_string()))
}

/// Validate that `cert` has a valid, non-expired self-signature on its
/// primary key (per `StandardPolicy`), and that it has a User ID matching
/// `address` (case-insensitive) with a valid binding self-signature.
pub fn validate_for_address(cert: &Cert, address: &str) -> Result<(), KeyError> {
    let policy = StandardPolicy::new();
    let valid_cert = cert
        .with_policy(&policy, None)
        .map_err(|e| KeyError::InvalidPrimaryKey(e.to_string()))?;

    let has_match = valid_cert
        .userids()
        .any(|ua| userid_matches(ua.userid(), address));

    if has_match {
        Ok(())
    } else {
        Err(KeyError::NoMatchingUserId(address.to_string()))
    }
}

fn userid_matches(userid: &sequoia_openpgp::packet::UserID, address: &str) -> bool {
    userid
        .email()
        .ok()
        .flatten()
        .map(|e| e.eq_ignore_ascii_case(address))
        .unwrap_or(false)
}

pub fn fingerprint_hex(cert: &Cert) -> String {
    cert.fingerprint().to_hex()
}

/// Produce a minimized export of `cert` for `address`: only the primary
/// key, the single User ID matching `address` with its valid binding
/// self-signature, and subkeys with their valid binding signatures. No
/// other User IDs and no third-party certifications are included.
///
/// Because the packets are rebuilt from the `PublicParts` view of each
/// key exclusively, the result can never carry secret key material even
/// if the input did.
pub fn minimize_for_address(cert: &Cert, address: &str) -> Result<Vec<u8>, KeyError> {
    let policy = StandardPolicy::new();
    let valid_cert = cert
        .with_policy(&policy, None)
        .map_err(|e| KeyError::InvalidPrimaryKey(e.to_string()))?;

    let mut packets: Vec<Packet> = Vec::new();
    packets.push(Packet::from(valid_cert.primary_key().key().clone()));

    let target = valid_cert
        .userids()
        .find(|ua| userid_matches(ua.userid(), address))
        .ok_or_else(|| KeyError::NoMatchingUserId(address.to_string()))?;
    packets.push(Packet::from(target.userid().clone()));
    packets.push(Packet::from(target.binding_signature().clone()));

    for ka in valid_cert.keys().subkeys() {
        packets.push(Packet::from(ka.key().clone()));
        packets.push(Packet::from(ka.binding_signature().clone()));
    }

    let minimized = Cert::from_packets(packets.into_iter())
        .map_err(|e| KeyError::ParseFailed(format!("failed to rebuild minimized cert: {e}")))?;

    let mut buf = Vec::new();
    minimized
        .serialize(&mut buf)
        .map_err(|e| KeyError::ParseFailed(format!("failed to serialize minimized cert: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::cert::CertBuilder;

    fn cert_with_uids(uids: &[&str]) -> Cert {
        let mut builder = CertBuilder::new().add_signing_subkey();
        for uid in uids {
            builder = builder.add_userid(*uid);
        }
        let (cert, _revocation) = builder.generate().unwrap();
        cert
    }

    #[test]
    fn parses_valid_generated_cert() {
        let cert = cert_with_uids(&["Alice <alice@example.com>"]);
        let mut buf = Vec::new();
        cert.serialize(&mut buf).unwrap();
        let parsed = parse_cert(&buf).unwrap();
        assert_eq!(parsed.fingerprint(), cert.fingerprint());
    }

    #[test]
    fn rejects_garbage_bytes() {
        let err = parse_cert(b"this is not an openpgp key").unwrap_err();
        assert!(matches!(err, KeyError::ParseFailed(_)));
    }

    #[test]
    fn validates_matching_address() {
        let cert = cert_with_uids(&["Alice <alice@example.com>"]);
        assert!(validate_for_address(&cert, "alice@example.com").is_ok());
        // Case-insensitive match.
        assert!(validate_for_address(&cert, "ALICE@EXAMPLE.COM").is_ok());
    }

    #[test]
    fn rejects_non_matching_address() {
        let cert = cert_with_uids(&["Alice <alice@example.com>"]);
        let err = validate_for_address(&cert, "mallory@example.com").unwrap_err();
        assert!(matches!(err, KeyError::NoMatchingUserId(_)));
    }

    /// Hard correctness requirement: given a cert with 2+ UIDs, the
    /// minimized export for address A contains exactly one UID and it
    /// matches A, regardless of how many UIDs the input had.
    #[test]
    fn minimization_strips_all_but_target_uid() {
        let cert = cert_with_uids(&[
            "Alice <alice@example.com>",
            "Alice Smith <alice.smith@example.org>",
            "Al <al@example.net>",
        ]);

        let minimized_bytes = minimize_for_address(&cert, "alice.smith@example.org").unwrap();
        let minimized = parse_cert(&minimized_bytes).unwrap();

        let uids: Vec<_> = minimized.userids().collect();
        assert_eq!(uids.len(), 1, "expected exactly one UID after minimization");
        assert_eq!(
            uids[0].userid().email().unwrap().unwrap(),
            "alice.smith@example.org"
        );

        // The minimized cert must still validate under policy: the
        // retained self-signature must still be valid.
        assert!(validate_for_address(&minimized, "alice.smith@example.org").is_ok());

        // Fingerprint (i.e. the primary key) is preserved.
        assert_eq!(minimized.fingerprint(), cert.fingerprint());
    }

    #[test]
    fn minimization_preserves_subkeys() {
        let cert = cert_with_uids(&["Alice <alice@example.com>", "Other <other@example.com>"]);
        let minimized_bytes = minimize_for_address(&cert, "alice@example.com").unwrap();
        let minimized = parse_cert(&minimized_bytes).unwrap();

        let original_subkey_count = cert.keys().subkeys().count();
        let minimized_subkey_count = minimized.keys().subkeys().count();
        assert_eq!(original_subkey_count, minimized_subkey_count);
        assert!(minimized_subkey_count > 0);
    }

    #[test]
    fn minimize_fails_for_address_without_uid() {
        let cert = cert_with_uids(&["Alice <alice@example.com>"]);
        let err = minimize_for_address(&cert, "nobody@example.com").unwrap_err();
        assert!(matches!(err, KeyError::NoMatchingUserId(_)));
    }
}
