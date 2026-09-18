//! OpenPGP key parsing, validation, ownership checking, and minimization
//! for WKD publication.

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::packet::Packet;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::Serialize as _;
use sequoia_openpgp::types::RevocationStatus;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("failed to parse key material: {0}")]
    ParseFailed(String),
    #[error("key has no valid self-signature on its primary key: {0}")]
    InvalidPrimaryKey(String),
    #[error("key has no valid User ID matching {0}")]
    NoMatchingUserId(String),
    #[error("key has expired: {0}")]
    Expired(String),
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
    let looks_armored = trimmed.starts_with("-----BEGIN PGP");

    match Cert::from_bytes(trimmed.as_bytes()) {
        Ok(cert) => return Ok(cert),
        // If it's clearly meant to be armor, report *that* parse error
        // rather than falling through to a misleading "neither armor nor
        // base64" message that sends people looking in the wrong place.
        Err(e) if looks_armored => {
            return Err(KeyError::ParseFailed(format!("invalid OpenPGP armor: {e}")))
        }
        Err(_) => {}
    }

    use base64::Engine;
    // `gpg --export ... | base64` line-wraps at 76 columns by default;
    // strip all whitespace (not just newlines) before decoding so the
    // most obvious way to produce this input actually works.
    let stripped: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&stripped)
        .map_err(|e| {
            KeyError::ParseFailed(format!(
                "key is neither valid OpenPGP armor nor valid base64: {e}"
            ))
        })?;
    Cert::from_bytes(&decoded).map_err(|e| KeyError::ParseFailed(e.to_string()))
}

/// Validate that `cert` has a valid self-signature on its primary key
/// (per `StandardPolicy`), that the primary key is currently live (not
/// expired), and that it has a User ID matching `address`
/// (case-insensitive) with a valid binding self-signature.
pub fn validate_for_address(cert: &Cert, address: &str) -> Result<(), KeyError> {
    let policy = StandardPolicy::new();
    let valid_cert = cert
        .with_policy(&policy, None)
        .map_err(|e| KeyError::InvalidPrimaryKey(e.to_string()))?;

    valid_cert
        .alive()
        .map_err(|e| KeyError::Expired(e.to_string()))?;

    let has_match = valid_cert
        .userids()
        .any(|ua| userid_matches(ua.userid(), address));

    if has_match {
        Ok(())
    } else {
        Err(KeyError::NoMatchingUserId(address.to_string()))
    }
}

/// The primary key's expiration time, if it has one (`None` for a
/// non-expiring key). Stored as `keys.expires_at` so `wkdmgr-query` can
/// stop serving a key that was live at upload time but has since
/// expired -- unlike revocation, expiry doesn't arrive via any upload
/// at all, so it has to be checked at lookup time rather than cached
/// from a one-time computation.
pub fn expiration_time(cert: &Cert) -> Result<Option<chrono::DateTime<chrono::Utc>>, KeyError> {
    let policy = StandardPolicy::new();
    let valid_cert = cert
        .with_policy(&policy, None)
        .map_err(|e| KeyError::InvalidPrimaryKey(e.to_string()))?;
    Ok(valid_cert
        .primary_key()
        .key_expiration_time()
        .map(chrono::DateTime::<chrono::Utc>::from))
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
/// Self-revocation signatures on the primary key, the target User ID,
/// and each subkey *are* retained (they aren't third-party
/// certifications, and dropping them would make it impossible to ever
/// publish a revocation through this API -- a revoked cert has to
/// survive minimization for `is_revoked` to see it later). Matching
/// uses `valid_cert.userids()`, which -- despite the name -- still
/// yields revoked User IDs (revocation and policy/liveness validity are
/// independent checks in sequoia), so an already-revoked address can
/// still be found and minimized: an owner republishing their own
/// revocation is exactly the case this needs to support, not reject.
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

    let primary = valid_cert.primary_key();
    packets.push(Packet::from(primary.key().clone()));
    for revocation in primary.self_revocations() {
        packets.push(Packet::from(revocation.clone()));
    }

    let target = valid_cert
        .userids()
        .find(|ua| userid_matches(ua.userid(), address))
        .ok_or_else(|| KeyError::NoMatchingUserId(address.to_string()))?;
    packets.push(Packet::from(target.userid().clone()));
    packets.push(Packet::from(target.binding_signature().clone()));
    for revocation in target.self_revocations() {
        packets.push(Packet::from(revocation.clone()));
    }

    for ka in valid_cert.keys().subkeys() {
        packets.push(Packet::from(ka.key().clone()));
        packets.push(Packet::from(ka.binding_signature().clone()));
        for revocation in ka.self_revocations() {
            packets.push(Packet::from(revocation.clone()));
        }
    }

    let minimized = Cert::from_packets(packets.into_iter())
        .map_err(|e| KeyError::ParseFailed(format!("failed to rebuild minimized cert: {e}")))?;

    let mut buf = Vec::new();
    minimized
        .serialize(&mut buf)
        .map_err(|e| KeyError::ParseFailed(format!("failed to serialize minimized cert: {e}")))?;
    Ok(buf)
}

/// Whether a stored (minimized) key is effectively revoked: either the
/// primary key itself is revoked, or its sole retained User ID is.
/// Called once at upload time; the result is cached in the `revoked`
/// column (see `wkdmgr_core::storage`) rather than re-parsed on every
/// WKD lookup, since in this system revocation status only ever changes
/// via a fresh upload.
///
/// Fails closed: bytes that don't even parse are treated as revoked
/// (never served) rather than silently passed through, since a
/// minimized blob that this function can't parse indicates something
/// has gone wrong with data this service itself produced.
pub fn is_revoked(cert_bytes: &[u8]) -> bool {
    let policy = StandardPolicy::new();
    let cert = match Cert::from_bytes(cert_bytes) {
        Ok(cert) => cert,
        Err(_) => return true,
    };

    if matches!(
        cert.revocation_status(&policy, None),
        RevocationStatus::Revoked(_)
    ) {
        return true;
    }

    cert.userids().any(|ua| {
        matches!(
            ua.revocation_status(&policy, None),
            RevocationStatus::Revoked(_)
        )
    })
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

    fn cert_with_validity_period(
        uid: &str,
        creation_time: std::time::SystemTime,
        validity_period: std::time::Duration,
    ) -> Cert {
        let (cert, _revocation) = CertBuilder::new()
            .add_signing_subkey()
            .add_userid(uid)
            .set_creation_time(creation_time)
            .set_validity_period(validity_period)
            .generate()
            .unwrap();
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

    fn revoke_userid(cert: &Cert, uid_str: &str) -> Cert {
        use sequoia_openpgp::packet::signature::SignatureBuilder;
        use sequoia_openpgp::packet::UserID;
        use sequoia_openpgp::types::{ReasonForRevocation, SignatureType};

        let uid: UserID = uid_str.into();
        let mut signer = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let target = cert.userids().find(|ua| ua.userid() == &uid).unwrap();
        let revocation = target
            .userid()
            .bind(
                &mut signer,
                cert,
                SignatureBuilder::new(SignatureType::CertificationRevocation)
                    .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"testing")
                    .unwrap(),
            )
            .unwrap();
        cert.clone()
            .insert_packets(vec![Packet::from(revocation)])
            .unwrap()
            .0
    }

    fn revoke_primary_key(cert: &Cert) -> Cert {
        use sequoia_openpgp::packet::signature::SignatureBuilder;
        use sequoia_openpgp::types::{ReasonForRevocation, SignatureType};

        let mut signer = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let revocation = SignatureBuilder::new(SignatureType::KeyRevocation)
            .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"testing")
            .unwrap()
            .sign_direct_key(&mut signer, None)
            .unwrap();
        cert.clone()
            .insert_packets(vec![Packet::from(revocation)])
            .unwrap()
            .0
    }

    /// A user must be able to publish their own revocation: uploading a
    /// cert whose only UID has since been revoked must still find and
    /// minimize that UID (not reject it as "no matching UID"), and the
    /// revocation signature must survive minimization so it's visible
    /// after the round trip.
    #[test]
    fn minimization_preserves_uid_revocation() {
        let cert = cert_with_uids(&["Alice <alice@example.com>"]);
        let revoked_cert = revoke_userid(&cert, "Alice <alice@example.com>");

        // Ownership/validity check still accepts it: revocation must not
        // block the very upload that publishes it.
        assert!(validate_for_address(&revoked_cert, "alice@example.com").is_ok());

        let minimized_bytes = minimize_for_address(&revoked_cert, "alice@example.com").unwrap();
        assert!(is_revoked(&minimized_bytes));

        let minimized = parse_cert(&minimized_bytes).unwrap();
        assert_eq!(minimized.userids().count(), 1);
    }

    #[test]
    fn minimization_preserves_primary_key_revocation() {
        let cert = cert_with_uids(&["Alice <alice@example.com>"]);
        let revoked_cert = revoke_primary_key(&cert);

        let minimized_bytes = minimize_for_address(&revoked_cert, "alice@example.com").unwrap();
        assert!(is_revoked(&minimized_bytes));
    }

    #[test]
    fn is_revoked_false_for_live_key() {
        let cert = cert_with_uids(&["Alice <alice@example.com>"]);
        let minimized_bytes = minimize_for_address(&cert, "alice@example.com").unwrap();
        assert!(!is_revoked(&minimized_bytes));
    }

    #[test]
    fn is_revoked_true_for_unparseable_bytes() {
        assert!(is_revoked(b"not a cert"));
    }

    #[test]
    fn parse_key_material_accepts_line_wrapped_base64() {
        let cert = cert_with_uids(&["Alice <alice@example.com>"]);
        let mut buf = Vec::new();
        cert.serialize(&mut buf).unwrap();

        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&buf);
        // Simulate `base64`'s default 76-column wrap.
        let wrapped: String = encoded
            .as_bytes()
            .chunks(76)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        let parsed = parse_key_material(&wrapped).unwrap();
        assert_eq!(parsed.fingerprint(), cert.fingerprint());
    }

    #[test]
    fn parse_key_material_reports_armor_error_for_corrupt_armor() {
        let broken_armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot valid base64 content!!\n-----END PGP PUBLIC KEY BLOCK-----\n";
        let err = parse_key_material(broken_armor).unwrap_err();
        let KeyError::ParseFailed(message) = err else {
            panic!("expected ParseFailed");
        };
        assert!(
            message.contains("armor"),
            "expected an armor-specific error, got: {message}"
        );
    }

    #[test]
    fn validate_for_address_rejects_expired_cert() {
        let now = std::time::SystemTime::now();
        let sixty_days = std::time::Duration::from_secs(60 * 24 * 60 * 60);
        let thirty_one_days = std::time::Duration::from_secs(31 * 24 * 60 * 60);
        let cert = cert_with_validity_period(
            "Alice <alice@example.com>",
            now - sixty_days,
            thirty_one_days,
        );

        let err = validate_for_address(&cert, "alice@example.com").unwrap_err();
        assert!(matches!(err, KeyError::Expired(_)), "got {err:?}");
    }

    #[test]
    fn validate_for_address_accepts_unexpired_cert_with_validity_period() {
        let now = std::time::SystemTime::now();
        let one_day = std::time::Duration::from_secs(24 * 60 * 60);
        let one_year = std::time::Duration::from_secs(365 * 24 * 60 * 60);
        let cert = cert_with_validity_period("Alice <alice@example.com>", now - one_day, one_year);

        assert!(validate_for_address(&cert, "alice@example.com").is_ok());
    }

    #[test]
    fn expiration_time_none_for_non_expiring_cert() {
        let cert = cert_with_uids(&["Alice <alice@example.com>"]);
        assert_eq!(expiration_time(&cert).unwrap(), None);
    }

    #[test]
    fn expiration_time_matches_validity_period() {
        // OpenPGP signature creation times have whole-second resolution,
        // so floor `now` to a whole second before deriving the expected
        // value -- otherwise this flakes on the sub-second remainder
        // sequoia truncates away when generating the cert.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(now_secs);
        let one_day = std::time::Duration::from_secs(24 * 60 * 60);
        let one_year = std::time::Duration::from_secs(365 * 24 * 60 * 60);
        let creation_time = now - one_day;
        let cert = cert_with_validity_period("Alice <alice@example.com>", creation_time, one_year);

        let expiration = expiration_time(&cert).unwrap().expect("expected Some");
        let expected: chrono::DateTime<chrono::Utc> = (creation_time + one_year).into();
        assert_eq!(expiration, expected);
    }
}
