//! SQLite storage: the single source of truth for published keys.
//! `wkdmgr-mgmt` is the sole writer; `wkdmgr-query` opens the same file
//! read-only. These helpers are synchronous (`rusqlite` is sync) —
//! callers on an async runtime should invoke them via
//! `tokio::task::spawn_blocking`.

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    uid         TEXT NOT NULL,
    domain      TEXT NOT NULL,
    address     TEXT NOT NULL,
    wkd_hash    TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    key_data    BLOB NOT NULL,
    uploaded_at TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    expires_at  TEXT,
    UNIQUE(domain, wkd_hash)
);
CREATE INDEX IF NOT EXISTS idx_keys_uid ON keys(uid);
CREATE INDEX IF NOT EXISTS idx_keys_domain_hash ON keys(domain, wkd_hash);
"#;

/// Fixed-precision RFC3339 (whole seconds, `Z` suffix) so `expires_at`
/// values and the `now` a lookup compares them against sort correctly as
/// plain strings -- `DateTime::to_rfc3339()`'s default variable-width
/// fractional seconds would otherwise make that comparison unreliable.
fn rfc3339_secs(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyRecord {
    pub id: i64,
    pub uid: String,
    pub address: String,
    pub domain: String,
    pub fingerprint: String,
    pub uploaded_at: String,
    /// Whether the stored (minimized) key was already revoked -- primary
    /// key or its sole retained User ID -- at the time it was uploaded.
    /// `wkdmgr-query` never serves a row with `revoked = true`.
    pub revoked: bool,
    /// RFC3339, if the key's primary key expires. `wkdmgr-query` never
    /// serves a row whose `expires_at` is in the past, so a key that was
    /// live at upload time stops being served on its own once it
    /// expires -- no re-upload needed to trigger that, unlike
    /// revocation.
    pub expires_at: Option<String>,
}

/// Open (creating if necessary) the database for read/write, enable WAL
/// mode, and ensure the schema exists. Only `wkdmgr-mgmt` should call
/// this.
pub fn open_writable(db_path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Open the database strictly read-only. `wkdmgr-query` uses this
/// exclusively and never writes through it.
pub fn open_read_only(db_path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

#[derive(Debug, thiserror::Error)]
pub enum InsertError {
    #[error("a key already exists for this domain/address")]
    Duplicate,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// A newly-uploaded, minimized key ready to store.
pub struct NewKey<'a> {
    pub uid: &'a str,
    pub domain: &'a str,
    pub address: &'a str,
    pub wkd_hash: &'a str,
    pub fingerprint: &'a str,
    pub key_data: &'a [u8],
    /// Computed by the caller (see `wkdmgr_core::openpgp::is_revoked`)
    /// from `key_data` itself at upload time. Because the only way
    /// revocation status can change in this system is a fresh upload,
    /// computing and caching it once here -- rather than re-parsing on
    /// every lookup -- is both correct and cheap.
    pub revoked: bool,
    /// From `wkdmgr_core::openpgp::expiration_time`. `None` for a
    /// non-expiring key.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Insert a newly-uploaded, minimized key, or -- if a key is already
/// published at this `(domain, wkd_hash)` under a *different* uid --
/// replace it, since a currently-verified owner (the caller has already
/// checked `new_key.uid` against `UserDb` before calling this) has to
/// have some way to reclaim an address that was reassigned to them:
/// without this, the old owner's stale key would keep being served
/// forever, and the new owner could never publish (`UNIQUE(domain,
/// wkd_hash)` would 409 them, and uid-scoped delete can't touch a row it
/// doesn't own either). If the existing row is already owned by
/// `new_key.uid`, this still fails with `InsertError::Duplicate` --
/// requiring an explicit delete first for your *own* key keeps the
/// "don't silently overwrite" guarantee the API contract makes for that
/// case.
pub fn insert_key(conn: &mut Connection, new_key: &NewKey) -> Result<KeyRecord, InsertError> {
    let tx = conn.transaction()?;

    let existing_uid: Option<String> = tx
        .query_row(
            "SELECT uid FROM keys WHERE domain = ?1 AND wkd_hash = ?2",
            params![new_key.domain, new_key.wkd_hash],
            |row| row.get(0),
        )
        .optional()?;

    match existing_uid {
        Some(ref existing) if existing == new_key.uid => {
            return Err(InsertError::Duplicate);
        }
        Some(_) => {
            // Owned by someone else on record: the address has been
            // reassigned to the caller. Replace, don't 409.
            tx.execute(
                "DELETE FROM keys WHERE domain = ?1 AND wkd_hash = ?2",
                params![new_key.domain, new_key.wkd_hash],
            )?;
        }
        None => {}
    }

    let uploaded_at = Utc::now().to_rfc3339();
    let expires_at = new_key.expires_at.map(rfc3339_secs);
    tx.execute(
        "INSERT INTO keys (uid, domain, address, wkd_hash, fingerprint, key_data, uploaded_at, revoked, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            new_key.uid,
            new_key.domain,
            new_key.address,
            new_key.wkd_hash,
            new_key.fingerprint,
            new_key.key_data,
            uploaded_at,
            new_key.revoked,
            expires_at,
        ],
    )?;
    let id = tx.last_insert_rowid();
    tx.commit()?;

    Ok(KeyRecord {
        id,
        uid: new_key.uid.to_string(),
        address: new_key.address.to_string(),
        domain: new_key.domain.to_string(),
        fingerprint: new_key.fingerprint.to_string(),
        uploaded_at,
        revoked: new_key.revoked,
        expires_at,
    })
}

/// List all keys owned by `uid`, most recently uploaded first.
pub fn list_keys_for_uid(conn: &Connection, uid: &str) -> rusqlite::Result<Vec<KeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, uid, address, domain, fingerprint, uploaded_at, revoked, expires_at \
         FROM keys WHERE uid = ?1 ORDER BY uploaded_at DESC",
    )?;
    let rows = stmt.query_map(params![uid], |row| {
        Ok(KeyRecord {
            id: row.get(0)?,
            uid: row.get(1)?,
            address: row.get(2)?,
            domain: row.get(3)?,
            fingerprint: row.get(4)?,
            uploaded_at: row.get(5)?,
            revoked: row.get(6)?,
            expires_at: row.get(7)?,
        })
    })?;
    rows.collect()
}

/// Delete the key with the given `id`, but only if it's owned by `uid`.
/// Returns `true` if a row was deleted. This is the sole authorization
/// check for revocation: the `uid` in the `WHERE` clause, not just
/// application-level logic.
pub fn delete_key_for_uid(conn: &Connection, id: i64, uid: &str) -> rusqlite::Result<bool> {
    let affected = conn.execute(
        "DELETE FROM keys WHERE id = ?1 AND uid = ?2",
        params![id, uid],
    )?;
    Ok(affected > 0)
}

/// Look up the raw minimized key bytes for a WKD request. Used only by
/// `wkdmgr-query`. A row marked `revoked`, or whose `expires_at` is in
/// the past, is never returned -- the lookup behaves exactly as if no
/// key were published for that address, so neither is distinguishable
/// on the wire from "no key published".
pub fn lookup_key_data(
    conn: &Connection,
    domain: &str,
    wkd_hash: &str,
) -> rusqlite::Result<Option<Vec<u8>>> {
    let now = rfc3339_secs(Utc::now());
    conn.query_row(
        "SELECT key_data FROM keys \
         WHERE domain = ?1 AND wkd_hash = ?2 AND revoked = 0 \
           AND (expires_at IS NULL OR expires_at > ?3)",
        params![domain, wkd_hash, now],
        |row| row.get(0),
    )
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn new_key<'a>(
        uid: &'a str,
        address: &'a str,
        fingerprint: &'a str,
        key_data: &'a [u8],
    ) -> NewKey<'a> {
        NewKey {
            uid,
            domain: "example.com",
            address,
            wkd_hash: "somehash",
            fingerprint,
            key_data,
            revoked: false,
            expires_at: None,
        }
    }

    #[test]
    fn insert_list_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let mut conn = open_writable(&db_path).unwrap();

        let rec = insert_key(
            &mut conn,
            &new_key("alice", "alice@example.com", "ABCD1234", b"key bytes"),
        )
        .unwrap();
        assert_eq!(rec.uid, "alice");
        assert!(!rec.revoked);
        assert_eq!(rec.expires_at, None);

        let keys = list_keys_for_uid(&conn, "alice").unwrap();
        assert_eq!(keys.len(), 1);
        assert!(!keys[0].revoked);

        let other = list_keys_for_uid(&conn, "bob").unwrap();
        assert!(other.is_empty());

        // Wrong uid cannot delete alice's key.
        assert!(!delete_key_for_uid(&conn, rec.id, "bob").unwrap());
        assert!(delete_key_for_uid(&conn, rec.id, "alice").unwrap());
        assert!(list_keys_for_uid(&conn, "alice").unwrap().is_empty());
    }

    #[test]
    fn duplicate_domain_hash_from_same_owner_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let mut conn = open_writable(&db_path).unwrap();

        insert_key(
            &mut conn,
            &new_key("alice", "alice@example.com", "ABCD1234", b"key bytes"),
        )
        .unwrap();

        let err = insert_key(
            &mut conn,
            &new_key("alice", "alice@example.com", "EEEE5678", b"other key bytes"),
        )
        .unwrap_err();
        assert!(matches!(err, InsertError::Duplicate));
    }

    /// The address-reassignment fix: a different, now-verified uid
    /// uploading for an address already on file under someone else
    /// replaces that row instead of 409ing forever.
    #[test]
    fn upload_from_new_owner_replaces_old_owners_row() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let mut conn = open_writable(&db_path).unwrap();

        let old = insert_key(
            &mut conn,
            &new_key("alice", "role@example.com", "AAAA1111", b"alice's key"),
        )
        .unwrap();

        let new = insert_key(
            &mut conn,
            &new_key("bob", "role@example.com", "BBBB2222", b"bob's key"),
        )
        .unwrap();
        assert_eq!(new.uid, "bob");
        assert_ne!(new.id, old.id);

        // Alice's row is gone entirely, not just hidden.
        assert!(list_keys_for_uid(&conn, "alice").unwrap().is_empty());
        let bobs_keys = list_keys_for_uid(&conn, "bob").unwrap();
        assert_eq!(bobs_keys.len(), 1);
        assert_eq!(bobs_keys[0].fingerprint, "BBBB2222");

        // The address now serves bob's key.
        let data = lookup_key_data(&conn, "example.com", "somehash").unwrap();
        assert_eq!(data, Some(b"bob's key".to_vec()));
    }

    #[test]
    fn query_binary_reads_via_readonly_handle() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        {
            let mut conn = open_writable(&db_path).unwrap();
            insert_key(
                &mut conn,
                &new_key("alice", "alice@example.com", "ABCD1234", b"key bytes"),
            )
            .unwrap();
        }

        let ro = open_read_only(&db_path).unwrap();
        let data = lookup_key_data(&ro, "example.com", "somehash").unwrap();
        assert_eq!(data, Some(b"key bytes".to_vec()));

        let missing = lookup_key_data(&ro, "example.com", "nope").unwrap();
        assert_eq!(missing, None);
    }

    #[test]
    fn revoked_row_is_never_served() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let mut conn = open_writable(&db_path).unwrap();

        let mut key = new_key(
            "alice",
            "alice@example.com",
            "ABCD1234",
            b"revoked key bytes",
        );
        key.revoked = true;
        let rec = insert_key(&mut conn, &key).unwrap();
        assert!(rec.revoked);

        // Still visible to its owner (so they can see/manage it)...
        let keys = list_keys_for_uid(&conn, "alice").unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].revoked);

        // ...but never served over WKD: same as "no key published".
        let data = lookup_key_data(&conn, "example.com", "somehash").unwrap();
        assert_eq!(data, None);
    }

    #[test]
    fn expired_row_is_never_served_but_stays_listed() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let mut conn = open_writable(&db_path).unwrap();

        let mut key = new_key(
            "alice",
            "alice@example.com",
            "ABCD1234",
            b"expired key bytes",
        );
        key.expires_at = Some(Utc::now() - chrono::Duration::days(1));
        let rec = insert_key(&mut conn, &key).unwrap();
        assert!(rec.expires_at.is_some());

        assert_eq!(list_keys_for_uid(&conn, "alice").unwrap().len(), 1);
        let data = lookup_key_data(&conn, "example.com", "somehash").unwrap();
        assert_eq!(data, None);
    }

    #[test]
    fn not_yet_expired_row_is_served() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let mut conn = open_writable(&db_path).unwrap();

        let mut key = new_key("alice", "alice@example.com", "ABCD1234", b"live key bytes");
        key.expires_at = Some(Utc::now() + chrono::Duration::days(365));
        insert_key(&mut conn, &key).unwrap();

        let data = lookup_key_data(&conn, "example.com", "somehash").unwrap();
        assert_eq!(data, Some(b"live key bytes".to_vec()));
    }

    #[test]
    fn rfc3339_secs_sorts_consistently() {
        let earlier = Utc::now();
        std::thread::sleep(Duration::from_millis(1100));
        let later = Utc::now();
        assert!(rfc3339_secs(earlier) < rfc3339_secs(later));
    }
}
