//! SQLite storage: the single source of truth for published keys.
//! `wkdmgr-mgmt` is the sole writer; `wkdmgr-query` opens the same file
//! read-only. These helpers are synchronous (`rusqlite` is sync) —
//! callers on an async runtime should invoke them via
//! `tokio::task::spawn_blocking`.

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
    UNIQUE(domain, wkd_hash)
);
CREATE INDEX IF NOT EXISTS idx_keys_uid ON keys(uid);
CREATE INDEX IF NOT EXISTS idx_keys_domain_hash ON keys(domain, wkd_hash);
"#;

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

/// Insert a newly-uploaded, minimized key. Returns the new row id.
/// Fails with `InsertError::Duplicate` if `UNIQUE(domain, wkd_hash)` is
/// violated (i.e. a key is already published for this address).
///
/// `revoked` is computed by the caller (see
/// `wkdmgr_core::openpgp::is_revoked`) from the minimized `key_data`
/// itself at upload time. Because the only way revocation status can
/// change in this system is a fresh upload (delete-then-republish, per
/// the API contract), computing and caching it once here -- rather than
/// re-parsing on every lookup -- is both correct and cheap.
#[allow(clippy::too_many_arguments)]
pub fn insert_key(
    conn: &Connection,
    uid: &str,
    domain: &str,
    address: &str,
    wkd_hash: &str,
    fingerprint: &str,
    key_data: &[u8],
    revoked: bool,
) -> Result<KeyRecord, InsertError> {
    let uploaded_at = chrono::Utc::now().to_rfc3339();
    let result = conn.execute(
        "INSERT INTO keys (uid, domain, address, wkd_hash, fingerprint, key_data, uploaded_at, revoked) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            uid,
            domain,
            address,
            wkd_hash,
            fingerprint,
            key_data,
            uploaded_at,
            revoked,
        ],
    );
    match result {
        Ok(_) => Ok(KeyRecord {
            id: conn.last_insert_rowid(),
            uid: uid.to_string(),
            address: address.to_string(),
            domain: domain.to_string(),
            fingerprint: fingerprint.to_string(),
            uploaded_at,
            revoked,
        }),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(InsertError::Duplicate)
        }
        Err(e) => Err(InsertError::Sqlite(e)),
    }
}

/// List all keys owned by `uid`, most recently uploaded first.
pub fn list_keys_for_uid(conn: &Connection, uid: &str) -> rusqlite::Result<Vec<KeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, uid, address, domain, fingerprint, uploaded_at, revoked \
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
/// `wkdmgr-query`. A row marked `revoked` is never returned -- the
/// lookup behaves exactly as if no key were published for that address,
/// so a revoked key and an address with no key are indistinguishable on
/// the wire.
pub fn lookup_key_data(
    conn: &Connection,
    domain: &str,
    wkd_hash: &str,
) -> rusqlite::Result<Option<Vec<u8>>> {
    conn.query_row(
        "SELECT key_data FROM keys WHERE domain = ?1 AND wkd_hash = ?2 AND revoked = 0",
        params![domain, wkd_hash],
        |row| row.get(0),
    )
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_list_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let conn = open_writable(&db_path).unwrap();

        let rec = insert_key(
            &conn,
            "alice",
            "example.com",
            "alice@example.com",
            "somehash",
            "ABCD1234",
            b"key bytes",
            false,
        )
        .unwrap();
        assert_eq!(rec.uid, "alice");
        assert!(!rec.revoked);

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
    fn duplicate_domain_hash_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let conn = open_writable(&db_path).unwrap();

        insert_key(
            &conn,
            "alice",
            "example.com",
            "alice@example.com",
            "somehash",
            "ABCD1234",
            b"key bytes",
            false,
        )
        .unwrap();

        let err = insert_key(
            &conn,
            "alice",
            "example.com",
            "alice@example.com",
            "somehash",
            "EEEE5678",
            b"other key bytes",
            false,
        )
        .unwrap_err();
        assert!(matches!(err, InsertError::Duplicate));
    }

    #[test]
    fn query_binary_reads_via_readonly_handle() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        {
            let conn = open_writable(&db_path).unwrap();
            insert_key(
                &conn,
                "alice",
                "example.com",
                "alice@example.com",
                "somehash",
                "ABCD1234",
                b"key bytes",
                false,
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
        let conn = open_writable(&db_path).unwrap();

        let rec = insert_key(
            &conn,
            "alice",
            "example.com",
            "alice@example.com",
            "somehash",
            "ABCD1234",
            b"revoked key bytes",
            true,
        )
        .unwrap();
        assert!(rec.revoked);

        // Still visible to its owner (so they can see/manage it)...
        let keys = list_keys_for_uid(&conn, "alice").unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].revoked);

        // ...but never served over WKD: same as "no key published".
        let data = lookup_key_data(&conn, "example.com", "somehash").unwrap();
        assert_eq!(data, None);
    }
}
