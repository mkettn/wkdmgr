//! SQLite storage: the single source of truth for published keys.
//! `wkdmgr-mgmt` is the sole writer; `wkdmgr-query` opens the same file
//! read-only. These helpers are synchronous (`rusqlite` is sync) —
//! callers on an async runtime should invoke them via
//! `tokio::task::spawn_blocking`.

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;

/// The full schema, as it currently ships. Pre-1.0, there's no released
/// version and no database anyone needs to keep across a schema change --
/// the answer to an old on-disk shape is "delete it and start over", not
/// "migrate it" -- so every column lives here rather than being bolted
/// on via `MIGRATIONS` after the fact.
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

/// Migrations applied on top of `SCHEMA`, tracked via `PRAGMA
/// user_version` so `open_writable` brings an *already-existing*
/// database up to date -- for the first post-1.0 column, not for any
/// shape from before this shipped (see `SCHEMA`'s doc comment). Empty
/// for now; the mechanism is kept wired up and exercised
/// (`open_writable_is_idempotent_across_repeated_opens`) so the first
/// real entry lands on a tested path.
///
/// Append-only from here: add new entries at the end; never edit or
/// reorder one that has already shipped, since `user_version` records
/// how many of these have already run.
const MIGRATIONS: &[&str] = &[];

/// Applies each pending migration in its own transaction -- the DDL and
/// the `user_version` bump that records it happening atomically, so a
/// crash between them can never leave a column added but `user_version`
/// still reporting it pending (which would otherwise fail every
/// subsequent start with "duplicate column name", permanently, until
/// someone hand-edits `user_version`).
fn run_migrations(conn: &Connection) -> rusqlite::Result<()> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let current = usize::try_from(current.max(0)).unwrap_or(0);
    for (i, migration) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(migration)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}

/// Fixed-precision RFC3339 (whole seconds, `Z` suffix) so timestamp
/// columns compared or sorted as plain strings behave correctly --
/// `DateTime::to_rfc3339()`'s default variable-width fractional seconds
/// (present only when nonzero) would otherwise make same-second values
/// compare inconsistently.
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
/// mode, and ensure the schema is fully up to date (base schema, then
/// any pending `MIGRATIONS`). Only `wkdmgr-mgmt` should call this.
pub fn open_writable(db_path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(SCHEMA)?;
    run_migrations(&conn)?;
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
    /// The row at `(domain, wkd_hash)` is owned by neither the caller
    /// nor the uid `replace_if_owned_by` named -- e.g. a concurrent
    /// upload replaced it between the caller's `UserDb` check and this
    /// call. Distinct from `Duplicate` so the caller can give a message
    /// that doesn't claim the caller's own key is what's in the way.
    #[error(
        "a key already exists for this domain/address, owned by someone else who still owns it"
    )]
    OwnedByOther,
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

/// Who (if anyone) currently owns the row at `(domain, wkd_hash)`. The
/// caller uses this *before* calling `insert_key` to decide whether a
/// different existing owner represents a genuine reassignment (that
/// uid's `UserDb`-reported addresses no longer include this one) or
/// concurrent/shared ownership (it still does) -- `insert_key` itself
/// has no access to `UserDb` and can't tell the two apart on its own.
pub fn existing_owner(
    conn: &Connection,
    domain: &str,
    wkd_hash: &str,
) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT uid FROM keys WHERE domain = ?1 AND wkd_hash = ?2",
        params![domain, wkd_hash],
        |row| row.get(0),
    )
    .optional()
}

/// Insert a newly-uploaded, minimized key.
///
/// If a key is already published at this `(domain, wkd_hash)` under the
/// *same* uid, this always fails with `InsertError::Duplicate`:
/// requiring an explicit delete first for your own key keeps the API
/// contract's "don't silently overwrite" guarantee.
///
/// If it's published under a *different* uid, the caller authorizes a
/// replacement by passing that uid as `replace_if_owned_by` (see
/// `existing_owner`) -- only after independently confirming via
/// `UserDb` that the uid no longer owns the address (a genuine
/// reassignment; see `wkdmgr_mgmt`'s `upload_key` handler). The row's
/// *current* owner is re-read inside this function's own transaction
/// and compared against `replace_if_owned_by` -- carrying the identity
/// the decision was made about, rather than a bare `bool` conclusion,
/// means a row that changed hands between the caller's check and this
/// call (e.g. a concurrent upload) fails closed as `OwnedByOther`
/// instead of deleting whoever's row happens to be there now. Passing
/// `None` -- e.g. a shared/role address the existing uid still owns
/// too -- 409s the same as the same-uid case, rather than silently
/// handing the address to whoever uploads next.
pub fn insert_key(
    conn: &mut Connection,
    new_key: &NewKey,
    replace_if_owned_by: Option<&str>,
) -> Result<KeyRecord, InsertError> {
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
        Some(ref existing) if replace_if_owned_by == Some(existing.as_str()) => {
            tx.execute(
                "DELETE FROM keys WHERE domain = ?1 AND wkd_hash = ?2",
                params![new_key.domain, new_key.wkd_hash],
            )?;
        }
        Some(_) => {
            return Err(InsertError::OwnedByOther);
        }
        None => {}
    }

    let uploaded_at = rfc3339_secs(Utc::now());
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
            None,
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
            None,
        )
        .unwrap();

        let err = insert_key(
            &mut conn,
            &new_key("alice", "alice@example.com", "EEEE5678", b"other key bytes"),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, InsertError::Duplicate));
    }

    /// The address-reassignment fix: a different uid uploading for an
    /// address already on file under someone else replaces that row
    /// when the caller has told `insert_key` to (`replace_if_owned_by =
    /// Some("alice")`) -- which the mgmt handler only does after
    /// confirming via `UserDb` that the *old* uid no longer owns the
    /// address.
    #[test]
    fn upload_from_new_owner_replaces_old_owners_row_when_told_to() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let mut conn = open_writable(&db_path).unwrap();

        let old = insert_key(
            &mut conn,
            &new_key("alice", "role@example.com", "AAAA1111", b"alice's key"),
            None,
        )
        .unwrap();

        let new = insert_key(
            &mut conn,
            &new_key("bob", "role@example.com", "BBBB2222", b"bob's key"),
            Some("alice"),
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

    /// The shared/concurrent-ownership fix: without a matching
    /// `replace_if_owned_by`, a different uid's upload still 409s
    /// instead of silently taking over the address -- this is what the
    /// mgmt handler does when the existing row's uid still owns the
    /// address per `UserDb` too (a role address two people legitimately
    /// hold at once), as opposed to a genuine reassignment. It's
    /// `OwnedByOther` rather than `Duplicate`: the caller's own key
    /// isn't what's in the way, someone else's still-valid one is.
    #[test]
    fn upload_from_different_owner_without_matching_replace_authorization_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let mut conn = open_writable(&db_path).unwrap();

        insert_key(
            &mut conn,
            &new_key("alice", "support@example.com", "AAAA1111", b"alice's key"),
            None,
        )
        .unwrap();

        let err = insert_key(
            &mut conn,
            &new_key("bob", "support@example.com", "BBBB2222", b"bob's key"),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, InsertError::OwnedByOther));

        // Alice's row is untouched.
        let alices_keys = list_keys_for_uid(&conn, "alice").unwrap();
        assert_eq!(alices_keys.len(), 1);
        assert_eq!(alices_keys[0].fingerprint, "AAAA1111");
        assert!(list_keys_for_uid(&conn, "bob").unwrap().is_empty());
        let data = lookup_key_data(&conn, "example.com", "somehash").unwrap();
        assert_eq!(data, Some(b"alice's key".to_vec()));
    }

    /// The TOCTOU fix: `replace_if_owned_by` carries the identity the
    /// caller's decision was made about, and `insert_key` re-checks it
    /// against the row's *current* owner inside its own transaction --
    /// so a row that changed hands between the caller's `UserDb` check
    /// and this call (a concurrent upload winning the race) is never
    /// silently deleted out from under its new, legitimate owner.
    #[test]
    fn stale_replace_authorization_does_not_delete_a_different_current_owners_row() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let mut conn = open_writable(&db_path).unwrap();

        // alice originally owned the address; a caller peeked that and
        // (elsewhere, not modeled here) confirmed via UserDb that alice
        // no longer owns it, authorizing replacement with
        // `Some("alice")`.
        insert_key(
            &mut conn,
            &new_key("alice", "support@example.com", "AAAA1111", b"alice's key"),
            None,
        )
        .unwrap();

        // Before that authorized replacement lands, carol -- who still
        // legitimately co-owns the address -- uploads first, replacing
        // alice's row for real (Some("alice") correctly matches the
        // current owner here).
        insert_key(
            &mut conn,
            &new_key("carol", "support@example.com", "CCCC3333", b"carol's key"),
            Some("alice"),
        )
        .unwrap();

        // The original caller's insert now arrives, still carrying the
        // stale `Some("alice")` authorization -- but the row's current
        // owner is carol, not alice, so this must fail closed rather
        // than deleting carol's still-current key.
        let err = insert_key(
            &mut conn,
            &new_key("bob", "support@example.com", "BBBB2222", b"bob's key"),
            Some("alice"),
        )
        .unwrap_err();
        assert!(matches!(err, InsertError::OwnedByOther));

        let carols_keys = list_keys_for_uid(&conn, "carol").unwrap();
        assert_eq!(carols_keys.len(), 1);
        assert_eq!(carols_keys[0].fingerprint, "CCCC3333");
        assert!(list_keys_for_uid(&conn, "bob").unwrap().is_empty());
        let data = lookup_key_data(&conn, "example.com", "somehash").unwrap();
        assert_eq!(data, Some(b"carol's key".to_vec()));
    }

    #[test]
    fn existing_owner_reports_current_uid_or_none() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let mut conn = open_writable(&db_path).unwrap();

        assert_eq!(
            existing_owner(&conn, "example.com", "somehash").unwrap(),
            None
        );

        insert_key(
            &mut conn,
            &new_key("alice", "alice@example.com", "ABCD1234", b"key bytes"),
            None,
        )
        .unwrap();

        assert_eq!(
            existing_owner(&conn, "example.com", "somehash").unwrap(),
            Some("alice".to_string())
        );
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
                None,
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
        let rec = insert_key(&mut conn, &key, None).unwrap();
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
        let rec = insert_key(&mut conn, &key, None).unwrap();
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
        insert_key(&mut conn, &key, None).unwrap();

        let data = lookup_key_data(&conn, "example.com", "somehash").unwrap();
        assert_eq!(data, Some(b"live key bytes".to_vec()));
    }

    #[test]
    fn rfc3339_secs_sorts_consistently() {
        let earlier = Utc::now();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let later = Utc::now();
        assert!(rfc3339_secs(earlier) < rfc3339_secs(later));
    }

    #[test]
    fn open_writable_is_idempotent_across_repeated_opens() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");

        open_writable(&db_path).unwrap();
        // Re-running migrations against an already-migrated database
        // must not error (e.g. "duplicate column").
        let mut conn = open_writable(&db_path).unwrap();
        insert_key(
            &mut conn,
            &new_key("alice", "alice@example.com", "ABCD1234", b"key bytes"),
            None,
        )
        .unwrap();
    }

    /// The migration-atomicity fix: applying a migration and stamping
    /// `user_version` happen in one transaction, so a migration that
    /// fails partway through -- or a process that dies between the DDL
    /// and the stamp -- never leaves `user_version` claiming a migration
    /// ran when its DDL didn't commit (which would otherwise wedge every
    /// subsequent start: the same `ALTER TABLE` re-runs and fails with
    /// "duplicate column name", permanently, until someone hand-edits
    /// `user_version`).
    #[test]
    fn failed_migration_does_not_advance_user_version() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");
        let conn = open_writable(&db_path).unwrap();

        // Simulate a migration whose DDL fails outright (the column
        // already exists) -- `run_migrations` itself only ever runs
        // `MIGRATIONS` (currently empty), so this exercises the same
        // per-migration transaction directly.
        let before: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let result = (|| -> rusqlite::Result<()> {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch("ALTER TABLE keys ADD COLUMN revoked TEXT;")?;
            tx.pragma_update(None, "user_version", before + 1)?;
            tx.commit()
        })();
        assert!(result.is_err(), "duplicate column add must fail");

        let after: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(
            before, after,
            "a failed migration's transaction must not leave user_version bumped"
        );
    }
}
