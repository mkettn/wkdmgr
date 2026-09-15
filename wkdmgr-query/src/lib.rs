use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub db_path: Arc<PathBuf>,
    /// A lazily-(re)opened read-only handle, shared across requests so
    /// the hot path doesn't reopen SQLite on every lookup. `None` means
    /// the last open attempt failed (or none has been made yet); the
    /// next request retries it. See `AppState::new` for the startup
    /// diagnostic this enables.
    pub db: Arc<Mutex<Option<Connection>>>,
    pub allowed_domains: Arc<Vec<String>>,
}

impl AppState {
    /// Attempt to open `db_path` once up front so a misconfigured path or
    /// permissions problem produces a loud, immediate `error!` log at
    /// startup instead of only ever showing up as a per-request `404`
    /// with a buried `warn!`. Deliberately does not fail startup on
    /// error: `wkdmgr-query` may legitimately start before
    /// `wkdmgr-mgmt` has created the database for the first time, and
    /// this same path is retried lazily on every subsequent request.
    pub fn new(db_path: PathBuf, allowed_domains: Vec<String>) -> Self {
        let initial_conn = match wkdmgr_core::storage::open_read_only(&db_path) {
            Ok(conn) => Some(conn),
            Err(e) => {
                tracing::error!(
                    "could not open database {} at startup ({e}); every WKD lookup will 404 \
                     until this is fixed. Retrying lazily on each request -- verify db_path, \
                     its permissions, and that wkdmgr-mgmt has created it.",
                    db_path.display()
                );
                None
            }
        };
        Self {
            db_path: Arc::new(db_path),
            db: Arc::new(Mutex::new(initial_conn)),
            allowed_domains: Arc::new(allowed_domains),
        }
    }
}

/// Build the `wkdmgr-query` router: public, unauthenticated, read-only WKD
/// lookups plus the required policy endpoints. No mutation of the SQLite
/// database ever happens through this router.
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/openpgpkey/policy", get(direct_policy))
        .route("/.well-known/openpgpkey/hu/{hash}", get(direct_hu))
        .route(
            "/.well-known/openpgpkey/{domain}/policy",
            get(advanced_policy),
        )
        .route(
            "/.well-known/openpgpkey/{domain}/hu/{hash}",
            get(advanced_hu),
        )
        .with_state(state)
}

async fn direct_policy() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/plain")], "")
}

async fn advanced_policy(Path(_domain): Path<String>) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/plain")], "")
}

async fn direct_hu(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    let Some(domain) = domain_from_host_header(&headers) else {
        return not_found();
    };
    lookup_and_respond(&state, &domain, &hash).await
}

async fn advanced_hu(
    State(state): State<AppState>,
    Path((domain, hash)): Path<(String, String)>,
) -> Response {
    lookup_and_respond(&state, &domain, &hash).await
}

fn domain_from_host_header(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    // Strip a port, if present. IPv6 literal hosts aren't a concern here
    // (WKD domains are DNS names), so a simple rsplit on ':' is fine.
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Look up a key by (domain, wkd_hash) and return it verbatim, or a bare
/// 404 for any reason at all (unknown domain, unknown hash, DB not yet
/// created). The response shape never differs between "no such user" and
/// "user exists but no key": both are this same 404.
async fn lookup_and_respond(state: &AppState, domain: &str, hash: &str) -> Response {
    let domain_lc = domain.to_ascii_lowercase();
    if !state
        .allowed_domains
        .iter()
        .any(|d| d.eq_ignore_ascii_case(&domain_lc))
    {
        return not_found();
    }

    let db = state.db.clone();
    let db_path = state.db_path.as_ref().clone();
    let hash_owned = hash.to_string();
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<Vec<u8>>> {
        let mut guard = db.lock().expect("query db mutex poisoned");
        if guard.is_none() {
            // Startup's open attempt failed, or this is the first
            // request since boot before wkdmgr-mgmt ever created the
            // file: retry lazily and cache the handle on success so we
            // don't reopen SQLite on every single lookup thereafter.
            match wkdmgr_core::storage::open_read_only(&db_path) {
                Ok(conn) => *guard = Some(conn),
                Err(e) => {
                    tracing::warn!("could not open database {}: {e}", db_path.display());
                    return Ok(None);
                }
            }
        }
        let conn = guard.as_ref().expect("just ensured Some above");
        let outcome = wkdmgr_core::storage::lookup_key_data(conn, &domain_lc, &hash_owned);
        if outcome.is_err() {
            // The cached handle can outlive what it points to -- the
            // file replaced by a backup restore or an atomic deploy
            // rename, or a transient IO fault. Drop it so the next
            // request reopens from scratch instead of every future
            // lookup failing the same way until the process is
            // restarted.
            *guard = None;
        }
        outcome
    })
    .await;

    match result {
        Ok(Ok(Some(data))) => {
            ([(header::CONTENT_TYPE, "application/octet-stream")], data).into_response()
        }
        Ok(Ok(None)) => not_found(),
        Ok(Err(e)) => {
            tracing::warn!("query lookup failed: {e}");
            not_found()
        }
        Err(e) => {
            tracing::warn!("query lookup task panicked: {e}");
            not_found()
        }
    }
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cached connection must be dropped when a query through it
    /// fails, not kept around to fail the same way on every future
    /// request -- otherwise the DB being replaced out from under it (a
    /// backup restore, an atomic deploy rename) or a transient IO fault
    /// permanently 404s every lookup until the process restarts.
    #[tokio::test]
    async fn cached_connection_is_invalidated_on_error_and_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite3");

        // Seed a valid database with one key, the way wkdmgr-mgmt would.
        {
            let mut conn = wkdmgr_core::storage::open_writable(&db_path).unwrap();
            wkdmgr_core::storage::insert_key(
                &mut conn,
                &wkdmgr_core::storage::NewKey {
                    uid: "alice",
                    domain: "example.com",
                    address: "alice@example.com",
                    wkd_hash: "somehash",
                    fingerprint: "ABCD1234",
                    key_data: b"key bytes",
                    revoked: false,
                    expires_at: None,
                },
                false,
            )
            .unwrap();
        }

        let state = AppState::new(db_path.clone(), vec!["example.com".to_string()]);

        // A normal lookup succeeds and caches the connection.
        let ok = lookup_and_respond(&state, "example.com", "somehash").await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert!(state.db.lock().unwrap().is_some());

        // Swap in a connection to a schema-less database, simulating a
        // cached handle that's gone bad. The next query through it must
        // fail with "no such table: keys"...
        let broken = rusqlite::Connection::open_in_memory().unwrap();
        *state.db.lock().unwrap() = Some(broken);

        let failed = lookup_and_respond(&state, "example.com", "somehash").await;
        assert_eq!(failed.status(), StatusCode::NOT_FOUND);
        // ...and that must clear the cache, not keep the bad handle.
        assert!(state.db.lock().unwrap().is_none());

        // The next lookup reopens db_path (still valid) from scratch and
        // recovers on its own, no restart needed.
        let recovered = lookup_and_respond(&state, "example.com", "somehash").await;
        assert_eq!(recovered.status(), StatusCode::OK);
    }
}
