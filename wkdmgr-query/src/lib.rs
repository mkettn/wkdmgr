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
        wkdmgr_core::storage::lookup_key_data(conn, &domain_lc, &hash_owned)
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
