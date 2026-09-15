use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wkdmgr_core::openpgp::KeyError;
use wkdmgr_core::UserDb;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub allowed_domains: Arc<Vec<String>>,
    pub sso_header_name: Arc<String>,
    pub userdb: Arc<dyn UserDb>,
    pub hooks_dir: Arc<PathBuf>,
    pub hook_timeout: Duration,
}

/// Build the `wkdmgr-mgmt` router: the SSO-gated JSON API under `/api`,
/// plus (if `frontend_dist_dir` is `Some`) a static-file fallback route
/// serving the built Vue frontend.
pub fn build_app(state: AppState, frontend_dist_dir: Option<PathBuf>) -> Router {
    let api = Router::new()
        .route("/me", get(get_me))
        .route("/keys", get(list_keys).post(upload_key))
        .route("/keys/{id}", axum::routing::delete(delete_key))
        .with_state(state);

    let mut app = Router::new().nest("/api", api);

    if let Some(dir) = frontend_dist_dir {
        if dir.is_dir() {
            let serve_dir =
                tower_http::services::ServeDir::new(&dir).append_index_html_on_directories(true);
            app = app.fallback_service(serve_dir);
        } else {
            tracing::warn!(
                "frontend_dist_dir {} does not exist; static frontend will not be served",
                dir.display()
            );
        }
    }

    app
}

// ---------------------------------------------------------------------
// Auth extractor
// ---------------------------------------------------------------------

pub struct AuthenticatedUid(pub String);

impl FromRequestParts<AppState> for AuthenticatedUid {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get(state.sso_header_name.as_str())
            .ok_or_else(ApiError::unauthenticated)?
            .to_str()
            .map_err(|_| ApiError::unauthenticated())?;
        if value.is_empty() {
            return Err(ApiError::unauthenticated());
        }
        Ok(AuthenticatedUid(value.to_string()))
    }
}

// ---------------------------------------------------------------------
// Error type: JSON body with a fixed `error` code and human `message`.
// ---------------------------------------------------------------------

pub struct ApiError {
    status: StatusCode,
    error: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, error: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            error,
            message: message.into(),
        }
    }

    fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "the SSO proxy header is missing; this should only happen if the reverse proxy is \
             misconfigured",
        )
    }

    fn address_not_owned(address: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "address_not_owned",
            format!("{address} is not one of your addresses"),
        )
    }

    fn domain_not_served(domain: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "address_not_owned",
            format!("{domain} is not a domain served by this instance"),
        )
    }

    fn already_exists(address: &str) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "already_exists",
            format!("a key already exists for {address}; delete it first"),
        )
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "not found")
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }

    fn userdb_unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, "userdb_unavailable", message)
    }

    fn from_key_error(e: KeyError) -> Self {
        match e {
            KeyError::ParseFailed(m) => Self::new(StatusCode::BAD_REQUEST, "parse_failed", m),
            KeyError::InvalidPrimaryKey(m) => Self::new(StatusCode::BAD_REQUEST, "parse_failed", m),
            KeyError::NoMatchingUserId(address) => Self::new(
                StatusCode::BAD_REQUEST,
                "no_matching_uid",
                format!("the key has no valid signature for {address}"),
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.error,
            "message": self.message,
        }));
        (self.status, body).into_response()
    }
}

// ---------------------------------------------------------------------
// GET /api/me
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct MeResponse {
    uid: String,
    addresses: Vec<String>,
}

async fn get_me(
    State(state): State<AppState>,
    uid: AuthenticatedUid,
) -> Result<Json<MeResponse>, ApiError> {
    let addresses = state
        .userdb
        .addresses_for_user(&uid.0)
        .await
        .map_err(|e| ApiError::userdb_unavailable(e.to_string()))?;
    Ok(Json(MeResponse {
        uid: uid.0,
        addresses,
    }))
}

// ---------------------------------------------------------------------
// GET /api/keys
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct KeyResponseItem {
    id: String,
    address: String,
    domain: String,
    fingerprint: String,
    uploaded_at: String,
}

impl From<wkdmgr_core::storage::KeyRecord> for KeyResponseItem {
    fn from(r: wkdmgr_core::storage::KeyRecord) -> Self {
        Self {
            id: r.id.to_string(),
            address: r.address,
            domain: r.domain,
            fingerprint: r.fingerprint,
            uploaded_at: r.uploaded_at,
        }
    }
}

async fn list_keys(
    State(state): State<AppState>,
    uid: AuthenticatedUid,
) -> Result<Json<Vec<KeyResponseItem>>, ApiError> {
    let db = state.db.clone();
    let uid_owned = uid.0.clone();
    let records = tokio::task::spawn_blocking(move || {
        let conn = db.lock().expect("db mutex poisoned");
        wkdmgr_core::storage::list_keys_for_uid(&conn, &uid_owned)
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(records.into_iter().map(Into::into).collect()))
}

// ---------------------------------------------------------------------
// POST /api/keys
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct UploadRequest {
    address: String,
    key: String,
}

async fn upload_key(
    State(state): State<AppState>,
    uid: AuthenticatedUid,
    Json(body): Json<UploadRequest>,
) -> Result<(StatusCode, Json<KeyResponseItem>), ApiError> {
    let owned_addresses = state
        .userdb
        .addresses_for_user(&uid.0)
        .await
        .map_err(|e| ApiError::userdb_unavailable(e.to_string()))?;
    if !owned_addresses
        .iter()
        .any(|a| a.eq_ignore_ascii_case(&body.address))
    {
        return Err(ApiError::address_not_owned(&body.address));
    }

    let (wkd_hash, domain) = wkdmgr_core::wkd_hash::wkd_hash_for_address(&body.address)
        .map_err(|_| ApiError::address_not_owned(&body.address))?;
    if !state
        .allowed_domains
        .iter()
        .any(|d| d.eq_ignore_ascii_case(&domain))
    {
        return Err(ApiError::domain_not_served(&domain));
    }

    let cert =
        wkdmgr_core::openpgp::parse_key_material(&body.key).map_err(ApiError::from_key_error)?;
    wkdmgr_core::openpgp::validate_for_address(&cert, &body.address)
        .map_err(ApiError::from_key_error)?;
    let minimized = wkdmgr_core::openpgp::minimize_for_address(&cert, &body.address)
        .map_err(ApiError::from_key_error)?;
    let fingerprint = wkdmgr_core::openpgp::fingerprint_hex(&cert);

    let db = state.db.clone();
    let uid_owned = uid.0.clone();
    let address = body.address.clone();
    let domain_owned = domain.clone();
    let wkd_hash_owned = wkd_hash.clone();
    let fingerprint_owned = fingerprint.clone();
    let minimized_for_insert = minimized.clone();

    let insert_result = tokio::task::spawn_blocking(move || {
        let conn = db.lock().expect("db mutex poisoned");
        wkdmgr_core::storage::insert_key(
            &conn,
            &uid_owned,
            &domain_owned,
            &address,
            &wkd_hash_owned,
            &fingerprint_owned,
            &minimized_for_insert,
        )
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let record = match insert_result {
        Ok(rec) => rec,
        Err(wkdmgr_core::storage::InsertError::Duplicate) => {
            return Err(ApiError::already_exists(&body.address))
        }
        Err(e) => return Err(ApiError::internal(e.to_string())),
    };

    wkdmgr_core::hooks::run_on_key_add(
        &state.hooks_dir,
        &body.address,
        &domain,
        &minimized,
        state.hook_timeout,
    )
    .await;

    Ok((StatusCode::CREATED, Json(record.into())))
}

// ---------------------------------------------------------------------
// DELETE /api/keys/:id
// ---------------------------------------------------------------------

async fn delete_key(
    State(state): State<AppState>,
    uid: AuthenticatedUid,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let db = state.db.clone();
    let uid_owned = uid.0.clone();

    let removed = tokio::task::spawn_blocking(
        move || -> rusqlite::Result<Option<wkdmgr_core::storage::KeyRecord>> {
            let conn = db.lock().expect("db mutex poisoned");
            let records = wkdmgr_core::storage::list_keys_for_uid(&conn, &uid_owned)?;
            let Some(target) = records.into_iter().find(|r| r.id == id) else {
                return Ok(None);
            };
            if wkdmgr_core::storage::delete_key_for_uid(&conn, id, &uid_owned)? {
                Ok(Some(target))
            } else {
                Ok(None)
            }
        },
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::internal(e.to_string()))?;

    match removed {
        Some(rec) => {
            wkdmgr_core::hooks::run_on_key_remove(
                &state.hooks_dir,
                &rec.address,
                &rec.domain,
                state.hook_timeout,
            )
            .await;
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(ApiError::not_found()),
    }
}
