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
use utoipa::{OpenApi, ToSchema};
use wkdmgr_core::openpgp::KeyError;
use wkdmgr_core::UserDb;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub allowed_domains: Arc<Vec<String>>,
    pub sso_header_name: Arc<String>,
    pub userdb: Arc<dyn UserDb>,
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

/// The single source of truth for the `/api/*` contract. `wkdmgr-mgmt
/// --print-openapi` dumps this as JSON, and the frontend's TypeScript
/// client (`frontend/src/api-types.ts`, gitignored) is generated from
/// that output via `openapi-typescript` as part of `npm run dev` /
/// `build` / `typecheck` (see `predev`/`prebuild`/`pretypecheck` in
/// `frontend/package.json`), so nothing there is hand-typed against a
/// second copy of the contract. There is currently no automated check
/// that a Rust change to this contract was followed by regenerating the
/// frontend client -- generation-at-build-time stops drift the moment
/// someone runs it, but nothing fails if they don't.
#[derive(OpenApi)]
#[openapi(
    paths(get_me, list_keys, upload_key, delete_key),
    components(schemas(MeResponse, KeyResponseItem, UploadRequest, ApiErrorBody))
)]
pub struct ApiDoc;

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

/// The JSON body every non-2xx response carries. Exists purely for the
/// generated OpenAPI schema -- `ApiError::into_response` builds this
/// shape ad hoc via `serde_json::json!` rather than constructing one of
/// these, so keep the two in sync by hand if either changes.
#[derive(Serialize, ToSchema)]
struct ApiErrorBody {
    /// A fixed, machine-matchable error code (e.g. `parse_failed`,
    /// `expired`, `address_not_owned`, `domain_not_served`,
    /// `already_exists`, `no_matching_uid`, `not_found`).
    error: String,
    /// A human-readable explanation, safe to display to the user.
    message: String,
}

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
            "domain_not_served",
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

    /// Same `already_exists` code as `Self::already_exists`, but for the
    /// case where the *existing* row's uid is not the caller: `UserDb`
    /// still reports that other uid as an owner of this address too, so
    /// this is a shared/role address rather than a stale reassignment,
    /// and the upload is refused rather than silently taking it over.
    fn already_exists_shared(address: &str) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "already_exists",
            format!(
                "a key already exists for {address}, published by another owner who still owns \
                 it too; ask them to remove it first"
            ),
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
            KeyError::Expired(m) => Self::new(StatusCode::BAD_REQUEST, "expired", m),
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

#[derive(Serialize, ToSchema)]
struct MeResponse {
    uid: String,
    addresses: Vec<String>,
}

/// Get the authenticated uid and the addresses it's authorized to manage
#[utoipa::path(
    get,
    path = "/api/me",
    responses(
        (status = 200, description = "The authenticated uid and its owned addresses", body = MeResponse),
        (status = 401, description = "Missing SSO identity header", body = ApiErrorBody),
        (status = 502, description = "UserDb backend unavailable", body = ApiErrorBody),
    ),
)]
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

#[derive(Serialize, ToSchema)]
struct KeyResponseItem {
    id: String,
    address: String,
    domain: String,
    fingerprint: String,
    uploaded_at: String,
    revoked: bool,
    /// RFC3339, if this key's primary key expires. `null` for a
    /// non-expiring key. A key past this time is no longer served over
    /// WKD even though the row is still listed here.
    expires_at: Option<String>,
}

impl From<wkdmgr_core::storage::KeyRecord> for KeyResponseItem {
    fn from(r: wkdmgr_core::storage::KeyRecord) -> Self {
        Self {
            id: r.id.to_string(),
            address: r.address,
            domain: r.domain,
            fingerprint: r.fingerprint,
            uploaded_at: r.uploaded_at,
            revoked: r.revoked,
            expires_at: r.expires_at,
        }
    }
}

/// List the authenticated uid's own published keys
#[utoipa::path(
    get,
    path = "/api/keys",
    responses(
        (status = 200, description = "Keys owned by the authenticated uid", body = Vec<KeyResponseItem>),
        (status = 401, description = "Missing SSO identity header", body = ApiErrorBody),
    ),
)]
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

#[derive(Deserialize, ToSchema)]
struct UploadRequest {
    address: String,
    /// ASCII-armored or base64-encoded OpenPGP public key material.
    key: String,
}

/// Publish a minimized key for one of the authenticated uid's addresses.
/// If the address was previously published under a *different* uid that
/// `UserDb` no longer reports as its owner, this replaces that row
/// rather than 409ing -- see `wkdmgr_core::storage::insert_key` -- since
/// otherwise a reassigned address would strand both the old and new
/// owner. Re-publishing over your own still-current key still 409s: you
/// need to delete it first.
#[utoipa::path(
    post,
    path = "/api/keys",
    request_body = UploadRequest,
    responses(
        (status = 201, description = "Published", body = KeyResponseItem),
        (status = 400, description = "parse_failed | expired | no_matching_uid | address_not_owned | domain_not_served", body = ApiErrorBody),
        (status = 401, description = "Missing SSO identity header", body = ApiErrorBody),
        (status = 409, description = "already_exists -- delete the existing key first", body = ApiErrorBody),
        (status = 502, description = "UserDb backend unavailable", body = ApiErrorBody),
    ),
)]
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
    // Computed once here and cached in the `revoked`/`expires_at`
    // columns: revocation status can only change via a fresh upload, so
    // wkdmgr-query never needs to re-parse the blob to check it. Expiry
    // is different -- it moves on its own -- so it's stored as a
    // timestamp wkdmgr-query compares against "now" on every lookup,
    // not a cached boolean.
    let revoked = wkdmgr_core::openpgp::is_revoked(&minimized);
    let expires_at =
        wkdmgr_core::openpgp::expiration_time(&cert).map_err(ApiError::from_key_error)?;

    let db = state.db.clone();
    let domain_for_peek = domain.clone();
    let wkd_hash_for_peek = wkd_hash.clone();
    let existing_owner = tokio::task::spawn_blocking({
        let db = db.clone();
        move || {
            let conn = db.lock().expect("db mutex poisoned");
            wkdmgr_core::storage::existing_owner(&conn, &domain_for_peek, &wkd_hash_for_peek)
        }
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // A row already published under a *different* uid: only replace it if
    // that uid no longer owns the address per `UserDb` (a genuine
    // reassignment). If it still does, this is a shared/role address and
    // the upload is refused with a distinct message rather than silently
    // taking it over -- see `wkdmgr_core::storage::insert_key`.
    let replace_existing = match &existing_owner {
        Some(existing_uid) if existing_uid != &uid.0 => {
            let still_owns = state
                .userdb
                .addresses_for_user(existing_uid)
                .await
                .map_err(|e| ApiError::userdb_unavailable(e.to_string()))?
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&body.address));
            if still_owns {
                return Err(ApiError::already_exists_shared(&body.address));
            }
            true
        }
        _ => false,
    };

    let uid_owned = uid.0.clone();
    let address = body.address.clone();
    let domain_owned = domain.clone();
    let wkd_hash_owned = wkd_hash.clone();
    let fingerprint_owned = fingerprint.clone();
    let minimized_for_insert = minimized.clone();

    let insert_result = tokio::task::spawn_blocking(move || {
        let mut conn = db.lock().expect("db mutex poisoned");
        wkdmgr_core::storage::insert_key(
            &mut conn,
            &wkdmgr_core::storage::NewKey {
                uid: &uid_owned,
                domain: &domain_owned,
                address: &address,
                wkd_hash: &wkd_hash_owned,
                fingerprint: &fingerprint_owned,
                key_data: &minimized_for_insert,
                revoked,
                expires_at,
            },
            replace_existing,
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

    Ok((StatusCode::CREATED, Json(record.into())))
}

// ---------------------------------------------------------------------
// DELETE /api/keys/:id
// ---------------------------------------------------------------------

/// Revoke (delete) one of the authenticated uid's own published keys
#[utoipa::path(
    delete,
    path = "/api/keys/{id}",
    params(
        ("id" = i64, Path, description = "The key's database row id, from GET /api/keys"),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Missing SSO identity header", body = ApiErrorBody),
        (status = 404, description = "Not found, or not owned by the authenticated uid", body = ApiErrorBody),
    ),
)]
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
        Some(_) => Ok(StatusCode::NO_CONTENT),
        None => Err(ApiError::not_found()),
    }
}
