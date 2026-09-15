use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use utoipa::OpenApi;
use wkdmgr_core::config::Config;
use wkdmgr_mgmt::{build_app, ApiDoc, AppState};

fn config_path() -> std::path::PathBuf {
    std::env::var("WKDMGR_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/etc/wkdmgr/config.yaml"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Dump the OpenAPI spec (the single source of truth the frontend's
    // TypeScript client is generated from) and exit -- no config, DB, or
    // socket needed for this.
    if std::env::args().any(|arg| arg == "--print-openapi") {
        println!("{}", ApiDoc::openapi().to_pretty_json()?);
        return Ok(());
    }

    tracing_subscriber::fmt::init();

    let cfg = Config::load(config_path())?;

    tracing::warn!(
        "wkdmgr-mgmt trusts the '{}' header unconditionally as the authenticated identity. It \
         MUST only be reachable through a reverse proxy that terminates SSO and strips any \
         client-supplied header of that name before setting its own. Never expose this socket \
         directly to the internet or to untrusted clients.",
        cfg.sso_header_name
    );

    let userdb = wkdmgr_core::userdb::build_userdb(&cfg.userdb_config).await?;

    let conn = wkdmgr_core::storage::open_writable(&cfg.db_path)?;
    let db = Arc::new(Mutex::new(conn));
    let db_for_shutdown = db.clone();

    let state = AppState {
        db,
        allowed_domains: Arc::new(cfg.allowed_domains.clone()),
        sso_header_name: Arc::new(cfg.sso_header_name.clone()),
        userdb,
    };

    let app = build_app(state, cfg.frontend_dist_dir.clone());

    let socket_path = &cfg.mgmt_socket.path;
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let listener = tokio::net::UnixListener::bind(socket_path)?;
    let mode = cfg.mgmt_socket.mode_bits()?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(mode))?;

    tracing::info!(
        "wkdmgr-mgmt listening on unix socket {} (mode {:o})",
        socket_path.display(),
        mode
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // WAL mode means a plain read-only open (no write access to the
    // containing directory) needs -wal/-shm to already exist, and
    // SQLite deletes both when the last connection to the database
    // closes cleanly -- which a graceful stop of the sole writer is.
    // Checkpointing back to journal_mode=DELETE here leaves a file any
    // read-only connection can open directly, no directory write access
    // needed; open_writable() switches back to WAL on the next start.
    // Best-effort: if another connection (e.g. a still-running
    // wkdmgr-query with its own already-open handle) is attached,
    // SQLite can't change the journal mode and this is a silent no-op,
    // which is fine, since that connection already works. See the
    // README's "Read-only access after a clean shutdown" note for the
    // full picture, including the directory-permission fix this
    // complements rather than replaces.
    if let Ok(conn) = db_for_shutdown.lock() {
        if let Err(e) = conn.pragma_update(None, "journal_mode", "DELETE") {
            tracing::warn!("could not checkpoint database to journal_mode=DELETE on shutdown: {e}");
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
