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

    axum::serve(listener, app).await?;
    Ok(())
}
