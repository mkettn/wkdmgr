use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use wkdmgr_core::config::Config;
use wkdmgr_query::{build_app, AppState};

fn config_path() -> std::path::PathBuf {
    std::env::var("WKDMGR_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/etc/wkdmgr/config.yaml"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Config::load(config_path())?;

    let state = AppState {
        db_path: Arc::new(cfg.db_path.clone()),
        allowed_domains: Arc::new(cfg.allowed_domains.clone()),
    };
    let app = build_app(state);

    let socket_path = &cfg.query_socket.path;
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let listener = tokio::net::UnixListener::bind(socket_path)?;
    let mode = cfg.query_socket.mode_bits()?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(mode))?;

    tracing::info!(
        "wkdmgr-query listening on unix socket {} (mode {:o})",
        socket_path.display(),
        mode
    );

    axum::serve(listener, app).await?;
    Ok(())
}
