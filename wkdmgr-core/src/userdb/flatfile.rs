//! `FlatFileUserDb`: the MVP/dev/testing `UserDb` backend, backed directly
//! by the `users` map in the userdb config file when its `backend` is
//! `flatfile`. Watches the file and hot-reloads on change.

use super::UserDb;
use crate::config::UserDbConfig;
use async_trait::async_trait;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub struct FlatFileUserDb {
    state: Arc<RwLock<HashMap<String, Vec<String>>>>,
    // Kept alive so the watcher isn't dropped (and stopped) while the
    // FlatFileUserDb is in use. Absent when constructed via `from_map`
    // for tests that don't need file watching.
    _watcher: Option<RecommendedWatcher>,
}

impl FlatFileUserDb {
    /// Load users from `path` (a userdb.yaml with `backend: flatfile`) and
    /// start watching it for changes, hot-reloading in place.
    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        let initial = Self::read_users(&path)?;
        let state = Arc::new(RwLock::new(initial));

        let watch_state = state.clone();
        let watch_path = path.clone();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Err(e) = res {
                tracing::warn!("userdb file watcher error: {e}");
                return;
            }
            match Self::read_users(&watch_path) {
                Ok(users) => {
                    if let Ok(mut guard) = watch_state.write() {
                        *guard = users;
                        tracing::info!("reloaded flatfile userdb from {}", watch_path.display());
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "failed to reload flatfile userdb from {}: {e} (keeping previous data)",
                        watch_path.display()
                    );
                }
            }
        })?;
        // Watch the parent directory rather than the file itself: editors
        // commonly replace-via-rename on save, which would orphan a
        // watch on the old inode.
        let watch_dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        watcher.watch(watch_dir, RecursiveMode::NonRecursive)?;

        Ok(Self {
            state,
            _watcher: Some(watcher),
        })
    }

    /// Construct directly from an in-memory map, with no file watching.
    /// Useful for tests and for embedding without a config file on disk.
    pub fn from_map(users: HashMap<String, Vec<String>>) -> Self {
        Self {
            state: Arc::new(RwLock::new(users)),
            _watcher: None,
        }
    }

    fn read_users(path: &Path) -> anyhow::Result<HashMap<String, Vec<String>>> {
        let cfg = UserDbConfig::load(path)?;
        match cfg {
            UserDbConfig::Flatfile(f) => Ok(f
                .users
                .into_iter()
                .map(|(uid, record)| (uid, record.addresses))
                .collect()),
            UserDbConfig::Ldap(_) => anyhow::bail!(
                "userdb config at {} switched to backend: ldap; FlatFileUserDb cannot reload it \
                 (restart with the correct backend)",
                path.display()
            ),
        }
    }
}

#[async_trait]
impl UserDb for FlatFileUserDb {
    async fn addresses_for_user(&self, uid: &str) -> anyhow::Result<Vec<String>> {
        let guard = self
            .state
            .read()
            .map_err(|_| anyhow::anyhow!("flatfile userdb lock poisoned"))?;
        Ok(guard.get(uid).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn returns_addresses_for_known_user() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            vec!["alice@example.com".to_string(), "a@example.org".to_string()],
        );
        let db = FlatFileUserDb::from_map(users);
        let addrs = db.addresses_for_user("alice").await.unwrap();
        assert_eq!(addrs.len(), 2);
    }

    #[tokio::test]
    async fn returns_empty_vec_for_unknown_user() {
        let db = FlatFileUserDb::from_map(HashMap::new());
        let addrs = db.addresses_for_user("nobody").await.unwrap();
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn hot_reloads_on_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("userdb.yaml");
        std::fs::write(
            &path,
            r#"
backend: flatfile
users:
  alice:
    addresses:
      - alice@example.com
"#,
        )
        .unwrap();

        let db = FlatFileUserDb::load(path.clone()).unwrap();
        assert_eq!(
            db.addresses_for_user("alice").await.unwrap(),
            vec!["alice@example.com".to_string()]
        );
        assert!(db.addresses_for_user("bob").await.unwrap().is_empty());

        std::fs::write(
            &path,
            r#"
backend: flatfile
users:
  alice:
    addresses:
      - alice@example.com
  bob:
    addresses:
      - bob@example.com
"#,
        )
        .unwrap();

        // The watcher callback runs asynchronously on a background thread;
        // poll for a bounded time instead of a fixed sleep.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if !db.addresses_for_user("bob").await.unwrap().is_empty() {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("flatfile userdb did not hot-reload within timeout");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
