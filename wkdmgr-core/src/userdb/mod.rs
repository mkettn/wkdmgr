mod flatfile;
mod ldap;

pub use flatfile::FlatFileUserDb;
pub use ldap::LdapUserDb;

use crate::config::UserDbConfig;
use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

/// Resolves an authenticated uid (from the SSO proxy header) to the full
/// set of email addresses that uid is authorized to manage.
#[async_trait]
pub trait UserDb: Send + Sync {
    /// Given the authenticated uid from the proxy header, return every
    /// email address this user is authorized to manage. An empty vec (not
    /// an error) if the uid doesn't exist or owns nothing.
    async fn addresses_for_user(&self, uid: &str) -> anyhow::Result<Vec<String>>;
}

/// Build the configured `UserDb` implementation from the userdb config
/// file at `path`, dispatching on its `backend` field.
pub async fn build_userdb(path: impl AsRef<Path>) -> anyhow::Result<Arc<dyn UserDb>> {
    let path = path.as_ref();
    let cfg = UserDbConfig::load(path)?;
    match cfg {
        UserDbConfig::Flatfile(_) => {
            let db = FlatFileUserDb::load(path.to_path_buf())?;
            Ok(Arc::new(db))
        }
        UserDbConfig::Ldap(ldap_cfg) => {
            let db = LdapUserDb::new(ldap_cfg)?;
            Ok(Arc::new(db))
        }
    }
}
