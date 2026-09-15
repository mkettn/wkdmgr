//! `LdapUserDb`: the production `UserDb` backend. Read-only; never writes
//! to the directory.

use super::UserDb;
use crate::config::LdapUserDbConfig;
use async_trait::async_trait;
use ldap3::{ldap_escape, LdapConnAsync, Scope, SearchEntry};

pub struct LdapUserDb {
    uri: String,
    bind_dn: String,
    bind_password: String,
    base_dn: String,
    uid_attr: String,
    mail_attr: String,
    alias_attr: String,
}

impl LdapUserDb {
    pub fn new(cfg: LdapUserDbConfig) -> anyhow::Result<Self> {
        let bind_password = std::fs::read_to_string(&cfg.bind_password_file)
            .map_err(|e| {
                anyhow::anyhow!(
                    "reading LDAP bind password file {}: {e}",
                    cfg.bind_password_file.display()
                )
            })?
            .trim_end_matches(['\n', '\r'])
            .to_string();

        Ok(Self {
            uri: cfg.uri,
            bind_dn: cfg.bind_dn,
            bind_password,
            base_dn: cfg.base_dn,
            uid_attr: cfg.uid_attr,
            mail_attr: cfg.mail_attr,
            alias_attr: cfg.alias_attr,
        })
    }
}

#[async_trait]
impl UserDb for LdapUserDb {
    async fn addresses_for_user(&self, uid: &str) -> anyhow::Result<Vec<String>> {
        let (conn, mut ldap) = LdapConnAsync::new(&self.uri).await?;
        ldap3::drive!(conn);

        ldap.simple_bind(&self.bind_dn, &self.bind_password)
            .await?
            .success()?;

        let filter = format!("({}={})", self.uid_attr, ldap_escape(uid));
        let (results, _res) = ldap
            .search(
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec![self.mail_attr.as_str(), self.alias_attr.as_str()],
            )
            .await?
            .success()?;

        let mut addresses = Vec::new();
        for result in results {
            let entry = SearchEntry::construct(result);
            if let Some(values) = entry.attrs.get(&self.mail_attr) {
                addresses.extend(values.iter().cloned());
            }
            if let Some(values) = entry.attrs.get(&self.alias_attr) {
                addresses.extend(values.iter().cloned());
            }
        }

        let _ = ldap.unbind().await;

        Ok(addresses)
    }
}
