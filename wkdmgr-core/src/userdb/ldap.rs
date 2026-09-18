//! `LdapUserDb`: the production `UserDb` backend. Read-only; never writes
//! to the directory.

use super::UserDb;
use crate::config::LdapUserDbConfig;
use async_trait::async_trait;
use ldap3::{ldap_escape, LdapConnAsync, Scope, SearchEntry};
use std::collections::HashMap;
use std::time::Duration;

pub struct LdapUserDb {
    uri: String,
    bind_dn: String,
    bind_password: String,
    base_dn: String,
    uid_attr: String,
    mail_attr: String,
    alias_attr: String,
    timeout: Duration,
}

impl LdapUserDb {
    pub fn new(cfg: LdapUserDbConfig) -> anyhow::Result<Self> {
        if cfg.timeout_secs == 0 {
            anyhow::bail!(
                "ldap.timeout_secs must be greater than zero (0 would make every lookup time \
                 out immediately)"
            );
        }

        Ok(Self {
            uri: cfg.uri,
            bind_dn: cfg.bind_dn,
            bind_password: cfg.bind_password,
            base_dn: cfg.base_dn,
            uid_attr: cfg.uid_attr,
            mail_attr: cfg.mail_attr,
            alias_attr: cfg.alias_attr,
            timeout: Duration::from_secs(cfg.timeout_secs),
        })
    }

    /// The connect+bind+search+collect sequence, unbounded in time on
    /// its own -- `addresses_for_user` wraps this in the configured
    /// timeout. Split out so the whole sequence shares one timeout
    /// budget rather than each `.await` getting its own (which would
    /// still let a slow-but-not-quite-timed-out directory add up to far
    /// more than `timeout` in total).
    async fn addresses_for_user_inner(&self, uid: &str) -> anyhow::Result<Vec<String>> {
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
        let mut any_entries = false;
        for result in results {
            any_entries = true;
            let entry = SearchEntry::construct(result);
            if let Some(values) = find_attr_ci(&entry.attrs, &self.mail_attr) {
                addresses.extend(values.iter().cloned());
            }
            if let Some(values) = find_attr_ci(&entry.attrs, &self.alias_attr) {
                addresses.extend(values.iter().cloned());
            }
        }

        if any_entries && addresses.is_empty() {
            tracing::warn!(
                "LDAP search for uid {uid:?} matched an entry but yielded no addresses from \
                 mail_attr={:?} or alias_attr={:?} -- likely an attribute-name/config mismatch, \
                 not a user with genuinely no addresses",
                self.mail_attr,
                self.alias_attr
            );
        }

        let _ = ldap.unbind().await;

        Ok(addresses)
    }
}

/// LDAP attribute *descriptors* are case-insensitive per RFC 4512, but
/// `SearchEntry::attrs` is a plain `HashMap` keyed by whatever casing
/// the server happened to answer with -- which isn't guaranteed to match
/// the casing in `mail_attr`/`alias_attr` config. Match case-insensitively
/// so a server that answers `Mail` for a `mail` request doesn't silently
/// look like the user has no addresses at all.
fn find_attr_ci<'a>(
    attrs: &'a HashMap<String, Vec<String>>,
    name: &str,
) -> Option<&'a Vec<String>> {
    attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

#[async_trait]
impl UserDb for LdapUserDb {
    async fn addresses_for_user(&self, uid: &str) -> anyhow::Result<Vec<String>> {
        tokio::time::timeout(self.timeout, self.addresses_for_user_inner(uid))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "LDAP lookup for uid {uid:?} timed out after {:?}",
                    self.timeout
                )
            })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LdapUserDbConfig;

    fn cfg_with_timeout(timeout_secs: u64) -> LdapUserDbConfig {
        LdapUserDbConfig {
            uri: "ldap://localhost".to_string(),
            bind_dn: "cn=admin,dc=example,dc=com".to_string(),
            bind_password: "secret".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            uid_attr: "uid".to_string(),
            mail_attr: "mail".to_string(),
            alias_attr: "mailAlternateAddress".to_string(),
            timeout_secs,
        }
    }

    #[test]
    fn new_rejects_zero_timeout() {
        let Err(err) = LdapUserDb::new(cfg_with_timeout(0)) else {
            panic!("expected LdapUserDb::new to reject timeout_secs = 0");
        };
        assert!(err.to_string().contains("timeout_secs"));
    }

    #[test]
    fn new_accepts_nonzero_timeout() {
        assert!(LdapUserDb::new(cfg_with_timeout(10)).is_ok());
    }

    #[test]
    fn find_attr_ci_matches_regardless_of_case() {
        let mut attrs = HashMap::new();
        attrs.insert("Mail".to_string(), vec!["alice@example.com".to_string()]);

        assert_eq!(
            find_attr_ci(&attrs, "mail"),
            Some(&vec!["alice@example.com".to_string()])
        );
        assert_eq!(
            find_attr_ci(&attrs, "MAIL"),
            Some(&vec!["alice@example.com".to_string()])
        );
        assert_eq!(find_attr_ci(&attrs, "mailAlternateAddress"), None);
    }
}
