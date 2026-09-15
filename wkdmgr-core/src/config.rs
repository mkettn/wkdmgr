//! Main service config (`config.yaml`) and userdb config (`userdb.yaml`)
//! parsing.

use serde::Deserialize;
use std::path::{Path, PathBuf};

fn default_sso_header_name() -> String {
    "Remote-User".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct SocketConfig {
    pub path: PathBuf,
    #[serde(default = "default_socket_mode")]
    pub mode: String,
}

fn default_socket_mode() -> String {
    "0660".to_string()
}

impl SocketConfig {
    /// Parse `mode` (an octal string like "0660") into a `u32` suitable for
    /// `std::fs::Permissions::from_mode`.
    pub fn mode_bits(&self) -> anyhow::Result<u32> {
        let trimmed = self.mode.trim_start_matches("0o");
        u32::from_str_radix(trimmed, 8)
            .map_err(|e| anyhow::anyhow!("invalid socket mode '{}': {e}", self.mode))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub allowed_domains: Vec<String>,
    pub db_path: PathBuf,
    #[serde(default = "default_sso_header_name")]
    pub sso_header_name: String,
    pub userdb_config: PathBuf,
    pub query_socket: SocketConfig,
    pub mgmt_socket: SocketConfig,
    /// Optional: if set, `wkdmgr-mgmt` serves the built frontend static
    /// bundle from this directory as a fallback route (see README for the
    /// alternative of serving it directly from nginx instead).
    #[serde(default)]
    pub frontend_dist_dir: Option<PathBuf>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.as_ref().display()))?;
        let cfg: Config = serde_yaml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parsing config {}: {e}", path.as_ref().display()))?;
        Ok(cfg)
    }

    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        self.allowed_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
    }
}

/// The `userdb.yaml` file. Self-describing via `backend`: the rest of the
/// shape depends on its value, so a bad/unknown backend fails fast at
/// deserialization time rather than deep in field-by-field parsing.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum UserDbConfig {
    Flatfile(FlatfileUserDbConfig),
    Ldap(LdapUserDbConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlatfileUserDbConfig {
    #[serde(default)]
    pub users: std::collections::BTreeMap<String, FlatfileUserRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlatfileUserRecord {
    #[serde(default)]
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LdapUserDbConfig {
    pub uri: String,
    pub bind_dn: String,
    pub bind_password_file: PathBuf,
    pub base_dn: String,
    #[serde(default = "default_uid_attr")]
    pub uid_attr: String,
    #[serde(default = "default_mail_attr")]
    pub mail_attr: String,
    pub alias_attr: String,
}

fn default_uid_attr() -> String {
    "uid".to_string()
}

fn default_mail_attr() -> String {
    "mail".to_string()
}

impl UserDbConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            anyhow::anyhow!("reading userdb config {}: {e}", path.as_ref().display())
        })?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let cfg: UserDbConfig =
            serde_yaml::from_str(raw).map_err(|e| anyhow::anyhow!("parsing userdb config: {e}"))?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flatfile_userdb_config() {
        let yaml = r#"
backend: flatfile
users:
  alice:
    addresses:
      - alice@example-1.tld
      - alice.smith@example-2.tld
  bob:
    addresses:
      - bob@example-1.tld
"#;
        let cfg = UserDbConfig::parse(yaml).unwrap();
        match cfg {
            UserDbConfig::Flatfile(f) => {
                assert_eq!(f.users.len(), 2);
                assert_eq!(f.users["alice"].addresses.len(), 2);
            }
            _ => panic!("expected flatfile"),
        }
    }

    #[test]
    fn parses_ldap_userdb_config() {
        let yaml = r#"
backend: ldap
uri: ldap://localhost:389
bind_dn: cn=admin,dc=example,dc=org
bind_password_file: /etc/wkdmgr/ldap-bind-password
base_dn: ou=users,dc=example,dc=org
uid_attr: uid
mail_attr: mail
alias_attr: mailAlternateAddress
"#;
        let cfg = UserDbConfig::parse(yaml).unwrap();
        match cfg {
            UserDbConfig::Ldap(l) => {
                assert_eq!(l.uri, "ldap://localhost:389");
                assert_eq!(l.alias_attr, "mailAlternateAddress");
            }
            _ => panic!("expected ldap"),
        }
    }

    #[test]
    fn unknown_backend_fails_fast() {
        let yaml = "backend: carrier-pigeon\n";
        assert!(UserDbConfig::parse(yaml).is_err());
    }

    #[test]
    fn main_config_parses() {
        let yaml = r#"
allowed_domains:
  - example-1.tld
  - example-2.tld
db_path: /var/lib/wkdmgr/meta.sqlite3
sso_header_name: Remote-User
userdb_config: /etc/wkdmgr/userdb.yaml
query_socket:
  path: /run/wkdmgr/query.sock
  mode: "0660"
mgmt_socket:
  path: /run/wkdmgr/mgmt.sock
  mode: "0660"
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.allowed_domains.len(), 2);
        assert!(cfg.is_domain_allowed("EXAMPLE-1.TLD"));
        assert_eq!(cfg.query_socket.mode_bits().unwrap(), 0o660);
    }
}
