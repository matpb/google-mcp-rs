use std::fmt;
use std::net::IpAddr;

use crate::domain::{self, Domain};
use crate::files::{FileJail, FileMaintenance};

/// Operator-supplied configuration loaded from the environment at startup.
///
/// The `Debug` impl deliberately redacts every secret-bearing field. Never
/// derive `Debug`, never log the struct via `?cfg` without going through this impl.
pub struct ServerConfig {
    pub host: IpAddr,
    pub port: u16,
    pub base_url: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub jwt_secret: Vec<u8>,
    pub storage_encryption_key: [u8; 32],
    pub database_url: String,
    pub cors_allow_localhost: bool,
    /// Extra `Host`/`X-Forwarded-Host` entries allowed beyond loopback and
    /// `BASE_URL`'s host, from `ALLOWED_HOSTS` (comma-separated).
    pub allowed_hosts: Vec<String>,
    pub enabled_domains: Vec<Domain>,
    /// Optional allowlist from `ALLOWED_GOOGLE_ACCOUNTS`; empty means no restriction.
    pub allowed_google_accounts: Vec<AllowedAccountEntry>,
    /// Jailed host directory for filesystem-based file exchange. `Some` when
    /// `FILE_ROOT` is set (and bind-mounted into the container); `None`
    /// disables path-based reads/writes so tools fall back to base64.
    pub file_jail: Option<FileJail>,
    /// Which file-maintenance tools (`files_info`/`files_cleanup`) to expose.
    /// Off by default so no deletion/listing tool appears unless opted in.
    pub file_maintenance: FileMaintenance,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        // Optional .env loading; ignore failure (env vars may be set directly).
        let _ = dotenvy::dotenv();

        let host = required("MCP_HOST")
            .unwrap_or_else(|_| "0.0.0.0".to_string())
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::Invalid("MCP_HOST must be a valid IP address"))?;

        let port = optional_env("MCP_PORT")
            .map(|s| {
                s.parse::<u16>()
                    .map_err(|_| ConfigError::Invalid("MCP_PORT must be a u16"))
            })
            .transpose()?
            .unwrap_or(8433);

        let base_url = required("BASE_URL")?;
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(ConfigError::Invalid(
                "BASE_URL must start with http:// or https://",
            ));
        }
        let base_url = base_url.trim_end_matches('/').to_string();

        let google_client_id = required("GOOGLE_CLIENT_ID")?;
        let google_client_secret = required("GOOGLE_CLIENT_SECRET")?;

        let jwt_secret = required("JWT_SECRET")?.into_bytes();
        if jwt_secret.len() < 32 {
            return Err(ConfigError::Invalid("JWT_SECRET must be at least 32 bytes"));
        }

        let storage_encryption_key = parse_storage_key(&required("STORAGE_ENCRYPTION_KEY")?)?;

        let database_url =
            optional_env("DATABASE_URL").unwrap_or_else(|| "./google-mcp.db".to_string());

        let cors_allow_localhost = optional_env("CORS_ALLOW_LOCALHOST")
            .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"));

        let allowed_hosts = optional_env("ALLOWED_HOSTS")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let enabled_domains = domain::parse_enabled(optional_env("ENABLED_DOMAINS").as_deref())
            .map_err(ConfigError::InvalidDomain)?;

        let allowed_google_accounts =
            parse_allowed_accounts(optional_env("ALLOWED_GOOGLE_ACCOUNTS").as_deref());

        let file_jail = FileJail::from_env(optional_env("FILE_ROOT").as_deref())
            .map_err(|e| ConfigError::InvalidFileRoot(e.to_string()))?;

        let file_maintenance =
            FileMaintenance::parse(optional_env("FILE_MAINTENANCE_TOOLS").as_deref())
                .map_err(ConfigError::InvalidFileMaintenance)?;

        Ok(Self {
            host,
            port,
            base_url,
            google_client_id,
            google_client_secret,
            jwt_secret,
            storage_encryption_key,
            database_url,
            cors_allow_localhost,
            allowed_hosts,
            enabled_domains,
            allowed_google_accounts,
            file_jail,
            file_maintenance,
        })
    }

    /// Convenience: full Google redirect URI registered in the GCP console.
    pub fn google_redirect_uri(&self) -> String {
        format!("{}/oauth/google/callback", self.base_url)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedAccountEntry {
    Email(String),
    /// Domain without the leading `@`.
    Domain(String),
}

fn parse_allowed_accounts(raw: Option<&str>) -> Vec<AllowedAccountEntry> {
    let Some(s) = raw else { return Vec::new() };
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| match s.strip_prefix('@') {
            Some(domain) => AllowedAccountEntry::Domain(domain.to_ascii_lowercase()),
            None => AllowedAccountEntry::Email(s.to_ascii_lowercase()),
        })
        .collect()
}

/// Matches an `hd` claim (from the `id_token`, at first sign-in).
pub fn account_allowed(entries: &[AllowedAccountEntry], email: &str, hd: Option<&str>) -> bool {
    if entries.is_empty() {
        return true;
    }
    let email_l = email.to_ascii_lowercase();
    entries.iter().any(|e| match e {
        AllowedAccountEntry::Email(allowed) => *allowed == email_l,
        AllowedAccountEntry::Domain(d) => hd.is_some_and(|h| h.eq_ignore_ascii_case(d)),
    })
}

/// Matches the email's own domain suffix (no `hd` stored on the account row).
pub fn account_allowed_by_email(entries: &[AllowedAccountEntry], email: &str) -> bool {
    if entries.is_empty() {
        return true;
    }
    let email_l = email.to_ascii_lowercase();
    entries.iter().any(|e| match e {
        AllowedAccountEntry::Email(allowed) => *allowed == email_l,
        AllowedAccountEntry::Domain(d) => email_l
            .rsplit_once('@')
            .is_some_and(|(_, dom)| dom == d.as_str()),
    })
}

fn required(key: &'static str) -> Result<String, ConfigError> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(ConfigError::Missing(key)),
    }
}

fn optional_env(key: &'static str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn parse_storage_key(raw: &str) -> Result<[u8; 32], ConfigError> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let bytes = Base64UrlUnpadded::decode_vec(raw.trim_end_matches('='))
        .map_err(|_| ConfigError::Invalid("STORAGE_ENCRYPTION_KEY must be base64url-encoded"))?;
    if bytes.len() != 32 {
        return Err(ConfigError::Invalid(
            "STORAGE_ENCRYPTION_KEY must decode to exactly 32 bytes",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(&'static str),
    #[error("invalid env var: {0}")]
    Invalid(&'static str),
    #[error("invalid env var ENABLED_DOMAINS: {0}")]
    InvalidDomain(String),
    #[error("invalid env var FILE_ROOT: {0}")]
    InvalidFileRoot(String),
    #[error("invalid env var FILE_MAINTENANCE_TOOLS: {0}")]
    InvalidFileMaintenance(String),
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("base_url", &self.base_url)
            .field("google_client_id", &Redacted)
            .field("google_client_secret", &Redacted)
            .field("jwt_secret", &Redacted)
            .field("storage_encryption_key", &Redacted)
            .field("database_url", &self.database_url)
            .field("cors_allow_localhost", &self.cors_allow_localhost)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("enabled_domains", &self.enabled_domains)
            .field("allowed_google_accounts", &self.allowed_google_accounts)
            .field("file_jail", &self.file_jail)
            .field("file_maintenance", &self.file_maintenance)
            .finish()
    }
}

struct Redacted;
impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize all env-mutating tests across the suite. cargo test runs
    // unit tests in parallel by default; without this, concurrent tests
    // would stomp each other's env vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // SAFETY: ENV_LOCK serializes every caller, so no other thread reads or
    // writes the environment while this function runs.
    #[allow(unsafe_code)]
    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let saved: Vec<_> = vars
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(val) => unsafe { std::env::set_var(k, val) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        f();
        for (k, v) in saved {
            match v {
                Some(val) => unsafe { std::env::set_var(&k, val) },
                None => unsafe { std::env::remove_var(&k) },
            }
        }
    }

    fn valid_storage_key() -> &'static str {
        // 32 zero bytes, base64url-encoded with no padding.
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }

    fn valid_jwt_secret() -> &'static str {
        "0123456789abcdef0123456789abcdef0123456789abcdef"
    }

    #[test]
    fn parses_valid_env() {
        with_env(
            &[
                ("BASE_URL", Some("http://localhost:8433")),
                ("GOOGLE_CLIENT_ID", Some("client-id-x")),
                ("GOOGLE_CLIENT_SECRET", Some("secret-y")),
                ("JWT_SECRET", Some(valid_jwt_secret())),
                ("STORAGE_ENCRYPTION_KEY", Some(valid_storage_key())),
                ("MCP_PORT", Some("9000")),
                ("CORS_ALLOW_LOCALHOST", Some("true")),
                ("DATABASE_URL", Some("/tmp/test.db")),
            ],
            || {
                let cfg = ServerConfig::from_env().expect("config");
                assert_eq!(cfg.port, 9000);
                assert_eq!(cfg.base_url, "http://localhost:8433");
                assert_eq!(
                    cfg.google_redirect_uri(),
                    "http://localhost:8433/oauth/google/callback"
                );
                assert!(cfg.cors_allow_localhost);
                assert_eq!(cfg.storage_encryption_key, [0u8; 32]);
                assert_eq!(cfg.database_url, "/tmp/test.db");
            },
        );
    }

    #[test]
    fn parses_allowed_hosts_csv() {
        with_env(
            &[
                ("BASE_URL", Some("http://localhost:8433")),
                ("GOOGLE_CLIENT_ID", Some("a")),
                ("GOOGLE_CLIENT_SECRET", Some("b")),
                ("JWT_SECRET", Some(valid_jwt_secret())),
                ("STORAGE_ENCRYPTION_KEY", Some(valid_storage_key())),
                (
                    "ALLOWED_HOSTS",
                    Some(" tunnel.example.net:8080 , other.example.com "),
                ),
            ],
            || {
                let cfg = ServerConfig::from_env().expect("config");
                assert_eq!(
                    cfg.allowed_hosts,
                    vec!["tunnel.example.net:8080", "other.example.com"]
                );
            },
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        with_env(
            &[
                ("BASE_URL", Some("http://localhost:8433")),
                ("GOOGLE_CLIENT_ID", Some("totally-secret-client-id")),
                ("GOOGLE_CLIENT_SECRET", Some("totally-secret-client-secret")),
                ("JWT_SECRET", Some(valid_jwt_secret())),
                ("STORAGE_ENCRYPTION_KEY", Some(valid_storage_key())),
                ("MCP_PORT", None),
                ("CORS_ALLOW_LOCALHOST", None),
                ("DATABASE_URL", None),
            ],
            || {
                let cfg = ServerConfig::from_env().expect("config");
                let dbg = format!("{cfg:?}");
                assert!(!dbg.contains("totally-secret-client-id"));
                assert!(!dbg.contains("totally-secret-client-secret"));
                assert!(!dbg.contains(valid_jwt_secret()));
                assert!(dbg.contains("***"));
            },
        );
    }

    #[test]
    fn rejects_short_jwt_secret() {
        with_env(
            &[
                ("BASE_URL", Some("http://localhost:8433")),
                ("GOOGLE_CLIENT_ID", Some("a")),
                ("GOOGLE_CLIENT_SECRET", Some("b")),
                ("JWT_SECRET", Some("too-short")),
                ("STORAGE_ENCRYPTION_KEY", Some(valid_storage_key())),
            ],
            || {
                assert!(matches!(
                    ServerConfig::from_env(),
                    Err(ConfigError::Invalid(_))
                ));
            },
        );
    }

    #[test]
    fn allowed_accounts_email_case_insensitive() {
        let entries = parse_allowed_accounts(Some("User@Example.com"));
        assert!(account_allowed(&entries, "user@example.com", None));
        assert!(account_allowed_by_email(&entries, "USER@EXAMPLE.COM"));
        assert!(!account_allowed(&entries, "other@example.com", None));
    }

    #[test]
    fn allowed_accounts_domain_matches_hd_not_email_suffix() {
        let entries = parse_allowed_accounts(Some("@example.com"));
        assert!(account_allowed(
            &entries,
            "anyone@else.com",
            Some("example.com")
        ));
        assert!(!account_allowed(&entries, "anyone@example.com", None));
        assert!(!account_allowed(
            &entries,
            "anyone@example.com",
            Some("other.com")
        ));
    }

    #[test]
    fn allowed_accounts_domain_by_email_suffix() {
        let entries = parse_allowed_accounts(Some("@example.com"));
        assert!(account_allowed_by_email(&entries, "anyone@example.com"));
        assert!(!account_allowed_by_email(&entries, "anyone@evil.com"));
    }

    #[test]
    fn allowed_accounts_empty_means_unrestricted() {
        let entries = parse_allowed_accounts(None);
        assert!(account_allowed(&entries, "anyone@anywhere.com", None));
    }

    #[test]
    fn rejects_wrong_length_storage_key() {
        with_env(
            &[
                ("BASE_URL", Some("http://localhost:8433")),
                ("GOOGLE_CLIENT_ID", Some("a")),
                ("GOOGLE_CLIENT_SECRET", Some("b")),
                ("JWT_SECRET", Some(valid_jwt_secret())),
                ("STORAGE_ENCRYPTION_KEY", Some("AAAA")),
            ],
            || {
                assert!(matches!(
                    ServerConfig::from_env(),
                    Err(ConfigError::Invalid(_))
                ));
            },
        );
    }
}
