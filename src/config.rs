use std::fmt;
use std::net::IpAddr;

/// Operator-supplied configuration loaded from the environment at startup.
///
/// The `Debug` impl deliberately redacts every secret-bearing field. Never
/// derive `Debug`, never log the struct via `?cfg` without going through this impl.
#[allow(dead_code)] // fields wired up in Phase 1 (storage) and Phase 2 (OAuth)
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
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

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
        })
    }

    /// Convenience: full Google redirect URI registered in the GCP console.
    #[allow(dead_code)] // wired up in Phase 2 (OAuth proxy)
    pub fn google_redirect_uri(&self) -> String {
        format!("{}/oauth/google/callback", self.base_url)
    }
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

    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
