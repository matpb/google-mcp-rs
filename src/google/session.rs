//! In-memory cache of live Google access tokens, with single-flight refresh.
//!
//! Each entry is keyed by Google `sub`. Access tokens are refreshed lazily:
//! reads return the cached token if it's good for at least another 60s,
//! otherwise the holder of the per-`sub` mutex calls Google's token
//! endpoint, then everyone waiting picks up the fresh token.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

use crate::oauth::GoogleOAuthError;
use crate::oauth::google::GoogleOAuthClient;
use crate::oauth::jwt::now_secs;
use crate::storage::{Db, DbError, accounts};

#[derive(Debug, Clone)]
#[allow(dead_code)] // `expires_at` surfaces to tools that want to expose it.
pub struct GoogleAccountSession {
    pub google_sub: String,
    pub email: String,
    pub access_token: String,
    pub expires_at: u64,
    pub scopes: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Google account not registered with this MCP server")]
    AccountNotFound,
    #[error("Google account has been disconnected (refresh token revoked); reconnect required")]
    ReconnectRequired,
    #[error("storage: {0}")]
    Storage(#[from] DbError),
    #[error("google: {0}")]
    Google(GoogleOAuthError),
}

const REFRESH_LEEWAY_SECS: u64 = 60;

#[derive(Clone)]
struct CachedSession {
    access_token: String,
    expires_at: u64,
    email: String,
    scopes: Vec<String>,
}

#[derive(Clone)]
pub struct SessionCache {
    state: Arc<State>,
}

struct State {
    cache: RwLock<HashMap<String, CachedSession>>,
    refresh_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    storage_key: [u8; 32],
    db: Db,
    google: Arc<GoogleOAuthClient>,
}

impl SessionCache {
    pub fn new(db: Db, google: Arc<GoogleOAuthClient>, storage_key: [u8; 32]) -> Self {
        Self {
            state: Arc::new(State {
                cache: RwLock::new(HashMap::new()),
                refresh_locks: Mutex::new(HashMap::new()),
                storage_key,
                db,
                google,
            }),
        }
    }

    /// Resolve a live session for `google_sub`, refreshing transparently.
    pub async fn resolve(&self, google_sub: &str) -> Result<GoogleAccountSession, SessionError> {
        if let Some(s) = self.read_fresh(google_sub).await {
            return Ok(s);
        }
        let lock = self.refresh_lock_for(google_sub).await;
        let _guard = lock.lock().await;

        // Another task may have refreshed while we waited.
        if let Some(s) = self.read_fresh(google_sub).await {
            return Ok(s);
        }

        // Slow path: hit Google. Debug-level traces here help diagnose
        // "account_not_found" reports without leaking the access token.
        tracing::debug!(google_sub, "session cache miss; fetching from DB");
        let refresh_token =
            accounts::get_refresh_token(&self.state.db, &self.state.storage_key, google_sub)
                .await?
                .ok_or(SessionError::AccountNotFound)?;

        let metadata = accounts::get(&self.state.db, google_sub)
            .await?
            .ok_or(SessionError::AccountNotFound)?;

        match self.state.google.refresh(&refresh_token).await {
            Ok(grant) => {
                let now = now_secs();
                let scopes: Vec<String> = grant
                    .scope
                    .as_deref()
                    .map(|s| s.split_whitespace().map(str::to_string).collect())
                    .unwrap_or(metadata.scopes.clone());
                let cached = CachedSession {
                    access_token: grant.access_token.clone(),
                    expires_at: now + grant.expires_in,
                    email: metadata.email.clone(),
                    scopes: scopes.clone(),
                };
                self.write_cache(google_sub, cached).await;
                let _ = accounts::touch_last_refresh(&self.state.db, google_sub).await;
                Ok(GoogleAccountSession {
                    google_sub: google_sub.to_string(),
                    email: metadata.email,
                    access_token: grant.access_token,
                    expires_at: now + grant.expires_in,
                    scopes,
                })
            }
            Err(GoogleOAuthError::InvalidGrant) => {
                tracing::warn!(
                    google_sub = %google_sub,
                    "Google returned invalid_grant; deleting account"
                );
                let _ = accounts::delete(&self.state.db, google_sub).await;
                self.invalidate(google_sub).await;
                Err(SessionError::ReconnectRequired)
            }
            Err(e) => Err(SessionError::Google(e)),
        }
    }

    /// Replace (or insert) the cache entry. Used by the OAuth callback to
    /// pre-warm the cache after the first authorization.
    pub async fn store_initial(
        &self,
        google_sub: &str,
        email: &str,
        access_token: &str,
        expires_in: u64,
        scopes: Vec<String>,
    ) {
        let cached = CachedSession {
            access_token: access_token.to_string(),
            expires_at: now_secs() + expires_in,
            email: email.to_string(),
            scopes,
        };
        self.write_cache(google_sub, cached).await;
    }

    pub async fn invalidate(&self, google_sub: &str) {
        self.state.cache.write().await.remove(google_sub);
    }

    async fn read_fresh(&self, google_sub: &str) -> Option<GoogleAccountSession> {
        let map = self.state.cache.read().await;
        let entry = map.get(google_sub)?;
        if entry.expires_at > now_secs() + REFRESH_LEEWAY_SECS {
            Some(GoogleAccountSession {
                google_sub: google_sub.to_string(),
                email: entry.email.clone(),
                access_token: entry.access_token.clone(),
                expires_at: entry.expires_at,
                scopes: entry.scopes.clone(),
            })
        } else {
            None
        }
    }

    async fn write_cache(&self, google_sub: &str, entry: CachedSession) {
        self.state
            .cache
            .write()
            .await
            .insert(google_sub.to_string(), entry);
    }

    async fn refresh_lock_for(&self, google_sub: &str) -> Arc<Mutex<()>> {
        let mut locks = self.state.refresh_locks.lock().await;
        Arc::clone(
            locks
                .entry(google_sub.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [3u8; 32]
    }

    fn make_cache(db: Db) -> SessionCache {
        // The Google client never gets called in this test (we exercise the cache fast-path only).
        let google = Arc::new(GoogleOAuthClient::new(
            "cid",
            "csecret",
            "http://localhost/cb",
            vec!["openid".to_string()],
            reqwest::Client::new(),
        ));
        SessionCache::new(db, google, key())
    }

    #[tokio::test]
    async fn store_initial_then_resolve_fast_path() {
        let db = Db::open_in_memory().await.unwrap();
        accounts::upsert(
            &db,
            &key(),
            accounts::UpsertAccount {
                google_sub: "sub-1".into(),
                email: "x@x.com".into(),
                refresh_token: "rt".into(),
                scopes: vec!["openid".into()],
            },
        )
        .await
        .unwrap();
        let cache = make_cache(db);
        cache
            .store_initial(
                "sub-1",
                "x@x.com",
                "live-access-token",
                3600,
                vec!["openid".into()],
            )
            .await;

        let session = cache.resolve("sub-1").await.unwrap();
        assert_eq!(session.access_token, "live-access-token");
        assert_eq!(session.email, "x@x.com");
        assert_eq!(session.scopes, vec!["openid"]);
    }

    #[tokio::test]
    async fn resolve_unknown_sub_returns_account_not_found() {
        let db = Db::open_in_memory().await.unwrap();
        let cache = make_cache(db);
        let err = cache.resolve("unknown").await.unwrap_err();
        assert!(matches!(err, SessionError::AccountNotFound));
    }

    #[tokio::test]
    async fn invalidate_drops_entry() {
        let db = Db::open_in_memory().await.unwrap();
        let cache = make_cache(db);
        cache
            .store_initial("sub", "x@x.com", "tok", 3600, vec![])
            .await;
        cache.invalidate("sub").await;
        // After invalidation, fast-path read miss; resolve falls into slow path
        // which fails because there's no row in oauth_accounts.
        let err = cache.resolve("sub").await.unwrap_err();
        assert!(matches!(err, SessionError::AccountNotFound));
    }
}
