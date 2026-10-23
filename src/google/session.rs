//! In-memory cache of Google access tokens keyed by `sub` (or `sub` + scope set for
//! downscoped tokens), refreshed lazily under a per-key single-flight lock.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

use crate::config::AllowedAccountEntry;
use crate::oauth::GoogleOAuthError;
use crate::oauth::google::GoogleOAuthClient;
use crate::oauth::jwt::now_secs;
use crate::storage::{Db, DbError, accounts, revocations};

/// Cache entry shape; `google_sub`/`expires_at` are set on insert but not read back by callers yet.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
    #[error("this Google account is no longer in ALLOWED_GOOGLE_ACCOUNTS")]
    AccountNotAllowed,
    #[error("storage: {0}")]
    Storage(#[from] DbError),
    #[error("google: {0}")]
    Google(GoogleOAuthError),
}

const REFRESH_LEEWAY_SECS: u64 = 60;
/// Separates the sub from the scope set in a downscoped cache key (never in a Google `sub`).
const KEY_SEP: char = '\u{0}';

/// Cache key: the bare sub for the full-scope token, else sub + sorted scope set.
fn cache_key(google_sub: &str, scopes: Option<&[&str]>) -> String {
    let Some(scopes) = scopes else {
        return google_sub.to_string();
    };
    let mut sorted: Vec<&str> = scopes.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    format!("{google_sub}{KEY_SEP}{}", sorted.join(" "))
}

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
    allowed_accounts: Vec<AllowedAccountEntry>,
}

impl SessionCache {
    pub fn new(
        db: Db,
        google: Arc<GoogleOAuthClient>,
        storage_key: [u8; 32],
        allowed_accounts: Vec<AllowedAccountEntry>,
    ) -> Self {
        Self {
            state: Arc::new(State {
                cache: RwLock::new(HashMap::new()),
                refresh_locks: Mutex::new(HashMap::new()),
                storage_key,
                db,
                google,
                allowed_accounts,
            }),
        }
    }

    /// Resolve a live session for `google_sub`, refreshing transparently.
    pub async fn resolve(&self, google_sub: &str) -> Result<GoogleAccountSession, SessionError> {
        self.resolve_inner(google_sub, None).await
    }

    /// Like `resolve`, but the token carries only `scopes`; cached per
    /// (sub, scope set) apart from the full-scope token.
    pub async fn resolve_scoped(
        &self,
        google_sub: &str,
        scopes: &[&str],
    ) -> Result<GoogleAccountSession, SessionError> {
        self.resolve_inner(google_sub, Some(scopes)).await
    }

    async fn resolve_inner(
        &self,
        google_sub: &str,
        scopes: Option<&[&str]>,
    ) -> Result<GoogleAccountSession, SessionError> {
        let key = cache_key(google_sub, scopes);
        if let Some(s) = self.read_fresh(&key, google_sub).await {
            return Ok(s);
        }
        let lock = self.refresh_lock_for(&key).await;
        let _guard = lock.lock().await;

        // Another task may have refreshed while we waited.
        if let Some(s) = self.read_fresh(&key, google_sub).await {
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

        if !crate::config::account_allowed_by_email(&self.state.allowed_accounts, &metadata.email) {
            return Err(SessionError::AccountNotAllowed);
        }

        let refreshed = match scopes {
            Some(sc) => self.state.google.refresh_scoped(&refresh_token, sc).await,
            None => self.state.google.refresh(&refresh_token).await,
        };
        match refreshed {
            Ok(grant) => {
                let now = now_secs();
                let fallback = match scopes {
                    Some(sc) => sc.iter().map(ToString::to_string).collect(),
                    None => metadata.scopes.clone(),
                };
                let scopes: Vec<String> = grant.scope.as_deref().map_or(fallback, |s| {
                    s.split_whitespace().map(str::to_string).collect()
                });
                let cached = CachedSession {
                    access_token: grant.access_token.clone(),
                    expires_at: now + grant.expires_in,
                    email: metadata.email.clone(),
                    scopes: scopes.clone(),
                };
                self.write_cache(&key, cached).await;
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
                let _ = revocations::revoke(&self.state.db, google_sub, now_secs() as i64).await;
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
        self.write_cache(&cache_key(google_sub, None), cached).await;
    }

    /// Drop the sub's full-scope entry and every downscoped entry.
    pub async fn invalidate(&self, google_sub: &str) {
        let scoped_prefix = format!("{google_sub}{KEY_SEP}");
        self.state
            .cache
            .write()
            .await
            .retain(|k, _| k != google_sub && !k.starts_with(&scoped_prefix));
    }

    async fn read_fresh(&self, key: &str, google_sub: &str) -> Option<GoogleAccountSession> {
        let map = self.state.cache.read().await;
        let entry = map.get(key)?;
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

    async fn write_cache(&self, key: &str, entry: CachedSession) {
        self.state
            .cache
            .write()
            .await
            .insert(key.to_string(), entry);
    }

    async fn refresh_lock_for(&self, key: &str) -> Arc<Mutex<()>> {
        let mut locks = self.state.refresh_locks.lock().await;
        Arc::clone(
            locks
                .entry(key.to_string())
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
        SessionCache::new(db, google, key(), vec![])
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

    #[tokio::test]
    async fn resolve_rejects_account_outside_allowlist() {
        let db = Db::open_in_memory().await.unwrap();
        accounts::upsert(
            &db,
            &key(),
            accounts::UpsertAccount {
                google_sub: "sub-1".into(),
                email: "outsider@evil.com".into(),
                refresh_token: "rt".into(),
                scopes: vec![],
            },
        )
        .await
        .unwrap();
        let google = Arc::new(GoogleOAuthClient::new(
            "cid",
            "csecret",
            "http://localhost/cb",
            vec!["openid".to_string()],
            reqwest::Client::new(),
        ));
        let cache = SessionCache::new(
            db,
            google,
            key(),
            vec![crate::config::AllowedAccountEntry::Domain(
                "example.com".into(),
            )],
        );
        cache
            .store_initial("sub-1", "outsider@evil.com", "tok", 3600, vec![])
            .await;
        // Fast-path cache hit still checks the allowlist on the slow path
        // only, so invalidate first to force the DB lookup.
        cache.invalidate("sub-1").await;
        let err = cache.resolve("sub-1").await.unwrap_err();
        assert!(matches!(err, SessionError::AccountNotAllowed));
    }

    fn entry(token: &str) -> CachedSession {
        CachedSession {
            access_token: token.into(),
            expires_at: now_secs() + 3600,
            email: "x@x.com".into(),
            scopes: vec![],
        }
    }

    #[test]
    fn cache_key_ignores_scope_order_and_differs_from_plain() {
        let a = cache_key("s", Some(&["b", "a"]));
        assert_eq!(a, cache_key("s", Some(&["a", "b", "a"])));
        assert_ne!(a, cache_key("s", None));
        assert_ne!(a, cache_key("s", Some(&["a"])));
        assert_eq!(cache_key("s", None), "s");
    }

    #[tokio::test]
    async fn scoped_and_plain_tokens_are_cached_separately() {
        let db = Db::open_in_memory().await.unwrap();
        let cache = make_cache(db);
        cache.write_cache("sub", entry("full")).await;
        cache
            .write_cache(&cache_key("sub", Some(&["h1", "h2"])), entry("health"))
            .await;
        assert_eq!(cache.resolve("sub").await.unwrap().access_token, "full");
        let scoped = cache.resolve_scoped("sub", &["h2", "h1"]).await.unwrap();
        assert_eq!(scoped.access_token, "health");
        assert_eq!(scoped.google_sub, "sub");
    }

    #[tokio::test]
    async fn invalidate_drops_scoped_entries_of_that_sub_only() {
        let db = Db::open_in_memory().await.unwrap();
        let cache = make_cache(db);
        let key = cache_key("sub", Some(&["h1"]));
        let other = cache_key("sub2", Some(&["h1"]));
        cache.write_cache("sub", entry("full")).await;
        cache.write_cache(&key, entry("health")).await;
        cache.write_cache("sub2", entry("full2")).await;
        cache.write_cache(&other, entry("health2")).await;
        cache.invalidate("sub").await;
        let map = cache.state.cache.read().await;
        assert!(!map.contains_key("sub") && !map.contains_key(&key));
        assert!(map.contains_key("sub2") && map.contains_key(&other));
    }

    #[tokio::test]
    async fn resolve_scoped_unknown_sub_returns_account_not_found() {
        let db = Db::open_in_memory().await.unwrap();
        let cache = make_cache(db);
        let err = cache.resolve_scoped("unknown", &["h1"]).await.unwrap_err();
        assert!(matches!(err, SessionError::AccountNotFound));
    }
}
