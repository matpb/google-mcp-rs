//! Shared application state passed to every Axum handler and the rmcp
//! tool handler. All fields are cheap to clone (`Arc` or already cloneable).

use std::sync::Arc;

use crate::config::ServerConfig;
use crate::google::session::SessionCache;
use crate::oauth::google::GoogleOAuthClient;
use crate::storage::Db;

/// How the server establishes caller identity per request.
#[derive(Clone)]
pub enum Tenancy {
    /// HTTP transport: identity comes from the per-request bearer JWT
    /// (`sub` claim), verified on every tool call.
    MultiTenant,
    /// stdio transport: the process is bound to a single local Google account
    /// (`google_sub`). `None` means no account has been connected yet — the
    /// user must run `google-mcp auth` once.
    Single(Option<Arc<str>>),
}

#[derive(Clone)]
#[allow(dead_code)] // `http` is consumed by the Phase-3 Gmail client.
pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub db: Db,
    pub http: Arc<reqwest::Client>,
    pub google_oauth: Arc<GoogleOAuthClient>,
    pub session_cache: SessionCache,
    /// Identity model for this process (HTTP multi-tenant vs stdio single).
    pub tenancy: Tenancy,
}
