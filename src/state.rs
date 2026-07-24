//! Shared application state passed to every Axum handler and the rmcp
//! tool handler. All fields are cheap to clone (`Arc` or already cloneable).

use std::sync::{Arc, RwLock};

use crate::config::ServerConfig;
use crate::google::session::SessionCache;
use crate::oauth::google::GoogleOAuthClient;
use crate::storage::Db;

/// The Google account a single-tenant process is bound to, if any.
///
/// Shared and interior-mutable: the in-chat `google_authenticate` tool rebinds
/// the running process to a newly authorized account, so a user who signs in
/// with a different account takes effect immediately instead of silently
/// continuing to act as the previously bound one.
pub type BoundAccount = Arc<RwLock<Option<Arc<str>>>>;

/// How the server establishes caller identity per request.
#[derive(Clone)]
pub enum Tenancy {
    /// HTTP transport: identity comes from the per-request bearer JWT
    /// (`sub` claim), verified on every tool call.
    MultiTenant,
    /// stdio transport: the process is bound to a single local Google account
    /// (`google_sub`). Empty means no account has been connected yet — the user
    /// signs in with the `google_authenticate` tool or `google-mcp auth`.
    Single(BoundAccount),
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
