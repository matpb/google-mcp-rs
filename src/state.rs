//! Shared application state passed to every Axum handler and the rmcp
//! tool handler. All fields are cheap to clone (`Arc` or already cloneable).

use std::sync::Arc;

use crate::config::ServerConfig;
use crate::google::session::SessionCache;
use crate::oauth::google::GoogleOAuthClient;
use crate::storage::Db;

#[derive(Clone)]
#[allow(dead_code)] // `http` is consumed by the Phase-3 Gmail client.
pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub db: Db,
    pub http: Arc<reqwest::Client>,
    pub google_oauth: Arc<GoogleOAuthClient>,
    pub session_cache: SessionCache,
}
