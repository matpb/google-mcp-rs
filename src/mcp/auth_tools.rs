//! The `google_authenticate` tool — exposed only in single-tenant (stdio)
//! mode, where there is no HTTP OAuth flow. Lets the user connect their Google
//! account from within the chat: calling it opens a browser for Google sign-in,
//! then stores the encrypted account locally. Composed into the router by
//! `GoogleMcp::new` when `Tenancy::Single`.

use rmcp::model::CallToolResult;
use rmcp::{ErrorData, tool, tool_router};

use crate::errors::McpError;
use crate::mcp::server::GoogleMcp;

#[tool_router(router = auth_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "google_authenticate",
        description = "Connect your Google account to this server. Opens a browser window for Google sign-in; approve access to Sheets and Drive, then return here. You only need to do this once — the connection is remembered."
    )]
    async fn google_authenticate(&self) -> Result<CallToolResult, ErrorData> {
        let scopes = crate::domain::google_scopes(&self.state.config.enabled_domains);
        match crate::local_auth::run_loopback(
            self.state.google_oauth.as_ref(),
            &self.state.config.base_url,
            &self.state.db,
            &self.state.config.storage_encryption_key,
            scopes,
            true,
        )
        .await
        {
            Ok(outcome) => Ok(CallToolResult::success(vec![rmcp::model::Content::text(
                format!(
                    "Connected Google account: {}. The Sheets and Drive tools are ready to use.",
                    outcome.email
                ),
            )])),
            Err(e) => Err(McpError::internal(format!("Google sign-in failed: {e}")).into()),
        }
    }
}
