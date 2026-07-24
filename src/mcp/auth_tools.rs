//! The `google_authenticate` tool — exposed only in single-tenant (stdio)
//! mode, where there is no HTTP OAuth flow. Lets the user connect their Google
//! account from within the chat: calling it opens a browser for Google sign-in,
//! then stores the encrypted account locally. Composed into the router by
//! `GoogleMcp::new` when `Tenancy::Single`.

use rmcp::model::CallToolResult;
use rmcp::{ErrorData, tool, tool_router};

use crate::errors::McpError;
use crate::mcp::server::GoogleMcp;
use crate::state::Tenancy;

#[tool_router(router = auth_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "google_authenticate",
        description = "Connect your Google account to this server. Opens a browser window for Google sign-in; approve the requested Google Workspace access, then return here. You only need to do this once — the connection is remembered."
    )]
    async fn google_authenticate(&self) -> Result<CallToolResult, ErrorData> {
        // Defence in depth. This tool binds a loopback listener and opens a
        // browser on the host, so it must never be reachable from the
        // multi-tenant HTTP surface even if the router composition in
        // `GoogleMcp::new` ever regressed and registered it there.
        if !matches!(self.state.tenancy, Tenancy::Single(_)) {
            return Err(McpError::invalid_input(
                "google_authenticate is only available in single-tenant (stdio) mode. \
                 HTTP clients authenticate through the OAuth flow at /authorize.",
            )
            .into());
        }

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
            Ok(outcome) => {
                // Rebind the running process to the account that just signed
                // in. Without this the server would keep using whichever
                // account was bound at startup while reporting success for the
                // new one — the user would silently read and send from the
                // wrong mailbox.
                if let Tenancy::Single(bound) = &self.state.tenancy {
                    *bound.write().expect("bound account lock") =
                        Some(std::sync::Arc::from(outcome.google_sub.as_str()));
                }
                let who = if outcome.email.is_empty() {
                    "your Google account".to_string()
                } else {
                    outcome.email.clone()
                };
                Ok(CallToolResult::success(vec![rmcp::model::Content::text(
                    format!("Connected {who}. Your Google Workspace tools are ready to use."),
                )]))
            }
            Err(e) => Err(McpError::internal(format!("Google sign-in failed: {e}")).into()),
        }
    }
}
