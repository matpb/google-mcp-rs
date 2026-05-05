//! `GoogleMcp` — the rmcp server handler. Holds the shared `AppState`,
//! provides per-request credential resolution, and bridges domain errors
//! into `rmcp::ErrorData`.

use http::request::Parts;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{ErrorData, ServerHandler, tool_handler};

use crate::credentials::{CredentialsError, resolve_google};
use crate::google::gmail::{GmailClient, GmailError};
use crate::google::session::GoogleAccountSession;
use crate::mime::MimeError;
use crate::state::AppState;

#[derive(Clone)]
pub struct GoogleMcp {
    pub(crate) state: AppState,
    pub(crate) tool_router: ToolRouter<Self>,
}

impl GoogleMcp {
    pub fn new(state: AppState) -> Self {
        let tool_router = Self::gmail_router();
        Self { state, tool_router }
    }

    pub(crate) async fn resolve_session(
        &self,
        parts: &Parts,
    ) -> Result<GoogleAccountSession, ErrorData> {
        resolve_google(
            parts,
            &self.state.config.jwt_secret,
            &self.state.config.base_url,
            &self.state.session_cache,
        )
        .await
        .map_err(creds_to_error)
    }

    pub(crate) async fn gmail_for(&self, parts: &Parts) -> Result<GmailClient, ErrorData> {
        let session = self.resolve_session(parts).await?;
        Ok(GmailClient::new(
            (*self.state.http).clone(),
            session.access_token,
        ))
    }
}

pub(crate) fn creds_to_error(e: CredentialsError) -> ErrorData {
    use CredentialsError::*;
    match e {
        Missing | Malformed => ErrorData::invalid_request(e.to_string(), None),
        Jwt(_) => ErrorData::invalid_request(e.to_string(), None),
        Session(s) => ErrorData::invalid_request(s.to_string(), None),
    }
}

pub(crate) fn gmail_to_error(e: GmailError) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}

pub(crate) fn mime_to_error(e: MimeError) -> ErrorData {
    ErrorData::invalid_params(e.to_string(), None)
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for GoogleMcp {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(
            "Google Workspace MCP — Gmail tools (Phase 1). Multi-tenant: each \
             user authorizes via the OAuth flow at /authorize and the server \
             mints an MCP JWT bound to their Google sub. All tools operate on \
             the authenticated user's mailbox; one Google account per JWT for \
             now (Phase 2 will add a per-tool `account` parameter). The send \
             surface is live by default — there is no draft-only safety knob, \
             so route agents to gmail_create_draft if you want explicit human \
             approval before a message goes out."
                .into(),
        );
        info
    }
}
