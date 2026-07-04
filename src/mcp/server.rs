//! `GoogleMcp` — the rmcp server handler. Holds the shared `AppState`,
//! provides per-request credential resolution, and bridges domain errors
//! into `rmcp::ErrorData`.

use http::request::Parts;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{ErrorData, ServerHandler, tool_handler};

use crate::credentials::resolve_google;
use crate::domain::Domain;
use crate::errors::to_mcp;
use crate::files::FileJail;
use crate::google::gmail::GmailClient;
use crate::google::session::GoogleAccountSession;
use crate::state::AppState;

#[derive(Clone)]
pub struct GoogleMcp {
    pub(crate) state: AppState,
    pub(crate) tool_router: ToolRouter<Self>,
}

impl GoogleMcp {
    pub fn new(state: AppState) -> Self {
        // Compose only the routers for domains the operator enabled via
        // `ENABLED_DOMAINS`. Each domain owns its own
        // `#[tool_router(router = ...)]` impl block. `parse_enabled`
        // guarantees the list is non-empty so the seed-then-fold pattern
        // is safe.
        let mut iter = state.config.enabled_domains.iter().copied();
        let first = iter.next().expect("enabled_domains is non-empty");
        let mut tool_router = Self::router_for(first);
        for d in iter {
            tool_router += Self::router_for(d);
        }
        // File-maintenance tools exist only when FILE_ROOT is set (they're
        // meaningless without an exchange directory) AND the operator opted in
        // via FILE_MAINTENANCE_TOOLS. Default is Off, so no listing/deletion
        // tool appears unless explicitly enabled. `files_info` is read-only
        // (Info or Full); `files_cleanup` deletes (Full only).
        if state.config.file_jail.is_some() {
            let m = state.config.file_maintenance;
            if m.info_enabled() {
                tool_router += Self::files_info_router();
            }
            if m.cleanup_enabled() {
                tool_router += Self::files_cleanup_router();
            }
        }
        Self { state, tool_router }
    }

    fn router_for(domain: Domain) -> ToolRouter<Self> {
        match domain {
            Domain::Gmail => Self::gmail_router(),
            Domain::Sheets => Self::sheets_router(),
            Domain::Drive => Self::drive_router(),
            Domain::Docs => Self::docs_router(),
            Domain::Calendar => Self::calendar_router(),
        }
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
        .map_err(to_mcp)
    }

    pub(crate) async fn gmail_for(&self, parts: &Parts) -> Result<GmailClient, ErrorData> {
        let session = self.resolve_session(parts).await?;
        Ok(GmailClient::new(
            (*self.state.http).clone(),
            session.access_token,
        ))
    }
}

#[cfg(test)]
mod harness {
    //! Integration-test harness — constructs a `GoogleMcp` from an
    //! in-memory `AppState` so we can verify the live tool router only
    //! contains the surfaces enabled via `ENABLED_DOMAINS`. Kept as a
    //! `pub(crate)` module so other tests can reuse it if needed.

    use std::sync::Arc;

    use super::{AppState, GoogleMcp};
    use crate::config::ServerConfig;
    use crate::domain::{self, Domain};
    use crate::google::session::SessionCache;
    use crate::oauth::google::GoogleOAuthClient;
    use crate::storage::Db;

    pub(crate) async fn make_mcp(enabled_domains: Vec<Domain>) -> GoogleMcp {
        let db = Db::open_in_memory().await.expect("open in-memory db");
        let http = Arc::new(reqwest::Client::new());
        let google_oauth = Arc::new(GoogleOAuthClient::new(
            "test-cid",
            "test-csecret",
            "http://localhost:8433/oauth/google/callback",
            domain::google_scopes(&enabled_domains),
            (*http).clone(),
        ));
        let session_cache = SessionCache::new(db.clone(), Arc::clone(&google_oauth), [0u8; 32]);
        let config = Arc::new(ServerConfig {
            host: "127.0.0.1".parse().expect("ip"),
            port: 8433,
            base_url: "http://localhost:8433".to_string(),
            google_client_id: "test-cid".to_string(),
            google_client_secret: "test-csecret".to_string(),
            jwt_secret: vec![0u8; 32],
            storage_encryption_key: [0u8; 32],
            database_url: ":memory:".to_string(),
            cors_allow_localhost: false,
            enabled_domains,
            file_jail: None,
            file_maintenance: crate::files::FileMaintenance::Off,
        });
        let state = AppState {
            config,
            db,
            http,
            google_oauth,
            session_cache,
        };
        GoogleMcp::new(state)
    }

    pub(crate) async fn make_mcp_with_jail(
        enabled_domains: Vec<Domain>,
        maintenance: crate::files::FileMaintenance,
    ) -> GoogleMcp {
        let dir = std::env::temp_dir().join(format!("gmcp-router-jail-{}", std::process::id()));
        let jail = crate::files::FileJail::from_env(Some(dir.to_str().unwrap()))
            .unwrap()
            .unwrap();
        let mcp = make_mcp(enabled_domains.clone()).await;
        // Rebuild with a config that has the jail + maintenance level set.
        let cfg = crate::config::ServerConfig {
            host: "127.0.0.1".parse().unwrap(),
            port: 8433,
            base_url: "http://localhost:8433".to_string(),
            google_client_id: "test-cid".to_string(),
            google_client_secret: "test-csecret".to_string(),
            jwt_secret: vec![0u8; 32],
            storage_encryption_key: [0u8; 32],
            database_url: ":memory:".to_string(),
            cors_allow_localhost: false,
            enabled_domains,
            file_jail: Some(jail),
            file_maintenance: maintenance,
        };
        let mut state = mcp.state.clone();
        state.config = std::sync::Arc::new(cfg);
        GoogleMcp::new(state)
    }

    pub(crate) fn tool_names(mcp: &GoogleMcp) -> Vec<String> {
        mcp.tool_router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect()
    }

    /// The number of tools each domain is expected to expose. Treated as
    /// part of the project's public surface contract — if you intentionally
    /// add a tool, bump the count here so the regression assertions
    /// continue to mean something.
    pub(crate) fn expected_count(d: Domain) -> usize {
        match d {
            Domain::Gmail => 25,
            Domain::Sheets => 11,
            Domain::Drive => 14,
            Domain::Docs => 12,
            Domain::Calendar => 14,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::harness::*;
    use crate::domain::Domain;

    #[tokio::test]
    async fn files_tools_gated_by_file_root_and_maintenance_level() {
        use super::GoogleMcp;
        use crate::files::FileMaintenance;
        let files_of = |m: &GoogleMcp| -> Vec<String> {
            let mut v: Vec<String> = tool_names(m)
                .into_iter()
                .filter(|n| n.starts_with("files_"))
                .collect();
            v.sort();
            v
        };

        // No FILE_ROOT => never any files_* tools.
        let without = make_mcp(vec![Domain::Gmail]).await;
        assert!(files_of(&without).is_empty());

        // FILE_ROOT set but maintenance Off (the default) => still none.
        let off = make_mcp_with_jail(vec![Domain::Gmail], FileMaintenance::Off).await;
        assert!(
            files_of(&off).is_empty(),
            "Off must expose no maintenance tools even with FILE_ROOT set"
        );

        // Info => files_info only (read-only), no deletion tool.
        let info = make_mcp_with_jail(vec![Domain::Gmail], FileMaintenance::Info).await;
        assert_eq!(files_of(&info), vec!["files_info".to_string()]);

        // Full => files_info + files_cleanup.
        let full = make_mcp_with_jail(vec![Domain::Gmail], FileMaintenance::Full).await;
        assert_eq!(
            files_of(&full),
            vec!["files_cleanup".to_string(), "files_info".to_string()]
        );

        // Domain tools unaffected.
        assert_eq!(
            tool_names(&full)
                .iter()
                .filter(|n| n.starts_with("gmail_"))
                .count(),
            expected_count(Domain::Gmail)
        );
    }

    #[tokio::test]
    async fn each_single_domain_loads_only_its_tools() {
        for d in Domain::ALL {
            let mcp = make_mcp(vec![d]).await;
            let names = tool_names(&mcp);
            let expected_prefix = format!("{}_", d.as_str());
            assert_eq!(
                names.len(),
                expected_count(d),
                "{d}: tool count drift — update expected_count() if intentional"
            );
            for name in &names {
                assert!(
                    name.starts_with(&expected_prefix),
                    "{d}: tool '{name}' doesn't start with '{expected_prefix}' (cross-domain leak?)"
                );
            }
        }
    }

    #[tokio::test]
    async fn all_domains_loads_full_surface() {
        let mcp = make_mcp(Domain::ALL.to_vec()).await;
        let names = tool_names(&mcp);
        let total: usize = Domain::ALL.iter().map(|d| expected_count(*d)).sum();
        assert_eq!(names.len(), total, "full surface count drift");

        for d in Domain::ALL {
            let prefix = format!("{}_", d.as_str());
            let count = names.iter().filter(|n| n.starts_with(&prefix)).count();
            assert_eq!(
                count,
                expected_count(d),
                "{d}: count in full set doesn't match domain-only count"
            );
        }
    }

    #[tokio::test]
    async fn pair_loads_only_listed_domains() {
        let mcp = make_mcp(vec![Domain::Gmail, Domain::Calendar]).await;
        let names = tool_names(&mcp);
        assert_eq!(
            names.len(),
            expected_count(Domain::Gmail) + expected_count(Domain::Calendar)
        );
        for name in &names {
            assert!(
                name.starts_with("gmail_") || name.starts_with("calendar_"),
                "tool '{name}' shouldn't be loaded for gmail+calendar pair"
            );
        }
    }

    #[tokio::test]
    async fn router_composition_is_order_independent() {
        let a = make_mcp(vec![Domain::Gmail, Domain::Sheets]).await;
        let b = make_mcp(vec![Domain::Sheets, Domain::Gmail]).await;
        let mut names_a = tool_names(&a);
        let mut names_b = tool_names(&b);
        names_a.sort();
        names_b.sort();
        assert_eq!(names_a, names_b);
    }

    #[tokio::test]
    async fn tool_names_are_unique_across_full_surface() {
        let mcp = make_mcp(Domain::ALL.to_vec()).await;
        let names = tool_names(&mcp);
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "duplicate tool name in composed router — two domains define the same tool"
        );
    }

    #[tokio::test]
    async fn dropping_a_domain_drops_exactly_its_tools() {
        let full = make_mcp(Domain::ALL.to_vec()).await;
        let without_drive = make_mcp(vec![
            Domain::Gmail,
            Domain::Sheets,
            Domain::Docs,
            Domain::Calendar,
        ])
        .await;
        let full_names: std::collections::HashSet<_> = tool_names(&full).into_iter().collect();
        let trimmed_names: std::collections::HashSet<_> =
            tool_names(&without_drive).into_iter().collect();
        let dropped: Vec<_> = full_names.difference(&trimmed_names).cloned().collect();
        assert_eq!(
            dropped.len(),
            expected_count(Domain::Drive),
            "dropping Drive should remove exactly {} tools",
            expected_count(Domain::Drive)
        );
        assert!(
            dropped.iter().all(|n| n.starts_with("drive_")),
            "non-Drive tool was dropped: {dropped:?}"
        );
    }
}

/// Build the FILE HANDLING section of the server instructions. Includes the
/// live exchange-directory path (when enabled) so a calling AI knows exactly
/// where to stage files — this is the single most important thing for it to
/// use paths instead of base64 correctly.
fn file_handling_instructions(jail: Option<&FileJail>) -> String {
    match jail {
        Some(j) => {
            let root = j.root().display();
            format!(
                "FILE HANDLING (READ THIS BEFORE MOVING ANY FILE — attachments, uploads, \
                 downloads). This server exchanges file bytes by PATH via a shared directory, \
                 which is far cheaper and more reliable than base64. The file-exchange directory \
                 is `{root}` (same path on the host and inside the server). Rules:\n\
                 • To ATTACH or UPLOAD a local file, the file MUST be inside `{root}`. Files \
                 anywhere else (e.g. ~/Downloads) are REJECTED — copy them into `{root}` first, \
                 then pass `path` (Gmail `attachments[].path`, `drive_create_file.path`, \
                 `drive_update_content.path`). Paths may be absolute under the dir or relative to it.\n\
                 • To SAVE an attachment or download, pass `dest_path` inside `{root}` \
                 (`gmail_download_attachment`, `drive_download_file`, `drive_export_file`). The \
                 bytes are written to disk and only `{{path, sizeBytes, ...}}` comes back — no base64.\n\
                 • To move a file between Gmail and Drive WITHOUT base64, use `drive_file_id` on a \
                 Gmail attachment, or `to_drive_folder_id` on `gmail_download_attachment`.\n\
                 • `mime_type` is inferred from the filename when omitted.\n\
                 • Only fall back to `data_base64` when a file genuinely can't be placed in `{root}`. \
                 Downloads larger than 8 MB refuse to return inline — use `dest_path`."
            )
        }
        None => "FILE HANDLING: the filesystem file-exchange is DISABLED on this server \
             (FILE_ROOT is unset). Provide file bytes via `data_base64` on uploads/attachments, \
             and downloads/attachments are returned as base64. Ask the operator to set FILE_ROOT \
             and bind-mount it to enable path-based exchange."
            .to_string(),
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for GoogleMcp {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        let base = "Google Workspace MCP — Gmail + Sheets + Drive + Docs + Calendar. \
             Multi-tenant: each user authorizes via the OAuth flow at \
             /authorize and the server mints an MCP JWT bound to their \
             Google sub. All tools operate on the authenticated user's \
             data; one Google account per JWT for now. The Gmail send \
             surface is live by default (no draft-only safety knob), so \
             route agents to gmail_create_draft when you want explicit \
             human approval. Drive's `drive_delete_permanent` is \
             irreversible — prefer `drive_trash_file`. Sheets \
             `value_input_option=USER_ENTERED` parses formulas/dates the \
             way the UI does; `RAW` (default) stores values verbatim. \
             Calendar event mutations default to `send_updates=none` so \
             agents don't accidentally email guests; pass \
             `send_updates=\"all\"` when the human-facing notification \
             is intentional.";
        info.instructions = Some(format!(
            "{base}\n\n{}",
            file_handling_instructions(self.state.config.file_jail.as_ref())
        ));
        info
    }
}
