//! File-exchange directory maintenance tools (`files_info`, `files_cleanup`).
//!
//! These are only wired into the router when `FILE_ROOT` is enabled (see
//! `GoogleMcp::new`), since they're meaningless without a file-exchange
//! directory. They operate purely on the server's local `FILE_ROOT` — no
//! Google API calls, no session needed beyond the JWT that already gates
//! `/mcp`. `files_cleanup` defaults to a dry run and never touches `keep/`.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::{Value, json};

use crate::errors::McpError;
use crate::files::{FileJail, plan_delete};
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;

#[tool_router(router = files_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "files_info",
        description = "Report the state of the file-exchange directory (FILE_ROOT): its path, the number of files, total bytes, and a listing (oldest first, so stale files surface). Use this to discover where to stage files for attachment/upload, and to see what has accumulated before calling files_cleanup. Files in the reserved `keep/` subdirectory are excluded."
    )]
    async fn files_info(
        &self,
        Parameters(p): Parameters<FilesInfoParams>,
    ) -> Result<String, ErrorData> {
        let jail = self.file_jail()?;
        let mut entries = jail.scan().map_err(crate::errors::to_mcp)?;
        entries.sort_by_key(|e| e.modified);
        let total_bytes: u64 = entries.iter().map(|e| e.size).sum();
        let total_files = entries.len();
        let now = std::time::SystemTime::now();
        let limit = p.limit.unwrap_or(100) as usize;
        let files: Vec<Value> = entries
            .iter()
            .take(limit)
            .map(|e| {
                let age_hours = now
                    .duration_since(e.modified)
                    .map(|d| d.as_secs_f64() / 3600.0)
                    .unwrap_or(0.0);
                json!({
                    "path": e.path.display().to_string(),
                    "sizeBytes": e.size,
                    "ageHours": (age_hours * 10.0).round() / 10.0,
                })
            })
            .collect();
        Ok(json!({
            "fileRoot": jail.root().display().to_string(),
            "totalFiles": total_files,
            "totalBytes": total_bytes,
            "listed": files.len(),
            "files": files,
            "note": "Stage files for attachment/upload here, then pass them by `path`. \
                     Save downloads here via `dest_path`. Put anything you want protected \
                     from files_cleanup under a `keep/` subdirectory.",
        })
        .to_string())
    }

    #[tool(
        name = "files_cleanup",
        description = "Tidy the file-exchange directory (FILE_ROOT). SAFE BY DEFAULT: dry_run is true unless you set it false, so by default this only REPORTS what would be deleted. Narrow the selection with `older_than_hours` and/or `name_contains`; with neither, it selects every file. Only regular files inside FILE_ROOT are eligible; the reserved `keep/` subdirectory is never touched. Set `dry_run=false` to actually delete."
    )]
    async fn files_cleanup(
        &self,
        Parameters(p): Parameters<FilesCleanupParams>,
    ) -> Result<String, ErrorData> {
        let jail = self.file_jail()?;
        let entries = jail.scan().map_err(crate::errors::to_mcp)?;
        let now = std::time::SystemTime::now();
        let older_than_secs = p.older_than_hours.map(|h| (h * 3600.0).max(0.0) as u64);
        let selected = plan_delete(&entries, now, older_than_secs, p.name_contains.as_deref());

        let selected_bytes: u64 = selected.iter().map(|e| e.size).sum();
        let names: Vec<String> = selected
            .iter()
            .map(|e| e.path.display().to_string())
            .collect();

        if p.dry_run {
            return Ok(json!({
                "dryRun": true,
                "wouldDelete": names.len(),
                "wouldFreeBytes": selected_bytes,
                "files": names,
                "hint": "Re-run with dry_run=false to delete these. Nothing was removed.",
            })
            .to_string());
        }

        let mut deleted = Vec::new();
        let mut freed: u64 = 0;
        let mut errors = Vec::new();
        for e in selected {
            match jail.remove_file(&e.path) {
                Ok(bytes) => {
                    freed += bytes;
                    deleted.push(e.path.display().to_string());
                }
                Err(err) => errors.push(json!({
                    "path": e.path.display().to_string(),
                    "error": err.to_string(),
                })),
            }
        }
        Ok(json!({
            "dryRun": false,
            "deleted": deleted.len(),
            "freedBytes": freed,
            "files": deleted,
            "errors": errors,
        })
        .to_string())
    }
}

impl GoogleMcp {
    /// The configured file-exchange jail, or a clear error when FILE_ROOT is
    /// unset. (The files tools are only routed when enabled, so this is
    /// belt-and-suspenders.)
    fn file_jail(&self) -> Result<&FileJail, ErrorData> {
        self.state.config.file_jail.as_ref().ok_or_else(|| {
            McpError::invalid_input(
                "file-exchange is disabled on this server (FILE_ROOT unset)",
            )
            .into()
        })
    }
}
