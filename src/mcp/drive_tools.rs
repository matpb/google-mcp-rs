//! Google Drive tools. Separate `#[tool_router(router = drive_router)]`
//! impl block — composed with `gmail_router` and `sheets_router` in
//! `mcp/server.rs`'s constructor via `ToolRouter::Add`.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::json;

use crate::errors::{McpError, to_mcp};
use crate::files::{FileJail, INLINE_MAX_BYTES, guess_mime};
use crate::google::drive::{DriveClient, DriveError};
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;

const FOLDER_MIME: &str = "application/vnd.google-apps.folder";

#[tool_router(router = drive_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "drive_list_files",
        description = "List/search Drive files using Drive's query syntax (https://developers.google.com/drive/api/guides/search-files). E.g. `name contains 'invoice' and mimeType = 'application/pdf' and trashed = false`. Returns `{ nextPageToken, files: [...] }`."
    )]
    async fn drive_list_files(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveListFilesParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        client
            .list_files(
                p.q.as_deref(),
                p.page_size,
                p.page_token.as_deref(),
                p.fields.as_deref(),
                p.order_by.as_deref(),
                p.spaces.as_deref(),
                p.include_items_from_all_drives,
            )
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "drive_get_file",
        description = "Fetch a Drive file's metadata. Default `fields` returns id, name, mimeType, parents, owners, timestamps, size, links, trashed status. Pass `supports_all_drives=true` for files that live in a Shared Drive."
    )]
    async fn drive_get_file(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveGetFileParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        client
            .get_file(&p.file_id, p.fields.as_deref(), p.supports_all_drives)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_drive_not_found(e, "file", &p.file_id))
    }

    #[tool(
        name = "drive_create_folder",
        description = "Create a new folder. `parent_id` nests it inside another folder; omit for the root."
    )]
    async fn drive_create_folder(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveCreateFolderParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        let mut body = json!({
            "name": p.name,
            "mimeType": FOLDER_MIME,
        });
        if let Some(parent) = p.parent_id {
            body["parents"] = json!([parent]);
        }
        if let Some(d) = p.description {
            body["description"] = json!(d);
        }
        client
            .create_metadata_only(&body)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "drive_create_file",
        description = "Upload a new file to Drive. Content comes from `path` (preferred — a file inside the server's FILE_ROOT exchange dir) OR `data_base64` (fallback). `mime_type` is inferred from the name/path when omitted. Multipart upload — keep payload below ~5 MB; for larger files use a follow-up resumable-upload tool (not yet wired)."
    )]
    async fn drive_create_file(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveCreateFileParams>,
    ) -> Result<String, ErrorData> {
        // Validate inputs before resolving the session so a bad payload
        // doesn't have to wait on a Google round-trip to surface.
        let (bytes, mime) = resolve_upload_content(
            self.state.config.file_jail.as_ref(),
            p.path.as_deref(),
            p.data_base64.as_deref(),
            p.mime_type.as_deref(),
            &p.name,
        )?;
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        let mut metadata = json!({
            "name": p.name,
            "mimeType": mime,
        });
        if let Some(parent) = p.parent_id {
            metadata["parents"] = json!([parent]);
        }
        if let Some(d) = p.description {
            metadata["description"] = json!(d);
        }
        client
            .create_with_content(&metadata, &bytes, &mime)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "drive_update_metadata",
        description = "Rename, re-describe, move (via add_parents/remove_parents), or star a file. Pass only the fields you want to change."
    )]
    async fn drive_update_metadata(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveUpdateMetadataParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        let mut body = json!({});
        if let Some(name) = p.name {
            body["name"] = json!(name);
        }
        if let Some(d) = p.description {
            body["description"] = json!(d);
        }
        if let Some(s) = p.starred {
            body["starred"] = json!(s);
        }
        client
            .update_metadata(
                &p.file_id,
                &body,
                p.add_parents.as_deref(),
                p.remove_parents.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_drive_not_found(e, "file", &p.file_id))
    }

    #[tool(
        name = "drive_update_content",
        description = "Replace a file's binary content. `mime_type` must match (or convert sensibly to) the file's stored type."
    )]
    async fn drive_update_content(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveUpdateContentParams>,
    ) -> Result<String, ErrorData> {
        let (bytes, mime) = resolve_upload_content(
            self.state.config.file_jail.as_ref(),
            p.path.as_deref(),
            p.data_base64.as_deref(),
            p.mime_type.as_deref(),
            // No name to infer from; fall back to octet-stream when neither a
            // mime_type nor a path extension is available.
            p.path.as_deref().unwrap_or(""),
        )?;
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        client
            .update_content(&p.file_id, &bytes, &mime)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_drive_not_found(e, "file", &p.file_id))
    }

    #[tool(
        name = "drive_download_file",
        description = "Download a file's binary bytes. Preferred: set `dest_path` (inside FILE_ROOT) to write the bytes to disk and get `{ path, sizeBytes, contentType }` back — nothing enters the model's context. Without `dest_path`, returns `{ contentType, sizeBytes, data: <base64 std> }` (capped when a file-exchange dir is available). For Google Docs/Sheets/Slides, use `drive_export_file` instead — they have no native bytes."
    )]
    async fn drive_download_file(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveDownloadFileParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        let (ct, bytes) = client
            .download_file(&p.file_id)
            .await
            .map_err(|e| reclassify_drive_not_found(e, "file", &p.file_id))?;
        deliver_bytes(
            self.state.config.file_jail.as_ref(),
            p.dest_path.as_deref(),
            &ct,
            &bytes,
        )
    }

    #[tool(
        name = "drive_export_file",
        description = "Export a Google Doc/Sheet/Slide to a downloadable format (e.g. `application/pdf`, `text/csv`, `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`, `text/markdown`). Returns base64-encoded bytes."
    )]
    async fn drive_export_file(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveExportFileParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        let (ct, bytes) = client
            .export_file(&p.file_id, &p.export_mime_type)
            .await
            .map_err(|e| reclassify_drive_not_found(e, "file", &p.file_id))?;
        deliver_bytes(
            self.state.config.file_jail.as_ref(),
            p.dest_path.as_deref(),
            &ct,
            &bytes,
        )
    }

    #[tool(
        name = "drive_copy_file",
        description = "Duplicate a file. Optional `name` and `parent_id` for the copy."
    )]
    async fn drive_copy_file(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveCopyFileParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        let mut metadata = json!({});
        if let Some(name) = p.name {
            metadata["name"] = json!(name);
        }
        if let Some(parent) = p.parent_id {
            metadata["parents"] = json!([parent]);
        }
        client
            .copy_file(&p.file_id, &metadata)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_drive_not_found(e, "file", &p.file_id))
    }

    #[tool(
        name = "drive_trash_file",
        description = "Move a file to Trash (reversible from Drive's UI for ~30 days)."
    )]
    async fn drive_trash_file(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveTrashFileParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        client
            .trash_file(&p.file_id)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_drive_not_found(e, "file", &p.file_id))
    }

    #[tool(
        name = "drive_delete_permanent",
        description = "Permanently delete a file. NOT reversible. Prefer `drive_trash_file` unless you really mean it."
    )]
    async fn drive_delete_permanent(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveDeletePermanentParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        client
            .delete_permanent(&p.file_id)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_drive_not_found(e, "file", &p.file_id))
    }

    #[tool(
        name = "drive_share_file",
        description = "Share a file by adding a permission. Required: `role` (`reader`/`commenter`/`writer`/`fileOrganizer`/`organizer`/`owner`) and `type` (`user`/`group`/`domain`/`anyone`). For user/group, also pass `email_address`. For domain, pass `domain`. By default a notification email goes out."
    )]
    async fn drive_share_file(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveSharePermissionParams>,
    ) -> Result<String, ErrorData> {
        validate_share(&p)?;
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        let mut perm = json!({
            "role": p.role,
            "type": p.r#type,
        });
        if let Some(e) = p.email_address {
            perm["emailAddress"] = json!(e);
        }
        if let Some(d) = p.domain {
            perm["domain"] = json!(d);
        }
        client
            .create_permission(
                &p.file_id,
                &perm,
                p.send_notification_email,
                p.email_message.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_drive_not_found(e, "file", &p.file_id))
    }

    #[tool(
        name = "drive_list_permissions",
        description = "List all permissions (sharing entries) on a file."
    )]
    async fn drive_list_permissions(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveListPermissionsParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        client
            .list_permissions(&p.file_id)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_drive_not_found(e, "file", &p.file_id))
    }

    #[tool(
        name = "drive_delete_permission",
        description = "Remove a sharing permission from a file by `permission_id` (get IDs from `drive_list_permissions`)."
    )]
    async fn drive_delete_permission(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DriveDeletePermissionParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DriveClient::new((*self.state.http).clone(), session.access_token);
        // 404 here is ambiguous between file_id and permission_id;
        // surface it as `permission` not_found since the parent file
        // existence is implicit (the agent could discover that themselves).
        client
            .delete_permission(&p.file_id, &p.permission_id)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_drive_not_found(e, "permission", &p.permission_id))
    }
}

/// Re-classify a Drive 404 into a typed `NotFound` so agents target their
/// discovery (e.g. `drive_list_files`) correctly.
fn reclassify_drive_not_found(e: DriveError, kind: &'static str, id: &str) -> ErrorData {
    if let DriveError::Api { status, .. } = &e
        && status.as_u16() == 404
    {
        return McpError::not_found(kind, id, "drive").into();
    }
    to_mcp(e)
}

fn validate_share(p: &DriveSharePermissionParams) -> Result<(), ErrorData> {
    let role = p.role.as_str();
    if !matches!(
        role,
        "reader" | "commenter" | "writer" | "fileOrganizer" | "organizer" | "owner"
    ) {
        return Err(McpError::invalid_input(format!(
            "invalid `role`: {role}; must be one of reader, commenter, writer, fileOrganizer, organizer, owner"
        ))
        .into());
    }
    let typ = p.r#type.as_str();
    if !matches!(typ, "user" | "group" | "domain" | "anyone") {
        return Err(McpError::invalid_input(format!(
            "invalid `type`: {typ}; must be one of user, group, domain, anyone"
        ))
        .into());
    }
    if matches!(typ, "user" | "group") && p.email_address.as_deref().unwrap_or("").is_empty() {
        return Err(
            McpError::invalid_input(format!("`type={typ}` requires `email_address`"))
                .with_hint("Pass the recipient's email in `email_address`.")
                .into(),
        );
    }
    if typ == "domain" && p.domain.as_deref().unwrap_or("").is_empty() {
        return Err(McpError::invalid_input(
            "`type=domain` requires `domain` (e.g. `example.com`)",
        )
        .into());
    }
    Ok(())
}

/// Error for when a tool needs FILE_ROOT but the operator hasn't enabled it.
fn no_file_root(what: &str) -> ErrorData {
    McpError::invalid_input(format!(
        "this server has no file-exchange directory configured (FILE_ROOT unset), so `{what}` cannot be used"
    ))
    .with_hint(
        "Use base64 instead, or ask the operator to set FILE_ROOT and bind-mount it into the container.",
    )
    .into()
}

/// Resolve upload content + effective MIME from exactly one of `path`
/// (via the FILE_ROOT jail) or `data_base64`. `name_for_mime` is the file
/// name/path used to infer a MIME type when none was supplied.
fn resolve_upload_content(
    jail: Option<&FileJail>,
    path: Option<&str>,
    data_base64: Option<&str>,
    mime_type: Option<&str>,
    name_for_mime: &str,
) -> Result<(Vec<u8>, String), ErrorData> {
    match (path, data_base64) {
        (Some(_), Some(_)) => Err(McpError::invalid_input(
            "`path` and `data_base64` are mutually exclusive — provide exactly one",
        )
        .into()),
        (None, None) => Err(McpError::invalid_input(
            "provide file content via `path` (preferred) or `data_base64`",
        )
        .into()),
        (Some(p), None) => {
            let jail = jail.ok_or_else(|| no_file_root("path"))?;
            let bytes = jail.read(p).map_err(to_mcp)?;
            let mime = mime_type
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| guess_mime(p).to_string());
            Ok((bytes, mime))
        }
        (None, Some(b64)) => {
            let bytes = decode_b64(b64)?;
            let mime = mime_type
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| guess_mime(name_for_mime).to_string());
            Ok((bytes, mime))
        }
    }
}

/// Deliver downloaded/exported bytes to the caller: write to `dest_path`
/// inside the jail (returning a path), or return base64 inline (guarded by
/// `INLINE_MAX_BYTES` when a jail alternative exists).
fn deliver_bytes(
    jail: Option<&FileJail>,
    dest_path: Option<&str>,
    content_type: &str,
    bytes: &[u8],
) -> Result<String, ErrorData> {
    if let Some(dest) = dest_path {
        let jail = jail.ok_or_else(|| no_file_root("dest_path"))?;
        let written = jail.write(dest, bytes).map_err(to_mcp)?;
        return Ok(json!({
            "path": written.display().to_string(),
            "sizeBytes": bytes.len(),
            "contentType": content_type,
        })
        .to_string());
    }
    if jail.is_some() && bytes.len() > INLINE_MAX_BYTES {
        return Err(McpError::invalid_input(format!(
            "file is {} bytes — too large to return inline as base64",
            bytes.len()
        ))
        .with_hint("Pass `dest_path` (inside FILE_ROOT) to write it to disk instead.")
        .into());
    }
    Ok(json!({
        "contentType": content_type,
        "sizeBytes": bytes.len(),
        "data": STANDARD.encode(bytes),
    })
    .to_string())
}

fn decode_b64(s: &str) -> Result<Vec<u8>, ErrorData> {
    let trimmed = s.trim();
    URL_SAFE_NO_PAD
        .decode(trimmed.trim_end_matches('='))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .or_else(|_| STANDARD.decode(trimmed))
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed.trim_end_matches('=')))
        .map_err(|e| ErrorData::invalid_params(format!("base64 decode: {e}"), None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_jail() -> FileJail {
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!("gmcp-drive-test-{}-{}", std::process::id(), id));
        FileJail::from_env(Some(dir.to_str().unwrap()))
            .unwrap()
            .unwrap()
    }

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn resolve_upload_from_base64_infers_mime_from_name() {
        let b64 = STANDARD.encode(b"hello");
        let (bytes, mime) =
            resolve_upload_content(None, None, Some(&b64), None, "notes.txt").unwrap();
        assert_eq!(bytes, b"hello");
        assert_eq!(mime, "text/plain");
    }

    #[test]
    fn resolve_upload_from_path_uses_jail() {
        let jail = temp_jail();
        jail.write("doc.pdf", b"%PDF-1.7").unwrap();
        let (bytes, mime) =
            resolve_upload_content(Some(&jail), Some("doc.pdf"), None, None, "doc.pdf").unwrap();
        assert_eq!(bytes, b"%PDF-1.7");
        assert_eq!(mime, "application/pdf");
    }

    #[test]
    fn resolve_upload_path_without_jail_errors() {
        let err = resolve_upload_content(None, Some("x.txt"), None, None, "x.txt").unwrap_err();
        // FILE_ROOT unset -> clear guidance, not a panic.
        assert!(err.message.contains("FILE_ROOT"), "got: {}", err.message);
    }

    #[test]
    fn resolve_upload_rejects_both_and_neither() {
        let b64 = STANDARD.encode(b"x");
        assert!(resolve_upload_content(None, Some("x"), Some(&b64), None, "x").is_err());
        assert!(resolve_upload_content(None, None, None, None, "x").is_err());
    }

    #[test]
    fn deliver_writes_to_dest_path() {
        let jail = temp_jail();
        let out = deliver_bytes(Some(&jail), Some("out.bin"), "application/octet-stream", b"data");
        let v = parse(&out.unwrap());
        assert_eq!(v["sizeBytes"], 4);
        let path = v["path"].as_str().unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"data");
        assert!(v.get("data").is_none(), "no base64 when writing to disk");
    }

    #[test]
    fn deliver_inline_base64_when_no_dest() {
        let out = deliver_bytes(None, None, "text/plain", b"hi").unwrap();
        let v = parse(&out);
        assert_eq!(v["data"], STANDARD.encode(b"hi"));
    }

    #[test]
    fn deliver_refuses_huge_inline_when_jail_available() {
        let jail = temp_jail();
        let big = vec![0u8; INLINE_MAX_BYTES + 1];
        let err = deliver_bytes(Some(&jail), None, "application/octet-stream", &big).unwrap_err();
        assert!(err.message.contains("too large"), "got: {}", err.message);
    }

    #[test]
    fn deliver_allows_huge_inline_when_no_jail() {
        // Without a jail there's no dest_path alternative, so we must not block.
        let big = vec![0u8; INLINE_MAX_BYTES + 1];
        assert!(deliver_bytes(None, None, "application/octet-stream", &big).is_ok());
    }
}
