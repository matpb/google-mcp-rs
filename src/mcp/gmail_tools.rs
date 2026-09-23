//! All Gmail `#[tool]` methods. The single `#[tool_router(router = gmail_router)]`
//! impl block emits a `Self::gmail_router()` constructor that the
//! `GoogleMcp::new` call wires into the struct's `tool_router` field.

use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::{Value, json};

use crate::errors::{McpError, to_mcp};
use crate::files::FileJail;
use crate::google::drive::DriveClient;
use crate::google::gmail::{
    CreateFilter, CreateLabel, FilterAction, FilterCriteria, GmailClient, LabelColor, ModifyLabels,
    UpdateLabel,
};
use crate::mcp::common;
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;
use crate::mime::{AttachmentInput, AttachmentSource, Compose, ReplyContext, ResolvedAttachment};

#[tool_router(router = gmail_router, vis = "pub(crate)")]
impl GoogleMcp {
    // -----------------------------------------------------------------
    // Profile
    // -----------------------------------------------------------------

    #[tool(
        name = "gmail_get_profile",
        description = "Return the connected Google account's email, the granted scopes, and Gmail's idea of total counts (messagesTotal, threadsTotal, historyId). Useful for confirming which mailbox the JWT is bound to."
    )]
    async fn gmail_get_profile(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = GmailClient::new((*self.state.http).clone(), &session.access_token);
        let profile = client.profile().await.map_err(to_mcp)?;
        let out = json!({
            "email": session.email,
            "scopes": session.scopes,
            "profile": profile,
        });
        Ok(out.to_string())
    }

    // -----------------------------------------------------------------
    // Threads
    // -----------------------------------------------------------------

    #[tool(
        name = "gmail_search_threads",
        description = "Search threads with Gmail query syntax (e.g. `from:foo is:unread newer_than:7d`). Returns a list of thread IDs and a nextPageToken cursor when there are more."
    )]
    async fn gmail_search_threads(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailSearchThreadsParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client
            .list_threads(
                Some(&p.q),
                p.max_results,
                p.page_token.as_deref(),
                &p.label_ids,
            )
            .await
            .map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_get_thread",
        description = "Fetch a thread with all its messages. Default `format=full` returns parsed payload (headers + decoded body parts). Use `metadata` to skip bodies, `raw` for the source RFC 5322."
    )]
    async fn gmail_get_thread(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailGetThreadParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client
            .get_thread(&p.id, p.format.as_deref())
            .await
            .map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_get_thread_url",
        description = "Build the Gmail web UI URL for a thread, scoped to the connected account so it routes correctly even when the user is signed into multiple Google accounts in the browser."
    )]
    async fn gmail_get_thread_url(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailGetThreadUrlParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let segment = match p.account_index {
            Some(idx) => idx.to_string(),
            None => session.email.clone(),
        };
        let url = format!(
            "https://mail.google.com/mail/u/{}/#inbox/{}",
            urlencoding(&segment),
            p.thread_id
        );
        Ok(json!({ "url": url, "account": session.email }).to_string())
    }

    // -----------------------------------------------------------------
    // Messages
    // -----------------------------------------------------------------

    #[tool(
        name = "gmail_list_messages",
        description = "List messages, optionally filtered by Gmail query syntax. Returns IDs + thread IDs + nextPageToken."
    )]
    async fn gmail_list_messages(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailListMessagesParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client
            .list_messages(
                p.q.as_deref(),
                p.max_results,
                p.page_token.as_deref(),
                &p.label_ids,
                p.include_spam_trash,
            )
            .await
            .map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_get_message",
        description = "Fetch a single message. Default `format=full` returns parsed payload. Pass `metadata_headers` (e.g. [\"Subject\",\"From\"]) with `format=metadata` to fetch only specific headers cheaply."
    )]
    async fn gmail_get_message(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailGetMessageParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client
            .get_message(&p.id, p.format.as_deref(), &p.metadata_headers)
            .await
            .map_err(to_mcp)?;
        Ok(v.to_string())
    }

    // -----------------------------------------------------------------
    // Attachments
    // -----------------------------------------------------------------

    #[tool(
        name = "gmail_list_attachments",
        description = "Walk a message's MIME tree and return a flat list of attachment descriptors {filename, mimeType, attachmentId, size}. Inline parts (with `Content-Disposition: inline`) are NOT included unless they have a filename."
    )]
    async fn gmail_list_attachments(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailListAttachmentsParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let msg = client
            .get_message(&p.message_id, Some("full"), &[])
            .await
            .map_err(to_mcp)?;
        let mut attachments: Vec<Value> = vec![];
        if let Some(payload) = msg.get("payload") {
            walk_attachments(payload, &mut attachments);
        }
        Ok(json!({ "attachments": attachments }).to_string())
    }

    #[tool(
        name = "gmail_download_attachment",
        description = "Download an attachment by message + attachment ID. Preferred: set `dest_path` (inside FILE_ROOT) to write bytes to disk, or `to_drive_folder_id` to push straight into Drive — neither routes bytes through the model's context. Without either, returns `{ size, data }` where `data` is base64url (capped when a file-exchange dir is available)."
    )]
    async fn gmail_download_attachment(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailDownloadAttachmentParams>,
    ) -> Result<String, ErrorData> {
        validate_download_destinations(p.dest_path.as_deref(), p.to_drive_folder_id.as_deref())?;

        let session = self.resolve_session(&parts).await?;
        let client = GmailClient::new((*self.state.http).clone(), &session.access_token);
        let jail = self.state.config.file_jail.as_ref();

        // Fast path: no disk/Drive destination and no size concern — return
        // Gmail's native payload untouched (backwards compatible).
        let raw = client
            .get_attachment(&p.message_id, &p.attachment_id)
            .await
            .map_err(|e| {
                common::reclassify_not_found(e, "attachment", &p.attachment_id, "gmail")
            })?;

        if p.dest_path.is_none() && p.to_drive_folder_id.is_none() {
            let size = raw
                .get("size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as usize;
            if jail.is_some() && size > crate::files::INLINE_MAX_BYTES {
                return Err(McpError::invalid_input(format!(
                    "attachment is {size} bytes — too large to return inline as base64"
                ))
                .with_hint(
                    "Pass `dest_path` (inside FILE_ROOT) or `to_drive_folder_id` to move it without base64.",
                )
                .into());
            }
            return Ok(raw.to_string());
        }

        // Decode the bytes for a disk/Drive destination.
        let data_b64 = raw.get("data").and_then(|v| v.as_str()).ok_or_else(|| {
            ErrorData::from(McpError::internal(
                "Gmail attachment response had no `data` field",
            ))
        })?;
        let bytes = crate::mime::decode_base64(data_b64).map_err(to_mcp)?;

        // Resolve a sensible filename/mime from the message's MIME tree when
        // the caller didn't supply one.
        let (meta_name, meta_mime) =
            find_attachment_meta(&client, &p.message_id, &p.attachment_id).await;

        if let Some(dest) = &p.dest_path {
            let jail = jail.ok_or_else(file_exchange_disabled)?;
            let written = jail.write(dest, &bytes).map_err(to_mcp)?;
            // Fall back to the destination's basename for the reported name,
            // and infer the MIME from it when the message lookup came up empty.
            let filename = p.filename.clone().or(meta_name).or_else(|| {
                written
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(str::to_string)
            });
            let mime_type = meta_mime.or_else(|| {
                filename
                    .as_deref()
                    .map(|f| crate::files::guess_mime(f).to_string())
            });
            return Ok(json!({
                "path": written.display().to_string(),
                "sizeBytes": bytes.len(),
                "filename": filename,
                "mimeType": mime_type,
            })
            .to_string());
        }

        // to_drive_folder_id path.
        let folder = p.to_drive_folder_id.as_deref().unwrap_or("root");
        let name = p
            .filename
            .clone()
            .or(meta_name)
            .unwrap_or_else(|| format!("attachment-{}", p.attachment_id));
        let mime = meta_mime.unwrap_or_else(|| crate::files::guess_mime(&name).to_string());
        let drive = DriveClient::new((*self.state.http).clone(), session.access_token.clone());
        let mut metadata = json!({ "name": name, "mimeType": mime });
        if folder != "root" {
            metadata["parents"] = json!([folder]);
        } else {
            metadata["parents"] = json!(["root"]);
        }
        let created = drive
            .create_with_content(&metadata, &bytes, &mime)
            .await
            .map_err(to_mcp)?;
        Ok(created.to_string())
    }

    // -----------------------------------------------------------------
    // Drafts
    // -----------------------------------------------------------------

    #[tool(
        name = "gmail_list_drafts",
        description = "List drafts. Optional Gmail query (`q`) filters by content/recipient/etc."
    )]
    async fn gmail_list_drafts(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailListDraftsParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client
            .list_drafts(p.q.as_deref(), p.max_results, p.page_token.as_deref())
            .await
            .map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_get_draft",
        description = "Fetch a draft by ID, including its underlying message."
    )]
    async fn gmail_get_draft(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailGetDraftParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client
            .get_draft(&p.id, p.format.as_deref())
            .await
            .map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_create_draft",
        description = "Create a draft. Set `reply_to_message_id` to thread the draft as a reply (the tool fetches the original's Message-Id/References/Subject and threadId automatically)."
    )]
    async fn gmail_create_draft(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailCreateDraftParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = GmailClient::new((*self.state.http).clone(), &session.access_token);
        let (raw, thread_id) = build_outgoing_message(
            &client,
            (*self.state.http).clone(),
            &session.access_token,
            self.state.config.file_jail.as_ref(),
            &session.email,
            p.compose,
        )
        .await?;
        let v = client
            .create_draft(&raw, thread_id.as_deref())
            .await
            .map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_update_draft",
        description = "Replace the contents of an existing draft. Same compose surface as gmail_send."
    )]
    async fn gmail_update_draft(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailUpdateDraftParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = GmailClient::new((*self.state.http).clone(), &session.access_token);
        let (raw, thread_id) = build_outgoing_message(
            &client,
            (*self.state.http).clone(),
            &session.access_token,
            self.state.config.file_jail.as_ref(),
            &session.email,
            p.compose,
        )
        .await?;
        let v = client
            .update_draft(&p.id, &raw, thread_id.as_deref())
            .await
            .map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_delete_draft",
        description = "Delete a draft permanently."
    )]
    async fn gmail_delete_draft(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailDeleteDraftParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client.delete_draft(&p.id).await.map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_send_draft",
        description = "Send a previously created draft."
    )]
    async fn gmail_send_draft(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailSendDraftParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client.send_draft(&p.id).await.map_err(to_mcp)?;
        Ok(v.to_string())
    }

    // -----------------------------------------------------------------
    // Send
    // -----------------------------------------------------------------

    #[tool(
        name = "gmail_send",
        description = "Send an email. Set `reply_to_message_id` to send as a threaded reply (In-Reply-To/References/Subject + threadId are wired automatically). Set `attachments` to add files (base64 inline or absolute server path; 24 MB total cap). NOTE: this sends immediately — route to gmail_create_draft when you want explicit human approval first."
    )]
    async fn gmail_send(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailSendParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = GmailClient::new((*self.state.http).clone(), &session.access_token);
        let (raw, thread_id) = build_outgoing_message(
            &client,
            (*self.state.http).clone(),
            &session.access_token,
            self.state.config.file_jail.as_ref(),
            &session.email,
            p.compose,
        )
        .await?;
        let v = client
            .send_message(&raw, thread_id.as_deref())
            .await
            .map_err(to_mcp)?;
        Ok(v.to_string())
    }

    // -----------------------------------------------------------------
    // Labels
    // -----------------------------------------------------------------

    #[tool(
        name = "gmail_list_labels",
        description = "List all labels in the mailbox (system + user-created)."
    )]
    async fn gmail_list_labels(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client.list_labels().await.map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_get_label",
        description = "Fetch a label by ID, including message/thread totals and color."
    )]
    async fn gmail_get_label(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailGetLabelParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client.get_label(&p.id).await.map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_create_label",
        description = "Create a new label. Optional `color` uses Gmail's restricted palette (see https://developers.google.com/gmail/api/reference/rest/v1/users.labels#color)."
    )]
    async fn gmail_create_label(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailCreateLabelParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let body = CreateLabel {
            name: p.name,
            label_list_visibility: p.label_list_visibility,
            message_list_visibility: p.message_list_visibility,
            color: p.color.map(label_color_owned),
        };
        let v = client.create_label(&body).await.map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_update_label",
        description = "Rename a label or change its color/visibility. Pass only the fields you want to update."
    )]
    async fn gmail_update_label(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailUpdateLabelParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let body = UpdateLabel {
            name: p.name,
            label_list_visibility: p.label_list_visibility,
            message_list_visibility: p.message_list_visibility,
            color: p.color.map(label_color_owned),
        };
        let v = client.update_label(&p.id, &body).await.map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_delete_label",
        description = "Delete a label. The label is removed from any messages it was applied to."
    )]
    async fn gmail_delete_label(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailDeleteLabelParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client.delete_label(&p.id).await.map_err(to_mcp)?;
        Ok(v.to_string())
    }

    // -----------------------------------------------------------------
    // Filters
    // -----------------------------------------------------------------

    #[tool(
        name = "gmail_list_filters",
        description = "List every Gmail filter with its id, criteria and action. Needs the gmail.settings.basic scope: a connection authorized before filter support returns auth_required and must be re-authorized."
    )]
    async fn gmail_list_filters(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let mut v = client.list_filters().await.map_err(to_mcp)?;
        if v.get("filter").is_none() {
            v = json!({"filter": []});
        }
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_create_filter",
        description = "Create a Gmail filter for incoming mail (it does not touch existing messages). `criteria` needs at least one field, `action` at least one label change. Actions are label edits only: user label IDs from gmail_list_labels plus system IDs (remove INBOX = skip inbox, remove UNREAD = mark read, add STARRED, add/remove IMPORTANT, add TRASH = delete, remove SPAM = never spam). Forwarding is deliberately unsupported. Gmail has no filter update: to edit one, gmail_delete_filter it and create the replacement. Returns the created filter."
    )]
    async fn gmail_create_filter(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailCreateFilterParams>,
    ) -> Result<String, ErrorData> {
        let body = build_filter(p)?;
        let client = self.gmail_for(&parts).await?;
        let v = client.create_filter(&body).await.map_err(to_mcp)?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_delete_filter",
        description = "Delete a Gmail filter by ID (from gmail_list_filters). Messages it already labeled stay as they are."
    )]
    async fn gmail_delete_filter(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailDeleteFilterParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client
            .delete_filter(&p.id)
            .await
            .map_err(|e| common::reclassify_not_found(e, "filter", &p.id, "gmail"))?;
        Ok(v.to_string())
    }

    // -----------------------------------------------------------------
    // Organize
    // -----------------------------------------------------------------

    #[tool(
        name = "gmail_modify_labels",
        description = "Add/remove label IDs on a single message OR thread. Pass `target=\"message\"` or `target=\"thread\"` and the corresponding ID. At least one of `add_label_ids` / `remove_label_ids` must be non-empty."
    )]
    async fn gmail_modify_labels(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailModifyLabelsParams>,
    ) -> Result<String, ErrorData> {
        if p.add_label_ids.is_empty() && p.remove_label_ids.is_empty() {
            return Err(McpError::invalid_input(
                "no-op: at least one of `add_label_ids` / `remove_label_ids` must be non-empty",
            )
            .with_hint("Pass label IDs from gmail_list_labels in either array.")
            .into());
        }
        let client = self.gmail_for(&parts).await?;
        let body = ModifyLabels {
            add_label_ids: p.add_label_ids,
            remove_label_ids: p.remove_label_ids,
        };
        let v = match p.target {
            LabelTarget::Message => client.modify_message(&p.id, &body).await,
            LabelTarget::Thread => client.modify_thread(&p.id, &body).await,
        }
        .map_err(|e| common::reclassify_not_found(e, p.target.as_kind(), &p.id, "gmail"))?;
        Ok(v.to_string())
    }

    #[tool(
        name = "gmail_mark_read",
        description = "Remove the UNREAD label from one or more messages or threads."
    )]
    async fn gmail_mark_read(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailLabelChangeParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let body = ModifyLabels {
            remove_label_ids: vec!["UNREAD".to_string()],
            ..Default::default()
        };
        Ok(
            json!({ "results": apply_label_change(&client, p.target, &p.ids, &body).await })
                .to_string(),
        )
    }

    #[tool(
        name = "gmail_mark_unread",
        description = "Add the UNREAD label to one or more messages or threads."
    )]
    async fn gmail_mark_unread(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailLabelChangeParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let body = ModifyLabels {
            add_label_ids: vec!["UNREAD".to_string()],
            ..Default::default()
        };
        Ok(
            json!({ "results": apply_label_change(&client, p.target, &p.ids, &body).await })
                .to_string(),
        )
    }

    #[tool(
        name = "gmail_archive",
        description = "Remove the INBOX label from one or more messages or threads (archives them)."
    )]
    async fn gmail_archive(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailLabelChangeParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let body = ModifyLabels {
            remove_label_ids: vec!["INBOX".to_string()],
            ..Default::default()
        };
        Ok(
            json!({ "results": apply_label_change(&client, p.target, &p.ids, &body).await })
                .to_string(),
        )
    }

    #[tool(
        name = "gmail_trash",
        description = "Move one or more messages or threads to Trash. Reversible from Gmail's UI for ~30 days."
    )]
    async fn gmail_trash(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailTrashParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let mut results: Vec<Value> = vec![];
        for id in &p.ids {
            let r = match p.target {
                LabelTarget::Message => client.trash_message(id).await,
                LabelTarget::Thread => client.trash_thread(id).await,
            };
            results.push(match r {
                Ok(v) => json!({ "id": id, "ok": true, "result": v }),
                Err(e) => json!({ "id": id, "ok": false, "error": e.to_string() }),
            });
        }
        Ok(json!({ "results": results }).to_string())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn label_color_owned(c: LabelColor) -> LabelColor {
    LabelColor {
        background_color: c.background_color,
        text_color: c.text_color,
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn apply_label_change(
    client: &GmailClient,
    target: LabelTarget,
    ids: &[String],
    body: &ModifyLabels,
) -> Vec<Value> {
    let mut results = Vec::with_capacity(ids.len());
    for id in ids {
        let r = match target {
            LabelTarget::Message => client.modify_message(id, body).await,
            LabelTarget::Thread => client.modify_thread(id, body).await,
        };
        results.push(match r {
            Ok(v) => json!({ "id": id, "ok": true, "result": v }),
            Err(e) => json!({ "id": id, "ok": false, "error": e.to_string() }),
        });
    }
    results
}

/// Walk a Gmail `payload` MIME tree and append any parts with attachment IDs.
fn walk_attachments(payload: &Value, out: &mut Vec<Value>) {
    if let Some(body) = payload.get("body")
        && let Some(att_id) = body.get("attachmentId").and_then(|v| v.as_str())
    {
        let filename = payload
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mime_type = payload
            .get("mimeType")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let size = body.get("size").cloned().unwrap_or(Value::Null);
        if !filename.is_empty() {
            out.push(json!({
                "filename": filename,
                "mimeType": mime_type,
                "attachmentId": att_id,
                "size": size,
            }));
        }
    }
    if let Some(parts) = payload.get("parts").and_then(|v| v.as_array()) {
        for p in parts {
            walk_attachments(p, out);
        }
    }
}

/// Look up an attachment's filename + MIME type by walking a message's MIME
/// tree. Best-effort: returns `(None, None)` if the message can't be fetched
/// or the attachment isn't found (the caller has fallbacks).
async fn find_attachment_meta(
    client: &GmailClient,
    message_id: &str,
    attachment_id: &str,
) -> (Option<String>, Option<String>) {
    let Ok(msg) = client.get_message(message_id, Some("full"), &[]).await else {
        return (None, None);
    };
    let mut attachments: Vec<Value> = vec![];
    if let Some(payload) = msg.get("payload") {
        walk_attachments(payload, &mut attachments);
    }
    let pick = |a: &Value| {
        let name = a
            .get("filename")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let mime = a
            .get("mimeType")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        (name, mime)
    };
    // Prefer an exact attachmentId match. Gmail's attachmentId isn't
    // guaranteed stable across separate get_message calls, though, so fall
    // back to the sole attachment when the message has exactly one.
    if let Some(a) = attachments
        .iter()
        .find(|a| a.get("attachmentId").and_then(|v| v.as_str()) == Some(attachment_id))
    {
        return pick(a);
    }
    if attachments.len() == 1 {
        return pick(&attachments[0]);
    }
    (None, None)
}

/// Build the outgoing RFC 5322 message + threadId for send/draft tools.
/// When `reply_to_message_id` is set, fetches the original's headers to
/// build a properly threaded reply.
async fn build_outgoing_message(
    client: &GmailClient,
    http: reqwest::Client,
    access_token: &str,
    jail: Option<&FileJail>,
    from_email: &str,
    p: GmailComposeParams,
) -> Result<(String, Option<String>), ErrorData> {
    if p.body_text.as_deref().unwrap_or("").is_empty()
        && p.body_html.as_deref().unwrap_or("").is_empty()
    {
        return Err(McpError::invalid_input(
            "compose body is empty: pass at least one of `body_text` or `body_html`",
        )
        .with_hint("Empty messages are valid RFC 5322 but rarely useful — supply text and/or HTML.")
        .into());
    }
    let mut reply: Option<ReplyContext> = None;
    let mut thread_id = p.thread_id.clone();

    if let Some(reply_id) = &p.reply_to_message_id {
        let metadata = client
            .get_message(
                reply_id,
                Some("metadata"),
                &[
                    "Message-Id".to_string(),
                    "References".to_string(),
                    "Subject".to_string(),
                ],
            )
            .await
            .map_err(|e| common::reclassify_not_found(e, "message", reply_id, "gmail"))?;

        if thread_id.is_none()
            && let Some(tid) = metadata.get("threadId").and_then(|v| v.as_str())
        {
            thread_id = Some(tid.to_string());
        }

        let headers = metadata
            .get("payload")
            .and_then(|p| p.get("headers"))
            .and_then(|h| h.as_array())
            .cloned()
            .unwrap_or_default();
        let header_value = |name: &str| -> Option<String> {
            headers.iter().find_map(|h| {
                let n = h.get("name").and_then(|v| v.as_str())?;
                if n.eq_ignore_ascii_case(name) {
                    h.get("value").and_then(|v| v.as_str()).map(str::to_string)
                } else {
                    None
                }
            })
        };

        let original_id = header_value("Message-Id")
            .or_else(|| header_value("Message-ID"))
            .ok_or_else(|| {
                ErrorData::internal_error(
                    format!("could not find Message-Id header on original message {reply_id}"),
                    None,
                )
            })?;
        let references_chain = header_value("References")
            .map(|s| {
                s.split_whitespace()
                    .map(str::to_string)
                    .filter(|x| !x.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let subject = header_value("Subject").unwrap_or_default();

        reply = Some(ReplyContext {
            message_id: original_id,
            references: references_chain,
            subject,
        });
    }

    // Resolve attachments first (fail fast on bad inputs). Bytes come from a
    // local path (via the FILE_ROOT jail), a Drive file (fetched server-side),
    // or inline base64 — never routing a Drive/local file through the model.
    let mut attachments: Vec<ResolvedAttachment> = Vec::with_capacity(p.attachments.len());
    for a in p.attachments {
        attachments.push(resolve_attachment(a, jail, &http, access_token).await?);
    }
    attachments_total_size_check(&attachments)?;

    let compose_req = Compose {
        from: crate::mime::Recipient {
            email: from_email.to_string(),
            name: None,
        },
        to: p.to,
        cc: p.cc,
        bcc: p.bcc,
        subject: p.subject,
        body_text: p.body_text,
        body_html: p.body_html,
        attachments,
        reply,
    };
    let raw = crate::mime::compose_for_gmail(compose_req).map_err(to_mcp)?;
    Ok((raw, thread_id))
}

/// Resolve one attachment's bytes from its (single) source. Local paths go
/// through the `FILE_ROOT` jail; Drive files are fetched server-side; base64 is
/// the remote-client fallback. None of these route file bytes through the
/// model's context except the caller-supplied base64.
async fn resolve_attachment(
    att: AttachmentInput,
    jail: Option<&FileJail>,
    http: &reqwest::Client,
    access_token: &str,
) -> Result<ResolvedAttachment, ErrorData> {
    let source = att.source().map_err(to_mcp)?;
    match source {
        AttachmentSource::Base64(b64) => {
            let bytes = crate::mime::decode_base64(b64).map_err(to_mcp)?;
            ResolvedAttachment::from_bytes(att.filename.clone(), att.mime_type.clone(), bytes)
                .map_err(to_mcp)
        }
        AttachmentSource::Path(path) => {
            let jail = jail.ok_or_else(file_exchange_disabled)?;
            let bytes = jail.read(path).map_err(to_mcp)?;
            // Default the filename to the file's base name when unspecified.
            let filename = att.filename.clone().or_else(|| {
                std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(str::to_string)
            });
            ResolvedAttachment::from_bytes(filename, att.mime_type.clone(), bytes).map_err(to_mcp)
        }
        AttachmentSource::Drive(file_id) => {
            let drive = DriveClient::new(http.clone(), access_token.to_string());
            // Fetch a good filename/mime from metadata when the caller didn't
            // provide one, then pull the bytes.
            let mut filename = att.filename.clone();
            let mut mime_type = att.mime_type.clone();
            if (filename.is_none() || mime_type.is_none())
                && let Ok(meta) = drive.get_file(file_id, Some("name,mimeType"), true).await
            {
                if filename.is_none() {
                    filename = meta
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                }
                if mime_type.is_none() {
                    mime_type = meta
                        .get("mimeType")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                }
            }
            let (ct, bytes) = drive
                .download_file(file_id)
                .await
                .map_err(|e| common::reclassify_not_found(e, "file", file_id, "drive"))?;
            let mime_type = mime_type.or(Some(ct));
            ResolvedAttachment::from_bytes(filename, mime_type, bytes).map_err(to_mcp)
        }
    }
}

/// Error for when a tool needs `FILE_ROOT` but the operator hasn't enabled it.
/// `dest_path` and `to_drive_folder_id` are alternate destinations, never both.
fn validate_download_destinations(
    dest_path: Option<&str>,
    to_drive_folder_id: Option<&str>,
) -> Result<(), ErrorData> {
    if dest_path.is_some() && to_drive_folder_id.is_some() {
        return Err(McpError::invalid_input(
            "`dest_path` and `to_drive_folder_id` are mutually exclusive: pick one destination",
        )
        .into());
    }
    Ok(())
}

fn file_exchange_disabled() -> ErrorData {
    McpError::invalid_input(
        "this server has no file-exchange directory configured (FILE_ROOT unset), so `path` \
         cannot be used",
    )
    .with_hint(
        "Provide the bytes via `data_base64` instead, or ask the operator to set FILE_ROOT and \
         bind-mount it into the container.",
    )
    .into()
}

/// Reclassify a Drive error hit while pulling attachment bytes so a bad
/// `drive_file_id` reports as a not-found file, not an opaque 500.
/// Check the total attachment payload up front so we can return a clear
/// error before we waste time encoding base64 and hitting Gmail.
fn attachments_total_size_check(attachments: &[ResolvedAttachment]) -> Result<(), ErrorData> {
    let total: usize = attachments.iter().map(|a| a.bytes.len()).sum();
    if total > crate::mime::MAX_MESSAGE_BYTES {
        let mb = total as f64 / 1_048_576.0;
        return Err(McpError::invalid_input(format!(
            "attachments total {mb:.1} MB which exceeds the 24 MB cap"
        ))
        .with_hint(
            "Reduce attachment count or size. Gmail's hard limit is 25 MB; we cap at 24 MB to leave room for MIME framing.",
        )
        .into());
    }
    Ok(())
}

/// Re-classify a Gmail 404 into a typed `NotFound` with the resource kind
/// and ID set so agents know which input to fix.
impl LabelTarget {
    fn as_kind(self) -> &'static str {
        match self {
            LabelTarget::Message => "message",
            LabelTarget::Thread => "thread",
        }
    }
}

fn trimmed(s: Option<String>) -> Option<String> {
    s.and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

fn build_filter(p: GmailCreateFilterParams) -> Result<CreateFilter, ErrorData> {
    let GmailCreateFilterParams { criteria, action } = p;
    let from = trimmed(criteria.from);
    let to = trimmed(criteria.to);
    let subject = trimmed(criteria.subject);
    let query = trimmed(criteria.query);
    let negated_query = trimmed(criteria.negated_query);
    let has_attachment = criteria.has_attachment;
    let exclude_chats = criteria.exclude_chats;
    let size = criteria.size;
    let size_comparison = criteria.size_comparison;

    if let Some(cmp) = &size_comparison
        && cmp != "larger"
        && cmp != "smaller"
    {
        return Err(
            McpError::invalid_input(format!("unknown `size_comparison` value '{cmp}'"))
                .with_hint("Use `larger` or `smaller`.")
                .into(),
        );
    }
    if size.is_some() != size_comparison.is_some() {
        return Err(
            McpError::invalid_input("`size` and `size_comparison` must be set together").into(),
        );
    }

    let has_criteria = from.is_some()
        || to.is_some()
        || subject.is_some()
        || query.is_some()
        || negated_query.is_some()
        || has_attachment == Some(true)
        || exclude_chats == Some(true)
        || size.is_some();
    if !has_criteria {
        return Err(McpError::invalid_input(
            "`criteria` needs at least one of from, to, subject, query, negated_query, has_attachment, exclude_chats, size",
        )
        .into());
    }

    let add_label_ids: Vec<String> = action
        .add_label_ids
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let remove_label_ids: Vec<String> = action
        .remove_label_ids
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if add_label_ids.is_empty() && remove_label_ids.is_empty() {
        return Err(McpError::invalid_input(
            "`action` needs at least one label in add_label_ids or remove_label_ids",
        )
        .into());
    }

    Ok(CreateFilter {
        criteria: FilterCriteria {
            from,
            to,
            subject,
            query,
            negated_query,
            has_attachment,
            exclude_chats,
            size,
            size_comparison,
        },
        action: FilterAction {
            add_label_ids,
            remove_label_ids,
        },
    })
}

#[cfg(test)]
mod download_attachment_tests {
    use super::*;

    #[test]
    fn both_destinations_set_is_rejected() {
        let err = validate_download_destinations(Some("out.txt"), Some("root")).unwrap_err();
        let data = err.data.unwrap();
        assert_eq!(data.get("category").unwrap(), "invalid_input");
    }

    #[test]
    fn single_or_no_destination_is_accepted() {
        assert!(validate_download_destinations(Some("out.txt"), None).is_ok());
        assert!(validate_download_destinations(None, Some("root")).is_ok());
        assert!(validate_download_destinations(None, None).is_ok());
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;
    use serde_json::json;

    fn params(v: Value) -> Result<GmailCreateFilterParams, serde_json::Error> {
        serde_json::from_value(v)
    }

    #[test]
    fn valid_from_and_remove_inbox_builds_and_trims() {
        let p = params(json!({
            "criteria": {"from": "  boss@example.com  "},
            "action": {"remove_label_ids": ["INBOX"]}
        }))
        .unwrap();
        let filter = build_filter(p).unwrap();
        assert_eq!(filter.criteria.from.as_deref(), Some("boss@example.com"));
        assert_eq!(filter.action.remove_label_ids, vec!["INBOX".to_string()]);
    }

    #[test]
    fn forward_field_is_rejected_at_deserialize() {
        let err = params(json!({
            "criteria": {"from": "x@example.com"},
            "action": {"forward": "x@evil.com"}
        }))
        .unwrap_err();
        assert!(err.to_string().contains("forward"));
    }

    #[test]
    fn unknown_criteria_field_is_rejected_at_deserialize() {
        let err = params(json!({
            "criteria": {"sender": "x"},
            "action": {"add_label_ids": ["STARRED"]}
        }))
        .unwrap_err();
        assert!(err.to_string().contains("sender"));
    }

    #[test]
    fn empty_criteria_is_rejected() {
        let p = params(json!({"criteria": {}, "action": {"add_label_ids": ["STARRED"]}})).unwrap();
        let err: ErrorData = build_filter(p).unwrap_err();
        assert!(err.message.contains("criteria"));
    }

    #[test]
    fn has_attachment_false_alone_is_not_criteria() {
        let p = params(json!({
            "criteria": {"has_attachment": false},
            "action": {"add_label_ids": ["STARRED"]}
        }))
        .unwrap();
        let err: ErrorData = build_filter(p).unwrap_err();
        assert!(err.message.contains("criteria"));
    }

    #[test]
    fn whitespace_only_from_is_rejected() {
        let p = params(json!({
            "criteria": {"from": "   "},
            "action": {"add_label_ids": ["STARRED"]}
        }))
        .unwrap();
        let err: ErrorData = build_filter(p).unwrap_err();
        assert!(err.message.contains("criteria"));
    }

    #[test]
    fn empty_action_is_rejected() {
        let p = params(json!({"criteria": {"from": "x@example.com"}, "action": {}})).unwrap();
        let err: ErrorData = build_filter(p).unwrap_err();
        assert!(err.message.contains("action"));
    }

    #[test]
    fn action_with_only_whitespace_label_is_rejected() {
        let p = params(json!({
            "criteria": {"from": "x@example.com"},
            "action": {"add_label_ids": [" "]}
        }))
        .unwrap();
        let err: ErrorData = build_filter(p).unwrap_err();
        assert!(err.message.contains("action"));
    }

    #[test]
    fn size_without_comparison_is_rejected() {
        let p = params(json!({
            "criteria": {"size": 1000},
            "action": {"add_label_ids": ["STARRED"]}
        }))
        .unwrap();
        let err: ErrorData = build_filter(p).unwrap_err();
        assert!(err.message.contains("size"));
    }

    #[test]
    fn unknown_size_comparison_is_rejected() {
        let p = params(json!({
            "criteria": {"size": 1000, "size_comparison": "bigger"},
            "action": {"add_label_ids": ["STARRED"]}
        }))
        .unwrap();
        let err: ErrorData = build_filter(p).unwrap_err();
        assert!(err.message.contains("size_comparison"));
    }

    #[test]
    fn size_and_larger_alone_is_valid_criteria() {
        let p = params(json!({
            "criteria": {"size": 1000000, "size_comparison": "larger"},
            "action": {"add_label_ids": ["STARRED"]}
        }))
        .unwrap();
        let filter = build_filter(p).unwrap();
        assert_eq!(filter.criteria.size, Some(1_000_000));
    }
}
