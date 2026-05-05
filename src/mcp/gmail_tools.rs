//! All Gmail `#[tool]` methods. The single `#[tool_router(router = gmail_router)]`
//! impl block emits a `Self::gmail_router()` constructor that the
//! `GoogleMcp::new` call wires into the struct's `tool_router` field.

use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::{Value, json};

use crate::google::gmail::{
    CreateLabel, GmailClient, GmailError, LabelColor, ModifyLabels, UpdateLabel,
};
use crate::mcp::params::*;
use crate::mcp::server::{GoogleMcp, gmail_to_error, mime_to_error};
use crate::mime::{Compose, ReplyContext, ResolvedAttachment};

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
        let profile = client.profile().await.map_err(gmail_to_error)?;
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
            .map_err(gmail_to_error)?;
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
            .map_err(gmail_to_error)?;
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
            .map_err(gmail_to_error)?;
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
            .map_err(gmail_to_error)?;
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
            .map_err(gmail_to_error)?;
        let mut attachments: Vec<Value> = vec![];
        if let Some(payload) = msg.get("payload") {
            walk_attachments(payload, &mut attachments);
        }
        Ok(json!({ "attachments": attachments }).to_string())
    }

    #[tool(
        name = "gmail_download_attachment",
        description = "Download an attachment by message + attachment ID. Returns `{ size, data }` where `data` is base64url-encoded (Gmail's native format). Decode client-side."
    )]
    async fn gmail_download_attachment(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailDownloadAttachmentParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let v = client
            .get_attachment(&p.message_id, &p.attachment_id)
            .await
            .map_err(gmail_to_error)?;
        Ok(v.to_string())
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
            .map_err(gmail_to_error)?;
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
            .map_err(gmail_to_error)?;
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
        let (raw, thread_id) = build_outgoing_message(&client, &session.email, p.compose).await?;
        let v = client
            .create_draft(&raw, thread_id.as_deref())
            .await
            .map_err(gmail_to_error)?;
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
        let (raw, thread_id) = build_outgoing_message(&client, &session.email, p.compose).await?;
        let v = client
            .update_draft(&p.id, &raw, thread_id.as_deref())
            .await
            .map_err(gmail_to_error)?;
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
        let v = client.delete_draft(&p.id).await.map_err(gmail_to_error)?;
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
        let v = client.send_draft(&p.id).await.map_err(gmail_to_error)?;
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
        let (raw, thread_id) = build_outgoing_message(&client, &session.email, p.compose).await?;
        let v = client
            .send_message(&raw, thread_id.as_deref())
            .await
            .map_err(gmail_to_error)?;
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
        let v = client.list_labels().await.map_err(gmail_to_error)?;
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
        let v = client.get_label(&p.id).await.map_err(gmail_to_error)?;
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
        let v = client.create_label(&body).await.map_err(gmail_to_error)?;
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
        let v = client
            .update_label(&p.id, &body)
            .await
            .map_err(gmail_to_error)?;
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
        let v = client.delete_label(&p.id).await.map_err(gmail_to_error)?;
        Ok(v.to_string())
    }

    // -----------------------------------------------------------------
    // Organize
    // -----------------------------------------------------------------

    #[tool(
        name = "gmail_modify_labels",
        description = "Add/remove label IDs on a single message OR thread. Pass `target=\"message\"` or `target=\"thread\"` and the corresponding ID."
    )]
    async fn gmail_modify_labels(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<GmailModifyLabelsParams>,
    ) -> Result<String, ErrorData> {
        let client = self.gmail_for(&parts).await?;
        let body = ModifyLabels {
            add_label_ids: p.add_label_ids,
            remove_label_ids: p.remove_label_ids,
        };
        let v = match p.target {
            LabelTarget::Message => client.modify_message(&p.id, &body).await,
            LabelTarget::Thread => client.modify_thread(&p.id, &body).await,
        }
        .map_err(gmail_to_error)?;
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

/// Build the outgoing RFC 5322 message + threadId for send/draft tools.
/// When `reply_to_message_id` is set, fetches the original's headers to
/// build a properly threaded reply.
async fn build_outgoing_message(
    client: &GmailClient,
    from_email: &str,
    p: GmailComposeParams,
) -> Result<(String, Option<String>), ErrorData> {
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
            .map_err(gmail_to_error)?;

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

    // Resolve attachments first (fail fast on bad inputs).
    let mut attachments: Vec<ResolvedAttachment> = Vec::with_capacity(p.attachments.len());
    for a in p.attachments {
        attachments.push(ResolvedAttachment::from_input(a).map_err(mime_to_error)?);
    }

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
    let raw = crate::mime::compose_for_gmail(compose_req).map_err(mime_to_error)?;
    Ok((raw, thread_id))
}

#[allow(dead_code)]
fn _gmail_error_marker(_: GmailError) {} // silence unused-import warning if any
