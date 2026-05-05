//! All `Params` structs for the rmcp tool surface, in one place.
//! Easier to scan and review the schema than scrolling through tool bodies.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::mime::{AttachmentInput, Recipient};

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailSearchThreadsParams {
    /// Gmail search query, e.g. `from:someone@example.com is:unread`.
    /// See https://support.google.com/mail/answer/7190.
    pub q: String,
    /// Page size (default 100, max 500).
    #[serde(default)]
    pub max_results: Option<u32>,
    /// Pagination cursor from a previous call.
    #[serde(default)]
    pub page_token: Option<String>,
    /// Restrict to threads with all of these label IDs.
    #[serde(default)]
    pub label_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailGetThreadParams {
    pub id: String,
    /// `minimal`, `metadata`, `full` (default), or `raw`.
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailGetMessageParams {
    pub id: String,
    /// `minimal`, `metadata`, `full` (default), or `raw`.
    #[serde(default)]
    pub format: Option<String>,
    /// When `format=metadata`, restricts the headers returned.
    #[serde(default)]
    pub metadata_headers: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailListMessagesParams {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub max_results: Option<u32>,
    #[serde(default)]
    pub page_token: Option<String>,
    #[serde(default)]
    pub label_ids: Vec<String>,
    #[serde(default)]
    pub include_spam_trash: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailListAttachmentsParams {
    pub message_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailDownloadAttachmentParams {
    pub message_id: String,
    pub attachment_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailGetThreadUrlParams {
    pub thread_id: String,
    /// Optional Gmail account index (the `u/{idx}` path segment). If omitted,
    /// the URL uses the connected account's email so it routes correctly when
    /// the user is signed into multiple Google accounts in the browser.
    #[serde(default)]
    pub account_index: Option<u8>,
}

// ---------------------------------------------------------------------------
// Send / Draft
// ---------------------------------------------------------------------------

/// Common payload shared between `gmail_send` and the draft tools.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailComposeParams {
    /// Recipients in the To: header. At least one of `to`, `cc`, `bcc` required.
    #[serde(default)]
    pub to: Vec<Recipient>,
    #[serde(default)]
    pub cc: Vec<Recipient>,
    #[serde(default)]
    pub bcc: Vec<Recipient>,
    /// Subject line. Ignored if `reply_to_message_id` is set and this is empty
    /// (the original subject with a single `Re: ` prefix is used instead).
    #[serde(default)]
    pub subject: String,
    /// Plain-text body. At least one of `body_text` / `body_html` required.
    #[serde(default)]
    pub body_text: Option<String>,
    /// HTML body. When both are present, a `multipart/alternative` is sent.
    #[serde(default)]
    pub body_html: Option<String>,
    /// Attachments — base64-encoded data inline OR an absolute server-side
    /// path. 24 MB cap, total.
    #[serde(default)]
    pub attachments: Vec<AttachmentInput>,
    /// Gmail message ID of the message being replied to. When set, this tool
    /// fetches that message's `Message-Id`/`References`/`Subject`/`threadId`
    /// and builds a properly-threaded reply (In-Reply-To + References headers,
    /// `Re:` subject prefix, threadId on the API request).
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
    /// Explicit Gmail thread ID. Usually inferred from `reply_to_message_id`.
    /// Only set this if you know what you're doing.
    #[serde(default)]
    pub thread_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailSendParams {
    #[serde(flatten)]
    pub compose: GmailComposeParams,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailCreateDraftParams {
    #[serde(flatten)]
    pub compose: GmailComposeParams,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailGetDraftParams {
    pub id: String,
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailListDraftsParams {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub max_results: Option<u32>,
    #[serde(default)]
    pub page_token: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailUpdateDraftParams {
    pub id: String,
    #[serde(flatten)]
    pub compose: GmailComposeParams,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailDeleteDraftParams {
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailSendDraftParams {
    pub id: String,
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailGetLabelParams {
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailCreateLabelParams {
    pub name: String,
    /// `labelShow` (default), `labelHide`, or `labelShowIfUnread`.
    #[serde(default)]
    pub label_list_visibility: Option<String>,
    /// `show` (default) or `hide`.
    #[serde(default)]
    pub message_list_visibility: Option<String>,
    #[serde(default)]
    pub color: Option<crate::google::gmail::LabelColor>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailUpdateLabelParams {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub label_list_visibility: Option<String>,
    #[serde(default)]
    pub message_list_visibility: Option<String>,
    #[serde(default)]
    pub color: Option<crate::google::gmail::LabelColor>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailDeleteLabelParams {
    pub id: String,
}

// ---------------------------------------------------------------------------
// Organize
// ---------------------------------------------------------------------------

/// What kind of object a label-modifying tool should target.
#[derive(Debug, Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum LabelTarget {
    Message,
    Thread,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailModifyLabelsParams {
    pub target: LabelTarget,
    /// ID of the message OR thread to modify (matches `target`).
    pub id: String,
    #[serde(default)]
    pub add_label_ids: Vec<String>,
    #[serde(default)]
    pub remove_label_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailLabelChangeParams {
    pub target: LabelTarget,
    /// IDs to apply the change to. Each ID is mutated independently;
    /// the tool returns an array of results.
    pub ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailTrashParams {
    pub target: LabelTarget,
    pub ids: Vec<String>,
}
