//! Google Chat tools (opt-in, Workspace accounts only). Separate
//! `#[tool_router(router = chat_router)]` impl block, composed only when `chat` is enabled.

use std::path::{Path, PathBuf};

use http::StatusCode;
use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::{Value, json};

use crate::errors::{McpError, to_mcp};
use crate::files::{FileError, FileJail, guess_mime};
use crate::google::chat::{self, ChatClient, ChatError};
use crate::mcp::common;
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;

/// Google Chat accepts at most 200 MB of attachments per message.
const MAX_ATTACHMENT_BYTES: u64 = 200 * 1024 * 1024;
const MAX_PAGE_SIZE: u32 = 1000;
const SPACE_HINT: &str = "Use chat_list_spaces to discover valid space names.";
const MESSAGE_HINT: &str =
    "Use chat_list_messages or chat_search_messages to discover valid message names.";

#[tool_router(router = chat_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "chat_list_spaces",
        annotations(read_only_hint = true, open_world_hint = false),
        description = "List the Chat spaces the user belongs to (rooms, group chats and direct messages). Filter with `space_type` (SPACE, GROUP_CHAT or DIRECT_MESSAGE) or a raw `filter`, not both. Returns `{ spaces: [{name, display_name, space_type, last_active_time, single_user_bot_dm?, external_user_allowed?, membership_count?}], next_page_token }`. Pass a space `name` (`spaces/<id>`) to the other chat_* tools."
    )]
    async fn chat_list_spaces(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatListSpacesParams>,
    ) -> Result<String, ErrorData> {
        ensure_page_size(p.page_size)?;
        let filter = space_filter(p.filter.as_deref(), p.space_type)?;
        let client = self.chat_for(&parts).await?;
        client
            .list_spaces(p.page_size, p.page_token.as_deref(), filter.as_deref())
            .await
            .map(|v| page(&v, "spaces", "spaces", slim_space).to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "chat_get_space",
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Get one space by `space` (`spaces/<id>`). Returns the slim space shape from chat_list_spaces plus `space_uri`."
    )]
    async fn chat_get_space(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatSpaceParams>,
    ) -> Result<String, ErrorData> {
        let client = self.chat_for(&parts).await?;
        client
            .get_space(&p.space)
            .await
            .map(|v| {
                let mut out = slim_space(&v);
                out["space_uri"] = v["spaceUri"].clone();
                out.to_string()
            })
            .map_err(|e| chat_not_found(e, "space", &p.space, SPACE_HINT))
    }

    #[tool(
        name = "chat_find_direct_message",
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Find the direct message space with one user. `user` is an email address (`someone@example.com`) or a `users/<id>` name. Returns the space. Fails with not_found when no direct message exists with that user yet."
    )]
    async fn chat_find_direct_message(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatFindDirectMessageParams>,
    ) -> Result<String, ErrorData> {
        let client = self.chat_for(&parts).await?;
        client
            .find_direct_message(&p.user)
            .await
            .map(|v| slim_space(&v).to_string())
            .map_err(|e| chat_not_found(e, "dm", &p.user, "no DM exists with that user yet"))
    }

    #[tool(
        name = "chat_list_members",
        annotations(read_only_hint = true, open_world_hint = false),
        description = "List the members of a space. Returns `{ members: [{name, role, state, user: {name, display_name, email?, type}}], next_page_token }`. `display_name` is `unknown user` when Google omits it. `filter` is passed to Chat as-is."
    )]
    async fn chat_list_members(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatListMembersParams>,
    ) -> Result<String, ErrorData> {
        let client = self.chat_for(&parts).await?;
        client
            .list_members(
                &p.space,
                p.page_size,
                p.page_token.as_deref(),
                p.filter.as_deref(),
            )
            .await
            .map(|v| page(&v, "memberships", "members", slim_membership).to_string())
            .map_err(|e| chat_not_found(e, "space", &p.space, SPACE_HINT))
    }

    #[tool(
        name = "chat_list_messages",
        annotations(read_only_hint = true, open_world_hint = false),
        description = "List messages in a space. `after` and `before` are RFC3339 bounds on the create time, `thread` (`spaces/<id>/threads/<id>`) narrows to one thread, `order_by` takes e.g. `createTime desc`, `show_deleted` includes deleted messages. Returns `{ messages: [...], next_page_token }` with the slim message shape."
    )]
    async fn chat_list_messages(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatListMessagesParams>,
    ) -> Result<String, ErrorData> {
        ensure_page_size(p.page_size)?;
        let filter = message_filter(&p)?;
        let client = self.chat_for(&parts).await?;
        client
            .list_messages(
                &p.space,
                p.page_size,
                p.page_token.as_deref(),
                filter.as_deref(),
                p.order_by.as_deref(),
                p.show_deleted,
            )
            .await
            .map(|v| page(&v, "messages", "messages", slim_message).to_string())
            .map_err(|e| chat_not_found(e, "space", &p.space, SPACE_HINT))
    }

    #[tool(
        name = "chat_get_message",
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Get one message by `name` (`spaces/<id>/messages/<id>`). Returns sender, text, thread, attachments (each with `resource_name` for chat_download_attachment) and reaction counts. `deleted` is true for deleted messages."
    )]
    async fn chat_get_message(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatMessageNameParams>,
    ) -> Result<String, ErrorData> {
        let client = self.chat_for(&parts).await?;
        client
            .get_message(&p.name)
            .await
            .map(|v| slim_message(&v).to_string())
            .map_err(|e| chat_not_found(e, "message", &p.name, MESSAGE_HINT))
    }

    #[tool(
        name = "chat_search_messages",
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Search messages by keyword across spaces. Pass `query`, at least one filter, or `raw_filter`. `sender`, `space`, `after`, `before`, `has_attachment`, `unread`, `has_link` and `mentions_me` are ANDed onto the query. `raw_filter` is sent verbatim and replaces them; use it if Google's filter grammar needs something the helpers do not build. Returns `{ messages: [...], next_page_token }` with the slim message shape."
    )]
    async fn chat_search_messages(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatSearchMessagesParams>,
    ) -> Result<String, ErrorData> {
        let filter = search_filter(&p)?;
        let client = self.chat_for(&parts).await?;
        client
            .search_messages(
                &filter,
                p.page_size,
                p.page_token.as_deref(),
                p.order_by.as_deref(),
            )
            .await
            .map(|v| slim_search(&v).to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "chat_download_attachment",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        ),
        description = "Download a chat attachment to `dest_path` inside FILE_ROOT. `resource_name` is the `resource_name` of an attachment from chat_get_message. Returns `{ path, size_bytes }`; the bytes never enter the context. An existing file is kept unless `overwrite=true`."
    )]
    async fn chat_download_attachment(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatDownloadAttachmentParams>,
    ) -> Result<String, ErrorData> {
        let jail = self
            .state
            .config
            .file_jail
            .as_ref()
            .ok_or_else(|| no_file_root("dest_path"))?;
        let dest = jail.resolve_write(&p.dest_path).map_err(to_mcp)?;
        ensure_writable(&dest, &p.dest_path, p.overwrite)?;
        let client = self.chat_for(&parts).await?;
        let bytes = client
            .download_attachment(&p.resource_name)
            .await
            .map_err(|e| {
                chat_not_found(
                    e,
                    "attachment",
                    &p.resource_name,
                    "Use chat_get_message to read a valid attachment resource_name.",
                )
            })?;
        let written = jail.write(&p.dest_path, &bytes).map_err(to_mcp)?;
        Ok(json!({
            "path": written.display().to_string(),
            "size_bytes": bytes.len(),
        })
        .to_string())
    }

    #[tool(
        name = "chat_send_message",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = true
        ),
        description = "Send a message to a space as the signed-in user. Provide `text` (at most 32,000 bytes), `attachments` (paths inside FILE_ROOT, 200 MB total), or both. Reply in a thread with `thread` (`spaces/<id>/threads/<id>`) or `thread_key`; `reply_mode` picks `fallback_new_thread` (default, starts a new thread if the reply cannot be threaded) or `or_fail`. This sends immediately and notifies the people in the space."
    )]
    async fn chat_send_message(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatSendMessageParams>,
    ) -> Result<String, ErrorData> {
        chat::check_name(&p.space, &["spaces"]).map_err(to_mcp)?;
        if let Some(thread) = p.thread.as_deref() {
            chat::check_name(thread, &["spaces", "threads"]).map_err(to_mcp)?;
        }
        let text = match p.text.as_deref() {
            None | Some("") => None,
            Some(t) => Some(t),
        };
        if let Some(t) = text {
            ensure_text_fits(t)?;
        }
        if text.is_none() && p.attachments.is_empty() {
            return Err(invalid("provide `text`, `attachments`, or both"));
        }
        let reply = reply_option(p.thread.as_deref(), p.thread_key.as_deref(), p.reply_mode)?;
        let files = if p.attachments.is_empty() {
            Vec::new()
        } else {
            let jail = self
                .state
                .config
                .file_jail
                .as_ref()
                .ok_or_else(|| no_file_root("attachments"))?;
            resolve_attachments(jail, &p.attachments)?
        };
        let client = self.chat_for(&parts).await?;
        let mut uploaded = Vec::with_capacity(files.len());
        for file in &files {
            let name = file
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| invalid("attachment file name is not valid UTF-8"))?;
            let content = std::fs::read(file).map_err(|e| {
                to_mcp(FileError::Io {
                    path: file.display().to_string(),
                    source: e,
                })
            })?;
            let attachment = client
                .upload_attachment(&p.space, name, &content, guess_mime(name))
                .await
                .map_err(to_mcp)?;
            uploaded.push(attachment);
        }
        client
            .create_message(
                &p.space,
                text,
                p.thread.as_deref(),
                p.thread_key.as_deref(),
                reply,
                &uploaded,
            )
            .await
            .map(|v| slim_message(&v).to_string())
            .map_err(|e| chat_not_found(e, "space", &p.space, SPACE_HINT))
    }

    #[tool(
        name = "chat_update_message",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        ),
        description = "Replace the text of a message by `name` (`spaces/<id>/messages/<id>`). `text` is at most 32,000 bytes. Returns the slim message."
    )]
    async fn chat_update_message(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatUpdateMessageParams>,
    ) -> Result<String, ErrorData> {
        common::ensure_non_empty(&p.text, "text", "chat")?;
        ensure_text_fits(&p.text)?;
        let client = self.chat_for(&parts).await?;
        client
            .update_message(&p.name, &p.text)
            .await
            .map(|v| slim_message(&v).to_string())
            .map_err(|e| chat_not_found(e, "message", &p.name, MESSAGE_HINT))
    }

    #[tool(
        name = "chat_delete_message",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        ),
        description = "Delete a message by `name` (`spaces/<id>/messages/<id>`). `force=true` also deletes the replies in its thread. Returns `{ deleted: name }`."
    )]
    async fn chat_delete_message(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatDeleteMessageParams>,
    ) -> Result<String, ErrorData> {
        let client = self.chat_for(&parts).await?;
        client
            .delete_message(&p.name, p.force)
            .await
            .map(|_| json!({ "deleted": p.name }).to_string())
            .map_err(|e| chat_not_found(e, "message", &p.name, MESSAGE_HINT))
    }

    #[tool(
        name = "chat_add_reaction",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        ),
        description = "Add a unicode emoji reaction (for example `👍`) to a message. Returns `{ name, emoji, user: {name, display_name} }`."
    )]
    async fn chat_add_reaction(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatAddReactionParams>,
    ) -> Result<String, ErrorData> {
        common::ensure_non_empty(&p.emoji, "emoji", "chat")?;
        let client = self.chat_for(&parts).await?;
        client
            .add_reaction(&p.message, &p.emoji)
            .await
            .map(|v| slim_reaction(&v).to_string())
            .map_err(|e| chat_not_found(e, "message", &p.message, MESSAGE_HINT))
    }

    #[tool(
        name = "chat_list_reactions",
        annotations(read_only_hint = true, open_world_hint = false),
        description = "List the reactions on a message. Returns `{ reactions: [{name, emoji, user: {name, display_name}}], next_page_token }`. `emoji` is the unicode character, or the custom emoji name. Pass a reaction `name` to chat_remove_reaction."
    )]
    async fn chat_list_reactions(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatListReactionsParams>,
    ) -> Result<String, ErrorData> {
        let client = self.chat_for(&parts).await?;
        client
            .list_reactions(
                &p.message,
                p.page_size,
                p.page_token.as_deref(),
                p.filter.as_deref(),
            )
            .await
            .map(|v| page(&v, "reactions", "reactions", slim_reaction).to_string())
            .map_err(|e| chat_not_found(e, "message", &p.message, MESSAGE_HINT))
    }

    #[tool(
        name = "chat_remove_reaction",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        ),
        description = "Remove a reaction by its `reaction_name` (`spaces/<id>/messages/<id>/reactions/<id>`, from chat_list_reactions). Returns `{ deleted: reaction_name }`."
    )]
    async fn chat_remove_reaction(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatRemoveReactionParams>,
    ) -> Result<String, ErrorData> {
        let client = self.chat_for(&parts).await?;
        client
            .remove_reaction(&p.reaction_name)
            .await
            .map(|_| json!({ "deleted": p.reaction_name }).to_string())
            .map_err(|e| {
                chat_not_found(
                    e,
                    "reaction",
                    &p.reaction_name,
                    "Use chat_list_reactions to discover valid reaction names.",
                )
            })
    }

    #[tool(
        name = "chat_get_read_state",
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Get the user's last-read time for a space (`space`) or for a thread (`thread`). Pass exactly one. Returns `{ name, last_read_time }`."
    )]
    async fn chat_get_read_state(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<ChatGetReadStateParams>,
    ) -> Result<String, ErrorData> {
        let target = read_target(p.space.as_deref(), p.thread.as_deref())?;
        let client = self.chat_for(&parts).await?;
        let result = match target {
            ReadTarget::Space(space) => client.get_space_read_state(space).await,
            ReadTarget::Thread(thread) => client.get_thread_read_state(thread).await,
        };
        result
            .map(|v| slim_read_state(&v).to_string())
            .map_err(to_mcp)
    }
}

impl GoogleMcp {
    pub(crate) async fn chat_for(&self, parts: &Parts) -> Result<ChatClient, ErrorData> {
        let session = self.resolve_session(parts).await?;
        Ok(ChatClient::new(
            (*self.state.http).clone(),
            session.access_token,
        ))
    }
}

fn invalid(message: impl Into<String>) -> ErrorData {
    McpError::invalid_input(message).with_service("chat").into()
}

/// Error for a tool that needs `FILE_ROOT` but the operator has not enabled it.
fn no_file_root(what: &str) -> ErrorData {
    McpError::invalid_input(format!(
        "this server has no file-exchange directory configured (FILE_ROOT unset), so `{what}` cannot be used"
    ))
    .with_service("chat")
    .with_hint("Ask the operator to set FILE_ROOT and bind-mount it into the container.")
    .into()
}

/// Maps a Chat 404 to `not_found` with a hint for the tool's discovery step.
fn chat_not_found(e: ChatError, kind: &'static str, id: &str, hint: &str) -> ErrorData {
    match e {
        ChatError::Api { status, .. } if status == StatusCode::NOT_FOUND => {
            McpError::not_found(kind, id, "chat").with_hint(hint).into()
        }
        other => to_mcp(other),
    }
}

fn ensure_page_size(page_size: Option<u32>) -> Result<(), ErrorData> {
    match page_size {
        Some(n) if n > MAX_PAGE_SIZE => Err(invalid(format!(
            "`page_size` is {n}; Google Chat allows at most {MAX_PAGE_SIZE}"
        ))),
        _ => Ok(()),
    }
}

/// Builds the `spaceType` filter for `chat_list_spaces`. The two filter inputs are exclusive.
fn space_filter(
    filter: Option<&str>,
    space_type: Option<ChatSpaceType>,
) -> Result<Option<String>, ErrorData> {
    match (filter, space_type) {
        (Some(_), Some(_)) => Err(invalid("pass either `filter` or `space_type`, not both")),
        (Some(f), None) => Ok(Some(f.to_string())),
        (None, Some(t)) => Ok(Some(format!("spaceType = \"{}\"", t.api_name()))),
        (None, None) => Ok(None),
    }
}

/// Builds the `createTime`/`thread.name` filter for `chat_list_messages`, clauses joined with AND.
fn message_filter(p: &ChatListMessagesParams) -> Result<Option<String>, ErrorData> {
    let mut clauses: Vec<String> = Vec::new();
    if let Some(after) = p.after.as_deref() {
        check_timestamp("after", after)?;
        clauses.push(format!("createTime > \"{after}\""));
    }
    if let Some(before) = p.before.as_deref() {
        check_timestamp("before", before)?;
        clauses.push(format!("createTime < \"{before}\""));
    }
    if let Some(thread) = p.thread.as_deref() {
        chat::check_name(thread, &["spaces", "threads"]).map_err(to_mcp)?;
        clauses.push(format!("thread.name = \"{thread}\""));
    }
    if clauses.is_empty() {
        return Ok(None);
    }
    Ok(Some(clauses.join(" AND ")))
}

/// Builds the `chat_search_messages` filter: the quoted keywords, then each set helper, joined
/// with AND. A `raw_filter` is returned verbatim and must not be combined with the rest.
fn search_filter(p: &ChatSearchMessagesParams) -> Result<String, ErrorData> {
    let structured = p.sender.is_some()
        || p.space.is_some()
        || p.after.is_some()
        || p.before.is_some()
        || p.has_attachment
        || p.unread
        || p.has_link
        || p.mentions_me;
    if let Some(raw) = p.raw_filter.as_deref() {
        if !p.query.is_empty() || structured {
            return Err(invalid(
                "`raw_filter` replaces `query` and the structured filters; pass one or the other",
            ));
        }
        if raw.trim().is_empty() {
            return Err(invalid("`raw_filter` must not be empty"));
        }
        return Ok(raw.to_string());
    }
    let keywords = p.query.trim();
    if keywords.is_empty() && !structured {
        return Err(invalid(
            "pass `query`, at least one filter (sender, space, after, before, has_attachment, unread, has_link, mentions_me), or `raw_filter`",
        ));
    }
    if keywords.contains(['"', '\\']) || keywords.chars().any(char::is_control) {
        return Err(invalid(
            "`query` must not contain double quotes, backslashes or control characters",
        ));
    }
    let mut clauses = Vec::new();
    if !keywords.is_empty() {
        clauses.push(format!("\"{keywords}\""));
    }
    if let Some(sender) = p.sender.as_deref() {
        chat::check_name(sender, &["users"]).map_err(to_mcp)?;
        clauses.push(format!("sender.name = \"{sender}\""));
    }
    if let Some(space) = p.space.as_deref() {
        chat::check_name(space, &["spaces"]).map_err(to_mcp)?;
        clauses.push(format!("space.name = \"{space}\""));
    }
    if let Some(after) = p.after.as_deref() {
        check_timestamp("after", after)?;
        clauses.push(format!("create_time >= \"{after}\""));
    }
    if let Some(before) = p.before.as_deref() {
        check_timestamp("before", before)?;
        clauses.push(format!("create_time < \"{before}\""));
    }
    if p.has_attachment {
        clauses.push("attachment:*".to_string());
    }
    if p.unread {
        clauses.push("is_unread()".to_string());
    }
    if p.has_link {
        clauses.push("has_link()".to_string());
    }
    if p.mentions_me {
        clauses.push("annotations.user_mentions.user.name:\"users/me\"".to_string());
    }
    Ok(clauses.join(" AND "))
}

fn check_timestamp(field: &str, value: &str) -> Result<(), ErrorData> {
    if is_rfc3339(value) {
        return Ok(());
    }
    Err(invalid(format!(
        "`{field}` must be an RFC3339 timestamp such as 2026-01-31T12:00:00Z, got `{value}`"
    )))
}

/// Structural RFC 3339 check (`YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM)`). Google checks ranges.
fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    let date_time = digits(0..4)
        && b.get(4) == Some(&b'-')
        && digits(5..7)
        && b.get(7) == Some(&b'-')
        && digits(8..10)
        && matches!(b.get(10), Some(b'T' | b't'))
        && digits(11..13)
        && b.get(13) == Some(&b':')
        && digits(14..16)
        && b.get(16) == Some(&b':')
        && digits(17..19);
    if b.len() < 20 || !date_time {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z' | b'z') => i + 1 == b.len(),
        Some(b'+' | b'-') => {
            b.len() == i + 6 && digits(i + 1..i + 3) && b[i + 3] == b':' && digits(i + 4..i + 6)
        }
        _ => false,
    }
}

/// Chat counts message text in bytes, not characters.
fn ensure_text_fits(text: &str) -> Result<(), ErrorData> {
    if text.len() <= chat::MAX_TEXT_BYTES {
        return Ok(());
    }
    Err(McpError::invalid_input(format!(
        "message text is {} bytes; Google Chat allows at most {} bytes",
        text.len(),
        chat::MAX_TEXT_BYTES
    ))
    .with_service("chat")
    .with_hint("Split the message into several sends.")
    .into())
}

/// Maps `thread`, `thread_key` and `reply_mode` to Chat's `messageReplyOption`.
fn reply_option(
    thread: Option<&str>,
    thread_key: Option<&str>,
    mode: Option<ChatReplyMode>,
) -> Result<Option<&'static str>, ErrorData> {
    if thread.is_some() && thread_key.is_some() {
        return Err(invalid("pass `thread` or `thread_key`, not both"));
    }
    let threaded = thread.is_some() || thread_key.is_some();
    match (threaded, mode) {
        (false, None) => Ok(None),
        (false, Some(_)) => Err(invalid(
            "`reply_mode` only applies with `thread` or `thread_key`",
        )),
        (true, None | Some(ChatReplyMode::FallbackNewThread)) => {
            Ok(Some("REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"))
        }
        (true, Some(ChatReplyMode::OrFail)) => Ok(Some("REPLY_MESSAGE_OR_FAIL")),
    }
}

/// Resolves attachment paths inside the jail and checks their total size before any read.
fn resolve_attachments(jail: &FileJail, paths: &[String]) -> Result<Vec<PathBuf>, ErrorData> {
    let mut resolved = Vec::with_capacity(paths.len());
    let mut total: u64 = 0;
    for path in paths {
        let file = jail.resolve_read(path).map_err(to_mcp)?;
        let len = std::fs::metadata(&file)
            .map_err(|e| {
                to_mcp(FileError::Io {
                    path: path.clone(),
                    source: e,
                })
            })?
            .len();
        total = total.saturating_add(len);
        ensure_attachment_total(total)?;
        resolved.push(file);
    }
    Ok(resolved)
}

fn ensure_attachment_total(total: u64) -> Result<(), ErrorData> {
    if total <= MAX_ATTACHMENT_BYTES {
        return Ok(());
    }
    Err(McpError::invalid_input(format!(
        "attachments total {total} bytes; Google Chat allows at most {MAX_ATTACHMENT_BYTES} bytes (200 MB) per message"
    ))
    .with_service("chat")
    .with_hint("Attach fewer or smaller files, and send the rest as a separate message.")
    .into())
}

/// Refuses to replace an existing destination unless `overwrite` is set.
fn ensure_writable(dest: &Path, input: &str, overwrite: bool) -> Result<(), ErrorData> {
    if overwrite || std::fs::symlink_metadata(dest).is_err() {
        return Ok(());
    }
    Err(McpError::invalid_input(format!("`{input}` already exists"))
        .with_service("chat")
        .with_hint("Pass `overwrite=true` to replace it, or choose another `dest_path`.")
        .into())
}

/// Which read-state resource a call targets: a space or a thread.
enum ReadTarget<'a> {
    Space(&'a str),
    Thread(&'a str),
}

fn read_target<'a>(
    space: Option<&'a str>,
    thread: Option<&'a str>,
) -> Result<ReadTarget<'a>, ErrorData> {
    match (space, thread) {
        (Some(s), None) => Ok(ReadTarget::Space(s)),
        (None, Some(t)) => Ok(ReadTarget::Thread(t)),
        _ => Err(invalid("pass exactly one of `space` or `thread`")),
    }
}

// ---------------------------------------------------------------------------
// Slim response shapes
// ---------------------------------------------------------------------------

/// A list response reduced to `{<out>: [slim items], next_page_token}`.
fn page(v: &Value, source: &str, out: &str, slim: fn(&Value) -> Value) -> Value {
    let items: Vec<Value> = v
        .get(source)
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |list| list.iter().map(slim).collect());
    let mut out_value = json!({ "next_page_token": v["nextPageToken"] });
    out_value[out] = Value::Array(items);
    out_value
}

/// `messages` (the documented shape) or `results[].message`, whichever the response carries.
fn slim_search(v: &Value) -> Value {
    let messages: Vec<Value> = match (
        v.get("messages").and_then(Value::as_array),
        v.get("results").and_then(Value::as_array),
    ) {
        (Some(list), _) => list.iter().map(slim_message).collect(),
        (None, Some(results)) => results
            .iter()
            .filter_map(|r| r.get("message"))
            .filter(|m| m.is_object())
            .map(slim_message)
            .collect(),
        (None, None) => Vec::new(),
    };
    json!({ "messages": messages, "next_page_token": v["nextPageToken"] })
}

fn slim_space(s: &Value) -> Value {
    let mut out = json!({
        "name": s["name"],
        "display_name": s["displayName"],
        "space_type": s["spaceType"],
        "last_active_time": s["lastActiveTime"],
    });
    for (api, slim) in [
        ("singleUserBotDm", "single_user_bot_dm"),
        ("externalUserAllowed", "external_user_allowed"),
    ] {
        if let Some(flag) = s.get(api) {
            out[slim] = flag.clone();
        }
    }
    if let Some(count) = s.get("membershipCount") {
        out["membership_count"] = json!({
            "joined_direct_human_user_count": count["joinedDirectHumanUserCount"],
            "joined_group_count": count["joinedGroupCount"],
        });
    }
    out
}

fn slim_membership(m: &Value) -> Value {
    json!({
        "name": m["name"],
        "role": m["role"],
        "state": m["state"],
        "user": slim_user(&m["member"]),
    })
}

fn slim_user(u: &Value) -> Value {
    let mut out = json!({
        "name": u["name"],
        "display_name": display_name(u),
        "type": u["type"],
    });
    if let Some(email) = u.get("email") {
        out["email"] = email.clone();
    }
    out
}

/// The user's display name, or `unknown user` when Google omits it.
fn display_name(user: &Value) -> Value {
    match user.get("displayName") {
        Some(name) if name.is_string() => name.clone(),
        _ => json!("unknown user"),
    }
}

fn slim_message(m: &Value) -> Value {
    let mut out = json!({
        "name": m["name"],
        "sender": slim_user(&m["sender"]),
        "create_time": m["createTime"],
        "text": m["text"],
        "thread_name": m["thread"]["name"],
        // Proto3 JSON omits false booleans, so an absent threadReply means false.
        "thread_reply": m["threadReply"].as_bool().unwrap_or(false),
        "space": m["space"]["name"],
        "attachments": page_items(m, "attachment", slim_attachment),
        "reactions_summary": page_items(m, "emojiReactionSummaries", slim_reaction_summary),
    });
    if let Some(updated) = m.get("lastUpdateTime") {
        out["last_update_time"] = updated.clone();
    }
    if m.get("deletionMetadata").is_some() {
        out["deleted"] = json!(true);
    }
    out
}

fn page_items(v: &Value, key: &str, slim: fn(&Value) -> Value) -> Value {
    Value::Array(
        v.get(key)
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |list| list.iter().map(slim).collect()),
    )
}

fn slim_attachment(a: &Value) -> Value {
    json!({
        "name": a["name"],
        "content_name": a["contentName"],
        "content_type": a["contentType"],
        "source": a["source"],
        "resource_name": a["attachmentDataRef"]["resourceName"],
        "drive_file_id": a["driveDataRef"]["driveFileId"],
    })
}

fn slim_reaction_summary(s: &Value) -> Value {
    json!({
        "emoji": emoji_text(&s["emoji"]),
        "count": s["reactionCount"],
    })
}

fn slim_reaction(r: &Value) -> Value {
    json!({
        "name": r["name"],
        "emoji": emoji_text(&r["emoji"]),
        "user": {
            "name": r["user"]["name"],
            "display_name": display_name(&r["user"]),
        },
    })
}

/// The unicode character, or the custom emoji's name (or uid) when it is not unicode.
fn emoji_text(e: &Value) -> Value {
    e.get("unicode")
        .or_else(|| e["customEmoji"].get("name"))
        .or_else(|| e["customEmoji"].get("uid"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn slim_read_state(v: &Value) -> Value {
    json!({
        "name": v["name"],
        "last_read_time": v["lastReadTime"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn list_params(v: Value) -> ChatListMessagesParams {
        serde_json::from_value(v).unwrap()
    }

    fn search_params(v: Value) -> ChatSearchMessagesParams {
        serde_json::from_value(v).unwrap()
    }

    fn temp_jail() -> FileJail {
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("gmcp-chat-test-{}-{}", std::process::id(), id));
        FileJail::from_env(Some(dir.to_str().unwrap()))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn space_filter_builds_space_type_and_rejects_both() {
        assert_eq!(
            space_filter(None, Some(ChatSpaceType::GroupChat)).unwrap(),
            Some("spaceType = \"GROUP_CHAT\"".to_string())
        );
        assert_eq!(
            space_filter(None, Some(ChatSpaceType::DirectMessage))
                .unwrap()
                .as_deref(),
            Some("spaceType = \"DIRECT_MESSAGE\"")
        );
        assert_eq!(
            space_filter(Some("spaceType = \"SPACE\""), None).unwrap(),
            Some("spaceType = \"SPACE\"".to_string())
        );
        assert_eq!(space_filter(None, None).unwrap(), None);
        // A present-but-empty raw filter is still passed through, not dropped.
        assert_eq!(space_filter(Some(""), None).unwrap(), Some(String::new()));
        let err = space_filter(Some("x"), Some(ChatSpaceType::Space)).unwrap_err();
        assert!(err.message.contains("not both"), "{}", err.message);
    }

    #[test]
    fn list_messages_filter_combinations() {
        let none = list_params(json!({"space": "spaces/AAA"}));
        assert_eq!(message_filter(&none).unwrap(), None);

        let after = list_params(json!({"space": "spaces/AAA", "after": "2026-01-01T00:00:00Z"}));
        assert_eq!(
            message_filter(&after).unwrap(),
            Some("createTime > \"2026-01-01T00:00:00Z\"".to_string())
        );

        let before =
            list_params(json!({"space": "spaces/AAA", "before": "2026-02-01T00:00:00+01:00"}));
        assert_eq!(
            message_filter(&before).unwrap(),
            Some("createTime < \"2026-02-01T00:00:00+01:00\"".to_string())
        );

        let thread = list_params(json!({"space": "spaces/AAA", "thread": "spaces/AAA/threads/T1"}));
        assert_eq!(
            message_filter(&thread).unwrap(),
            Some("thread.name = \"spaces/AAA/threads/T1\"".to_string())
        );

        let all = list_params(json!({
            "space": "spaces/AAA",
            "after": "2026-01-01T00:00:00Z",
            "before": "2026-02-01T00:00:00Z",
            "thread": "spaces/AAA/threads/T1",
        }));
        assert_eq!(
            message_filter(&all).unwrap(),
            Some(
                "createTime > \"2026-01-01T00:00:00Z\" AND createTime < \"2026-02-01T00:00:00Z\" AND thread.name = \"spaces/AAA/threads/T1\""
                    .to_string()
            )
        );
    }

    #[test]
    fn list_messages_filter_rejects_bad_timestamp_and_thread() {
        let bad_time = list_params(json!({"space": "spaces/AAA", "after": "yesterday"}));
        let err = message_filter(&bad_time).unwrap_err();
        assert!(
            err.message.contains("`after` must be an RFC3339"),
            "{}",
            err.message
        );

        let quote =
            list_params(json!({"space": "spaces/AAA", "before": "2026-01-01T00:00:00Z\" OR x"}));
        assert!(message_filter(&quote).is_err());

        let bad_thread =
            list_params(json!({"space": "spaces/AAA", "thread": "spaces/AAA/messages/M"}));
        assert!(message_filter(&bad_thread).is_err());
    }

    #[test]
    fn rfc3339_structure() {
        for ok in [
            "2026-01-31T12:00:00Z",
            "2026-01-31t12:00:00.123456z",
            "2026-01-31T12:00:00+01:00",
            "2026-01-31T12:00:00.5-05:30",
        ] {
            assert!(is_rfc3339(ok), "{ok}");
        }
        for bad in [
            "",
            "2026-01-31",
            "2026-01-31 12:00:00Z",
            "2026-01-31T12:00:00",
            "2026-01-31T12:00:00ZZ",
            "2026-01-31T12:00:00.Z",
            "2026-01-31T12:00:00+0100",
            "2026-01-31T12:00:00Z\" OR 1=1",
            "2026-01-31T12:00:00Z ",
        ] {
            assert!(!is_rfc3339(bad), "{bad}");
        }
    }

    #[test]
    fn search_filter_allows_filters_without_keywords() {
        let p = search_params(json!({"mentions_me": true}));
        assert_eq!(
            search_filter(&p).unwrap(),
            "annotations.user_mentions.user.name:\"users/me\""
        );
        assert!(search_filter(&search_params(json!({}))).is_err());
    }

    #[test]
    fn search_filter_query_only_is_quoted() {
        let p = search_params(json!({"query": "  deploy notes  "}));
        assert_eq!(search_filter(&p).unwrap(), "\"deploy notes\"");
    }

    #[test]
    fn search_filter_combines_every_helper_in_order() {
        let p = search_params(json!({
            "query": "deploy",
            "sender": "users/123",
            "space": "spaces/AAA",
            "after": "2026-01-01T00:00:00Z",
            "before": "2026-02-01T00:00:00Z",
            "has_attachment": true,
            "unread": true,
            "has_link": true,
            "mentions_me": true,
        }));
        assert_eq!(
            search_filter(&p).unwrap(),
            "\"deploy\" AND sender.name = \"users/123\" AND space.name = \"spaces/AAA\" AND create_time >= \"2026-01-01T00:00:00Z\" AND create_time < \"2026-02-01T00:00:00Z\" AND attachment:* AND is_unread() AND has_link() AND annotations.user_mentions.user.name:\"users/me\""
        );
    }

    #[test]
    fn search_filter_false_flags_add_nothing() {
        let p = search_params(json!({
            "query": "x",
            "has_attachment": false,
            "unread": false,
            "has_link": false,
            "mentions_me": false,
        }));
        assert_eq!(search_filter(&p).unwrap(), "\"x\"");
    }

    #[test]
    fn search_filter_needs_query_or_raw_filter() {
        let blank = search_params(json!({"query": "   "}));
        assert!(
            search_filter(&blank)
                .unwrap_err()
                .message
                .contains("at least one filter")
        );
        let only_helpers = search_params(json!({"unread": true}));
        assert_eq!(search_filter(&only_helpers).unwrap(), "is_unread()");
    }

    #[test]
    fn search_filter_raw_filter_is_verbatim_and_exclusive() {
        let raw =
            search_params(json!({"raw_filter": "space.name = \"spaces/AAA\" OR is_unread()"}));
        assert_eq!(
            search_filter(&raw).unwrap(),
            "space.name = \"spaces/AAA\" OR is_unread()"
        );
        let with_query = search_params(json!({"query": "x", "raw_filter": "is_unread()"}));
        assert!(search_filter(&with_query).is_err());
        let with_helper = search_params(json!({"raw_filter": "is_unread()", "unread": true}));
        assert!(search_filter(&with_helper).is_err());
        let blank = search_params(json!({"raw_filter": "  "}));
        assert!(search_filter(&blank).is_err());
    }

    #[test]
    fn search_filter_rejects_quotes_backslashes_and_controls_in_query() {
        for bad in ["a\"b", "a\\b", "a\nb"] {
            let p = search_params(json!({ "query": bad }));
            assert!(search_filter(&p).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn search_filter_validates_sender_space_and_timestamps() {
        let bad_sender = search_params(json!({"query": "x", "sender": "someone@example.com"}));
        assert!(search_filter(&bad_sender).is_err());
        let bad_space = search_params(json!({"query": "x", "space": "people/AAA"}));
        assert!(search_filter(&bad_space).is_err());
        let bad_after = search_params(json!({"query": "x", "after": "2026-01-01"}));
        assert!(search_filter(&bad_after).is_err());
    }

    #[test]
    fn reply_option_combinations() {
        assert_eq!(reply_option(None, None, None).unwrap(), None);
        assert_eq!(
            reply_option(Some("spaces/A/threads/T"), None, None).unwrap(),
            Some("REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD")
        );
        assert_eq!(
            reply_option(None, Some("key"), None).unwrap(),
            Some("REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD")
        );
        assert_eq!(
            reply_option(
                Some("spaces/A/threads/T"),
                None,
                Some(ChatReplyMode::OrFail)
            )
            .unwrap(),
            Some("REPLY_MESSAGE_OR_FAIL")
        );
        assert_eq!(
            reply_option(None, Some("key"), Some(ChatReplyMode::FallbackNewThread)).unwrap(),
            Some("REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD")
        );
        assert!(reply_option(None, None, Some(ChatReplyMode::OrFail)).is_err());
        assert!(reply_option(Some("spaces/A/threads/T"), Some("key"), None).is_err());
    }

    #[test]
    fn text_limit_counts_bytes_not_characters() {
        assert!(ensure_text_fits(&"a".repeat(32_000)).is_ok());
        let err = ensure_text_fits(&"a".repeat(32_001)).unwrap_err();
        assert!(err.message.contains("32000"), "{}", err.message);
        // 16,000 two-byte characters are exactly 32,000 bytes.
        assert!(ensure_text_fits(&"é".repeat(16_000)).is_ok());
        assert!(ensure_text_fits(&"é".repeat(16_001)).is_err());
    }

    #[test]
    fn page_size_is_capped_at_one_thousand() {
        assert!(ensure_page_size(None).is_ok());
        assert!(ensure_page_size(Some(1000)).is_ok());
        let err = ensure_page_size(Some(1001)).unwrap_err();
        assert!(err.message.contains("at most 1000"), "{}", err.message);
    }

    #[test]
    fn read_target_needs_exactly_one_of_space_or_thread() {
        assert!(matches!(
            read_target(Some("spaces/A"), None),
            Ok(ReadTarget::Space("spaces/A"))
        ));
        assert!(matches!(
            read_target(None, Some("spaces/A/threads/T")),
            Ok(ReadTarget::Thread("spaces/A/threads/T"))
        ));
        assert!(read_target(None, None).is_err());
        assert!(read_target(Some("spaces/A"), Some("spaces/A/threads/T")).is_err());
    }

    #[test]
    fn slim_space_keeps_optional_flags_only_when_present() {
        let full = json!({
            "name": "spaces/AAA",
            "displayName": "Team",
            "spaceType": "SPACE",
            "lastActiveTime": "2026-01-31T12:00:00Z",
            "singleUserBotDm": false,
            "externalUserAllowed": true,
            "membershipCount": {"joinedDirectHumanUserCount": 4, "joinedGroupCount": 1},
            "spaceUri": "https://chat.example.com/room/AAA",
        });
        assert_eq!(
            slim_space(&full),
            json!({
                "name": "spaces/AAA",
                "display_name": "Team",
                "space_type": "SPACE",
                "last_active_time": "2026-01-31T12:00:00Z",
                "single_user_bot_dm": false,
                "external_user_allowed": true,
                "membership_count": {"joined_direct_human_user_count": 4, "joined_group_count": 1},
            })
        );
        let dm = json!({"name": "spaces/DM1", "spaceType": "DIRECT_MESSAGE"});
        let slim = slim_space(&dm);
        assert!(slim.get("single_user_bot_dm").is_none());
        assert!(slim.get("external_user_allowed").is_none());
        assert!(slim.get("membership_count").is_none());
        assert_eq!(slim["display_name"], Value::Null);
    }

    #[test]
    fn membership_falls_back_to_unknown_user_only_when_name_is_missing() {
        let missing = json!({
            "name": "spaces/AAA/members/M1",
            "role": "ROLE_MEMBER",
            "state": "JOINED",
            "member": {"name": "users/1", "type": "HUMAN"},
        });
        assert_eq!(
            slim_membership(&missing),
            json!({
                "name": "spaces/AAA/members/M1",
                "role": "ROLE_MEMBER",
                "state": "JOINED",
                "user": {"name": "users/1", "display_name": "unknown user", "type": "HUMAN"},
            })
        );
        let named = json!({
            "name": "spaces/AAA/members/M2",
            "member": {"name": "users/2", "displayName": "Example Person", "type": "HUMAN", "email": "person@example.com"},
        });
        let slim = slim_membership(&named);
        assert_eq!(slim["user"]["display_name"], "Example Person");
        assert_eq!(slim["user"]["email"], "person@example.com");
        // A present but empty display name is kept as it is; only a missing one falls back.
        let empty = json!({"member": {"name": "users/3", "displayName": ""}});
        assert_eq!(slim_membership(&empty)["user"]["display_name"], "");
    }

    #[test]
    fn slim_message_maps_thread_attachments_and_reactions() {
        let m = json!({
            "name": "spaces/AAA/messages/BBB",
            "sender": {"name": "users/1", "displayName": "Example Person", "type": "HUMAN"},
            "createTime": "2026-01-31T12:00:00Z",
            "lastUpdateTime": "2026-01-31T12:05:00Z",
            "text": "hello",
            "thread": {"name": "spaces/AAA/threads/T1"},
            "threadReply": true,
            "space": {"name": "spaces/AAA"},
            "attachment": [{
                "name": "spaces/AAA/messages/BBB/attachments/X",
                "contentName": "report.pdf",
                "contentType": "application/pdf",
                "source": "UPLOADED_CONTENT",
                "attachmentDataRef": {"resourceName": "spaces/AAA/attachments/X"},
            }, {
                "name": "spaces/AAA/messages/BBB/attachments/Y",
                "contentName": "doc.txt",
                "source": "DRIVE_FILE",
                "driveDataRef": {"driveFileId": "drive-file-1"},
            }],
            "emojiReactionSummaries": [
                {"emoji": {"unicode": "👍"}, "reactionCount": 2},
                {"emoji": {"customEmoji": {"uid": "c1", "name": "party"}}, "reactionCount": 1},
            ],
        });
        assert_eq!(
            slim_message(&m),
            json!({
                "name": "spaces/AAA/messages/BBB",
                "sender": {"name": "users/1", "display_name": "Example Person", "type": "HUMAN"},
                "create_time": "2026-01-31T12:00:00Z",
                "text": "hello",
                "thread_name": "spaces/AAA/threads/T1",
                "thread_reply": true,
                "space": "spaces/AAA",
                "attachments": [
                    {
                        "name": "spaces/AAA/messages/BBB/attachments/X",
                        "content_name": "report.pdf",
                        "content_type": "application/pdf",
                        "source": "UPLOADED_CONTENT",
                        "resource_name": "spaces/AAA/attachments/X",
                        "drive_file_id": null,
                    },
                    {
                        "name": "spaces/AAA/messages/BBB/attachments/Y",
                        "content_name": "doc.txt",
                        "content_type": null,
                        "source": "DRIVE_FILE",
                        "resource_name": null,
                        "drive_file_id": "drive-file-1",
                    },
                ],
                "reactions_summary": [
                    {"emoji": "👍", "count": 2},
                    {"emoji": "party", "count": 1},
                ],
                "last_update_time": "2026-01-31T12:05:00Z",
            })
        );
    }

    #[test]
    fn slim_message_defaults_for_absent_fields() {
        let bare = json!({
            "name": "spaces/AAA/messages/BBB",
            "sender": {"name": "users/9", "type": "BOT"},
            "createTime": "2026-01-31T12:00:00Z",
            "space": {"name": "spaces/AAA"},
        });
        let slim = slim_message(&bare);
        assert_eq!(slim["sender"]["display_name"], "unknown user");
        assert_eq!(slim["thread_reply"], false);
        assert_eq!(slim["text"], Value::Null);
        assert_eq!(slim["attachments"], json!([]));
        assert_eq!(slim["reactions_summary"], json!([]));
        assert!(slim.get("last_update_time").is_none());
        assert!(slim.get("deleted").is_none());
    }

    #[test]
    fn slim_message_marks_deleted_messages() {
        let deleted = json!({
            "name": "spaces/AAA/messages/BBB",
            "deletionMetadata": {"deletionType": "CREATOR"},
        });
        assert_eq!(slim_message(&deleted)["deleted"], true);
    }

    #[test]
    fn search_response_with_messages_key() {
        let v = json!({
            "messages": [
                {"name": "spaces/AAA/messages/1", "text": "one"},
                {"name": "spaces/AAA/messages/2", "text": "two"},
            ],
            "nextPageToken": "next",
        });
        let out = slim_search(&v);
        assert_eq!(out["messages"].as_array().unwrap().len(), 2);
        assert_eq!(out["messages"][1]["text"], "two");
        assert_eq!(out["next_page_token"], "next");
    }

    #[test]
    fn search_response_with_results_message_shape() {
        let v = json!({
            "results": [
                {"message": {"name": "spaces/AAA/messages/1", "text": "one"}},
                {"score": 0.4},
                {"message": {"name": "spaces/AAA/messages/3", "text": "three"}},
            ],
        });
        let out = slim_search(&v);
        let names: Vec<&Value> = out["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| &m["name"])
            .collect();
        assert_eq!(
            names,
            vec!["spaces/AAA/messages/1", "spaces/AAA/messages/3"]
        );
        assert_eq!(out["next_page_token"], Value::Null);
    }

    #[test]
    fn search_response_empty_or_unknown_shape_is_empty_list() {
        assert_eq!(slim_search(&json!({}))["messages"], json!([]));
        assert_eq!(slim_search(&json!({"other": 1}))["messages"], json!([]));
    }

    #[test]
    fn page_wraps_items_under_the_output_key() {
        let v = json!({
            "reactions": [{"name": "r1", "emoji": {"unicode": "👍"}, "user": {"name": "users/1", "displayName": "Example Person"}}],
            "nextPageToken": "p2",
        });
        let out = page(&v, "reactions", "reactions", slim_reaction);
        assert_eq!(
            out,
            json!({
                "reactions": [{
                    "name": "r1",
                    "emoji": "👍",
                    "user": {"name": "users/1", "display_name": "Example Person"},
                }],
                "next_page_token": "p2",
            })
        );
        let empty = page(&json!({}), "spaces", "spaces", slim_space);
        assert_eq!(empty, json!({"spaces": [], "next_page_token": null}));
    }

    #[test]
    fn reaction_user_without_display_name_is_unknown_user() {
        let r = json!({"name": "r1", "emoji": {"unicode": "🎉"}, "user": {"name": "users/7"}});
        assert_eq!(slim_reaction(&r)["user"]["display_name"], "unknown user");
    }

    #[test]
    fn read_state_output_shape() {
        let v = json!({"name": "users/me/spaces/AAA/spaceReadState", "lastReadTime": "2026-01-31T12:00:00Z"});
        assert_eq!(
            slim_read_state(&v),
            json!({
                "name": "users/me/spaces/AAA/spaceReadState",
                "last_read_time": "2026-01-31T12:00:00Z",
            })
        );
    }

    #[test]
    fn attachment_total_is_capped() {
        assert!(ensure_attachment_total(MAX_ATTACHMENT_BYTES).is_ok());
        let err = ensure_attachment_total(MAX_ATTACHMENT_BYTES + 1).unwrap_err();
        assert!(err.message.contains("200 MB"), "{}", err.message);
    }

    #[test]
    fn resolve_attachments_stays_inside_the_jail() {
        let jail = temp_jail();
        jail.write("notes.txt", b"hello").unwrap();
        let files = resolve_attachments(&jail, &["notes.txt".to_string()]).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(std::fs::read(&files[0]).unwrap(), b"hello");
        assert!(resolve_attachments(&jail, &["missing.txt".to_string()]).is_err());
    }

    #[test]
    fn existing_download_destination_needs_overwrite() {
        let jail = temp_jail();
        let dest = jail.resolve_write("out.bin").unwrap();
        assert!(ensure_writable(&dest, "out.bin", false).is_ok());
        std::fs::write(&dest, b"old").unwrap();
        let err = ensure_writable(&dest, "out.bin", false).unwrap_err();
        assert!(err.message.contains("already exists"), "{}", err.message);
        assert!(ensure_writable(&dest, "out.bin", true).is_ok());
    }

    #[test]
    fn no_file_root_names_the_field() {
        let err = no_file_root("dest_path");
        assert!(err.message.contains("FILE_ROOT unset"));
        assert!(err.message.contains("dest_path"));
    }

    #[test]
    fn chat_not_found_only_rewrites_404() {
        let missing = chat_not_found(
            ChatError::Api {
                status: StatusCode::NOT_FOUND,
                message: "x".into(),
            },
            "dm",
            "someone@example.com",
            "no DM exists with that user yet",
        );
        assert_eq!(missing.data.as_ref().unwrap()["category"], "not_found");
        assert_eq!(
            missing.data.as_ref().unwrap()["hint"],
            "no DM exists with that user yet"
        );
        let denied = chat_not_found(
            ChatError::Api {
                status: StatusCode::FORBIDDEN,
                message: "x".into(),
            },
            "dm",
            "someone@example.com",
            "hint",
        );
        assert_eq!(
            denied.data.as_ref().unwrap()["category"],
            "permission_denied"
        );
    }
}
