//! Google Chat v1 client: a thin reqwest wrapper using the user's access token.
//! Each endpoint's URL, query and body come from a pure builder, tested offline.

use http::StatusCode;
use reqwest::Method;
use serde_json::{Value, json};

use super::http::{MAX_API_RESPONSE_BYTES, MAX_DOWNLOAD_BYTES, ReadBodyError, read_body_capped};

const BASE: &str = "https://chat.googleapis.com/v1";
const UPLOAD_BASE: &str = "https://chat.googleapis.com/upload/v1";

/// Google Chat rejects message text longer than this many bytes.
pub const MAX_TEXT_BYTES: usize = 32_000;

#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Chat returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("Chat rejected the access token: an OAuth scope this tool needs was not granted")]
    InsufficientScope,
    #[error("could not parse Chat response: {0}")]
    Parse(serde_json::Error),
    #[error("invalid name: {0}")]
    InvalidId(String),
    #[error("response body exceeds the {cap}-byte cap (at least {actual} bytes)")]
    TooLarge { cap: usize, actual: usize },
}

impl From<ReadBodyError> for ChatError {
    fn from(e: ReadBodyError) -> Self {
        match e {
            ReadBodyError::Http(e) => ChatError::Http(e),
            ReadBodyError::TooLarge { cap, actual } => ChatError::TooLarge { cap, actual },
        }
    }
}

/// Chat ids are ASCII letters, digits, `-`, `_` and `.` (message ids look like `A.B`); `.` and `..` alone are refused.
fn is_id(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Base64 token as Chat returns in `attachmentDataRef.resourceName`; no `.`, `?`, `#` or `%` can appear.
fn is_media_token(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('/')
        && !s.contains("//")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}

/// Checks `kinds[0]/<id>/kinds[1]/<id>/...`, e.g. `["spaces", "messages"]` for `spaces/<id>/messages/<id>`.
pub fn check_name(name: &str, kinds: &[&str]) -> Result<(), ChatError> {
    let parts: Vec<&str> = name.split('/').collect();
    let well_formed = parts.len() == 2 * kinds.len()
        && kinds
            .iter()
            .enumerate()
            .all(|(i, kind)| parts[2 * i] == *kind && is_id(parts[2 * i + 1]));
    if well_formed {
        return Ok(());
    }
    let shape: Vec<String> = kinds.iter().map(|k| format!("{k}/{{id}}")).collect();
    Err(ChatError::InvalidId(format!(
        "`{name}` is not a valid name, expected `{}`",
        shape.join("/")
    )))
}

/// Checks an attachment media name: an opaque base64 token, or `spaces/` then id segments.
pub fn check_media_name(name: &str) -> Result<(), ChatError> {
    let parts: Vec<&str> = name.split('/').collect();
    let path_ok = parts.len() >= 2 && parts[0] == "spaces" && parts.iter().copied().all(is_id);
    if path_ok || is_media_token(name) {
        return Ok(());
    }
    Err(ChatError::InvalidId(format!(
        "`{name}` is not a valid attachment resource name, expected the `resource_name` from an attachment"
    )))
}

fn is_email(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    let chars_ok = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-' | b'@'));
    chars_ok
        && !local.is_empty()
        && domain.contains('.')
        && !domain.contains('@')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !s.contains("..")
}

/// Normalizes an email address or a user id to the `users/<id>` resource name.
pub fn user_resource(user: &str) -> Result<String, ChatError> {
    let rest = user.strip_prefix("users/").unwrap_or(user);
    if is_id(rest) || is_email(rest) {
        return Ok(format!("users/{rest}"));
    }
    Err(ChatError::InvalidId(format!(
        "`{user}` is neither an email address nor a `users/<id>` name"
    )))
}

/// `users/me/spaces/<id>/spaceReadState` for a space name.
pub fn space_read_state_path(space: &str) -> Result<String, ChatError> {
    check_name(space, &["spaces"])?;
    Ok(format!("users/me/{space}/spaceReadState"))
}

/// `users/me/spaces/<id>/threads/<id>/threadReadState` for a thread name.
pub fn thread_read_state_path(thread: &str) -> Result<String, ChatError> {
    check_name(thread, &["spaces", "threads"])?;
    Ok(format!("users/me/{thread}/threadReadState"))
}

/// One HTTP request, built without any I/O.
#[derive(Debug, PartialEq)]
struct Call {
    method: Method,
    url: String,
    query: Vec<(String, String)>,
    body: Body,
}

#[derive(Debug, PartialEq)]
enum Body {
    Empty,
    Json(Value),
    Multipart {
        content_type: String,
        bytes: Vec<u8>,
    },
}

fn request(method: Method, url: String, query: Vec<(String, String)>, body: Body) -> Call {
    Call {
        method,
        url,
        query,
        body,
    }
}

fn get(url: String, query: Vec<(String, String)>) -> Call {
    request(Method::GET, url, query, Body::Empty)
}

fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_string(), value.to_string())
}

fn list_query(
    page_size: Option<u32>,
    page_token: Option<&str>,
    filter: Option<&str>,
) -> Vec<(String, String)> {
    let mut query = Vec::new();
    if let Some(n) = page_size {
        query.push(pair("pageSize", &n.to_string()));
    }
    if let Some(t) = page_token {
        query.push(pair("pageToken", t));
    }
    if let Some(f) = filter {
        query.push(pair("filter", f));
    }
    query
}

fn list_spaces_call(
    page_size: Option<u32>,
    page_token: Option<&str>,
    filter: Option<&str>,
) -> Call {
    get(
        format!("{BASE}/spaces"),
        list_query(page_size, page_token, filter),
    )
}

fn get_space_call(space: &str) -> Result<Call, ChatError> {
    check_name(space, &["spaces"])?;
    Ok(get(format!("{BASE}/{space}"), Vec::new()))
}

fn find_direct_message_call(user: &str) -> Result<Call, ChatError> {
    let name = user_resource(user)?;
    Ok(get(
        format!("{BASE}/spaces:findDirectMessage"),
        vec![pair("name", &name)],
    ))
}

fn list_members_call(
    space: &str,
    page_size: Option<u32>,
    page_token: Option<&str>,
    filter: Option<&str>,
) -> Result<Call, ChatError> {
    check_name(space, &["spaces"])?;
    Ok(get(
        format!("{BASE}/{space}/members"),
        list_query(page_size, page_token, filter),
    ))
}

fn list_messages_call(
    space: &str,
    page_size: Option<u32>,
    page_token: Option<&str>,
    filter: Option<&str>,
    order_by: Option<&str>,
    show_deleted: bool,
) -> Result<Call, ChatError> {
    check_name(space, &["spaces"])?;
    let mut query = list_query(page_size, page_token, filter);
    if let Some(o) = order_by {
        query.push(pair("orderBy", o));
    }
    if show_deleted {
        query.push(pair("showDeleted", "true"));
    }
    Ok(get(format!("{BASE}/{space}/messages"), query))
}

fn get_message_call(name: &str) -> Result<Call, ChatError> {
    check_name(name, &["spaces", "messages"])?;
    Ok(get(format!("{BASE}/{name}"), Vec::new()))
}

fn search_messages_call(
    filter: &str,
    page_size: Option<u32>,
    page_token: Option<&str>,
    order_by: Option<&str>,
) -> Call {
    let mut body = json!({ "filter": filter });
    if let Some(n) = page_size {
        body["pageSize"] = json!(n);
    }
    if let Some(t) = page_token {
        body["pageToken"] = json!(t);
    }
    if let Some(o) = order_by {
        body["orderBy"] = json!(o);
    }
    request(
        Method::POST,
        format!("{BASE}/spaces/-/messages:search"),
        Vec::new(),
        Body::Json(body),
    )
}

fn download_attachment_call(resource_name: &str) -> Result<Call, ChatError> {
    check_media_name(resource_name)?;
    Ok(get(
        format!("{BASE}/media/{resource_name}"),
        vec![pair("alt", "media")],
    ))
}

fn create_message_call(
    space: &str,
    text: Option<&str>,
    thread: Option<&str>,
    thread_key: Option<&str>,
    reply_option: Option<&str>,
    attachments: &[Value],
) -> Result<Call, ChatError> {
    check_name(space, &["spaces"])?;
    let mut body = json!({});
    if let Some(t) = text {
        body["text"] = json!(t);
    }
    if let Some(name) = thread {
        check_name(name, &["spaces", "threads"])?;
        body["thread"] = json!({ "name": name });
    }
    if !attachments.is_empty() {
        body["attachment"] = json!(attachments);
    }
    let mut query = Vec::new();
    if let Some(key) = thread_key {
        query.push(pair("threadKey", key));
    }
    if let Some(option) = reply_option {
        query.push(pair("messageReplyOption", option));
    }
    Ok(request(
        Method::POST,
        format!("{BASE}/{space}/messages"),
        query,
        Body::Json(body),
    ))
}

/// Multipart/related body: the JSON metadata part, then the raw content part.
fn multipart_body(boundary: &str, metadata: &Value, content: &[u8], content_mime: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(content.len() + 256);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
    body.extend_from_slice(metadata.to_string().as_bytes());
    body.extend_from_slice(
        format!("\r\n--{boundary}\r\nContent-Type: {content_mime}\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

fn upload_attachment_call(
    space: &str,
    filename: &str,
    content: &[u8],
    content_mime: &str,
    boundary: &str,
) -> Result<Call, ChatError> {
    check_name(space, &["spaces"])?;
    let metadata = json!({ "filename": filename });
    let bytes = multipart_body(boundary, &metadata, content, content_mime);
    Ok(request(
        Method::POST,
        format!("{UPLOAD_BASE}/{space}/attachments:upload"),
        vec![pair("uploadType", "multipart")],
        Body::Multipart {
            content_type: format!("multipart/related; boundary={boundary}"),
            bytes,
        },
    ))
}

fn update_message_call(name: &str, text: &str) -> Result<Call, ChatError> {
    check_name(name, &["spaces", "messages"])?;
    Ok(request(
        Method::PATCH,
        format!("{BASE}/{name}"),
        vec![pair("updateMask", "text")],
        Body::Json(json!({ "text": text })),
    ))
}

fn delete_message_call(name: &str, force: bool) -> Result<Call, ChatError> {
    check_name(name, &["spaces", "messages"])?;
    Ok(request(
        Method::DELETE,
        format!("{BASE}/{name}"),
        vec![pair("force", if force { "true" } else { "false" })],
        Body::Empty,
    ))
}

fn add_reaction_call(message: &str, emoji: &str) -> Result<Call, ChatError> {
    check_name(message, &["spaces", "messages"])?;
    Ok(request(
        Method::POST,
        format!("{BASE}/{message}/reactions"),
        Vec::new(),
        Body::Json(json!({ "emoji": { "unicode": emoji } })),
    ))
}

fn list_reactions_call(
    message: &str,
    page_size: Option<u32>,
    page_token: Option<&str>,
    filter: Option<&str>,
) -> Result<Call, ChatError> {
    check_name(message, &["spaces", "messages"])?;
    Ok(get(
        format!("{BASE}/{message}/reactions"),
        list_query(page_size, page_token, filter),
    ))
}

fn remove_reaction_call(name: &str) -> Result<Call, ChatError> {
    check_name(name, &["spaces", "messages", "reactions"])?;
    Ok(request(
        Method::DELETE,
        format!("{BASE}/{name}"),
        Vec::new(),
        Body::Empty,
    ))
}

fn space_read_state_call(space: &str) -> Result<Call, ChatError> {
    let path = space_read_state_path(space)?;
    Ok(get(format!("{BASE}/{path}"), Vec::new()))
}

fn thread_read_state_call(thread: &str) -> Result<Call, ChatError> {
    let path = thread_read_state_path(thread)?;
    Ok(get(format!("{BASE}/{path}"), Vec::new()))
}

/// Body-less POSTs must send `Content-Length: 0` or Google answers HTTP 411.
fn needs_zero_length(call: &Call) -> bool {
    call.method == Method::POST && call.body == Body::Empty
}

fn api_error(status: StatusCode, bytes: &[u8]) -> ChatError {
    let text = String::from_utf8_lossy(bytes);
    if status == StatusCode::FORBIDDEN
        && (text.contains("ACCESS_TOKEN_SCOPE_INSUFFICIENT")
            || text.contains("insufficient authentication scopes"))
    {
        return ChatError::InsufficientScope;
    }
    ChatError::Api {
        status,
        message: text.chars().take(800).collect(),
    }
}

#[derive(Clone)]
pub struct ChatClient {
    http: reqwest::Client,
    access_token: String,
}

impl ChatClient {
    pub fn new(http: reqwest::Client, access_token: impl Into<String>) -> Self {
        Self {
            http,
            access_token: access_token.into(),
        }
    }

    pub async fn list_spaces(
        &self,
        page_size: Option<u32>,
        page_token: Option<&str>,
        filter: Option<&str>,
    ) -> Result<Value, ChatError> {
        self.json(list_spaces_call(page_size, page_token, filter))
            .await
    }

    pub async fn get_space(&self, space: &str) -> Result<Value, ChatError> {
        self.json(get_space_call(space)?).await
    }

    pub async fn find_direct_message(&self, user: &str) -> Result<Value, ChatError> {
        self.json(find_direct_message_call(user)?).await
    }

    pub async fn list_members(
        &self,
        space: &str,
        page_size: Option<u32>,
        page_token: Option<&str>,
        filter: Option<&str>,
    ) -> Result<Value, ChatError> {
        self.json(list_members_call(space, page_size, page_token, filter)?)
            .await
    }

    pub async fn list_messages(
        &self,
        space: &str,
        page_size: Option<u32>,
        page_token: Option<&str>,
        filter: Option<&str>,
        order_by: Option<&str>,
        show_deleted: bool,
    ) -> Result<Value, ChatError> {
        self.json(list_messages_call(
            space,
            page_size,
            page_token,
            filter,
            order_by,
            show_deleted,
        )?)
        .await
    }

    pub async fn get_message(&self, name: &str) -> Result<Value, ChatError> {
        self.json(get_message_call(name)?).await
    }

    pub async fn search_messages(
        &self,
        filter: &str,
        page_size: Option<u32>,
        page_token: Option<&str>,
        order_by: Option<&str>,
    ) -> Result<Value, ChatError> {
        self.json(search_messages_call(
            filter, page_size, page_token, order_by,
        ))
        .await
    }

    /// Raw attachment bytes for a `resource_name` from an attachment's `attachmentDataRef`.
    pub async fn download_attachment(&self, resource_name: &str) -> Result<Vec<u8>, ChatError> {
        self.execute(download_attachment_call(resource_name)?, MAX_DOWNLOAD_BYTES)
            .await
    }

    /// Uploads bytes to a space and returns the attachment object to send in a message.
    pub async fn upload_attachment(
        &self,
        space: &str,
        filename: &str,
        content: &[u8],
        content_mime: &str,
    ) -> Result<Value, ChatError> {
        let boundary = format!("googlemcp_{}", uuid::Uuid::new_v4().simple());
        self.json(upload_attachment_call(
            space,
            filename,
            content,
            content_mime,
            &boundary,
        )?)
        .await
    }

    pub async fn create_message(
        &self,
        space: &str,
        text: Option<&str>,
        thread: Option<&str>,
        thread_key: Option<&str>,
        reply_option: Option<&str>,
        attachments: &[Value],
    ) -> Result<Value, ChatError> {
        self.json(create_message_call(
            space,
            text,
            thread,
            thread_key,
            reply_option,
            attachments,
        )?)
        .await
    }

    pub async fn update_message(&self, name: &str, text: &str) -> Result<Value, ChatError> {
        self.json(update_message_call(name, text)?).await
    }

    pub async fn delete_message(&self, name: &str, force: bool) -> Result<Value, ChatError> {
        self.json(delete_message_call(name, force)?).await
    }

    pub async fn add_reaction(&self, message: &str, emoji: &str) -> Result<Value, ChatError> {
        self.json(add_reaction_call(message, emoji)?).await
    }

    pub async fn list_reactions(
        &self,
        message: &str,
        page_size: Option<u32>,
        page_token: Option<&str>,
        filter: Option<&str>,
    ) -> Result<Value, ChatError> {
        self.json(list_reactions_call(message, page_size, page_token, filter)?)
            .await
    }

    pub async fn remove_reaction(&self, name: &str) -> Result<Value, ChatError> {
        self.json(remove_reaction_call(name)?).await
    }

    pub async fn get_space_read_state(&self, space: &str) -> Result<Value, ChatError> {
        self.json(space_read_state_call(space)?).await
    }

    pub async fn get_thread_read_state(&self, thread: &str) -> Result<Value, ChatError> {
        self.json(thread_read_state_call(thread)?).await
    }

    async fn json(&self, call: Call) -> Result<Value, ChatError> {
        let bytes = self.execute(call, MAX_API_RESPONSE_BYTES).await?;
        if bytes.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_slice(&bytes).map_err(ChatError::Parse)
    }

    /// Sends one request and returns the raw success body, capped at `success_cap`.
    async fn execute(&self, call: Call, success_cap: usize) -> Result<Vec<u8>, ChatError> {
        let zero_length = needs_zero_length(&call);
        let mut req = self
            .http
            .request(call.method, &call.url)
            .bearer_auth(&self.access_token);
        if !call.query.is_empty() {
            req = req.query(&call.query);
        }
        req = match call.body {
            Body::Empty if zero_length => req.header(reqwest::header::CONTENT_LENGTH, "0"),
            Body::Empty => req,
            Body::Json(v) => req.json(&v),
            Body::Multipart {
                content_type,
                bytes,
            } => req
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(bytes),
        };
        let resp = req.send().await?;
        let status = resp.status();
        let cap = if status.is_success() {
            success_cap
        } else {
            MAX_API_RESPONSE_BYTES
        };
        let bytes = read_body_capped(resp, cap).await?;
        if status.is_success() {
            return Ok(bytes);
        }
        Err(api_error(status, &bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect(method: Method, url: &str, query: &[(&str, &str)], body: Body) -> Call {
        Call {
            method,
            url: url.to_string(),
            query: query.iter().map(|(k, v)| pair(k, v)).collect(),
            body,
        }
    }

    fn get_expect(url: &str, query: &[(&str, &str)]) -> Call {
        expect(Method::GET, url, query, Body::Empty)
    }

    #[test]
    fn check_name_accepts_well_formed_names() {
        assert!(check_name("spaces/AAA-1_b", &["spaces"]).is_ok());
        assert!(check_name("spaces/AAA/messages/BBB", &["spaces", "messages"]).is_ok());
        assert!(
            check_name(
                "spaces/AAA/messages/BBB/reactions/CCC",
                &["spaces", "messages", "reactions"]
            )
            .is_ok()
        );
        assert!(check_name("spaces/AAA/threads/BBB", &["spaces", "threads"]).is_ok());
        assert!(check_name("users/me", &["users"]).is_ok());
    }

    #[test]
    fn check_name_rejects_wrong_shape_and_unsafe_characters() {
        let bad = [
            "",
            "spaces",
            "spaces/",
            "spaces//AAA",
            "spaces/AAA/",
            "people/AAA",
            "spaces/AAA/threads/BBB",
            "spaces/../x",
            "spaces/AAA/..",
            "spaces/AAA?alt=media",
            "spaces/AAA#frag",
            "spaces/a b",
            "spaces/A%2F..",
            "spaces/AAA/messages/BBB/extra",
            "spaces/AAA\n",
        ];
        for name in bad {
            let err = check_name(name, &["spaces"]).unwrap_err();
            assert!(
                matches!(&err, ChatError::InvalidId(m) if m.contains("expected `spaces/{id}`")),
                "{name}: {err}"
            );
        }
        assert!(check_name("spaces/AAA/threads/BBB", &["spaces", "messages"]).is_err());
        assert!(check_name("spaces/../messages/x", &["spaces", "messages"]).is_err());
        assert!(check_name("spaces/AAA/messages/.", &["spaces", "messages"]).is_err());
        assert!(check_name("spaces/AAA/messages/B1.B1", &["spaces", "messages"]).is_ok());
    }

    #[test]
    fn media_name_is_opaque_but_bounded() {
        assert!(check_media_name("spaces/AAA/attachments/BBB").is_ok());
        assert!(check_media_name("spaces/AAA").is_ok());
        assert!(check_media_name("Clxz+cGFj/ZXMvQUFB_LWJ-aW4=").is_ok());
        for bad in [
            "",
            "spaces/../x",
            "spaces/AAA/attachments/BBB?alt=media",
            "spaces//x",
            "/abs",
            "a%2F..",
            "tok#frag",
            "a b",
        ] {
            assert!(check_media_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn user_resource_accepts_email_and_ids() {
        assert_eq!(
            user_resource("someone@example.com").unwrap(),
            "users/someone@example.com"
        );
        assert_eq!(user_resource("users/123").unwrap(), "users/123");
        assert_eq!(user_resource("123").unwrap(), "users/123");
        assert_eq!(user_resource("users/me").unwrap(), "users/me");
    }

    #[test]
    fn user_resource_rejects_paths_and_malformed_emails() {
        for bad in [
            "",
            "users/",
            "a..b@example.com",
            "someone@example",
            "x@y@example.com",
            "someone@example.com/../x",
            "someone@example.com?x=1",
            "@example.com",
            "spaces/AAA",
        ] {
            assert!(user_resource(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn read_state_paths_are_derived_from_space_and_thread_names() {
        assert_eq!(
            space_read_state_path("spaces/AAA").unwrap(),
            "users/me/spaces/AAA/spaceReadState"
        );
        assert_eq!(
            thread_read_state_path("spaces/S1/threads/T2").unwrap(),
            "users/me/spaces/S1/threads/T2/threadReadState"
        );
        assert!(thread_read_state_path("spaces/S1").is_err());
        assert!(space_read_state_path("spaces/S1/threads/T2").is_err());
    }

    #[test]
    fn list_spaces_builds_query_and_omits_absent_params() {
        assert_eq!(
            list_spaces_call(Some(10), Some("tok"), Some("spaceType = \"SPACE\"")),
            get_expect(
                "https://chat.googleapis.com/v1/spaces",
                &[
                    ("pageSize", "10"),
                    ("pageToken", "tok"),
                    ("filter", "spaceType = \"SPACE\""),
                ],
            )
        );
        assert_eq!(
            list_spaces_call(None, None, None),
            get_expect("https://chat.googleapis.com/v1/spaces", &[])
        );
    }

    #[test]
    fn get_space_and_read_state_urls() {
        assert_eq!(
            get_space_call("spaces/AAA").unwrap(),
            get_expect("https://chat.googleapis.com/v1/spaces/AAA", &[])
        );
        assert_eq!(
            space_read_state_call("spaces/AAA").unwrap(),
            get_expect(
                "https://chat.googleapis.com/v1/users/me/spaces/AAA/spaceReadState",
                &[]
            )
        );
        assert_eq!(
            thread_read_state_call("spaces/S1/threads/T2").unwrap(),
            get_expect(
                "https://chat.googleapis.com/v1/users/me/spaces/S1/threads/T2/threadReadState",
                &[]
            )
        );
        assert!(get_space_call("people/AAA").is_err());
    }

    #[test]
    fn find_direct_message_normalizes_the_user_query() {
        assert_eq!(
            find_direct_message_call("someone@example.com").unwrap(),
            get_expect(
                "https://chat.googleapis.com/v1/spaces:findDirectMessage",
                &[("name", "users/someone@example.com")],
            )
        );
        assert_eq!(
            find_direct_message_call("users/123").unwrap(),
            get_expect(
                "https://chat.googleapis.com/v1/spaces:findDirectMessage",
                &[("name", "users/123")],
            )
        );
        assert!(find_direct_message_call("not an email").is_err());
    }

    #[test]
    fn list_members_builds_url_and_query() {
        assert_eq!(
            list_members_call(
                "spaces/AAA",
                Some(5),
                Some("p2"),
                Some("role = \"ROLE_MANAGER\"")
            )
            .unwrap(),
            get_expect(
                "https://chat.googleapis.com/v1/spaces/AAA/members",
                &[
                    ("pageSize", "5"),
                    ("pageToken", "p2"),
                    ("filter", "role = \"ROLE_MANAGER\""),
                ],
            )
        );
    }

    #[test]
    fn list_messages_builds_order_show_deleted_and_filter() {
        assert_eq!(
            list_messages_call(
                "spaces/AAA",
                Some(50),
                None,
                Some("createTime > \"2026-01-01T00:00:00Z\""),
                Some("createTime desc"),
                true,
            )
            .unwrap(),
            get_expect(
                "https://chat.googleapis.com/v1/spaces/AAA/messages",
                &[
                    ("pageSize", "50"),
                    ("filter", "createTime > \"2026-01-01T00:00:00Z\""),
                    ("orderBy", "createTime desc"),
                    ("showDeleted", "true"),
                ],
            )
        );
        // showDeleted=false is the API default, so it is not sent.
        assert_eq!(
            list_messages_call("spaces/AAA", None, None, None, None, false).unwrap(),
            get_expect("https://chat.googleapis.com/v1/spaces/AAA/messages", &[])
        );
    }

    #[test]
    fn get_message_url_uses_full_name() {
        assert_eq!(
            get_message_call("spaces/AAA/messages/BBB").unwrap(),
            get_expect(
                "https://chat.googleapis.com/v1/spaces/AAA/messages/BBB",
                &[]
            )
        );
        assert!(get_message_call("spaces/AAA/messages").is_err());
    }

    #[test]
    fn search_posts_filter_and_optional_body_fields() {
        assert_eq!(
            search_messages_call(
                "\"deploy\" AND is_unread()",
                Some(20),
                Some("pt"),
                Some("create_time desc"),
            ),
            expect(
                Method::POST,
                "https://chat.googleapis.com/v1/spaces/-/messages:search",
                &[],
                Body::Json(json!({
                    "filter": "\"deploy\" AND is_unread()",
                    "pageSize": 20,
                    "pageToken": "pt",
                    "orderBy": "create_time desc",
                })),
            )
        );
        assert_eq!(
            search_messages_call("\"x\"", None, None, None),
            expect(
                Method::POST,
                "https://chat.googleapis.com/v1/spaces/-/messages:search",
                &[],
                Body::Json(json!({ "filter": "\"x\"" })),
            )
        );
    }

    #[test]
    fn download_uses_media_path_with_alt_media() {
        assert_eq!(
            download_attachment_call("spaces/AAA/attachments/BBB").unwrap(),
            get_expect(
                "https://chat.googleapis.com/v1/media/spaces/AAA/attachments/BBB",
                &[("alt", "media")],
            )
        );
        assert!(download_attachment_call("spaces/AAA/../x").is_err());
    }

    #[test]
    fn create_message_body_and_query() {
        let attachment = json!({"attachmentDataRef": {"resourceName": "spaces/AAA/attachments/Z"}});
        let call = create_message_call(
            "spaces/AAA",
            Some("hi"),
            Some("spaces/AAA/threads/T1"),
            None,
            Some("REPLY_MESSAGE_OR_FAIL"),
            std::slice::from_ref(&attachment),
        )
        .unwrap();
        assert_eq!(
            call,
            expect(
                Method::POST,
                "https://chat.googleapis.com/v1/spaces/AAA/messages",
                &[("messageReplyOption", "REPLY_MESSAGE_OR_FAIL")],
                Body::Json(json!({
                    "text": "hi",
                    "thread": {"name": "spaces/AAA/threads/T1"},
                    "attachment": [attachment],
                })),
            )
        );
    }

    #[test]
    fn create_message_with_thread_key_sends_it_as_query() {
        let call = create_message_call(
            "spaces/AAA",
            Some("hi"),
            None,
            Some("order-1"),
            Some("REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"),
            &[],
        )
        .unwrap();
        assert_eq!(
            call,
            expect(
                Method::POST,
                "https://chat.googleapis.com/v1/spaces/AAA/messages",
                &[
                    ("threadKey", "order-1"),
                    ("messageReplyOption", "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"),
                ],
                Body::Json(json!({"text": "hi"})),
            )
        );
    }

    #[test]
    fn create_message_rejects_bad_space_or_thread_names() {
        assert!(create_message_call("people/AAA", Some("x"), None, None, None, &[]).is_err());
        assert!(
            create_message_call("spaces/AAA", Some("x"), Some("spaces/AAA"), None, None, &[])
                .is_err()
        );
    }

    #[test]
    fn multipart_body_is_exact() {
        let body = multipart_body("B", &json!({"filename": "a.txt"}), b"hi", "text/plain");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "--B\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\"filename\":\"a.txt\"}\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B--\r\n"
        );
    }

    #[test]
    fn upload_targets_multipart_endpoint_with_related_content_type() {
        let call = upload_attachment_call("spaces/AAA", "a.txt", b"hi", "text/plain", "B").unwrap();
        assert_eq!(call.method, Method::POST);
        assert_eq!(
            call.url,
            "https://chat.googleapis.com/upload/v1/spaces/AAA/attachments:upload"
        );
        assert_eq!(call.query, vec![pair("uploadType", "multipart")]);
        match call.body {
            Body::Multipart {
                content_type,
                bytes,
            } => {
                assert_eq!(content_type, "multipart/related; boundary=B");
                assert!(
                    String::from_utf8(bytes)
                        .unwrap()
                        .contains("{\"filename\":\"a.txt\"}")
                );
            }
            other => panic!("expected multipart body, got {other:?}"),
        }
        assert!(upload_attachment_call("people/AAA", "a.txt", b"", "text/plain", "B").is_err());
    }

    #[test]
    fn update_patches_text_with_update_mask() {
        assert_eq!(
            update_message_call("spaces/AAA/messages/BBB", "edited").unwrap(),
            expect(
                Method::PATCH,
                "https://chat.googleapis.com/v1/spaces/AAA/messages/BBB",
                &[("updateMask", "text")],
                Body::Json(json!({"text": "edited"})),
            )
        );
    }

    #[test]
    fn delete_sends_force_flag_either_way() {
        assert_eq!(
            delete_message_call("spaces/AAA/messages/BBB", true).unwrap(),
            expect(
                Method::DELETE,
                "https://chat.googleapis.com/v1/spaces/AAA/messages/BBB",
                &[("force", "true")],
                Body::Empty,
            )
        );
        assert_eq!(
            delete_message_call("spaces/AAA/messages/BBB", false)
                .unwrap()
                .query,
            vec![pair("force", "false")]
        );
    }

    #[test]
    fn add_reaction_posts_unicode_emoji() {
        assert_eq!(
            add_reaction_call("spaces/AAA/messages/BBB", "👍").unwrap(),
            expect(
                Method::POST,
                "https://chat.googleapis.com/v1/spaces/AAA/messages/BBB/reactions",
                &[],
                Body::Json(json!({"emoji": {"unicode": "👍"}})),
            )
        );
    }

    #[test]
    fn list_reactions_url_and_query() {
        assert_eq!(
            list_reactions_call("spaces/AAA/messages/BBB", Some(3), Some("p"), None).unwrap(),
            get_expect(
                "https://chat.googleapis.com/v1/spaces/AAA/messages/BBB/reactions",
                &[("pageSize", "3"), ("pageToken", "p")],
            )
        );
    }

    #[test]
    fn remove_reaction_deletes_the_reaction_name() {
        assert_eq!(
            remove_reaction_call("spaces/AAA/messages/BBB/reactions/CCC").unwrap(),
            expect(
                Method::DELETE,
                "https://chat.googleapis.com/v1/spaces/AAA/messages/BBB/reactions/CCC",
                &[],
                Body::Empty,
            )
        );
        assert!(remove_reaction_call("spaces/AAA/messages/BBB").is_err());
    }

    #[test]
    fn only_bodyless_posts_need_zero_length() {
        let bodyless_post = request(Method::POST, "u".into(), vec![], Body::Empty);
        assert!(needs_zero_length(&bodyless_post));
        let json_post = request(Method::POST, "u".into(), vec![], Body::Json(json!({})));
        assert!(!needs_zero_length(&json_post));
        let get_call = get("u".into(), vec![]);
        assert!(!needs_zero_length(&get_call));
        let delete_call = request(Method::DELETE, "u".into(), vec![], Body::Empty);
        assert!(!needs_zero_length(&delete_call));
    }

    #[test]
    fn forbidden_with_missing_scope_is_insufficient_scope() {
        let body = br#"{"error":{"code":403,"message":"Request had insufficient authentication scopes.","status":"PERMISSION_DENIED","details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT"}]}}"#;
        assert!(matches!(
            api_error(StatusCode::FORBIDDEN, body),
            ChatError::InsufficientScope
        ));
    }

    #[test]
    fn other_errors_keep_status_and_truncate_message() {
        let plain = api_error(StatusCode::FORBIDDEN, b"nope");
        assert!(
            matches!(&plain, ChatError::Api { status, message } if *status == StatusCode::FORBIDDEN && message == "nope")
        );
        let scope_on_404 = api_error(StatusCode::NOT_FOUND, b"ACCESS_TOKEN_SCOPE_INSUFFICIENT");
        assert!(
            matches!(scope_on_404, ChatError::Api { status, .. } if status == StatusCode::NOT_FOUND)
        );
        let long = vec![b'x'; 2000];
        match api_error(StatusCode::BAD_REQUEST, &long) {
            ChatError::Api { message, .. } => assert_eq!(message.chars().count(), 800),
            other => panic!("expected Api, got {other:?}"),
        }
    }
}
