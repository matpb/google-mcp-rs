//! Unified MCP error type. Domain errors (Gmail, Sheets, Drive, MIME,
//! credentials, session) all funnel through `McpError`, which knows how to
//! classify itself for the agent: invalid input vs. not-found vs.
//! rate-limited vs. transient vs. needs-reauth.
//!
//! Every error carries a structured `data` payload alongside the human
//! message so an agent can make programmatic decisions:
//!
//! ```json
//! {
//!   "category": "not_found",
//!   "retryable": false,
//!   "http_status": 404,
//!   "upstream_reason": "notFound",
//!   "service": "gmail",
//!   "hint": "Verify the message ID exists. Use gmail_search_threads to discover IDs."
//! }
//! ```

use std::borrow::Cow;

use rmcp::ErrorData;
use rmcp::model::ErrorCode;
use serde_json::{Value, json};

use crate::credentials::CredentialsError;
use crate::google::calendar::CalendarError;
use crate::google::docs::DocsError;
use crate::google::drive::DriveError;
use crate::google::gmail::GmailError;
use crate::google::session::SessionError;
use crate::google::sheets::SheetsError;
use crate::mime::MimeError;
use crate::oauth::{GoogleOAuthError, JwtError};

/// Categorization an agent can switch on without parsing free-form text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Bad request shape: missing required field, wrong type, mutually
    /// exclusive options both set, etc. Agent should fix args and retry.
    InvalidInput,
    /// Resource ID does not exist. Agent should *discover* (list, search)
    /// before retrying with a different ID.
    NotFound,
    /// User needs to re-authorize this MCP server through their MCP
    /// client. Not retryable from the tool layer — only the user can fix.
    AuthRequired,
    /// Auth header missing/malformed/forged. Distinct from AuthRequired
    /// because here the JWT itself is invalid (vs. the upstream Google
    /// refresh token being revoked).
    AuthInvalid,
    /// Google rate limit hit. Retryable after backoff.
    RateLimited,
    /// User's account doesn't have permission for this action (file
    /// shared without write access, etc.).
    PermissionDenied,
    /// Network blip / Google 5xx / refresh-token network failure.
    /// Retryable after a short delay.
    Transient,
    /// Upstream returned an error we don't categorize specifically.
    /// Agent should look at message + http_status to decide.
    Upstream,
    /// Server-side bug. Retry won't help.
    Internal,
}

impl Category {
    pub fn name(self) -> &'static str {
        match self {
            Category::InvalidInput => "invalid_input",
            Category::NotFound => "not_found",
            Category::AuthRequired => "auth_required",
            Category::AuthInvalid => "auth_invalid",
            Category::RateLimited => "rate_limited",
            Category::PermissionDenied => "permission_denied",
            Category::Transient => "transient",
            Category::Upstream => "upstream",
            Category::Internal => "internal",
        }
    }

    pub fn retryable(self) -> bool {
        matches!(self, Category::RateLimited | Category::Transient)
    }

    pub fn error_code(self) -> ErrorCode {
        match self {
            Category::InvalidInput => ErrorCode::INVALID_PARAMS,
            Category::NotFound => ErrorCode::RESOURCE_NOT_FOUND,
            Category::AuthRequired | Category::AuthInvalid => ErrorCode::INVALID_REQUEST,
            Category::RateLimited
            | Category::Transient
            | Category::PermissionDenied
            | Category::Upstream
            | Category::Internal => ErrorCode::INTERNAL_ERROR,
        }
    }
}

#[derive(Debug)]
pub struct McpError {
    pub category: Category,
    pub message: String,
    pub service: Option<&'static str>,
    pub http_status: Option<u16>,
    pub upstream_reason: Option<String>,
    pub retry_after_ms: Option<u64>,
    pub hint: Option<String>,
    /// Optional resource kind ("message", "thread", "file", ...) for
    /// NotFound errors so agents can target the right discovery tool.
    pub resource_kind: Option<&'static str>,
    pub resource_id: Option<String>,
    /// For AuthRequired: where the user (or their MCP client) should go
    /// to start a fresh OAuth flow.
    pub reconnect_url: Option<String>,
}

impl McpError {
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::base(Category::InvalidInput, message)
    }

    pub fn not_found(kind: &'static str, id: impl Into<String>, service: &'static str) -> Self {
        let id_owned: String = id.into();
        Self {
            category: Category::NotFound,
            message: format!("{service} {kind} not found: {id_owned}"),
            service: Some(service),
            http_status: Some(404),
            upstream_reason: Some("notFound".into()),
            retry_after_ms: None,
            hint: Some(default_not_found_hint(kind)),
            resource_kind: Some(kind),
            resource_id: Some(id_owned),
            reconnect_url: None,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::base(Category::Internal, message)
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn with_service(mut self, service: &'static str) -> Self {
        self.service = Some(service);
        self
    }

    fn base(category: Category, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
            service: None,
            http_status: None,
            upstream_reason: None,
            retry_after_ms: None,
            hint: None,
            resource_kind: None,
            resource_id: None,
            reconnect_url: None,
        }
    }

    fn data(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("category".into(), json!(self.category.name()));
        obj.insert("retryable".into(), json!(self.category.retryable()));
        if let Some(s) = self.service {
            obj.insert("service".into(), json!(s));
        }
        if let Some(h) = self.http_status {
            obj.insert("http_status".into(), json!(h));
        }
        if let Some(r) = &self.upstream_reason {
            obj.insert("upstream_reason".into(), json!(r));
        }
        if let Some(r) = self.retry_after_ms {
            obj.insert("retry_after_ms".into(), json!(r));
        }
        if let Some(h) = &self.hint {
            obj.insert("hint".into(), json!(h));
        }
        if let Some(k) = self.resource_kind {
            obj.insert("resource_kind".into(), json!(k));
        }
        if let Some(id) = &self.resource_id {
            obj.insert("resource_id".into(), json!(id));
        }
        if let Some(u) = &self.reconnect_url {
            obj.insert("reconnect_url".into(), json!(u));
        }
        Value::Object(obj)
    }
}

impl From<McpError> for ErrorData {
    fn from(e: McpError) -> Self {
        let code = e.category.error_code();
        let data = e.data();
        ErrorData::new(code, Cow::Owned(e.message), Some(data))
    }
}

fn default_not_found_hint(kind: &str) -> String {
    match kind {
        "message" => "Use gmail_search_threads or gmail_list_messages to discover valid message IDs.".into(),
        "thread" => "Use gmail_search_threads to discover valid thread IDs.".into(),
        "draft" => "Use gmail_list_drafts to discover valid draft IDs.".into(),
        "label" => "Use gmail_list_labels to discover valid label IDs.".into(),
        "attachment" => "Use gmail_list_attachments to discover valid attachment IDs for a message.".into(),
        "file" => "Use drive_list_files to discover valid file IDs.".into(),
        "spreadsheet" => "Use drive_list_files with `mimeType = 'application/vnd.google-apps.spreadsheet'` to find spreadsheets.".into(),
        "document" => "Use drive_list_files with `mimeType = 'application/vnd.google-apps.document'` to find Google Docs.".into(),
        "permission" => "Use drive_list_permissions to discover valid permission IDs for a file.".into(),
        "calendar" => "Use calendar_list_calendars to discover valid calendar IDs (or use \"primary\" for the user's main calendar).".into(),
        "event" => "Use calendar_list_events to discover valid event IDs.".into(),
        _ => format!("Verify the {kind} ID exists."),
    }
}

/// Convenience helper for `.map_err(to_mcp)?`.
pub fn to_mcp<E: Into<McpError>>(e: E) -> ErrorData {
    e.into().into()
}

// ===========================================================================
// Conversions from domain errors
// ===========================================================================

impl From<GmailError> for McpError {
    fn from(e: GmailError) -> Self {
        match e {
            GmailError::Http(err) => transient_from_reqwest("gmail", err),
            GmailError::Api {
                status,
                message,
                details,
            } => google_api_error("gmail", status.as_u16(), message, details),
            GmailError::Parse(err) => {
                McpError::internal(format!("could not parse Gmail response: {err}"))
                    .with_service("gmail")
            }
            GmailError::Invalid(s) => McpError::invalid_input(format!("invalid input: {s}")),
        }
    }
}

impl From<SheetsError> for McpError {
    fn from(e: SheetsError) -> Self {
        match e {
            SheetsError::Http(err) => transient_from_reqwest("sheets", err),
            SheetsError::Api { status, message } => {
                google_api_error("sheets", status.as_u16(), message, None)
            }
            SheetsError::Parse(err) => {
                McpError::internal(format!("could not parse Sheets response: {err}"))
                    .with_service("sheets")
            }
        }
    }
}

impl From<DocsError> for McpError {
    fn from(e: DocsError) -> Self {
        match e {
            DocsError::Http(err) => transient_from_reqwest("docs", err),
            DocsError::Api { status, message } => {
                google_api_error("docs", status.as_u16(), message, None)
            }
            DocsError::Parse(err) => {
                McpError::internal(format!("could not parse Docs response: {err}"))
                    .with_service("docs")
            }
        }
    }
}

impl From<DriveError> for McpError {
    fn from(e: DriveError) -> Self {
        match e {
            DriveError::Http(err) => transient_from_reqwest("drive", err),
            DriveError::Api { status, message } => {
                google_api_error("drive", status.as_u16(), message, None)
            }
            DriveError::Parse(err) => {
                McpError::internal(format!("could not parse Drive response: {err}"))
                    .with_service("drive")
            }
        }
    }
}

impl From<CalendarError> for McpError {
    fn from(e: CalendarError) -> Self {
        match e {
            CalendarError::Http(err) => transient_from_reqwest("calendar", err),
            CalendarError::Api { status, message } => {
                google_api_error("calendar", status.as_u16(), message, None)
            }
            CalendarError::Parse(err) => {
                McpError::internal(format!("could not parse Calendar response: {err}"))
                    .with_service("calendar")
            }
        }
    }
}

impl From<MimeError> for McpError {
    fn from(e: MimeError) -> Self {
        match e {
            MimeError::AttachmentTooLarge => {
                McpError::invalid_input("attachment(s) exceed Gmail's 24 MB total cap").with_hint(
                    "Reduce attachment size or send fewer attachments per message. \
                 The cap leaves headroom under Gmail's 25 MB hard limit for MIME framing.",
                )
            }
            MimeError::NoRecipients => {
                McpError::invalid_input("at least one recipient is required (to, cc, or bcc)")
                    .with_hint("Pass a non-empty `to`, `cc`, or `bcc` array.")
            }
            MimeError::Build(msg) => {
                McpError::invalid_input(format!("could not build MIME message: {msg}"))
            }
        }
    }
}

impl From<CredentialsError> for McpError {
    fn from(e: CredentialsError) -> Self {
        match e {
            CredentialsError::Missing => {
                let mut err = McpError::base(
                    Category::AuthInvalid,
                    "missing Authorization header (expected `Bearer <jwt>`)",
                );
                err.hint = Some(
                    "This shouldn't happen if the MCP client is configured \
                     correctly — every /mcp call must include the JWT issued \
                     by /oauth/token."
                        .into(),
                );
                err
            }
            CredentialsError::Malformed => McpError::base(
                Category::AuthInvalid,
                "malformed Authorization header (expected `Bearer <jwt>`)",
            ),
            CredentialsError::Jwt(jwt) => jwt.into(),
            CredentialsError::Session(s) => s.into(),
        }
    }
}

impl From<JwtError> for McpError {
    fn from(e: JwtError) -> Self {
        let kind = match &e {
            JwtError::Verify(inner) => match inner.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => "expired",
                jsonwebtoken::errors::ErrorKind::InvalidSignature => "invalid_signature",
                _ => "invalid",
            },
            JwtError::Sign(_) => return McpError::internal(format!("could not sign JWT: {e}")),
            JwtError::AudienceMismatch => "audience_mismatch",
        };
        let mut err = McpError::base(Category::AuthInvalid, e.to_string());
        err.upstream_reason = Some(kind.into());
        err.hint = Some(match kind {
            "expired" => "JWT has expired. Re-run the OAuth flow at /authorize to mint a new one.".into(),
            "invalid_signature" => "JWT signature does not match this server's key. Has the operator rotated JWT_SECRET?".into(),
            "audience_mismatch" => "JWT was issued for a different resource (the `aud` claim does not match this server's URL).".into(),
            _ => "Re-run the OAuth flow at /authorize.".into(),
        });
        err
    }
}

impl From<SessionError> for McpError {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::AccountNotFound => McpError {
                category: Category::AuthRequired,
                message: "this Google account is not registered with the MCP server (the JWT references an unknown sub)".into(),
                service: Some("oauth"),
                http_status: None,
                upstream_reason: Some("account_not_found".into()),
                retry_after_ms: None,
                hint: Some("Re-run the OAuth flow at /authorize to register the account.".into()),
                resource_kind: None,
                resource_id: None,
                reconnect_url: Some("/authorize".into()),
            },
            SessionError::ReconnectRequired => McpError {
                category: Category::AuthRequired,
                message: "Google account disconnected — refresh token was revoked or expired".into(),
                service: Some("oauth"),
                http_status: Some(401),
                upstream_reason: Some("invalid_grant".into()),
                retry_after_ms: None,
                hint: Some(
                    "The user must re-authorize this MCP server. In Claude.ai, \
                     disconnect and reconnect the connector. In Claude Code, \
                     re-run the OAuth flow."
                        .into(),
                ),
                resource_kind: None,
                resource_id: None,
                reconnect_url: Some("/authorize".into()),
            },
            SessionError::Storage(db) => McpError::internal(format!("storage: {db}"))
                .with_service("storage"),
            SessionError::Google(g) => match g {
                GoogleOAuthError::InvalidGrant => McpError {
                    category: Category::AuthRequired,
                    message: "Google rejected the refresh token (invalid_grant)".into(),
                    service: Some("oauth"),
                    http_status: Some(401),
                    upstream_reason: Some("invalid_grant".into()),
                    retry_after_ms: None,
                    hint: Some("User must re-authorize via /authorize.".into()),
                    resource_kind: None,
                    resource_id: None,
                    reconnect_url: Some("/authorize".into()),
                },
                GoogleOAuthError::Http(err) => transient_from_reqwest("oauth", err),
                GoogleOAuthError::TokenEndpoint {
                    status,
                    error,
                    description,
                } => McpError {
                    category: classify_oauth_error(&error),
                    message: format!(
                        "Google /token returned {status}: {error}{}",
                        description
                            .as_ref()
                            .map(|d| format!(" — {d}"))
                            .unwrap_or_default()
                    ),
                    service: Some("oauth"),
                    http_status: Some(status.as_u16()),
                    upstream_reason: Some(error.clone()),
                    retry_after_ms: None,
                    hint: oauth_hint(&error),
                    resource_kind: None,
                    resource_id: None,
                    reconnect_url: oauth_reconnect_url(&error),
                },
                GoogleOAuthError::Unexpected { status, body } => McpError {
                    category: if status.is_server_error() {
                        Category::Transient
                    } else {
                        Category::Upstream
                    },
                    message: format!("Google /token returned unexpected {status}: {body}"),
                    service: Some("oauth"),
                    http_status: Some(status.as_u16()),
                    upstream_reason: None,
                    retry_after_ms: None,
                    hint: None,
                    resource_kind: None,
                    resource_id: None,
                    reconnect_url: None,
                },
                GoogleOAuthError::ParseResponse { source, body } => McpError::internal(format!(
                    "Google /token returned a malformed response: {source}; body: {body}"
                ))
                .with_service("oauth"),
                GoogleOAuthError::IdToken(s) => McpError::internal(format!("ID token parse: {s}"))
                    .with_service("oauth"),
            },
        }
    }
}

// ===========================================================================
// HTTP-status → category classifier shared by Gmail/Sheets/Drive
// ===========================================================================

fn google_api_error(
    service: &'static str,
    status: u16,
    message: String,
    details: Option<String>,
) -> McpError {
    // GmailClient formats `details` as "{domain}/{reason}: {message}" — pull
    // out just the `{reason}` token so agents get a stable Google error code.
    let upstream_reason: Option<String> = details
        .as_ref()
        .and_then(|d| d.split_once(": ").map(|(prefix, _)| prefix))
        .and_then(|p| p.split_once('/').map(|(_, reason)| reason.to_string()));

    let (category, hint) = classify_http(status, upstream_reason.as_deref(), service);

    let retry_after_ms = if matches!(category, Category::RateLimited | Category::Transient) {
        // Gmail/Drive/Sheets all honor Retry-After in seconds; we don't get
        // the header here (only the body) — leave None and let the caller
        // back off heuristically. A future improvement: thread the header
        // through the *Client structs.
        None
    } else {
        None
    };

    McpError {
        category,
        message,
        service: Some(service),
        http_status: Some(status),
        upstream_reason,
        retry_after_ms,
        hint,
        resource_kind: None,
        resource_id: None,
        reconnect_url: if matches!(category, Category::AuthRequired | Category::AuthInvalid) {
            Some("/authorize".into())
        } else {
            None
        },
    }
}

fn classify_http(
    status: u16,
    upstream_reason: Option<&str>,
    service: &str,
) -> (Category, Option<String>) {
    match status {
        400 => {
            let cat = Category::InvalidInput;
            let hint = match upstream_reason {
                Some("invalidArgument") => Some(
                    "The request shape was rejected by Google. Check the field types and required fields against the API docs.".into(),
                ),
                Some("badRequest") => Some(
                    "Google rejected the request. The error message above is from Google verbatim.".into(),
                ),
                _ => Some(format!(
                    "Inspect the error message — Google rejected this {service} request as malformed."
                )),
            };
            (cat, hint)
        }
        401 => (
            Category::AuthRequired,
            Some(
                "Google rejected the access token. The session cache will refresh on the next call; if this persists, the user must re-authorize via /authorize."
                    .into(),
            ),
        ),
        403 => {
            let cat = match upstream_reason {
                Some("rateLimitExceeded") | Some("userRateLimitExceeded") | Some("quotaExceeded") => {
                    Category::RateLimited
                }
                Some("insufficientPermissions") | Some("forbidden") | Some("notFound") => {
                    Category::PermissionDenied
                }
                _ => Category::PermissionDenied,
            };
            let hint = match upstream_reason {
                Some(r) if r.contains("RateLimit") || r == "quotaExceeded" => Some(
                    "Back off and retry. Google's per-user-per-second quota is in the low hundreds of units; bulk operations should pace themselves.".into(),
                ),
                _ => Some(
                    "The authenticated user doesn't have permission for this resource. For Drive: check sharing. For Gmail: ensure the gmail.modify scope was granted.".into(),
                ),
            };
            (cat, hint)
        }
        404 => (
            Category::NotFound,
            Some(format!("The {service} resource ID does not exist (or is not visible to the authenticated user).")),
        ),
        409 => (
            Category::InvalidInput,
            Some("Conflict — the resource already exists or is in a state that doesn't permit this operation.".into()),
        ),
        429 => (
            Category::RateLimited,
            Some("Rate limited. Wait and retry. If the agent is in a tight loop, exponential backoff (250ms → 1s → 4s) is appropriate.".into()),
        ),
        500..=599 => (
            Category::Transient,
            Some("Google returned a 5xx — transient. Retry after a short delay (1–5 seconds).".into()),
        ),
        _ => (Category::Upstream, None),
    }
}

fn transient_from_reqwest(service: &'static str, err: reqwest::Error) -> McpError {
    let category = if err.is_timeout() || err.is_connect() {
        Category::Transient
    } else {
        Category::Upstream
    };
    let hint = if matches!(category, Category::Transient) {
        Some("Network error to Google. Retry after a short delay.".into())
    } else {
        None
    };
    McpError {
        category,
        message: format!("HTTP error talking to {service}: {err}"),
        service: Some(service),
        http_status: err.status().map(|s| s.as_u16()),
        upstream_reason: None,
        retry_after_ms: None,
        hint,
        resource_kind: None,
        resource_id: None,
        reconnect_url: None,
    }
}

fn classify_oauth_error(err: &str) -> Category {
    match err {
        "invalid_grant" | "invalid_token" | "unauthorized_client" => Category::AuthRequired,
        "invalid_request" | "invalid_scope" | "unsupported_grant_type" => Category::InvalidInput,
        "temporarily_unavailable" | "server_error" => Category::Transient,
        _ => Category::Upstream,
    }
}

fn oauth_hint(err: &str) -> Option<String> {
    match err {
        "invalid_grant" => Some("Refresh token revoked or expired. User must re-authorize via /authorize.".into()),
        "invalid_scope" => Some(
            "The OAuth client is missing a scope this MCP requires. Add openid, email, gmail.modify, spreadsheets, drive to the consent screen in the GCP console."
                .into(),
        ),
        _ => None,
    }
}

fn oauth_reconnect_url(err: &str) -> Option<String> {
    match err {
        "invalid_grant" | "invalid_token" => Some("/authorize".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_codes_and_retryability() {
        assert_eq!(
            Category::InvalidInput.error_code(),
            ErrorCode::INVALID_PARAMS
        );
        assert_eq!(
            Category::NotFound.error_code(),
            ErrorCode::RESOURCE_NOT_FOUND
        );
        assert_eq!(
            Category::AuthRequired.error_code(),
            ErrorCode::INVALID_REQUEST
        );
        assert_eq!(
            Category::AuthInvalid.error_code(),
            ErrorCode::INVALID_REQUEST
        );
        assert_eq!(Category::Internal.error_code(), ErrorCode::INTERNAL_ERROR);
        assert!(Category::RateLimited.retryable());
        assert!(Category::Transient.retryable());
        assert!(!Category::InvalidInput.retryable());
        assert!(!Category::NotFound.retryable());
        assert!(!Category::AuthRequired.retryable());
    }

    #[test]
    fn data_payload_includes_classification() {
        let err = McpError::not_found("message", "abc123", "gmail");
        let data: Value = err.data();
        let obj = data.as_object().unwrap();
        assert_eq!(obj.get("category").unwrap(), "not_found");
        assert_eq!(obj.get("retryable").unwrap(), false);
        assert_eq!(obj.get("http_status").unwrap(), 404);
        assert_eq!(obj.get("service").unwrap(), "gmail");
        assert_eq!(obj.get("upstream_reason").unwrap(), "notFound");
        assert_eq!(obj.get("resource_kind").unwrap(), "message");
        assert_eq!(obj.get("resource_id").unwrap(), "abc123");
        assert!(obj.get("hint").is_some());
    }

    #[test]
    fn http_404_classifies_as_not_found() {
        let (cat, hint) = classify_http(404, None, "gmail");
        assert_eq!(cat, Category::NotFound);
        assert!(hint.is_some());
    }

    #[test]
    fn http_429_classifies_as_rate_limited() {
        let (cat, _) = classify_http(429, None, "gmail");
        assert_eq!(cat, Category::RateLimited);
        assert!(cat.retryable());
    }

    #[test]
    fn http_503_classifies_as_transient() {
        let (cat, _) = classify_http(503, None, "drive");
        assert_eq!(cat, Category::Transient);
        assert!(cat.retryable());
    }

    #[test]
    fn http_403_quota_classifies_as_rate_limited() {
        let (cat, _) = classify_http(403, Some("userRateLimitExceeded"), "gmail");
        assert_eq!(cat, Category::RateLimited);
    }

    #[test]
    fn http_403_default_classifies_as_permission_denied() {
        let (cat, _) = classify_http(403, Some("forbidden"), "drive");
        assert_eq!(cat, Category::PermissionDenied);
    }

    #[test]
    fn invalid_input_to_error_data() {
        let err = McpError::invalid_input("`to` must be non-empty");
        let ed: ErrorData = err.into();
        assert_eq!(ed.code, ErrorCode::INVALID_PARAMS);
        let data = ed.data.unwrap();
        assert_eq!(data.get("category").unwrap(), "invalid_input");
        assert_eq!(data.get("retryable").unwrap(), false);
    }

    #[test]
    fn session_reconnect_required_includes_reconnect_url() {
        let err: McpError = SessionError::ReconnectRequired.into();
        assert_eq!(err.category, Category::AuthRequired);
        let data = err.data();
        assert_eq!(data.get("reconnect_url").unwrap(), "/authorize");
        assert_eq!(data.get("upstream_reason").unwrap(), "invalid_grant");
    }

    #[test]
    fn session_account_not_found_classifies_as_auth_required() {
        let err: McpError = SessionError::AccountNotFound.into();
        assert_eq!(err.category, Category::AuthRequired);
    }

    #[test]
    fn mime_no_recipients_is_invalid_input() {
        let err: McpError = MimeError::NoRecipients.into();
        assert_eq!(err.category, Category::InvalidInput);
        assert!(err.hint.is_some());
    }

    #[test]
    fn mime_attachment_too_large_is_invalid_input_with_hint() {
        let err: McpError = MimeError::AttachmentTooLarge.into();
        assert_eq!(err.category, Category::InvalidInput);
        assert!(err.message.contains("24 MB"));
        assert!(err.hint.unwrap().to_lowercase().contains("reduce"));
    }

    #[test]
    fn jwt_audience_mismatch_classifies_as_auth_invalid() {
        let err: McpError = JwtError::AudienceMismatch.into();
        assert_eq!(err.category, Category::AuthInvalid);
        let data = err.data();
        assert_eq!(data.get("upstream_reason").unwrap(), "audience_mismatch");
    }
}
