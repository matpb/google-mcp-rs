//! Gmail REST v1 client. Thin wrapper that authenticates with the user's
//! current access token and returns deserialized JSON to the caller.
//!
//! Tools own the API contract: this module just plumbs HTTP. All methods
//! return `serde_json::Value` so the rmcp layer can forward Gmail's
//! payload structure to the agent without lossy intermediate types.

use http::StatusCode;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Invalid is held for future client-side validations
pub enum GmailError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Gmail returned {status}: {message}{}", details.as_deref().map(|d| format!(" — {d}")).unwrap_or_default())]
    Api {
        status: StatusCode,
        message: String,
        details: Option<String>,
    },
    #[error("could not parse Gmail response: {0}")]
    Parse(serde_json::Error),
    #[error("invalid input: {0}")]
    Invalid(&'static str),
}

const BASE: &str = "https://gmail.googleapis.com/gmail/v1/users/me";

#[derive(Clone)]
pub struct GmailClient {
    http: reqwest::Client,
    access_token: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ModifyLabels {
    #[serde(rename = "addLabelIds", skip_serializing_if = "Vec::is_empty")]
    pub add_label_ids: Vec<String>,
    #[serde(rename = "removeLabelIds", skip_serializing_if = "Vec::is_empty")]
    pub remove_label_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateLabel {
    pub name: String,
    #[serde(
        rename = "labelListVisibility",
        skip_serializing_if = "Option::is_none"
    )]
    pub label_list_visibility: Option<String>,
    #[serde(
        rename = "messageListVisibility",
        skip_serializing_if = "Option::is_none"
    )]
    pub message_list_visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<LabelColor>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateLabel {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        rename = "labelListVisibility",
        skip_serializing_if = "Option::is_none"
    )]
    pub label_list_visibility: Option<String>,
    #[serde(
        rename = "messageListVisibility",
        skip_serializing_if = "Option::is_none"
    )]
    pub message_list_visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<LabelColor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LabelColor {
    /// Background color hex (Gmail's restricted palette, e.g. `#16a766`).
    #[serde(rename = "backgroundColor")]
    pub background_color: String,
    /// Text color hex (Gmail's restricted palette, e.g. `#ffffff`).
    #[serde(rename = "textColor")]
    pub text_color: String,
}

impl GmailClient {
    pub fn new(http: reqwest::Client, access_token: impl Into<String>) -> Self {
        Self {
            http,
            access_token: access_token.into(),
        }
    }

    // --- profile ---------------------------------------------------------

    pub async fn profile(&self) -> Result<Value, GmailError> {
        self.request(Method::GET, format!("{BASE}/profile"), None::<&()>, &[])
            .await
    }

    // --- threads ---------------------------------------------------------

    pub async fn list_threads(
        &self,
        q: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
        label_ids: &[String],
    ) -> Result<Value, GmailError> {
        let mut query: Vec<(String, String)> = Vec::new();
        if let Some(q) = q {
            query.push(("q".into(), q.into()));
        }
        if let Some(n) = max_results {
            query.push(("maxResults".into(), n.to_string()));
        }
        if let Some(t) = page_token {
            query.push(("pageToken".into(), t.into()));
        }
        for l in label_ids {
            query.push(("labelIds".into(), l.clone()));
        }
        self.request(Method::GET, format!("{BASE}/threads"), None::<&()>, &query)
            .await
    }

    pub async fn get_thread(&self, id: &str, format: Option<&str>) -> Result<Value, GmailError> {
        let mut query = vec![];
        if let Some(f) = format {
            query.push(("format".into(), f.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/threads/{id}"),
            None::<&()>,
            &query,
        )
        .await
    }

    pub async fn modify_thread(&self, id: &str, body: &ModifyLabels) -> Result<Value, GmailError> {
        self.request(
            Method::POST,
            format!("{BASE}/threads/{id}/modify"),
            Some(body),
            &[],
        )
        .await
    }

    pub async fn trash_thread(&self, id: &str) -> Result<Value, GmailError> {
        self.request(
            Method::POST,
            format!("{BASE}/threads/{id}/trash"),
            None::<&()>,
            &[],
        )
        .await
    }

    // --- messages --------------------------------------------------------

    pub async fn list_messages(
        &self,
        q: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
        label_ids: &[String],
        include_spam_trash: bool,
    ) -> Result<Value, GmailError> {
        let mut query: Vec<(String, String)> = Vec::new();
        if let Some(q) = q {
            query.push(("q".into(), q.into()));
        }
        if let Some(n) = max_results {
            query.push(("maxResults".into(), n.to_string()));
        }
        if let Some(t) = page_token {
            query.push(("pageToken".into(), t.into()));
        }
        for l in label_ids {
            query.push(("labelIds".into(), l.clone()));
        }
        if include_spam_trash {
            query.push(("includeSpamTrash".into(), "true".into()));
        }
        self.request(Method::GET, format!("{BASE}/messages"), None::<&()>, &query)
            .await
    }

    pub async fn get_message(
        &self,
        id: &str,
        format: Option<&str>,
        metadata_headers: &[String],
    ) -> Result<Value, GmailError> {
        let mut query = vec![];
        if let Some(f) = format {
            query.push(("format".into(), f.into()));
        }
        for h in metadata_headers {
            query.push(("metadataHeaders".into(), h.clone()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/messages/{id}"),
            None::<&()>,
            &query,
        )
        .await
    }

    pub async fn modify_message(&self, id: &str, body: &ModifyLabels) -> Result<Value, GmailError> {
        self.request(
            Method::POST,
            format!("{BASE}/messages/{id}/modify"),
            Some(body),
            &[],
        )
        .await
    }

    pub async fn trash_message(&self, id: &str) -> Result<Value, GmailError> {
        self.request(
            Method::POST,
            format!("{BASE}/messages/{id}/trash"),
            None::<&()>,
            &[],
        )
        .await
    }

    pub async fn send_message(
        &self,
        raw_b64url: &str,
        thread_id: Option<&str>,
    ) -> Result<Value, GmailError> {
        let body = match thread_id {
            Some(tid) => json!({"raw": raw_b64url, "threadId": tid}),
            None => json!({"raw": raw_b64url}),
        };
        self.request(
            Method::POST,
            format!("{BASE}/messages/send"),
            Some(&body),
            &[],
        )
        .await
    }

    // --- attachments -----------------------------------------------------

    pub async fn get_attachment(
        &self,
        message_id: &str,
        attachment_id: &str,
    ) -> Result<Value, GmailError> {
        self.request(
            Method::GET,
            format!("{BASE}/messages/{message_id}/attachments/{attachment_id}"),
            None::<&()>,
            &[],
        )
        .await
    }

    // --- drafts ----------------------------------------------------------

    pub async fn list_drafts(
        &self,
        q: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<Value, GmailError> {
        let mut query: Vec<(String, String)> = vec![];
        if let Some(q) = q {
            query.push(("q".into(), q.into()));
        }
        if let Some(n) = max_results {
            query.push(("maxResults".into(), n.to_string()));
        }
        if let Some(t) = page_token {
            query.push(("pageToken".into(), t.into()));
        }
        self.request(Method::GET, format!("{BASE}/drafts"), None::<&()>, &query)
            .await
    }

    pub async fn get_draft(&self, id: &str, format: Option<&str>) -> Result<Value, GmailError> {
        let mut query = vec![];
        if let Some(f) = format {
            query.push(("format".into(), f.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/drafts/{id}"),
            None::<&()>,
            &query,
        )
        .await
    }

    pub async fn create_draft(
        &self,
        raw_b64url: &str,
        thread_id: Option<&str>,
    ) -> Result<Value, GmailError> {
        let message = match thread_id {
            Some(tid) => json!({"raw": raw_b64url, "threadId": tid}),
            None => json!({"raw": raw_b64url}),
        };
        let body = json!({"message": message});
        self.request(Method::POST, format!("{BASE}/drafts"), Some(&body), &[])
            .await
    }

    pub async fn update_draft(
        &self,
        id: &str,
        raw_b64url: &str,
        thread_id: Option<&str>,
    ) -> Result<Value, GmailError> {
        let message = match thread_id {
            Some(tid) => json!({"raw": raw_b64url, "threadId": tid}),
            None => json!({"raw": raw_b64url}),
        };
        let body = json!({"message": message});
        self.request(Method::PUT, format!("{BASE}/drafts/{id}"), Some(&body), &[])
            .await
    }

    pub async fn send_draft(&self, id: &str) -> Result<Value, GmailError> {
        let body = json!({"id": id});
        self.request(
            Method::POST,
            format!("{BASE}/drafts/send"),
            Some(&body),
            &[],
        )
        .await
    }

    pub async fn delete_draft(&self, id: &str) -> Result<Value, GmailError> {
        self.request_empty_ok(Method::DELETE, format!("{BASE}/drafts/{id}"), None::<&()>)
            .await
    }

    // --- labels ----------------------------------------------------------

    pub async fn list_labels(&self) -> Result<Value, GmailError> {
        self.request(Method::GET, format!("{BASE}/labels"), None::<&()>, &[])
            .await
    }

    pub async fn get_label(&self, id: &str) -> Result<Value, GmailError> {
        self.request(Method::GET, format!("{BASE}/labels/{id}"), None::<&()>, &[])
            .await
    }

    pub async fn create_label(&self, body: &CreateLabel) -> Result<Value, GmailError> {
        self.request(Method::POST, format!("{BASE}/labels"), Some(body), &[])
            .await
    }

    pub async fn update_label(&self, id: &str, body: &UpdateLabel) -> Result<Value, GmailError> {
        self.request(
            Method::PATCH,
            format!("{BASE}/labels/{id}"),
            Some(body),
            &[],
        )
        .await
    }

    pub async fn delete_label(&self, id: &str) -> Result<Value, GmailError> {
        self.request_empty_ok(Method::DELETE, format!("{BASE}/labels/{id}"), None::<&()>)
            .await
    }

    // --- internals -------------------------------------------------------

    async fn request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: String,
        body: Option<&B>,
        query: &[(String, String)],
    ) -> Result<Value, GmailError> {
        let resp = self.send_raw(method, url, body, query).await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            if text.is_empty() {
                return Ok(json!({}));
            }
            return serde_json::from_str(&text).map_err(GmailError::Parse);
        }
        Err(parse_error(status, &text))
    }

    async fn request_empty_ok<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: String,
        body: Option<&B>,
    ) -> Result<Value, GmailError> {
        let resp = self.send_raw(method, url, body, &[]).await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            return Ok(json!({"ok": true}));
        }
        Err(parse_error(status, &text))
    }

    async fn send_raw<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: String,
        body: Option<&B>,
        query: &[(String, String)],
    ) -> Result<reqwest::Response, GmailError> {
        let mut req = self
            .http
            .request(method, &url)
            .bearer_auth(&self.access_token);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        Ok(req.send().await?)
    }
}

fn parse_error(status: StatusCode, body: &str) -> GmailError {
    #[derive(Deserialize)]
    struct ApiErrorWrapper {
        error: ApiError,
    }
    #[derive(Deserialize)]
    struct ApiError {
        #[serde(default)]
        code: i32,
        message: String,
        #[serde(default)]
        errors: Option<Vec<ErrorDetail>>,
        #[serde(default)]
        status: Option<String>,
    }
    #[derive(Deserialize)]
    struct ErrorDetail {
        #[serde(default)]
        reason: Option<String>,
        #[serde(default)]
        domain: Option<String>,
        #[serde(default)]
        message: Option<String>,
    }
    if let Ok(parsed) = serde_json::from_str::<ApiErrorWrapper>(body) {
        let detail = parsed.error.errors.as_ref().and_then(|errs| {
            errs.first().map(|e| {
                let r = e.reason.as_deref().unwrap_or("");
                let d = e.domain.as_deref().unwrap_or("");
                let m = e.message.as_deref().unwrap_or("");
                format!("{d}/{r}: {m}")
            })
        });
        let _ = parsed.error.code;
        return GmailError::Api {
            status,
            message: parsed.error.status.unwrap_or(parsed.error.message),
            details: detail,
        };
    }
    GmailError::Api {
        status,
        message: body.chars().take(400).collect(),
        details: None,
    }
}
