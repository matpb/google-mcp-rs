//! Google Drive v3 client. Thin wrapper covering CRUD + content
//! upload/download + share + export. Uses Drive's "simple" upload
//! (`uploadType=multipart`) to bundle metadata + bytes in one request,
//! which is enough for the day-1 surface (≤ 5 MB content per call).
//! Larger payloads can be supported later via resumable uploads.

use std::borrow::Cow;

use http::StatusCode;
use reqwest::Method;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum DriveError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Drive returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("could not parse Drive response: {0}")]
    Parse(serde_json::Error),
}

const BASE: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD_BASE: &str = "https://www.googleapis.com/upload/drive/v3";

/// Default fields returned for file resources — chosen to be useful
/// without being huge. Callers can override with their own fields filter.
pub const DEFAULT_FILE_FIELDS: &str = "id,name,mimeType,parents,owners,createdTime,modifiedTime,size,webViewLink,webContentLink,trashed,iconLink,description";

#[derive(Clone)]
pub struct DriveClient {
    http: reqwest::Client,
    access_token: String,
}

impl DriveClient {
    pub fn new(http: reqwest::Client, access_token: impl Into<String>) -> Self {
        Self {
            http,
            access_token: access_token.into(),
        }
    }

    #[allow(clippy::too_many_arguments)] // Drive's list endpoint has many tunables
    pub async fn list_files(
        &self,
        q: Option<&str>,
        page_size: Option<u32>,
        page_token: Option<&str>,
        fields: Option<&str>,
        order_by: Option<&str>,
        spaces: Option<&str>,
        include_items_from_all_drives: bool,
    ) -> Result<Value, DriveError> {
        let mut query: Vec<(String, String)> = vec![];
        if let Some(s) = q {
            query.push(("q".into(), s.into()));
        }
        if let Some(n) = page_size {
            query.push(("pageSize".into(), n.to_string()));
        }
        if let Some(t) = page_token {
            query.push(("pageToken".into(), t.into()));
        }
        let f = fields.unwrap_or(
            "nextPageToken,files(id,name,mimeType,parents,modifiedTime,size,webViewLink)",
        );
        query.push(("fields".into(), f.into()));
        if let Some(o) = order_by {
            query.push(("orderBy".into(), o.into()));
        }
        if let Some(s) = spaces {
            query.push(("spaces".into(), s.into()));
        }
        if include_items_from_all_drives {
            query.push(("supportsAllDrives".into(), "true".into()));
            query.push(("includeItemsFromAllDrives".into(), "true".into()));
        }
        self.request(Method::GET, format!("{BASE}/files"), None::<&()>, &query)
            .await
    }

    pub async fn get_file(
        &self,
        file_id: &str,
        fields: Option<&str>,
        supports_all_drives: bool,
    ) -> Result<Value, DriveError> {
        let mut q: Vec<(String, String)> = vec![];
        q.push((
            "fields".into(),
            fields.unwrap_or(DEFAULT_FILE_FIELDS).into(),
        ));
        if supports_all_drives {
            q.push(("supportsAllDrives".into(), "true".into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/files/{file_id}"),
            None::<&()>,
            &q,
        )
        .await
    }

    /// Create a file with metadata only (e.g. a folder, or a shortcut, or
    /// an empty Google Doc/Sheet — Drive treats those as "metadata-only"
    /// when their `mimeType` is `application/vnd.google-apps.*`).
    pub async fn create_metadata_only(&self, metadata: &Value) -> Result<Value, DriveError> {
        let mut q: Vec<(String, String)> = vec![("fields".into(), DEFAULT_FILE_FIELDS.into())];
        // Allow caller to pass parents under a Shared Drive.
        q.push(("supportsAllDrives".into(), "true".into()));
        self.request(Method::POST, format!("{BASE}/files"), Some(metadata), &q)
            .await
    }

    /// Create a file with both metadata and content (multipart upload).
    /// Pass `metadata.mimeType` to specify the file type and
    /// `metadata.parents` to nest in a folder.
    pub async fn create_with_content(
        &self,
        metadata: &Value,
        content: &[u8],
        content_mime: &str,
    ) -> Result<Value, DriveError> {
        let url = format!(
            "{UPLOAD_BASE}/files?uploadType=multipart&fields={DEFAULT_FILE_FIELDS}&supportsAllDrives=true"
        );
        self.upload_multipart(Method::POST, url, metadata, content, content_mime)
            .await
    }

    pub async fn update_metadata(
        &self,
        file_id: &str,
        metadata: &Value,
        add_parents: Option<&str>,
        remove_parents: Option<&str>,
    ) -> Result<Value, DriveError> {
        let mut q: Vec<(String, String)> = vec![("fields".into(), DEFAULT_FILE_FIELDS.into())];
        q.push(("supportsAllDrives".into(), "true".into()));
        if let Some(a) = add_parents {
            q.push(("addParents".into(), a.into()));
        }
        if let Some(r) = remove_parents {
            q.push(("removeParents".into(), r.into()));
        }
        self.request(
            Method::PATCH,
            format!("{BASE}/files/{file_id}"),
            Some(metadata),
            &q,
        )
        .await
    }

    pub async fn update_content(
        &self,
        file_id: &str,
        content: &[u8],
        content_mime: &str,
    ) -> Result<Value, DriveError> {
        let url = format!(
            "{UPLOAD_BASE}/files/{file_id}?uploadType=media&supportsAllDrives=true&fields={DEFAULT_FILE_FIELDS}"
        );
        let resp = self
            .http
            .request(Method::PATCH, &url)
            .bearer_auth(&self.access_token)
            .header(http::header::CONTENT_TYPE, content_mime)
            .body(content.to_vec())
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            return serde_json::from_str(&text).map_err(DriveError::Parse);
        }
        Err(DriveError::Api {
            status,
            message: text.chars().take(800).collect(),
        })
    }

    /// Download a file's binary content (the raw bytes Drive stores).
    /// Returns `(content_type, bytes)`. For Google Docs/Sheets/Slides,
    /// use `export_file` instead — those have no underlying bytes.
    pub async fn download_file(&self, file_id: &str) -> Result<(String, Vec<u8>), DriveError> {
        let url = format!("{BASE}/files/{file_id}?alt=media&supportsAllDrives=true");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            return Err(DriveError::Api {
                status,
                message: text.chars().take(800).collect(),
            });
        }
        let ct = resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let bytes = resp.bytes().await?.to_vec();
        Ok((ct, bytes))
    }

    /// Export a Google Doc/Sheet/Slide to a downloadable format
    /// (e.g. PDF, CSV, XLSX). Returns `(content_type, bytes)`.
    pub async fn export_file(
        &self,
        file_id: &str,
        export_mime: &str,
    ) -> Result<(String, Vec<u8>), DriveError> {
        let url = format!(
            "{BASE}/files/{file_id}/export?mimeType={}",
            urlencoded(export_mime)
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            return Err(DriveError::Api {
                status,
                message: text.chars().take(800).collect(),
            });
        }
        let ct = resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(export_mime)
            .to_string();
        let bytes = resp.bytes().await?.to_vec();
        Ok((ct, bytes))
    }

    pub async fn copy_file(&self, file_id: &str, metadata: &Value) -> Result<Value, DriveError> {
        let q = vec![
            ("fields".to_string(), DEFAULT_FILE_FIELDS.to_string()),
            ("supportsAllDrives".to_string(), "true".to_string()),
        ];
        self.request(
            Method::POST,
            format!("{BASE}/files/{file_id}/copy"),
            Some(metadata),
            &q,
        )
        .await
    }

    /// Move to trash (reversible). Use `delete_permanent` for hard delete.
    pub async fn trash_file(&self, file_id: &str) -> Result<Value, DriveError> {
        let body = json!({"trashed": true});
        self.update_metadata(file_id, &body, None, None).await
    }

    pub async fn delete_permanent(&self, file_id: &str) -> Result<Value, DriveError> {
        let url = format!("{BASE}/files/{file_id}?supportsAllDrives=true");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(json!({"ok": true}));
        }
        let text = resp.text().await?;
        Err(DriveError::Api {
            status,
            message: text.chars().take(800).collect(),
        })
    }

    /// Create a permission entry (sharing). Body is the
    /// [Permission](https://developers.google.com/drive/api/reference/rest/v3/permissions)
    /// resource — at minimum `{"role":"reader","type":"user","emailAddress":"..."}`.
    pub async fn create_permission(
        &self,
        file_id: &str,
        permission: &Value,
        send_notification_email: bool,
        email_message: Option<&str>,
    ) -> Result<Value, DriveError> {
        let mut q: Vec<(String, String)> = vec![
            (
                "sendNotificationEmail".into(),
                send_notification_email.to_string(),
            ),
            ("supportsAllDrives".into(), "true".into()),
        ];
        if let Some(m) = email_message {
            q.push(("emailMessage".into(), m.into()));
        }
        self.request(
            Method::POST,
            format!("{BASE}/files/{file_id}/permissions"),
            Some(permission),
            &q,
        )
        .await
    }

    pub async fn list_permissions(&self, file_id: &str) -> Result<Value, DriveError> {
        let q = vec![
            ("supportsAllDrives".to_string(), "true".to_string()),
            (
                "fields".to_string(),
                "permissions(id,type,role,emailAddress,domain,displayName,deleted)".to_string(),
            ),
        ];
        self.request(
            Method::GET,
            format!("{BASE}/files/{file_id}/permissions"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn delete_permission(
        &self,
        file_id: &str,
        permission_id: &str,
    ) -> Result<Value, DriveError> {
        let url =
            format!("{BASE}/files/{file_id}/permissions/{permission_id}?supportsAllDrives=true");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(json!({"ok": true}));
        }
        let text = resp.text().await?;
        Err(DriveError::Api {
            status,
            message: text.chars().take(800).collect(),
        })
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    async fn request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: String,
        body: Option<&B>,
        query: &[(String, String)],
    ) -> Result<Value, DriveError> {
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
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            if text.is_empty() {
                return Ok(json!({}));
            }
            return serde_json::from_str(&text).map_err(DriveError::Parse);
        }
        Err(DriveError::Api {
            status,
            message: text.chars().take(800).collect(),
        })
    }

    /// Multipart upload per the Drive REST docs:
    /// `Content-Type: multipart/related; boundary=...`
    /// part 1 = metadata (application/json), part 2 = content.
    async fn upload_multipart(
        &self,
        method: Method,
        url: String,
        metadata: &Value,
        content: &[u8],
        content_mime: &str,
    ) -> Result<Value, DriveError> {
        let boundary = format!("googlemcp_{}", uuid::Uuid::new_v4().simple());
        let mut body: Vec<u8> = Vec::with_capacity(content.len() + 1024);
        let metadata_json = serde_json::to_string(metadata).map_err(DriveError::Parse)?;
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
        body.extend_from_slice(metadata_json.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(format!("Content-Type: {content_mime}\r\n\r\n").as_bytes());
        body.extend_from_slice(content);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let resp = self
            .http
            .request(method, &url)
            .bearer_auth(&self.access_token)
            .header(
                http::header::CONTENT_TYPE,
                Cow::<str>::from(format!("multipart/related; boundary={boundary}")).into_owned(),
            )
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            return serde_json::from_str(&text).map_err(DriveError::Parse);
        }
        Err(DriveError::Api {
            status,
            message: text.chars().take(800).collect(),
        })
    }
}

fn urlencoded(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
