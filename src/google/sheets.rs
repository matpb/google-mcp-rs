//! Google Sheets v4 client. Same shape as `gmail`: a thin reqwest wrapper
//! that authenticates with the user's current access token and forwards
//! Google's JSON to callers as `serde_json::Value`.

use http::StatusCode;
use reqwest::Method;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum SheetsError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Sheets returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("could not parse Sheets response: {0}")]
    Parse(serde_json::Error),
}

const BASE: &str = "https://sheets.googleapis.com/v4/spreadsheets";

#[derive(Clone)]
pub struct SheetsClient {
    http: reqwest::Client,
    access_token: String,
}

impl SheetsClient {
    pub fn new(http: reqwest::Client, access_token: impl Into<String>) -> Self {
        Self {
            http,
            access_token: access_token.into(),
        }
    }

    /// Create a new spreadsheet. Body is the full
    /// [Spreadsheet](https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets)
    /// resource — at minimum `{"properties":{"title":"..."}}`.
    pub async fn create(&self, body: &Value) -> Result<Value, SheetsError> {
        self.request(Method::POST, BASE.to_string(), Some(body), &[])
            .await
    }

    pub async fn get(
        &self,
        spreadsheet_id: &str,
        ranges: &[String],
        include_grid_data: bool,
        fields: Option<&str>,
    ) -> Result<Value, SheetsError> {
        let mut q: Vec<(String, String)> = vec![];
        for r in ranges {
            q.push(("ranges".into(), r.clone()));
        }
        if include_grid_data {
            q.push(("includeGridData".into(), "true".into()));
        }
        if let Some(f) = fields {
            q.push(("fields".into(), f.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/{spreadsheet_id}"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn get_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
        major_dimension: Option<&str>,
        value_render_option: Option<&str>,
        date_time_render_option: Option<&str>,
    ) -> Result<Value, SheetsError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(d) = major_dimension {
            q.push(("majorDimension".into(), d.into()));
        }
        if let Some(v) = value_render_option {
            q.push(("valueRenderOption".into(), v.into()));
        }
        if let Some(d) = date_time_render_option {
            q.push(("dateTimeRenderOption".into(), d.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/{spreadsheet_id}/values/{range}"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn batch_get_values(
        &self,
        spreadsheet_id: &str,
        ranges: &[String],
        major_dimension: Option<&str>,
        value_render_option: Option<&str>,
    ) -> Result<Value, SheetsError> {
        let mut q: Vec<(String, String)> = vec![];
        for r in ranges {
            q.push(("ranges".into(), r.clone()));
        }
        if let Some(d) = major_dimension {
            q.push(("majorDimension".into(), d.into()));
        }
        if let Some(v) = value_render_option {
            q.push(("valueRenderOption".into(), v.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/{spreadsheet_id}/values:batchGet"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn update_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
        values: &Value,
        value_input_option: &str,
        major_dimension: Option<&str>,
    ) -> Result<Value, SheetsError> {
        let mut q: Vec<(String, String)> =
            vec![("valueInputOption".into(), value_input_option.into())];
        if let Some(d) = major_dimension {
            q.push(("majorDimension".into(), d.into()));
        }
        let body = serde_json::json!({"values": values});
        self.request(
            Method::PUT,
            format!("{BASE}/{spreadsheet_id}/values/{range}"),
            Some(&body),
            &q,
        )
        .await
    }

    pub async fn append_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
        values: &Value,
        value_input_option: &str,
        insert_data_option: Option<&str>,
    ) -> Result<Value, SheetsError> {
        let mut q: Vec<(String, String)> =
            vec![("valueInputOption".into(), value_input_option.into())];
        if let Some(i) = insert_data_option {
            q.push(("insertDataOption".into(), i.into()));
        }
        let body = serde_json::json!({"values": values});
        self.request(
            Method::POST,
            format!("{BASE}/{spreadsheet_id}/values/{range}:append"),
            Some(&body),
            &q,
        )
        .await
    }

    pub async fn clear_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
    ) -> Result<Value, SheetsError> {
        let body = serde_json::json!({});
        self.request(
            Method::POST,
            format!("{BASE}/{spreadsheet_id}/values/{range}:clear"),
            Some(&body),
            &[],
        )
        .await
    }

    pub async fn batch_update_values(
        &self,
        spreadsheet_id: &str,
        body: &Value,
    ) -> Result<Value, SheetsError> {
        self.request(
            Method::POST,
            format!("{BASE}/{spreadsheet_id}/values:batchUpdate"),
            Some(body),
            &[],
        )
        .await
    }

    /// Schema-level batch update (add/delete sheets, formatting, conditional
    /// formatting, charts, etc.). Body shape:
    /// `{"requests":[{"addSheet":{...}},{"updateCells":{...}},...],"includeSpreadsheetInResponse":bool}`.
    /// See https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets/request
    pub async fn batch_update(
        &self,
        spreadsheet_id: &str,
        body: &Value,
    ) -> Result<Value, SheetsError> {
        self.request(
            Method::POST,
            format!("{BASE}/{spreadsheet_id}:batchUpdate"),
            Some(body),
            &[],
        )
        .await
    }

    async fn request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: String,
        body: Option<&B>,
        query: &[(String, String)],
    ) -> Result<Value, SheetsError> {
        let needs_zero_len = body.is_none() && method == Method::POST;
        let mut req = self
            .http
            .request(method, &url)
            .bearer_auth(&self.access_token);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(b) = body {
            req = req.json(b);
        } else if needs_zero_len {
            // Google's frontend rejects body-less POSTs without Content-Length:0 (HTTP 411).
            req = req.header(reqwest::header::CONTENT_LENGTH, "0");
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            if text.is_empty() {
                return Ok(serde_json::json!({}));
            }
            return serde_json::from_str(&text).map_err(SheetsError::Parse);
        }
        Err(SheetsError::Api {
            status,
            message: text.chars().take(800).collect(),
        })
    }
}
