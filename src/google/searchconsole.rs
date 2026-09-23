//! Sites, sitemaps and search analytics live on Webmasters v3; URL
//! inspection is on searchconsole.googleapis.com v1.

use http::StatusCode;
use reqwest::Method;
use serde::Serialize;
use serde_json::Value;

use super::http::{
    InvalidPathSegment, MAX_API_RESPONSE_BYTES, ReadBodyError, read_body_capped, seg,
};

#[derive(Debug, thiserror::Error)]
pub enum SearchConsoleError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Search Console returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("could not parse Search Console response: {0}")]
    Parse(serde_json::Error),
    #[error("invalid id: {0}")]
    InvalidId(String),
    #[error("response body exceeds the {cap}-byte cap (at least {actual} bytes)")]
    TooLarge { cap: usize, actual: usize },
}

impl From<InvalidPathSegment> for SearchConsoleError {
    fn from(e: InvalidPathSegment) -> Self {
        SearchConsoleError::InvalidId(e.0)
    }
}

impl From<ReadBodyError> for SearchConsoleError {
    fn from(e: ReadBodyError) -> Self {
        match e {
            ReadBodyError::Http(e) => SearchConsoleError::Http(e),
            ReadBodyError::TooLarge { cap, actual } => SearchConsoleError::TooLarge { cap, actual },
        }
    }
}

const V3: &str = "https://www.googleapis.com/webmasters/v3";
const INSPECT_URL: &str = "https://searchconsole.googleapis.com/v1/urlInspection/index:inspect";

#[derive(Clone)]
pub struct SearchConsoleClient {
    http: reqwest::Client,
    access_token: String,
}

impl SearchConsoleClient {
    pub fn new(http: reqwest::Client, access_token: impl Into<String>) -> Self {
        Self {
            http,
            access_token: access_token.into(),
        }
    }

    pub async fn list_sites(&self) -> Result<Value, SearchConsoleError> {
        self.request(Method::GET, format!("{V3}/sites"), None::<&()>, &[])
            .await
    }

    pub async fn get_site(&self, site_url: &str) -> Result<Value, SearchConsoleError> {
        let site_url = seg(site_url)?;
        self.request(
            Method::GET,
            format!("{V3}/sites/{site_url}"),
            None::<&()>,
            &[],
        )
        .await
    }

    pub async fn list_sitemaps(
        &self,
        site_url: &str,
        sitemap_index: Option<&str>,
    ) -> Result<Value, SearchConsoleError> {
        let site_url = seg(site_url)?;
        let mut q: Vec<(String, String)> = vec![];
        if let Some(i) = sitemap_index {
            q.push(("sitemapIndex".into(), i.into()));
        }
        self.request(
            Method::GET,
            format!("{V3}/sites/{site_url}/sitemaps"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn get_sitemap(
        &self,
        site_url: &str,
        feedpath: &str,
    ) -> Result<Value, SearchConsoleError> {
        let site_url = seg(site_url)?;
        let feedpath = seg(feedpath)?;
        self.request(
            Method::GET,
            format!("{V3}/sites/{site_url}/sitemaps/{feedpath}"),
            None::<&()>,
            &[],
        )
        .await
    }

    pub async fn submit_sitemap(
        &self,
        site_url: &str,
        feedpath: &str,
    ) -> Result<Value, SearchConsoleError> {
        let site_url = seg(site_url)?;
        let feedpath = seg(feedpath)?;
        self.request(
            Method::PUT,
            format!("{V3}/sites/{site_url}/sitemaps/{feedpath}"),
            None::<&()>,
            &[],
        )
        .await
    }

    pub async fn delete_sitemap(
        &self,
        site_url: &str,
        feedpath: &str,
    ) -> Result<Value, SearchConsoleError> {
        let site_url = seg(site_url)?;
        let feedpath = seg(feedpath)?;
        self.request(
            Method::DELETE,
            format!("{V3}/sites/{site_url}/sitemaps/{feedpath}"),
            None::<&()>,
            &[],
        )
        .await
    }

    pub async fn query_search_analytics(
        &self,
        site_url: &str,
        body: &Value,
    ) -> Result<Value, SearchConsoleError> {
        let site_url = seg(site_url)?;
        self.request(
            Method::POST,
            format!("{V3}/sites/{site_url}/searchAnalytics/query"),
            Some(body),
            &[],
        )
        .await
    }

    pub async fn inspect_url(&self, body: &Value) -> Result<Value, SearchConsoleError> {
        self.request(Method::POST, INSPECT_URL.to_string(), Some(body), &[])
            .await
    }

    async fn request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: String,
        body: Option<&B>,
        query: &[(String, String)],
    ) -> Result<Value, SearchConsoleError> {
        let needs_zero_len = body.is_none() && (method == Method::POST || method == Method::PUT);
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
            // Google's frontend rejects body-less POST/PUT without Content-Length:0 (HTTP 411).
            req = req.header(reqwest::header::CONTENT_LENGTH, "0");
        }
        let resp = req.send().await?;
        let status = resp.status();
        let bytes = read_body_capped(resp, MAX_API_RESPONSE_BYTES).await?;
        if status.is_success() {
            if bytes.is_empty() {
                return Ok(serde_json::json!({}));
            }
            return serde_json::from_slice(&bytes).map_err(SearchConsoleError::Parse);
        }
        Err(SearchConsoleError::Api {
            status,
            message: String::from_utf8_lossy(&bytes).chars().take(800).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_site_url_as_one_path_segment() {
        assert!(!seg("sc-domain:example.com").unwrap().contains(':'));
        let encoded = seg("https://example.com/").unwrap();
        assert!(!encoded.contains('/'));
        assert_eq!(encoded, "https%3A%2F%2Fexample.com%2F");
    }
}
