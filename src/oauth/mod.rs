//! OAuth 2.1 — server-side proxy that wraps Google for upstream auth and
//! issues MCP-bound JWTs to MCP clients.

pub mod consent;
pub mod google;
pub mod jwt;
pub mod pkce;
pub mod proxy;

use reqwest::StatusCode as ReqwestStatus;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("failed to sign JWT")]
    Sign,
    #[error("malformed token")]
    Malformed,
    #[error("invalid signature")]
    BadSignature,
    #[error("token expired")]
    Expired,
    #[error("audience mismatch")]
    AudienceMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum GoogleOAuthError {
    #[error("http: {0}")]
    Http(reqwest::Error),
    #[error("token endpoint returned {status}: {error} ({description:?})")]
    TokenEndpoint {
        status: ReqwestStatus,
        error: String,
        description: Option<String>,
    },
    #[error("refresh token revoked or invalid (Google: invalid_grant)")]
    InvalidGrant,
    #[error("unexpected response {status}: {body}")]
    Unexpected { status: ReqwestStatus, body: String },
    #[error("could not parse Google response: {source}\nbody: {body}")]
    ParseResponse {
        #[source]
        source: serde_json::Error,
        body: String,
    },
    #[error("id token parse: {0}")]
    IdToken(String),
    #[error("response body exceeds the {cap}-byte cap (at least {actual} bytes)")]
    TooLarge { cap: usize, actual: usize },
}

impl From<crate::google::http::ReadBodyError> for GoogleOAuthError {
    fn from(e: crate::google::http::ReadBodyError) -> Self {
        match e {
            crate::google::http::ReadBodyError::Http(e) => GoogleOAuthError::Http(e),
            crate::google::http::ReadBodyError::TooLarge { cap, actual } => {
                GoogleOAuthError::TooLarge { cap, actual }
            }
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct OauthErrorBody {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

pub fn oauth_err(error: &str, description: impl Into<Option<String>>) -> OauthErrorBody {
    OauthErrorBody {
        error: error.to_string(),
        error_description: description.into(),
    }
}
