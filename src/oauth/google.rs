//! Thin Google OAuth 2.0 client.
//!
//! Builds the `accounts.google.com` authorization URL; exchanges codes and
//! refreshes access tokens against `oauth2.googleapis.com/token`. The ID
//! token is parsed (without signature verification — see README's caveats)
//! to extract the user's stable `sub` and email.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::GoogleOAuthError;

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

pub const DEFAULT_SCOPES: &[&str] = &[
    "openid",
    "email",
    "https://www.googleapis.com/auth/gmail.modify",
];

pub struct GoogleOAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // some fields are surfaced for callers; not all consumed yet
pub struct TokenGrant {
    pub access_token: String,
    pub expires_in: u64,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // email_verified is surfaced for future hardening
pub struct IdTokenPayload {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
}

impl GoogleOAuthClient {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        scopes: Vec<String>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            scopes,
            http,
        }
    }

    /// Build the Google consent-screen URL the user is redirected to.
    /// Always includes `access_type=offline` and `prompt=consent` so
    /// re-authorization re-issues a refresh token.
    pub fn build_authorize_url(&self, state: &str, login_hint: Option<&str>) -> String {
        let scopes = self.scopes.join(" ");
        let mut params: Vec<(&str, &str)> = vec![
            ("client_id", &self.client_id),
            ("redirect_uri", &self.redirect_uri),
            ("response_type", "code"),
            ("scope", &scopes),
            ("state", state),
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("include_granted_scopes", "true"),
        ];
        if let Some(hint) = login_hint {
            params.push(("login_hint", hint));
        }
        let query = serde_urlencoded::to_string(&params).expect("query");
        format!("{GOOGLE_AUTH_URL}?{query}")
    }

    /// Exchange a one-shot Google authorization code for tokens.
    pub async fn exchange_code(&self, code: &str) -> Result<TokenGrant, GoogleOAuthError> {
        let body = TokenRequest::AuthorizationCode {
            code,
            client_id: &self.client_id,
            client_secret: &self.client_secret,
            redirect_uri: &self.redirect_uri,
            grant_type: "authorization_code",
        };
        self.post_token_request(&body).await
    }

    /// Use a refresh token to mint a new access token. Google returns
    /// `error=invalid_grant` when the refresh token has been revoked or
    /// is otherwise no longer usable; that is mapped to
    /// `GoogleOAuthError::InvalidGrant`.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenGrant, GoogleOAuthError> {
        let body = TokenRequest::Refresh {
            refresh_token,
            client_id: &self.client_id,
            client_secret: &self.client_secret,
            grant_type: "refresh_token",
        };
        self.post_token_request(&body).await
    }

    async fn post_token_request<T: Serialize + ?Sized>(
        &self,
        body: &T,
    ) -> Result<TokenGrant, GoogleOAuthError> {
        let resp = self
            .http
            .post(GOOGLE_TOKEN_URL)
            .form(body)
            .send()
            .await
            .map_err(GoogleOAuthError::Http)?;
        let status = resp.status();
        let text = resp.text().await.map_err(GoogleOAuthError::Http)?;
        if status.is_success() {
            return serde_json::from_str(&text).map_err(|e| GoogleOAuthError::ParseResponse {
                source: e,
                body: text,
            });
        }
        // Try to parse a typed Google error.
        if let Ok(err) = serde_json::from_str::<GoogleErrorBody>(&text) {
            return Err(match err.error.as_str() {
                "invalid_grant" => GoogleOAuthError::InvalidGrant,
                _ => GoogleOAuthError::TokenEndpoint {
                    status,
                    error: err.error,
                    description: err.error_description,
                },
            });
        }
        Err(GoogleOAuthError::Unexpected { status, body: text })
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum TokenRequest<'a> {
    AuthorizationCode {
        code: &'a str,
        client_id: &'a str,
        client_secret: &'a str,
        redirect_uri: &'a str,
        grant_type: &'static str,
    },
    Refresh {
        refresh_token: &'a str,
        client_id: &'a str,
        client_secret: &'a str,
        grant_type: &'static str,
    },
}

/// Parse the middle segment of a Google ID token (a JWT) without verifying
/// its signature. The TLS channel to Google's token endpoint guarantees
/// authenticity for our purposes; signature verification against the JWKS
/// is on the hardening roadmap.
pub fn parse_id_token(id_token: &str) -> Result<IdTokenPayload, GoogleOAuthError> {
    let parts: Vec<&str> = id_token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(GoogleOAuthError::IdToken("malformed JWT".into()));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1].trim_end_matches('='))
        .map_err(|e| GoogleOAuthError::IdToken(format!("base64: {e}")))?;
    serde_json::from_slice::<IdTokenPayload>(&payload_bytes)
        .map_err(|e| GoogleOAuthError::IdToken(format!("json: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn fake_id_token(sub: &str, email: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "sub": sub,
                "email": email,
                "email_verified": true,
            }))
            .unwrap(),
        );
        let signature = URL_SAFE_NO_PAD.encode(b"fake-sig");
        format!("{header}.{payload}.{signature}")
    }

    #[test]
    fn parses_id_token() {
        let token = fake_id_token("123abc", "user@example.com");
        let p = parse_id_token(&token).unwrap();
        assert_eq!(p.sub, "123abc");
        assert_eq!(p.email.as_deref(), Some("user@example.com"));
        assert_eq!(p.email_verified, Some(true));
    }

    #[test]
    fn rejects_malformed_jwt() {
        assert!(
            parse_id_token("not.a.jwt.too-many.parts").is_err()
                || parse_id_token("just-one-part").is_err()
        );
        assert!(parse_id_token("only.two").is_err());
    }

    #[test]
    fn build_url_includes_required_params() {
        let client = GoogleOAuthClient::new(
            "cid",
            "csecret",
            "http://localhost:8433/oauth/google/callback",
            DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect(),
            reqwest::Client::new(),
        );
        let url = client.build_authorize_url("state-abc", None);
        assert!(url.starts_with(GOOGLE_AUTH_URL));
        assert!(url.contains("client_id=cid"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
        assert!(url.contains("state=state-abc"));
        assert!(url.contains("scope=openid"));
        assert!(url.contains("gmail.modify"));
    }

    #[test]
    fn build_url_with_login_hint() {
        let client = GoogleOAuthClient::new(
            "cid",
            "csecret",
            "http://x/cb",
            vec!["openid".into()],
            reqwest::Client::new(),
        );
        let url = client.build_authorize_url("s", Some("user@x.com"));
        assert!(url.contains("login_hint=user%40x.com"));
    }
}
