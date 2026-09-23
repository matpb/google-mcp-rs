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
use crate::google::http::{MAX_API_RESPONSE_BYTES, read_body_capped};

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
const ID_TOKEN_EXP_LEEWAY_SECS: i64 = 60;

pub struct GoogleOAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    http: reqwest::Client,
}

/// Google's token-endpoint response shape; `token_type` is always `"Bearer"` and unused.
#[derive(Debug, Deserialize)]
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
    #[allow(dead_code)]
    pub token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdTokenPayload {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub hd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    #[serde(default)]
    aud: Option<AudValue>,
    exp: i64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudValue {
    One(String),
    Many(Vec<String>),
}

impl AudValue {
    fn contains(&self, v: &str) -> bool {
        match self {
            AudValue::One(s) => s == v,
            AudValue::Many(vs) => vs.iter().any(|x| x == v),
        }
    }
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
        let bytes = read_body_capped(resp, MAX_API_RESPONSE_BYTES).await?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
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

/// Parses without verifying the JWT signature (TLS to Google's token
/// endpoint covers authenticity); does check `iss`, `aud` and `exp`.
pub fn parse_id_token(
    id_token: &str,
    expected_aud: &str,
) -> Result<IdTokenPayload, GoogleOAuthError> {
    let parts: Vec<&str> = id_token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(GoogleOAuthError::IdToken("malformed JWT".into()));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1].trim_end_matches('='))
        .map_err(|e| GoogleOAuthError::IdToken(format!("base64: {e}")))?;

    let claims: IdTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| GoogleOAuthError::IdToken(format!("json: {e}")))?;
    if claims.iss != "accounts.google.com" && claims.iss != "https://accounts.google.com" {
        return Err(GoogleOAuthError::IdToken(format!(
            "unexpected iss: {}",
            claims.iss
        )));
    }
    if !claims
        .aud
        .as_ref()
        .is_some_and(|a| a.contains(expected_aud))
    {
        return Err(GoogleOAuthError::IdToken("aud does not match".into()));
    }
    let now = super::jwt::now_secs() as i64;
    if claims.exp + ID_TOKEN_EXP_LEEWAY_SECS < now {
        return Err(GoogleOAuthError::IdToken("id_token expired".into()));
    }

    serde_json::from_slice::<IdTokenPayload>(&payload_bytes)
        .map_err(|e| GoogleOAuthError::IdToken(format!("json: {e}")))
}

/// Best-effort RFC 7009 revoke; failures are for the caller to log only.
pub async fn revoke_token(http: &reqwest::Client, token: &str) -> Result<(), GoogleOAuthError> {
    let resp = http
        .post(GOOGLE_REVOKE_URL)
        .form(&[("token", token)])
        .send()
        .await
        .map_err(GoogleOAuthError::Http)?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(GoogleOAuthError::Unexpected {
            status: resp.status(),
            body: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn fake_id_token_full(sub: &str, email: &str, iss: &str, aud: &str, exp: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "sub": sub,
                "email": email,
                "email_verified": true,
                "iss": iss,
                "aud": aud,
                "exp": exp,
            }))
            .unwrap(),
        );
        let signature = URL_SAFE_NO_PAD.encode(b"fake-sig");
        format!("{header}.{payload}.{signature}")
    }

    fn fake_id_token(sub: &str, email: &str) -> String {
        let now = super::super::jwt::now_secs() as i64;
        fake_id_token_full(sub, email, "https://accounts.google.com", "cid", now + 3600)
    }

    #[test]
    fn parses_id_token() {
        let token = fake_id_token("123abc", "user@example.com");
        let p = parse_id_token(&token, "cid").unwrap();
        assert_eq!(p.sub, "123abc");
        assert_eq!(p.email.as_deref(), Some("user@example.com"));
        assert_eq!(p.email_verified, Some(true));
    }

    #[test]
    fn rejects_malformed_jwt() {
        assert!(
            parse_id_token("not.a.jwt.too-many.parts", "cid").is_err()
                || parse_id_token("just-one-part", "cid").is_err()
        );
        assert!(parse_id_token("only.two", "cid").is_err());
    }

    #[test]
    fn accepts_iss_without_scheme() {
        let now = super::super::jwt::now_secs() as i64;
        let token = fake_id_token_full("s", "e@x.com", "accounts.google.com", "cid", now + 60);
        assert!(parse_id_token(&token, "cid").is_ok());
    }

    #[test]
    fn rejects_wrong_iss() {
        let now = super::super::jwt::now_secs() as i64;
        let token = fake_id_token_full("s", "e@x.com", "evil.example", "cid", now + 60);
        assert!(parse_id_token(&token, "cid").is_err());
    }

    #[test]
    fn rejects_wrong_aud() {
        let token = fake_id_token("s", "e@x.com");
        assert!(parse_id_token(&token, "other-client-id").is_err());
    }

    #[test]
    fn accepts_aud_as_array() {
        let now = super::super::jwt::now_secs() as i64;
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "sub": "s",
                "email": "e@x.com",
                "iss": "https://accounts.google.com",
                "aud": ["other", "cid"],
                "exp": now + 60,
            }))
            .unwrap(),
        );
        let token = format!("{header}.{payload}.sig");
        assert!(parse_id_token(&token, "cid").is_ok());
    }

    #[test]
    fn rejects_expired_id_token() {
        let now = super::super::jwt::now_secs() as i64;
        let token = fake_id_token_full("s", "e@x.com", "accounts.google.com", "cid", now - 1000);
        assert!(parse_id_token(&token, "cid").is_err());
    }

    #[test]
    fn build_url_includes_required_params() {
        let scopes = crate::domain::google_scopes(&crate::domain::Domain::ALL);
        let client = GoogleOAuthClient::new(
            "cid",
            "csecret",
            "http://localhost:8433/oauth/google/callback",
            scopes,
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
        assert!(url.contains("gmail.settings.basic"));
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
