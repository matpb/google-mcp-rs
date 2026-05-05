//! Endpoints implementing the OAuth 2.1 authorization-server side of the
//! MCP server, and the `/.well-known/*` discovery documents.
//!
//! The MCP server proxies to Google for end-user consent: our `/authorize`
//! redirects the user to Google's consent screen, our fixed
//! `/oauth/google/callback` exchanges Google's code for Google tokens,
//! stores the user's encrypted refresh token, and redirects back to the
//! MCP client with our own (single-use) authorization code. The MCP
//! client then redeems that code at `/oauth/token` for an MCP-bound JWT.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::response::Redirect;
use axum::{Form, Json};
use http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain;
use crate::oauth::google::parse_id_token;
use crate::oauth::jwt::{Claims, TOKEN_LIFETIME_SECS, now_secs, sign as sign_jwt};
use crate::oauth::pkce::verify_s256;
use crate::oauth::{GoogleOAuthError, oauth_err};
use crate::state::AppState;
use crate::storage::{accounts, clients, codes};

// ---------------------------------------------------------------------------
// Issuer & well-known
// ---------------------------------------------------------------------------

/// Derive the issuer URL from request headers. Honors `X-Forwarded-Proto`
/// and `X-Forwarded-Host` so deployments behind tunnels/proxies advertise
/// the correct external origin.
pub fn issuer_from_headers(headers: &HeaderMap, fallback_base: &str) -> String {
    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
        })
        .map(str::to_string);
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if host
                .as_deref()
                .is_some_and(|h| h.starts_with("localhost") || h.starts_with("127.0.0.1"))
            {
                "http".into()
            } else {
                "https".into()
            }
        });
    match host {
        Some(h) => format!("{scheme}://{h}"),
        None => fallback_base.to_string(),
    }
}

#[derive(Serialize)]
pub struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    bearer_methods_supported: Vec<String>,
    scopes_supported: Vec<String>,
}

#[derive(Serialize)]
pub struct AuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    scopes_supported: Vec<String>,
}

pub async fn protected_resource_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<ProtectedResourceMetadata> {
    let iss = issuer_from_headers(&headers, &state.config.base_url);
    Json(ProtectedResourceMetadata {
        resource: format!("{iss}/mcp"),
        authorization_servers: vec![iss],
        bearer_methods_supported: vec!["header".to_string()],
        scopes_supported: domain::google_scopes(&state.config.enabled_domains),
    })
}

pub async fn authorization_server_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<AuthServerMetadata> {
    let iss = issuer_from_headers(&headers, &state.config.base_url);
    Json(AuthServerMetadata {
        authorization_endpoint: format!("{iss}/authorize"),
        token_endpoint: format!("{iss}/oauth/token"),
        registration_endpoint: format!("{iss}/oauth/register"),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post".to_string(),
            "none".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
        scopes_supported: domain::google_scopes(&state.config.enabled_domains),
        issuer: iss,
    })
}

// ---------------------------------------------------------------------------
// Dynamic client registration (RFC 7591)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
// All fields are accepted per RFC 7591; we only act on a subset and echo
// back sensible defaults for the rest. The unread fields exist for future
// metadata expansion and to avoid client-side rejection of "unknown" keys.
#[allow(dead_code)]
pub struct RegisterRequest {
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub client_id: String,
    pub client_secret: String,
    pub client_id_issued_at: i64,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), (StatusCode, Json<crate::oauth::OauthErrorBody>)>
{
    if req.redirect_uris.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_redirect_uri",
                Some("redirect_uris must not be empty".to_string()),
            )),
        ));
    }
    for uri in &req.redirect_uris {
        if !is_valid_redirect_uri(uri) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(oauth_err(
                    "invalid_redirect_uri",
                    Some(format!("invalid redirect_uri: {uri}")),
                )),
            ));
        }
    }
    let client_id = format!("mcp_{}", Uuid::new_v4().simple());
    let client_secret = Uuid::new_v4().simple().to_string();
    clients::create(
        &state.db,
        clients::CreateClient {
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            redirect_uris: req.redirect_uris.clone(),
            client_name: req.client_name.clone(),
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(err = ?e, "DCR insert failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(oauth_err(
                "server_error",
                Some("could not register client".into()),
            )),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            client_id,
            client_secret,
            client_id_issued_at: now_secs() as i64,
            redirect_uris: req.redirect_uris,
            client_name: req.client_name,
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: req
                .token_endpoint_auth_method
                .unwrap_or_else(|| "client_secret_post".to_string()),
        }),
    ))
}

fn is_valid_redirect_uri(uri: &str) -> bool {
    if uri.starts_with("https://") {
        return true;
    }
    // Allow loopback for local development per RFC 8252.
    if let Some(rest) = uri.strip_prefix("http://") {
        // Strip path first; remaining authority is "host" or "host:port"
        // or "[ipv6]" or "[ipv6]:port".
        let authority = rest.split('/').next().unwrap_or("");
        let host = if let Some(stripped) = authority.strip_prefix('[') {
            // Bracketed IPv6: take everything up to the closing bracket.
            match stripped.find(']') {
                Some(idx) => &stripped[..idx],
                None => return false,
            }
        } else {
            // Strip optional :port from a non-IPv6 authority.
            authority.split(':').next().unwrap_or("")
        };
        return host == "localhost" || host == "127.0.0.1" || host == "::1";
    }
    false
}

// ---------------------------------------------------------------------------
// /authorize
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
// `scope` is intentionally accepted but ignored: the consent screen below
// uses our server-fixed scope set, not the client's request, so callers
// can't escalate scope by asking.
#[allow(dead_code)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub login_hint: Option<String>,
}

pub async fn authorize(
    State(state): State<AppState>,
    Query(q): Query<AuthorizeQuery>,
) -> Result<Redirect, (StatusCode, Json<crate::oauth::OauthErrorBody>)> {
    if q.response_type != "code" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "unsupported_response_type",
                Some("only response_type=code is supported".into()),
            )),
        ));
    }
    if q.code_challenge_method != "S256" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_request",
                Some("code_challenge_method must be S256".into()),
            )),
        ));
    }
    let client = clients::get(&state.db, &q.client_id)
        .await
        .map_err(|e| {
            tracing::error!(err = ?e, "client lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(oauth_err("server_error", None)),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(oauth_err(
                    "invalid_client",
                    Some("unknown client_id".into()),
                )),
            )
        })?;

    let registered: HashSet<&String> = client.redirect_uris.iter().collect();
    if !registered.contains(&q.redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_redirect_uri",
                Some("redirect_uri not registered for this client".into()),
            )),
        ));
    }

    let state_id = Uuid::new_v4().simple().to_string();
    codes::insert_state(
        &state.db,
        codes::InsertState {
            state_id: state_id.clone(),
            mcp_client_id: q.client_id,
            mcp_redirect_uri: q.redirect_uri,
            mcp_state: q.state,
            code_challenge: q.code_challenge,
            code_challenge_method: q.code_challenge_method,
            resource: q.resource,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(err = ?e, "insert oauth_state failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(oauth_err("server_error", None)),
        )
    })?;

    let google_url = state
        .google_oauth
        .build_authorize_url(&state_id, q.login_hint.as_deref());
    Ok(Redirect::to(&google_url))
}

// ---------------------------------------------------------------------------
// /oauth/google/callback
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct GoogleCallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

pub async fn google_callback(
    State(state): State<AppState>,
    Query(q): Query<GoogleCallbackQuery>,
) -> Result<Redirect, (StatusCode, String)> {
    if let Some(err) = q.error {
        let desc = q.error_description.unwrap_or_default();
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Google denied authorization: {err} {desc}"),
        ));
    }
    let Some(code) = q.code else {
        return Err((StatusCode::BAD_REQUEST, "missing code".into()));
    };
    let Some(state_id) = q.state else {
        return Err((StatusCode::BAD_REQUEST, "missing state".into()));
    };

    let proxy_state = codes::consume_state(&state.db, &state_id)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::BAD_REQUEST, "state expired or unknown".into()))?;

    let grant = state.google_oauth.exchange_code(&code).await.map_err(|e| {
        tracing::error!(err = ?e, "Google code exchange failed");
        (
            StatusCode::BAD_GATEWAY,
            format!("Google token exchange failed: {e}"),
        )
    })?;

    let id_token = grant.id_token.as_deref().ok_or((
        StatusCode::BAD_GATEWAY,
        "Google did not return an id_token; ensure 'openid' scope was requested".into(),
    ))?;
    let id = parse_id_token(id_token).map_err(|e| {
        tracing::error!(err = ?e, "id_token parse failed");
        (StatusCode::BAD_GATEWAY, format!("id_token parse: {e}"))
    })?;

    let refresh_token = grant.refresh_token.as_deref().ok_or((
        StatusCode::BAD_GATEWAY,
        "Google did not return a refresh_token; ensure prompt=consent + access_type=offline".into(),
    ))?;

    let scopes: Vec<String> = grant
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_else(|| domain::google_scopes(&state.config.enabled_domains));
    let email = id.email.clone().unwrap_or_default();

    accounts::upsert(
        &state.db,
        &state.config.storage_encryption_key,
        accounts::UpsertAccount {
            google_sub: id.sub.clone(),
            email: email.clone(),
            refresh_token: refresh_token.to_string(),
            scopes: scopes.clone(),
        },
    )
    .await
    .map_err(internal)?;

    state
        .session_cache
        .store_initial(
            &id.sub,
            &email,
            &grant.access_token,
            grant.expires_in,
            scopes,
        )
        .await;

    let mcp_code = format!("mcpc_{}", Uuid::new_v4().simple());
    codes::insert_code(
        &state.db,
        codes::InsertCode {
            code: mcp_code.clone(),
            mcp_client_id: proxy_state.mcp_client_id.clone(),
            mcp_redirect_uri: proxy_state.mcp_redirect_uri.clone(),
            code_challenge: proxy_state.code_challenge,
            google_sub: id.sub,
            resource: proxy_state.resource,
        },
    )
    .await
    .map_err(internal)?;

    let mut url = url::Url::parse(&proxy_state.mcp_redirect_uri).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid registered redirect_uri: {e}"),
        )
    })?;
    url.query_pairs_mut().append_pair("code", &mcp_code);
    if let Some(s) = proxy_state.mcp_state.as_deref() {
        url.query_pairs_mut().append_pair("state", s);
    }
    Ok(Redirect::to(url.as_str()))
}

fn internal<E: std::fmt::Debug>(e: E) -> (StatusCode, String) {
    tracing::error!(err = ?e, "internal error in OAuth proxy");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}

// ---------------------------------------------------------------------------
// /oauth/token
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenForm>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<crate::oauth::OauthErrorBody>)> {
    if req.grant_type != "authorization_code" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "unsupported_grant_type",
                Some("only authorization_code is supported".into()),
            )),
        ));
    }
    let code = req.code.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(oauth_err("invalid_request", Some("missing code".into()))),
        )
    })?;
    let code_verifier = req.code_verifier.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_request",
                Some("missing code_verifier (PKCE required)".into()),
            )),
        )
    })?;

    let stored = codes::consume_code(&state.db, &code)
        .await
        .map_err(|e| {
            tracing::error!(err = ?e, "consume_code failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(oauth_err("server_error", None)),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(oauth_err(
                    "invalid_grant",
                    Some("code expired or already used".into()),
                )),
            )
        })?;

    if let Some(client_id) = req.client_id.as_deref()
        && client_id != stored.mcp_client_id
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_client",
                Some("client_id does not match code".into()),
            )),
        ));
    }

    let client = clients::get(&state.db, &stored.mcp_client_id)
        .await
        .map_err(|e| {
            tracing::error!(err = ?e, "client lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(oauth_err("server_error", None)),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(oauth_err("invalid_client", Some("client not found".into()))),
            )
        })?;

    if let Some(secret) = req.client_secret.as_deref()
        && !clients::verify_secret(secret, &client.client_secret_hash)
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(oauth_err(
                "invalid_client",
                Some("invalid client_secret".into()),
            )),
        ));
    }

    if let Some(supplied_redirect) = req.redirect_uri.as_deref()
        && supplied_redirect != stored.mcp_redirect_uri
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_grant",
                Some("redirect_uri does not match authorization request".into()),
            )),
        ));
    }

    if !verify_s256(&code_verifier, &stored.code_challenge) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_grant",
                Some("PKCE verification failed".into()),
            )),
        ));
    }

    let iss = issuer_from_headers(&headers, &state.config.base_url);
    let aud = req
        .resource
        .or(stored.resource)
        .unwrap_or_else(|| format!("{iss}/mcp"));
    let now = now_secs();
    let claims = Claims {
        iss: iss.clone(),
        sub: stored.google_sub,
        iat: now,
        exp: now + TOKEN_LIFETIME_SECS,
        aud: Some(aud),
    };
    let jwt = sign_jwt(&state.config.jwt_secret, &claims).map_err(|e| {
        tracing::error!(err = ?e, "JWT sign failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(oauth_err("server_error", None)),
        )
    })?;
    Ok(Json(TokenResponse {
        access_token: jwt,
        token_type: "Bearer",
        expires_in: TOKEN_LIFETIME_SECS,
        scope: None,
    }))
}

// Convert SessionError → ErrorData / HTTP response variants. Currently used
// by integration code; kept here for reuse.
#[allow(dead_code)]
pub fn session_error_to_status(e: &crate::google::session::SessionError) -> StatusCode {
    use crate::google::session::SessionError::*;
    match e {
        AccountNotFound | ReconnectRequired => StatusCode::UNAUTHORIZED,
        Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
        Google(GoogleOAuthError::InvalidGrant) => StatusCode::UNAUTHORIZED,
        Google(_) => StatusCode::BAD_GATEWAY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(host: &str, proto: Option<&str>) -> HeaderMap {
        let mut hm = HeaderMap::new();
        hm.insert(http::header::HOST, host.parse().unwrap());
        if let Some(p) = proto {
            hm.insert("x-forwarded-proto", p.parse().unwrap());
        }
        hm
    }

    #[test]
    fn issuer_from_headers_localhost_defaults_to_http() {
        assert_eq!(
            issuer_from_headers(&h("localhost:8433", None), "http://fallback"),
            "http://localhost:8433"
        );
    }

    #[test]
    fn issuer_from_headers_remote_defaults_to_https() {
        assert_eq!(
            issuer_from_headers(&h("google-mcp.example.com", None), "http://fallback"),
            "https://google-mcp.example.com"
        );
    }

    #[test]
    fn issuer_from_headers_honors_forwarded_proto() {
        assert_eq!(
            issuer_from_headers(&h("google-mcp.example.com", Some("http")), "http://fb"),
            "http://google-mcp.example.com"
        );
    }

    #[test]
    fn redirect_uri_validation() {
        assert!(is_valid_redirect_uri("https://claude.ai/api/cb"));
        assert!(is_valid_redirect_uri("http://localhost:3000/cb"));
        assert!(is_valid_redirect_uri("http://127.0.0.1:5173/auth"));
        assert!(is_valid_redirect_uri("http://[::1]/x"));
        assert!(!is_valid_redirect_uri("http://example.com/cb"));
        assert!(!is_valid_redirect_uri("ftp://x"));
        assert!(!is_valid_redirect_uri("javascript:alert(1)"));
    }
}
