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
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain;
use crate::host_guard::{self, AllowedHost};
use crate::oauth::consent;
use crate::oauth::google::parse_id_token;
use crate::oauth::jwt::{Claims, TOKEN_LIFETIME_SECS, now_secs, sign as sign_jwt};
use crate::oauth::oauth_err;
use crate::oauth::pkce::{constant_time_eq, verify_s256};
use crate::state::AppState;
use crate::storage::{accounts, clients, codes};

/// Sign a browser-binding cookie name so /authorize and /oauth/google/callback
/// (and /authorize/consent) agree on it.
fn binding_cookie_name(state_id: &str) -> String {
    format!("gmcp_c_{state_id}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn is_https(url: &str) -> bool {
    url.starts_with("https://")
}

fn origin_of(url_str: &str) -> Option<String> {
    let u = url::Url::parse(url_str).ok()?;
    let host = u.host_str()?;
    Some(match u.port() {
        Some(p) => format!("{}://{host}:{p}", u.scheme()),
        None => format!("{}://{host}", u.scheme()),
    })
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

fn set_binding_cookie(resp: &mut Response, state_id: &str, secret: &str, secure: bool) {
    let secure_attr = if secure { "; Secure" } else { "" };
    let value = format!(
        "{}={secret}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600{secure_attr}",
        binding_cookie_name(state_id)
    );
    if let Ok(v) = HeaderValue::from_str(&value) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
}

fn clear_binding_cookie(resp: &mut Response, state_id: &str, secure: bool) {
    let secure_attr = if secure { "; Secure" } else { "" };
    let value = format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure_attr}",
        binding_cookie_name(state_id)
    );
    if let Ok(v) = HeaderValue::from_str(&value) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
}

// ---------------------------------------------------------------------------
// Issuer & well-known
// ---------------------------------------------------------------------------

/// Derive the issuer from request headers: first `X-Forwarded-Host` element,
/// else `Host`; `X-Forwarded-Proto` only when exactly `http` or `https`.
pub fn issuer_from_headers(headers: &HeaderMap, fallback_base: &str) -> String {
    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .or_else(|| {
            headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
        })
        .map(str::to_string);
    let forwarded_proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|p| *p == "http" || *p == "https");
    let scheme = forwarded_proto.map_or_else(
        || {
            if host
                .as_deref()
                .is_some_and(|h| h.starts_with("localhost") || h.starts_with("127.0.0.1"))
            {
                "http".into()
            } else {
                "https".into()
            }
        },
        str::to_string,
    );
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

// RFC 7591 accepts all these fields; unread ones just echo back defaults.
#[derive(Deserialize)]
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
    if req.redirect_uris.len() > MAX_REDIRECT_URIS
        || req.redirect_uris.iter().any(|u| u.len() > MAX_URI_BYTES)
        || req
            .client_name
            .as_deref()
            .is_some_and(|n| n.chars().count() > MAX_CLIENT_NAME_CHARS)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_client_metadata",
                Some(format!(
                    "at most {MAX_REDIRECT_URIS} redirect_uris (each <= {MAX_URI_BYTES} bytes), client_name <= {MAX_CLIENT_NAME_CHARS} chars"
                )),
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
    let client_count = clients::count(&state.db).await.map_err(|e| {
        tracing::error!(err = ?e, "client count failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(oauth_err("server_error", None)),
        )
    })?;
    if client_count >= clients::MAX_MCP_CLIENTS {
        tracing::warn!(
            count = client_count,
            "refusing DCR: mcp_clients at capacity"
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(oauth_err("temporarily_unavailable", None)),
        ));
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

// RFC 8252 section 7.1 endorses private-use URI schemes for native apps.
const NATIVE_CLIENT_REDIRECT_PREFIXES: &[&str] = &["cursor://anysphere.cursor-mcp/"];

const MAX_REDIRECT_URIS: usize = 10;
const MAX_URI_BYTES: usize = 2048;
const MAX_CLIENT_NAME_CHARS: usize = 200;

/// Parses with `url::Url` so userinfo/fragment tricks (`user:pass@evil`,
/// `#frag`) can't slip past string splitting.
fn is_valid_redirect_uri(uri: &str) -> bool {
    if NATIVE_CLIENT_REDIRECT_PREFIXES
        .iter()
        .any(|prefix| uri.starts_with(prefix))
    {
        let Ok(parsed) = url::Url::parse(uri) else {
            return false;
        };
        return parsed.scheme() == "cursor"
            && parsed.host_str() == Some("anysphere.cursor-mcp")
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.fragment().is_none();
    }

    let Ok(parsed) = url::Url::parse(uri) else {
        return false;
    };
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return false;
    }
    match parsed.scheme() {
        "https" => parsed.host_str().is_some(),
        // Loopback-only for local development, per RFC 8252.
        // `Url::host_str` returns IPv6 hosts bracketed (`[::1]`).
        "http" => matches!(
            parsed.host_str(),
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
        ),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// /authorize
// ---------------------------------------------------------------------------

// `scope` is accepted but ignored: consent uses our server-fixed scope set.
#[derive(Deserialize)]
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
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<AuthorizeQuery>,
) -> Result<Response, (StatusCode, Json<crate::oauth::OauthErrorBody>)> {
    // Google always calls back to BASE_URL, so the browser-binding cookie
    // must be set on BASE_URL's origin, before any state/cookie exists.
    let iss = issuer_from_headers(&headers, &state.config.base_url);
    if iss != state.config.base_url {
        let target = match uri.query() {
            Some(qs) => format!("{}/authorize?{qs}", state.config.base_url),
            None => format!("{}/authorize", state.config.base_url),
        };
        let mut resp = StatusCode::FOUND.into_response();
        if let Ok(v) = HeaderValue::from_str(&target) {
            resp.headers_mut().insert(header::LOCATION, v);
        }
        return Ok(resp);
    }

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

    let _ = clients::touch_last_used(&state.db, &q.client_id).await;

    let state_id = Uuid::new_v4().simple().to_string();
    let mut secret_bytes = [0u8; 32];
    getrandom::fill(&mut secret_bytes).expect("OS RNG failure");
    let binding_secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let binding_hash = sha256_hex(binding_secret.as_bytes());

    codes::insert_state(
        &state.db,
        codes::InsertState {
            state_id: state_id.clone(),
            mcp_client_id: q.client_id,
            mcp_redirect_uri: q.redirect_uri.clone(),
            mcp_state: q.state,
            code_challenge: q.code_challenge,
            code_challenge_method: q.code_challenge_method,
            resource: q.resource,
            browser_binding: binding_hash,
            login_hint: q.login_hint,
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

    let scopes: Vec<&str> = state
        .config
        .enabled_domains
        .iter()
        .map(super::super::domain::Domain::human_name)
        .collect();
    let page = consent::render_consent_page(
        client.client_name.as_deref(),
        &q.redirect_uri,
        &scopes,
        &state_id,
    );

    let mut resp = Html(page).into_response();
    consent::security_headers(resp.headers_mut());
    set_binding_cookie(
        &mut resp,
        &state_id,
        &binding_secret,
        is_https(&state.config.base_url),
    );
    Ok(resp)
}

// ---------------------------------------------------------------------------
// /authorize/consent
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ConsentForm {
    pub state_id: String,
    pub decision: String,
}

pub async fn authorize_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Result<Response, (StatusCode, String)> {
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let base_origin = origin_of(&state.config.base_url);
        if origin_of(origin) != base_origin {
            return Err((StatusCode::FORBIDDEN, "origin not allowed".into()));
        }
    }

    let secure = is_https(&state.config.base_url);
    let cookie_name = binding_cookie_name(&form.state_id);
    let Some(cookie_secret) = cookie_value(&headers, &cookie_name) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "missing browser-binding cookie; complete sign-in in the same browser it started in"
                .into(),
        ));
    };

    let st = codes::get_state(&state.db, &form.state_id)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::BAD_REQUEST, "state expired or unknown".into()))?;
    if st.expires_at < now_secs() as i64 {
        return Err((StatusCode::BAD_REQUEST, "state expired".into()));
    }
    let expected_hash = st.browser_binding.clone().unwrap_or_default();
    let computed_hash = sha256_hex(cookie_secret.as_bytes());
    if !constant_time_eq(computed_hash.as_bytes(), expected_hash.as_bytes()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "browser-binding cookie does not match this authorization attempt".into(),
        ));
    }

    if form.decision == "approve" {
        // Idempotent for a double-clicked Approve; false only if the state expired.
        if !codes::mark_approved(&state.db, &form.state_id)
            .await
            .map_err(internal)?
        {
            return Err((StatusCode::BAD_REQUEST, "state expired".into()));
        }
        let google_url = state
            .google_oauth
            .build_authorize_url(&form.state_id, st.login_hint.as_deref());
        // The cookie must survive the round trip through Google's consent
        // screen — /oauth/google/callback is what finally clears it.
        Ok(Redirect::to(&google_url).into_response())
    } else {
        codes::consume_state(&state.db, &form.state_id)
            .await
            .map_err(internal)?;
        let target = denied_redirect(&st.mcp_redirect_uri, st.mcp_state.as_deref())
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let mut resp = Redirect::to(&target).into_response();
        clear_binding_cookie(&mut resp, &form.state_id, secure);
        Ok(resp)
    }
}

fn denied_redirect(redirect_uri: &str, mcp_state: Option<&str>) -> Result<String, String> {
    let mut url = url::Url::parse(redirect_uri)
        .map_err(|e| format!("invalid registered redirect_uri: {e}"))?;
    url.query_pairs_mut().append_pair("error", "access_denied");
    if let Some(s) = mcp_state {
        url.query_pairs_mut().append_pair("state", s);
    }
    Ok(url.to_string())
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
    headers: HeaderMap,
    Query(q): Query<GoogleCallbackQuery>,
) -> Response {
    let secure = is_https(&state.config.base_url);
    let cookie_name = q.state.as_deref().map(binding_cookie_name);
    let cookie_secret = cookie_name
        .as_deref()
        .and_then(|n| cookie_value(&headers, n));

    let result = google_callback_inner(&state, q, cookie_secret.as_deref()).await;
    let mut resp = match result {
        Ok(url) => Redirect::to(&url).into_response(),
        Err((status, msg)) => (status, msg).into_response(),
    };
    if let Some(state_id) = cookie_name
        .as_deref()
        .and_then(|n| n.strip_prefix("gmcp_c_"))
    {
        clear_binding_cookie(&mut resp, state_id, secure);
    }
    resp
}

async fn google_callback_inner(
    state: &AppState,
    q: GoogleCallbackQuery,
    cookie_secret: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    let Some(state_id) = q.state else {
        return Err((StatusCode::BAD_REQUEST, "missing state".into()));
    };

    if let Some(err) = q.error {
        let desc = q.error_description.unwrap_or_default();
        if let Some(proxy_state) = codes::consume_state(&state.db, &state_id)
            .await
            .map_err(internal)?
        {
            let target = denied_redirect(
                &proxy_state.mcp_redirect_uri,
                proxy_state.mcp_state.as_deref(),
            )
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
            return Ok(target);
        }
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Google denied authorization: {err} {desc}"),
        ));
    }
    let Some(code) = q.code else {
        return Err((StatusCode::BAD_REQUEST, "missing code".into()));
    };

    let proxy_state = codes::consume_state(&state.db, &state_id)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::BAD_REQUEST, "state expired or unknown".into()))?;

    if !proxy_state.approved {
        return Err((
            StatusCode::BAD_REQUEST,
            "authorization was not approved; complete sign-in in the same browser it started in"
                .into(),
        ));
    }
    // Only the victim's own browser carries the cookie checked here.
    let expected_hash = proxy_state.browser_binding.clone().unwrap_or_default();
    let cookie_ok = cookie_secret
        .map(|s| sha256_hex(s.as_bytes()))
        .is_some_and(|computed| constant_time_eq(computed.as_bytes(), expected_hash.as_bytes()));
    if !cookie_ok {
        return Err((
            StatusCode::BAD_REQUEST,
            "missing or mismatched browser-binding cookie; complete sign-in in the same browser it started in"
                .into(),
        ));
    }

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
    let id = parse_id_token(id_token, &state.config.google_client_id).map_err(|e| {
        tracing::error!(err = ?e, "id_token parse failed");
        (StatusCode::BAD_GATEWAY, format!("id_token parse: {e}"))
    })?;

    let refresh_token = grant.refresh_token.as_deref().ok_or((
        StatusCode::BAD_GATEWAY,
        "Google did not return a refresh_token; ensure prompt=consent + access_type=offline".into(),
    ))?;

    let scopes: Vec<String> = grant.scope.as_deref().map_or_else(
        || domain::google_scopes(&state.config.enabled_domains),
        |s| s.split_whitespace().map(str::to_string).collect(),
    );
    let email = id.email.clone().unwrap_or_default();

    if !state.config.allowed_google_accounts.is_empty() {
        let email_verified = id.email_verified.unwrap_or(false);
        let allowed = email_verified
            && crate::config::account_allowed(
                &state.config.allowed_google_accounts,
                &email,
                id.hd.as_deref(),
            );
        if !allowed {
            tracing::warn!(hd = ?id.hd, "rejecting sign-in: account not in ALLOWED_GOOGLE_ACCOUNTS");
            let _ = crate::oauth::google::revoke_token(&state.http, refresh_token).await;
            let target = denied_redirect(
                &proxy_state.mcp_redirect_uri,
                proxy_state.mcp_state.as_deref(),
            )
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
            return Ok(target);
        }
    }

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
    Ok(url.to_string())
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
        && !clients::verify_secret(secret, &client.client_secret_hash).await
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

    let allowed_hosts =
        host_guard::build_allowed_hosts(&state.config.base_url, &state.config.allowed_hosts);
    if let Some(resource) = req.resource.as_deref().or(stored.resource.as_deref())
        && !resource_target_valid(resource, &allowed_hosts)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_target",
                Some(format!("resource not allowed: {resource}")),
            )),
        ));
    }

    let iss = issuer_from_headers(&headers, &state.config.base_url);
    let now = now_secs();
    let claims = Claims {
        iss: iss.clone(),
        sub: stored.google_sub,
        iat: now,
        exp: now + TOKEN_LIFETIME_SECS,
        aud: format!("{iss}/mcp"),
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

/// RFC 8707 `resource` validity for `/oauth/token`: an allowlisted host and
/// a path of `/mcp`, `/mcp/`, or the server root (empty/`/`).
fn resource_target_valid(resource: &str, allowed: &[AllowedHost]) -> bool {
    let Ok(url) = url::Url::parse(resource) else {
        return false;
    };
    if url.scheme() != "http" && url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let authority = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    if !host_guard::host_allowed(&authority, allowed) {
        return false;
    }
    matches!(url.path(), "/mcp" | "/mcp/" | "/" | "")
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
    fn issuer_from_headers_uses_first_forwarded_host_element() {
        let mut hm = h("localhost:8433", None);
        hm.insert(
            "x-forwarded-host",
            "a.example.com, b.example.com".parse().unwrap(),
        );
        assert_eq!(
            issuer_from_headers(&hm, "http://fb"),
            "https://a.example.com"
        );
    }

    #[test]
    fn issuer_from_headers_ignores_junk_forwarded_proto() {
        let mut hm = h("google-mcp.example.com", None);
        hm.insert("x-forwarded-proto", "gopher".parse().unwrap());
        assert_eq!(
            issuer_from_headers(&hm, "http://fb"),
            "https://google-mcp.example.com"
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
        assert!(is_valid_redirect_uri(
            "cursor://anysphere.cursor-mcp/oauth/callback"
        ));
        assert!(is_valid_redirect_uri(
            "cursor://anysphere.cursor-mcp/other/path"
        ));
        assert!(!is_valid_redirect_uri(
            "cursor://anysphere.cursor-mcp.evil.com/cb"
        ));
        assert!(!is_valid_redirect_uri("cursor://evil.example/cb"));
        assert!(!is_valid_redirect_uri("cursor://"));
        assert!(!is_valid_redirect_uri("myapp://anysphere.cursor-mcp/cb"));
    }

    #[test]
    fn redirect_uri_userinfo_tricks_rejected() {
        assert!(!is_valid_redirect_uri("http://localhost:80@evil.com/cb"));
        assert!(!is_valid_redirect_uri("https://claude.ai@evil.com/cb"));
    }

    #[test]
    fn redirect_uri_fragment_rejected() {
        assert!(!is_valid_redirect_uri("https://x.example/cb#f"));
    }

    #[test]
    fn redirect_uri_bracketed_ipv6_with_port_accepted() {
        assert!(is_valid_redirect_uri("http://[::1]:3000/cb"));
    }

    #[test]
    fn redirect_uri_scheme_case_insensitive() {
        assert!(is_valid_redirect_uri("HTTPS://claude.ai/cb"));
    }

    #[test]
    fn cursor_redirect_uri_accepts_query_params() {
        let mut url = url::Url::parse("cursor://anysphere.cursor-mcp/oauth/callback").unwrap();
        assert!(!url.cannot_be_a_base());
        url.query_pairs_mut()
            .append_pair("code", "abc123")
            .append_pair("state", "xyz");
        assert!(url.as_str().contains("code=abc123"));
        assert!(url.as_str().contains("state=xyz"));
    }

    // -----------------------------------------------------------------
    // Consent interstitial: handler-level tests against a real in-memory DB.
    // -----------------------------------------------------------------

    async fn app_state(base_url: &str) -> AppState {
        let db = crate::storage::Db::open_in_memory().await.unwrap();
        let http = std::sync::Arc::new(reqwest::Client::new());
        let google_oauth = std::sync::Arc::new(crate::oauth::google::GoogleOAuthClient::new(
            "test-cid",
            "test-secret",
            format!("{base_url}/oauth/google/callback"),
            domain::google_scopes(&[domain::Domain::Gmail]),
            (*http).clone(),
        ));
        let session_cache = crate::google::session::SessionCache::new(
            db.clone(),
            std::sync::Arc::clone(&google_oauth),
            [0u8; 32],
            vec![],
        );
        let config = std::sync::Arc::new(crate::config::ServerConfig {
            host: "127.0.0.1".parse().unwrap(),
            port: 8433,
            base_url: base_url.to_string(),
            google_client_id: "test-cid".to_string(),
            google_client_secret: "test-secret".to_string(),
            jwt_secret: vec![0u8; 32],
            storage_encryption_key: [0u8; 32],
            database_url: ":memory:".to_string(),
            cors_allow_localhost: true,
            allowed_hosts: vec![],
            enabled_domains: vec![domain::Domain::Gmail],
            allowed_google_accounts: vec![],
            file_jail: None,
            file_maintenance: crate::files::FileMaintenance::Off,
        });
        AppState {
            config,
            db,
            http,
            google_oauth,
            session_cache,
            tenancy: crate::state::Tenancy::MultiTenant,
        }
    }

    async fn seed_client(state: &AppState, client_id: &str, redirect_uri: &str) {
        clients::create(
            &state.db,
            clients::CreateClient {
                client_id: client_id.to_string(),
                client_secret: "s".to_string(),
                redirect_uris: vec![redirect_uri.to_string()],
                client_name: Some("Test Client".to_string()),
            },
        )
        .await
        .unwrap();
    }

    fn extract_set_cookie(resp: &Response) -> String {
        resp.headers()
            .get(http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    async fn run_authorize(state: &AppState, client_id: &str, redirect_uri: &str) -> Response {
        let q = AuthorizeQuery {
            response_type: "code".to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: None,
            state: Some("client-state-xyz".to_string()),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            resource: None,
            login_hint: None,
        };
        authorize(
            State(state.clone()),
            h("localhost:8433", None),
            "/authorize".parse().unwrap(),
            Query(q),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn authorize_renders_consent_with_cookie_and_security_headers() {
        let state = app_state("http://localhost:8433").await;
        seed_client(&state, "cid", "https://x.example/cb").await;
        let resp = run_authorize(&state, "cid", "https://x.example/cb").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(http::header::SET_COOKIE).is_some());
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
        );
        assert_eq!(
            resp.headers().get(http::header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
        assert_eq!(
            resp.headers()
                .get(http::header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            resp.headers().get(http::header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[tokio::test]
    async fn consent_without_cookie_is_400() {
        let state = app_state("http://localhost:8433").await;
        seed_client(&state, "cid", "https://x.example/cb").await;
        let auth_resp = run_authorize(&state, "cid", "https://x.example/cb").await;
        let cookie = extract_set_cookie(&auth_resp);
        let state_id = cookie
            .split('=')
            .next()
            .unwrap()
            .strip_prefix("gmcp_c_")
            .unwrap();

        let form = ConsentForm {
            state_id: state_id.to_string(),
            decision: "approve".to_string(),
        };
        let err = authorize_consent(State(state.clone()), HeaderMap::new(), Form(form))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn consent_with_wrong_origin_is_403() {
        let state = app_state("http://localhost:8433").await;
        seed_client(&state, "cid", "https://x.example/cb").await;
        let auth_resp = run_authorize(&state, "cid", "https://x.example/cb").await;
        let cookie = extract_set_cookie(&auth_resp);
        let state_id = cookie
            .split('=')
            .next()
            .unwrap()
            .strip_prefix("gmcp_c_")
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, cookie.parse().unwrap());
        headers.insert(
            http::header::ORIGIN,
            "https://evil.example".parse().unwrap(),
        );
        let form = ConsentForm {
            state_id: state_id.to_string(),
            decision: "approve".to_string(),
        };
        let err = authorize_consent(State(state.clone()), headers, Form(form))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn consent_approve_redirects_303_to_google_with_state() {
        let state = app_state("http://localhost:8433").await;
        seed_client(&state, "cid", "https://x.example/cb").await;
        let auth_resp = run_authorize(&state, "cid", "https://x.example/cb").await;
        let cookie = extract_set_cookie(&auth_resp);
        let state_id = cookie
            .split('=')
            .next()
            .unwrap()
            .strip_prefix("gmcp_c_")
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, cookie.parse().unwrap());
        let form = ConsentForm {
            state_id: state_id.to_string(),
            decision: "approve".to_string(),
        };
        let resp = authorize_consent(State(state.clone()), headers, Form(form))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp
            .headers()
            .get(http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(loc.starts_with("https://accounts.google.com/"));
        assert!(loc.contains(&format!("state={state_id}")));
    }

    #[tokio::test]
    async fn consent_deny_redirects_303_with_access_denied() {
        let state = app_state("http://localhost:8433").await;
        seed_client(&state, "cid", "https://x.example/cb").await;
        let auth_resp = run_authorize(&state, "cid", "https://x.example/cb").await;
        let cookie = extract_set_cookie(&auth_resp);
        let state_id = cookie
            .split('=')
            .next()
            .unwrap()
            .strip_prefix("gmcp_c_")
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, cookie.parse().unwrap());
        let form = ConsentForm {
            state_id: state_id.to_string(),
            decision: "deny".to_string(),
        };
        let resp = authorize_consent(State(state.clone()), headers, Form(form))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp
            .headers()
            .get(http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(loc.starts_with("https://x.example/cb"));
        assert!(loc.contains("error=access_denied"));
        assert!(loc.contains("client-state-xyz"));
    }

    #[tokio::test]
    async fn callback_on_unapproved_state_is_400() {
        let state = app_state("http://localhost:8433").await;
        seed_client(&state, "cid", "https://x.example/cb").await;
        let auth_resp = run_authorize(&state, "cid", "https://x.example/cb").await;
        let cookie = extract_set_cookie(&auth_resp);
        let state_id = cookie
            .split('=')
            .next()
            .unwrap()
            .strip_prefix("gmcp_c_")
            .unwrap();

        let q = GoogleCallbackQuery {
            code: Some("fake-code".to_string()),
            state: Some(state_id.to_string()),
            error: None,
            error_description: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, cookie.parse().unwrap());
        let resp = google_callback(State(state.clone()), headers, Query(q)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn callback_without_cookie_after_approval_is_400() {
        let state = app_state("http://localhost:8433").await;
        seed_client(&state, "cid", "https://x.example/cb").await;
        let auth_resp = run_authorize(&state, "cid", "https://x.example/cb").await;
        let cookie = extract_set_cookie(&auth_resp);
        let state_id = cookie
            .split('=')
            .next()
            .unwrap()
            .strip_prefix("gmcp_c_")
            .unwrap();
        codes::mark_approved(&state.db, state_id).await.unwrap();

        let q = GoogleCallbackQuery {
            code: Some("fake-code".to_string()),
            state: Some(state_id.to_string()),
            error: None,
            error_description: None,
        };
        // No Cookie header at all: the browser-binding check must fail closed.
        let resp = google_callback(State(state.clone()), HeaderMap::new(), Query(q)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
