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

use axum::extract::rejection::{FormRejection, JsonRejection};
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
use crate::oauth::jwt::{Claims, now_secs, sign as sign_jwt};
use crate::oauth::oauth_err;
use crate::oauth::pkce::{constant_time_eq, verify_s256};
use crate::state::AppState;
use crate::storage::clients::{ClientAuth, McpClient};
use crate::storage::{accounts, clients, codes, refresh_tokens};

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
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        token_endpoint_auth_methods_supported: vec![
            ClientAuth::SecretBasic.as_str().to_string(),
            ClientAuth::SecretPost.as_str().to_string(),
            ClientAuth::None.as_str().to_string(),
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

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    pub client_id_issued_at: i64,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
}

type RegisterError = (StatusCode, Json<crate::oauth::OauthErrorBody>);

/// Registration responses carry secrets, so they are never cacheable (RFC 7591 3.2.1).
pub async fn register(
    State(state): State<AppState>,
    body: Result<Json<RegisterRequest>, JsonRejection>,
) -> Response {
    let resp = match body {
        Ok(Json(req)) => match register_inner(&state, req).await {
            Ok(ok) => ok.into_response(),
            Err(e) => e.into_response(),
        },
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_client_metadata",
                Some("request body is not valid registration JSON".to_string()),
            )),
        )
            .into_response(),
    };
    with_no_store(resp)
}

fn with_no_store(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

async fn register_inner(
    state: &AppState,
    req: RegisterRequest,
) -> Result<(StatusCode, Json<RegisterResponse>), RegisterError> {
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
    let method_name = req
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or(ClientAuth::SecretBasic.as_str());
    let Some(auth_method) = ClientAuth::parse(method_name) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(oauth_err(
                "invalid_client_metadata",
                Some(
                    "token_endpoint_auth_method must be one of client_secret_basic, client_secret_post, none"
                        .to_string(),
                ),
            )),
        ));
    };
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
    let client_secret =
        (auth_method != ClientAuth::None).then(|| Uuid::new_v4().simple().to_string());
    clients::create(
        &state.db,
        clients::CreateClient {
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            redirect_uris: req.redirect_uris.clone(),
            client_name: req.client_name.clone(),
            auth_method,
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
            client_secret_expires_at: client_secret.is_some().then_some(0),
            client_secret,
            client_id_issued_at: now_secs() as i64,
            redirect_uris: req.redirect_uris,
            client_name: req.client_name,
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: auth_method.as_str().to_string(),
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
    pub refresh_token: Option<String>,
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
    pub refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// An OAuth error response; `challenge` adds `WWW-Authenticate: Basic` (RFC 6749 5.2).
#[derive(Debug)]
struct TokenError {
    status: StatusCode,
    body: crate::oauth::OauthErrorBody,
    challenge: bool,
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let mut resp = (self.status, Json(self.body)).into_response();
        if self.challenge {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(BASIC_CHALLENGE),
            );
        }
        resp
    }
}

const BASIC_CHALLENGE: &str = "Basic realm=\"google-mcp\"";

fn token_err(status: StatusCode, error: &str, description: Option<&str>) -> TokenError {
    TokenError {
        status,
        body: oauth_err(error, description.map(str::to_string)),
        challenge: false,
    }
}

fn invalid_client(used_basic: bool) -> TokenError {
    TokenError {
        challenge: used_basic,
        ..token_err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            Some("client authentication failed"),
        )
    }
}

fn server_error<E: std::fmt::Debug>(what: &'static str) -> impl FnOnce(E) -> TokenError {
    move |e| {
        tracing::error!(err = ?e, "{what} failed");
        token_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", None)
    }
}

/// Success and error responses are never cacheable (RFC 6749 5.1).
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<TokenForm>, FormRejection>,
) -> Response {
    let resp = match form {
        Ok(Form(req)) => match token_inner(&state, &headers, req).await {
            Ok(ok) => ok.into_response(),
            Err(e) => e.into_response(),
        },
        Err(_) => token_err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("malformed token request"),
        )
        .into_response(),
    };
    with_no_store(resp)
}

async fn token_inner(
    state: &AppState,
    headers: &HeaderMap,
    req: TokenForm,
) -> Result<Json<TokenResponse>, TokenError> {
    match req.grant_type.as_str() {
        "authorization_code" => authorization_code_grant(state, headers, req).await,
        "refresh_token" => refresh_token_grant(state, headers, req).await,
        _ => Err(token_err(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            Some("only authorization_code and refresh_token are supported"),
        )),
    }
}

/// Decode one half of a Basic credential: `+` is a space, then percent-decoding (RFC 6749 2.3.1).
fn form_urldecode(raw: &str) -> Option<String> {
    let spaced = raw.replace('+', " ");
    percent_encoding::percent_decode_str(&spaced)
        .decode_utf8()
        .ok()
        .map(std::borrow::Cow::into_owned)
}

/// The decoded `(client_id, client_secret)` of an `Authorization: Basic` header, if
/// there is one. `Ok(None)` when no header uses the Basic scheme.
fn basic_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, TokenError> {
    let mut basic = headers.get_all(header::AUTHORIZATION).iter().filter(|v| {
        let bytes = v.as_bytes();
        let scheme_end = bytes.iter().position(|b| *b == b' ').unwrap_or(bytes.len());
        bytes[..scheme_end].eq_ignore_ascii_case(b"basic")
    });
    let Some(value) = basic.next() else {
        return Ok(None);
    };
    if basic.next().is_some() {
        return Err(invalid_client(true));
    }
    let parsed = (|| {
        let text = value.to_str().ok()?;
        let (_, encoded) = text.split_once(' ')?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (id, secret) = decoded.split_once(':')?;
        let id = form_urldecode(id)?;
        if id.is_empty() {
            return None;
        }
        Some((id, form_urldecode(secret)?))
    })();
    parsed.map(Some).ok_or_else(|| invalid_client(true))
}

/// Returns `(client_id, client_secret, used_basic)`.
fn client_credentials(
    headers: &HeaderMap,
    form: &TokenForm,
) -> Result<(String, Option<String>, bool), TokenError> {
    if let Some((client_id, secret)) = basic_credentials(headers)? {
        let invalid_request =
            |why: &str| token_err(StatusCode::BAD_REQUEST, "invalid_request", Some(why));
        if form.client_secret.is_some() {
            return Err(invalid_request("use one client authentication method"));
        }
        if form.client_id.as_deref().is_some_and(|f| f != client_id) {
            return Err(invalid_request(
                "client_id does not match the Authorization header",
            ));
        }
        return Ok((client_id, Some(secret), true));
    }
    let client_id = form.client_id.clone().ok_or_else(|| {
        token_err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("missing client_id"),
        )
    })?;
    Ok((client_id, form.client_secret.clone(), false))
}

/// Authenticate before touching any code or token, so a failure burns nothing.
async fn authenticate_client(
    state: &AppState,
    client_id: &str,
    secret: Option<&str>,
    used_basic: bool,
) -> Result<McpClient, TokenError> {
    let client = clients::get(&state.db, client_id)
        .await
        .map_err(server_error("client lookup"))?
        .ok_or_else(|| invalid_client(used_basic))?;
    let verified = match secret {
        Some(secret) => clients::verify_secret(secret, &client.client_secret_hash).await,
        None => false,
    };
    let accepted = match client.token_endpoint_auth_method {
        Some(ClientAuth::None) => true,
        Some(ClientAuth::SecretPost | ClientAuth::SecretBasic) => verified,
        None => secret.is_none() || verified,
    };
    if accepted {
        Ok(client)
    } else {
        Err(invalid_client(used_basic))
    }
}

async fn authorization_code_grant(
    state: &AppState,
    headers: &HeaderMap,
    req: TokenForm,
) -> Result<Json<TokenResponse>, TokenError> {
    let (client_id, secret, used_basic) = client_credentials(headers, &req)?;
    authenticate_client(state, &client_id, secret.as_deref(), used_basic).await?;

    let code = req.code.ok_or_else(|| {
        token_err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("missing code"),
        )
    })?;
    let code_verifier = req.code_verifier.ok_or_else(|| {
        token_err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("missing code_verifier (PKCE required)"),
        )
    })?;

    let stored = codes::consume_code(&state.db, &code)
        .await
        .map_err(server_error("consume_code"))?
        .ok_or_else(|| {
            token_err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("code expired or already used"),
            )
        })?;

    if stored.mcp_client_id != client_id {
        return Err(token_err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some("code was issued to another client"),
        ));
    }
    if let Some(supplied_redirect) = req.redirect_uri.as_deref()
        && supplied_redirect != stored.mcp_redirect_uri
    {
        return Err(token_err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some("redirect_uri does not match authorization request"),
        ));
    }

    if !verify_s256(&code_verifier, &stored.code_challenge) {
        return Err(token_err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some("PKCE verification failed"),
        ));
    }

    if let (Some(requested), Some(bound)) = (req.resource.as_deref(), stored.resource.as_deref())
        && requested != bound
    {
        return Err(token_err(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("resource does not match the authorization request"),
        ));
    }
    let resource = stored.resource.or(req.resource);
    check_resource(state, resource.as_deref())?;

    let access_token = sign_access_token(state, headers, &stored.google_sub)?;
    let refresh_token = new_refresh_token();
    refresh_tokens::issue(
        &state.db,
        &refresh_token,
        refresh_tokens::IssueRefresh {
            family_id: Uuid::new_v4().simple().to_string(),
            mcp_client_id: client_id,
            google_sub: stored.google_sub,
            resource,
        },
    )
    .await
    .map_err(server_error("refresh token insert"))?;
    Ok(token_response(state, access_token, refresh_token))
}

async fn refresh_token_grant(
    state: &AppState,
    headers: &HeaderMap,
    req: TokenForm,
) -> Result<Json<TokenResponse>, TokenError> {
    let (client_id, secret, used_basic) = client_credentials(headers, &req)?;
    authenticate_client(state, &client_id, secret.as_deref(), used_basic).await?;

    let presented = req.refresh_token.as_deref().ok_or_else(|| {
        token_err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("missing refresh_token"),
        )
    })?;
    check_resource(state, req.resource.as_deref())?;

    let successor = new_refresh_token();
    let rotation = refresh_tokens::rotate(
        &state.db,
        refresh_tokens::RotateRequest {
            presented,
            client_id: &client_id,
            resource: req.resource.as_deref(),
            successor: &successor,
            grace_secs: state.config.refresh_reuse_grace_secs,
            encryption_key: &state.config.storage_encryption_key,
        },
    )
    .await
    .map_err(server_error("refresh token rotation"))?;

    let invalid = |why: &str| token_err(StatusCode::BAD_REQUEST, "invalid_grant", Some(why));
    use refresh_tokens::Rotation;
    match rotation {
        Rotation::Valid {
            grant,
            refresh_token,
        } => {
            let access_token = sign_access_token(state, headers, &grant.google_sub)?;
            Ok(token_response(state, access_token, refresh_token))
        }
        Rotation::WrongResource => Err(token_err(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("resource does not match the original grant"),
        )),
        Rotation::Invalid => Err(invalid("refresh token expired or unknown")),
        Rotation::Replayed => {
            tracing::warn!(client_id = %client_id, "refresh token replayed; family deleted");
            Err(invalid("refresh token already used; authorize again"))
        }
        Rotation::WrongClient => {
            tracing::warn!(client_id = %client_id, "refresh token presented by another client; family deleted");
            Err(invalid("refresh token was issued to another client"))
        }
        Rotation::Revoked => Err(invalid("account access was revoked; authorize again")),
        Rotation::Disconnected => Err(invalid(
            "Google account is no longer connected; authorize again",
        )),
    }
}

fn check_resource(state: &AppState, resource: Option<&str>) -> Result<(), TokenError> {
    let allowed_hosts =
        host_guard::build_allowed_hosts(&state.config.base_url, &state.config.allowed_hosts);
    match resource {
        Some(resource) if !resource_target_valid(resource, &allowed_hosts) => Err(token_err(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some(&format!("resource not allowed: {resource}")),
        )),
        _ => Ok(()),
    }
}

/// Sign an access JWT that lives `access_token_lifetime_secs`.
fn sign_access_token(
    state: &AppState,
    headers: &HeaderMap,
    google_sub: &str,
) -> Result<String, TokenError> {
    let iss = issuer_from_headers(headers, &state.config.base_url);
    let now = now_secs();
    let claims = Claims {
        iss: iss.clone(),
        sub: google_sub.to_string(),
        iat: now,
        exp: now + state.config.access_token_lifetime_secs,
        aud: format!("{iss}/mcp"),
    };
    sign_jwt(&state.config.jwt_secret, &claims).map_err(server_error("JWT sign"))
}

/// `mcpr_` plus 32 OS-random bytes, base64url.
fn new_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS RNG failure");
    format!("mcpr_{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn token_response(
    state: &AppState,
    access_token: String,
    refresh_token: String,
) -> Json<TokenResponse> {
    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.access_token_lifetime_secs,
        refresh_token,
        scope: None,
    })
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
    use crate::storage::revocations;

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
        app_state_with(base_url, 3600, 10).await
    }

    async fn app_state_with(base_url: &str, lifetime_secs: u64, grace_secs: i64) -> AppState {
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
            access_token_lifetime_secs: lifetime_secs,
            refresh_reuse_grace_secs: grace_secs,
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

    const SECRET: &str = "s";

    async fn seed_client_with(
        state: &AppState,
        client_id: &str,
        redirect_uri: &str,
        auth_method: ClientAuth,
    ) {
        clients::create(
            &state.db,
            clients::CreateClient {
                client_id: client_id.to_string(),
                client_secret: (auth_method != ClientAuth::None).then(|| SECRET.to_string()),
                redirect_uris: vec![redirect_uri.to_string()],
                client_name: Some("Test Client".to_string()),
                auth_method,
            },
        )
        .await
        .unwrap();
    }

    async fn seed_client(state: &AppState, client_id: &str, redirect_uri: &str) {
        seed_client_with(state, client_id, redirect_uri, ClientAuth::SecretPost).await;
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

    // -----------------------------------------------------------------
    // Registration, client authentication and refresh tokens.
    // -----------------------------------------------------------------

    const VERIFIER: &str = "a-pkce-verifier-that-is-long-enough-for-s256-0123456789";
    const REDIRECT: &str = "http://127.0.0.1:9/cb";
    const RES: &str = "http://localhost:8433/mcp";
    const OTHER_RES: &str = "http://localhost:8433/";

    fn reg_req(method: Option<&str>) -> RegisterRequest {
        RegisterRequest {
            redirect_uris: vec!["https://claude.ai/cb".to_string()],
            client_name: Some("Sam's client".to_string()),
            token_endpoint_auth_method: method.map(str::to_string),
            grant_types: None,
            response_types: None,
            scope: None,
        }
    }

    async fn register_json(state: &AppState, method: Option<&str>) -> serde_json::Value {
        let (status, Json(body)) = register_inner(state, reg_req(method)).await.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        serde_json::to_value(body).unwrap()
    }

    #[tokio::test]
    async fn register_omitted_method_defaults_to_basic_with_secret() {
        let state = app_state("http://localhost:8433").await;
        let body = register_json(&state, None).await;
        assert!(
            body["client_secret"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        assert_eq!(body["client_secret_expires_at"], 0);
        assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");
        let stored = clients::get(&state.db, body["client_id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.token_endpoint_auth_method,
            Some(ClientAuth::SecretBasic)
        );
        assert!(
            clients::verify_secret(
                body["client_secret"].as_str().unwrap(),
                &stored.client_secret_hash
            )
            .await
        );
    }

    #[tokio::test]
    async fn register_none_has_no_secret() {
        let state = app_state("http://localhost:8433").await;
        let body = register_json(&state, Some("none")).await;
        let obj = body.as_object().unwrap();
        assert!(!obj.contains_key("client_secret"));
        assert!(!obj.contains_key("client_secret_expires_at"));
        assert_eq!(body["token_endpoint_auth_method"], "none");
        let stored = clients::get(&state.db, body["client_id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.token_endpoint_auth_method, Some(ClientAuth::None));
        assert_eq!(stored.client_secret_hash, "");
    }

    #[tokio::test]
    async fn register_post_echoed() {
        let state = app_state("http://localhost:8433").await;
        let body = register_json(&state, Some("client_secret_post")).await;
        assert_eq!(body["token_endpoint_auth_method"], "client_secret_post");
        assert_eq!(body["client_secret_expires_at"], 0);
        assert!(body["client_secret"].is_string());
        let stored = clients::get(&state.db, body["client_id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.token_endpoint_auth_method,
            Some(ClientAuth::SecretPost)
        );
    }

    #[tokio::test]
    async fn register_rejects_unknown_method() {
        let state = app_state("http://localhost:8433").await;
        for method in ["private_key_jwt", "", "NONE", "client_secret_jwt"] {
            let (status, Json(body)) = register_inner(&state, reg_req(Some(method)))
                .await
                .unwrap_err();
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method:?}");
            assert_eq!(body.error, "invalid_client_metadata");
            let why = body.error_description.unwrap();
            for accepted in ["client_secret_basic", "client_secret_post", "none"] {
                assert!(why.contains(accepted));
            }
        }
        assert_eq!(clients::count(&state.db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn metadata_lists_three_auth_methods() {
        let state = app_state("http://localhost:8433").await;
        let Json(meta) =
            authorization_server_metadata(State(state), h("localhost:8433", None)).await;
        let v = serde_json::to_value(meta).unwrap();
        assert_eq!(
            v["token_endpoint_auth_methods_supported"],
            serde_json::json!(["client_secret_basic", "client_secret_post", "none"])
        );
    }

    // -- client_credentials ------------------------------------------------

    fn basic_header(raw: &str) -> HeaderMap {
        let mut hm = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        hm.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        hm
    }

    fn raw_auth(value: &str) -> HeaderMap {
        let mut hm = HeaderMap::new();
        hm.insert(header::AUTHORIZATION, value.parse().unwrap());
        hm
    }

    fn bare_form() -> TokenForm {
        TokenForm {
            grant_type: "authorization_code".to_string(),
            code: None,
            refresh_token: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            resource: None,
        }
    }

    #[test]
    fn basic_credentials_parse() {
        let (id, secret, basic) =
            client_credentials(&basic_header("cid:s3cret"), &bare_form()).unwrap();
        assert_eq!(
            (id.as_str(), secret.as_deref(), basic),
            ("cid", Some("s3cret"), true)
        );
    }

    #[test]
    fn basic_credentials_scheme_is_case_insensitive() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("cid:s");
        let (id, _, basic) =
            client_credentials(&raw_auth(&format!("bAsIc {encoded}")), &bare_form()).unwrap();
        assert_eq!((id.as_str(), basic), ("cid", true));
    }

    #[test]
    fn basic_credentials_are_form_urldecoded() {
        let (id, secret, _) =
            client_credentials(&basic_header("my%3Aid:a+b%3Ac%25"), &bare_form()).unwrap();
        assert_eq!(id, "my:id");
        assert_eq!(secret.as_deref(), Some("a b:c%"));
        // Only the first colon splits; later colons stay in the secret.
        let (id, secret, _) = client_credentials(&basic_header("cid:a:b"), &bare_form()).unwrap();
        assert_eq!((id.as_str(), secret.as_deref()), ("cid", Some("a:b")));
    }

    #[test]
    fn basic_without_colon_is_401() {
        let err = client_credentials(&basic_header("no-colon-here"), &bare_form()).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.body.error, "invalid_client");
        assert!(err.challenge);
    }

    #[test]
    fn basic_with_bad_base64_is_401() {
        for value in [
            "Basic !!!not-base64!!!",
            "Basic",
            "Basic Y2lkOnM",
            "Basic  ",
        ] {
            let err = client_credentials(&raw_auth(value), &bare_form()).unwrap_err();
            assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{value}");
            assert!(err.challenge);
        }
    }

    #[test]
    fn basic_with_empty_id_bad_utf8_or_bad_escape_is_401() {
        assert_eq!(
            client_credentials(&basic_header(":secret"), &bare_form())
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode([b'a', b':', 0xff]);
        let err =
            client_credentials(&raw_auth(&format!("Basic {encoded}")), &bare_form()).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            client_credentials(&basic_header("cid:%ff"), &bare_form())
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn two_basic_headers_are_401() {
        let mut hm = basic_header("a:b");
        hm.append(
            header::AUTHORIZATION,
            basic_header("c:d")[header::AUTHORIZATION].clone(),
        );
        assert_eq!(
            client_credentials(&hm, &bare_form()).unwrap_err().status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn basic_plus_form_secret_is_400() {
        let mut f = bare_form();
        f.client_secret = Some("s".to_string());
        let err = client_credentials(&basic_header("cid:s"), &f).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "invalid_request");
    }

    #[test]
    fn basic_plus_different_form_client_id_is_400() {
        let mut f = bare_form();
        f.client_id = Some("other".to_string());
        let err = client_credentials(&basic_header("cid:s"), &f).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "invalid_request");
    }

    #[test]
    fn basic_plus_same_form_client_id_is_ok() {
        let mut f = bare_form();
        f.client_id = Some("cid".to_string());
        let (id, secret, basic) = client_credentials(&basic_header("cid:s"), &f).unwrap();
        assert_eq!(
            (id.as_str(), secret.as_deref(), basic),
            ("cid", Some("s"), true)
        );
    }

    #[test]
    fn bearer_header_is_ignored() {
        let mut f = bare_form();
        f.client_id = Some("cid".to_string());
        f.client_secret = Some("posted".to_string());
        let (id, secret, basic) = client_credentials(&raw_auth("Bearer abc"), &f).unwrap();
        assert_eq!(
            (id.as_str(), secret.as_deref(), basic),
            ("cid", Some("posted"), false)
        );
        let err = client_credentials(&raw_auth("Bearer abc"), &bare_form()).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            err.body.error_description.as_deref(),
            Some("missing client_id")
        );
    }

    // -- token endpoint helpers --------------------------------------------

    #[derive(Debug)]
    struct Refused {
        status: StatusCode,
        error: String,
        challenge: bool,
    }

    enum Auth<'a> {
        Nothing,
        Post(&'a str),
        Basic(&'a str),
    }

    async fn seed_account(state: &AppState, sub: &str) {
        accounts::upsert(
            &state.db,
            &[0u8; 32],
            accounts::UpsertAccount {
                google_sub: sub.to_string(),
                email: format!("{sub}@example.com"),
                refresh_token: "google-rt".to_string(),
                scopes: vec![],
            },
        )
        .await
        .unwrap();
    }

    /// Insert a redeemable code (resource `RES`) for an already seeded client and account.
    async fn insert_code_with(
        state: &AppState,
        code: &str,
        client_id: &str,
        sub: &str,
        resource: Option<&str>,
    ) {
        codes::insert_code(
            &state.db,
            codes::InsertCode {
                code: code.to_string(),
                mcp_client_id: client_id.to_string(),
                mcp_redirect_uri: REDIRECT.to_string(),
                code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
                google_sub: sub.to_string(),
                resource: resource.map(str::to_string),
            },
        )
        .await
        .unwrap();
    }

    /// Seed a client with `auth_method`, a connected account and one code for them.
    async fn code_for(
        state: &AppState,
        client_id: &str,
        sub: &str,
        auth_method: ClientAuth,
    ) -> String {
        seed_client_with(state, client_id, REDIRECT, auth_method).await;
        seed_account(state, sub).await;
        let code = format!("mcpc_{client_id}");
        insert_code_with(state, &code, client_id, sub, Some(RES)).await;
        code
    }

    fn form(grant_type: &str, client_id: &str) -> TokenForm {
        TokenForm {
            grant_type: grant_type.to_string(),
            client_id: Some(client_id.to_string()),
            ..bare_form()
        }
    }

    async fn call(
        state: &AppState,
        mut f: TokenForm,
        client_id: &str,
        auth: Auth<'_>,
    ) -> Result<TokenResponse, Refused> {
        let mut headers = h("localhost:8433", None);
        match auth {
            Auth::Nothing => {}
            Auth::Post(secret) => f.client_secret = Some(secret.to_string()),
            Auth::Basic(secret) => {
                f.client_id = None;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{client_id}:{secret}"));
                headers.insert(
                    header::AUTHORIZATION,
                    format!("Basic {encoded}").parse().unwrap(),
                );
            }
        }
        token_inner(state, &headers, f)
            .await
            .map(|r| r.0)
            .map_err(|e| Refused {
                status: e.status,
                error: e.body.error,
                challenge: e.challenge,
            })
    }

    async fn exchange(
        state: &AppState,
        code: &str,
        client_id: &str,
        auth: Auth<'_>,
    ) -> Result<TokenResponse, Refused> {
        let mut f = form("authorization_code", client_id);
        f.code = Some(code.to_string());
        f.code_verifier = Some(VERIFIER.to_string());
        call(state, f, client_id, auth).await
    }

    async fn refresh(
        state: &AppState,
        refresh_token: &str,
        client_id: &str,
        auth: Auth<'_>,
    ) -> Result<TokenResponse, Refused> {
        let mut f = form("refresh_token", client_id);
        f.refresh_token = Some(refresh_token.to_string());
        call(state, f, client_id, auth).await
    }

    fn accepted(result: Result<TokenResponse, Refused>) -> TokenResponse {
        result.unwrap_or_else(|e| panic!("request was refused: {e:?}"))
    }

    fn refused(result: Result<TokenResponse, Refused>) -> Refused {
        match result {
            Ok(_) => panic!("request was accepted"),
            Err(e) => e,
        }
    }

    fn assert_refused(result: Result<TokenResponse, Refused>, status: StatusCode, error: &str) {
        let e = refused(result);
        assert_eq!((e.status, e.error.as_str()), (status, error));
    }

    async fn sql(state: &AppState, query: &'static str) {
        state
            .db
            .call(move |conn| {
                conn.execute(query, [])?;
                Ok(())
            })
            .await
            .unwrap();
    }

    /// Exchange a fresh code for a client's first token pair.
    async fn first_tokens(
        state: &AppState,
        client_id: &str,
        sub: &str,
        method: ClientAuth,
    ) -> TokenResponse {
        let code = code_for(state, client_id, sub, method).await;
        let auth = if method == ClientAuth::None {
            Auth::Nothing
        } else {
            Auth::Post(SECRET)
        };
        accepted(exchange(state, &code, client_id, auth).await)
    }

    // -- authorization_code ------------------------------------------------

    #[tokio::test]
    async fn code_confidential_without_secret_is_401_and_code_survives() {
        let state = app_state("http://localhost:8433").await;
        for (client, method) in [
            ("post", ClientAuth::SecretPost),
            ("basic", ClientAuth::SecretBasic),
        ] {
            let code = code_for(&state, client, "sub-1", method).await;
            let e = refused(exchange(&state, &code, client, Auth::Nothing).await);
            assert_eq!(e.status, StatusCode::UNAUTHORIZED);
            assert_eq!(e.error, "invalid_client");
            assert!(!e.challenge, "no Basic attempt, no challenge");
            accepted(exchange(&state, &code, client, Auth::Post(SECRET)).await);
        }
    }

    #[tokio::test]
    async fn code_wrong_secret_is_401_and_code_survives() {
        let state = app_state("http://localhost:8433").await;
        let code = code_for(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        assert_refused(
            exchange(&state, &code, "cid", Auth::Post("wrong")).await,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        );
        let e = refused(exchange(&state, &code, "cid", Auth::Basic("wrong")).await);
        assert_eq!(e.status, StatusCode::UNAUTHORIZED);
        assert!(
            e.challenge,
            "a failed Basic attempt carries WWW-Authenticate"
        );
        accepted(exchange(&state, &code, "cid", Auth::Basic(SECRET)).await);
    }

    #[tokio::test]
    async fn code_basic_auth_ok() {
        let state = app_state("http://localhost:8433").await;
        let code = code_for(&state, "cid", "sub-1", ClientAuth::SecretBasic).await;
        accepted(exchange(&state, &code, "cid", Auth::Basic(SECRET)).await);
    }

    #[tokio::test]
    async fn code_post_auth_ok() {
        let state = app_state("http://localhost:8433").await;
        let code = code_for(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        accepted(exchange(&state, &code, "cid", Auth::Post(SECRET)).await);
    }

    #[tokio::test]
    async fn code_secret_transport_need_not_match_registered_method() {
        let state = app_state("http://localhost:8433").await;
        let a = code_for(&state, "basic-client", "sub-1", ClientAuth::SecretBasic).await;
        accepted(exchange(&state, &a, "basic-client", Auth::Post(SECRET)).await);
        let b = code_for(&state, "post-client", "sub-1", ClientAuth::SecretPost).await;
        accepted(exchange(&state, &b, "post-client", Auth::Basic(SECRET)).await);
    }

    #[tokio::test]
    async fn code_public_client_without_secret_ok() {
        let state = app_state("http://localhost:8433").await;
        let code = code_for(&state, "cid", "sub-1", ClientAuth::None).await;
        accepted(exchange(&state, &code, "cid", Auth::Nothing).await);
        // A secret sent by a public client is ignored, right or wrong.
        insert_code_with(&state, "again", "cid", "sub-1", Some(RES)).await;
        accepted(exchange(&state, "again", "cid", Auth::Post("whatever")).await);
    }

    #[tokio::test]
    async fn code_legacy_client_secret_optional() {
        let state = app_state("http://localhost:8433").await;
        let c1 = code_for(&state, "legacy", "sub-1", ClientAuth::SecretPost).await;
        sql(
            &state,
            "UPDATE mcp_clients SET token_endpoint_auth_method = NULL",
        )
        .await;
        accepted(exchange(&state, &c1, "legacy", Auth::Nothing).await);

        insert_code_with(&state, "c2", "legacy", "sub-1", Some(RES)).await;
        assert_refused(
            exchange(&state, "c2", "legacy", Auth::Post("wrong")).await,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        );
        insert_code_with(&state, "c3", "legacy", "sub-1", Some(RES)).await;
        accepted(exchange(&state, "c3", "legacy", Auth::Post(SECRET)).await);
        // The wrong-secret attempt did not consume c2.
        accepted(exchange(&state, "c2", "legacy", Auth::Basic(SECRET)).await);
    }

    #[tokio::test]
    async fn code_from_other_client_is_invalid_grant_and_burned() {
        let state = app_state("http://localhost:8433").await;
        let code = code_for(&state, "client-a", "sub-1", ClientAuth::SecretPost).await;
        seed_client(&state, "client-b", REDIRECT).await;
        assert_refused(
            exchange(&state, &code, "client-b", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
        assert_refused(
            exchange(&state, &code, "client-a", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
    }

    #[tokio::test]
    async fn code_resource_mismatch_is_invalid_target() {
        let state = app_state("http://localhost:8433").await;
        let code = code_for(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        let mut f = form("authorization_code", "cid");
        f.code = Some(code);
        f.code_verifier = Some(VERIFIER.to_string());
        f.resource = Some(OTHER_RES.to_string());
        assert_refused(
            call(&state, f, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_target",
        );
    }

    #[tokio::test]
    async fn code_disallowed_resource_is_invalid_target() {
        let state = app_state("http://localhost:8433").await;
        seed_client(&state, "cid", REDIRECT).await;
        seed_account(&state, "sub-1").await;
        insert_code_with(&state, "no-resource", "cid", "sub-1", None).await;
        let mut f = form("authorization_code", "cid");
        f.code = Some("no-resource".to_string());
        f.code_verifier = Some(VERIFIER.to_string());
        f.resource = Some("http://evil.example/mcp".to_string());
        assert_refused(
            call(&state, f, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_target",
        );
    }

    #[tokio::test]
    async fn code_unknown_client_is_401() {
        let state = app_state("http://localhost:8433").await;
        assert_refused(
            exchange(&state, "mcpc_x", "nobody", Auth::Post(SECRET)).await,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        );
        let e = refused(exchange(&state, "mcpc_x", "nobody", Auth::Basic(SECRET)).await);
        assert!(e.challenge);
    }

    #[tokio::test]
    async fn code_requires_client_id_code_and_verifier() {
        let state = app_state("http://localhost:8433").await;
        let mut f = form("authorization_code", "cid");
        f.client_id = None;
        f.code = Some("c".to_string());
        assert_refused(
            call(&state, f, "cid", Auth::Nothing).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
        seed_client(&state, "cid", REDIRECT).await;
        let mut f = form("authorization_code", "cid");
        f.code_verifier = Some(VERIFIER.to_string());
        assert_refused(
            call(&state, f, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
        let mut f = form("authorization_code", "cid");
        f.code = Some("c".to_string());
        assert_refused(
            call(&state, f, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
    }

    #[tokio::test]
    async fn token_responses_are_no_store() {
        let state = app_state("http://localhost:8433").await;
        let code = code_for(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        let routed =
            |f: TokenForm| token(State(state.clone()), h("localhost:8433", None), Ok(Form(f)));

        let mut f = form("authorization_code", "cid");
        f.code = Some(code);
        f.code_verifier = Some(VERIFIER.to_string());
        f.client_secret = Some(SECRET.to_string());
        let ok = routed(f).await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(ok.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(ok.headers()[header::PRAGMA], "no-cache");

        let mut f = form("authorization_code", "cid");
        f.code = Some("gone".to_string());
        f.code_verifier = Some(VERIFIER.to_string());
        f.client_secret = Some(SECRET.to_string());
        let err = routed(f).await;
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert_eq!(err.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(err.headers()[header::PRAGMA], "no-cache");

        let mut f = form("authorization_code", "cid");
        f.client_secret = Some("wrong".to_string());
        let unauth = routed(f).await;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(unauth.headers()[header::CACHE_CONTROL], "no-store");
        assert!(unauth.headers().get(header::WWW_AUTHENTICATE).is_none());

        let encoded = base64::engine::general_purpose::STANDARD.encode("cid:wrong");
        let mut hm = h("localhost:8433", None);
        hm.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        let unauth = token(
            State(state.clone()),
            hm,
            Ok(Form(bare_form_for("authorization_code"))),
        )
        .await;
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(unauth.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            unauth.headers()[header::WWW_AUTHENTICATE],
            "Basic realm=\"google-mcp\""
        );
    }

    fn bare_form_for(grant: &str) -> TokenForm {
        TokenForm {
            grant_type: grant.to_string(),
            ..bare_form()
        }
    }

    #[tokio::test]
    async fn register_responses_are_no_store() {
        let state = app_state("http://localhost:8433").await;
        let ok = register(State(state.clone()), Ok(Json(reg_req(None)))).await;
        assert_eq!(ok.status(), StatusCode::CREATED);
        assert_eq!(ok.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(ok.headers()[header::PRAGMA], "no-cache");
        let err = register(State(state), Ok(Json(reg_req(Some("private_key_jwt"))))).await;
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert_eq!(err.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(err.headers()[header::PRAGMA], "no-cache");
    }

    #[tokio::test]
    async fn access_token_lifetime_from_config() {
        let state = app_state_with("http://localhost:8433", 120, 10).await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        assert_eq!(first.expires_in, 120);
        let claims = crate::oauth::jwt::verify(&first.access_token, &[0u8; 32], |_| true).unwrap();
        assert_eq!(claims.exp - claims.iat, 120);

        let second =
            accepted(refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await);
        assert_eq!(second.expires_in, 120);
        let claims = crate::oauth::jwt::verify(&second.access_token, &[0u8; 32], |_| true).unwrap();
        assert_eq!(claims.exp - claims.iat, 120);
    }

    #[tokio::test]
    async fn unknown_grant_type_is_400() {
        let state = app_state("http://localhost:8433").await;
        assert_refused(
            call(&state, form("password", "cid"), "cid", Auth::Nothing).await,
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
        );
    }

    // -- refresh_token -----------------------------------------------------

    #[tokio::test]
    async fn refresh_rotates_and_old_token_dies_after_grace() {
        let state = app_state_with("http://localhost:8433", 3600, 0).await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretPost).await;

        let second =
            accepted(refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await);
        assert_ne!(second.refresh_token, first.refresh_token);
        assert!(second.refresh_token.starts_with("mcpr_"));
        let claims = crate::oauth::jwt::verify(&second.access_token, &[0u8; 32], |_| true).unwrap();
        assert_eq!(claims.sub, "sub-1");

        assert_refused(
            refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
        assert_refused(
            refresh(&state, &second.refresh_token, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
    }

    #[tokio::test]
    async fn refresh_old_token_dies_once_grace_has_elapsed() {
        let state = app_state_with("http://localhost:8433", 3600, 10).await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        let second =
            accepted(refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await);
        sql(
            &state,
            "UPDATE mcp_refresh_tokens SET used_at = used_at - 11 WHERE used_at IS NOT NULL",
        )
        .await;
        assert_refused(
            refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
        assert_refused(
            refresh(&state, &second.refresh_token, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
    }

    #[tokio::test]
    async fn refresh_confidential_without_secret_is_401_family_untouched() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        for _ in 0..3 {
            assert_refused(
                refresh(&state, &first.refresh_token, "cid", Auth::Nothing).await,
                StatusCode::UNAUTHORIZED,
                "invalid_client",
            );
        }
        accepted(refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await);
    }

    #[tokio::test]
    async fn refresh_wrong_secret_is_401_family_untouched() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretBasic).await;
        assert_refused(
            refresh(&state, &first.refresh_token, "cid", Auth::Post("wrong")).await,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        );
        let e = refused(refresh(&state, &first.refresh_token, "cid", Auth::Basic("wrong")).await);
        assert!(e.challenge);
        accepted(refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await);
    }

    #[tokio::test]
    async fn refresh_wrong_client_burns_family() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "client-a", "sub-1", ClientAuth::SecretPost).await;
        seed_client(&state, "client-b", REDIRECT).await;
        assert_refused(
            refresh(&state, &first.refresh_token, "client-b", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
        assert_refused(
            refresh(&state, &first.refresh_token, "client-a", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
    }

    #[tokio::test]
    async fn refresh_in_grace_reuse_returns_same_token() {
        let state = app_state_with("http://localhost:8433", 3600, 10).await;
        let t = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        let auth = || Auth::Post(SECRET);

        let s1 = accepted(refresh(&state, &t.refresh_token, "cid", auth()).await);
        let again = accepted(refresh(&state, &t.refresh_token, "cid", auth()).await);
        assert_eq!(s1.refresh_token, again.refresh_token);
        assert_ne!(s1.refresh_token, t.refresh_token);
        let claims = crate::oauth::jwt::verify(&again.access_token, &[0u8; 32], |_| true).unwrap();
        assert_eq!(claims.sub, "sub-1");

        // The shared successor rotates normally; the family never forked.
        let s2 = accepted(refresh(&state, &s1.refresh_token, "cid", auth()).await);
        assert_ne!(s2.refresh_token, s1.refresh_token);
        // Reusing T now would hand out a spent successor: the family burns.
        assert_refused(
            refresh(&state, &t.refresh_token, "cid", auth()).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
        assert_refused(
            refresh(&state, &s2.refresh_token, "cid", auth()).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
    }

    #[tokio::test]
    async fn refresh_revoked_sub_invalid_grant() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        revocations::revoke(&state.db, "sub-1", now_secs() as i64)
            .await
            .unwrap();
        assert_refused(
            refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
        // The family is gone, not just refused.
        let rows: i64 = state
            .db
            .call(|conn| {
                Ok(conn.query_row("SELECT COUNT(*) FROM mcp_refresh_tokens", [], |r| r.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[tokio::test]
    async fn refresh_deleted_account_invalid_grant() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "cid", "sub-2", ClientAuth::SecretPost).await;
        accounts::delete(&state.db, "sub-2").await.unwrap();
        assert_refused(
            refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
    }

    #[tokio::test]
    async fn refresh_expired_invalid_grant() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        sql(&state, "UPDATE mcp_refresh_tokens SET expires_at = 1").await;
        assert_refused(
            refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
    }

    #[tokio::test]
    async fn refresh_family_max_age_invalid_grant() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        sql(
            &state,
            "UPDATE mcp_refresh_tokens SET family_issued_at = family_issued_at - 91 * 24 * 3600",
        )
        .await;
        assert_refused(
            refresh(&state, &first.refresh_token, "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
    }

    #[tokio::test]
    async fn refresh_resource_mismatch_invalid_target_token_still_usable() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        for resource in [OTHER_RES, "http://evil.example/mcp"] {
            let mut f = form("refresh_token", "cid");
            f.refresh_token = Some(first.refresh_token.clone());
            f.resource = Some(resource.to_string());
            assert_refused(
                call(&state, f, "cid", Auth::Post(SECRET)).await,
                StatusCode::BAD_REQUEST,
                "invalid_target",
            );
        }
        let mut f = form("refresh_token", "cid");
        f.refresh_token = Some(first.refresh_token.clone());
        f.resource = Some(RES.to_string());
        accepted(call(&state, f, "cid", Auth::Post(SECRET)).await);
    }

    #[tokio::test]
    async fn refresh_unknown_token_invalid_grant() {
        let state = app_state("http://localhost:8433").await;
        seed_client(&state, "cid", REDIRECT).await;
        assert_refused(
            refresh(&state, "mcpr_unknown", "cid", Auth::Post(SECRET)).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        );
    }

    #[tokio::test]
    async fn refresh_with_basic_auth_ok() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretBasic).await;
        accepted(refresh(&state, &first.refresh_token, "cid", Auth::Basic(SECRET)).await);
    }

    #[tokio::test]
    async fn refresh_public_client_needs_no_secret() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::None).await;
        accepted(refresh(&state, &first.refresh_token, "cid", Auth::Nothing).await);
    }

    #[tokio::test]
    async fn refresh_requires_token_and_client_id() {
        let state = app_state("http://localhost:8433").await;
        seed_client(&state, "cid", REDIRECT).await;
        let mut f = form("refresh_token", "cid");
        f.client_id = None;
        f.refresh_token = Some("mcpr_x".to_string());
        assert_refused(
            call(&state, f, "cid", Auth::Nothing).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
        assert_refused(
            call(
                &state,
                form("refresh_token", "cid"),
                "cid",
                Auth::Post(SECRET),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
    }

    #[tokio::test]
    async fn refresh_failed_authentication_does_not_touch_the_table() {
        let state = app_state("http://localhost:8433").await;
        let first = first_tokens(&state, "cid", "sub-1", ClientAuth::SecretPost).await;
        let before: Vec<(String, Option<i64>, i64)> = state
            .db
            .call(|conn| {
                let mut stmt = conn
                    .prepare("SELECT token_hash, used_at, successor_ct IS NULL FROM mcp_refresh_tokens ORDER BY token_hash")?;
                let rows = stmt
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .unwrap();
        for auth in [Auth::Nothing, Auth::Post("wrong"), Auth::Basic("wrong")] {
            refused(refresh(&state, &first.refresh_token, "cid", auth).await);
        }
        let after: Vec<(String, Option<i64>, i64)> = state
            .db
            .call(|conn| {
                let mut stmt = conn
                    .prepare("SELECT token_hash, used_at, successor_ct IS NULL FROM mcp_refresh_tokens ORDER BY token_hash")?;
                let rows = stmt
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .unwrap();
        assert_eq!(before, after);
    }
}
