//! 401 + WWW-Authenticate middleware for the `/mcp` endpoint.
//!
//! When a request to `/mcp` arrives without a `Bearer` token, we respond
//! with `401 Unauthorized` and a `WWW-Authenticate` header pointing at our
//! `/.well-known/oauth-protected-resource/mcp` document so MCP clients
//! (Claude.ai, ChatGPT, etc.) can discover the OAuth flow.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode};

use crate::oauth::proxy::issuer_from_headers;
use crate::state::AppState;

pub async fn require_bearer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let has_bearer = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer "));

    if has_bearer {
        return next.run(req).await;
    }

    let iss = issuer_from_headers(req.headers(), &state.config.base_url);
    let resource_metadata = format!("{iss}/.well-known/oauth-protected-resource/mcp");
    let challenge = format!(r#"Bearer resource_metadata="{resource_metadata}""#);
    let mut resp = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    if let Ok(v) = HeaderValue::from_str(&challenge) {
        resp.headers_mut().insert(http::header::WWW_AUTHENTICATE, v);
    }
    resp
}
