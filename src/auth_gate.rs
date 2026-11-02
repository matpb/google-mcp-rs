//! 401 + WWW-Authenticate middleware for the `/mcp` endpoint.
//!
//! Fully verifies the bearer JWT (signature, expiry, `aud`) so an invalid
//! or forged token never reaches a tool handler as a 200. On success the
//! verified `Claims` are inserted into the request extensions so downstream
//! handlers (`credentials::resolve_google`) don't re-verify.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode};

use crate::host_guard;
use crate::oauth::JwtError;
use crate::oauth::jwt::{Claims, verify};
use crate::oauth::proxy::issuer_from_headers;
use crate::state::AppState;

pub async fn require_bearer(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let iss = issuer_from_headers(req.headers(), &state.config.base_url);
    let resource_metadata = format!("{iss}/.well-known/oauth-protected-resource/mcp");

    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);

    let Some(auth_header) = auth_header else {
        return challenge(&resource_metadata, None);
    };
    let Some(token) = auth_header.strip_prefix("Bearer ") else {
        return challenge(&resource_metadata, Some("malformed Authorization header"));
    };

    let allowed_hosts =
        host_guard::build_allowed_hosts(&state.config.base_url, &state.config.allowed_hosts);
    match verify(token.trim(), &state.config.jwt_secret, |aud| {
        host_guard::aud_is_valid(aud, &allowed_hosts)
    }) {
        Ok(claims) => {
            if !lifetime_ok(&claims, state.config.access_token_lifetime_secs) {
                return challenge(
                    &resource_metadata,
                    Some("token lifetime exceeds server policy"),
                );
            }
            match crate::storage::revocations::not_before(&state.db, &claims.sub).await {
                Ok(Some(nb)) if (claims.iat as i64) <= nb => {
                    return challenge(&resource_metadata, Some("token revoked"));
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(err = ?e, "revocation lookup failed");
                    return challenge(&resource_metadata, Some("invalid token"));
                }
            }
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(e) => challenge(&resource_metadata, Some(invalid_token_reason(&e))),
    }
}

/// Slack on the configured lifetime, matching the verifier's clock leeway.
const LIFETIME_SLACK_SECS: u64 = 60;

/// Rejects tokens minted with a longer lifetime than the server allows now.
fn lifetime_ok(claims: &Claims, max_lifetime_secs: u64) -> bool {
    claims.exp.saturating_sub(claims.iat) <= max_lifetime_secs.saturating_add(LIFETIME_SLACK_SECS)
}

fn invalid_token_reason(e: &JwtError) -> &'static str {
    match e {
        JwtError::Expired => "token expired",
        JwtError::BadSignature => "invalid signature",
        JwtError::AudienceMismatch => "invalid or missing audience",
        JwtError::Sign | JwtError::Malformed => "invalid token",
    }
}

/// `reason` present => `error="invalid_token"` challenge (401). `None` keeps
/// the plain discovery challenge used when no bearer token was sent at all.
fn challenge(resource_metadata: &str, reason: Option<&str>) -> Response {
    let value = match reason {
        Some(desc) => format!(
            r#"Bearer error="invalid_token", error_description="{desc}", resource_metadata="{resource_metadata}""#
        ),
        None => format!(r#"Bearer resource_metadata="{resource_metadata}""#),
    };
    let mut resp = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    if let Ok(v) = HeaderValue::from_str(&value) {
        resp.headers_mut().insert(http::header::WWW_AUTHENTICATE, v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(lifetime: u64) -> Claims {
        Claims {
            iss: "http://localhost:8433".to_string(),
            sub: "sub-1".to_string(),
            iat: 1_000,
            exp: 1_000 + lifetime,
            aud: "http://localhost:8433/mcp".to_string(),
        }
    }

    #[test]
    fn lifetime_ok_allows_up_to_the_policy_plus_slack() {
        assert!(lifetime_ok(&claims(3600), 3600));
        assert!(lifetime_ok(&claims(3660), 3600));
        assert!(!lifetime_ok(&claims(3661), 3600));
        assert!(!lifetime_ok(&claims(30 * 24 * 3600), 3600));
        assert!(lifetime_ok(&claims(30 * 24 * 3600), 30 * 24 * 3600));
    }

    #[test]
    fn lifetime_ok_survives_odd_claims() {
        let mut c = claims(0);
        c.exp = 5;
        c.iat = 10;
        assert!(lifetime_ok(&c, 60));
        assert!(!lifetime_ok(&claims(u64::MAX - 1_000), 3600));
        assert!(lifetime_ok(&claims(3600), u64::MAX));
    }
}
