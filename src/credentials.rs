//! Per-request credential resolution: extract the bearer JWT from the
//! request, verify its signature + audience, look up the live Google
//! access token, transparently refresh if needed.

use http::request::Parts;

use crate::google::session::{GoogleAccountSession, SessionCache, SessionError};
use crate::oauth::JwtError;
use crate::oauth::jwt::verify;
use crate::oauth::proxy::issuer_from_headers;

#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    #[error("missing Authorization header")]
    Missing,
    #[error("malformed Authorization header (expected `Bearer <token>`)")]
    Malformed,
    #[error("invalid JWT: {0}")]
    Jwt(#[from] JwtError),
    #[error("session: {0}")]
    Session(#[from] SessionError),
}

pub async fn resolve_google(
    parts: &Parts,
    jwt_secret: &[u8],
    base_url: &str,
    session_cache: &SessionCache,
) -> Result<GoogleAccountSession, CredentialsError> {
    let auth = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .ok_or(CredentialsError::Missing)?
        .to_str()
        .map_err(|_| CredentialsError::Malformed)?;
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(CredentialsError::Malformed)?
        .trim();

    let expected_aud = expected_audience_from_parts(parts, base_url);
    let claims = verify(token, jwt_secret, expected_aud.as_deref())?;

    let session = session_cache.resolve(&claims.sub).await?;
    Ok(session)
}

/// Compute the audience the JWT must be bound to, given the inbound
/// request's host + scheme. For loopback (localhost / 127.0.0.1) we skip
/// audience binding to keep local development frictionless — matching
/// cortex-client's behavior for tunnel deployments.
fn expected_audience_from_parts(parts: &Parts, base_url: &str) -> Option<String> {
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())?;
    if host.starts_with("localhost") || host.starts_with("127.0.0.1") {
        return None;
    }
    Some(format!(
        "{}/mcp",
        issuer_from_headers(&parts.headers, base_url)
    ))
}
