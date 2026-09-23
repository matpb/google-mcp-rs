//! Per-request credential resolution: extract the bearer JWT from the
//! request, verify its signature + audience, look up the live Google
//! access token, transparently refresh if needed.

use http::request::Parts;

use crate::google::session::{GoogleAccountSession, SessionCache, SessionError};
use crate::host_guard::{self, AllowedHost};
use crate::oauth::JwtError;
use crate::oauth::jwt::{Claims, verify};

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

/// Prefers `Claims` the `require_bearer` middleware already verified
/// (`parts.extensions`); falls back to verifying the header itself.
pub async fn resolve_google(
    parts: &Parts,
    jwt_secret: &[u8],
    allowed_hosts: &[AllowedHost],
    session_cache: &SessionCache,
) -> Result<GoogleAccountSession, CredentialsError> {
    let claims = match parts.extensions.get::<Claims>() {
        Some(c) => c.clone(),
        None => {
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
            verify(token, jwt_secret, |aud| {
                host_guard::aud_is_valid(aud, allowed_hosts)
            })?
        }
    };

    let session = session_cache.resolve(&claims.sub).await?;
    Ok(session)
}
