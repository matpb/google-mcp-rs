//! HS256 JWT signing and verification for MCP-issued bearer tokens.
//!
//! Tokens are bound to:
//! - `iss`: the dynamic per-request issuer (computed from Host + scheme).
//! - `sub`: the user's stable Google `sub`.
//! - `aud`: the resource the token is good for (`{iss}/mcp`), per RFC 8707.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use super::JwtError;

/// 30 days, matching cortex-client's default.
pub const TOKEN_LIFETIME_SECS: u64 = 30 * 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

pub fn sign(secret: &[u8], claims: &Claims) -> Result<String, JwtError> {
    let key = EncodingKey::from_secret(secret);
    encode(&Header::new(Algorithm::HS256), claims, &key).map_err(JwtError::Sign)
}

/// Verify a token's signature and (when `expected_audience` is `Some`) its
/// `aud` claim. Tokens issued before audience binding (no `aud`) are
/// accepted to preserve backwards compatibility, mirroring cortex-client.
pub fn verify(
    token: &str,
    secret: &[u8],
    expected_audience: Option<&str>,
) -> Result<Claims, JwtError> {
    let key = DecodingKey::from_secret(secret);
    let mut validation = Validation::new(Algorithm::HS256);
    // We don't use `validation.set_audience()` because we want to accept
    // tokens without `aud` (legacy), and to perform the comparison ourselves.
    validation.validate_aud = false;
    let data = decode::<Claims>(token, &key, &validation).map_err(JwtError::Verify)?;
    if let (Some(expected), Some(claim)) = (expected_audience, data.claims.aud.as_deref())
        && expected != claim
    {
        return Err(JwtError::AudienceMismatch);
    }
    Ok(data.claims)
}

pub fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Vec<u8> {
        b"a-very-long-secret-of-at-least-32-bytes-............".to_vec()
    }

    fn claims(aud: Option<&str>) -> Claims {
        let now = now_secs();
        Claims {
            iss: "https://example/".to_string(),
            sub: "google-sub-123".to_string(),
            iat: now,
            exp: now + 60,
            aud: aud.map(|s| s.to_string()),
        }
    }

    #[test]
    fn sign_and_verify_with_audience() {
        let aud = "https://example/mcp";
        let token = sign(&secret(), &claims(Some(aud))).unwrap();
        let verified = verify(&token, &secret(), Some(aud)).unwrap();
        assert_eq!(verified.sub, "google-sub-123");
        assert_eq!(verified.aud.as_deref(), Some(aud));
    }

    #[test]
    fn sign_and_verify_without_audience() {
        let token = sign(&secret(), &claims(None)).unwrap();
        // Even with an expected aud, a token without aud is accepted (legacy).
        let v = verify(&token, &secret(), Some("https://example/mcp")).unwrap();
        assert!(v.aud.is_none());
    }

    #[test]
    fn audience_mismatch_rejected() {
        let token = sign(&secret(), &claims(Some("https://a/mcp"))).unwrap();
        let err = verify(&token, &secret(), Some("https://b/mcp")).unwrap_err();
        assert!(matches!(err, JwtError::AudienceMismatch));
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = sign(&secret(), &claims(None)).unwrap();
        let err = verify(
            &token,
            b"a-completely-different-secret-of-32-bytes-............",
            None,
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::Verify(_)));
    }

    #[test]
    fn expired_token_rejected() {
        // jsonwebtoken's default Validation has leeway=60s, so push the
        // expiry well past it.
        let mut c = claims(None);
        c.iat = now_secs() - 1000;
        c.exp = now_secs() - 500;
        let token = sign(&secret(), &c).unwrap();
        let err = verify(&token, &secret(), None).unwrap_err();
        assert!(matches!(err, JwtError::Verify(_)));
    }
}
