//! Minimal HS256 JWT signing and verification for MCP-issued bearer tokens.
//!
//! HS256 only, over a server-held secret, built on the audited
//! `hmac`/`sha2` primitives instead of a general-purpose JWT crate.
//! Tokens are bound to:
//! - `iss`: the dynamic per-request issuer (computed from Host + scheme).
//! - `sub`: the user's stable Google `sub`.
//! - `aud`: the resource the token is good for (`{iss}/mcp`), per RFC 8707.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::JwtError;

/// 30 days.
pub const TOKEN_LIFETIME_SECS: u64 = 30 * 24 * 3600;

const MAX_TOKEN_LEN: usize = 8 * 1024;
const LEEWAY_SECS: i64 = 60;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub aud: String,
}

/// `typ` first, matching jsonwebtoken 9's HS256 header exactly.
#[derive(Serialize)]
struct JwtHeader {
    typ: &'static str,
    alg: &'static str,
}

#[derive(Deserialize)]
struct DecodedHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    crit: Option<serde_json::Value>,
}

fn mac_over(secret: &[u8], data: &[u8]) -> Result<HmacSha256, JwtError> {
    HmacSha256::new_from_slice(secret)
        .map(|mut mac| {
            mac.update(data);
            mac
        })
        .map_err(|_| JwtError::Sign)
}

/// HMAC-SHA256 over `data`. Exposed for the RFC 7515 test vector.
fn hmac_sha256(secret: &[u8], data: &[u8]) -> Result<Vec<u8>, JwtError> {
    Ok(mac_over(secret, data)?.finalize().into_bytes().to_vec())
}

fn decode_b64(part: &str) -> Result<Vec<u8>, JwtError> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| JwtError::Malformed)
}

pub fn sign(secret: &[u8], claims: &Claims) -> Result<String, JwtError> {
    let header = serde_json::to_vec(&JwtHeader {
        typ: "JWT",
        alg: "HS256",
    })
    .map_err(|_| JwtError::Sign)?;
    let payload = serde_json::to_vec(claims).map_err(|_| JwtError::Sign)?;

    let b64h = URL_SAFE_NO_PAD.encode(header);
    let b64p = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{b64h}.{b64p}");
    let sig = hmac_sha256(secret, signing_input.as_bytes())?;
    let b64s = URL_SAFE_NO_PAD.encode(sig);

    Ok(format!("{signing_input}.{b64s}"))
}

/// Verify signature, header shape, expiry, and `aud` (via caller's
/// allowlist check). A missing or non-allowlisted `aud` is rejected.
pub fn verify(
    token: &str,
    secret: &[u8],
    audience_ok: impl FnOnce(&str) -> bool,
) -> Result<Claims, JwtError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(JwtError::Malformed);
    }

    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed);
    };
    if h.is_empty() || p.is_empty() || s.is_empty() {
        return Err(JwtError::Malformed);
    }

    let header_bytes = decode_b64(h)?;
    let header: DecodedHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::Malformed)?;
    if header.alg != "HS256" {
        return Err(JwtError::Malformed);
    }
    if header.typ.is_some_and(|typ| typ != "JWT") {
        return Err(JwtError::Malformed);
    }
    if header.crit.is_some() {
        return Err(JwtError::Malformed);
    }

    let sig_bytes = decode_b64(s)?;
    let signing_input = format!("{h}.{p}");
    let mac = mac_over(secret, signing_input.as_bytes())?;
    mac.verify_slice(&sig_bytes)
        .map_err(|_| JwtError::BadSignature)?;

    let payload_bytes = decode_b64(p)?;
    let claims: Claims = serde_json::from_slice(&payload_bytes).map_err(|_| JwtError::Malformed)?;

    let now = now_secs() as i64;
    if claims.exp as i64 <= now - LEEWAY_SECS {
        return Err(JwtError::Expired);
    }
    if claims.iat as i64 > now + LEEWAY_SECS {
        return Err(JwtError::Malformed);
    }
    if !audience_ok(&claims.aud) {
        return Err(JwtError::AudienceMismatch);
    }

    Ok(claims)
}

pub fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Vec<u8> {
        b"a-very-long-secret-of-at-least-32-bytes-............".to_vec()
    }

    fn claims(aud: &str) -> Claims {
        let now = now_secs();
        Claims {
            iss: "https://example/".to_string(),
            sub: "google-sub-123".to_string(),
            iat: now,
            exp: now + 60,
            aud: aud.to_string(),
        }
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Bypasses `sign` so tests can build malformed/type-confused tokens.
    fn raw_token(header_json: &str, payload_json: &str, secret: &[u8]) -> String {
        let h = b64(header_json.as_bytes());
        let p = b64(payload_json.as_bytes());
        let signing_input = format!("{h}.{p}");
        let sig = hmac_sha256(secret, signing_input.as_bytes()).unwrap();
        format!("{signing_input}.{}", b64(&sig))
    }

    #[test]
    fn round_trip() {
        let aud = "https://example/mcp";
        let token = sign(&secret(), &claims(aud)).unwrap();
        let verified = verify(&token, &secret(), |a| a == aud).unwrap();
        assert_eq!(verified.sub, "google-sub-123");
        assert_eq!(verified.aud, aud);
    }

    #[test]
    fn tampered_payload_rejected() {
        let token = sign(&secret(), &claims("https://example/mcp")).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_payload = b64(
            br#"{"iss":"x","sub":"evil","iat":0,"exp":9999999999,"aud":"https://example/mcp"}"#,
        );
        parts[1] = &tampered_payload;
        let tampered = parts.join(".");
        let err = verify(&tampered, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::BadSignature));
    }

    #[test]
    fn tampered_signature_rejected() {
        let token = sign(&secret(), &claims("https://example/mcp")).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let bad_sig = b64(b"not-the-real-signature-bytes...");
        parts[2] = &bad_sig;
        let tampered = parts.join(".");
        let err = verify(&tampered, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::BadSignature));
    }

    #[test]
    fn alg_none_rejected() {
        let now = now_secs();
        let payload = format!(
            r#"{{"iss":"x","sub":"y","iat":{now},"exp":{},"aud":"a"}}"#,
            now + 60
        );
        let token = raw_token(r#"{"typ":"JWT","alg":"none"}"#, &payload, &secret());
        let err = verify(&token, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn alg_hs384_rejected() {
        let now = now_secs();
        let payload = format!(
            r#"{{"iss":"x","sub":"y","iat":{now},"exp":{},"aud":"a"}}"#,
            now + 60
        );
        let token = raw_token(r#"{"typ":"JWT","alg":"HS384"}"#, &payload, &secret());
        let err = verify(&token, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn header_with_crit_rejected() {
        let now = now_secs();
        let payload = format!(
            r#"{{"iss":"x","sub":"y","iat":{now},"exp":{},"aud":"a"}}"#,
            now + 60
        );
        let token = raw_token(
            r#"{"typ":"JWT","alg":"HS256","crit":["exp"]}"#,
            &payload,
            &secret(),
        );
        let err = verify(&token, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn expired_rejected() {
        let mut c = claims("https://example/mcp");
        c.iat = now_secs() - 1000;
        c.exp = now_secs() - 500;
        let token = sign(&secret(), &c).unwrap();
        let err = verify(&token, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Expired));
    }

    #[test]
    fn iat_in_future_rejected() {
        let mut c = claims("https://example/mcp");
        c.iat = now_secs() + 1000;
        let token = sign(&secret(), &c).unwrap();
        let err = verify(&token, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn missing_aud_rejected() {
        let now = now_secs();
        let payload = format!(r#"{{"iss":"x","sub":"y","iat":{now},"exp":{}}}"#, now + 60);
        let token = raw_token(r#"{"typ":"JWT","alg":"HS256"}"#, &payload, &secret());
        let err = verify(&token, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn aud_as_array_rejected() {
        let now = now_secs();
        let payload = format!(
            r#"{{"iss":"x","sub":"y","iat":{now},"exp":{},"aud":["a","b"]}}"#,
            now + 60
        );
        let token = raw_token(r#"{"typ":"JWT","alg":"HS256"}"#, &payload, &secret());
        let err = verify(&token, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn exp_as_string_rejected() {
        let now = now_secs();
        let payload = format!(
            r#"{{"iss":"x","sub":"y","iat":{now},"exp":"{}","aud":"a"}}"#,
            now + 60
        );
        let token = raw_token(r#"{"typ":"JWT","alg":"HS256"}"#, &payload, &secret());
        let err = verify(&token, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = sign(&secret(), &claims("https://example/mcp")).unwrap();
        let err = verify(
            &token,
            b"a-completely-different-secret-of-32-bytes-............",
            |_| true,
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::BadSignature));
    }

    #[test]
    fn two_part_token_rejected() {
        let err = verify("aa.bb", &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn four_part_token_rejected() {
        let err = verify("aa.bb.cc.dd", &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn padded_base64_rejected() {
        let token = sign(&secret(), &claims("https://example/mcp")).unwrap();
        let padded = format!("{token}=");
        let err = verify(&padded, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn oversize_token_rejected() {
        let huge = "a".repeat(MAX_TOKEN_LEN + 1);
        let token = format!("{huge}.bb.cc");
        let err = verify(&token, &secret(), |_| true).unwrap_err();
        assert!(matches!(err, JwtError::Malformed));
    }

    #[test]
    fn jsonwebtoken_9_format_token_accepted() {
        // jsonwebtoken 9's exact header shape and base64url-no-pad encoding.
        let now = now_secs();
        let payload = format!(
            r#"{{"iss":"https://example/","sub":"google-sub-123","iat":{now},"exp":{},"aud":"https://example/mcp"}}"#,
            now + 60
        );
        let token = raw_token(r#"{"typ":"JWT","alg":"HS256"}"#, &payload, &secret());
        let verified = verify(&token, &secret(), |a| a == "https://example/mcp").unwrap();
        assert_eq!(verified.sub, "google-sub-123");
    }

    #[test]
    fn audience_mismatch_rejected() {
        let token = sign(&secret(), &claims("https://a/mcp")).unwrap();
        let err = verify(&token, &secret(), |a| a == "https://b/mcp").unwrap_err();
        assert!(matches!(err, JwtError::AudienceMismatch));
    }

    #[test]
    fn rfc7515_appendix_a1_hmac_vector() {
        // Payload has no aud/sub, so this drives the MAC directly.
        let key_b64url = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
        let key = URL_SAFE_NO_PAD.decode(key_b64url).unwrap();
        let signing_input = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let expected_sig = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = URL_SAFE_NO_PAD.decode(expected_sig).unwrap();
        let actual = hmac_sha256(&key, signing_input.as_bytes()).unwrap();
        assert_eq!(actual, expected);
    }
}
