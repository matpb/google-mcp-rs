//! PKCE (RFC 7636) S256 challenge verification.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

/// Verify that `code_verifier` matches the previously stored `code_challenge`
/// produced via the `S256` method (`BASE64URL(SHA256(verifier))`).
pub fn verify_s256(code_verifier: &str, code_challenge: &str) -> bool {
    if code_verifier.is_empty() || code_challenge.is_empty() {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let computed = Base64UrlUnpadded::encode_string(&hasher.finalize());
    constant_time_eq(computed.as_bytes(), code_challenge.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge_for(verifier: &str) -> String {
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        Base64UrlUnpadded::encode_string(&h.finalize())
    }

    #[test]
    fn matches_known_vector() {
        // RFC 7636 Appendix B vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_s256(verifier, challenge));
    }

    #[test]
    fn rejects_wrong_verifier() {
        let v = "verifier-original";
        let c = challenge_for(v);
        assert!(!verify_s256("not-the-verifier", &c));
    }

    #[test]
    fn rejects_empty_inputs() {
        assert!(!verify_s256("", "x"));
        assert!(!verify_s256("x", ""));
        assert!(!verify_s256("", ""));
    }

    #[test]
    fn round_trip() {
        let v = "verifier-string-with-some-entropy-1234";
        assert!(verify_s256(v, &challenge_for(v)));
    }
}
