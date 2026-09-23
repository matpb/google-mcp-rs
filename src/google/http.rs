//! Shared `reqwest::Client`, agent-ID path-segment validation (guards
//! against `url`'s dot-segment normalization), and a response-body cap.

use std::time::Duration;

pub fn build() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("google-mcp/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Some(Duration::from_secs(30)))
        .build()
        .expect("reqwest client")
}

/// Cap for ordinary JSON API responses.
pub const MAX_API_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Cap for Drive download/export and Gmail attachment bodies.
pub const MAX_DOWNLOAD_BYTES: usize = 256 * 1024 * 1024;

/// A caller-supplied path segment or resource name failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid id: {0}")]
pub struct InvalidPathSegment(pub String);

/// RFC 3986 unreserved chars pass through unescaped; everything else
/// (`/ ? # % space @` included) is percent-encoded.
const UNRESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encode `s` for use as one URL path segment.
/// Rejects empty, literal `.`/`..` (only danger since `%` itself encodes), control chars.
pub fn seg(s: &str) -> Result<String, InvalidPathSegment> {
    if s.is_empty() {
        return Err(InvalidPathSegment("must not be empty".into()));
    }
    // Also covers `../x` style ids, in case an upstream decodes `%2F` before routing.
    if s.split(['/', '\\']).any(|part| part == "." || part == "..") {
        return Err(InvalidPathSegment(format!(
            "'{s}' is a dot-segment, not a valid resource id"
        )));
    }
    if s.chars().any(char::is_control) {
        return Err(InvalidPathSegment(
            "must not contain control characters".into(),
        ));
    }
    Ok(percent_encoding::utf8_percent_encode(s, UNRESERVED).to_string())
}

/// Validate and rebuild a People API resource name `<prefix>/<id>`.
/// `id` must match `[A-Za-z0-9_-]+`, so it can never contain `/` or `.`.
pub fn resource_name(s: &str, allowed_prefixes: &[&str]) -> Result<String, InvalidPathSegment> {
    let (prefix, id) = s
        .split_once('/')
        .ok_or_else(|| InvalidPathSegment(format!("expected `<prefix>/<id>`, got '{s}'")))?;
    if !allowed_prefixes.contains(&prefix) {
        return Err(InvalidPathSegment(format!(
            "unknown resource prefix '{prefix}' (expected one of {allowed_prefixes:?})"
        )));
    }
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(InvalidPathSegment(format!("invalid resource id '{id}'")));
    }
    Ok(format!("{prefix}/{id}"))
}

/// A response body was rejected before or during reading.
#[derive(Debug, thiserror::Error)]
pub enum ReadBodyError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("response body exceeds the {cap}-byte cap (at least {actual} bytes)")]
    TooLarge { cap: usize, actual: usize },
}

/// Pulled out of `read_body_capped` so the counting logic is testable
/// without a live `reqwest::Response`.
fn accumulate_capped(
    running_total: usize,
    chunk_len: usize,
    max_bytes: usize,
) -> Result<usize, ReadBodyError> {
    let total = running_total + chunk_len;
    if total > max_bytes {
        return Err(ReadBodyError::TooLarge {
            cap: max_bytes,
            actual: total,
        });
    }
    Ok(total)
}

/// Reads a body into memory, aborting once it would exceed `max_bytes`.
/// Checks `Content-Length` first; otherwise enforced per-chunk.
pub async fn read_body_capped(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, ReadBodyError> {
    if let Some(len) = resp.content_length()
        && len > max_bytes as u64
    {
        return Err(ReadBodyError::TooLarge {
            cap: max_bytes,
            actual: len as usize,
        });
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        accumulate_capped(buf.len(), chunk.len(), max_bytes)?;
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seg_rejects_empty_and_dot_segments() {
        assert!(seg("").is_err());
        assert!(seg(".").is_err());
        assert!(seg("..").is_err());
        assert!(seg("...").is_ok()); // three dots is not a dot-segment
        assert!(seg("../../gmail/v1/users/me/messages/send").is_err());
        assert!(seg("a/../b").is_err());
        assert!(seg("..\\x").is_err());
        assert!(seg("Q1/Q2!A1").is_ok());
    }

    #[test]
    fn seg_rejects_control_chars() {
        assert!(seg("abc\ndef").is_err());
        assert!(seg("abc\0def").is_err());
    }

    #[test]
    fn seg_encodes_reserved_chars_and_keeps_unreserved() {
        let encoded = seg("abc/gmail/v1?x=1#f").unwrap();
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('?'));
        assert!(!encoded.contains('#'));
        assert!(!encoded.contains(' '));

        let space_hash = seg("Sheet 1!A1:B2#x?y%z").unwrap();
        assert!(!space_hash.contains(' '));
        assert!(!space_hash.contains('#'));
        assert!(!space_hash.contains('?'));

        // Unreserved chars (ALPHA DIGIT - . _ ~) pass through unescaped.
        let id = seg("abc-DEF_123.~x").unwrap();
        assert_eq!(id, "abc-DEF_123.~x");
        assert!(seg("a@b").unwrap().contains("%40"));
    }

    #[test]
    fn drive_file_url_from_hostile_id_stays_under_files_path() {
        assert!(seg("../../gmail/v1/users/me/messages/send").is_err());
        let encoded = seg("abc%2F..%2Fgmail").unwrap();
        let url = url::Url::parse(&format!(
            "https://www.googleapis.com/drive/v3/files/{encoded}"
        ))
        .unwrap();
        assert!(url.path().starts_with("/drive/v3/files/"));
        assert_eq!(url.path().matches('/').count(), 4);
    }

    #[test]
    fn calendar_id_with_hash_stays_in_path_not_fragment() {
        let calendar_id = "en.usa#holiday@group.v.calendar.google.com";
        let encoded = seg(calendar_id).unwrap();
        let url = url::Url::parse(&format!(
            "https://www.googleapis.com/calendar/v3/calendars/{encoded}"
        ))
        .unwrap();
        assert!(url.fragment().is_none());
        assert!(url.path().starts_with("/calendar/v3/calendars/"));
        assert!(url.path().contains("holiday"));
    }

    #[test]
    fn sheets_range_with_space_encodes() {
        let range = seg("Sheet 1!A1:B2").unwrap();
        assert!(!range.contains(' '));
        let url = url::Url::parse(&format!(
            "https://sheets.googleapis.com/v4/spreadsheets/id/values/{range}"
        ))
        .unwrap();
        assert!(url.path().ends_with(range.as_str()));
    }

    #[test]
    fn resource_name_accepts_allowed_prefix_rejects_others() {
        let allowed = ["people", "contactGroups", "otherContacts"];
        assert_eq!(
            resource_name("people/c123", &allowed).unwrap(),
            "people/c123"
        );
        assert!(resource_name("people/../x", &allowed).is_err());
        assert!(resource_name("evil/c1", &allowed).is_err());
        assert!(resource_name("people/", &allowed).is_err());
        assert!(resource_name("people", &allowed).is_err());
    }

    #[test]
    fn accumulate_capped_rejects_over_cap_bodies() {
        assert_eq!(accumulate_capped(0, 10, 100).unwrap(), 10);
        assert!(accumulate_capped(95, 10, 100).is_err());
        let err = accumulate_capped(0, 101, 100).unwrap_err();
        match err {
            ReadBodyError::TooLarge { cap, actual } => {
                assert_eq!(cap, 100);
                assert_eq!(actual, 101);
            }
            _ => panic!("expected TooLarge"),
        }
    }
}
