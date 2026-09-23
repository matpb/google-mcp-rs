//! Host-header allowlist: rejects requests whose `Host` (or any
//! `X-Forwarded-Host` element) isn't recognized, mitigating DNS rebinding.
//! Also backs the RFC 8707 `aud` allowlist used by JWT verification.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::StatusCode;

use crate::state::AppState;

/// Loopback names, treated as one equivalence class accepting any port.
const LOOPBACK_NAMES: &[&str] = &["localhost", "127.0.0.1", "::1"];

pub fn is_loopback_name(host: &str) -> bool {
    LOOPBACK_NAMES.contains(&host)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedHost {
    pub host: String,
    pub port: Option<u16>,
}

/// Lowercase, strip IPv6 brackets, strip a trailing dot.
pub fn normalize_host(host: &str) -> String {
    let h = host.trim();
    let h = h
        .strip_prefix('[')
        .and_then(|r| r.find(']').map(|i| &r[..i]));
    let h = h.unwrap_or(host.trim());
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// Parse a `host`, `host:port`, `[ipv6]` or `[ipv6]:port` authority.
pub fn parse_authority(authority: &str) -> (String, Option<u16>) {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host = normalize_host(&rest[..end]);
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok());
        return (host, port);
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (normalize_host(h), p.parse().ok())
        }
        _ => (normalize_host(authority), None),
    }
}

/// Loopback + `BASE_URL`'s host + operator-supplied `ALLOWED_HOSTS`.
pub fn build_allowed_hosts(base_url: &str, extra: &[String]) -> Vec<AllowedHost> {
    let mut out = Vec::with_capacity(extra.len() + 1);
    if let Ok(url) = url::Url::parse(base_url)
        && let Some(host) = url.host_str()
    {
        out.push(AllowedHost {
            host: normalize_host(host),
            port: url.port(),
        });
    }
    for e in extra {
        let (host, port) = parse_authority(e);
        if !host.is_empty() {
            out.push(AllowedHost { host, port });
        }
    }
    out
}

/// Loopback names match any port; other entries match host, and port too
/// when the allowlist entry carries one.
pub fn host_allowed(authority: &str, allowed: &[AllowedHost]) -> bool {
    let (host, port) = parse_authority(authority);
    if host.is_empty() {
        return false;
    }
    if is_loopback_name(&host) {
        return true;
    }
    allowed
        .iter()
        .any(|a| a.host == host && (a.port.is_none() || a.port == port))
}

/// RFC 8707 `aud` validity: an http(s) URL whose host passes the allowlist
/// and whose path is `/mcp` or `/mcp/`.
pub fn aud_is_valid(aud: &str, allowed: &[AllowedHost]) -> bool {
    let Ok(url) = url::Url::parse(aud) else {
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
    if !host_allowed(&authority, allowed) {
        return false;
    }
    matches!(url.path(), "/mcp" | "/mcp/")
}

/// Same allowlist, flattened to `host`/`host:port` strings including the
/// loopback names, for `rmcp`'s own `StreamableHttpServerConfig` Host check.
pub fn allowed_host_strings(base_url: &str, extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = LOOPBACK_NAMES
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    for a in build_allowed_hosts(base_url, extra) {
        out.push(match a.port {
            Some(p) => format!("{}:{}", a.host, p),
            None => a.host,
        });
    }
    out
}

/// Validates `Host` (or the URI authority, if `Host` is absent) plus every
/// `X-Forwarded-Host` element against the allowlist.
pub async fn check_host(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let allowed = build_allowed_hosts(&state.config.base_url, &state.config.allowed_hosts);

    let authority = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(std::string::ToString::to_string));

    let Some(authority) = authority else {
        tracing::warn!("rejected request with no Host header or URI authority");
        return forbidden();
    };
    if !host_allowed(&authority, &allowed) {
        tracing::warn!(host = %authority, "rejected request: Host not allowed");
        return forbidden();
    }

    if let Some(xfh) = req
        .headers()
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
    {
        for part in xfh.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if !host_allowed(part, &allowed) {
                tracing::warn!(host = %part, "rejected request: X-Forwarded-Host element not allowed");
                return forbidden();
            }
        }
    }

    next.run(req).await
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden: host not allowed").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(base: &str, extra: &[&str]) -> Vec<AllowedHost> {
        build_allowed_hosts(
            base,
            &extra
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn loopback_any_port_allowed() {
        let a = allowed("http://google-mcp.example.com", &[]);
        assert!(host_allowed("localhost", &a));
        assert!(host_allowed("localhost:9999", &a));
        assert!(host_allowed("127.0.0.1:1234", &a));
        assert!(host_allowed("[::1]:8433", &a));
    }

    #[test]
    fn evil_host_rejected() {
        let a = allowed("http://google-mcp.example.com", &[]);
        assert!(!host_allowed("evil.example", &a));
    }

    #[test]
    fn base_url_host_accepted() {
        let a = allowed("http://google-mcp.example.com:8433", &[]);
        assert!(host_allowed("google-mcp.example.com:8433", &a));
        assert!(!host_allowed("google-mcp.example.com:9999", &a));
    }

    #[test]
    fn allowed_hosts_entry_accepted() {
        let a = allowed(
            "http://google-mcp.example.com",
            &["tunnel.example.net:8080"],
        );
        assert!(host_allowed("tunnel.example.net:8080", &a));
        assert!(!host_allowed("tunnel.example.net:9090", &a));
    }

    #[test]
    fn allowed_hosts_entry_without_port_matches_any_port() {
        let a = allowed("http://google-mcp.example.com", &["tunnel.example.net"]);
        assert!(host_allowed("tunnel.example.net:8080", &a));
        assert!(host_allowed("tunnel.example.net", &a));
    }

    #[test]
    fn trailing_dot_normalized() {
        let a = allowed("http://google-mcp.example.com", &[]);
        assert!(host_allowed("google-mcp.example.com.", &a));
    }

    #[test]
    fn ipv6_loopback_accepted() {
        let a = allowed("http://google-mcp.example.com", &[]);
        assert!(host_allowed("[::1]", &a));
    }

    #[test]
    fn aud_accepted_for_loopback_regardless_of_requested_host() {
        let a = allowed("http://localhost:8433", &[]);
        assert!(aud_is_valid("http://localhost:8433/mcp", &a));
        assert!(aud_is_valid("http://127.0.0.1:8433/mcp", &a));
        assert!(aud_is_valid("http://127.0.0.1:8433/mcp/", &a));
    }

    #[test]
    fn aud_rejects_evil_host() {
        let a = allowed("http://localhost:8433", &[]);
        assert!(!aud_is_valid("http://evil.example/mcp", &a));
    }

    #[test]
    fn aud_rejects_wrong_path() {
        let a = allowed("http://localhost:8433", &[]);
        assert!(!aud_is_valid("http://localhost:8433/other", &a));
    }
}
