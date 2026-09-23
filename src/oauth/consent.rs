//! HTML rendering for the `/authorize` consent interstitial.

use http::{HeaderMap, HeaderValue, header};

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Describes where access will be sent, using the `redirect_uri`'s *parsed*
/// host — never the raw string — so a hostile query component can't leak in.
pub fn redirect_target_description(redirect_uri: &str) -> String {
    let Ok(url) = url::Url::parse(redirect_uri) else {
        return "an unknown destination".to_string();
    };
    if url.scheme() == "cursor" {
        return "the Cursor app".to_string();
    }
    if url.scheme() == "http"
        && matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
        )
    {
        let port = url
            .port()
            .map_or_else(|| "80".to_string(), |p| p.to_string());
        return format!("an app on this computer (port {port})");
    }
    url.host_str()
        .map_or_else(|| "an unknown destination".to_string(), str::to_string)
}

pub fn render_consent_page(
    client_name: Option<&str>,
    redirect_uri: &str,
    scopes: &[&str],
    state_id: &str,
) -> String {
    let name_html = client_name
        .map(html_escape)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "An application".to_string());
    let target = html_escape(&redirect_target_description(redirect_uri));
    let scopes_html: String = scopes
        .iter()
        .map(|s| format!("<li>{}</li>", html_escape(s)))
        .collect();
    let state_html = html_escape(state_id);

    format!(
        r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize access · Google Workspace MCP</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       max-width: 480px; margin: 3rem auto; padding: 0 1.25rem;
       background: #fff; color: #111; }}
@media (prefers-color-scheme: dark) {{
  body {{ background: #111; color: #eee; }}
  .card {{ background: #1c1c1e; border-color: #333; }}
}}
.card {{ border: 1px solid #ddd; border-radius: 12px; padding: 1.5rem; }}
h1 {{ font-size: 1.25rem; margin-top: 0; }}
.self-reported {{ font-size: 0.85rem; opacity: 0.7; }}
ul {{ padding-left: 1.2rem; }}
.buttons {{ display: flex; gap: 0.75rem; margin-top: 1.5rem; }}
button {{ flex: 1; padding: 0.75rem; border-radius: 8px; border: none; font-size: 1rem; cursor: pointer; }}
button.approve {{ background: #2a6; color: #fff; }}
button.deny {{ background: #888; color: #fff; }}
.eyebrow {{ font-size: 0.8rem; letter-spacing: 0.04em; text-transform: uppercase; opacity: 0.6; margin: 0 0 0.5rem; }}
.warn {{ border-left: 3px solid #d80; padding-left: 0.75rem; }}
h1 {{ overflow-wrap: anywhere; }}
</style>
</head>
<body>
<div class="card">
<p class="eyebrow">Google Workspace MCP</p>
<h1>Connect {name_html} to your Google account?</h1>
<p class="self-reported">The app chose this name itself; it is not verified.</p>
<p>Access will be sent to <strong>{target}</strong>.</p>
<p class="warn">Only approve if you just started connecting an app. If you didn&#39;t, choose Deny.</p>
<p>After approval, Google will ask you to sign in and confirm access to:</p>
<ul>{scopes_html}</ul>
<form method="post" action="/authorize/consent">
<input type="hidden" name="state_id" value="{state_html}">
<div class="buttons">
<button class="approve" type="submit" name="decision" value="approve">Approve</button>
<button class="deny" type="submit" name="decision" value="deny">Deny</button>
</div>
</form>
</div>
</body>
</html>"#
    )
}

/// CSP intentionally omits `form-action`: Chrome applies it to the 303 after
/// a POST submit and would block the redirect to Google's consent screen.
pub fn security_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_all_five_characters() {
        assert_eq!(html_escape(r#"&<>"'"#), "&amp;&lt;&gt;&quot;&#39;");
    }

    #[test]
    fn escape_is_noop_on_plain_text() {
        assert_eq!(html_escape("Claude Desktop"), "Claude Desktop");
    }

    #[test]
    fn loopback_http_describes_port() {
        assert_eq!(
            redirect_target_description("http://127.0.0.1:5173/cb"),
            "an app on this computer (port 5173)"
        );
    }

    #[test]
    fn https_uses_host() {
        assert_eq!(
            redirect_target_description("https://claude.ai/api/cb"),
            "claude.ai"
        );
    }

    #[test]
    fn cursor_scheme_named() {
        assert_eq!(
            redirect_target_description("cursor://anysphere.cursor-mcp/oauth/callback"),
            "the Cursor app"
        );
    }

    #[test]
    fn consent_page_escapes_client_name_and_never_leaks_raw_redirect_uri() {
        let page = render_consent_page(
            Some("<script>alert(1)</script>"),
            "https://evil.example/cb?token=leak",
            &["Gmail"],
            "state-1",
        );
        assert!(!page.contains("<script>alert(1)</script>"));
        assert!(page.contains("&lt;script&gt;"));
        assert!(!page.contains("token=leak"));
        assert!(page.contains("evil.example"));
    }

    #[test]
    fn consent_page_shows_loopback_wording() {
        let page = render_consent_page(Some("MyApp"), "http://localhost:3000/cb", &[], "s");
        assert!(page.contains("an app on this computer (port 3000)"));
    }

    #[test]
    fn consent_page_includes_state_id_in_hidden_field() {
        let page = render_consent_page(None, "https://x.example/cb", &[], "abc123");
        assert!(page.contains(r#"value="abc123""#));
    }
}
