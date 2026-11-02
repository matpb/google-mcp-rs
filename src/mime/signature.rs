//! Gmail signature support for the compose tools. Gmail inserts a signature
//! only in its own compose UI, so the API path adds it here.

use serde_json::Value;

/// Opening tag Gmail uses to wrap a signature in the HTML part.
pub const SIGNATURE_DIV_OPEN: &str =
    r#"<div class="gmail_signature" data-smartmail="gmail_signature">"#;

/// Escape HTML and turn line breaks into `<br>`.
pub fn text_to_html(text: &str) -> String {
    crate::oauth::consent::html_escape(text)
        .replace("\r\n", "\n")
        .replace('\n', "<br>")
}

/// Longest entity body (text between `&` and `;`) that is decoded.
const MAX_ENTITY_BODY: usize = 10;

/// Render signature HTML as plain text.
pub fn html_to_text(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len());
    // Output offset of the current link's text, and its decoded href.
    let mut link: Option<(usize, String)> = None;
    let mut pos = 0;
    while let Some(off) = html[pos..].find('<') {
        let lt = pos + off;
        decode_into(&mut out, &html[pos..lt]);
        pos = lt + 1;
        let starts_tag = bytes
            .get(lt + 1)
            .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'/' | b'!' | b'?'));
        if !starts_tag {
            out.push('<');
            continue;
        }
        if lower[lt..].starts_with("<!--") {
            pos = lower[lt + 4..]
                .find("-->")
                .map_or(html.len(), |end| lt + 4 + end + 3);
            continue;
        }
        let Some(gt) = tag_end(bytes, lt + 1) else {
            out.push('<');
            continue;
        };
        let tag = &html[lt + 1..gt];
        let tag_lower = &lower[lt + 1..gt];
        pos = gt + 1;

        let closing = tag_lower.starts_with('/');
        let name_src = if closing { &tag_lower[1..] } else { tag_lower };
        let name_len = name_src
            .bytes()
            .take_while(u8::is_ascii_alphanumeric)
            .count();
        let name = &name_src[..name_len];

        if !closing && matches!(name, "style" | "script") {
            let start = pos;
            pos = lower[start..]
                .find(&format!("</{name}"))
                .map_or(html.len(), |i| start + i);
            continue;
        }
        match name {
            "br" => out.push('\n'),
            "li" if !closing => out.push_str("- "),
            "p" | "div" | "tr" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" if closing => {
                out.push('\n');
            }
            "a" if !closing => {
                if let Some(href) = attr_value(tag, "href")
                    && link.is_none()
                {
                    link = Some((out.len(), href));
                }
            }
            "a" => {
                if let Some((start, href)) = link.take() {
                    let inner = out.split_off(start);
                    let label = inner.trim();
                    if href.is_empty() {
                        out.push_str(label);
                    } else if label.is_empty() {
                        out.push_str(&format!("<{href}>"));
                    } else if label == href || href.strip_prefix("mailto:") == Some(label) {
                        out.push_str(label);
                    } else {
                        out.push_str(&format!("{label} <{href}>"));
                    }
                }
            }
            "img" if !closing => {
                if let Some(alt) = attr_value(tag, "alt") {
                    out.push_str(&alt);
                }
            }
            _ => {}
        }
    }
    decode_into(&mut out, &html[pos..]);

    let mut joined = String::with_capacity(out.len());
    let mut newline_run = 0;
    for (i, line) in out.split('\n').map(str::trim_end).enumerate() {
        if i > 0 {
            newline_run += 1;
            if newline_run <= 2 {
                joined.push('\n');
            }
        }
        if !line.is_empty() {
            newline_run = 0;
        }
        joined.push_str(line);
    }
    joined.trim().to_string()
}

/// Index of the `>` closing the tag whose body starts at `from`, skipping quoted attribute values.
fn tag_end(bytes: &[u8], from: usize) -> Option<usize> {
    let mut quote: Option<u8> = None;
    let mut prev = b' ';
    for (i, &b) in bytes.iter().enumerate().skip(from) {
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
        } else if b == b'>' {
            return Some(i);
        } else if (b == b'"' || b == b'\'') && prev == b'=' {
            quote = Some(b);
        }
        if !b.is_ascii_whitespace() {
            prev = b;
        }
    }
    None
}

/// Entity-decoded value of attribute `name` in a tag body (the text between `<` and `>`).
fn attr_value(tag: &str, name: &str) -> Option<String> {
    let b = tag.as_bytes();
    let mut i = b
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(b.len());
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let key_start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' {
            i += 1;
        }
        let key = &tag[key_start..i];
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = "";
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if let Some(&q) = b.get(i).filter(|&&c| c == b'"' || c == b'\'') {
                let start = i + 1;
                let end = b[start..]
                    .iter()
                    .position(|&c| c == q)
                    .map_or(b.len(), |p| start + p);
                value = &tag[start..end];
                i = (end + 1).min(b.len());
            } else {
                let start = i;
                while i < b.len() && !b[i].is_ascii_whitespace() {
                    i += 1;
                }
                value = &tag[start..i];
            }
        }
        if key.eq_ignore_ascii_case(name) {
            let mut decoded = String::with_capacity(value.len());
            decode_into(&mut decoded, value);
            return Some(decoded);
        }
    }
    None
}

/// Append `s` to `out`, decoding character references.
fn decode_into(out: &mut String, s: &str) {
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        match decode_entity(after) {
            Some((c, used)) => {
                out.push(c);
                rest = &after[used..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
}

/// Decode the reference whose body (text after `&`) starts `s`. Returns the char and the
/// bytes consumed, `;` included.
fn decode_entity(s: &str) -> Option<(char, usize)> {
    let end = s.bytes().take(MAX_ENTITY_BODY).position(|b| b == b';')?;
    let c = match &s[..end] {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        body => {
            let num = body.strip_prefix('#')?;
            let code = match num.strip_prefix(['x', 'X']) {
                Some(hex) if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    u32::from_str_radix(hex, 16).ok()?
                }
                Some(_) => return None,
                None if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) => {
                    num.parse().ok()?
                }
                None => return None,
            };
            // A numeric no-break space renders as a space, like `&nbsp;`.
            match code {
                0 => return None,
                0xA0 => ' ',
                _ => char::from_u32(code)?,
            }
        }
    };
    Some((c, end + 1))
}

/// Append a signature to the body. Returns the inputs unchanged when `sig_html` is blank.
pub fn apply_signature(
    body_text: Option<String>,
    body_html: Option<String>,
    sig_html: &str,
) -> (Option<String>, Option<String>) {
    if sig_html.trim().is_empty() {
        return (body_text, body_html);
    }
    let body = match body_html {
        Some(h) if !h.is_empty() => h,
        _ => text_to_html(body_text.as_deref().unwrap_or("")),
    };
    let html = format!("{body}<br><br>{SIGNATURE_DIV_OPEN}{sig_html}</div>");
    let sig_text = html_to_text(sig_html);
    let text = match body_text {
        Some(t) if !t.is_empty() && !sig_text.is_empty() => Some(format!("{t}\n\n{sig_text}")),
        other => other,
    };
    (text, Some(html))
}

/// Pick a sendAs entry from a `users.settings.sendAs.list` response.
pub fn pick_send_as<'a>(list: &'a Value, wanted: Option<&str>) -> Option<&'a Value> {
    let entries = list.get("sendAs")?.as_array()?;
    match wanted {
        Some(email) => entries.iter().find(|e| {
            e.get("sendAsEmail")
                .and_then(Value::as_str)
                .is_some_and(|s| s.eq_ignore_ascii_case(email))
        }),
        None => entries
            .iter()
            .find(|e| flag_set(e, "isDefault"))
            .or_else(|| entries.iter().find(|e| flag_set(e, "isPrimary")))
            .or_else(|| entries.first()),
    }
}

fn flag_set(entry: &Value, key: &str) -> bool {
    entry.get(key).and_then(Value::as_bool) == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mime::{Compose, Recipient, compose};
    use serde_json::json;

    #[test]
    fn text_to_html_escapes_and_breaks_lines() {
        assert_eq!(text_to_html("a < b\nc & d"), "a &lt; b<br>c &amp; d");
        assert_eq!(
            text_to_html(r#"say "hi" & 'bye'"#),
            "say &quot;hi&quot; &amp; &#39;bye&#39;"
        );
        assert_eq!(text_to_html("one\r\ntwo\n"), "one<br>two<br>");
        assert_eq!(text_to_html(""), "");
    }

    #[test]
    fn html_to_text_renders_breaks_links_entities() {
        assert_eq!(
            html_to_text(
                r#"<div dir="ltr">Sam B.<br>Dev &amp; Co<br><a href="https://example.com">site</a></div>"#
            ),
            "Sam B.\nDev & Co\nsite <https://example.com>"
        );
        assert_eq!(
            html_to_text(r#"<a href="mailto:x@example.com">x@example.com</a>"#),
            "x@example.com"
        );
        assert_eq!(
            html_to_text(r#"<a href="https://example.com">https://example.com</a>"#),
            "https://example.com"
        );
        assert_eq!(
            html_to_text("It&#x27;s&nbsp;fine &#39;ok&#39; &apos;x&apos;"),
            "It's fine 'ok' 'x'"
        );
    }

    #[test]
    fn html_to_text_keeps_unknown_references_and_non_ascii() {
        assert_eq!(
            html_to_text("Q&A &copy; Zoë &#0; &#x110000;"),
            "Q&A &copy; Zoë &#0; &#x110000;"
        );
        assert_eq!(html_to_text("a <b"), "a <b");
        assert_eq!(html_to_text("x<style>never closed"), "x");
    }

    #[test]
    fn html_to_text_large_input_is_exact() {
        let one = r#"<div dir="ltr">Sam B.<br>Dev &amp; Co<br><a href="https://example.com">site</a></div>"#;
        let expected = "Sam B.\nDev & Co\nsite <https://example.com>";
        let big = one.repeat(1000);
        assert_eq!(html_to_text(&big), vec![expected; 1000].join("\n"));
    }

    #[test]
    fn html_to_text_handles_lists_headings_images_and_hidden_parts() {
        assert_eq!(
            html_to_text("<ul><li>One</li><li>Two</li></ul>"),
            "- One\n- Two"
        );
        assert_eq!(html_to_text("<h2>Title</h2>Body"), "Title\nBody");
        assert_eq!(
            html_to_text(r#"<img src="a.png" alt="Logo"> Name"#),
            "Logo Name"
        );
        assert_eq!(html_to_text(r#"<img src="a.png">Name"#), "Name");
        assert_eq!(
            html_to_text("<style>p{color:red}</style>Hi<SCRIPT>x()</SCRIPT>"),
            "Hi"
        );
        assert_eq!(html_to_text("a<!-- hidden -->b"), "ab");
        assert_eq!(html_to_text(r#"<span title="x>y">z</span>"#), "z");
        assert_eq!(html_to_text("a < b"), "a < b");
        assert_eq!(html_to_text("a<br><br><br><br>b   <br>c"), "a\n\nb\nc");
        assert_eq!(html_to_text("  <BR>Sam<BR/>  "), "Sam");
    }

    #[test]
    fn apply_signature_text_only_builds_html() {
        assert_eq!(
            apply_signature(Some("Hi\nthere".into()), None, "<b>Sam</b>"),
            (
                Some("Hi\nthere\n\nSam".into()),
                Some(format!(
                    "Hi<br>there<br><br>{SIGNATURE_DIV_OPEN}<b>Sam</b></div>"
                ))
            )
        );
    }

    #[test]
    fn apply_signature_with_html_appends_div() {
        assert_eq!(
            apply_signature(Some("t".into()), Some("<p>h</p>".into()), "Sam"),
            (
                Some("t\n\nSam".into()),
                Some(format!("<p>h</p><br><br>{SIGNATURE_DIV_OPEN}Sam</div>"))
            )
        );
        assert_eq!(
            apply_signature(None, Some("<p>h</p>".into()), "Sam"),
            (
                None,
                Some(format!("<p>h</p><br><br>{SIGNATURE_DIV_OPEN}Sam</div>"))
            )
        );
    }

    #[test]
    fn apply_signature_empty_signature_is_noop() {
        assert_eq!(
            apply_signature(Some("t".into()), None, "  "),
            (Some("t".into()), None)
        );
        assert_eq!(apply_signature(None, None, ""), (None, None));
        assert_eq!(
            apply_signature(Some("t".into()), Some("<p>h</p>".into()), " \n "),
            (Some("t".into()), Some("<p>h</p>".into()))
        );
    }

    #[test]
    fn apply_signature_image_only_signature_adds_no_text_gap() {
        assert_eq!(
            apply_signature(Some("t".into()), None, r#"<img src="x.png">"#),
            (
                Some("t".into()),
                Some(format!(
                    r#"t<br><br>{SIGNATURE_DIV_OPEN}<img src="x.png"></div>"#
                ))
            )
        );
    }

    #[test]
    fn pick_send_as_prefers_explicit_then_default_then_primary() {
        let list = json!({"sendAs": [
            {"sendAsEmail": "a@example.com", "isDefault": false, "isPrimary": false},
            {"sendAsEmail": "Main@Example.com", "isDefault": false, "isPrimary": true},
            {"sendAsEmail": "alias@example.com", "isDefault": true, "isPrimary": false}
        ]});
        assert_eq!(
            pick_send_as(&list, Some("main@example.com")),
            Some(&list["sendAs"][1])
        );
        assert_eq!(pick_send_as(&list, Some("missing@example.com")), None);
        assert_eq!(pick_send_as(&list, None), Some(&list["sendAs"][2]));

        let no_default = json!({"sendAs": [
            {"sendAsEmail": "a@example.com", "isDefault": false, "isPrimary": false},
            {"sendAsEmail": "main@example.com", "isPrimary": true}
        ]});
        assert_eq!(
            pick_send_as(&no_default, None),
            Some(&no_default["sendAs"][1])
        );

        let bare = json!({"sendAs": [
            {"sendAsEmail": "x@example.com"},
            {"sendAsEmail": "y@example.com"}
        ]});
        assert_eq!(pick_send_as(&bare, None), Some(&bare["sendAs"][0]));

        assert_eq!(pick_send_as(&json!({"sendAs": []}), None), None);
        assert_eq!(pick_send_as(&json!({}), None), None);
    }

    #[test]
    fn signed_draft_is_multipart_with_signature_div() {
        let (text, html) = apply_signature(Some("Hello".into()), None, "<b>Sam</b>");
        let bytes = compose(Compose {
            from: Recipient {
                email: "me@example.com".into(),
                name: None,
            },
            to: vec![Recipient {
                email: "you@example.com".into(),
                name: None,
            }],
            cc: vec![],
            bcc: vec![],
            subject: "Hi".into(),
            body_text: text,
            body_html: html,
            attachments: vec![],
            reply: None,
        })
        .unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.to_lowercase().contains("multipart/alternative"));
        assert!(s.contains("gmail_signature"));
    }
}
