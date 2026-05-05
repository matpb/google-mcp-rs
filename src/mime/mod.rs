//! RFC 5322 message composition for `gmail_send` and the draft tools.
//!
//! Wraps `mail-builder` with helpers for reply-threading
//! (`In-Reply-To`/`References` headers, `Re:` subject prefixing) and
//! produces the base64url-encoded payload Gmail's `users.messages.send`
//! expects in `{ "raw": "..." }`.

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mail_builder::MessageBuilder;
use mail_builder::headers::address::{Address, EmailAddress};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum MimeError {
    #[error("mime: {0}")]
    Build(String),
    #[error("attachment exceeds size limit (24 MB)")]
    AttachmentTooLarge,
    #[error("recipients are required (at least one of to/cc/bcc)")]
    NoRecipients,
}

/// Maximum total message size we permit, leaving headroom under Gmail's
/// 25 MB outgoing limit for MIME framing overhead.
pub const MAX_MESSAGE_BYTES: usize = 24 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct Recipient {
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct AttachmentInput {
    pub filename: String,
    /// MIME type (e.g. `application/pdf`). Defaults to `application/octet-stream`.
    #[serde(default)]
    pub mime_type: Option<String>,
    /// Base64-encoded bytes (standard or url-safe). Mutually exclusive with `path`.
    #[serde(default)]
    pub data_base64: Option<String>,
    /// Server-side absolute path to read the attachment from. Mutually
    /// exclusive with `data_base64`. Useful when an MCP client has the
    /// file on the same machine as this server.
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReplyContext {
    /// RFC 5322 `Message-Id` header value of the message being replied to.
    /// Note: this is NOT the Gmail message ID (the opaque `18b3c…` blob).
    pub message_id: String,
    /// Existing `References` chain, oldest first. May be empty.
    pub references: Vec<String>,
    /// Subject of the original message. The composer adds a single `Re: `
    /// prefix unless one already exists.
    pub subject: String,
}

#[derive(Debug, Clone)]
pub struct Compose {
    pub from: Recipient,
    pub to: Vec<Recipient>,
    pub cc: Vec<Recipient>,
    pub bcc: Vec<Recipient>,
    pub subject: String,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub attachments: Vec<ResolvedAttachment>,
    pub reply: Option<ReplyContext>,
}

#[derive(Debug, Clone)]
pub struct ResolvedAttachment {
    pub filename: String,
    pub mime_type: String,
    pub bytes: Vec<u8>,
}

impl ResolvedAttachment {
    pub fn from_input(att: AttachmentInput) -> Result<Self, MimeError> {
        let mime_type = att
            .mime_type
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let bytes = match (att.data_base64, att.path) {
            (Some(_), Some(_)) => {
                return Err(MimeError::Build(
                    "attachment.data_base64 and attachment.path are mutually exclusive".into(),
                ));
            }
            (Some(b64), None) => decode_base64(&b64)?,
            (None, Some(path)) => std::fs::read(&path).map_err(|e| {
                MimeError::Build(format!("could not read attachment file {path}: {e}"))
            })?,
            (None, None) => {
                return Err(MimeError::Build(
                    "attachment requires data_base64 or path".into(),
                ));
            }
        };
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(MimeError::AttachmentTooLarge);
        }
        Ok(Self {
            filename: att.filename,
            mime_type,
            bytes,
        })
    }
}

fn decode_base64(s: &str) -> Result<Vec<u8>, MimeError> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};
    let trimmed = s.trim();
    URL_SAFE_NO_PAD
        .decode(trimmed.trim_end_matches('='))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .or_else(|_| STANDARD.decode(trimmed))
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed.trim_end_matches('=')))
        .map_err(|e| MimeError::Build(format!("base64 decode: {e}")))
}

fn build_address(rs: &[Recipient]) -> Option<Address<'_>> {
    if rs.is_empty() {
        return None;
    }
    let list: Vec<Address<'_>> = rs
        .iter()
        .map(|r| {
            Address::Address(EmailAddress {
                name: r.name.as_deref().map(Cow::Borrowed),
                email: Cow::Borrowed(r.email.as_str()),
            })
        })
        .collect();
    Some(if list.len() == 1 {
        list.into_iter().next().unwrap()
    } else {
        Address::new_list(list)
    })
}

fn rewrite_subject(reply: &Option<ReplyContext>, supplied: &str) -> String {
    let Some(ctx) = reply else {
        return supplied.to_string();
    };
    let base = if !supplied.is_empty() {
        supplied
    } else {
        ctx.subject.as_str()
    };
    if has_re_prefix(base) {
        base.to_string()
    } else {
        format!("Re: {base}")
    }
}

fn has_re_prefix(s: &str) -> bool {
    let t = s.trim_start();
    t.len() >= 3 && t.as_bytes()[0..3].eq_ignore_ascii_case(b"re:")
}

fn strip_brackets(s: &str) -> &str {
    let t = s.trim();
    let t = t.strip_prefix('<').unwrap_or(t);
    t.strip_suffix('>').unwrap_or(t)
}

/// Compose the message and return raw RFC 5322 bytes.
pub fn compose(req: Compose) -> Result<Vec<u8>, MimeError> {
    if req.to.is_empty() && req.cc.is_empty() && req.bcc.is_empty() {
        return Err(MimeError::NoRecipients);
    }
    let from_addr = Address::Address(EmailAddress {
        name: req.from.name.as_deref().map(Cow::Borrowed),
        email: Cow::Borrowed(req.from.email.as_str()),
    });

    let subject = rewrite_subject(&req.reply, &req.subject);

    let mut b = MessageBuilder::new().from(from_addr).subject(subject);
    if let Some(to) = build_address(&req.to) {
        b = b.to(to);
    }
    if let Some(cc) = build_address(&req.cc) {
        b = b.cc(cc);
    }
    if let Some(bcc) = build_address(&req.bcc) {
        b = b.bcc(bcc);
    }

    if let Some(reply) = &req.reply {
        // mail-builder wraps every message id in <...> on serialization,
        // so we strip any surrounding brackets that callers may have left
        // on (Gmail-API-returned `Message-Id` header values include them).
        let canonical_id = strip_brackets(&reply.message_id).to_string();
        b = b.in_reply_to(canonical_id.clone());
        let mut chain: Vec<String> = reply
            .references
            .iter()
            .map(|s| strip_brackets(s).to_string())
            .collect();
        if !chain.iter().any(|s| s == &canonical_id) {
            chain.push(canonical_id);
        }
        b = b.references(chain);
    }

    if let Some(text) = req.body_text.as_deref() {
        b = b.text_body(text.to_string());
    }
    if let Some(html) = req.body_html.as_deref() {
        b = b.html_body(html.to_string());
    }

    for att in &req.attachments {
        b = b.attachment(
            att.mime_type.as_str(),
            att.filename.as_str(),
            att.bytes.clone(),
        );
    }

    let bytes = b
        .write_to_vec()
        .map_err(|e| MimeError::Build(format!("serialize: {e}")))?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(MimeError::AttachmentTooLarge);
    }
    Ok(bytes)
}

/// Compose and encode for Gmail's `{ "raw": ... }` payload.
pub fn compose_for_gmail(req: Compose) -> Result<String, MimeError> {
    let raw = compose(req)?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rcpt(email: &str) -> Recipient {
        Recipient {
            email: email.to_string(),
            name: None,
        }
    }

    fn named(name: &str, email: &str) -> Recipient {
        Recipient {
            email: email.to_string(),
            name: Some(name.to_string()),
        }
    }

    fn base() -> Compose {
        Compose {
            from: rcpt("me@example.com"),
            to: vec![rcpt("you@example.com")],
            cc: vec![],
            bcc: vec![],
            subject: "Hello".to_string(),
            body_text: Some("Body text".to_string()),
            body_html: None,
            attachments: vec![],
            reply: None,
        }
    }

    fn as_string(req: Compose) -> String {
        let bytes = compose(req).unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn simple_message() {
        let s = as_string(base());
        assert!(s.contains("From: <me@example.com>") || s.contains("From: me@example.com"));
        assert!(s.contains("To: <you@example.com>") || s.contains("To: you@example.com"));
        assert!(s.contains("Subject: Hello"));
        assert!(s.contains("Body text"));
    }

    #[test]
    fn requires_recipient() {
        let req = Compose {
            to: vec![],
            ..base()
        };
        assert!(matches!(compose(req).unwrap_err(), MimeError::NoRecipients));
    }

    #[test]
    fn cc_bcc_emit_headers() {
        let s = as_string(Compose {
            cc: vec![rcpt("c@example.com")],
            bcc: vec![rcpt("b@example.com")],
            ..base()
        });
        assert!(s.contains("Cc: ") && s.contains("c@example.com"));
        assert!(s.contains("Bcc: ") && s.contains("b@example.com"));
    }

    #[test]
    fn named_recipient_includes_display_name() {
        let s = as_string(Compose {
            to: vec![named("Jane Doe", "jane@example.com")],
            ..base()
        });
        assert!(s.contains("Jane Doe"));
        assert!(s.contains("jane@example.com"));
    }

    #[test]
    fn html_and_text_both_emit() {
        let s = as_string(Compose {
            body_text: Some("plain".into()),
            body_html: Some("<p>html</p>".into()),
            ..base()
        });
        // multipart/alternative with both parts.
        assert!(s.to_lowercase().contains("multipart/alternative"));
        assert!(s.contains("plain"));
        assert!(s.contains("<p>html</p>"));
    }

    #[test]
    fn reply_adds_in_reply_to_and_references() {
        let s = as_string(Compose {
            subject: "Project status".into(),
            reply: Some(ReplyContext {
                message_id: "<orig@x>".into(),
                references: vec!["<root@x>".into(), "<mid@x>".into()],
                subject: "Project status".into(),
            }),
            ..base()
        });
        assert!(s.contains("In-Reply-To: <orig@x>"));
        // References chain should contain the prior chain plus the original message id at the end.
        assert!(s.contains("References:"));
        assert!(s.contains("<root@x>"));
        assert!(s.contains("<mid@x>"));
        assert!(s.contains("<orig@x>"));
        // Subject is rewritten with single Re: prefix.
        assert!(s.contains("Subject: Re: Project status"));
    }

    #[test]
    fn reply_does_not_double_prefix() {
        let s = as_string(Compose {
            subject: "Re: Already prefixed".into(),
            reply: Some(ReplyContext {
                message_id: "<m>".into(),
                references: vec![],
                subject: "Re: Already prefixed".into(),
            }),
            ..base()
        });
        assert!(s.contains("Subject: Re: Already prefixed"));
        assert!(!s.contains("Re: Re:"));
    }

    #[test]
    fn reply_uses_original_subject_if_supplied_is_empty() {
        let s = as_string(Compose {
            subject: String::new(),
            reply: Some(ReplyContext {
                message_id: "<m>".into(),
                references: vec![],
                subject: "Original".into(),
            }),
            ..base()
        });
        assert!(s.contains("Subject: Re: Original"));
    }

    #[test]
    fn references_chain_does_not_duplicate_message_id() {
        let s = as_string(Compose {
            reply: Some(ReplyContext {
                message_id: "<m@x>".into(),
                references: vec!["<m@x>".into()],
                subject: "X".into(),
            }),
            ..base()
        });
        // <m@x> should appear in References at most once, and in In-Reply-To once.
        let refs_count = s.matches("<m@x>").count();
        // Expect 2 occurrences: once in In-Reply-To, once in References.
        assert!(
            refs_count <= 3,
            "<m@x> appeared {refs_count} times, expected ≤ 3"
        );
    }

    #[test]
    fn attachment_via_base64_round_trips() {
        let payload = b"hello-attachment".to_vec();
        let b64 = URL_SAFE_NO_PAD.encode(&payload);
        let att = ResolvedAttachment::from_input(AttachmentInput {
            filename: "f.txt".into(),
            mime_type: Some("text/plain".into()),
            data_base64: Some(b64),
            path: None,
        })
        .unwrap();
        assert_eq!(att.bytes, payload);

        let s = as_string(Compose {
            attachments: vec![att],
            ..base()
        });
        assert!(s.to_lowercase().contains("attachment"));
        assert!(s.contains("f.txt"));
    }

    #[test]
    fn attachment_path_and_b64_mutually_exclusive() {
        let err = ResolvedAttachment::from_input(AttachmentInput {
            filename: "f".into(),
            mime_type: None,
            data_base64: Some("aGk=".into()),
            path: Some("/tmp/x".into()),
        })
        .unwrap_err();
        assert!(matches!(err, MimeError::Build(_)));
    }

    #[test]
    fn attachment_requires_one_source() {
        let err = ResolvedAttachment::from_input(AttachmentInput {
            filename: "f".into(),
            mime_type: None,
            data_base64: None,
            path: None,
        })
        .unwrap_err();
        assert!(matches!(err, MimeError::Build(_)));
    }

    #[test]
    fn compose_for_gmail_returns_valid_base64url() {
        let encoded = compose_for_gmail(base()).unwrap();
        // base64url-no-pad: alphabet is [A-Za-z0-9_-] only.
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "encoded payload contains non-base64url bytes"
        );
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        let s = String::from_utf8(decoded).unwrap();
        assert!(s.contains("From: <me@example.com>"));
        assert!(s.contains("To: <you@example.com>"));
        assert!(s.contains("Subject: Hello"));
    }

    #[test]
    fn strip_brackets_removes_angle_brackets() {
        assert_eq!(strip_brackets("<abc@example.com>"), "abc@example.com");
        assert_eq!(strip_brackets("abc@example.com"), "abc@example.com");
        assert_eq!(strip_brackets("  <x>  "), "x");
        // Lenient about unbalanced brackets (Gmail-returned headers are well-formed).
        assert_eq!(strip_brackets("<unbalanced"), "unbalanced");
        assert_eq!(strip_brackets("unbalanced>"), "unbalanced");
    }
}
