//! RFC 5322 message composition for `gmail_send` and draft tools.
//!
//! Phase 3. Wraps `mail-builder` with helpers for reply-threading
//! (`In-Reply-To`, `References`, `Re:` subject prefixing) and for
//! base64url-encoding the raw message into the form Gmail's API expects.
