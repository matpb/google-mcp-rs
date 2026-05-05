//! OAuth 2.1 — server-side proxy that wraps Google for upstream auth and
//! issues MCP-bound JWTs to MCP clients.
//!
//! Phase 2 introduces:
//! - `proxy`: `/authorize`, `/oauth/google/callback`, `/oauth/token`, `/oauth/register`.
//! - `google`: thin Google OAuth client (build URL, exchange, refresh, parse ID token).
//! - `jwt`: HS256 sign/verify with RFC 8707 audience binding.
//! - `pkce`: S256 challenge verification.
//! - `store`: SQLite-backed lookups for clients, codes, and proxy state.
//!
//! Plus the well-known endpoints (`/.well-known/oauth-protected-resource[/mcp]`
//! and `/.well-known/oauth-authorization-server`), wired in `mod.rs::router`.
