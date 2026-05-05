//! 401 + WWW-Authenticate middleware for the `/mcp` endpoint.
//!
//! Implemented in Phase 2 (OAuth proxy). Gates `/mcp` so that requests
//! without a `Bearer` token receive an RFC 6750 challenge pointing at
//! `/.well-known/oauth-protected-resource/mcp` per RFC 9728.
