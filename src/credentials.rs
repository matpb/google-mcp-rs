//! Per-request credential resolution.
//!
//! Implemented in Phase 2. `resolve_google` extracts the bearer JWT from the
//! request, verifies it, derives the user's Google `sub`, and returns a live
//! `GoogleAccountSession` (refreshing the access token if needed).
