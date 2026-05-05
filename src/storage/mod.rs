//! SQLite-backed persistence: OAuth accounts, MCP clients, codes, proxy state.
//!
//! Phase 1 introduces:
//! - `crypto`: AES-256-GCM seal/unseal with AAD bound to `google_sub` so
//!   ciphertext cannot be swapped between accounts.
//! - `accounts`, `clients`, `codes`: typed CRUD over `rusqlite` via
//!   `tokio::task::spawn_blocking`.
//!
//! Schema lives in `migrations/001_initial.sql` and is applied on startup
//! via `rusqlite_migration`.
