//! SQLite-backed persistence: OAuth accounts, MCP clients, codes, proxy state.
//!
//! Single-connection model wrapped in `Arc<std::sync::Mutex<Connection>>`,
//! invoked from async code via `tokio::task::spawn_blocking`. SQLite is
//! single-writer at the kernel level anyway and our workload is light.
//! WAL is enabled to keep reads from blocking the occasional write.

// Some struct fields and helpers are read by Phase 2 (`oauth/proxy.rs`) and
// Phase 2.5 (`google/session.rs`) but not yet by tests. Suppress the
// transient dead-code noise so CI's `clippy -D warnings` stays green.
#![allow(dead_code)]

pub mod accounts;
pub mod clients;
pub mod codes;
pub mod crypto;

use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use rusqlite_migration::{M, Migrations};

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("migration: {0}")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("password hash: {0}")]
    PasswordHash(String),
    #[error("blocking task panicked: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("connection mutex poisoned")]
    Poisoned,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("invalid input: {0}")]
    Invalid(&'static str),
}

const MIGRATION_001: &str = include_str!("migrations/001_initial.sql");

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(MIGRATION_001)])
}

impl Db {
    /// Open (or create) the SQLite database at `path` and run all pending migrations.
    pub async fn open(path: impl Into<String>) -> Result<Self, DbError> {
        let path = path.into();
        let conn = tokio::task::spawn_blocking(move || -> Result<Connection, DbError> {
            let mut conn = Connection::open(&path)?;
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "foreign_keys", "ON")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
            migrations().to_latest(&mut conn)?;
            Ok(conn)
        })
        .await??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory database (for tests).
    pub async fn open_in_memory() -> Result<Self, DbError> {
        let conn = tokio::task::spawn_blocking(|| -> Result<Connection, DbError> {
            let mut conn = Connection::open_in_memory()?;
            conn.pragma_update(None, "foreign_keys", "ON")?;
            migrations().to_latest(&mut conn)?;
            Ok(conn)
        })
        .await??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Run a synchronous database closure on the blocking pool.
    pub async fn call<F, R>(&self, f: F) -> Result<R, DbError>
    where
        F: FnOnce(&mut Connection) -> Result<R, DbError> + Send + 'static,
        R: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| DbError::Poisoned)?;
            f(&mut guard)
        })
        .await?
    }
}

pub fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrations_run_on_in_memory() {
        let db = Db::open_in_memory().await.expect("open");
        let count: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'oauth_%'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .expect("count");
        // oauth_accounts, oauth_codes, oauth_states + mcp_clients
        assert_eq!(count, 3, "expected 3 oauth_* tables");

        let mcp_clients: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mcp_clients'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .expect("count clients");
        assert_eq!(mcp_clients, 1);
    }

    #[tokio::test]
    async fn migrations_are_idempotent() {
        let db = Db::open_in_memory().await.expect("open");
        // Re-run migrations against the same connection.
        db.call(|conn| {
            migrations().to_latest(conn)?;
            Ok(())
        })
        .await
        .expect("idempotent");
    }
}
