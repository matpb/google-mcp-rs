//! SQLite-backed persistence: OAuth accounts, MCP clients, codes, proxy state.
//!
//! Single-connection model wrapped in `Arc<std::sync::Mutex<Connection>>`,
//! invoked from async code via `tokio::task::spawn_blocking`. `SQLite` is
//! single-writer at the kernel level anyway and our workload is light.
//! WAL is enabled to keep reads from blocking the occasional write.

pub mod accounts;
pub mod clients;
pub mod codes;
pub mod crypto;
pub mod revocations;

use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use rusqlite::params;
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
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

const MIGRATION_001: &str = include_str!("migrations/001_initial.sql");
const MIGRATION_002: &str = include_str!("migrations/002_consent_and_revocation.sql");

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(MIGRATION_001), M::up(MIGRATION_002)])
}

/// Create the DB file at mode 0600 if absent, or tighten it if group/other
/// bits are set. No-op on non-unix and for `:memory:`.
#[cfg(unix)]
fn ensure_file_permissions(path: &str) -> Result<(), DbError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if path == ":memory:" || path.is_empty() {
        return Ok(());
    }
    let p = std::path::Path::new(path);
    if !p.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(p)?;
        return Ok(());
    }
    let meta = std::fs::metadata(p)?;
    if meta.permissions().mode() & 0o077 != 0 {
        let mut perm = meta.permissions();
        perm.set_mode(0o600);
        std::fs::set_permissions(p, perm)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_file_permissions(_path: &str) -> Result<(), DbError> {
    Ok(())
}

/// `rusqlite_migration` errors `DatabaseTooFarAhead` if an older binary later
/// opens a migrated DB, so back up before the 002 migration runs.
fn backup_before_migration(conn: &Connection, path: &str) -> Result<(), DbError> {
    if path == ":memory:" || path.is_empty() {
        return Ok(());
    }
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version != 1 {
        return Ok(());
    }
    let backup_path = format!("{path}.pre-002.bak");
    if std::path::Path::new(&backup_path).exists() {
        return Ok(());
    }
    // VACUUM INTO accepts an empty target, so pre-create it at 0600.
    ensure_file_permissions(&backup_path)?;
    conn.execute("VACUUM INTO ?1", params![backup_path])?;
    Ok(())
}

impl Db {
    /// Open (or create) the `SQLite` database at `path` and run all pending migrations.
    pub async fn open(path: impl Into<String>) -> Result<Self, DbError> {
        let path = path.into();
        let conn = tokio::task::spawn_blocking(move || -> Result<Connection, DbError> {
            ensure_file_permissions(&path)?;
            let mut conn = Connection::open(&path)?;
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "foreign_keys", "ON")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
            backup_before_migration(&conn, &path)?;
            migrations().to_latest(&mut conn)?;
            Ok(conn)
        })
        .await??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory database (for tests).
    #[cfg(test)]
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
        .map_or(0, |d| d.as_secs() as i64)
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

    #[tokio::test]
    async fn migration_002_adds_columns_and_table_on_fresh_db() {
        let db = Db::open_in_memory().await.expect("open");
        let cols: Vec<String> = db
            .call(|conn| {
                let mut stmt = conn.prepare("PRAGMA table_info(mcp_clients)")?;
                let names = stmt
                    .query_map([], |r| r.get::<_, String>(1))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(names)
            })
            .await
            .unwrap();
        assert!(cols.contains(&"last_used_at".to_string()));

        let revoked: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='revoked_subs'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(revoked, 1);
    }

    #[tokio::test]
    async fn migration_002_backfills_last_used_at_and_backs_up_v1_db() {
        let dir = std::env::temp_dir().join(format!("gmcp-mig-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("db.sqlite");
        let db_path_str = db_path.to_str().unwrap().to_string();

        // Create a v1-only DB by running just migration 001, seeding a client.
        {
            let mut conn = Connection::open(&db_path_str).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            Migrations::new(vec![M::up(MIGRATION_001)])
                .to_latest(&mut conn)
                .unwrap();
            conn.execute(
                "INSERT INTO mcp_clients (client_id, client_secret_hash, redirect_uris, client_name, created_at)
                 VALUES ('c1','h','[]',NULL, 1000)",
                [],
            )
            .unwrap();
        }

        let db = Db::open(db_path_str.clone()).await.expect("open v1 db");
        let last_used: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT last_used_at FROM mcp_clients WHERE client_id='c1'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert!(last_used > 0, "backfilled last_used_at should be set");

        let backup_path = format!("{db_path_str}.pre-002.bak");
        assert!(
            std::path::Path::new(&backup_path).exists(),
            "expected pre-002 backup at {backup_path}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&backup_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "backup should be created 0600");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn db_file_created_0600_and_loose_perms_tightened() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("gmcp-perm-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("db.sqlite");
        let db_path_str = db_path.to_str().unwrap().to_string();

        let _db = Db::open(db_path_str.clone()).await.expect("open");
        let mode = std::fs::metadata(&db_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "new DB should be created 0600");
        drop(_db);

        // A pre-existing, loosely-permissioned file gets tightened on open.
        let db_path2 = dir.join("db2.sqlite");
        std::fs::write(&db_path2, b"").unwrap();
        std::fs::set_permissions(&db_path2, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _db2 = Db::open(db_path2.to_str().unwrap().to_string())
            .await
            .expect("open");
        let mode2 = std::fs::metadata(&db_path2).unwrap().permissions().mode();
        assert_eq!(mode2 & 0o777, 0o600, "loose perms should be tightened");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
