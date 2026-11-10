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
pub mod refresh_tokens;
pub mod revocations;

use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use rusqlite::params;

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database schema version {db} is newer than this binary supports ({binary})")]
    DatabaseTooFarAhead { db: i64, binary: i64 },
    #[error("invalid database user_version {0}")]
    InvalidUserVersion(i64),
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
const MIGRATION_003: &str = include_str!("migrations/003_refresh_tokens.sql");
const MIGRATION_004: &str = include_str!("migrations/004_refresh_rotation_and_client_auth.sql");
/// Migration `n` (1-based) leaves `user_version` at `n`.
const MIGRATIONS: &[&str] = &[MIGRATION_001, MIGRATION_002, MIGRATION_003, MIGRATION_004];
const LATEST_VERSION: i64 = MIGRATIONS.len() as i64;

/// Run the migrations past `user_version` in one transaction and store their count in it.
fn migrate_to(conn: &mut Connection, migrations: &[&str]) -> Result<(), DbError> {
    let target = migrations.len() as i64;
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current < 0 {
        return Err(DbError::InvalidUserVersion(current));
    }
    if current > target {
        return Err(DbError::DatabaseTooFarAhead {
            db: current,
            binary: target,
        });
    }
    if current == target {
        return Ok(());
    }
    let tx = conn.transaction()?;
    for sql in &migrations[current as usize..] {
        tx.execute_batch(sql)?;
    }
    tx.pragma_update(None, "user_version", target)?;
    tx.commit()?;
    Ok(())
}

fn migrate_to_latest(conn: &mut Connection) -> Result<(), DbError> {
    migrate_to(conn, MIGRATIONS)
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

/// An older binary refuses a DB newer than itself (`DbError::DatabaseTooFarAhead`),
/// so back up an existing DB before any migration runs, as `<path>.pre-<next version>.bak`.
fn backup_before_migration(conn: &Connection, path: &str) -> Result<(), DbError> {
    if path == ":memory:" || path.is_empty() {
        return Ok(());
    }
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if !(1..LATEST_VERSION).contains(&version) {
        return Ok(());
    }
    let backup_path = format!("{path}.pre-{:03}.bak", version + 1);
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
            migrate_to_latest(&mut conn)?;
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
            migrate_to_latest(&mut conn)?;
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

    #[test]
    fn latest_version_counts_every_migration() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate_to_latest(&mut conn).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, LATEST_VERSION);
    }

    #[test]
    fn fresh_database_ends_at_user_version_4() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate_to_latest(&mut conn).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 4);
    }

    #[test]
    fn database_newer_than_binary_is_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate_to_latest(&mut conn).unwrap();
        conn.pragma_update(None, "user_version", 5).unwrap();
        let err = migrate_to_latest(&mut conn).unwrap_err();
        assert!(matches!(
            err,
            DbError::DatabaseTooFarAhead { db: 5, binary: 4 }
        ));
        assert_eq!(
            err.to_string(),
            "database schema version 5 is newer than this binary supports (4)"
        );
    }

    #[test]
    fn negative_user_version_is_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", -1).unwrap();
        let err = migrate_to_latest(&mut conn).unwrap_err();
        assert!(matches!(err, DbError::InvalidUserVersion(-1)));
        assert_eq!(err.to_string(), "invalid database user_version -1");
    }

    #[test]
    fn failed_migration_rolls_back_the_whole_run() {
        let mut conn = Connection::open_in_memory().unwrap();
        let err = migrate_to(&mut conn, &["CREATE TABLE a(x);", "THIS IS NOT SQL"]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "sqlite: near \"THIS\": syntax error in THIS IS NOT SQL at offset 0"
        );
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 0);
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='a'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
    }

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
            migrate_to_latest(conn)?;
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
            migrate_to(&mut conn, &MIGRATIONS[..1]).unwrap();
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

    async fn client_columns(db: &Db) -> Vec<String> {
        db.call(|conn| {
            let mut stmt = conn.prepare("PRAGMA table_info(mcp_clients)")?;
            let names = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(names)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn migration_004_adds_auth_method_column_on_fresh_db() {
        let db = Db::open_in_memory().await.expect("open");
        assert!(
            client_columns(&db)
                .await
                .contains(&"token_endpoint_auth_method".to_string())
        );
        let cols: Vec<String> = db
            .call(|conn| {
                let mut stmt = conn.prepare("PRAGMA table_info(mcp_refresh_tokens)")?;
                let names = stmt
                    .query_map([], |r| r.get::<_, String>(1))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(names)
            })
            .await
            .unwrap();
        assert!(cols.contains(&"family_issued_at".to_string()));
        assert!(cols.contains(&"successor_ct".to_string()));
        assert!(cols.contains(&"successor_nonce".to_string()));
        assert!(!cols.contains(&"grace_used".to_string()));
    }

    #[tokio::test]
    async fn migration_004_upgrades_contributor_v3_db() {
        let dir = std::env::temp_dir().join(format!("gmcp-mig4-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("db.sqlite");
        let db_path_str = db_path.to_str().unwrap().to_string();

        {
            let mut conn = Connection::open(&db_path_str).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            migrate_to(&mut conn, &MIGRATIONS[..3]).unwrap();
            conn.execute(
                "INSERT INTO mcp_clients (client_id, client_secret_hash, redirect_uris, client_name, created_at)
                 VALUES ('legacy','h','[]',NULL, 1000)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO oauth_accounts (google_sub, email, refresh_token_ct, refresh_token_nonce, scopes, created_at, updated_at)
                 VALUES ('sub-1','sam@example.com',x'00',x'00','',0,0)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO mcp_refresh_tokens (token_hash, family_id, mcp_client_id, google_sub, resource, issued_at, expires_at, used_at)
                 VALUES ('old-hash','old-fam','legacy','sub-1',NULL,1000,9999999999,NULL)",
                [],
            )
            .unwrap();
        }

        let db = Db::open(db_path_str.clone()).await.expect("open v3 db");
        assert!(
            client_columns(&db)
                .await
                .contains(&"token_endpoint_auth_method".to_string())
        );
        let method: Option<String> = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT token_endpoint_auth_method FROM mcp_clients WHERE client_id='legacy'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert!(method.is_none(), "pre-existing rows stay NULL (legacy)");

        let old_rows: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM mcp_refresh_tokens WHERE token_hash = 'old-hash'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(old_rows, 0, "old-schema rows are dropped");
        refresh_tokens::issue(
            &db,
            "fresh-token",
            refresh_tokens::IssueRefresh {
                family_id: "fam".to_string(),
                mcp_client_id: "legacy".to_string(),
                google_sub: "sub-1".to_string(),
                resource: None,
            },
        )
        .await
        .unwrap();
        let rotated = refresh_tokens::rotate(
            &db,
            refresh_tokens::RotateRequest {
                presented: "fresh-token",
                client_id: "legacy",
                resource: None,
                successor: "next-token",
                grace_secs: 10,
                encryption_key: &[0u8; 32],
            },
        )
        .await
        .unwrap();
        assert!(matches!(rotated, refresh_tokens::Rotation::Valid { .. }));

        let backup_path = format!("{db_path_str}.pre-004.bak");
        assert!(
            std::path::Path::new(&backup_path).exists(),
            "expected pre-004 backup at {backup_path}"
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
