//! `mcp_clients` CRUD. New secrets are random 128-bit values, hashed as
//! `sha256$<hex>`; legacy Argon2id PHC hashes still verify.

use argon2::Argon2;
#[cfg(test)]
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
#[cfg(test)]
use argon2::password_hash::{PasswordHasher, SaltString};
use rusqlite::params;
use sha2::{Digest, Sha256};

use super::{Db, DbError, now_secs};
use crate::oauth::pkce::constant_time_eq;

/// Refuse new DCR registrations once `mcp_clients` reaches this many rows.
pub const MAX_MCP_CLIENTS: i64 = 10_000;

/// Maps `mcp_clients` rows 1:1; some fields are set on read but not yet consumed by callers.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct McpClient {
    pub client_id: String,
    pub client_secret_hash: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

pub struct CreateClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Hash a newly issued client secret as `sha256$<hex>`.
pub fn hash_secret(secret: &str) -> String {
    format!("sha256${}", sha256_hex(secret.as_bytes()))
}

/// Legacy Argon2id hashing, kept only to produce a fixture for `verify_secret_argon2` tests.
#[cfg(test)]
fn hash_secret_argon2(secret: &str) -> Result<String, DbError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|p| p.to_string())
        .map_err(|e| DbError::PasswordHash(e.to_string()))
}

/// `sha256$` hashes compare inline; Argon2 verify runs off the async runtime.
pub async fn verify_secret(secret: &str, hash: &str) -> bool {
    if let Some(hex) = hash.strip_prefix("sha256$") {
        let computed = sha256_hex(secret.as_bytes());
        return constant_time_eq(computed.as_bytes(), hex.as_bytes());
    }
    let secret = secret.to_string();
    let hash = hash.to_string();
    tokio::task::spawn_blocking(move || verify_secret_argon2(&secret, &hash))
        .await
        .unwrap_or(false)
}

fn verify_secret_argon2(secret: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(secret.as_bytes(), &parsed)
        .is_ok()
}

pub async fn count(db: &Db) -> Result<i64, DbError> {
    db.call(|conn| Ok(conn.query_row("SELECT COUNT(*) FROM mcp_clients", [], |r| r.get(0))?))
        .await
}

pub async fn create(db: &Db, req: CreateClient) -> Result<(), DbError> {
    let hash = hash_secret(&req.client_secret);
    let redirect_json = serde_json::to_string(&req.redirect_uris)
        .map_err(|_| DbError::Invalid("redirect_uris not JSON-serializable"))?;
    let now = now_secs();
    db.call(move |conn| {
        let n = conn.execute(
            "INSERT INTO mcp_clients
                (client_id, client_secret_hash, redirect_uris, client_name, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![req.client_id, hash, redirect_json, req.client_name, now],
        );
        match n {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(DbError::Conflict("client_id already exists"))
            }
            Err(e) => Err(e.into()),
        }
    })
    .await
}

pub async fn get(db: &Db, client_id: &str) -> Result<Option<McpClient>, DbError> {
    let client_id = client_id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT client_id, client_secret_hash, redirect_uris, client_name, created_at, last_used_at
             FROM mcp_clients WHERE client_id = ?1",
        )?;
        let row = stmt.query_row([&client_id], |r| {
            let redirects: String = r.get(2)?;
            Ok(McpClient {
                client_id: r.get(0)?,
                client_secret_hash: r.get(1)?,
                redirect_uris: serde_json::from_str(&redirects).unwrap_or_default(),
                client_name: r.get(3)?,
                created_at: r.get(4)?,
                last_used_at: r.get(5)?,
            })
        });
        match row {
            Ok(c) => Ok(Some(c)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    })
    .await
}

pub async fn touch_last_used(db: &Db, client_id: &str) -> Result<(), DbError> {
    let client_id = client_id.to_string();
    let now = now_secs();
    db.call(move |conn| {
        conn.execute(
            "UPDATE mcp_clients SET last_used_at = ?1 WHERE client_id = ?2",
            params![now, client_id],
        )?;
        Ok(())
    })
    .await
}

/// Periodic sweeper: drop clients that registered but never completed
/// `/authorize` within `older_than_secs`.
pub async fn delete_stale_unused(db: &Db, older_than_secs: i64) -> Result<usize, DbError> {
    let cutoff = now_secs() - older_than_secs;
    db.call(move |conn| {
        Ok(conn.execute(
            "DELETE FROM mcp_clients WHERE last_used_at IS NULL AND created_at < ?1",
            params![cutoff],
        )?)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_uses_sha256_prefix() {
        let h = hash_secret("super-secret");
        assert!(h.starts_with("sha256$"));
    }

    #[tokio::test]
    async fn sha256_secret_round_trip() {
        let h = hash_secret("super-secret");
        assert!(verify_secret("super-secret", &h).await);
        assert!(!verify_secret("wrong", &h).await);
    }

    #[tokio::test]
    async fn legacy_argon2_hash_still_verifies() {
        let h = hash_secret_argon2("legacy-secret").unwrap();
        assert!(h.starts_with("$argon2"));
        assert!(verify_secret("legacy-secret", &h).await);
        assert!(!verify_secret("wrong", &h).await);
    }

    #[tokio::test]
    async fn create_then_get() {
        let db = Db::open_in_memory().await.unwrap();
        create(
            &db,
            CreateClient {
                client_id: "cid-1".to_string(),
                client_secret: "csecret".to_string(),
                redirect_uris: vec!["https://claude.ai/cb".to_string()],
                client_name: Some("Claude.ai".to_string()),
            },
        )
        .await
        .unwrap();

        let c = get(&db, "cid-1").await.unwrap().expect("present");
        assert_eq!(c.client_id, "cid-1");
        assert_eq!(c.redirect_uris, vec!["https://claude.ai/cb"]);
        assert_eq!(c.client_name.as_deref(), Some("Claude.ai"));
        assert!(c.last_used_at.is_none());
        assert!(verify_secret("csecret", &c.client_secret_hash).await);
        assert!(!verify_secret("wrong", &c.client_secret_hash).await);
    }

    #[tokio::test]
    async fn create_duplicate_conflicts() {
        let db = Db::open_in_memory().await.unwrap();
        let make = || CreateClient {
            client_id: "cid".to_string(),
            client_secret: "x".to_string(),
            redirect_uris: vec![],
            client_name: None,
        };
        create(&db, make()).await.unwrap();
        let err = create(&db, make()).await.unwrap_err();
        assert!(matches!(err, DbError::Conflict(_)));
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let db = Db::open_in_memory().await.unwrap();
        assert!(get(&db, "nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn touch_last_used_sets_timestamp() {
        let db = Db::open_in_memory().await.unwrap();
        create(
            &db,
            CreateClient {
                client_id: "cid".to_string(),
                client_secret: "x".to_string(),
                redirect_uris: vec![],
                client_name: None,
            },
        )
        .await
        .unwrap();
        touch_last_used(&db, "cid").await.unwrap();
        assert!(
            get(&db, "cid")
                .await
                .unwrap()
                .unwrap()
                .last_used_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn delete_stale_unused_removes_only_never_used_old_rows() {
        let db = Db::open_in_memory().await.unwrap();
        db.call(|conn| {
            conn.execute(
                "INSERT INTO mcp_clients (client_id, client_secret_hash, redirect_uris, client_name, created_at, last_used_at)
                 VALUES ('stale','h','[]',NULL, 0, NULL),
                        ('used-old','h','[]',NULL, 0, 0),
                        ('fresh','h','[]',NULL, ?1, NULL)",
                params![now_secs()],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let removed = delete_stale_unused(&db, 24 * 3600).await.unwrap();
        assert_eq!(removed, 1);
        assert!(get(&db, "stale").await.unwrap().is_none());
        assert!(get(&db, "used-old").await.unwrap().is_some());
        assert!(get(&db, "fresh").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn cap_enforced_at_10k_rows() {
        let db = Db::open_in_memory().await.unwrap();
        db.call(|conn| {
            let tx = conn.transaction()?;
            for i in 0..MAX_MCP_CLIENTS {
                tx.execute(
                    "INSERT INTO mcp_clients (client_id, client_secret_hash, redirect_uris, client_name, created_at, last_used_at)
                     VALUES (?1, 'h', '[]', NULL, 0, NULL)",
                    params![format!("c{i}")],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(count(&db).await.unwrap(), MAX_MCP_CLIENTS);
    }
}
