//! `mcp_clients` CRUD. Stores Argon2id PHC hashes of MCP client secrets
//! issued via RFC 7591 dynamic client registration.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rusqlite::params;

use super::{Db, DbError, now_secs};

#[derive(Debug, Clone)]
pub struct McpClient {
    pub client_id: String,
    pub client_secret_hash: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub created_at: i64,
}

pub struct CreateClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
}

pub fn hash_secret(secret: &str) -> Result<String, DbError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|p| p.to_string())
        .map_err(|e| DbError::PasswordHash(e.to_string()))
}

pub fn verify_secret(secret: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(secret.as_bytes(), &parsed)
        .is_ok()
}

pub async fn create(db: &Db, req: CreateClient) -> Result<(), DbError> {
    let hash = hash_secret(&req.client_secret)?;
    let redirect_json = serde_json::to_string(&req.redirect_uris)
        .map_err(|_| DbError::Invalid("redirect_uris not JSON-serializable"))?;
    let now = now_secs();
    db.call(move |conn| {
        let n = conn.execute(
            "INSERT INTO mcp_clients
                (client_id, client_secret_hash, redirect_uris, client_name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
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
            "SELECT client_id, client_secret_hash, redirect_uris, client_name, created_at
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash_secret("super-secret").unwrap();
        assert!(verify_secret("super-secret", &h));
        assert!(!verify_secret("wrong", &h));
    }

    #[test]
    fn hash_is_unique_per_call() {
        let h1 = hash_secret("same").unwrap();
        let h2 = hash_secret("same").unwrap();
        assert_ne!(h1, h2, "salt must randomize");
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
        assert!(verify_secret("csecret", &c.client_secret_hash));
        assert!(!verify_secret("wrong", &c.client_secret_hash));
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
}
