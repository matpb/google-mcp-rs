//! `oauth_codes` and `oauth_states` — both single-use, expiring records used
//! to thread state through the OAuth flow.
//!
//! - `oauth_codes`: MCP authorization codes redeemed at `/oauth/token`.
//! - `oauth_states`: opaque tokens we send to Google as `state` and consume
//!   when Google redirects back to `/oauth/google/callback`.

use rusqlite::params;

use super::{Db, DbError, now_secs};

const CODE_TTL_SECS: i64 = 300;
const STATE_TTL_SECS: i64 = 300;

#[derive(Debug, Clone)]
pub struct OauthCode {
    pub code: String,
    pub mcp_client_id: String,
    pub mcp_redirect_uri: String,
    pub code_challenge: String,
    pub google_sub: String,
    pub resource: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct OauthState {
    pub state_id: String,
    pub mcp_client_id: String,
    pub mcp_redirect_uri: String,
    pub mcp_state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub resource: Option<String>,
    pub expires_at: i64,
}

pub struct InsertCode {
    pub code: String,
    pub mcp_client_id: String,
    pub mcp_redirect_uri: String,
    pub code_challenge: String,
    pub google_sub: String,
    pub resource: Option<String>,
}

pub struct InsertState {
    pub state_id: String,
    pub mcp_client_id: String,
    pub mcp_redirect_uri: String,
    pub mcp_state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub resource: Option<String>,
}

pub async fn insert_code(db: &Db, req: InsertCode) -> Result<(), DbError> {
    let expires_at = now_secs() + CODE_TTL_SECS;
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO oauth_codes
                (code, mcp_client_id, mcp_redirect_uri, code_challenge,
                 google_sub, resource, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                req.code,
                req.mcp_client_id,
                req.mcp_redirect_uri,
                req.code_challenge,
                req.google_sub,
                req.resource,
                expires_at,
            ],
        )?;
        Ok(())
    })
    .await
}

/// Fetch and delete the code in one transaction. Returns `None` if missing
/// or expired (and removes expired rows opportunistically).
pub async fn consume_code(db: &Db, code: &str) -> Result<Option<OauthCode>, DbError> {
    let code = code.to_string();
    db.call(move |conn| {
        let tx = conn.transaction()?;
        let row: Option<OauthCode> = {
            let mut stmt = tx.prepare(
                "SELECT code, mcp_client_id, mcp_redirect_uri, code_challenge,
                        google_sub, resource, expires_at
                 FROM oauth_codes WHERE code = ?1",
            )?;
            let result = stmt.query_row([&code], |r| {
                Ok(OauthCode {
                    code: r.get(0)?,
                    mcp_client_id: r.get(1)?,
                    mcp_redirect_uri: r.get(2)?,
                    code_challenge: r.get(3)?,
                    google_sub: r.get(4)?,
                    resource: r.get(5)?,
                    expires_at: r.get(6)?,
                })
            });
            match result {
                Ok(r) => Some(r),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(DbError::from(e)),
            }
        };
        // Always delete the row (single-use) regardless of whether it has expired.
        tx.execute("DELETE FROM oauth_codes WHERE code = ?1", params![code])?;
        tx.commit()?;
        Ok(row.filter(|r| r.expires_at >= now_secs()))
    })
    .await
}

pub async fn insert_state(db: &Db, req: InsertState) -> Result<(), DbError> {
    let expires_at = now_secs() + STATE_TTL_SECS;
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO oauth_states
                (state_id, mcp_client_id, mcp_redirect_uri, mcp_state,
                 code_challenge, code_challenge_method, resource, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                req.state_id,
                req.mcp_client_id,
                req.mcp_redirect_uri,
                req.mcp_state,
                req.code_challenge,
                req.code_challenge_method,
                req.resource,
                expires_at,
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn consume_state(db: &Db, state_id: &str) -> Result<Option<OauthState>, DbError> {
    let state_id = state_id.to_string();
    db.call(move |conn| {
        let tx = conn.transaction()?;
        let row: Option<OauthState> = {
            let mut stmt = tx.prepare(
                "SELECT state_id, mcp_client_id, mcp_redirect_uri, mcp_state,
                        code_challenge, code_challenge_method, resource, expires_at
                 FROM oauth_states WHERE state_id = ?1",
            )?;
            let result = stmt.query_row([&state_id], |r| {
                Ok(OauthState {
                    state_id: r.get(0)?,
                    mcp_client_id: r.get(1)?,
                    mcp_redirect_uri: r.get(2)?,
                    mcp_state: r.get(3)?,
                    code_challenge: r.get(4)?,
                    code_challenge_method: r.get(5)?,
                    resource: r.get(6)?,
                    expires_at: r.get(7)?,
                })
            });
            match result {
                Ok(r) => Some(r),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(DbError::from(e)),
            }
        };
        tx.execute(
            "DELETE FROM oauth_states WHERE state_id = ?1",
            params![state_id],
        )?;
        tx.commit()?;
        Ok(row.filter(|r| r.expires_at >= now_secs()))
    })
    .await
}

/// Garbage-collect expired codes and states. Safe to call periodically.
pub async fn sweep_expired(db: &Db) -> Result<usize, DbError> {
    let now = now_secs();
    db.call(move |conn| {
        let a = conn.execute("DELETE FROM oauth_codes WHERE expires_at < ?1", params![now])?;
        let b = conn.execute("DELETE FROM oauth_states WHERE expires_at < ?1", params![now])?;
        Ok(a + b)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::accounts;
    use crate::storage::clients;

    fn key() -> [u8; 32] {
        [42u8; 32]
    }

    async fn seed_account(db: &Db, sub: &str) {
        accounts::upsert(
            db,
            &key(),
            accounts::UpsertAccount {
                google_sub: sub.to_string(),
                email: format!("{sub}@x.com"),
                refresh_token: "t".to_string(),
                scopes: vec![],
            },
        )
        .await
        .unwrap();
    }

    async fn seed_client(db: &Db, cid: &str) {
        clients::create(
            db,
            clients::CreateClient {
                client_id: cid.to_string(),
                client_secret: "s".to_string(),
                redirect_uris: vec!["https://x/cb".to_string()],
                client_name: None,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn code_round_trip() {
        let db = Db::open_in_memory().await.unwrap();
        seed_client(&db, "cid").await;
        seed_account(&db, "sub").await;
        insert_code(
            &db,
            InsertCode {
                code: "c-1".to_string(),
                mcp_client_id: "cid".to_string(),
                mcp_redirect_uri: "https://x/cb".to_string(),
                code_challenge: "ch".to_string(),
                google_sub: "sub".to_string(),
                resource: Some("https://x/mcp".to_string()),
            },
        )
        .await
        .unwrap();

        let c = consume_code(&db, "c-1").await.unwrap().expect("present");
        assert_eq!(c.code, "c-1");
        assert_eq!(c.google_sub, "sub");
        assert_eq!(c.resource.as_deref(), Some("https://x/mcp"));
        // Second consume returns None (single-use).
        assert!(consume_code(&db, "c-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn state_round_trip() {
        let db = Db::open_in_memory().await.unwrap();
        seed_client(&db, "cid").await;
        insert_state(
            &db,
            InsertState {
                state_id: "s-1".to_string(),
                mcp_client_id: "cid".to_string(),
                mcp_redirect_uri: "https://x/cb".to_string(),
                mcp_state: Some("client-state".to_string()),
                code_challenge: "ch".to_string(),
                code_challenge_method: "S256".to_string(),
                resource: None,
            },
        )
        .await
        .unwrap();

        let s = consume_state(&db, "s-1").await.unwrap().expect("present");
        assert_eq!(s.state_id, "s-1");
        assert_eq!(s.mcp_state.as_deref(), Some("client-state"));
        assert!(consume_state(&db, "s-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_code_returns_none_but_is_removed() {
        let db = Db::open_in_memory().await.unwrap();
        seed_client(&db, "cid").await;
        seed_account(&db, "sub").await;
        // Insert directly with a past expiry to bypass the helper's TTL.
        db.call(|conn| {
            conn.execute(
                "INSERT INTO oauth_codes (code, mcp_client_id, mcp_redirect_uri,
                    code_challenge, google_sub, resource, expires_at)
                 VALUES ('c-old','cid','https://x/cb','ch','sub',NULL, ?1)",
                params![now_secs() - 1],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(consume_code(&db, "c-old").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sweep_deletes_expired_rows() {
        let db = Db::open_in_memory().await.unwrap();
        seed_client(&db, "cid").await;
        seed_account(&db, "sub").await;
        db.call(|conn| {
            conn.execute(
                "INSERT INTO oauth_codes (code, mcp_client_id, mcp_redirect_uri,
                    code_challenge, google_sub, resource, expires_at)
                 VALUES ('expired','cid','https://x/cb','ch','sub',NULL, ?1),
                        ('fresh',  'cid','https://x/cb','ch','sub',NULL, ?2)",
                params![now_secs() - 10, now_secs() + 600],
            )?;
            conn.execute(
                "INSERT INTO oauth_states (state_id, mcp_client_id, mcp_redirect_uri,
                    mcp_state, code_challenge, code_challenge_method, resource, expires_at)
                 VALUES ('s-old','cid','https://x/cb',NULL,'ch','S256',NULL, ?1)",
                params![now_secs() - 1],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let removed = sweep_expired(&db).await.unwrap();
        assert_eq!(removed, 2, "expected 1 code + 1 state removed");

        let remaining: i64 = db
            .call(|conn| Ok(conn.query_row("SELECT COUNT(*) FROM oauth_codes", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(remaining, 1, "fresh code should remain");
    }
}
