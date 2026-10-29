//! `mcp_refresh_tokens` — rotating refresh tokens for `/oauth/token`.
//!
//! Each use issues a new token in the same family and marks the old one used.
//! Presenting a used token again means it was copied: the whole family is
//! deleted (RFC 9700 section 4.14.2).

use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::{Db, DbError, now_secs};

/// Idle lifetime: every rotation starts a new one.
pub const REFRESH_TTL_SECS: i64 = 30 * 24 * 3600;

pub struct IssueRefresh {
    pub family_id: String,
    pub mcp_client_id: String,
    pub google_sub: String,
    pub resource: Option<String>,
}

/// The grant behind a redeemed refresh token.
#[derive(Debug, Clone)]
pub struct RefreshGrant {
    pub family_id: String,
    pub mcp_client_id: String,
    pub google_sub: String,
    pub resource: Option<String>,
    pub issued_at: i64,
}

#[derive(Debug)]
pub enum Redeemed {
    Valid(RefreshGrant),
    /// Unknown or expired.
    Invalid,
    /// Already used once; its family has been revoked.
    Replayed,
}

fn hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Store `token` (only its hash) for a new or continuing family.
pub async fn issue(db: &Db, token: &str, req: IssueRefresh) -> Result<(), DbError> {
    let token_hash = hash(token);
    let now = now_secs();
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO mcp_refresh_tokens
                (token_hash, family_id, mcp_client_id, google_sub, resource, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                token_hash,
                req.family_id,
                req.mcp_client_id,
                req.google_sub,
                req.resource,
                now,
                now + REFRESH_TTL_SECS,
            ],
        )?;
        Ok(())
    })
    .await
}

/// Mark `token` used and return its grant. A token can be redeemed once.
pub async fn redeem(db: &Db, token: &str) -> Result<Redeemed, DbError> {
    let token_hash = hash(token);
    let now = now_secs();
    db.call(move |conn| {
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM mcp_refresh_tokens WHERE expires_at <= ?1",
            params![now],
        )?;
        let row = tx
            .query_row(
                "SELECT family_id, mcp_client_id, google_sub, resource, issued_at, used_at
                 FROM mcp_refresh_tokens WHERE token_hash = ?1",
                [&token_hash],
                |r| {
                    Ok((
                        RefreshGrant {
                            family_id: r.get(0)?,
                            mcp_client_id: r.get(1)?,
                            google_sub: r.get(2)?,
                            resource: r.get(3)?,
                            issued_at: r.get(4)?,
                        },
                        r.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()?;
        let result = match row {
            None => Redeemed::Invalid,
            Some((grant, Some(_))) => {
                tx.execute(
                    "DELETE FROM mcp_refresh_tokens WHERE family_id = ?1",
                    params![grant.family_id],
                )?;
                Redeemed::Replayed
            }
            Some((grant, None)) => {
                tx.execute(
                    "UPDATE mcp_refresh_tokens SET used_at = ?1 WHERE token_hash = ?2",
                    params![now, token_hash],
                )?;
                Redeemed::Valid(grant)
            }
        };
        tx.commit()?;
        Ok(result)
    })
    .await
}

pub async fn delete_family(db: &Db, family_id: &str) -> Result<(), DbError> {
    let family_id = family_id.to_string();
    db.call(move |conn| {
        conn.execute(
            "DELETE FROM mcp_refresh_tokens WHERE family_id = ?1",
            params![family_id],
        )?;
        Ok(())
    })
    .await
}

/// Forget every refresh token of an account (revocation, disconnect).
pub async fn delete_for_sub(db: &Db, google_sub: &str) -> Result<usize, DbError> {
    let google_sub = google_sub.to_string();
    db.call(move |conn| {
        Ok(conn.execute(
            "DELETE FROM mcp_refresh_tokens WHERE google_sub = ?1",
            params![google_sub],
        )?)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(family: &str, sub: &str) -> IssueRefresh {
        IssueRefresh {
            family_id: family.to_string(),
            mcp_client_id: "cid".to_string(),
            google_sub: sub.to_string(),
            resource: Some("http://localhost:8433/mcp".to_string()),
        }
    }

    #[tokio::test]
    async fn redeems_once_and_replay_revokes_the_family() {
        let db = Db::open_in_memory().await.unwrap();
        issue(&db, "rt-1", req("fam", "sub-1")).await.unwrap();
        let Redeemed::Valid(grant) = redeem(&db, "rt-1").await.unwrap() else {
            panic!("first use is valid");
        };
        assert_eq!(grant.google_sub, "sub-1");
        assert_eq!(grant.mcp_client_id, "cid");
        issue(&db, "rt-2", req("fam", "sub-1")).await.unwrap();

        assert!(matches!(
            redeem(&db, "rt-1").await.unwrap(),
            Redeemed::Replayed
        ));
        // The replay took the successor with it.
        assert!(matches!(
            redeem(&db, "rt-2").await.unwrap(),
            Redeemed::Invalid
        ));
    }

    #[tokio::test]
    async fn unknown_and_expired_tokens_are_invalid() {
        let db = Db::open_in_memory().await.unwrap();
        assert!(matches!(
            redeem(&db, "nope").await.unwrap(),
            Redeemed::Invalid
        ));
        issue(&db, "old", req("fam", "sub-1")).await.unwrap();
        db.call(|conn| {
            conn.execute("UPDATE mcp_refresh_tokens SET expires_at = 1", [])?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(matches!(
            redeem(&db, "old").await.unwrap(),
            Redeemed::Invalid
        ));
    }

    #[tokio::test]
    async fn only_hashes_are_stored() {
        let db = Db::open_in_memory().await.unwrap();
        issue(&db, "secret-token", req("fam", "sub-1"))
            .await
            .unwrap();
        let stored: String = db
            .call(|conn| {
                Ok(
                    conn.query_row("SELECT token_hash FROM mcp_refresh_tokens", [], |r| {
                        r.get(0)
                    })?,
                )
            })
            .await
            .unwrap();
        assert_ne!(stored, "secret-token");
        assert_eq!(stored.len(), 64);
    }

    #[tokio::test]
    async fn delete_for_sub_spares_other_accounts() {
        let db = Db::open_in_memory().await.unwrap();
        issue(&db, "a", req("f1", "sub-1")).await.unwrap();
        issue(&db, "b", req("f2", "sub-2")).await.unwrap();
        assert_eq!(delete_for_sub(&db, "sub-1").await.unwrap(), 1);
        assert!(matches!(redeem(&db, "a").await.unwrap(), Redeemed::Invalid));
        assert!(matches!(
            redeem(&db, "b").await.unwrap(),
            Redeemed::Valid(_)
        ));
    }
}
