//! `mcp_refresh_tokens`: rotating refresh tokens for `/oauth/token`.
//! Within the grace window a used token is answered with the same successor again; any other reuse deletes its family.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::crypto::{seal, unseal};
use super::{Db, DbError, now_secs};
use crate::config::MAX_REFRESH_REUSE_GRACE_SECS;

/// Idle lifetime: every rotation starts a new one.
pub const REFRESH_TTL_SECS: i64 = 30 * 24 * 3600;
/// Absolute lifetime of a family: re-consent is required after this.
pub const REFRESH_FAMILY_MAX_AGE_SECS: i64 = 90 * 24 * 3600;
/// Used rows kept per family; older ones are deleted on rotation.
pub const MAX_USED_ROWS_PER_FAMILY: i64 = 1000;

pub struct IssueRefresh {
    pub family_id: String,
    pub mcp_client_id: String,
    pub google_sub: String,
    pub resource: Option<String>,
}

/// The grant behind a rotated refresh token; callers read only some fields so far.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RefreshGrant {
    pub family_id: String,
    pub mcp_client_id: String,
    pub google_sub: String,
    pub resource: Option<String>,
    pub issued_at: i64,
    pub family_issued_at: i64,
}

#[derive(Debug)]
pub enum Rotation {
    /// `refresh_token` is what the client receives: the fresh successor, or the one already issued.
    Valid {
        grant: RefreshGrant,
        refresh_token: String,
    },
    /// Unknown or expired (idle or absolute).
    Invalid,
    /// Used token outside the grace, or its successor is gone or used: family deleted.
    Replayed,
    /// Presented by another client: family deleted.
    WrongClient,
    /// Requested resource differs from the stored one: nothing changed.
    WrongResource,
    /// The account was revoked after this family began: family deleted.
    Revoked,
    /// The Google account is no longer connected: family deleted.
    Disconnected,
}

pub struct RotateRequest<'a> {
    pub presented: &'a str,
    pub client_id: &'a str,
    /// From the token request; `None` keeps the stored resource.
    pub resource: Option<&'a str>,
    /// New plaintext token; only its hash is stored.
    pub successor: &'a str,
    /// Seconds a used token is answered with the same successor again; 0 disables.
    pub grace_secs: i64,
    /// `STORAGE_ENCRYPTION_KEY`; seals the successor for the grace window.
    pub encryption_key: &'a [u8; 32],
}

fn hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Store `token` (only its hash) as the first token of a new family.
pub async fn issue(db: &Db, token: &str, req: IssueRefresh) -> Result<(), DbError> {
    let token_hash = hash(token);
    let now = now_secs();
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO mcp_refresh_tokens
                (token_hash, family_id, mcp_client_id, google_sub, resource, issued_at, expires_at, family_issued_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?6)",
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

const SWEEP_SQL: &str =
    "DELETE FROM mcp_refresh_tokens WHERE expires_at <= ?1 OR family_issued_at <= ?2";
const WIPE_SQL: &str = "UPDATE mcp_refresh_tokens SET successor_nonce = NULL, successor_ct = NULL
    WHERE used_at IS NOT NULL AND used_at <= ?1 AND successor_ct IS NOT NULL";

fn successor_aad(token_hash: &str) -> Vec<u8> {
    [b"mcp-refresh-successor:".as_slice(), token_hash.as_bytes()].concat()
}

/// Delete idle-expired rows and families past the absolute cap, and wipe stale sealed successors.
pub async fn sweep(db: &Db) -> Result<usize, DbError> {
    let now = now_secs();
    db.call(move |conn| {
        let removed = conn.execute(SWEEP_SQL, params![now, now - REFRESH_FAMILY_MAX_AGE_SECS])?;
        conn.execute(WIPE_SQL, params![now - MAX_REFRESH_REUSE_GRACE_SECS])?;
        Ok(removed)
    })
    .await
}

struct StoredToken {
    family_id: String,
    mcp_client_id: String,
    google_sub: String,
    resource: Option<String>,
    used_at: Option<i64>,
    family_issued_at: i64,
    successor_nonce: Option<Vec<u8>>,
    successor_ct: Option<Vec<u8>>,
}

/// Retire `presented` and store `successor` atomically, or refuse and say why.
/// Every check runs before any write; a SQL error rolls everything back.
pub async fn rotate(db: &Db, req: RotateRequest<'_>) -> Result<Rotation, DbError> {
    let presented_hash = hash(req.presented);
    let successor_hash = hash(req.successor);
    let successor = req.successor.to_string();
    let client_id = req.client_id.to_string();
    let resource = req.resource.map(str::to_string);
    let grace_secs = req.grace_secs;
    let key = *req.encryption_key;
    let now = now_secs();
    db.call(move |conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(SWEEP_SQL, params![now, now - REFRESH_FAMILY_MAX_AGE_SECS])?;
        tx.execute(WIPE_SQL, params![now - MAX_REFRESH_REUSE_GRACE_SECS])?;

        let stored = tx
            .query_row(
                "SELECT family_id, mcp_client_id, google_sub, resource, used_at, family_issued_at, successor_nonce, successor_ct
                 FROM mcp_refresh_tokens WHERE token_hash = ?1",
                [&presented_hash],
                |r| {
                    Ok(StoredToken {
                        family_id: r.get(0)?,
                        mcp_client_id: r.get(1)?,
                        google_sub: r.get(2)?,
                        resource: r.get(3)?,
                        used_at: r.get(4)?,
                        family_issued_at: r.get(5)?,
                        successor_nonce: r.get(6)?,
                        successor_ct: r.get(7)?,
                    })
                },
            )
            .optional()?;
        let Some(stored) = stored else {
            tx.commit()?;
            return Ok(Rotation::Invalid);
        };

        let burn = |outcome: Rotation| -> Result<Rotation, DbError> {
            tx.execute(
                "DELETE FROM mcp_refresh_tokens WHERE family_id = ?1",
                params![stored.family_id],
            )?;
            Ok(outcome)
        };

        let in_grace = match stored.used_at {
            None => false,
            Some(used_at) => {
                if grace_secs > 0 && now - used_at <= grace_secs {
                    true
                } else {
                    let out = burn(Rotation::Replayed)?;
                    tx.commit()?;
                    return Ok(out);
                }
            }
        };
        if stored.mcp_client_id != client_id {
            let out = burn(Rotation::WrongClient)?;
            tx.commit()?;
            return Ok(out);
        }
        if let Some(requested) = resource.as_deref()
            && stored.resource.as_deref() != Some(requested)
        {
            tx.commit()?;
            return Ok(Rotation::WrongResource);
        }
        let not_before: Option<i64> = tx
            .query_row(
                "SELECT not_before FROM revoked_subs WHERE google_sub = ?1",
                [&stored.google_sub],
                |r| r.get(0),
            )
            .optional()?;
        if not_before.is_some_and(|nb| nb >= stored.family_issued_at) {
            let out = burn(Rotation::Revoked)?;
            tx.commit()?;
            return Ok(out);
        }
        let connected: bool = tx
            .query_row(
                "SELECT 1 FROM oauth_accounts WHERE google_sub = ?1",
                [&stored.google_sub],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !connected {
            let out = burn(Rotation::Disconnected)?;
            tx.commit()?;
            return Ok(out);
        }

        if in_grace {
            let reserved = match (&stored.successor_nonce, &stored.successor_ct) {
                (Some(nonce), Some(ct)) => unseal(&key, &successor_aad(&presented_hash), nonce, ct)
                    .ok()
                    .and_then(|plain| String::from_utf8(plain).ok()),
                _ => None,
            };
            let live = match reserved {
                Some(token) => tx
                    .query_row(
                        "SELECT issued_at FROM mcp_refresh_tokens
                         WHERE token_hash = ?1 AND family_id = ?2 AND used_at IS NULL",
                        params![hash(&token), stored.family_id],
                        |r| r.get::<_, i64>(0),
                    )
                    .optional()?
                    .map(|issued_at| (token, issued_at)),
                None => None,
            };
            let out = match live {
                Some((refresh_token, issued_at)) => Rotation::Valid {
                    grant: RefreshGrant {
                        family_id: stored.family_id,
                        mcp_client_id: client_id,
                        google_sub: stored.google_sub,
                        resource: stored.resource,
                        issued_at,
                        family_issued_at: stored.family_issued_at,
                    },
                    refresh_token,
                },
                None => burn(Rotation::Replayed)?,
            };
            tx.commit()?;
            return Ok(out);
        }

        tx.execute(
            "UPDATE mcp_refresh_tokens SET used_at = ?1 WHERE token_hash = ?2",
            params![now, presented_hash],
        )?;
        if grace_secs > 0 {
            let sealed = seal(&key, &successor_aad(&presented_hash), successor.as_bytes())?;
            tx.execute(
                "UPDATE mcp_refresh_tokens SET successor_nonce = ?1, successor_ct = ?2 WHERE token_hash = ?3",
                params![sealed.nonce, sealed.ciphertext, presented_hash],
            )?;
        }
        tx.execute(
            "INSERT INTO mcp_refresh_tokens
                (token_hash, family_id, mcp_client_id, google_sub, resource, issued_at, expires_at, used_at, family_issued_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
            params![
                successor_hash,
                stored.family_id,
                client_id,
                stored.google_sub,
                stored.resource,
                now,
                now + REFRESH_TTL_SECS,
                stored.family_issued_at,
            ],
        )?;
        tx.execute(
            "DELETE FROM mcp_refresh_tokens
             WHERE family_id = ?1 AND used_at IS NOT NULL AND rowid NOT IN (
                 SELECT rowid FROM mcp_refresh_tokens
                 WHERE family_id = ?1 AND used_at IS NOT NULL
                 ORDER BY issued_at DESC, rowid DESC LIMIT ?2)",
            params![stored.family_id, MAX_USED_ROWS_PER_FAMILY],
        )?;
        tx.commit()?;
        Ok(Rotation::Valid {
            grant: RefreshGrant {
                family_id: stored.family_id,
                mcp_client_id: client_id,
                google_sub: stored.google_sub,
                resource: stored.resource,
                issued_at: now,
                family_issued_at: stored.family_issued_at,
            },
            refresh_token: successor,
        })
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

    const RES: &str = "http://localhost:8433/mcp";
    const KEY: [u8; 32] = [7u8; 32];

    fn req(family: &str, sub: &str) -> IssueRefresh {
        IssueRefresh {
            family_id: family.to_string(),
            mcp_client_id: "cid".to_string(),
            google_sub: sub.to_string(),
            resource: Some(RES.to_string()),
        }
    }

    async fn seed_account(db: &Db, sub: &str) {
        crate::storage::accounts::upsert(
            db,
            &[0u8; 32],
            crate::storage::accounts::UpsertAccount {
                google_sub: sub.to_string(),
                email: format!("{sub}@example.com"),
                refresh_token: "google-rt".to_string(),
                scopes: vec![],
            },
        )
        .await
        .unwrap();
    }

    /// A connected account with one issued token `rt-1` in family `fam`.
    async fn setup() -> Db {
        let db = Db::open_in_memory().await.unwrap();
        seed_account(&db, "sub-1").await;
        issue(&db, "rt-1", req("fam", "sub-1")).await.unwrap();
        db
    }

    async fn rot(
        db: &Db,
        presented: &str,
        client: &str,
        resource: Option<&str>,
        successor: &str,
        grace_secs: i64,
    ) -> Rotation {
        rotate(
            db,
            RotateRequest {
                presented,
                client_id: client,
                resource,
                successor,
                grace_secs,
                encryption_key: &KEY,
            },
        )
        .await
        .unwrap()
    }

    async fn exec(db: &Db, sql: &'static str) {
        db.call(move |conn| {
            conn.execute(sql, [])?;
            Ok(())
        })
        .await
        .unwrap();
    }

    async fn rows_with(db: &Db, token: &str) -> i64 {
        let h = hash(token);
        db.call(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM mcp_refresh_tokens WHERE token_hash = ?1",
                [&h],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap()
    }

    async fn total_rows(db: &Db) -> i64 {
        db.call(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM mcp_refresh_tokens", [], |r| r.get(0))?)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn rotate_valid_stores_one_successor_and_marks_old_used() {
        let db = setup().await;
        let Rotation::Valid {
            grant,
            refresh_token,
        } = rot(&db, "rt-1", "cid", Some(RES), "rt-2", 0).await
        else {
            panic!("expected Valid");
        };
        assert_eq!(refresh_token, "rt-2");
        assert_eq!(grant.google_sub, "sub-1");
        assert_eq!(grant.family_id, "fam");
        assert_eq!(grant.resource.as_deref(), Some(RES));
        assert_eq!(rows_with(&db, "rt-2").await, 1);
        assert_eq!(total_rows(&db).await, 2);
        let (fam_issued, succ_fam_issued): (i64, i64) = db
            .call(|conn| {
                let a = conn.query_row(
                    "SELECT family_issued_at FROM mcp_refresh_tokens WHERE token_hash = ?1",
                    [hash("rt-1")],
                    |r| r.get(0),
                )?;
                let b = conn.query_row(
                    "SELECT family_issued_at FROM mcp_refresh_tokens WHERE token_hash = ?1",
                    [hash("rt-2")],
                    |r| r.get(0),
                )?;
                Ok((a, b))
            })
            .await
            .unwrap();
        assert_eq!(fam_issued, succ_fam_issued);
        assert_eq!(grant.family_issued_at, fam_issued);
        // Successor works, resource omitted keeps the stored one.
        assert!(matches!(
            rot(&db, "rt-2", "cid", None, "rt-3", 0).await,
            Rotation::Valid { .. }
        ));
    }

    #[tokio::test]
    async fn used_token_outside_grace_burns_the_family() {
        let db = setup().await;
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-2", 0).await,
            Rotation::Valid { .. }
        ));
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-3", 0).await,
            Rotation::Replayed
        ));
        assert_eq!(total_rows(&db).await, 0);
        assert!(matches!(
            rot(&db, "rt-2", "cid", None, "rt-4", 0).await,
            Rotation::Invalid
        ));
    }

    #[tokio::test]
    async fn reuse_after_the_grace_window_is_a_replay() {
        let db = setup().await;
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-2", 10).await,
            Rotation::Valid { .. }
        ));
        exec(
            &db,
            "UPDATE mcp_refresh_tokens SET used_at = used_at - 11 WHERE used_at IS NOT NULL",
        )
        .await;
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-3", 10).await,
            Rotation::Replayed
        ));
        assert_eq!(total_rows(&db).await, 0);
    }

    async fn served(db: &Db, presented: &str, successor: &str) -> String {
        match rot(db, presented, "cid", None, successor, 10).await {
            Rotation::Valid { refresh_token, .. } => refresh_token,
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    async fn unused_rows(db: &Db) -> i64 {
        db.call(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM mcp_refresh_tokens WHERE used_at IS NULL",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn in_grace_reuse_returns_the_same_successor() {
        let db = setup().await;
        assert_eq!(served(&db, "rt-1", "rt-2").await, "rt-2");
        for attempt in ["rt-x", "rt-y", "rt-z"] {
            assert_eq!(served(&db, "rt-1", attempt).await, "rt-2");
            assert_eq!(rows_with(&db, attempt).await, 0);
        }
        assert_eq!(unused_rows(&db).await, 1);
        assert_eq!(total_rows(&db).await, 2);
        assert_eq!(served(&db, "rt-2", "rt-3").await, "rt-3");
    }

    #[tokio::test]
    async fn in_grace_reuse_after_successor_used_burns() {
        let db = setup().await;
        served(&db, "rt-1", "rt-2").await;
        served(&db, "rt-2", "rt-3").await;
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-4", 10).await,
            Rotation::Replayed
        ));
        assert_eq!(total_rows(&db).await, 0);
    }

    #[tokio::test]
    async fn in_grace_reuse_with_tampered_ciphertext_burns() {
        let db = setup().await;
        served(&db, "rt-1", "rt-2").await;
        served(&db, "rt-2", "rt-3").await;
        // rt-2's sealed successor is bound to rt-2's hash, so it cannot be moved onto rt-1.
        db.call(|conn| {
            conn.execute(
                "UPDATE mcp_refresh_tokens
                 SET successor_nonce = (SELECT successor_nonce FROM mcp_refresh_tokens WHERE token_hash = ?1),
                     successor_ct = (SELECT successor_ct FROM mcp_refresh_tokens WHERE token_hash = ?1)
                 WHERE token_hash = ?2",
                params![hash("rt-2"), hash("rt-1")],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-9", 10).await,
            Rotation::Replayed
        ));
        assert_eq!(total_rows(&db).await, 0);
    }

    #[tokio::test]
    async fn in_grace_reuse_with_flipped_ciphertext_or_missing_ciphertext_burns() {
        for sql in [
            "UPDATE mcp_refresh_tokens SET successor_ct = substr(successor_ct, 2) WHERE successor_ct IS NOT NULL",
            "UPDATE mcp_refresh_tokens SET successor_ct = NULL, successor_nonce = NULL",
        ] {
            let db = setup().await;
            served(&db, "rt-1", "rt-2").await;
            exec(&db, sql).await;
            assert!(matches!(
                rot(&db, "rt-1", "cid", None, "rt-9", 10).await,
                Rotation::Replayed
            ));
            assert_eq!(total_rows(&db).await, 0);
        }
    }

    #[tokio::test]
    async fn in_grace_reuse_with_another_key_burns() {
        let db = setup().await;
        served(&db, "rt-1", "rt-2").await;
        let out = rotate(
            &db,
            RotateRequest {
                presented: "rt-1",
                client_id: "cid",
                resource: None,
                successor: "rt-9",
                grace_secs: 10,
                encryption_key: &[9u8; 32],
            },
        )
        .await
        .unwrap();
        assert!(matches!(out, Rotation::Replayed));
        assert_eq!(total_rows(&db).await, 0);
    }

    #[tokio::test]
    async fn in_grace_reuse_by_another_client_burns() {
        let db = setup().await;
        served(&db, "rt-1", "rt-2").await;
        assert!(matches!(
            rot(&db, "rt-1", "other", None, "rt-9", 10).await,
            Rotation::WrongClient
        ));
        assert_eq!(total_rows(&db).await, 0);
    }

    #[tokio::test]
    async fn in_grace_reuse_after_revocation_burns() {
        let db = setup().await;
        served(&db, "rt-1", "rt-2").await;
        crate::storage::revocations::revoke(&db, "sub-1", now_secs())
            .await
            .unwrap();
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-9", 10).await,
            Rotation::Revoked
        ));
        assert_eq!(total_rows(&db).await, 0);
    }

    #[tokio::test]
    async fn grace_zero_stores_no_ciphertext() {
        let db = setup().await;
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-2", 0).await,
            Rotation::Valid { .. }
        ));
        let sealed: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM mcp_refresh_tokens WHERE successor_ct IS NOT NULL OR successor_nonce IS NOT NULL",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(sealed, 0);
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-3", 0).await,
            Rotation::Replayed
        ));
        assert_eq!(total_rows(&db).await, 0);
    }

    #[tokio::test]
    async fn sweep_wipes_successor_ciphertext_after_window() {
        let db = setup().await;
        served(&db, "rt-1", "rt-2").await;
        let sealed = |db: Db| async move {
            db.call(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM mcp_refresh_tokens WHERE successor_ct IS NOT NULL",
                    [],
                    |r| r.get::<_, i64>(0),
                )?)
            })
            .await
            .unwrap()
        };
        sweep(&db).await.unwrap();
        assert_eq!(sealed(db.clone()).await, 1, "still inside the window");
        exec(
            &db,
            "UPDATE mcp_refresh_tokens SET used_at = used_at - 61 WHERE used_at IS NOT NULL",
        )
        .await;
        sweep(&db).await.unwrap();
        assert_eq!(sealed(db.clone()).await, 0);
        assert_eq!(
            total_rows(&db).await,
            2,
            "rows stay, only the ciphertext goes"
        );
    }

    #[tokio::test]
    async fn rotate_wipes_stale_ciphertext_of_other_rows() {
        let db = setup().await;
        served(&db, "rt-1", "rt-2").await;
        exec(
            &db,
            "UPDATE mcp_refresh_tokens SET used_at = used_at - 61 WHERE used_at IS NOT NULL",
        )
        .await;
        served(&db, "rt-2", "rt-3").await;
        let wiped: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM mcp_refresh_tokens WHERE token_hash = ?1 AND successor_ct IS NULL",
                    [hash("rt-1")],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(wiped, 1);
    }

    #[tokio::test]
    async fn used_rows_per_family_are_capped() {
        let db = setup().await;
        db.call(|conn| {
            let tx = conn.transaction()?;
            for i in 0..1005i64 {
                tx.execute(
                    "INSERT INTO mcp_refresh_tokens
                        (token_hash, family_id, mcp_client_id, google_sub, resource, issued_at, expires_at, used_at, family_issued_at)
                     VALUES (?1, 'fam', 'cid', 'sub-1', NULL, ?2, 9999999999, 5000, CAST(strftime('%s','now') AS INTEGER))",
                    params![format!("seed-{i}"), 1_000_000 + i],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap();
        served(&db, "rt-1", "rt-2").await;
        let used: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM mcp_refresh_tokens WHERE family_id = 'fam' AND used_at IS NOT NULL",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(used, MAX_USED_ROWS_PER_FAMILY);
        // rt-1 (just used, newest issue time) and the newest seeds survive; the oldest seeds go.
        assert_eq!(rows_with(&db, "rt-1").await, 1);
        assert_eq!(rows_with(&db, "rt-2").await, 1);
        let raw = |name: &'static str| {
            let db = db.clone();
            async move {
                db.call(move |conn| {
                    Ok(conn.query_row(
                        "SELECT COUNT(*) FROM mcp_refresh_tokens WHERE token_hash = ?1",
                        [name],
                        |r| r.get::<_, i64>(0),
                    )?)
                })
                .await
                .unwrap()
            }
        };
        assert_eq!(raw("seed-1004").await, 1);
        assert_eq!(raw("seed-6").await, 1);
        for old in ["seed-0", "seed-1", "seed-5"] {
            assert_eq!(raw(old).await, 0, "{old}");
        }
    }

    #[tokio::test]
    async fn in_grace_reuse_keeps_the_original_used_at() {
        let db = setup().await;
        rot(&db, "rt-1", "cid", None, "rt-2", 10).await;
        exec(
            &db,
            "UPDATE mcp_refresh_tokens SET used_at = used_at - 5 WHERE used_at IS NOT NULL",
        )
        .await;
        let before: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT used_at FROM mcp_refresh_tokens WHERE token_hash = ?1",
                    [hash("rt-1")],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        rot(&db, "rt-1", "cid", None, "rt-3", 10).await;
        let after: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT used_at FROM mcp_refresh_tokens WHERE token_hash = ?1",
                    [hash("rt-1")],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn unknown_and_expired_tokens_are_invalid() {
        let db = setup().await;
        assert!(matches!(
            rot(&db, "nope", "cid", None, "rt-2", 10).await,
            Rotation::Invalid
        ));
        exec(&db, "UPDATE mcp_refresh_tokens SET expires_at = 1").await;
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-2", 10).await,
            Rotation::Invalid
        ));
        assert_eq!(rows_with(&db, "rt-2").await, 0);
    }

    #[tokio::test]
    async fn family_older_than_the_absolute_cap_is_invalid() {
        let db = setup().await;
        exec(
            &db,
            "UPDATE mcp_refresh_tokens SET family_issued_at = family_issued_at - 91 * 24 * 3600",
        )
        .await;
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-2", 10).await,
            Rotation::Invalid
        ));
        assert_eq!(total_rows(&db).await, 0);
    }

    #[tokio::test]
    async fn wrong_client_burns_the_family() {
        let db = setup().await;
        assert!(matches!(
            rot(&db, "rt-1", "other", None, "rt-2", 10).await,
            Rotation::WrongClient
        ));
        assert_eq!(total_rows(&db).await, 0);
    }

    #[tokio::test]
    async fn wrong_resource_changes_nothing() {
        let db = setup().await;
        assert!(matches!(
            rot(
                &db,
                "rt-1",
                "cid",
                Some("http://localhost:8433/"),
                "rt-2",
                10
            )
            .await,
            Rotation::WrongResource
        ));
        assert_eq!(total_rows(&db).await, 1);
        let (used, sealed): (Option<i64>, Option<Vec<u8>>) = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT used_at, successor_ct FROM mcp_refresh_tokens",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!((used, sealed), (None, None));
        assert!(matches!(
            rot(&db, "rt-1", "cid", Some(RES), "rt-2", 10).await,
            Rotation::Valid { .. }
        ));
    }

    #[tokio::test]
    async fn wrong_resource_in_grace_writes_nothing() {
        let db = setup().await;
        rot(&db, "rt-1", "cid", None, "rt-2", 10).await;
        assert!(matches!(
            rot(
                &db,
                "rt-1",
                "cid",
                Some("http://localhost:8433/"),
                "rt-3",
                10
            )
            .await,
            Rotation::WrongResource
        ));
        assert_eq!(total_rows(&db).await, 2, "nothing written");
        assert_eq!(served(&db, "rt-1", "rt-3").await, "rt-2");
    }

    #[tokio::test]
    async fn stored_none_resource_differs_from_a_requested_one() {
        let db = Db::open_in_memory().await.unwrap();
        seed_account(&db, "sub-1").await;
        issue(
            &db,
            "rt-1",
            IssueRefresh {
                resource: None,
                ..req("fam", "sub-1")
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            rot(&db, "rt-1", "cid", Some(RES), "rt-2", 10).await,
            Rotation::WrongResource
        ));
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-2", 10).await,
            Rotation::Valid { .. }
        ));
    }

    #[tokio::test]
    async fn revoked_sub_burns_the_family_on_family_issued_at() {
        let db = setup().await;
        let fam_issued: i64 = db
            .call(|conn| {
                Ok(
                    conn.query_row("SELECT family_issued_at FROM mcp_refresh_tokens", [], |r| {
                        r.get(0)
                    })?,
                )
            })
            .await
            .unwrap();
        // A tombstone older than the family does not touch it.
        crate::storage::revocations::revoke(&db, "sub-1", fam_issued - 1)
            .await
            .unwrap();
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-2", 10).await,
            Rotation::Valid { .. }
        ));
        // Equal to family_issued_at revokes, even through a later token of the family.
        crate::storage::revocations::revoke(&db, "sub-1", fam_issued)
            .await
            .unwrap();
        assert!(matches!(
            rot(&db, "rt-2", "cid", None, "rt-3", 10).await,
            Rotation::Revoked
        ));
        assert_eq!(total_rows(&db).await, 0);
    }

    #[tokio::test]
    async fn disconnected_account_burns_the_family() {
        let db = setup().await;
        crate::storage::accounts::delete(&db, "sub-1")
            .await
            .unwrap();
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-2", 10).await,
            Rotation::Disconnected
        ));
        assert_eq!(total_rows(&db).await, 0);
    }

    #[tokio::test]
    async fn rotate_is_atomic() {
        // Every non-Valid outcome leaves no successor row.
        type Mutate = Option<&'static str>;
        let cases: Vec<(Mutate, &str, Option<&str>, i64)> = vec![
            (
                Some("UPDATE mcp_refresh_tokens SET expires_at = 1"),
                "cid",
                None,
                10,
            ),
            (None, "other", None, 10),
            (None, "cid", Some("http://localhost:8433/"), 10),
            (
                Some("UPDATE mcp_refresh_tokens SET used_at = 1"),
                "cid",
                None,
                10,
            ),
            (
                Some("UPDATE mcp_refresh_tokens SET used_at = 1"),
                "cid",
                None,
                0,
            ),
            (Some("DELETE FROM oauth_accounts"), "cid", None, 10),
            (
                Some(
                    "INSERT INTO revoked_subs (google_sub, not_before) VALUES ('sub-1', 9999999999)",
                ),
                "cid",
                None,
                10,
            ),
        ];
        for (i, (mutate, client, resource, grace)) in cases.into_iter().enumerate() {
            let db = setup().await;
            if let Some(sql) = mutate {
                exec(&db, sql).await;
            }
            let out = rot(&db, "rt-1", client, resource, "rt-succ", grace).await;
            assert!(!matches!(out, Rotation::Valid { .. }), "case {i}: {out:?}");
            assert_eq!(rows_with(&db, "rt-succ").await, 0, "case {i}: {out:?}");
        }
        // Valid leaves exactly one.
        let db = setup().await;
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-succ", 10).await,
            Rotation::Valid { .. }
        ));
        assert_eq!(rows_with(&db, "rt-succ").await, 1);
    }

    #[tokio::test]
    async fn sql_error_mid_rotation_consumes_nothing() {
        let db = setup().await;
        issue(&db, "rt-other", req("fam2", "sub-1")).await.unwrap();
        // The successor collides with an existing hash: the insert fails after the used_at update.
        let err = rotate(
            &db,
            RotateRequest {
                presented: "rt-1",
                client_id: "cid",
                resource: None,
                successor: "rt-other",
                grace_secs: 10,
                encryption_key: &KEY,
            },
        )
        .await;
        assert!(err.is_err());
        let used: Option<i64> = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT used_at FROM mcp_refresh_tokens WHERE token_hash = ?1",
                    [hash("rt-1")],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(used, None, "rolled back, token still usable");
        assert!(matches!(
            rot(&db, "rt-1", "cid", None, "rt-2", 10).await,
            Rotation::Valid { .. }
        ));
    }

    #[tokio::test]
    async fn only_hashes_are_stored() {
        let db = setup().await;
        rot(&db, "rt-1", "cid", None, "plain-successor", 10).await;
        issue(&db, "secret-token", req("fam3", "sub-1"))
            .await
            .unwrap();
        let rows: Vec<Vec<String>> = db
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT token_hash, family_id, mcp_client_id, google_sub, COALESCE(resource,'') FROM mcp_refresh_tokens",
                )?;
                let rows = stmt
                    .query_map([], |r| {
                        (0..5).map(|i| r.get::<_, String>(i)).collect::<Result<Vec<_>, _>>()
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);
        let blobs: Vec<Vec<u8>> = db
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT successor_ct FROM mcp_refresh_tokens WHERE successor_ct IS NOT NULL",
                )?;
                let blobs = stmt
                    .query_map([], |r| r.get::<_, Vec<u8>>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(blobs)
            })
            .await
            .unwrap();
        assert_eq!(blobs.len(), 1, "the grace successor is sealed");
        let needle = b"plain-successor";
        assert!(!blobs[0].windows(needle.len()).any(|w| w == needle));
        for row in &rows {
            assert_eq!(row[0].len(), 64);
            for cell in row {
                for token in ["rt-1", "plain-successor", "secret-token"] {
                    assert_ne!(cell, token);
                }
            }
        }
    }

    #[tokio::test]
    async fn sweep_removes_expired_and_over_age_rows() {
        let db = Db::open_in_memory().await.unwrap();
        for (tok, fam) in [("fresh", "f1"), ("idle", "f2"), ("old", "f3")] {
            issue(&db, tok, req(fam, "sub-1")).await.unwrap();
        }
        db.call(|conn| {
            conn.execute(
                "UPDATE mcp_refresh_tokens SET expires_at = 1 WHERE family_id = 'f2'",
                [],
            )?;
            conn.execute(
                "UPDATE mcp_refresh_tokens SET family_issued_at = 1 WHERE family_id = 'f3'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(sweep(&db).await.unwrap(), 2);
        assert_eq!(rows_with(&db, "fresh").await, 1);
        assert_eq!(total_rows(&db).await, 1);
    }

    #[tokio::test]
    async fn rotate_sweeps_expired_rows_of_other_families() {
        let db = setup().await;
        issue(&db, "stale", req("f2", "sub-1")).await.unwrap();
        exec(
            &db,
            "UPDATE mcp_refresh_tokens SET expires_at = 1 WHERE family_id = 'f2'",
        )
        .await;
        rot(&db, "rt-1", "cid", None, "rt-2", 10).await;
        assert_eq!(rows_with(&db, "stale").await, 0);
    }

    #[tokio::test]
    async fn delete_for_sub_spares_other_accounts() {
        let db = Db::open_in_memory().await.unwrap();
        seed_account(&db, "sub-1").await;
        seed_account(&db, "sub-2").await;
        issue(&db, "a", req("f1", "sub-1")).await.unwrap();
        issue(&db, "b", req("f2", "sub-2")).await.unwrap();
        assert_eq!(delete_for_sub(&db, "sub-1").await.unwrap(), 1);
        assert!(matches!(
            rot(&db, "a", "cid", None, "a2", 10).await,
            Rotation::Invalid
        ));
        assert!(matches!(
            rot(&db, "b", "cid", None, "b2", 10).await,
            Rotation::Valid { .. }
        ));
    }
}
