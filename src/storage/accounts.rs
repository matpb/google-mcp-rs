//! `oauth_accounts` CRUD. Refresh tokens are encrypted with AES-256-GCM
//! using AAD = `google_sub`; this module is the only place that touches
//! ciphertexts.

use rusqlite::params;

use super::{Db, DbError, crypto, now_secs};

#[derive(Debug, Clone)]
pub struct Account {
    pub google_sub: String,
    pub email: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_refresh_at: Option<i64>,
}

pub struct UpsertAccount {
    pub google_sub: String,
    pub email: String,
    pub refresh_token: String,
    pub scopes: Vec<String>,
}

pub async fn upsert(
    db: &Db,
    encryption_key: &[u8; 32],
    req: UpsertAccount,
) -> Result<(), DbError> {
    let sealed = crypto::seal(
        encryption_key,
        req.google_sub.as_bytes(),
        req.refresh_token.as_bytes(),
    )?;
    let now = now_secs();
    let scopes = req.scopes.join(" ");
    let google_sub = req.google_sub;
    let email = req.email;

    db.call(move |conn| {
        conn.execute(
            "INSERT INTO oauth_accounts
                (google_sub, email, refresh_token_ct, refresh_token_nonce, scopes, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(google_sub) DO UPDATE SET
                email = excluded.email,
                refresh_token_ct = excluded.refresh_token_ct,
                refresh_token_nonce = excluded.refresh_token_nonce,
                scopes = excluded.scopes,
                updated_at = excluded.updated_at",
            params![
                google_sub,
                email,
                sealed.ciphertext,
                sealed.nonce,
                scopes,
                now,
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn get(db: &Db, google_sub: &str) -> Result<Option<Account>, DbError> {
    let google_sub = google_sub.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT google_sub, email, scopes, created_at, updated_at, last_refresh_at
             FROM oauth_accounts WHERE google_sub = ?1",
        )?;
        let row = stmt.query_row([&google_sub], |r| {
            let scopes: String = r.get(2)?;
            Ok(Account {
                google_sub: r.get(0)?,
                email: r.get(1)?,
                scopes: scopes.split_whitespace().map(str::to_string).collect(),
                created_at: r.get(3)?,
                updated_at: r.get(4)?,
                last_refresh_at: r.get(5)?,
            })
        });
        match row {
            Ok(a) => Ok(Some(a)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    })
    .await
}

/// Decrypt and return the stored refresh token, or `None` if the account does not exist.
pub async fn get_refresh_token(
    db: &Db,
    encryption_key: &[u8; 32],
    google_sub: &str,
) -> Result<Option<String>, DbError> {
    let sub_owned = google_sub.to_string();
    let row = db
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT refresh_token_ct, refresh_token_nonce
                 FROM oauth_accounts WHERE google_sub = ?1",
            )?;
            let r = stmt.query_row([&sub_owned], |r| {
                let ct: Vec<u8> = r.get(0)?;
                let nonce: Vec<u8> = r.get(1)?;
                Ok((ct, nonce))
            });
            match r {
                Ok(t) => Ok(Some(t)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
        .await?;

    let Some((ct, nonce)) = row else {
        return Ok(None);
    };
    let plaintext = crypto::unseal(encryption_key, google_sub.as_bytes(), &nonce, &ct)?;
    let token = String::from_utf8(plaintext)
        .map_err(|_| DbError::Crypto(crypto::CryptoError::Decrypt))?;
    Ok(Some(token))
}

pub async fn touch_last_refresh(db: &Db, google_sub: &str) -> Result<(), DbError> {
    let google_sub = google_sub.to_string();
    let now = now_secs();
    db.call(move |conn| {
        conn.execute(
            "UPDATE oauth_accounts SET last_refresh_at = ?1, updated_at = ?1 WHERE google_sub = ?2",
            params![now, google_sub],
        )?;
        Ok(())
    })
    .await
}

pub async fn delete(db: &Db, google_sub: &str) -> Result<(), DbError> {
    let google_sub = google_sub.to_string();
    db.call(move |conn| {
        conn.execute(
            "DELETE FROM oauth_accounts WHERE google_sub = ?1",
            params![google_sub],
        )?;
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        k
    }

    #[tokio::test]
    async fn upsert_then_get() {
        let db = Db::open_in_memory().await.unwrap();
        upsert(
            &db,
            &key(),
            UpsertAccount {
                google_sub: "sub-1".to_string(),
                email: "a@b.com".to_string(),
                refresh_token: "1//refresh-token-abc".to_string(),
                scopes: vec!["openid".to_string(), "email".to_string()],
            },
        )
        .await
        .unwrap();

        let got = get(&db, "sub-1").await.unwrap().expect("present");
        assert_eq!(got.google_sub, "sub-1");
        assert_eq!(got.email, "a@b.com");
        assert_eq!(got.scopes, vec!["openid", "email"]);
        assert!(got.last_refresh_at.is_none());

        let token = get_refresh_token(&db, &key(), "sub-1")
            .await
            .unwrap()
            .expect("present");
        assert_eq!(token, "1//refresh-token-abc");
    }

    #[tokio::test]
    async fn upsert_overwrites() {
        let db = Db::open_in_memory().await.unwrap();
        upsert(
            &db,
            &key(),
            UpsertAccount {
                google_sub: "sub-1".to_string(),
                email: "old@x.com".to_string(),
                refresh_token: "old".to_string(),
                scopes: vec![],
            },
        )
        .await
        .unwrap();
        upsert(
            &db,
            &key(),
            UpsertAccount {
                google_sub: "sub-1".to_string(),
                email: "new@x.com".to_string(),
                refresh_token: "new".to_string(),
                scopes: vec!["a".to_string()],
            },
        )
        .await
        .unwrap();
        let acc = get(&db, "sub-1").await.unwrap().unwrap();
        assert_eq!(acc.email, "new@x.com");
        assert_eq!(acc.scopes, vec!["a"]);
        let tok = get_refresh_token(&db, &key(), "sub-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tok, "new");
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let db = Db::open_in_memory().await.unwrap();
        assert!(get(&db, "missing").await.unwrap().is_none());
        assert!(
            get_refresh_token(&db, &key(), "missing")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn refresh_token_decryption_aad_bound_to_sub() {
        let db = Db::open_in_memory().await.unwrap();
        // Insert two accounts.
        for sub in ["sub-A", "sub-B"] {
            upsert(
                &db,
                &key(),
                UpsertAccount {
                    google_sub: sub.to_string(),
                    email: format!("{sub}@x.com"),
                    refresh_token: format!("token-for-{sub}"),
                    scopes: vec![],
                },
            )
            .await
            .unwrap();
        }
        // Manually swap ciphertexts in the DB to simulate an attacker.
        db.call(|conn| {
            let (ct_a, nc_a): (Vec<u8>, Vec<u8>) = conn.query_row(
                "SELECT refresh_token_ct, refresh_token_nonce FROM oauth_accounts WHERE google_sub='sub-A'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            conn.execute(
                "UPDATE oauth_accounts SET refresh_token_ct=?1, refresh_token_nonce=?2 WHERE google_sub='sub-B'",
                params![ct_a, nc_a],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        // sub-B's row now has sub-A's ciphertext. Decryption must fail because AAD doesn't match.
        let err = get_refresh_token(&db, &key(), "sub-B").await.unwrap_err();
        assert!(matches!(err, DbError::Crypto(_)));
    }

    #[tokio::test]
    async fn touch_last_refresh_updates_timestamp() {
        let db = Db::open_in_memory().await.unwrap();
        upsert(
            &db,
            &key(),
            UpsertAccount {
                google_sub: "sub-1".to_string(),
                email: "x@x.com".to_string(),
                refresh_token: "t".to_string(),
                scopes: vec![],
            },
        )
        .await
        .unwrap();
        assert!(get(&db, "sub-1").await.unwrap().unwrap().last_refresh_at.is_none());
        touch_last_refresh(&db, "sub-1").await.unwrap();
        assert!(get(&db, "sub-1").await.unwrap().unwrap().last_refresh_at.is_some());
    }

    #[tokio::test]
    async fn delete_removes_account() {
        let db = Db::open_in_memory().await.unwrap();
        upsert(
            &db,
            &key(),
            UpsertAccount {
                google_sub: "sub-1".to_string(),
                email: "x@x.com".to_string(),
                refresh_token: "t".to_string(),
                scopes: vec![],
            },
        )
        .await
        .unwrap();
        delete(&db, "sub-1").await.unwrap();
        assert!(get(&db, "sub-1").await.unwrap().is_none());
    }
}
