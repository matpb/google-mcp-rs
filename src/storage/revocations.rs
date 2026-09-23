//! `revoked_subs` tombstones. No foreign key to `oauth_accounts`: a
//! tombstone must outlive the row it revokes so an already-issued JWT is
//! still rejected after the account is deleted.

use rusqlite::params;

use super::{Db, DbError};

pub async fn revoke(db: &Db, google_sub: &str, not_before: i64) -> Result<(), DbError> {
    let google_sub = google_sub.to_string();
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO revoked_subs (google_sub, not_before) VALUES (?1, ?2)
             ON CONFLICT(google_sub) DO UPDATE SET not_before = excluded.not_before",
            params![google_sub, not_before],
        )?;
        Ok(())
    })
    .await
}

pub async fn not_before(db: &Db, google_sub: &str) -> Result<Option<i64>, DbError> {
    let google_sub = google_sub.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare("SELECT not_before FROM revoked_subs WHERE google_sub = ?1")?;
        match stmt.query_row([&google_sub], |r| r.get::<_, i64>(0)) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn revoke_then_not_before() {
        let db = Db::open_in_memory().await.unwrap();
        assert!(not_before(&db, "sub-1").await.unwrap().is_none());
        revoke(&db, "sub-1", 100).await.unwrap();
        assert_eq!(not_before(&db, "sub-1").await.unwrap(), Some(100));
    }

    #[tokio::test]
    async fn revoke_survives_account_deletion() {
        let db = Db::open_in_memory().await.unwrap();
        crate::storage::accounts::upsert(
            &db,
            &[0u8; 32],
            crate::storage::accounts::UpsertAccount {
                google_sub: "sub-1".to_string(),
                email: "x@x.com".to_string(),
                refresh_token: "t".to_string(),
                scopes: vec![],
            },
        )
        .await
        .unwrap();
        revoke(&db, "sub-1", 200).await.unwrap();
        crate::storage::accounts::delete(&db, "sub-1")
            .await
            .unwrap();
        assert_eq!(not_before(&db, "sub-1").await.unwrap(), Some(200));
    }

    #[tokio::test]
    async fn revoke_upserts_latest_not_before() {
        let db = Db::open_in_memory().await.unwrap();
        revoke(&db, "sub-1", 100).await.unwrap();
        revoke(&db, "sub-1", 300).await.unwrap();
        assert_eq!(not_before(&db, "sub-1").await.unwrap(), Some(300));
    }
}
