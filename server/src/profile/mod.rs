use std::time::Duration;
use trustify_common::db::Database;
use trustify_infrastructure::health::{Check, checks::Local};

pub mod api;
pub mod importer;

/// A common database check
pub fn spawn_db_check(db: Database) -> anyhow::Result<impl Check> {
    Local::spawn_periodic("no database connection", Duration::from_secs(1), {
        let db = db.clone();
        move || {
            let db = db.clone();
            async move {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    async move { db.ping().await.is_ok() },
                )
                .await
                .is_ok()
            }
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::profile::spawn_db_check;
    use test_log::test;

    #[test(tokio::test)]
    async fn timeout() {
        let (db, postgresql) = trustify_db::embedded::create().await.expect("must create");

        let check = spawn_db_check(db).expect("must create");

        // must turn to "ok" within 5 seconds

        tokio::time::timeout(Duration::from_secs(5), async {
            while check.run().await.is_err() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
        .await
        .expect("must turn to ok");

        // shut down database instance

        drop(postgresql);

        // must turn to "error" within 15 seconds

        tokio::time::timeout(Duration::from_secs(15), async {
            while check.run().await.is_ok() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
        .await
        .expect("must turn to error");
    }
}
