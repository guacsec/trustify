use std::future::Future;

use super::Error;
use crate::model::Importer;
use sea_orm::{QueryFilter, entity::*, prelude::*};
use time::OffsetDateTime;
use tokio::{
    task::{JoinHandle, spawn_local},
    time::{Duration, interval},
};
use tokio_util::sync::CancellationToken;
use trustify_common::db::ReadWrite;
use trustify_entity::importer;

pub struct Heart {
    handle: JoinHandle<()>,
    token: CancellationToken,
}

impl Heart {
    pub const RATE: Duration = Duration::from_secs(10);

    pub fn new<F>(importer: Importer, db: ReadWrite, future: F, token: CancellationToken) -> Self
    where
        F: Future + 'static,
    {
        let handle = spawn_local(Heart::pump(importer, db, future, token.clone()));
        Self { handle, token }
    }

    pub fn is_beating(&self) -> bool {
        !self.handle.is_finished()
    }

    // Attempts to acquire exclusive optimistic lock. Upon success,
    // spawns the future, and regularly updates the lock until the
    // future completes.
    async fn pump<F>(importer: Importer, db: ReadWrite, future: F, token: CancellationToken)
    where
        F: Future + 'static,
    {
        let name = importer.name.clone();
        if let Ok(importer) = Heart::beat(&importer, &db).await {
            log::debug!("Acquired lock; running '{name}'");
            let work = spawn_local(future);
            let mut interval = interval(Heart::RATE);
            let mut importer = importer;
            loop {
                interval.tick().await;
                match Self::beat(&importer, &db).await {
                    Ok(i) => {
                        log::debug!("{name}: {:#?}", i.data.progress);
                        importer = i;
                    }
                    Err(e) => {
                        log::error!("Aborting '{name}': {e}");
                        token.cancel();
                    }
                }
                if work.is_finished() {
                    log::debug!("Releasing lock; finished '{name}'");
                    break;
                } else if token.is_cancelled() {
                    log::warn!("Importer '{name}' not responding to cancel");
                }
            }
        } else {
            log::debug!("Unable to acquire lock to run '{name}'");
        }
    }

    // Employs an optimistic locking strategy to update the importer
    // record with the current time, but only if the db matches the
    // state of the &Importer parameter, otherwise an error is
    // returned. Upon success, the updated Importer is returned.
    async fn beat(importer: &Importer, db: &ReadWrite) -> Result<Importer, Error> {
        let t = OffsetDateTime::now_utc().unix_timestamp_nanos();
        let model = importer::ActiveModel {
            name: Set(importer.name.to_owned()),
            heartbeat: Set(Some(t.into())),
            ..Default::default()
        };
        use importer::Column::Heartbeat;
        let lock = match importer.heartbeat {
            Some(t) => Expr::col(Heartbeat).eq(Decimal::from_i128_with_scale(t, 0)),
            None => Expr::col(Heartbeat).is_null(),
        };
        // We rely on the fact that `update` will return an error if
        // no row is affected, as opposed to how `update_many` works
        match importer::Entity::update(model).filter(lock).exec(db).await {
            Ok(model) => Importer::try_from(model).map_err(Error::Json),
            Err(e) => Err(Error::Heartbeat(e)),
        }
    }
}

impl Drop for Heart {
    fn drop(&mut self) {
        self.token.cancel();
        self.handle.abort();
    }
}
