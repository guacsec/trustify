//! How the framework runs data migrations.

use futures_util::FutureExt;
use migration::{
    DeriveMigrationName, MigratorExt, async_trait,
    data::{
        Database, Direction, MigrationTraitWithData, Migrations, Options, Runner,
        SchemaDataManager,
        advisory::{Advisory, Id},
    },
};
use sea_orm::DbErr;
use std::{
    hint::spin_loop,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use test_context::test_context;
use trustify_test_context::TrustifyContext;

static RUNNING: AtomicUsize = AtomicUsize::new(0);
static OVERLAPPED: AtomicBool = AtomicBool::new(false);

/// Blocks the thread of a document until another document runs as well, which only happens on
/// another thread.
#[derive(DeriveMigrationName)]
struct Blocking;

#[async_trait::async_trait]
impl MigrationTraitWithData for Blocking {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        manager
            .process(self, |_: Advisory, _: Id, _| {
                async move {
                    RUNNING.fetch_add(1, Ordering::SeqCst);
                    let start = Instant::now();
                    while start.elapsed() < Duration::from_secs(10) {
                        if RUNNING.load(Ordering::SeqCst) >= 2 {
                            OVERLAPPED.store(true, Ordering::SeqCst);
                            break;
                        }
                        spin_loop();
                    }
                    // the other document isn't released when this one is over before it started
                    if !OVERLAPPED.load(Ordering::SeqCst) {
                        RUNNING.fetch_sub(1, Ordering::SeqCst);
                    }
                    Ok(())
                }
                .boxed()
            })
            .await
    }

    async fn down(&self, _: &SchemaDataManager) -> Result<(), DbErr> {
        Ok(())
    }
}

struct BlockingMigrator;

impl MigratorExt for BlockingMigrator {
    fn build_migrations() -> Migrations {
        Migrations::new().data(Blocking)
    }
}

/// CPU intensive work of one document doesn't hold up the others.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn documents_run_on_different_threads(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("osv/DSA-5790-1.json").await?;
    ctx.ingest_document("osv/GHSA-qq9f-q439-2574.json").await?;

    Runner {
        database: Database::Provided(ctx.db.clone().into_connection()),
        storage: ctx.storage.clone().into(),
        direction: Direction::Up,
        migrations: vec!["parallel".into()],
        options: Options {
            concurrent: 2,
            ..Default::default()
        },
    }
    .run::<BlockingMigrator>()
    .await?;

    assert!(OVERLAPPED.load(Ordering::SeqCst));
    Ok(())
}
