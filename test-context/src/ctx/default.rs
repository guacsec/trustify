use crate::{
    TrustifyTestContext,
    resource::{ResourceStack, TestResourceExt, defer},
};
use std::{env, ops::Deref};
use test_context::AsyncTestContext;
use tracing::instrument;
use trustify_common::{config, db};
use trustify_module_storage::service::fs::FileSystemBackend;

pub struct TrustifyContext(pub TrustifyTestContext);

impl TrustifyContext {
    pub async fn new(
        db: db::Database,
        port: u16,
        storage: FileSystemBackend,
        resources: impl Into<ResourceStack>,
    ) -> Self {
        Self(TrustifyTestContext::new(db, port, storage, resources))
    }
}

impl From<TrustifyTestContext> for TrustifyContext {
    fn from(value: TrustifyTestContext) -> Self {
        Self(value)
    }
}

impl Deref for TrustifyContext {
    type Target = TrustifyTestContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsyncTestContext for TrustifyContext {
    #[instrument]
    #[allow(clippy::expect_used)]
    async fn setup() -> Self {
        let (storage, tmp) = FileSystemBackend::for_test()
            .await
            .expect("initializing the storage backend");

        if env::var("EXTERNAL_TEST_DB").is_ok() {
            log::warn!("Using external database from 'DB_*' env vars");
            let config = config::Database::from_env().expect("DB config from env");

            let db = if matches!(
                env::var("EXTERNAL_TEST_DB_BOOTSTRAP").as_deref(),
                Ok("1" | "true")
            ) {
                trustify_db::Database::bootstrap(&config).await
            } else {
                db::Database::new(&config).await
            }
            .expect("Configuring the database");

            return TrustifyContext::new(db, config.port, storage, defer(tmp)).await;
        }

        let (db, postgresql) = trustify_db::embedded::create()
            .await
            .expect("Create an embedded database");

        TrustifyContext::new(
            db,
            postgresql.settings().port,
            storage,
            defer(tmp).then(defer(postgresql)),
        )
        .await
    }

    async fn teardown(self) {
        self.0.teardown().await;
    }
}
