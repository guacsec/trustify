use crate::{TrustifyTestContext, migration::Migration};
use anyhow::Context;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::ops::Deref;
use tar::Archive;
use test_context::AsyncTestContext;
use trustify_db::embedded::{Options, Source, default_settings};
use trustify_module_storage::service::fs::FileSystemBackend;

#[macro_export]
macro_rules! commit {
    ($t:ident($id:literal)) => {
        pub struct $t;

        impl DumpId for $t {
            fn dump_id() -> Option<&'static str> {
                Some($id)
            }
        }
    };
}

pub trait DumpId {
    fn dump_id() -> Option<&'static str>;
}

impl DumpId for () {
    fn dump_id() -> Option<&'static str> {
        None
    }
}

/// Creates a database and imports the previous DB and storage dump.
pub struct TrustifyMigrationContext<ID: DumpId = ()>(
    pub(crate) TrustifyTestContext,
    PhantomData<ID>,
);

impl<ID: DumpId> Deref for TrustifyMigrationContext<ID> {
    type Target = TrustifyTestContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<ID: DumpId> TrustifyMigrationContext<ID> {
    pub async fn new() -> anyhow::Result<Self> {
        let migration = Migration::new().expect("failed to create migration manager");
        let id: Cow<'static, str> = match ID::dump_id() {
            Some(id) => format!("commit-{id}").into(),
            None => "latest".into(),
        };
        let base = migration.provide(&id).await?;

        // create storage

        let (storage, tmp) = FileSystemBackend::for_test()
            .await
            .expect("Unable to create storage backend");

        let mut archive = Archive::new(
            std::fs::File::open(base.join("dump.tar")).context("failed to open storage dump")?,
        );
        archive
            .unpack(tmp.path())
            .context("failed to unpack storage dump")?;

        // create DB

        let settings = default_settings().context("unable to create default settings")?;

        let (db, postgresql) = trustify_db::embedded::create_for(
            settings,
            Options {
                source: Source::Import(base.join("dump.sql.xz")),
            },
        )
        .await
        .context("failed to create an embedded database")?;

        Ok(Self(
            TrustifyTestContext::new(db, storage, tmp, postgresql).await,
            Default::default(),
        ))
    }
}

impl<ID: DumpId> AsyncTestContext for TrustifyMigrationContext<ID> {
    async fn setup() -> Self {
        Self::new()
            .await
            .expect("failed to create migration context")
    }
}
