mod snapshot;

use crate::{
    TrustifyTestContext,
    ctx::migration::snapshot::Snapshot,
    migration::{Dump, Dumps, Migration, is_missing},
};
use anyhow::{Context, bail};
use std::{borrow::Cow, marker::PhantomData, ops::Deref};
use test_context::AsyncTestContext;
use uuid::Uuid;

#[macro_export]
macro_rules! commit {
    ($t:ident($id:literal)) => {
        pub struct $t;

        impl $crate::ctx::DumpId for $t {
            fn dump_id() -> $crate::ctx::MigrationSource {
                $crate::ctx::MigrationSource::Migration(Some($id))
            }
        }
    };
}

#[macro_export]
macro_rules! dump {
    ($t:ident($url:literal) $($chain:tt)*) => {
        pub struct $t;

        impl $crate::ctx::DumpId for $t {
            fn dump_id() -> $crate::ctx::Source {
                $crate::ctx::Source::Dump(
                    $crate::ctx::DumpSource::new($url) $($chain)*
                )
            }
        }
    };
}

#[derive(Debug)]
pub struct DumpSource {
    pub base_url: &'static str,
    pub db_file: &'static str,
    pub storage_file: &'static str,
    pub digests: bool,
    pub strip: usize,
    pub fix_zstd: bool,
}

impl DumpSource {
    pub fn new(base_url: &'static str) -> Self {
        Self {
            base_url,
            db_file: "dump.sql.gz",
            storage_file: "dump.tar",
            digests: true,
            strip: 0,
            fix_zstd: false,
        }
    }

    pub fn db_file(mut self, v: &'static str) -> Self {
        self.db_file = v;
        self
    }

    pub fn storage_file(mut self, v: &'static str) -> Self {
        self.storage_file = v;
        self
    }

    pub fn digests(mut self, v: bool) -> Self {
        self.digests = v;
        self
    }

    pub fn no_digests(self) -> Self {
        self.digests(false)
    }

    pub fn strip(mut self, v: usize) -> Self {
        self.strip = v;
        self
    }

    /// Appends the zstd EOF marker (`[0x01, 0x00, 0x00]`) to all `.zstd` files in the storage
    /// directory after unpacking. Older dump generation did not properly close the zstd stream,
    /// leaving the EOF marker unwritten.
    pub fn fix_zstd(mut self) -> Self {
        self.fix_zstd = true;
        self
    }
}

#[derive(Debug)]
pub enum Source {
    Migration(Option<&'static str>),
    Dump(DumpSource),
}

impl Source {
    /// generate a reproducible, unique ID for a source
    ///
    /// We do this by generating a debug string, which contains all the necessary information, and
    /// then creating a v5 UUID, which is basically a SHA-1 digest.
    pub fn id(&self) -> String {
        const NAMESPACE: Uuid = Uuid::from_bytes([
            0x2c, 0x84, 0x27, 0x45, 0xb6, 0xc8, 0x4a, 0xf7, 0x9a, 0xdb, 0x28, 0x76, 0x8b, 0x45,
            0x6e, 0x95,
        ]);

        let debug_str = format!("{self:?}");

        Uuid::new_v5(&NAMESPACE, debug_str.as_bytes()).to_string()
    }
}

pub trait DumpId {
    fn dump_id() -> Source;
}

impl DumpId for () {
    fn dump_id() -> Source {
        Source::Migration(None)
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
        let source = ID::dump_id();
        let source_id = source.id();

        let dumps = Dumps::new()?;

        let snapshot = match source {
            Source::Migration(migration) => {
                let id: Cow<'static, str> = match migration {
                    Some(id) => format!("commit-{id}").into(),
                    None => "latest".into(),
                };
                let migration =
                    Migration::new(&id).context("failed to create migration manager")?;

                let mut base = None;
                let mut last = None;

                for dump in migration.as_dumps() {
                    let url = dump.url.to_string();
                    match dumps.provide_raw("migration", dump).await {
                        Ok(path) => {
                            base = Some(path);
                            break;
                        }
                        // only fall back to the next candidate if the dump is simply not there
                        Err(err) if is_missing(&err) => {
                            log::info!("no migration dump at '{url}', trying next: {err}");
                            last = Some(err);
                        }
                        Err(err) => return Err(err),
                    }
                }

                let base = match (base, last) {
                    (Some(base), _) => base,
                    (None, Some(err)) => return Err(err),
                    (None, None) => bail!("no migration dump candidates"),
                };

                Snapshot {
                    id: source_id,
                    base,
                    db_file: "dump.sql.xz".to_string(),
                    storage_file: "dump.tar".to_string(),
                    #[cfg(target_os = "linux")]
                    snapshot_file: None,
                    strip: 0,
                    fix_zstd: false,
                }
            }

            Source::Dump(DumpSource {
                base_url,
                db_file,
                storage_file,
                digests,
                strip,
                fix_zstd,
            }) => {
                let snapshot_file = Snapshot::is_supported().then_some("snapshot.tar.xz");

                let files: Vec<_> = [db_file, storage_file]
                    .into_iter()
                    .chain(snapshot_file)
                    .collect();

                let base = dumps
                    .provide(Dump {
                        url: base_url,
                        files: files.as_slice(),
                        digests,
                    })
                    .await?;

                Snapshot {
                    id: source_id,
                    base,
                    db_file: db_file.to_string(),
                    storage_file: storage_file.to_string(),
                    #[cfg(target_os = "linux")]
                    snapshot_file: snapshot_file.map(ToOwned::to_owned),
                    strip,
                    fix_zstd,
                }
            }
        };

        Ok(Self(snapshot.materialize().await?, Default::default()))
    }
}

impl<ID: DumpId> AsyncTestContext for TrustifyMigrationContext<ID> {
    async fn setup() -> Self {
        Self::new()
            .await
            .expect("failed to create migration context")
    }

    #[allow(clippy::manual_async_fn)]
    fn teardown(self) -> impl Future<Output = ()> {
        async {
            self.0.teardown().await;
        }
    }
}
