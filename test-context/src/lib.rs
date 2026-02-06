#![recursion_limit = "256"]
#![allow(clippy::expect_used)]

pub mod app;
pub mod auth;
pub mod call;
pub mod ctx;
pub mod flame;
pub mod migration;
pub mod q;
pub mod spdx;
pub mod subset;

pub use ctx::{ReadOnly, TrustifyContext, TrustifyMigrationContext};

use ::migration::{
    ConnectionTrait, DbErr,
    sea_orm::{RuntimeErr, Statement, prelude::Uuid, sqlx},
};
use futures::Stream;
use peak_alloc::PeakAlloc;
use postgresql_embedded::PostgreSQL;
use serde::Serialize;
use std::{
    env,
    fmt::Debug,
    io::{Cursor, Read, Seek, Write},
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use tokio_util::{bytes::Bytes, io::ReaderStream};
use trustify_common::{db::Database, decompress::decompress_async, hashing::Digests};
use trustify_entity::labels::Labels;
use trustify_module_ingestor::{
    graph::Graph,
    model::IngestResult,
    service::{Cache, Format, IngestorService, dataset::DatasetIngestResult},
};
use trustify_module_storage::service::fs::FileSystemBackend;
use zip::write::FileOptions;

pub enum Dataset {
    DS3,
}

impl AsRef<Path> for Dataset {
    fn as_ref(&self) -> &Path {
        match self {
            Self::DS3 => Path::new("../datasets/ds3"),
        }
    }
}

/// A common test content.
///
/// **NOTE:** Dropping it will tear down the embedded database. So it must be kept until the end
/// of the test.
#[allow(dead_code)]
pub struct TrustifyTestContext {
    pub db: Database,
    pub graph: Graph,
    pub storage: FileSystemBackend,
    pub ingestor: IngestorService,
    pub mem_limit_mb: f32,
    pub postgresql: Option<PostgreSQL>,
    /// Temp directory resource, will be deleted when dropped
    _tmp: TempDir,
}

#[global_allocator]
static PEAK_ALLOC: PeakAlloc = PeakAlloc;

impl TrustifyTestContext {
    async fn new(
        db: Database,
        storage: FileSystemBackend,
        tmp: TempDir,
        postgresql: impl Into<Option<PostgreSQL>>,
    ) -> Self {
        let graph = Graph::new(db.clone());
        let ingestor = IngestorService::new(graph.clone(), storage.clone(), Default::default());
        let mem_limit_mb = env::var("MEM_LIMIT_MB")
            .unwrap_or("500".into())
            .parse()
            .expect("a numerical value");

        Self {
            db,
            graph,
            storage,
            ingestor,
            mem_limit_mb,
            postgresql: postgresql.into(),
            _tmp: tmp,
        }
    }

    /// Turn the context's database into a read-only by default database.
    pub async fn read_only(self) -> Result<Self, DbErr> {
        let db = self.db;

        db.execute_unprepared(
            r#"
DO $$
DECLARE
    dbname text;
BEGIN
    -- find the current database name
    SELECT current_database() INTO dbname;

    -- set it to read-only
    EXECUTE format(
        'ALTER DATABASE %I SET default_transaction_read_only = on',
        dbname
    );
END
$$;
"#,
        )
        .await?;

        terminate_connections(&db).await?;

        let result = db
            .query_one(Statement::from_string(
                db.get_database_backend(),
                "SHOW default_transaction_read_only",
            ))
            .await?;

        if let Some(row) = result {
            for c in row.column_names() {
                log::info!("{c}: {:?}", row.try_get_by::<String, _>(c.as_str()));
            }
        }

        Ok(Self { db, ..self })
    }

    /// The paths are relative to `<workspace>/etc/test-data`.
    pub async fn ingest_documents<P: IntoIterator<Item = impl AsRef<str>>>(
        &self,
        paths: P,
    ) -> Result<Vec<IngestResult>, anyhow::Error> {
        let mut results = Vec::new();
        for path in paths {
            results.push(self.ingest_document(path.as_ref()).await?);
        }
        Ok(results)
    }

    /// Same as [`Self::ingest_document_as`], but with a format of [`Format::Unknown`].
    ///
    /// The path is relative to `<workspace>/etc/test-data`.
    pub async fn ingest_document(&self, path: &str) -> Result<IngestResult, anyhow::Error> {
        self.ingest_document_as(path, Format::Unknown, ("source", "TrustifyContext"))
            .await
    }

    /// Ingest a document with a specific format and labels
    ///
    /// Consumed raw bytes.
    pub async fn ingest_bytes_as(
        &self,
        bytes: &[u8],
        format: Format,
        labels: impl Into<Labels> + Debug,
    ) -> Result<IngestResult, anyhow::Error> {
        Ok(self
            .db
            .transaction(async |tx| {
                self.ingestor
                    .ingest(bytes, format, labels, None, Cache::Skip, tx)
                    .await
            })
            .await?)
    }

    /// Ingest a document with a specific format and labels
    ///
    /// The path is relative to `<workspace>/etc/test-data`.
    pub async fn ingest_document_as(
        &self,
        path: &str,
        format: Format,
        labels: impl Into<Labels> + Debug,
    ) -> Result<IngestResult, anyhow::Error> {
        let bytes = document_bytes(path).await?;

        self.ingest_bytes_as(&bytes, format, labels).await
    }

    pub async fn ingest_read<R: Read>(&self, mut read: R) -> Result<IngestResult, anyhow::Error> {
        let mut bytes = Vec::new();
        read.read_to_end(&mut bytes)?;

        self.ingest_bytes_as(&bytes, Format::Unknown, ("source", "TrustifyContext"))
            .await
    }

    /// Ingest a document by ingesting its JSON representation
    pub async fn ingest_json<S: Serialize>(&self, doc: S) -> Result<IngestResult, anyhow::Error> {
        let bytes = serde_json::to_vec(&doc)?;

        self.ingest_bytes_as(&bytes, Format::Unknown, ("source", "TrustifyContext"))
            .await
    }

    pub fn absolute_path(&self, path: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
        absolute(path)
    }

    pub async fn ingest_parallel<const N: usize>(
        &self,
        paths: [&str; N],
    ) -> Result<[IngestResult; N], anyhow::Error> {
        let mut f = vec![];

        for path in paths {
            f.push(self.ingest_document(path));
        }

        let r = futures::future::try_join_all(f).await?;
        let r = r.try_into().expect("Unexpected number of results");

        Ok(r)
    }

    /// Create a dataset on the fly and ingest it
    ///
    /// The path can either be a literal path, or a pre-defined constant like [`Dataset`].
    pub async fn ingest_dataset(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<DatasetIngestResult, anyhow::Error> {
        let base = self.absolute_path(path)?;
        let mut data = vec![];
        let mut dataset = zip::write::ZipWriter::new(Cursor::new(&mut data));
        for entry in walkdir::WalkDir::new(&base) {
            let entry = entry?;
            let Ok(path) = entry.path().strip_prefix(&base) else {
                continue;
            };

            if entry.file_type().is_file() {
                dataset.start_file_from_path(path, FileOptions::<()>::default())?;
                dataset.write_all(&(std::fs::read(entry.path())?))?;
            } else if entry.file_type().is_dir() {
                dataset.add_directory_from_path(path, FileOptions::<()>::default())?;
            }
        }
        dataset.finish()?;

        Ok(self
            .db
            .transaction(async |tx| self.ingestor.ingest_dataset(&data, (), 0, tx).await)
            .await?)
    }

    pub(crate) fn teardown(&self) {
        let peak_mem = PEAK_ALLOC.peak_usage_as_mb();
        let args: Vec<String> = env::args().collect();
        // Prints the error message when running the tests with threads=1
        if args.iter().any(|arg| arg == "--test-threads=1") && peak_mem > self.mem_limit_mb {
            log::error!("Too much RAM used: {peak_mem} MB");
        }
        PEAK_ALLOC.reset_peak_usage();
    }
}

/// return an absolute part, relative to `<workspace>/etc/test-data`.
fn absolute(path: impl AsRef<Path>) -> Result<PathBuf, anyhow::Error> {
    let workspace_root: PathBuf = env!("CARGO_WORKSPACE_ROOT").into();
    let test_data = workspace_root.join("etc/test-data");
    Ok(test_data.join(path))
}

/// Load a test document and decompress it, if necessary.
pub async fn document_bytes(path: &str) -> Result<Bytes, anyhow::Error> {
    let bytes = document_bytes_raw(path).await?;
    let bytes = decompress_async(bytes, None, 0).await??;
    Ok(bytes)
}

/// Load a test document as-is, no decompression.
///
/// The path is relative to `<workspace>/etc/test-data`.
pub async fn document_bytes_raw(path: &str) -> Result<Bytes, anyhow::Error> {
    let bytes = tokio::fs::read(absolute(path)?).await?;
    Ok(bytes.into())
}

/// Get a stream for a document from the test-data directory
pub async fn document_stream(
    path: &str,
) -> Result<impl Stream<Item = Result<Bytes, std::io::Error>>, anyhow::Error> {
    let file = tokio::fs::File::open(absolute(path)?).await?;
    Ok(ReaderStream::new(file))
}

/// Read a document from the test-data directory. Does not decompress.
pub fn document_read(path: &str) -> Result<impl Read + Seek, anyhow::Error> {
    Ok(std::fs::File::open(absolute(path)?)?)
}

/// Read a document and parse it as JSON.
pub async fn document<T>(path: &str) -> Result<(T, Digests), anyhow::Error>
where
    T: serde::de::DeserializeOwned + Send + 'static,
{
    let data = document_bytes(path).await?;
    let digests = Digests::digest(&data);
    let f = move || Ok::<_, anyhow::Error>(serde_json::from_slice::<T>(&data)?);

    Ok((tokio::task::spawn_blocking(f).await??, digests))
}

/// terminate connections, either all or only everything except our own
async fn terminate_connections_int(db: &Database, our: bool) -> Result<(), DbErr> {
    let and = match our {
        true => "AND pid = pg_backend_pid()",
        false => "AND pid <> pg_backend_pid()",
    };

    db.execute_unprepared(
        &format!(r#"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() {and}"#),
    )
        .await
        .map(|_| ())
        .or_else(|err| match err {
            DbErr::Exec(RuntimeErr::SqlxError(sqlx::error::Error::Database(err)))
            if err.code().as_deref() == Some("57P01") =>
                {
                    log::info!("Ignoring broken connection");
                    // should catch the "terminating connection due to administrator command", which
                    // is caused by killing the connection at the end of the above statement.
                    Ok(())
                }
            _ => Err(err),
        })?;

    Ok(())
}

/// terminate all connections
async fn terminate_connections(db: &Database) -> Result<(), DbErr> {
    // we do this twice. Once without our own, in order to kill all and then our own
    // if we do this in one step, we will kill our own session and stop killing the remaining ones
    terminate_connections_int(db, false).await?;
    terminate_connections_int(db, true).await?;
    Ok(())
}

pub trait IngestionResult: Sized {
    /// Collect all IDs from a result
    fn collect_ids(self) -> impl Iterator<Item = String>;

    /// Turn into an array of IDs
    ///
    /// **NOTE:** This will panic if the array size doesn't match the result set size
    fn into_id<const N: usize>(self) -> [String; N] {
        self.collect_ids()
            .collect::<Vec<_>>()
            .try_into()
            .expect("Unexpected number of results")
    }

    /// Turn into an array of UUIDs, by parsing UUIDs from the IDs.
    ///
    /// **NOTE:** This will panic if the array size doesn't match the result set size
    fn into_uuid<const N: usize>(self) -> [Uuid; N] {
        self.collect_ids()
            .filter_map(|id| Uuid::parse_str(&id).ok())
            .collect::<Vec<_>>()
            .try_into()
            .expect("Unexpected number of results")
    }
}

impl IngestionResult for Vec<IngestResult> {
    fn collect_ids(self) -> impl Iterator<Item = String> {
        self.into_iter().map(|r| r.id)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use futures::StreamExt;
    use test_context::test_context;
    use test_log::test;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_documents(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let result = ctx
            .ingest_documents(["zookeeper-3.9.2-cyclonedx.json"])
            .await?;

        let ingestion_result = &result[0];

        assert!(ingestion_result.document_id.is_some());

        Ok(())
    }

    #[test(tokio::test)]
    async fn test_document_bytes() {
        let bytes = document_bytes("zookeeper-3.9.2-cyclonedx.json")
            .await
            .unwrap();
        assert!(!bytes.is_empty());
    }

    #[test(tokio::test)]
    async fn test_document_stream() {
        let stream = document_stream("zookeeper-3.9.2-cyclonedx.json")
            .await
            .unwrap();
        assert!(Box::pin(stream).next().await.is_some());
    }

    #[test(tokio::test)]
    async fn test_document_struct() {
        use hex::ToHex;
        use osv::schema::Vulnerability;

        let (osv, digests): (Vulnerability, _) =
            document("osv/RUSTSEC-2021-0079.json").await.unwrap();

        assert_eq!(osv.id, "RUSTSEC-2021-0079");
        assert_eq!(
            digests.sha256.encode_hex::<String>(),
            "d113c2bd1ad6c3ac00a3a8d3f89d3f38de935f8ede0d174a55afe9911960cf51"
        );
    }
}
