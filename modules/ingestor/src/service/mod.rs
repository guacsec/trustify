pub mod advisory;
pub mod dataset;
pub mod sbom;
pub mod weakness;

mod format;
pub use format::Format;

use crate::{
    graph::Graph,
    model::IngestResult,
    service::dataset::{DatasetIngestResult, DatasetLoader},
};
use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use anyhow::anyhow;
use parking_lot::Mutex;
use sbom_walker::report::ReportSink;
use sea_orm::error::DbErr;
use std::{fmt::Debug, sync::Arc, time::Instant};
use tokio::task::JoinError;
use tracing::instrument;
use trustify_common::{db::DatabaseErrors, error::ErrorInformation, id::Id, id::IdError};
use trustify_entity::labels::Labels;
use trustify_module_analysis::service::AnalysisService;
use trustify_module_storage::service::{StorageBackend, dispatch::DispatchBackend};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    HashKey(#[from] IdError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    JsonPath(#[from] jsonpath_rust::parser::errors::JsonPathError),
    #[error(transparent)]
    Xml(#[from] roxmltree::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yml::Error),
    #[error(transparent)]
    Graph(#[from] crate::graph::error::Error),
    #[error(transparent)]
    Db(DbErr),
    #[error("storage error: {0}")]
    Storage(#[source] anyhow::Error),
    #[error(transparent)]
    Generic(anyhow::Error),
    #[error("invalid content: {0}")]
    InvalidContent(#[source] anyhow::Error),
    #[error("invalid format: {0}")]
    UnsupportedFormat(String),
    #[error("failed to await the task: {0}")]
    Join(#[from] JoinError),
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("unavailable")]
    Unavailable,
}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        if value.is_read_only() {
            Error::Unavailable
        } else {
            Error::Db(value)
        }
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Json(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "JsonParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::JsonPath(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "JsonPath".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Yaml(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "YamlParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Xml(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "XmlParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Io(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "I/O".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Utf8(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "UTF-8".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Storage(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Storage".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Join(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Join".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Db(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Database".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Graph(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Graph".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Generic(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Generic".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::InvalidContent(details) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "InvalidContent".into(),
                message: "Invalid content".to_string(),
                details: Some(details.to_string()),
            }),
            Self::UnsupportedFormat(fmt) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "UnsupportedFormat".into(),
                message: format!("Unsupported document format: {fmt}"),
                details: None,
            }),
            Error::HashKey(inner) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "Digest key error".into(),
                message: inner.to_string(),
                details: None,
            }),
            Self::Zip(inner) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "ZipError".into(),
                message: inner.to_string(),
                details: None,
            }),
            Self::PayloadTooLarge => HttpResponse::PayloadTooLarge().json(ErrorInformation {
                error: "PayloadTooLarge".into(),
                message: self.to_string(),
                details: None,
            }),
            Self::Unavailable => HttpResponse::ServiceUnavailable().json(ErrorInformation {
                error: "Unavailable".into(),
                message: self.to_string(),
                details: None,
            }),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Default, serde::Deserialize, utoipa::ToSchema)]
#[schema(rename_all = "camelCase")]
pub enum Cache {
    /// Skip loading into cache
    #[default]
    Skip,
    /// Queue a request to load into cache
    Queue,
    /// Queue and await request to load into cache
    Wait,
}

impl From<Cache> for Option<bool> {
    fn from(value: Cache) -> Self {
        match value {
            Cache::Skip => None,
            Cache::Queue => Some(false),
            Cache::Wait => Some(true),
        }
    }
}

#[derive(Clone)]
pub struct IngestorService {
    graph: Graph,
    storage: DispatchBackend,
    analysis: Option<AnalysisService>,
}

impl IngestorService {
    pub fn new(
        graph: Graph,
        storage: impl Into<DispatchBackend>,
        analysis: Option<AnalysisService>,
    ) -> Self {
        Self {
            graph,
            storage: storage.into(),
            analysis,
        }
    }

    pub fn storage(&self) -> &DispatchBackend {
        &self.storage
    }

    pub fn graph(&self) -> &Graph {
        &self.graph
    }

    pub fn db(&self) -> trustify_common::db::Database {
        self.graph.db.clone()
    }

    #[instrument(skip_all, err)]
    pub async fn ingest(
        &self,
        bytes: &[u8],
        format: Format,
        labels: impl Into<Labels> + Debug,
        issuer: Option<String>,
        cache: Cache,
    ) -> Result<IngestResult, Error> {
        let start = Instant::now();

        // We want to resolve the format first to avoid storing a
        // document that we can't subsequently retrieve and load into
        // the database.
        let fmt = match format {
            Format::Advisory => Format::advisory_from_bytes(bytes)?,
            Format::SBOM => Format::sbom_from_bytes(bytes)?,
            Format::Unknown => Format::from_bytes(bytes)?,
            v => v,
        };

        let result = self
            .storage
            .store(bytes)
            .await
            .map_err(|err| Error::Storage(anyhow!("{err}")))?;

        let result = fmt
            .load(&self.graph, labels.into(), issuer, &result.digests, bytes)
            .await?;

        if let Some(wait) = cache.into() {
            self.load_graph_cache(fmt, &result, wait).await;
        }

        let duration = start.elapsed();
        log::debug!(
            "Ingested: {} ({:?}): took {}",
            result.id,
            result.document_id,
            humantime::Duration::from(duration),
        );

        Ok(result)
    }

    /// Ingest a dataset archive
    #[instrument(skip(self, bytes), err(level=tracing::Level::INFO))]
    pub async fn ingest_dataset(
        &self,
        bytes: &[u8],
        labels: impl Into<Labels> + Debug,
        limit: usize,
    ) -> Result<DatasetIngestResult, Error> {
        let loader = DatasetLoader::new(self.graph(), self.storage(), limit);
        loader.load(labels.into(), bytes).await
    }

    /// If appropriate, load result into analysis graph cache
    #[instrument(skip(self))]
    async fn load_graph_cache(&self, fmt: Format, result: &IngestResult, wait: bool) {
        let Some(analysis) = &self.analysis else {
            // if we don't have an instance, we skip
            return;
        };

        let (Format::SPDX | Format::CycloneDX) = fmt else {
            // wrong format, we skip that too
            return;
        };

        let Id::Uuid(id) = result.id else {
            // no ID in the result, strange, but skip
            return;
        };

        match analysis.queue_load(id.to_string()) {
            Ok(r) if wait => {
                // queued ok, await processing
                if let Err(err) = r.await {
                    log::warn!("Failed to await queue load: {err}");
                }
            }
            Ok(_) => {
                // queued ok, don't wait
            }
            Err(e) => {
                // failed to queue
                log::warn!(
                    "Error queuing graph load for SBOM {}: {e}",
                    result.id.value()
                );
            }
        }
    }
}

/// Capture warnings from the import process
#[derive(Default)]
pub(crate) struct Warnings(Arc<Mutex<Vec<String>>>);

impl Warnings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, msg: String) {
        self.0.lock().push(msg);
    }
}

impl ReportSink for Warnings {
    fn error(&self, msg: String) {
        self.add(msg)
    }
}

impl From<Warnings> for Vec<String> {
    fn from(value: Warnings) -> Self {
        match Arc::try_unwrap(value.0) {
            Ok(warnings) => warnings.into_inner(),
            Err(warnings) => warnings.lock().clone(),
        }
    }
}

pub struct Discard;

impl ReportSink for Discard {
    fn error(&self, _msg: String) {}
}
