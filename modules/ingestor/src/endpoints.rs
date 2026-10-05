use crate::{
    graph::Graph,
    service::{DocumentDetector, Error, Format, IngestorService, validation::Validator},
};
use actix_web::{HttpResponse, Responder, http::header, post, web};
use sea_orm::TransactionTrait;
use std::sync::Arc;
use trustify_auth::{
    UploadDataset,
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Require},
};
use trustify_common::{
    db,
    decompress::{self, decompress_async},
    model::BinaryData,
};
use trustify_entity::labels::Labels;
use trustify_module_analysis::service::AnalysisService;
use trustify_module_storage::service::dispatch::DispatchBackend;
use utoipa::IntoParams;

/// Decompress an uploaded document, if required, enforcing the limit on the decompressed size.
///
/// Without a content type declaring the compression, it is detected by magic bytes.
async fn decompress_upload(
    bytes: web::Bytes,
    content_type: Option<header::ContentType>,
    limit: usize,
) -> Result<web::Bytes, Error> {
    match decompress_async(bytes, content_type, limit)
        .await
        .map_err(|e| Error::Generic(e.into()))?
    {
        Ok(bytes) => Ok(bytes),
        Err(decompress::Error::PayloadTooLarge) => Err(Error::PayloadTooLarge),
        Err(err) => Err(Error::Generic(err.into())),
    }
}

/// mount the "ingestor" module
pub fn configure(
    svc: &mut utoipa_actix_web::service_config::ServiceConfig,
    config: Config,
    db: db::ReadWrite,
    storage: impl Into<DispatchBackend>,
    analysis: Option<AnalysisService>,
    validators: Vec<Arc<dyn Validator>>,
) {
    let ingestor_service =
        IngestorService::new(Graph::new(), storage, analysis).with_validators(validators);

    svc.app_data(web::Data::new(ingestor_service))
        .app_data(web::Data::new(config))
        .app_data(web::Data::new(db))
        .service(upload_dataset)
        .service(upload_document)
        .service(upload_document_from_url);
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Config {
    /// Limit of a single content entry (after decompression).
    pub dataset_entry_limit: usize,
    /// Limit for document uploads (after decompression).
    pub upload_limit: usize,
}

#[derive(
    IntoParams, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
struct UploadParams {
    /// Optional labels.
    ///
    /// Only use keys with a prefix of `labels.`
    #[serde(flatten, with = "trustify_entity::labels::prefixed")]
    labels: Labels,
}

#[utoipa::path(
    tag = "dataset",
    operation_id = "uploadDataset",
    request_body = inline(BinaryData),
    params(UploadParams),
    responses(
        (status = 201, description = "Uploaded the dataset"),
        (status = 400, description = "The file could not be parsed as an dataset"),
    )
)]
#[post("/v3/dataset")]
/// Upload a new dataset
pub async fn upload_dataset(
    service: web::Data<IngestorService>,
    config: web::Data<Config>,
    db: web::Data<db::ReadWrite>,
    web::Query(UploadParams { labels }): web::Query<UploadParams>,
    bytes: web::Bytes,
    _: Require<UploadDataset>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let result = service
        .ingest_dataset(&bytes, labels, config.dataset_entry_limit, &tx)
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::Created().json(result))
}

fn default_format() -> Format {
    Format::Unknown
}

#[derive(IntoParams, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DocumentUploadParams {
    /// Optional issuer if it cannot be determined from document contents.
    #[serde(default)]
    issuer: Option<String>,
    /// Optional labels.
    ///
    /// Only use keys with a prefix of `labels.`
    #[serde(flatten, with = "trustify_entity::labels::prefixed")]
    labels: Labels,
    /// Optional format hint. Defaults to auto-detection.
    #[serde(default = "default_format")]
    #[param(inline)]
    format: Format,
}

impl Default for DocumentUploadParams {
    fn default() -> Self {
        Self {
            issuer: None,
            labels: Labels::default(),
            format: default_format(),
        }
    }
}

fn require_permission(
    format: Format,
    authorizer: &Authorizer,
    user: &UserInformation,
) -> Result<(), Error> {
    if let Some(permission) = format.required_permission() {
        authorizer
            .require(user, permission)
            .map_err(|_| Error::Forbidden(format!("permission '{permission}' required")))?;
    }
    Ok(())
}

#[utoipa::path(
    tag = "upload",
    operation_id = "uploadDocument",
    request_body = inline(BinaryData),
    params(DocumentUploadParams),
    responses(
        (status = 201, description = "Document ingested successfully"),
        (status = 400, description = "The file could not be parsed"),
        (status = 403, description = "Insufficient permissions for this document type"),
    )
)]
#[post("/v3/upload")]
#[allow(clippy::too_many_arguments)]
/// Upload a document with auto-detected format and permission checking.
pub async fn upload_document(
    service: web::Data<IngestorService>,
    config: web::Data<Config>,
    db: web::Data<db::ReadWrite>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
    web::Query(DocumentUploadParams {
        issuer,
        labels,
        format,
    }): web::Query<DocumentUploadParams>,
    content_type: Option<web::Header<header::ContentType>>,
    bytes: web::Bytes,
) -> Result<impl Responder, Error> {
    let bytes = decompress_upload(bytes, content_type.map(|ct| ct.0), config.upload_limit).await?;

    let detected = DocumentDetector::detect_as(&bytes, format)?;
    let fmt = detected.format();

    require_permission(fmt, &authorizer, &user)?;

    let tx = db.begin().await?;
    let result = service
        .ingest(
            &bytes,
            fmt,
            labels,
            issuer,
            crate::service::Cache::Skip,
            &tx,
        )
        .await?;
    tx.commit().await?;

    tracing::info!("Uploaded document ({}): {}", fmt, result.id);

    Ok(HttpResponse::Created().json(result))
}

#[utoipa::path(
    tag = "upload",
    operation_id = "uploadDocumentFromUrl",
    request_body = trustify_api::ingest::IngestFromUrlRequest,
    params(DocumentUploadParams),
    responses(
        (status = 201, description = "Document fetched and ingested"),
        (status = 400, description = "The document could not be parsed"),
        (status = 403, description = "Insufficient permissions for this document type"),
        (status = 502, description = "Failed to download the document from the given URL"),
    )
)]
#[post("/v3/upload/from-url")]
#[allow(clippy::too_many_arguments)]
/// Download a document from a URL and ingest it with auto-detected format.
pub async fn upload_document_from_url(
    service: web::Data<IngestorService>,
    config: web::Data<Config>,
    http_client: web::Data<reqwest::Client>,
    db: web::Data<db::ReadWrite>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
    web::Query(DocumentUploadParams {
        issuer,
        labels,
        format,
    }): web::Query<DocumentUploadParams>,
    web::Json(body): web::Json<trustify_api::ingest::IngestFromUrlRequest>,
) -> Result<impl Responder, Error> {
    let response = http_client
        .get(&body.url)
        .send()
        .await
        .map_err(|e| Error::Generic(anyhow::anyhow!("request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(Error::Generic(anyhow::anyhow!(
            "HTTP {} from {}",
            response.status(),
            body.url
        )));
    }

    if let Some(content_length) = response.content_length()
        && config.upload_limit > 0
        && content_length > config.upload_limit as u64
    {
        return Err(Error::PayloadTooLarge);
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| Error::Generic(anyhow::anyhow!("failed to read response body: {e}")))?;

    if config.upload_limit > 0 && bytes.len() > config.upload_limit {
        return Err(Error::PayloadTooLarge);
    }

    // The server's content type is not trusted to declare the compression: compressed files are
    // commonly served as `application/x-xz` or `application/octet-stream`. Detect it instead.
    let bytes = decompress_upload(bytes, None, config.upload_limit).await?;

    let detected = DocumentDetector::detect_as(&bytes, format)?;
    let fmt = detected.format();

    require_permission(fmt, &authorizer, &user)?;

    let tx = db.begin().await?;
    let result = service
        .ingest(
            &bytes,
            fmt,
            labels,
            issuer,
            crate::service::Cache::Skip,
            &tx,
        )
        .await?;
    tx.commit().await?;

    tracing::info!("Ingested document from URL {}: {}", body.url, result.id);

    Ok(HttpResponse::Created().json(result))
}
