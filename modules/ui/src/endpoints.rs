use crate::{
    error::Error,
    model::ExtractResult,
    service::{extract_cyclonedx_purls, extract_spdx_purls},
};
use actix_multipart::form::{MultipartForm, json::Json as MPJson};
use actix_web::{
    HttpResponse, Responder,
    http::header,
    post,
    web::{self, Bytes, ServiceConfig},
};
use actix_web_static_files::{ResourceFiles, deps::static_files::Resource};
use flate2::{Compression, write::GzEncoder};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tar::{Builder, Header};
use trustify_common::{decompress::decompress_async, error::ErrorInformation, model::BinaryData};
use trustify_module_ingestor::service::Format;
use trustify_ui::{UI, trustify_ui};
use utoipa::{IntoParams, ToSchema};

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Config {
    /// Upload limit for scan (after decompression).
    pub scan_limit: usize,
}

pub fn post_configure(svc: &mut ServiceConfig, ui: Arc<UiResources>) {
    let resources = ui.resources();
    svc.app_data(web::Data::new(ui))
        .service(ResourceFiles::new("/", resources).resolve_not_found_to(""));
}

pub fn configure(svc: &mut utoipa_actix_web::service_config::ServiceConfig, config: Config) {
    svc.app_data(web::Data::new(config))
        .service(extract_sbom_purls)
        .service(generate_sbom_static_report);
}

pub struct UiResources {
    resources: HashMap<&'static str, Resource>,
}

impl UiResources {
    pub fn new(ui: &UI) -> anyhow::Result<Self> {
        Ok(Self {
            resources: trustify_ui(ui)?,
        })
    }

    pub fn resources(&self) -> HashMap<&'static str, Resource> {
        self.resources
            .iter()
            .map(|(k, v)| {
                // unfortunately, we can't just clone, but we can do it ourselves
                (
                    *k,
                    Resource {
                        data: v.data,
                        modified: v.modified,
                        mime_type: v.mime_type,
                    },
                )
            })
            .collect()
    }
}

#[derive(IntoParams, Clone, Debug, PartialEq, Eq, serde::Deserialize)]
struct ExtractSbomPurls {
    /// An SBOM format to expect, or [`Format::SBOM`] and [`Format::Unknown`] to auto-detect.
    #[serde(default = "default::format")]
    format: Format,
}

mod default {
    use super::*;

    pub const fn format() -> Format {
        Format::SBOM
    }
}

#[utoipa::path(
    tag = "ui",
    operation_id = "extractSbomPurls",
    request_body = inline(BinaryData),
    params(
        ExtractSbomPurls,
    ),
    responses(
        (
            status = 200,
            description = "Information extracted from the SBOM",
            body = ExtractResult,
        ),
        (
            status = 400,
            description = "Bad request data, like an unsupported format or invalid data",
            body = ErrorInformation,
        )
    )
)]
#[post("/v2/ui/extract-sbom-purls")]
/// Extract PURLs from an SBOM provided in the request
async fn extract_sbom_purls(
    web::Query(ExtractSbomPurls { format }): web::Query<ExtractSbomPurls>,
    config: web::Data<Config>,
    content_type: Option<web::Header<header::ContentType>>,
    bytes: Bytes,
) -> Result<impl Responder, Error> {
    let bytes = decompress_async(bytes, content_type.map(|ct| ct.0), config.scan_limit).await??;

    let (format, packages, warnings) = tokio::task::spawn_blocking(move || {
        let format = format.resolve(&bytes)?;
        let mut warnings = vec![];

        match format {
            Format::SPDX => {
                let sbom = serde_json::from_slice(&bytes)?;
                Ok((format, extract_spdx_purls(sbom, &mut warnings), warnings))
            }
            Format::CycloneDX => {
                let sbom = serde_json::from_slice(&bytes)?;
                Ok((
                    format,
                    extract_cyclonedx_purls(sbom, &mut warnings),
                    warnings,
                ))
            }
            other => Err(Error::BadRequest(
                format!("Format {other} is not supported"),
                Some("Only 'SPDX' or 'CycloneDX' is supported".into()),
            )),
        }
    })
    .await??;

    Ok(HttpResponse::Ok().json(ExtractResult {
        format,
        packages,
        warnings,
    }))
}

#[derive(Debug, MultipartForm, ToSchema)]
struct UploadForm {
    #[schema(value_type = Object)]
    analysis_response: MPJson<serde_json::Value>,
}

#[utoipa::path(
    tag = "ui",
    operation_id = "generateSbomStaticReport",
    request_body(content = UploadForm, content_type = "multipart/form-data"),
    responses(
        (
            status = 200,
            description = "Static report",
            body = Vec<u8>,
            content_type = "application/gzip"
        ),
        (
            status = 400,
            description = "Bad request data, like an unsupported format or invalid data",
            body = ErrorInformation,
        )
    )
)]
#[post("/v2/ui/generate-sbom-static-report")]
/// Generates an static report
async fn generate_sbom_static_report(
    ui: web::Data<Arc<UiResources>>,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> Result<impl Responder, Error> {
    let mut data = Vec::new();
    {
        let encoder = GzEncoder::new(&mut data, Compression::default());
        let mut gzip = Builder::new(encoder);

        // Add static report template
        let prefix = "static-report/";
        for (path, resource) in ui.resources.iter() {
            if let Some(relative_path) = path.strip_prefix(prefix) {
                let mut header = Header::new_gnu();
                header.set_size(resource.data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                header.set_mtime(
                    std::time::UNIX_EPOCH
                        .elapsed()
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs(),
                );

                gzip.append_data(&mut header, relative_path, resource.data)?;
            }
        }

        // Add static report data
        let json_data = serde_json::to_string(&form.analysis_response.0)?;
        let js_data = format!("window.analysis_response={json_data}");

        let mut header = Header::new_gnu();
        header.set_size(js_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        header.set_mtime(
            std::time::UNIX_EPOCH
                .elapsed()
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
        );
        gzip.append_data(&mut header, "data.js", js_data.as_bytes())?;

        // Close gzip
        gzip.finish()?;
    }

    Ok(HttpResponse::Ok()
        .content_type("application/gzip")
        .append_header((
            "Content-Disposition",
            "attachment; filename=\"static-report.tar.gz\"",
        ))
        .body(data))
}
