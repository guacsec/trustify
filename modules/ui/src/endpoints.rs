use crate::{
    error::Error,
    model::ExtractResult,
    service::{extract_cyclonedx_purls, extract_spdx_purls},
};
use actix_web::{
    HttpResponse, Responder,
    http::header,
    post,
    web::{self, Bytes, ServiceConfig},
};
use actix_web_static_files::{ResourceFiles, deps::static_files::Resource};
use std::collections::HashMap;
use trustify_common::{decompress::decompress_async, error::ErrorInformation, model::BinaryData};
use trustify_module_ingestor::service::{DetectedDocument, DocumentDetector, Format};
use trustify_ui::{UI, trustify_ui};
use utoipa::IntoParams;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Config {
    /// Upload limit for scan (after decompression).
    pub scan_limit: usize,
}

pub fn post_configure(svc: &mut ServiceConfig, ui: &UiResources) {
    svc.service(ResourceFiles::new("/", ui.resources()).resolve_not_found_to(""));
}

pub fn configure(svc: &mut utoipa_actix_web::service_config::ServiceConfig, config: Config) {
    svc.app_data(web::Data::new(config))
        .service(extract_sbom_purls);
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
#[post("/v3/ui/extract-sbom-purls")]
/// Extract PURLs from an SBOM provided in the request
async fn extract_sbom_purls(
    web::Query(ExtractSbomPurls { format }): web::Query<ExtractSbomPurls>,
    config: web::Data<Config>,
    content_type: Option<web::Header<header::ContentType>>,
    bytes: Bytes,
) -> Result<impl Responder, Error> {
    let bytes = decompress_async(bytes, content_type.map(|ct| ct.0), config.scan_limit).await??;

    let (format, packages, warnings) = tokio::task::spawn_blocking(move || {
        let detector = DocumentDetector::detect_as(&bytes, format)?;
        let detected_format = detector.format();
        let mut warnings = vec![];

        match detector.into_document() {
            DetectedDocument::Spdx(value) => {
                let sbom: spdx_rs::models::SPDX = serde_json::from_value(value)?;
                Ok((
                    detected_format,
                    extract_spdx_purls(sbom, &mut warnings),
                    warnings,
                ))
            }
            DetectedDocument::CycloneDx(sbom) => Ok((
                detected_format,
                extract_cyclonedx_purls(*sbom, &mut warnings),
                warnings,
            )),
            _ => Err(Error::BadRequest(
                format!("Format {detected_format} is not supported"),
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
