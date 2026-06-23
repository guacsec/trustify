use crate::sbom::model::SbomExternalPackageReference;
use actix_http::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use trustify_common::{cpe::Cpe, error::ErrorInformation, purl::Purl};

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct ExternalReferenceQuery {
    /// Find by PURL
    #[serde(default)]
    pub purl: Option<Purl>,
    /// Find by CPE
    #[serde(default)]
    pub cpe: Option<Cpe>,
}

#[derive(Debug, thiserror::Error)]
#[error("Requires either `purl` or `cpe` (got - purl: {:?}, cpe: {:?})", self.0.purl, self.0.cpe)]
pub struct ExternalReferenceQueryParseError(ExternalReferenceQuery);

impl ResponseError for ExternalReferenceQueryParseError {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::BadRequest().json(ErrorInformation {
            error: "CpeOrPurl".into(),
            message: "Requires either `purl` or `cpe`".to_string(),
            details: Some(format!(
                "Received - PURL: {:?}, CPE: {:?}",
                self.0.purl, self.0.cpe
            )),
        })
    }
}

impl<'a> TryFrom<&'a ExternalReferenceQuery> for SbomExternalPackageReference<'a> {
    type Error = ExternalReferenceQueryParseError;

    fn try_from(value: &'a ExternalReferenceQuery) -> Result<Self, Self::Error> {
        Ok(match value {
            ExternalReferenceQuery {
                purl: Some(purl),
                cpe: None,
            } => SbomExternalPackageReference::Purl(purl),
            ExternalReferenceQuery {
                purl: None,
                cpe: Some(cpe),
            } => SbomExternalPackageReference::Cpe(cpe),
            _ => {
                return Err(ExternalReferenceQueryParseError(value.clone()));
            }
        })
    }
}
