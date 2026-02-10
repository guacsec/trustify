pub mod sbom_license;

use crate::{Error, purl::model::VersionedPurlHead, sbom::model::SbomHead};
use serde::{Deserialize, Serialize};
use spdx::License;
use trustify_entity::license;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseSummary {
    #[serde(with = "uuid::serde::urn")]
    #[schema(value_type=String)]
    pub id: Uuid,
    pub license: String,
    pub spdx_licenses: Vec<String>,
    pub spdx_license_exceptions: Vec<String>,
    pub purls: u64,
}

impl LicenseSummary {
    pub async fn from_entity(license: &license::Model, purls: u64) -> Result<Self, Error> {
        Ok(LicenseSummary {
            id: license.id,
            license: license.text.clone(),
            spdx_licenses: license.spdx_licenses.as_ref().cloned().unwrap_or_default(),
            spdx_license_exceptions: license
                .spdx_license_exceptions
                .as_ref()
                .cloned()
                .unwrap_or_default(),
            purls,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseDetailsPurlSummary {
    pub purl: VersionedPurlHead,
    pub sbom: SbomHead,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpdxLicenseSummary {
    pub id: String,
    pub name: String,
}

impl SpdxLicenseSummary {
    pub fn from_details(rows: &[&License]) -> Vec<Self> {
        rows.iter()
            .map(
                |License {
                     name: id,
                     full_name: name,
                     ..
                 }| Self {
                    id: id.to_string(),
                    name: name.to_string(),
                },
            )
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpdxLicenseDetails {
    #[serde(flatten)]
    pub summary: SpdxLicenseSummary,
    pub text: String,
}
