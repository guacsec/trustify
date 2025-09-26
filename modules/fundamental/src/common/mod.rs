use crate::sbom::service::sbom::LicenseBasicInfo;
use sea_orm::FromQueryResult;
use sea_query::FromValueTuple;
use serde::{Deserialize, Serialize};
use trustify_entity::sbom_package_license::LicenseCategory;
use utoipa::ToSchema;

pub mod license_filtering;
pub mod service;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, FromQueryResult)]
pub struct LicenseRefMapping {
    pub license_id: String,
    pub license_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct LicenseInfo {
    pub license_name: String,
    pub license_type: LicenseCategory,
}

impl From<LicenseBasicInfo> for LicenseInfo {
    fn from(license_basic_info: LicenseBasicInfo) -> Self {
        LicenseInfo {
            license_name: license_basic_info.license_name,
            license_type: LicenseCategory::from_value_tuple(license_basic_info.license_type),
        }
    }
}
