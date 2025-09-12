use sea_orm::FromQueryResult;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub mod service;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, FromQueryResult)]
pub struct LicenseRefMapping {
    pub license_id: String,
    pub license_name: String,
}
