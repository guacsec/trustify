use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Copy,
    Clone,
    Eq,
    Hash,
    Debug,
    PartialEq,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
    DeriveActiveEnum,
    EnumIter,
)]
#[strum(serialize_all = "snake_case")]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "status")]
pub enum Status {
    #[sea_orm(string_value = "affected")]
    Affected,
    #[sea_orm(string_value = "fixed")]
    Fixed,
    #[sea_orm(string_value = "not_affected")]
    NotAffected,
    #[sea_orm(string_value = "under_investigation")]
    UnderInvestigation,
    #[sea_orm(string_value = "recommended")]
    Recommended,
}
