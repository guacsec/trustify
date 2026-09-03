use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(
    Copy,
    Clone,
    Eq,
    Hash,
    Debug,
    PartialEq,
    EnumIter,
    DeriveActiveEnum,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "status")]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ActiveEnum, Iterable};

    /// Verifies that SeaORM, strum, and serde serialization values align for all Status variants.
    #[test]
    fn status_serialization_alignment() {
        for variant in Status::iter() {
            let sea_orm_value = variant.to_value();
            let strum_value = variant.to_string();
            let serde_value = serde_json::to_value(variant).unwrap();

            assert_eq!(
                sea_orm_value, strum_value,
                "SeaORM and strum disagree for {:?}: sea_orm={}, strum={}",
                variant, sea_orm_value, strum_value
            );
            assert_eq!(
                serde_value.as_str().unwrap(),
                strum_value,
                "serde and strum disagree for {:?}: serde={}, strum={}",
                variant,
                serde_value,
                strum_value
            );
        }
    }
}
