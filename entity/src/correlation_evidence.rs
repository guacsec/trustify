use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "correlation_evidence")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub sbom_id: Uuid,
    pub node_id: String,
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub status: AssertionStatus,
    pub match_dimension: MatchDimension,
    pub confidence: f64,
    pub extractor: String,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
    #[sea_orm(
        belongs_to = "super::advisory::Entity",
        from = "Column::AdvisoryId",
        to = "super::advisory::Column::Id"
    )]
    Advisory,
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl Related<super::advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, ToSchema,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "assertion_status")]
#[serde(rename_all = "snake_case")]
pub enum AssertionStatus {
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

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, ToSchema,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "match_dimension")]
#[serde(rename_all = "snake_case")]
pub enum MatchDimension {
    #[sea_orm(string_value = "digest")]
    Digest,
    #[sea_orm(string_value = "purl")]
    Purl,
    #[sea_orm(string_value = "cpe")]
    Cpe,
}
