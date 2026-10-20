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
    pub confidence: f64,
    pub extractor: String,
    /// The advisory side value which matched, a serialized `trustify_api::correlation::MatchedValue`.
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub matched_value: Option<serde_json::Value>,
    pub created_at: TimeDateTimeWithTimeZone,
    /// The factors of the confidence, serialized `trustify_api::correlation::ConfidenceFactor`s.
    /// Empty for evidence extracted before they were recorded.
    #[sea_orm(column_type = "JsonBinary")]
    pub confidence_factors: serde_json::Value,
    /// Source assertions which survived identity, version and product-context matching.
    /// Empty for evidence extracted before source references were recorded.
    #[sea_orm(column_type = "JsonBinary")]
    pub source_assertions: serde_json::Value,
}

/// A source statement, independent of the extractor or rule which matched it.
/// References retain the subject/version/context relationship when evidence is merged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum SourceAssertionRef {
    Purl(Uuid),
    Cpe(Uuid),
    Digest(Uuid),
    ProductIdentifier(Uuid),
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
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    EnumIter,
    DeriveActiveEnum,
    Serialize,
    Deserialize,
    ToSchema,
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
