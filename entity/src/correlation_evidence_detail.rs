//! The view `correlation_evidence_detail`: [`super::correlation_evidence`] joined with its
//! matched value and confidence factors, which are stored once per distinct value. Read only.
use super::correlation_evidence::AssertionStatus;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "correlation_evidence_detail")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
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
    /// Contains at least one source assertion reference.
    #[sea_orm(column_type = "JsonBinary")]
    pub source_assertions: serde_json::Value,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
