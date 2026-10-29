//! Read-only view combining verdict completion with upstream extraction freshness.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "correlation_verdict_freshness")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub sbom_id: Uuid,
    pub generation: Option<Uuid>,
    pub completed_at: Option<TimeDateTimeWithTimeZone>,
    pub required_revision: i64,
    pub completed_revision: Option<i64>,
    pub status: FreshnessStatus,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

/// Whether a completed snapshot exists and is current.
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum FreshnessStatus {
    #[sea_orm(string_value = "current")]
    Current,
    #[sea_orm(string_value = "stale")]
    Stale,
    #[sea_orm(string_value = "unknown")]
    Unknown,
}
