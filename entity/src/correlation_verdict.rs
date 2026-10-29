//! Published default verdicts. Snapshot fields belong to the same computation.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "correlation_verdict")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub sbom_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub node_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub vulnerability_id: String,
    pub status: VerdictStatus,
    #[sea_orm(column_type = "JsonBinary")]
    pub snapshot: Json,
    pub remediation_count: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

/// Resolved status, independently of an advisory's assertion status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "verdict_status")]
pub enum VerdictStatus {
    #[sea_orm(string_value = "affected")]
    Affected,
    #[sea_orm(string_value = "fixed")]
    Fixed,
    #[sea_orm(string_value = "not_affected")]
    NotAffected,
    #[sea_orm(string_value = "under_investigation")]
    UnderInvestigation,
    #[sea_orm(string_value = "none")]
    None,
}
