//! Published verdict counts of an SBOM, written together with its verdicts. A verdict counts once
//! per member of the class of its node.
use super::correlation_verdict::VerdictStatus;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "correlation_verdict_count")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub sbom_id: Uuid,
    pub affected: i64,
    pub fixed: i64,
    pub not_affected: i64,
    pub under_investigation: i64,
    pub none: i64,
    pub remediations: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
}

impl ActiveModelBehavior for ActiveModel {}

impl Column {
    /// The column counting verdicts of a status.
    pub fn for_status(status: VerdictStatus) -> Self {
        match status {
            VerdictStatus::Affected => Self::Affected,
            VerdictStatus::Fixed => Self::Fixed,
            VerdictStatus::NotAffected => Self::NotAffected,
            VerdictStatus::UnderInvestigation => Self::UnderInvestigation,
            VerdictStatus::None => Self::None,
        }
    }
}
