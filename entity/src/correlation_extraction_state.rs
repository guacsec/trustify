use sea_orm::entity::prelude::*;

/// Extraction completion metadata for an SBOM.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "correlation_extraction_state")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub sbom_id: Uuid,
    pub completed_revision: i64,
    pub completed_at: Option<TimeDateTimeWithTimeZone>,
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
