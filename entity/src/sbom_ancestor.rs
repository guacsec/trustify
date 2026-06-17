use sea_orm::entity::prelude::*;

/// A materialized cross-SBOM link discovered through shared checksums
/// in `sbom_node_checksum`. Used to avoid expensive runtime ancestor
/// resolution in the analysis "latest" endpoints.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_ancestor")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,

    #[sea_orm(primary_key)]
    pub ancestor_sbom_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::AncestorSbomId",
        to = "super::sbom::Column::SbomId"
    )]
    AncestorSbom,
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
