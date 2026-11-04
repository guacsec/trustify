//! The class of each node of an SBOM: nodes of one class have the same evidence and verdicts,
//! which are stored once, for the representative node of the class.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "correlation_node_class")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub sbom_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub node_id: String,
    /// The member of the class holding its evidence and verdicts, possibly the node itself.
    pub representative_node_id: String,
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
