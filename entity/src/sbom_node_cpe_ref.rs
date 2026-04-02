use sea_orm::entity::prelude::*;

/// An external CPE reference of an SBOM node
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_node_cpe_ref")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,

    #[sea_orm(primary_key)]
    pub node_id: String,

    #[sea_orm(primary_key)]
    pub cpe_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
    #[sea_orm(has_many = "super::sbom_node::Entity")]
    Node,
    #[sea_orm(has_one = "super::cpe::Entity")]
    Cpe,
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl Related<super::sbom_node::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Node.def()
    }
}

impl Related<super::cpe::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cpe.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
