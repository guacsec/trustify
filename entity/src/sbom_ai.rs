use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_ai")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,
    #[sea_orm(primary_key)]
    pub node_id: String,
    pub properties: serde_json::Value,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_one = "super::sbom_node::Entity")]
    Node,
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
    #[sea_orm(
        belongs_to = "super::sbom_package_purl_ref::Entity",
        from = "(Column::SbomId, Column::NodeId)",
        to = "(super::sbom_package_purl_ref::Column::SbomId, super::sbom_package_purl_ref::Column::NodeId)"
    )]
    Purl,
}

impl Related<super::sbom_node::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Node.def()
    }
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl Related<super::sbom_package_purl_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Purl.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
