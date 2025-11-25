use sea_orm::entity::prelude::*;

/// Checksums for the SBOM node (mainly files or packages)
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_node_checksum")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,

    #[sea_orm(primary_key)]
    pub node_id: String,

    #[sea_orm(primary_key)]
    pub r#type: String,

    pub value: String,
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
    #[sea_orm(
        belongs_to = "Entity",
        from = "(Column::Value, Column::Type)",
        to = "(Column::Value, Column::Type)"
    )]
    SelfRef,
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

impl ActiveModelBehavior for ActiveModel {}
