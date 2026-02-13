use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_node")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,
    #[sea_orm(primary_key)]
    pub node_id: String,

    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom_package::Entity",
        from = "(Column::SbomId, Column::NodeId)",
        to = "(super::sbom_package::Column::SbomId, super::sbom_package::Column::NodeId)"
    )]
    Package,
    #[sea_orm(
        belongs_to = "super::sbom_package::Entity",
        from = "Column::SbomId",
        to = "super::sbom_package::Column::SbomId"
    )]
    PackageBySbomId,
    #[sea_orm(
        belongs_to = "super::sbom_file::Entity",
        from = "(Column::SbomId, Column::NodeId)",
        to = "(super::sbom_file::Column::SbomId, super::sbom_file::Column::NodeId)"
    )]
    File,
    #[sea_orm(
        belongs_to = "super::sbom_ai::Entity",
        from = "(Column::SbomId, Column::NodeId)",
        to = "(super::sbom_ai::Column::SbomId, super::sbom_ai::Column::NodeId)"
    )]
    AI,
    #[sea_orm(
        belongs_to = "super::sbom_crypto::Entity",
        from = "(Column::SbomId, Column::NodeId)",
        to = "(super::sbom_crypto::Column::SbomId, super::sbom_crypto::Column::NodeId)"
    )]
    Crypto,
    #[sea_orm(
        belongs_to = "super::sbom_node_checksum::Entity",
        from = "(Column::SbomId, Column::NodeId)",
        to = "(super::sbom_node_checksum::Column::SbomId, super::sbom_node_checksum::Column::NodeId)"
    )]
    Checksum,
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "(Column::NodeId, Column::SbomId)",
        to = "(super::sbom::Column::NodeId, super::sbom::Column::SbomId)"
    )]
    SbomNode,
    #[sea_orm(
        belongs_to = "super::package_relates_to_package::Entity",
        from = "Column::SbomId",
        to = "super::package_relates_to_package::Column::SbomId",
        on_condition = r#"super::package_relates_to_package::Column::Relationship.eq(crate::relationship::Relationship::Describes)"#
    )]
    DescribesSbom,
}

impl Related<super::sbom_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

impl Related<super::sbom_file::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::File.def()
    }
}

impl Related<super::sbom_ai::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AI.def()
    }
}

impl Related<super::sbom_crypto::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Crypto.def()
    }
}

impl Related<super::sbom_node_checksum::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Checksum.def()
    }
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl Related<super::package_relates_to_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::DescribesSbom.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
