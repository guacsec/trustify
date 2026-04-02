use sea_orm::entity::prelude::*;

/// An external PURL reference of an SBOM package. Technically, this
/// should be called sbom_NODE_purl_ref because it relates things
/// other than packages to purls, e.g. AI models
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_package_purl_ref")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,

    #[sea_orm(primary_key)]
    pub node_id: String,

    #[sea_orm(primary_key)]
    pub qualified_purl_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
    #[sea_orm(has_many = "super::sbom_package::Entity")]
    Package,
    #[sea_orm(has_one = "super::qualified_purl::Entity")]
    Purl,
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl Related<super::qualified_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Purl.def()
    }
}

impl Related<super::sbom_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
