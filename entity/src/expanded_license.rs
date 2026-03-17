use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "expanded_license")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub expanded_text: String,
    pub text_hash: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::sbom_license_expanded::Entity")]
    SbomLicenseExpanded,
}

impl Related<super::sbom_license_expanded::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SbomLicenseExpanded.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
