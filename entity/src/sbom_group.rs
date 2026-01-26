use crate::labels::Labels;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_group")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,

    pub parent: Option<Uuid>,
    pub name: String,

    pub revision: Uuid,

    pub labels: Labels,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        super::sbom_group_assignment::Relation::Sbom.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::sbom_group_assignment::Relation::Group.def().rev())
    }
}
