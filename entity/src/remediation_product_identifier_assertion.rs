//! Product applicability of a remediation, through an existing source assertion.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "remediation_product_identifier_assertion")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub remediation_id: Uuid,
    #[sea_orm(primary_key)]
    pub assertion_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::remediation::Entity",
        from = "Column::RemediationId",
        to = "super::remediation::Column::Id",
        on_delete = "Cascade"
    )]
    Remediation,
    #[sea_orm(
        belongs_to = "super::advisory_vulnerability_product_identifier::Entity",
        from = "Column::AssertionId",
        to = "super::advisory_vulnerability_product_identifier::Column::Id",
        on_delete = "Cascade"
    )]
    Assertion,
}

impl Related<super::remediation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Remediation.def()
    }
}
impl Related<super::advisory_vulnerability_product_identifier::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Assertion.def()
    }
}
impl ActiveModelBehavior for ActiveModel {}
