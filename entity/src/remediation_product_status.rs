use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "remediation_product_status")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub remediation_id: Uuid,
    #[sea_orm(primary_key)]
    pub product_status_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(belongs_to = "super::remediation::Entity",
        from = "Column::RemediationId"
        to = "super::remediation::Column::Id"
    )]
    Remediation,

    #[sea_orm(belongs_to = "super::product_status::Entity",
        from = "Column::ProductStatusId"
        to = "super::product_status::Column::Id"
    )]
    ProductStatus,
}

impl Related<super::remediation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Remediation.def()
    }
}

impl Related<super::product_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProductStatus.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
