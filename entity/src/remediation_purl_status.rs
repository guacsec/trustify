use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "remediation_purl_status")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub remediation_id: Uuid,
    #[sea_orm(primary_key)]
    pub purl_status_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(belongs_to = "super::remediation::Entity",
        from = "Column::RemediationId"
        to = "super::remediation::Column::Id"
    )]
    Remediation,

    #[sea_orm(belongs_to = "super::purl_status::Entity",
        from = "Column::PurlStatusId"
        to = "super::purl_status::Column::Id"
    )]
    PurlStatus,
}

impl Related<super::remediation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Remediation.def()
    }
}

impl Related<super::purl_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PurlStatus.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
