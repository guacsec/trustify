use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cpe_status")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub status_id: Uuid,
    pub cpe_id: Uuid,
    pub version_range_id: Uuid,
    pub context_cpe_id: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(belongs_to = "super::version_range::Entity"
        from = "Column::VersionRangeId",
        to = "super::version_range::Column::Id"
    )]
    VersionRange,

    #[sea_orm(belongs_to = "super::cpe::Entity",
        from = "Column::CpeId"
        to = "super::cpe::Column::Id"
    )]
    Cpe,

    #[sea_orm(belongs_to = "super::vulnerability::Entity",
        from = "Column::VulnerabilityId"
        to = "super::vulnerability::Column::Id"
    )]
    Vulnerability,

    #[sea_orm(belongs_to = "super::advisory::Entity",
        from = "Column::AdvisoryId"
        to = "super::advisory::Column::Id"
    )]
    Advisory,

    #[sea_orm(belongs_to = "super::status::Entity",
        from = "Column::StatusId"
        to = "super::status::Column::Id"
    )]
    Status,

    #[sea_orm(belongs_to = "super::advisory_vulnerability::Entity",
        from = "(Column::AdvisoryId, Column::VulnerabilityId)"
        to = "(super::advisory_vulnerability::Column::AdvisoryId, super::advisory_vulnerability::Column::VulnerabilityId)"
    )]
    AdvisoryVulnerability,

    #[sea_orm(belongs_to = "super::cpe::Entity",
        from = "Column::ContextCpeId"
        to = "super::cpe::Column::Id"
    )]
    ContextCpe,
}

impl Related<super::version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionRange.def()
    }
}

impl Related<super::cpe::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cpe.def()
    }
}

impl Related<super::vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vulnerability.def()
    }
}

impl Related<super::advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl Related<super::status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Status.def()
    }
}

impl Related<super::advisory_vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AdvisoryVulnerability.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
