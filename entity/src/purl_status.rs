use sea_orm::LinkDef;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "purl_status")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub status_id: Uuid,
    pub base_purl_id: Uuid,
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

    #[sea_orm(belongs_to = "super::base_purl::Entity",
        from = "Column::BasePurlId"
        to = "super::base_purl::Column::Id"
    )]
    BasePurl,

    #[sea_orm(has_many = "super::versioned_purl::Entity")]
    VersionedPurl,

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

pub struct VersionedPurlLink;

impl Linked for VersionedPurlLink {
    type FromEntity = Entity;
    type ToEntity = super::versioned_purl::Entity;

    fn link(&self) -> Vec<LinkDef> {
        vec![
            Relation::VersionRange.def(),
            super::version_range::Relation::VersionedPurls.def(),
        ]
    }
}

impl Related<super::version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionRange.def()
    }
}

impl Related<super::base_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::BasePurl.def()
    }
}

impl Related<super::versioned_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionedPurl.def()
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

impl Related<super::cpe::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ContextCpe.def()
    }
}

impl Related<super::remediation::Entity> for Entity {
    fn to() -> RelationDef {
        super::remediation_purl_status::Relation::Remediation.def()
    }

    fn via() -> Option<RelationDef> {
        Some(
            super::remediation_purl_status::Relation::PurlStatus
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}
