use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "remediation")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub category: RemediationCategory,
    pub details: Option<String>,
    pub url: Option<String>,
    pub data: serde_json::Value,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(belongs_to = "super::advisory::Entity",
        from = "Column::AdvisoryId"
        to = "super::advisory::Column::Id"
    )]
    Advisory,

    #[sea_orm(belongs_to = "super::vulnerability::Entity",
        from = "Column::VulnerabilityId"
        to = "super::vulnerability::Column::Id"
    )]
    Vulnerability,

    #[sea_orm(belongs_to = "super::advisory_vulnerability::Entity",
        from = "(Column::AdvisoryId, Column::VulnerabilityId)"
        to = "(super::advisory_vulnerability::Column::AdvisoryId, super::advisory_vulnerability::Column::VulnerabilityId)"
    )]
    AdvisoryVulnerability,

    #[sea_orm(has_many = "super::remediation_purl_status::Entity")]
    RemediationPurlStatus,

    #[sea_orm(has_many = "super::remediation_product_status::Entity")]
    RemediationProductStatus,
}

impl Related<super::advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl Related<super::vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vulnerability.def()
    }
}

impl Related<super::advisory_vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AdvisoryVulnerability.def()
    }
}

impl Related<super::remediation_purl_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RemediationPurlStatus.def()
    }
}

impl Related<super::remediation_product_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RemediationProductStatus.def()
    }
}

impl Related<super::purl_status::Entity> for Entity {
    fn to() -> RelationDef {
        super::remediation_purl_status::Relation::PurlStatus.def()
    }

    fn via() -> Option<RelationDef> {
        Some(
            super::remediation_purl_status::Relation::Remediation
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(
    Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, ToSchema,
)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "remediation_category"
)]
#[serde(rename_all = "snake_case")]
pub enum RemediationCategory {
    #[sea_orm(string_value = "vendor_fix")]
    VendorFix,
    #[sea_orm(string_value = "workaround")]
    Workaround,
    #[sea_orm(string_value = "mitigation")]
    Mitigation,
    #[sea_orm(string_value = "no_fix_planned")]
    NoFixPlanned,
    #[sea_orm(string_value = "none_available")]
    NoneAvailable,
    #[sea_orm(string_value = "will_not_fix")]
    WillNotFix,
}

impl RemediationCategory {
    /// Maps enum keys to stable strings for use in generating a stable UUID even if
    /// the enum names drift.
    pub fn remediation_category_key(self) -> &'static str {
        match self {
            RemediationCategory::VendorFix => "vendor_fix",
            RemediationCategory::Workaround => "workaround",
            RemediationCategory::Mitigation => "mitigation",
            RemediationCategory::NoFixPlanned => "no_fix_planned",
            RemediationCategory::NoneAvailable => "none_available",
            RemediationCategory::WillNotFix => "will_not_fix",
        }
    }
}

impl From<&csaf::vulnerability::RemediationCategory> for RemediationCategory {
    fn from(value: &csaf::vulnerability::RemediationCategory) -> Self {
        match value {
            csaf::vulnerability::RemediationCategory::Mitigation => RemediationCategory::Mitigation,
            csaf::vulnerability::RemediationCategory::NoFixPlanned => {
                RemediationCategory::NoFixPlanned
            }
            csaf::vulnerability::RemediationCategory::NoneAvailable => {
                RemediationCategory::NoneAvailable
            }
            csaf::vulnerability::RemediationCategory::VendorFix => RemediationCategory::VendorFix,
            csaf::vulnerability::RemediationCategory::Workaround => RemediationCategory::Workaround,
            // voteblake/csaf-rs doesn't support CSAF 2.1 which adds will_not_fix
            #[allow(unreachable_patterns)]
            handle => todo!(
                "Unexpected csaf::vulnerability::RemediationCategory found {:?}",
                handle
            ),
        }
    }
}
