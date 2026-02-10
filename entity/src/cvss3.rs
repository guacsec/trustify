use crate::{advisory, advisory_vulnerability, vulnerability};
use sea_orm::entity::prelude::*;
use std::fmt::{Display, Formatter};
use trustify_cvss::cvss3;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "cvss3")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub advisory_id: Uuid,

    #[sea_orm(primary_key)]
    pub vulnerability_id: String,

    #[sea_orm(primary_key)]
    pub minor_version: i32,

    pub av: AttackVector,
    pub ac: AttackComplexity,
    pub pr: PrivilegesRequired,
    pub ui: UserInteraction,
    pub s: Scope,
    pub c: Confidentiality,
    pub i: Integrity,
    pub a: Availability,

    pub score: f64,
    pub severity: Severity,
}

impl From<&Model> for cvss3::Cvss3Base {
    fn from(value: &Model) -> Self {
        Self {
            minor_version: value.minor_version as u8,
            av: value.av.into(),
            ac: value.ac.into(),
            pr: value.pr.into(),
            ui: value.ui.into(),
            s: value.s.into(),
            c: value.c.into(),
            i: value.i.into(),
            a: value.a.into(),
        }
    }
}

impl From<Model> for cvss3::Cvss3Base {
    fn from(value: Model) -> Self {
        Self::from(&value)
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
    belongs_to = "super::advisory::Entity",
    from = "super::cvss3::Column::AdvisoryId"
    to = "super::advisory::Column::Id")]
    Advisory,

    #[sea_orm(
    belongs_to = "super::vulnerability::Entity",
    from = "super::cvss3::Column::VulnerabilityId"
    to = "super::vulnerability::Column::Id")]
    Vulnerability,

    #[sea_orm(
        belongs_to = "super::advisory_vulnerability::Entity",
        from = "(super::cvss3::Column::AdvisoryId, super::cvss3::Column::VulnerabilityId)"
        to = "(super::advisory_vulnerability::Column::AdvisoryId, super::advisory_vulnerability::Column::VulnerabilityId)")]
    AdvisoryVulnerability,
}

impl Related<advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl Related<vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vulnerability.def()
    }
}

impl Related<advisory_vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AdvisoryVulnerability.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss3_av")]
pub enum AttackVector {
    #[sea_orm(string_value = "n")]
    Network,
    #[sea_orm(string_value = "a")]
    Adjacent,
    #[sea_orm(string_value = "l")]
    Local,
    #[sea_orm(string_value = "p")]
    Physical,
}

impl From<AttackVector> for cvss3::AttackVector {
    fn from(value: AttackVector) -> Self {
        match value {
            AttackVector::Network => Self::Network,
            AttackVector::Adjacent => Self::Adjacent,
            AttackVector::Local => Self::Local,
            AttackVector::Physical => Self::Physical,
        }
    }
}

impl From<cvss3::AttackVector> for AttackVector {
    fn from(value: cvss3::AttackVector) -> Self {
        match value {
            cvss3::AttackVector::Network => Self::Network,
            cvss3::AttackVector::Adjacent => Self::Adjacent,
            cvss3::AttackVector::Local => Self::Local,
            cvss3::AttackVector::Physical => Self::Physical,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss3_ac")]
pub enum AttackComplexity {
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<AttackComplexity> for cvss3::AttackComplexity {
    fn from(value: AttackComplexity) -> Self {
        match value {
            AttackComplexity::Low => Self::Low,
            AttackComplexity::High => Self::High,
        }
    }
}

impl From<cvss3::AttackComplexity> for AttackComplexity {
    fn from(value: cvss3::AttackComplexity) -> Self {
        match value {
            cvss3::AttackComplexity::Low => Self::Low,
            cvss3::AttackComplexity::High => Self::High,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss3_pr")]
pub enum PrivilegesRequired {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<PrivilegesRequired> for cvss3::PrivilegesRequired {
    fn from(value: PrivilegesRequired) -> Self {
        match value {
            PrivilegesRequired::None => Self::None,
            PrivilegesRequired::Low => Self::Low,
            PrivilegesRequired::High => Self::High,
        }
    }
}

impl From<cvss3::PrivilegesRequired> for PrivilegesRequired {
    fn from(value: cvss3::PrivilegesRequired) -> Self {
        match value {
            cvss3::PrivilegesRequired::None => Self::None,
            cvss3::PrivilegesRequired::Low => Self::Low,
            cvss3::PrivilegesRequired::High => Self::High,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss3_ui")]
pub enum UserInteraction {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "r")]
    Required,
}

impl From<UserInteraction> for cvss3::UserInteraction {
    fn from(value: UserInteraction) -> Self {
        match value {
            UserInteraction::None => Self::None,
            UserInteraction::Required => Self::Required,
        }
    }
}

impl From<cvss3::UserInteraction> for UserInteraction {
    fn from(value: cvss3::UserInteraction) -> Self {
        match value {
            cvss3::UserInteraction::None => Self::None,
            cvss3::UserInteraction::Required => Self::Required,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss3_s")]
pub enum Scope {
    #[sea_orm(string_value = "u")]
    Unchanged,
    #[sea_orm(string_value = "c")]
    Changed,
}

impl From<Scope> for cvss3::Scope {
    fn from(value: Scope) -> Self {
        match value {
            Scope::Unchanged => Self::Unchanged,
            Scope::Changed => Self::Changed,
        }
    }
}

impl From<cvss3::Scope> for Scope {
    fn from(value: cvss3::Scope) -> Self {
        match value {
            cvss3::Scope::Unchanged => Self::Unchanged,
            cvss3::Scope::Changed => Self::Changed,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss3_c")]
pub enum Confidentiality {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<Confidentiality> for cvss3::Confidentiality {
    fn from(value: Confidentiality) -> Self {
        match value {
            Confidentiality::None => Self::None,
            Confidentiality::Low => Self::Low,
            Confidentiality::High => Self::High,
        }
    }
}

impl From<cvss3::Confidentiality> for Confidentiality {
    fn from(value: cvss3::Confidentiality) -> Self {
        match value {
            cvss3::Confidentiality::None => Self::None,
            cvss3::Confidentiality::Low => Self::Low,
            cvss3::Confidentiality::High => Self::High,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss3_i")]
pub enum Integrity {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<Integrity> for cvss3::Integrity {
    fn from(value: Integrity) -> Self {
        match value {
            Integrity::None => Self::None,
            Integrity::Low => Self::Low,
            Integrity::High => Self::High,
        }
    }
}

impl From<cvss3::Integrity> for Integrity {
    fn from(value: cvss3::Integrity) -> Self {
        match value {
            cvss3::Integrity::None => Self::None,
            cvss3::Integrity::Low => Self::Low,
            cvss3::Integrity::High => Self::High,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss3_a")]
pub enum Availability {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<Availability> for cvss3::Availability {
    fn from(value: Availability) -> Self {
        match value {
            Availability::None => Self::None,
            Availability::Low => Self::Low,
            Availability::High => Self::High,
        }
    }
}

impl From<cvss3::Availability> for Availability {
    fn from(value: cvss3::Availability) -> Self {
        match value {
            cvss3::Availability::None => Self::None,
            cvss3::Availability::Low => Self::Low,
            cvss3::Availability::High => Self::High,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss3_severity")]
pub enum Severity {
    #[sea_orm(string_value = "none")]
    None,
    #[sea_orm(string_value = "low")]
    Low,
    #[sea_orm(string_value = "medium")]
    Medium,
    #[sea_orm(string_value = "high")]
    High,
    #[sea_orm(string_value = "critical")]
    Critical,
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::None => {
                write!(f, "none")
            }
            Severity::Low => {
                write!(f, "low")
            }
            Severity::Medium => {
                write!(f, "medium")
            }
            Severity::High => {
                write!(f, "high")
            }
            Severity::Critical => {
                write!(f, "critical")
            }
        }
    }
}

impl From<cvss3::severity::Severity> for Severity {
    fn from(value: cvss3::severity::Severity) -> Self {
        match value {
            cvss3::severity::Severity::None => Self::None,
            cvss3::severity::Severity::Low => Self::Low,
            cvss3::severity::Severity::Medium => Self::Medium,
            cvss3::severity::Severity::High => Self::High,
            cvss3::severity::Severity::Critical => Self::Critical,
        }
    }
}

impl From<Severity> for cvss3::severity::Severity {
    fn from(value: Severity) -> Self {
        match value {
            Severity::None => Self::None,
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }
}
