use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_package_license")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,
    #[sea_orm(primary_key)]
    pub node_id: String,
    #[sea_orm(primary_key)]
    pub license_id: Uuid,
    #[sea_orm(primary_key)]
    pub license_type: LicenseCategory,
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
    #[sea_orm(has_one = "super::license::Entity")]
    License,
}

#[derive(
    Copy,
    Clone,
    Debug,
    strum::Display,
    Eq,
    PartialEq,
    EnumIter,
    DeriveActiveEnum,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
#[serde(rename_all = "lowercase")]
pub enum LicenseCategory {
    Declared = 0,
    Concluded = 1,
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl Related<super::sbom_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

impl Related<super::license::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::License.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl LicenseCategory {
    /// Returns the string representation of the license category
    ///
    /// # Examples
    /// ```
    /// use trustify_entity::sbom_package_license::LicenseCategory;
    ///
    /// assert_eq!(LicenseCategory::Declared.show(), "Declared");
    /// assert_eq!(LicenseCategory::Concluded.show(), "Concluded");
    /// ```
    pub fn show(&self) -> &'static str {
        match self {
            LicenseCategory::Declared => "Declared",
            LicenseCategory::Concluded => "Concluded",
        }
    }
}
