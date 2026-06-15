use deepsize::DeepSizeOf;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_external_node")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,
    #[sea_orm(primary_key)]
    pub node_id: String,
    pub external_doc_ref: String,
    pub external_node_ref: String,
    pub external_type: ExternalType,
    pub target_sbom_id: Option<Uuid>,
    pub discriminator_type: Option<DiscriminatorType>,
    pub discriminator_value: Option<String>,
}

/// Type of the SBOM document discriminator, when using external references.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    EnumIter,
    DeriveActiveEnum,
    serde::Serialize,
    serde::Deserialize,
    DeepSizeOf,
)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
#[serde(rename_all = "snake_case")]
pub enum DiscriminatorType {
    /// By using an SHA-256 digest
    #[sea_orm(num_value = 0)]
    Sha256,
    /// By using an SHA-384 digest
    #[sea_orm(num_value = 1)]
    Sha384,
    /// By using an SHA-512 digest
    #[sea_orm(num_value = 2)]
    Sha512,
    /// By using an CycloneDX version
    #[sea_orm(num_value = 3)]
    CycloneDxVersion,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    EnumIter,
    DeriveActiveEnum,
    serde::Serialize,
    serde::Deserialize,
    DeepSizeOf,
)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
#[serde(rename_all = "snake_case")]
pub enum ExternalType {
    #[sea_orm(num_value = 0)]
    SPDX,
    #[sea_orm(num_value = 1)]
    CycloneDx,
    #[sea_orm(num_value = 2)]
    RedHatProductComponent,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
    #[sea_orm(
        belongs_to = "super::package_relates_to_package::Entity",
        from = "Column::SbomId",
        to = "super::package_relates_to_package::Column::SbomId",
        on_condition = r#"super::package_relates_to_package::Column::Relationship.eq(crate::relationship::Relationship::Describes)"#
    )]
    DescribesSbom,
    #[sea_orm(
        belongs_to = "super::sbom_describing_cpe::Entity",
        from = "Column::SbomId",
        to = "super::sbom_describing_cpe::Column::SbomId"
    )]
    DescribingCpe,
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl Related<super::package_relates_to_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::DescribesSbom.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
