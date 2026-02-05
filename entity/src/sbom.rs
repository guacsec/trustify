use crate::labels::Labels;
use sea_orm::{Condition, LinkDef, entity::prelude::*, sea_query::IntoCondition};
use time::OffsetDateTime;
use trustify_common::id::{Id, IdError, TryFilterForId};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,
    pub node_id: String,

    pub document_id: Option<String>,

    pub published: Option<OffsetDateTime>,
    pub authors: Vec<String>,
    pub suppliers: Vec<String>,
    pub data_licenses: Vec<String>,

    pub source_document_id: Uuid,

    pub revision: Uuid,

    pub labels: Labels,

    /// properties from the SBOM document
    pub properties: serde_json::Value,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::source_document::Entity"
        from = "Column::SourceDocumentId"
        to = "super::source_document::Column::Id")]
    SourceDocument,

    #[sea_orm(has_many = "super::sbom_package::Entity")]
    Packages,
    #[sea_orm(has_many = "super::sbom_file::Entity")]
    Files,
    #[sea_orm(has_one = "super::sbom_node::Entity")]
    Node,
    #[sea_orm(has_many = "super::package_relates_to_package::Entity")]
    PackageRelatesToPackages,
    #[sea_orm(has_one = "super::product_version::Entity")]
    ProductVersion,
    #[sea_orm(
        belongs_to = "super::sbom_node::Entity",
        from = "(Column::NodeId, Column::SbomId)",
        to = "(super::sbom_node::Column::NodeId, super::sbom_node::Column::SbomId)"
    )]
    SbomNode,
}

pub struct SbomPurlsLink;

impl Linked for SbomPurlsLink {
    type FromEntity = Entity;
    type ToEntity = super::qualified_purl::Entity;

    fn link(&self) -> Vec<LinkDef> {
        vec![
            Relation::Packages.def(),
            super::sbom_package::Relation::Purl.def(),
            super::sbom_package_purl_ref::Relation::Purl.def(),
        ]
    }
}

pub struct SbomVersionedPurlsLink;

impl Linked for SbomVersionedPurlsLink {
    type FromEntity = Entity;
    type ToEntity = super::base_purl::Entity;

    fn link(&self) -> Vec<LinkDef> {
        vec![
            Relation::Packages.def(),
            super::sbom_package::Relation::Purl.def(),
            super::sbom_package_purl_ref::Relation::Purl.def(),
            super::qualified_purl::Relation::VersionedPurl.def(),
        ]
    }
}

pub struct SbomNodeLink;

impl Linked for SbomNodeLink {
    type FromEntity = Entity;
    type ToEntity = super::sbom_node::Entity;

    fn link(&self) -> Vec<LinkDef> {
        vec![super::sbom_node::Relation::SbomNode.def().rev()]
    }
}

impl Related<super::source_document::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SourceDocument.def()
    }
}

impl Related<super::sbom_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Packages.def()
    }
}

impl Related<super::sbom_file::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Files.def()
    }
}

impl Related<super::sbom_node::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Node.def()
    }
}

impl Related<super::package_relates_to_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageRelatesToPackages.def()
    }
}

impl Related<super::product_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProductVersion.def()
    }
}

impl Related<super::sbom_group::Entity> for Entity {
    fn to() -> RelationDef {
        super::sbom_group_assignment::Relation::Group.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::sbom_group_assignment::Relation::Sbom.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl TryFilterForId for Entity {
    fn try_filter(id: Id) -> Result<Condition, IdError> {
        Ok(match id {
            Id::Uuid(uuid) => Column::SbomId.eq(uuid).into_condition(),
            Id::Sha256(hash) => super::source_document::Column::Sha256
                .eq(hash)
                .into_condition(),
            Id::Sha384(hash) => super::source_document::Column::Sha384
                .eq(hash)
                .into_condition(),
            Id::Sha512(hash) => super::source_document::Column::Sha512
                .eq(hash)
                .into_condition(),
            n => return Err(IdError::UnsupportedAlgorithm(n.prefix().to_string())),
        })
    }
}
