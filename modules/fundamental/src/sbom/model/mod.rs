pub mod details;
pub mod raw_sql;

use super::service::SbomService;
use crate::{
    Error,
    common::{LicenseInfo, LicenseRefMapping},
    purl::model::summary::purl::PurlSummary,
    sbom::service::sbom::IntoPackage,
    source_document::model::SourceDocument,
};
use sea_orm::{ConnectionTrait, FromQueryResult, ModelTrait, PaginatorTrait, prelude::Uuid};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{info_span, instrument};
use tracing_futures::Instrument;
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::{
    labels::Labels, relationship::Relationship, sbom, sbom_node, sbom_package, source_document,
};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, Default)]
pub struct SbomHead {
    #[serde(with = "uuid::serde::urn")]
    #[schema(value_type=String)]
    pub id: Uuid,

    pub document_id: Option<String>,
    pub labels: Labels,
    pub data_licenses: Vec<String>,

    #[schema(required)]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,

    /// Authors of the SBOM
    pub authors: Vec<String>,
    /// Suppliers of the SBOMs content
    pub suppliers: Vec<String>,

    pub name: String,

    /// The number of packages this SBOM has
    pub number_of_packages: u64,
}

impl SbomHead {
    #[instrument(
        skip(sbom, db),
        fields(
            sbom=%sbom.sbom_id,
        )
        err(level=tracing::Level::INFO),
    )]
    pub async fn from_entity<C: ConnectionTrait>(
        sbom: &sbom::Model,
        sbom_node: &sbom_node::Model,
        db: &C,
    ) -> Result<Self, Error> {
        let number_of_packages = sbom
            .find_related(sbom_package::Entity)
            .count(db)
            .instrument(info_span!("counting packages"))
            .await?;
        Ok(Self {
            id: sbom.sbom_id,
            document_id: sbom.document_id.clone(),
            labels: sbom.labels.clone(),
            published: sbom.published,
            authors: sbom.authors.clone(),
            suppliers: sbom.suppliers.clone(),
            name: sbom_node.name.clone(),
            data_licenses: sbom.data_licenses.clone(),
            number_of_packages,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomSummary<P: IntoPackage = SbomPackage> {
    #[serde(flatten)]
    pub head: SbomHead,

    #[serde(flatten)]
    pub source_document: SourceDocument,

    pub described_by: Vec<P>,
}

impl<P: IntoPackage> SbomSummary<P> {
    #[instrument(skip(service, db), err(level=tracing::Level::INFO))]
    pub async fn from_entity<C: ConnectionTrait>(
        (sbom, node, source_document): (sbom::Model, sbom_node::Model, source_document::Model),
        service: &SbomService,
        db: &C,
    ) -> Result<Self, Error> {
        // TODO: consider improving the n-select issues here
        let described_by = service.describes_packages(sbom.sbom_id, (), db).await?;

        Ok(SbomSummary {
            head: SbomHead::from_entity(&sbom, &node, db).await?,
            source_document: SourceDocument::from_entity(&source_document),
            described_by,
        })
    }
}

#[derive(FromQueryResult)]
pub struct ModelCatcher {
    pub id: String,
    pub name: String,
    pub purls: Vec<serde_json::Value>,
    pub properties: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SbomModel {
    /// The internal ID of a model
    pub id: String,
    /// The name of the model in the SBOM
    pub name: String,
    /// The model's PURL
    pub purls: Vec<PurlSummary>,
    /// The properties associated with the model
    pub properties: serde_json::Map<String, serde_json::Value>,
    /// Number of SBOMs containing this model
    pub sbom_count: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, Default)]
pub struct SbomPackage {
    /// The SBOM internal ID of a package
    pub id: String,
    /// The name of the package in the SBOM
    pub name: String,
    /// An optional group/namespace for an SBOM package
    pub group: Option<String>,
    /// An optional version for an SBOM package
    pub version: Option<String>,
    /// PURLs identifying the package
    pub purl: Vec<PurlSummary>,
    /// CPEs identifying the package
    pub cpe: Vec<String>,
    /// License info
    pub licenses: Vec<LicenseInfo>,
    /// LicenseRef mappings
    ///
    /// **Deprecated**: Licenses are now pre-expanded at ingestion time via `expanded_license` /
    /// `sbom_license_expanded` tables. This field is always empty and will be removed in a future
    /// release.
    #[deprecated(note = "Licenses are pre-expanded; this field is always empty")]
    pub licenses_ref_mapping: Vec<LicenseRefMapping>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, Default)]
pub struct SbomPackageSummary {
    /// The SBOM internal ID of a package
    pub id: String,
    /// The name of the package in the SBOM
    pub name: String,
    /// An optional group/namespace for an SBOM package
    pub group: Option<String>,
    /// An optional version for an SBOM package
    pub version: Option<String>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SbomPackageReference<'a> {
    Internal(&'a str),
    External(SbomExternalPackageReference<'a>),
}

impl<'a> From<SbomExternalPackageReference<'a>> for SbomPackageReference<'a> {
    fn from(value: SbomExternalPackageReference<'a>) -> Self {
        Self::External(value)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SbomExternalPackageReference<'a> {
    Purl(&'a Purl),
    Cpe(&'a Cpe),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum SbomNodeReference<'a> {
    /// Reference all packages of the SBOM.
    All,
    /// Reference a package inside an SBOM, by its node id.
    // TODO: replace with `SbomPackageReference`
    Package(&'a str),
}

impl<'a> From<&'a str> for SbomNodeReference<'a> {
    fn from(value: &'a str) -> Self {
        Self::Package(value)
    }
}

impl From<()> for SbomNodeReference<'_> {
    fn from(_value: ()) -> Self {
        Self::All
    }
}

impl<'a> From<&'a SbomPackage> for SbomNodeReference<'a> {
    fn from(value: &'a SbomPackage) -> Self {
        Self::Package(&value.id)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SbomPackageRelation<P: IntoPackage> {
    pub relationship: Relationship,
    pub package: P,
}

#[derive(Clone, Eq, PartialEq, Default, Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Which {
    /// Originating side
    #[default]
    Left,
    /// Target side
    Right,
}
