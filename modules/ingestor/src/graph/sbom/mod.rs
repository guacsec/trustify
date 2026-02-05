//! Support for SBOMs.

pub mod clearly_defined;
pub mod cyclonedx;
pub mod processor;
pub mod spdx;

mod common;
pub use common::*;

use super::error::Error;
use crate::{
    db::{LeftPackageId, QualifiedPackageTransitive},
    graph::{
        CreateOutcome, Graph, Outcome,
        cpe::CpeContext,
        product::{ProductContext, product_version::ProductVersionContext},
        purl::{creator::PurlCreator, qualified_package::QualifiedPackageContext},
    },
};
use cpe::uri::OwnedUri;
use entity::{product, product_version};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter,
    QuerySelect, RelationTrait, Select, Set, TransactionTrait, prelude::Uuid,
};
use sea_query::{Condition, Expr, Func, JoinType, Query, SimpleExpr, extension::postgres::PgExpr};
use std::{
    fmt::{Debug, Formatter},
    str::FromStr,
};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{cpe::Cpe, hashing::Digests, purl::Purl, sbom::SbomLocator};
use trustify_entity::{
    self as entity, labels::Labels, license, relationship::Relationship, sbom, sbom_node,
    sbom_package, sbom_package_cpe_ref, sbom_package_license, sbom_package_purl_ref,
    source_document,
};

#[derive(Clone, Default)]
pub struct SbomInformation {
    /// The id of the document in the SBOM graph
    pub node_id: String,
    /// The name of the document/node
    pub name: String,
    pub published: Option<OffsetDateTime>,
    pub authors: Vec<String>,
    pub suppliers: Vec<String>,
    /// The licenses of the data itself, if known.
    pub data_licenses: Vec<String>,
    /// general purpose properties from the SBOM
    pub properties: serde_json::Value,
}

impl From<()> for SbomInformation {
    fn from(_value: ()) -> Self {
        Self::default()
    }
}

type SelectEntity<E> = Select<E>;

impl Graph {
    pub async fn get_sbom_by_id<C: ConnectionTrait>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(sbom::Entity::find_by_id(id)
            .one(connection)
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    #[instrument(skip(connection))]
    pub async fn get_sbom_by_digest<C: ConnectionTrait>(
        &self,
        digest: &str,
        connection: &C,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(sbom::Entity::find()
            .join(JoinType::LeftJoin, sbom::Relation::SourceDocument.def())
            .filter(
                Condition::any()
                    .add(source_document::Column::Sha256.eq(digest.to_string()))
                    .add(source_document::Column::Sha384.eq(digest.to_string()))
                    .add(source_document::Column::Sha512.eq(digest.to_string())),
            )
            .one(connection)
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    #[instrument(skip(connection, info), err(level=tracing::Level::INFO))]
    pub async fn ingest_sbom<C>(
        &self,
        labels: impl Into<Labels> + Debug,
        digests: &Digests,
        document_id: Option<String>,
        info: impl Into<SbomInformation>,
        connection: &C,
    ) -> Result<Outcome<SbomContext>, Error>
    where
        C: ConnectionTrait + TransactionTrait,
    {
        let SbomInformation {
            node_id,
            name,
            published,
            authors,
            suppliers,
            data_licenses,
            properties,
        } = info.into();

        let new_id = match self
            .create_doc(digests, connection, async |sha256| {
                self.get_sbom_by_digest(&sha256, connection).await
            })
            .await?
        {
            CreateOutcome::Exists(sbom) => return Ok(Outcome::Existed(sbom)),
            CreateOutcome::Created(new_id) => new_id,
        };

        let sbom_id = Uuid::now_v7();

        let model = sbom::ActiveModel {
            sbom_id: Set(sbom_id),
            node_id: Set(node_id.clone()),

            document_id: Set(document_id),

            published: Set(published),
            authors: Set(authors),
            suppliers: Set(suppliers),

            source_document_id: Set(new_id),
            labels: Set(labels.into().validate()?),
            data_licenses: Set(data_licenses),

            properties: Set(properties),
            revision: Set(Uuid::now_v7()),
        };

        let node_model = sbom_node::ActiveModel {
            sbom_id: Set(sbom_id),
            node_id: Set(node_id),
            name: Set(name),
        };

        let result = model.insert(connection).await?;
        node_model.insert(connection).await?;

        Ok(Outcome::Added(SbomContext::new(self, result)))
    }

    /// Fetch a single SBOM located via internal `id`, external `location` (URL),
    /// described pURL, described CPE, or sha256 hash.
    ///
    /// Fetching by pURL, CPE or location may result in a single result where multiple
    /// may exist in the fetch in actuality.
    ///
    /// If the requested SBOM does not exist in the fetch, it will not exist
    /// after this query either. This function is *non-mutating*.
    pub async fn locate_sbom<C: ConnectionTrait>(
        &self,
        sbom_locator: SbomLocator,
        connection: &C,
    ) -> Result<Option<SbomContext>, Error> {
        match sbom_locator {
            SbomLocator::Id(id) => self.locate_sbom_by_id(id, connection).await,
            SbomLocator::Sha256(sha256) => self.locate_sbom_by_sha256(&sha256, connection).await,
            SbomLocator::Purl(purl) => self.locate_sbom_by_purl(&purl, connection).await,
            SbomLocator::Cpe(cpe) => self.locate_sbom_by_cpe22(&cpe, connection).await,
        }
    }

    pub async fn locate_sboms<C: ConnectionTrait>(
        &self,
        sbom_locator: SbomLocator,
        connection: &C,
    ) -> Result<Vec<SbomContext>, Error> {
        match sbom_locator {
            SbomLocator::Id(id) => {
                if let Some(sbom) = self.locate_sbom_by_id(id, connection).await? {
                    Ok(vec![sbom])
                } else {
                    Ok(vec![])
                }
            }
            SbomLocator::Sha256(sha256) => self.locate_sboms_by_sha256(&sha256, connection).await,
            SbomLocator::Purl(purl) => self.locate_sboms_by_purl(&purl, connection).await,
            SbomLocator::Cpe(cpe) => self.locate_sboms_by_cpe22(cpe, connection).await,
        }
    }

    async fn locate_one_sbom<C: ConnectionTrait>(
        &self,
        query: SelectEntity<sbom::Entity>,
        connection: &C,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(query
            .one(connection)
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    pub async fn locate_many_sboms<C: ConnectionTrait>(
        &self,
        query: SelectEntity<sbom::Entity>,
        connection: &C,
    ) -> Result<Vec<SbomContext>, Error> {
        Ok(query
            .all(connection)
            .await?
            .into_iter()
            .map(|sbom| SbomContext::new(self, sbom))
            .collect())
    }

    pub async fn locate_sbom_by_id<C: ConnectionTrait>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<Option<SbomContext>, Error> {
        let _query = sbom::Entity::find_by_id(id);
        Ok(sbom::Entity::find_by_id(id)
            .one(connection)
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    pub async fn locate_sboms_by_labels<C: ConnectionTrait>(
        &self,
        labels: Labels,
        connection: &C,
    ) -> Result<Vec<SbomContext>, Error> {
        self.locate_many_sboms(
            sbom::Entity::find().filter(Expr::col(sbom::Column::Labels).contains(labels)),
            connection,
        )
        .await
    }

    async fn locate_sbom_by_sha256<C: ConnectionTrait>(
        &self,
        sha256: &str,
        connection: &C,
    ) -> Result<Option<SbomContext>, Error> {
        self.locate_one_sbom(
            sbom::Entity::find()
                .join(JoinType::Join, sbom::Relation::SourceDocument.def())
                .filter(source_document::Column::Sha256.eq(sha256.to_string())),
            connection,
        )
        .await
    }

    async fn locate_sboms_by_sha256<C: ConnectionTrait>(
        &self,
        sha256: &str,
        connection: &C,
    ) -> Result<Vec<SbomContext>, Error> {
        self.locate_many_sboms(
            sbom::Entity::find()
                .join(JoinType::Join, sbom::Relation::SourceDocument.def())
                .filter(source_document::Column::Sha256.eq(sha256.to_string())),
            connection,
        )
        .await
    }

    fn query_by_purl(package: QualifiedPackageContext) -> Select<sbom::Entity> {
        sbom::Entity::find()
            .join_rev(JoinType::Join, sbom_package::Relation::Sbom.def())
            .join_rev(
                JoinType::Join,
                sbom_package_purl_ref::Relation::Package.def(),
            )
            .filter(sbom_package_purl_ref::Column::QualifiedPurlId.eq(package.qualified_package.id))
    }

    fn query_by_cpe(cpe: CpeContext) -> Select<sbom::Entity> {
        sbom::Entity::find()
            .join_rev(JoinType::Join, sbom_package::Relation::Sbom.def())
            .join_rev(
                JoinType::Join,
                sbom_package_cpe_ref::Relation::Package.def(),
            )
            .filter(sbom_package_cpe_ref::Column::CpeId.eq(cpe.cpe.id))
    }

    async fn locate_sbom_by_purl<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        connection: &C,
    ) -> Result<Option<SbomContext>, Error> {
        let package = self.get_qualified_package(purl, connection).await?;

        if let Some(package) = package {
            self.locate_one_sbom(Self::query_by_purl(package), connection)
                .await
        } else {
            Ok(None)
        }
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    async fn locate_sboms_by_purl<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        connection: &C,
    ) -> Result<Vec<SbomContext>, Error> {
        let package = self.get_qualified_package(purl, connection).await?;

        if let Some(package) = package {
            self.locate_many_sboms(Self::query_by_purl(package), connection)
                .await
        } else {
            Ok(vec![])
        }
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    async fn locate_sbom_by_cpe22<C: ConnectionTrait>(
        &self,
        cpe: &Cpe,
        connection: &C,
    ) -> Result<Option<SbomContext>, Error> {
        if let Some(cpe) = self.get_cpe(cpe.clone(), connection).await? {
            self.locate_one_sbom(Self::query_by_cpe(cpe), connection)
                .await
        } else {
            Ok(None)
        }
    }

    #[instrument(skip(self, connection), err)]
    async fn locate_sboms_by_cpe22<C: ConnectionTrait>(
        &self,
        cpe: impl Into<Cpe> + Debug,
        connection: &C,
    ) -> Result<Vec<SbomContext>, Error> {
        if let Some(cpe) = self.get_cpe(cpe, connection).await? {
            self.locate_many_sboms(Self::query_by_cpe(cpe), connection)
                .await
        } else {
            Ok(vec![])
        }
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RelationshipReference {
    Root,
    Purl(Purl),
    Cpe(Cpe),
}

impl From<()> for RelationshipReference {
    fn from(_: ()) -> Self {
        Self::Root
    }
}

impl From<Purl> for RelationshipReference {
    fn from(value: Purl) -> Self {
        Self::Purl(value)
    }
}

impl From<Cpe> for RelationshipReference {
    fn from(value: Cpe) -> Self {
        Self::Cpe(value)
    }
}

impl FromStr for RelationshipReference {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(purl) = Purl::from_str(s) {
            return Ok(Self::Purl(purl));
        }

        if let Ok(cpe) = OwnedUri::from_str(s) {
            return Ok(Self::Cpe(cpe.into()));
        }

        Err(())
    }
}

#[derive(Clone)]
pub struct SbomContext {
    pub graph: Graph,
    pub sbom: sbom::Model,
}

impl PartialEq for SbomContext {
    fn eq(&self, other: &Self) -> bool {
        self.sbom.eq(&other.sbom)
    }
}

impl Debug for SbomContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.sbom.fmt(f)
    }
}

impl SbomContext {
    pub fn new(graph: &Graph, sbom: sbom::Model) -> Self {
        Self {
            graph: graph.clone(),
            sbom,
        }
    }

    pub async fn ingest_purl_license_assertion<C: ConnectionTrait>(
        &self,
        license: &str,
        connection: &C,
    ) -> Result<(), Error> {
        let license_info = LicenseInfo {
            license: license.to_string(),
        };

        let (spdx_licenses, spdx_exceptions) = license_info.spdx_info();

        let license = license::Entity::find_by_id(license_info.uuid())
            .one(connection)
            .await?;

        let license = if let Some(license) = license {
            license
        } else {
            license::ActiveModel {
                id: Set(license_info.uuid()),
                text: Set(license_info.license.clone()),
                spdx_licenses: if spdx_licenses.is_empty() {
                    Set(None)
                } else {
                    Set(Some(spdx_licenses))
                },
                spdx_license_exceptions: if spdx_exceptions.is_empty() {
                    Set(None)
                } else {
                    Set(Some(spdx_exceptions))
                },
            }
            .insert(connection)
            .await?
        };

        sbom_package_license::ActiveModel {
            sbom_id: Set(self.sbom.sbom_id),
            node_id: Set(self.sbom.node_id.clone()),
            license_id: Set(license.id),
            license_type: Set(sbom_package_license::LicenseCategory::Declared),
        }
        .insert(connection)
        .await?;

        Ok(())
    }

    /// Within the context of *this* SBOM, ingest a relationship between
    /// two packages.
    ///
    /// The packages will be created if they don't yet exist.
    ///
    /// **NOTE:** This is a convenience function, creating relationships for tests. It is terribly slow.
    #[instrument(skip(connection, er), err)]
    pub async fn ingest_package_relates_to_package<
        C: ConnectionTrait,
        ER: ExternalReferenceProcessor,
    >(
        &self,
        left: impl Into<RelationshipReference> + Debug,
        relationship: Relationship,
        right: impl Into<RelationshipReference> + Debug,
        er: ER,
        connection: &C,
    ) -> Result<(), Error> {
        let left = left.into();
        let right = right.into();

        // ensure the PURLs and CPEs exist first

        let mut creator = PurlCreator::new();
        let (left_node_id, left_purls, left_cpes) = match left {
            RelationshipReference::Root => (None, vec![], vec![]),
            RelationshipReference::Purl(purl) => {
                creator.add(purl.clone());
                (Some(purl.to_string()), vec![purl], vec![])
            }
            RelationshipReference::Cpe(cpe) => {
                let cpe_ctx = self.graph.ingest_cpe22(cpe.clone(), connection).await?;
                (Some(cpe.to_string()), vec![], vec![cpe_ctx.cpe.id])
            }
        };
        let (right_node_id, right_purls, right_cpes) = match right {
            RelationshipReference::Root => (None, vec![], vec![]),
            RelationshipReference::Purl(purl) => {
                creator.add(purl.clone());
                (Some(purl.to_string()), vec![purl], vec![])
            }
            RelationshipReference::Cpe(cpe) => {
                let cpe_ctx = self.graph.ingest_cpe22(cpe.clone(), connection).await?;
                (Some(cpe.to_string()), vec![], vec![cpe_ctx.cpe.id])
            }
        };

        creator.create(connection).await?;

        // create the nodes

        if let Some(left_node_id) = left_node_id.clone() {
            self.ingest_package(
                left_node_id.clone(),
                left_node_id.clone(),
                None,
                left_purls,
                left_cpes,
                connection,
            )
            .await?;
        }

        if let Some(right_node_id) = right_node_id.clone() {
            self.ingest_package(
                right_node_id.clone(),
                right_node_id.clone(),
                None,
                right_purls,
                right_cpes,
                connection,
            )
            .await?;
        }

        // now create the relationship

        let left_node_id = left_node_id.unwrap_or_else(|| self.sbom.node_id.clone());
        let right_node_id = right_node_id.unwrap_or_else(|| self.sbom.node_id.clone());

        let mut relationships = RelationshipCreator::new(self.sbom.sbom_id, er);
        relationships.relate(left_node_id, relationship, right_node_id);
        relationships.create(connection).await?;

        Ok(())
    }

    #[instrument(skip(self, connection, er), err)]
    pub async fn ingest_describes_package<C: ConnectionTrait, ER: ExternalReferenceProcessor>(
        &self,
        package: Purl,
        er: ER,
        connection: &C,
    ) -> anyhow::Result<()> {
        self.ingest_package_relates_to_package(
            RelationshipReference::Purl(package),
            Relationship::Describes,
            RelationshipReference::Root,
            er,
            connection,
        )
        .await?;
        Ok(())
    }

    #[instrument(skip(self, connection, er), err)]
    pub async fn ingest_describes_cpe22<C: ConnectionTrait, ER: ExternalReferenceProcessor>(
        &self,
        cpe: Cpe,
        er: ER,
        connection: &C,
    ) -> anyhow::Result<()> {
        self.ingest_package_relates_to_package(
            RelationshipReference::Cpe(cpe),
            Relationship::Describes,
            RelationshipReference::Root,
            er,
            connection,
        )
        .await?;
        Ok(())
    }

    /// Ingest a single package for this SBOM.
    ///
    /// **NOTE:** This function ingests a single package, and is terribly slow.
    /// Use the [`PackageCreator`] for creating more than one.
    #[instrument(skip(self, connection), err)]
    async fn ingest_package<C: ConnectionTrait>(
        &self,
        node_id: String,
        name: String,
        version: Option<String>,
        purls: Vec<Purl>,
        cpes: Vec<Uuid>,
        connection: &C,
    ) -> Result<(), Error> {
        let mut creator = PackageCreator::new(self.sbom.sbom_id);

        let refs: Vec<PackageReference> = purls
            .into_iter()
            .map(PackageReference::Purl)
            .chain(cpes.into_iter().map(PackageReference::Cpe))
            .collect();
        creator.add(
            NodeInfoParam {
                node_id,
                name,
                group: None,
                version,
                package_license_info: vec![],
            },
            refs.iter(),
            Checksum::NONE,
        );

        creator.create(connection).await?;

        // done

        Ok(())
    }

    #[instrument(skip(self, connection), err)]
    pub async fn related_packages_transitively<C: ConnectionTrait>(
        &self,
        relationships: &[Relationship],
        pkg: &Purl,
        connection: &C,
    ) -> Result<Vec<QualifiedPackageContext<'_>>, Error> {
        let pkg = self.graph.get_qualified_package(pkg, connection).await?;

        if let Some(pkg) = pkg {
            let rels: SimpleExpr = relationships
                .iter()
                .map(|e| (*e) as i32)
                .collect::<Vec<_>>()
                .into();

            let sbom_id: SimpleExpr = self.sbom.sbom_id.into();
            let qualified_package_id: SimpleExpr = pkg.qualified_package.id.into();

            Ok(self
                .graph
                .get_qualified_packages_by_query(
                    Query::select()
                        .column(LeftPackageId)
                        .from_function(
                            Func::cust(QualifiedPackageTransitive).args([
                                sbom_id,
                                qualified_package_id,
                                rels,
                            ]),
                            QualifiedPackageTransitive,
                        )
                        .to_owned(),
                    connection,
                )
                .await?)
        } else {
            Ok(vec![])
        }
    }

    pub async fn link_to_product<'a, C: ConnectionTrait>(
        &self,
        product_version: ProductVersionContext<'a>,
        connection: &C,
    ) -> Result<ProductVersionContext<'a>, Error> {
        let mut entity = product_version::ActiveModel::from(product_version.product_version);
        entity.sbom_id = Set(Some(self.sbom.sbom_id));
        let model = entity.update(connection).await?;
        Ok(ProductVersionContext::new(&product_version.product, model))
    }

    pub async fn get_product<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<Option<ProductVersionContext<'_>>, Error> {
        if let Some(vers) = product_version::Entity::find()
            .filter(product_version::Column::SbomId.eq(self.sbom.sbom_id))
            .one(connection)
            .await?
        {
            if let Some(prod) = vers.find_related(product::Entity).one(connection).await? {
                Ok(Some(ProductVersionContext::new(
                    &ProductContext::new(&self.graph, prod),
                    vers,
                )))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}
