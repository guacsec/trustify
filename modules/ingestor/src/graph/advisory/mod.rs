//! Support for advisories.

use crate::{
    common::{Deprecation, DeprecationExt},
    graph::{
        CreateOutcome, Graph, Outcome,
        advisory::advisory_vulnerability::AdvisoryVulnerabilityContext, error::Error,
        organization::creator::OrganizationCreator,
    },
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel,
    ModelTrait, QueryFilter, QuerySelect, RelationTrait, TransactionTrait,
};
use sea_query::{Condition, JoinType, OnConflict};
use semver::Version;
use std::fmt::{Debug, Formatter};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{db::UpdateDeprecatedAdvisory, hashing::Digests};
use trustify_entity::{self as entity, advisory, labels::Labels, source_document};
use uuid::Uuid;

pub mod advisory_vulnerability;
pub mod product_status;
pub mod purl_status;
pub mod version;

#[derive(Clone, Default)]
pub struct AdvisoryInformation {
    pub id: String,
    pub title: Option<String>,
    pub issuer: Option<String>,
    pub published: Option<OffsetDateTime>,
    pub modified: Option<OffsetDateTime>,
    pub withdrawn: Option<OffsetDateTime>,
    pub version: Option<Version>,
}

pub struct AdvisoryVulnerabilityInformation {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub reserved_date: Option<OffsetDateTime>,
    pub discovery_date: Option<OffsetDateTime>,
    pub release_date: Option<OffsetDateTime>,
    pub cwes: Option<Vec<String>>,
}

impl AdvisoryInformation {
    pub fn has_data(&self) -> bool {
        self.title.is_some()
            || self.issuer.is_some()
            || self.published.is_some()
            || self.modified.is_some()
            || self.withdrawn.is_some()
            || self.version.is_some()
    }
}

impl From<()> for AdvisoryInformation {
    fn from(_value: ()) -> Self {
        Self::default()
    }
}

impl Graph {
    pub async fn get_advisory_by_id<C: ConnectionTrait>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<Option<AdvisoryContext<'_>>, Error> {
        Ok(advisory::Entity::find_by_id(id)
            .one(connection)
            .await?
            .map(|advisory| AdvisoryContext::new(self, advisory)))
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn get_advisory_by_digest<C: ConnectionTrait>(
        &self,
        digest: &str,
        connection: &C,
    ) -> Result<Option<AdvisoryContext<'_>>, Error> {
        Ok(advisory::Entity::find()
            .join(JoinType::Join, advisory::Relation::SourceDocument.def())
            .filter(
                Condition::any()
                    .add(source_document::Column::Sha256.eq(digest.to_string()))
                    .add(source_document::Column::Sha384.eq(digest.to_string()))
                    .add(source_document::Column::Sha512.eq(digest.to_string())),
            )
            .one(connection)
            .await?
            .map(|advisory| AdvisoryContext::new(self, advisory)))
    }

    pub async fn get_advisories<C: ConnectionTrait>(
        &self,
        deprecation: Deprecation,
        connection: &C,
    ) -> Result<Vec<AdvisoryContext<'_>>, Error> {
        Ok(advisory::Entity::find()
            .with_deprecation(deprecation)
            .all(connection)
            .await?
            .into_iter()
            .map(|advisory| AdvisoryContext::new(self, advisory))
            .collect())
    }

    #[instrument(skip(self, labels, information, connection), err(level=tracing::Level::INFO))]
    pub async fn ingest_advisory<C>(
        &self,
        identifier: impl Into<String> + Debug,
        labels: impl Into<Labels>,
        digests: &Digests,
        information: impl Into<AdvisoryInformation>,
        connection: &C,
    ) -> Result<Outcome<AdvisoryContext<'_>>, Error>
    where
        C: ConnectionTrait + TransactionTrait,
    {
        let identifier = identifier.into();
        let labels = labels.into();

        let AdvisoryInformation {
            id,
            title,
            issuer,
            published,
            modified,
            withdrawn,
            version,
        } = information.into();

        let new_id = match self
            .create_doc(digests, connection, async |sha256| {
                self.get_advisory_by_digest(&sha256, connection).await
            })
            .await?
        {
            CreateOutcome::Exists(advisory) => return Ok(Outcome::Existed(advisory)),
            CreateOutcome::Created(new_id) => new_id,
        };

        // Batch create organization using OrganizationCreator to avoid race conditions
        let organization = if let Some(issuer) = issuer.clone() {
            let mut org_creator = OrganizationCreator::new();
            org_creator.add(&issuer, None, None);
            org_creator.create(connection).await?;

            // Query back the organization
            self.get_organization_by_name(&issuer, connection).await?
        } else {
            None
        };

        // insert

        let model = advisory::ActiveModel {
            id: Default::default(),
            identifier: Set(identifier),
            // we create it as not deprecated (false), as we update all documents in the next step.
            deprecated: Set(false),
            version: Set(version.map(|version| version.to_string())),
            document_id: Set(id),
            issuer_id: Set(organization.map(|org| org.organization.id)),
            title: Set(title),
            published: Set(published),
            modified: Set(modified),
            withdrawn: Set(withdrawn),
            labels: Set(labels.validate()?),
            source_document_id: Set(new_id),
        };

        let result = model.insert(connection).await?;

        // update deprecation marker

        UpdateDeprecatedAdvisory::execute(connection, &result.identifier).await?;

        // done

        Ok(Outcome::Added(AdvisoryContext::new(self, result)))
    }
}

#[derive(Clone)]
pub struct AdvisoryContext<'g> {
    pub graph: &'g Graph,
    pub advisory: entity::advisory::Model,
}

impl PartialEq for AdvisoryContext<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.advisory.eq(&other.advisory)
    }
}

impl Debug for AdvisoryContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.advisory.fmt(f)
    }
}

impl<'g> AdvisoryContext<'g> {
    pub fn new(graph: &'g Graph, advisory: advisory::Model) -> Self {
        Self { graph, advisory }
    }

    pub async fn set_published_at<C: ConnectionTrait>(
        &self,
        published_at: OffsetDateTime,
        connection: &C,
    ) -> Result<(), Error> {
        let mut entity = self.advisory.clone().into_active_model();
        entity.published = Set(Some(published_at));
        entity.save(connection).await?;
        Ok(())
    }

    pub fn published_at(&self) -> Option<OffsetDateTime> {
        self.advisory.published
    }

    pub async fn set_modified_at<C: ConnectionTrait>(
        &self,
        modified_at: OffsetDateTime,
        connection: &C,
    ) -> Result<(), Error> {
        let mut entity = self.advisory.clone().into_active_model();
        entity.modified = Set(Some(modified_at));
        entity.save(connection).await?;
        Ok(())
    }

    pub fn modified_at(&self) -> Option<OffsetDateTime> {
        self.advisory.modified
    }

    pub async fn set_withdrawn_at<C: ConnectionTrait>(
        &self,
        withdrawn_at: OffsetDateTime,
        connection: &C,
    ) -> Result<(), Error> {
        let mut entity = self.advisory.clone().into_active_model();
        entity.withdrawn = Set(Some(withdrawn_at));
        entity.save(connection).await?;
        Ok(())
    }

    pub fn withdrawn_at(&self) -> Option<OffsetDateTime> {
        self.advisory.withdrawn
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn get_vulnerability<C: ConnectionTrait>(
        &self,
        identifier: &str,
        connection: &C,
    ) -> Result<Option<AdvisoryVulnerabilityContext<'g>>, Error> {
        Ok(self
            .advisory
            .find_related(entity::advisory_vulnerability::Entity)
            .filter(entity::advisory_vulnerability::Column::VulnerabilityId.eq(identifier))
            .one(connection)
            .await?
            .map(|vuln| (self, vuln).into()))
    }

    #[instrument(skip(self, information, connection), err)]
    pub async fn link_to_vulnerability<C: ConnectionTrait>(
        &self,
        identifier: &str,
        information: Option<AdvisoryVulnerabilityInformation>,
        connection: &C,
    ) -> Result<AdvisoryVulnerabilityContext<'_>, Error> {
        let entity = entity::advisory_vulnerability::ActiveModel {
            advisory_id: Set(self.advisory.id),
            vulnerability_id: Set(identifier.to_string()),
            title: Set(information.as_ref().and_then(|info| info.title.clone())),
            summary: Set(information.as_ref().and_then(|info| info.summary.clone())),
            description: Set(information
                .as_ref()
                .and_then(|info| info.description.clone())),
            reserved_date: Set(information.as_ref().and_then(|info| info.reserved_date)),
            discovery_date: Set(information.as_ref().and_then(|info| info.discovery_date)),
            release_date: Set(information.as_ref().and_then(|info| info.release_date)),
            cwes: Set(information.as_ref().and_then(|info| info.cwes.clone())),
        };

        // do an upsert, updating field on a conflict
        let entity = entity::advisory_vulnerability::Entity::insert(entity)
            .on_conflict(
                OnConflict::columns([
                    entity::advisory_vulnerability::Column::AdvisoryId,
                    entity::advisory_vulnerability::Column::VulnerabilityId,
                ])
                .update_columns([
                    entity::advisory_vulnerability::Column::Title,
                    entity::advisory_vulnerability::Column::Summary,
                    entity::advisory_vulnerability::Column::Description,
                    entity::advisory_vulnerability::Column::DiscoveryDate,
                    entity::advisory_vulnerability::Column::ReleaseDate,
                    entity::advisory_vulnerability::Column::Cwes,
                ])
                .to_owned(),
            )
            .exec_with_returning(connection)
            .await?;

        Ok((self, entity).into())
    }

    pub async fn vulnerabilities<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<Vec<AdvisoryVulnerabilityContext<'_>>, Error> {
        Ok(self
            .advisory
            .find_related(entity::advisory_vulnerability::Entity)
            .all(connection)
            .await?
            .into_iter()
            .map(|e| (self, e).into())
            .collect())
    }
}

#[cfg(test)]
mod test {
    use crate::common::Deprecation;
    use crate::graph::Graph;
    use crate::graph::advisory::AdvisoryInformation;
    use test_context::test_context;
    use test_log::test;
    use time::OffsetDateTime;
    use time::macros::datetime;
    use trustify_common::hashing::Digests;
    use trustify_entity::labels::Labels;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_advisories(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let system = Graph::new(ctx.db.clone());

        let advisory1 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                Labels::from_one("source", "http://db.com/rhsa-ghsa-2"),
                &Digests::digest("RHSA-GHSA-1_1"),
                (),
                &ctx.db,
            )
            .await?;

        let advisory2 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                Labels::from_one("source", "http://db.com/rhsa-ghsa-2"),
                &Digests::digest("RHSA-GHSA-1_1"),
                (),
                &ctx.db,
            )
            .await?;

        let advisory3 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                Labels::from_one("source", "http://db.com/rhsa-ghsa-2"),
                &Digests::digest("RHSA-GHSA-1_2"),
                (),
                &ctx.db,
            )
            .await?;

        assert_eq!(advisory1.advisory.id, advisory2.advisory.id);
        assert_ne!(advisory1.advisory.id, advisory3.advisory.id);

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_advisory_cve(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let system = Graph::new(ctx.db.clone());

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                Labels::from_one("source", "http://db.com/rhsa-ghsa-2"),
                &Digests::digest("RHSA-GHSA-1"),
                (),
                &ctx.db,
            )
            .await?;

        advisory
            .link_to_vulnerability("CVE-123", None, &ctx.db)
            .await?;
        advisory
            .link_to_vulnerability("CVE-123", None, &ctx.db)
            .await?;
        advisory
            .link_to_vulnerability("CVE-456", None, &ctx.db)
            .await?;

        let vulns = advisory.vulnerabilities(&ctx.db).await?;

        assert_eq!(vulns.len(), 2);

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn deprecation(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        struct Info<'i>(&'i str, OffsetDateTime);

        impl From<Info<'_>> for AdvisoryInformation {
            fn from(value: Info) -> Self {
                AdvisoryInformation {
                    id: value.0.to_string(),
                    title: None,
                    issuer: None,
                    published: None,
                    modified: Some(value.1),
                    withdrawn: None,
                    version: None,
                }
            }
        }

        let system = Graph::new(ctx.db.clone());

        let a1 = system
            .ingest_advisory(
                "RHSA",
                (),
                &Digests::digest("RHSA-1"),
                Info("RHSA", datetime!(2024-01-02 00:00:00 UTC)),
                &ctx.db,
            )
            .await?
            .advisory
            .id;

        let a2 = system
            .ingest_advisory(
                "RHSA",
                (),
                &Digests::digest("RHSA-2"),
                Info("RHSA", datetime!(2024-01-03 00:00:00 UTC)),
                &ctx.db,
            )
            .await?
            .advisory
            .id;

        let a3 = system
            .ingest_advisory(
                "RHSA",
                (),
                &Digests::digest("RHSA-3"),
                Info("RHSA", datetime!(2024-01-01 00:00:00 UTC)),
                &ctx.db,
            )
            .await?
            .advisory
            .id;

        let mut advs = system
            .get_advisories(Deprecation::Consider, &ctx.db)
            .await?;
        advs.sort_unstable_by(|a, b| a.advisory.modified.cmp(&b.advisory.modified));
        let deps = advs
            .iter()
            .map(|adv| (adv.advisory.id, adv.advisory.deprecated))
            .collect::<Vec<_>>();

        // a3 must come first, it was ingested last, but its timestamp is the earliest one. Also,
        // it must be deprecated, despite being ingested last.
        // a1 is ingested first but deprecated when ingesting a2.
        // a2 is the "most recent" one, and most not be deprecated.

        assert_eq!(deps, vec![(a3, true), (a1, true), (a2, false)]);

        Ok(())
    }
}
