use crate::{
    Error,
    advisory::model::AdvisoryHead,
    purl::model::{BasePurlHead, PurlHead, VersionedPurlHead},
    vulnerability::model::VulnerabilityHead,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, LoaderTrait, ModelTrait, QueryFilter, QuerySelect,
    RelationTrait,
};
use sea_query::{Asterisk, Expr, Func, JoinType, SimpleExpr};
use serde::{Deserialize, Serialize};
use trustify_common::{db::VersionMatches, memo::Memo};
use trustify_entity::{
    advisory, base_purl, organization, purl_status, qualified_purl, status, version_range,
    versioned_purl, vulnerability,
};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct VersionedPurlDetails {
    #[serde(flatten)]
    pub head: VersionedPurlHead,
    pub base: BasePurlHead,
    pub purls: Vec<PurlHead>,
    pub advisories: Vec<VersionedPurlAdvisory>,
}

impl VersionedPurlDetails {
    pub async fn from_entity<C: ConnectionTrait>(
        package: Option<base_purl::Model>,
        package_version: &versioned_purl::Model,
        tx: &C,
    ) -> Result<Self, Error> {
        let package = if let Some(package) = package {
            package
        } else {
            package_version
                .find_related(base_purl::Entity)
                .one(tx)
                .await?
                .ok_or(Error::Data("underlying package missing".to_string()))?
        };

        let qualified_packages = package_version
            .find_related(qualified_purl::Entity)
            .all(tx)
            .await?;

        let qualified_packages =
            PurlHead::from_entities(&package, package_version, &qualified_packages);

        let statuses = purl_status::Entity::find()
            .columns([
                version_range::Column::Id,
                version_range::Column::LowVersion,
                version_range::Column::LowInclusive,
                version_range::Column::HighVersion,
                version_range::Column::HighInclusive,
            ])
            .left_join(base_purl::Entity)
            .join(
                JoinType::LeftJoin,
                base_purl::Relation::VersionedPurls.def(),
            )
            .left_join(version_range::Entity)
            .filter(purl_status::Column::BasePurlId.eq(package.id))
            .filter(SimpleExpr::FunctionCall(
                Func::cust(VersionMatches)
                    .arg(Expr::col(versioned_purl::Column::Version))
                    .arg(Expr::col((version_range::Entity, Asterisk))),
            ))
            .all(tx)
            .await?;

        Ok(Self {
            head: VersionedPurlHead::from_entity(&package, package_version),
            base: BasePurlHead::from_entity(&package),
            purls: qualified_packages,
            advisories: VersionedPurlAdvisory::from_entities(statuses, tx).await?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct VersionedPurlAdvisory {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub status: Vec<VersionedPurlStatus>,
}

impl VersionedPurlAdvisory {
    pub async fn from_entities<C: ConnectionTrait>(
        statuses: Vec<purl_status::Model>,
        tx: &C,
    ) -> Result<Vec<Self>, Error> {
        let vulns = statuses.load_one(vulnerability::Entity, tx).await?;

        let advisories = statuses.load_one(advisory::Entity, tx).await?;

        let mut results: Vec<Self> = Vec::new();

        for ((vuln, advisory), status) in vulns.iter().zip(advisories.iter()).zip(statuses.iter()) {
            if let (Some(vulnerability), Some(advisory)) = (vuln, advisory) {
                let qualified_package_status =
                    VersionedPurlStatus::from_entity(vulnerability, status, tx).await?;

                if let Some(entry) = results.iter_mut().find(|e| e.head.uuid == advisory.id) {
                    entry.status.push(qualified_package_status)
                } else {
                    let organization = advisory.find_related(organization::Entity).one(tx).await?;

                    results.push(Self {
                        head: AdvisoryHead::from_advisory(
                            advisory,
                            Memo::Provided(organization),
                            tx,
                        )
                        .await?,
                        status: vec![qualified_package_status],
                    })
                }
            }
        }

        Ok(results)
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct VersionedPurlStatus {
    pub vulnerability: VulnerabilityHead,
    pub status: String,
}

impl VersionedPurlStatus {
    pub async fn from_entity<C: ConnectionTrait>(
        vuln: &vulnerability::Model,
        package_status: &purl_status::Model,
        tx: &C,
    ) -> Result<Self, Error> {
        let status = status::Entity::find_by_id(package_status.status_id)
            .one(tx)
            .await?;

        let status = status.map(|e| e.slug).unwrap_or("unknown".to_string());

        Ok(Self {
            vulnerability: VulnerabilityHead::from_vulnerability_entity(
                vuln,
                Memo::NotProvided,
                tx,
            )
            .await?,
            status,
        })
    }
}
