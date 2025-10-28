use super::SbomSummary;
use crate::{
    Error,
    advisory::model::AdvisoryHead,
    purl::model::{details::purl::StatusContext, summary::purl::PurlSummary},
    sbom::{
        model::{SbomPackage, raw_sql},
        service::{SbomService, sbom::QueryCatcher},
    },
    vulnerability::model::VulnerabilityHead,
};
use cpe::uri::OwnedUri;
use sea_orm::{
    ConnectionTrait, DbBackend, EntityTrait, FromQueryResult, JoinType, ModelTrait, QueryFilter,
    QuerySelect, RelationTrait, Statement,
};
use sea_query::{Asterisk, Expr, Func, PgFunc, SimpleExpr};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::instrument;
use trustify_common::{
    db::{VersionMatches, multi_model::SelectIntoMultiModel},
    memo::Memo,
};
use trustify_cvss::cvss3::{Cvss3Base, score::Score, severity::Severity};
use trustify_entity::{
    advisory, advisory_vulnerability, base_purl, cvss3, purl_status, qualified_purl, sbom,
    sbom_node, sbom_package, sbom_package_purl_ref, status, version_range, versioned_purl,
    vulnerability,
};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SbomDetails {
    #[serde(flatten)]
    pub summary: SbomSummary,

    pub advisories: Vec<SbomAdvisory>,
}

impl SbomDetails {
    /// turn an (sbom, sbom_node) row into an [`SbomDetails`], if possible
    #[instrument(skip(service, tx), err(level=tracing::Level::INFO))]
    pub async fn from_entity<C>(
        (sbom, node): (sbom::Model, Option<sbom_node::Model>),
        service: &SbomService,
        tx: &C,
        statuses: Vec<String>,
    ) -> Result<Option<SbomDetails>, Error>
    where
        C: ConnectionTrait,
    {
        let summary = match SbomSummary::from_entity((sbom.clone(), node), service, tx).await? {
            Some(summary) => summary,
            None => return Ok(None),
        };

        let mut query = sbom
            .find_related(sbom_package::Entity)
            .join(JoinType::Join, sbom_package::Relation::Node.def())
            .join(JoinType::LeftJoin, sbom_package::Relation::Purl.def())
            .join(
                JoinType::LeftJoin,
                sbom_package_purl_ref::Relation::Purl.def(),
            )
            .join(
                JoinType::LeftJoin,
                qualified_purl::Relation::VersionedPurl.def(),
            )
            .join(JoinType::LeftJoin, versioned_purl::Relation::BasePurl.def())
            .join(JoinType::Join, base_purl::Relation::PurlStatus.def())
            .join(JoinType::Join, purl_status::Relation::Status.def());

        if !statuses.is_empty() {
            query = query
                .filter(Expr::col((status::Entity, status::Column::Slug)).is_in(statuses.clone()));
        }

        query = query.filter(Expr::cust_with_values(
            raw_sql::CONTEXT_CPE_FILTER_SQL,
            vec![sbom.sbom_id],
        ));

        // Collect all results from the first query using the transaction
        let mut relevant_advisory_info = query
            .join(
                JoinType::LeftJoin,
                purl_status::Relation::VersionRange.def(),
            )
            .filter(SimpleExpr::FunctionCall(
                Func::cust(VersionMatches)
                    .arg(Expr::col((
                        versioned_purl::Entity,
                        versioned_purl::Column::Version,
                    )))
                    .arg(Expr::col((version_range::Entity, Asterisk))),
            ))
            .join(JoinType::LeftJoin, purl_status::Relation::ContextCpe.def())
            .join(JoinType::Join, purl_status::Relation::Advisory.def())
            .join(JoinType::LeftJoin, advisory::Relation::Issuer.def())
            .join(
                JoinType::Join,
                purl_status::Relation::AdvisoryVulnerability.def(),
            )
            .join(
                JoinType::Join,
                advisory_vulnerability::Relation::Vulnerability.def(),
            )
            .select_only()
            .try_into_multi_model::<QueryCatcher>()?
            .all(tx)
            .await?;

        log::debug!("Result: {:?}", relevant_advisory_info.len());

        // Execute the raw SQL query and collect results
        let raw_results = tx
            .query_all(Statement::from_sql_and_values(
                DbBackend::Postgres,
                raw_sql::product_advisory_info_sql(),
                [sbom.sbom_id.into(), statuses.into()],
            ))
            .await?;

        // Convert raw SQL results to QueryCatcher objects
        for row in raw_results {
            match QueryCatcher::from_query_result(&row, "") {
                Ok(result) => relevant_advisory_info.push(result),
                Err(err) => return Err(Error::from(err)),
            }
        }

        log::debug!("Combined results: {}", relevant_advisory_info.len());

        // Pre-fetch all cvss3 scores in bulk - collect unique IDs
        let (advisory_ids, vulnerability_ids): (Vec<Uuid>, Vec<String>) = relevant_advisory_info
            .iter()
            .map(|info| (info.advisory.id, info.vulnerability.id.clone()))
            .unzip();

        let cvss3_scores = if !advisory_ids.is_empty() {
            cvss3::Entity::find()
                .filter(Expr::col(cvss3::Column::AdvisoryId).eq(PgFunc::any(advisory_ids)))
                .filter(
                    Expr::col(cvss3::Column::VulnerabilityId).eq(PgFunc::any(vulnerability_ids)),
                )
                .all(tx)
                .await?
        } else {
            vec![]
        };

        // Build lookup map: (advisory_id, vulnerability_id) -> Vec<cvss3::Model>
        let mut cvss3_map: HashMap<(Uuid, String), Vec<cvss3::Model>> = HashMap::new();
        for score in cvss3_scores {
            cvss3_map
                .entry((score.advisory_id, score.vulnerability_id.clone()))
                .or_default()
                .push(score);
        }

        let advisories = SbomAdvisory::from_models(relevant_advisory_info, &cvss3_map, tx).await?;

        Ok(Some(SbomDetails {
            summary,
            advisories,
        }))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct SbomAdvisory {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub status: Vec<SbomStatus>,
}

impl SbomAdvisory {
    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    pub async fn from_models<C: ConnectionTrait>(
        statuses: Vec<QueryCatcher>,
        cvss3_map: &HashMap<(Uuid, String), Vec<cvss3::Model>>,
        tx: &C,
    ) -> Result<Vec<Self>, Error> {
        let mut advisories = HashMap::new();

        for each in statuses {
            let status_cpe = each
                .context_cpe
                .as_ref()
                .and_then(|cpe| cpe.try_into().ok());

            let advisory = if let Some(advisory) = advisories.get_mut(&each.advisory.id) {
                advisory
            } else {
                advisories.insert(
                    each.advisory.id,
                    SbomAdvisory {
                        head: AdvisoryHead::from_advisory(
                            &each.advisory,
                            Memo::Provided(each.organization.clone()),
                            tx,
                        )
                        .await?,
                        status: vec![],
                    },
                );

                advisories
                    .get_mut(&each.advisory.id)
                    .ok_or(Error::Data("Failed to build advisories".to_string()))?
            };

            let sbom_status = if let Some(status) = advisory.status.iter_mut().find(|status| {
                status.status == each.status.slug
                    && status.vulnerability.identifier == each.vulnerability.id
            }) {
                status
            } else {
                let status = SbomStatus::new(
                    &each.advisory_vulnerability,
                    &each.vulnerability,
                    each.status.slug,
                    status_cpe,
                    vec![],
                    // Look up pre-fetched cvss3 scores from the map
                    cvss3_map
                        .get(&(each.advisory.id, each.vulnerability.id.clone()))
                        .cloned()
                        .unwrap_or_default(),
                )
                .await?;
                advisory.status.push(status);
                if let Some(status) = advisory.status.last_mut() {
                    status
                } else {
                    return Err(Error::Data("failed to build advisory status".to_string()));
                }
            };

            sbom_status.packages.push(SbomPackage {
                id: each.sbom_package.node_id,
                name: each.sbom_node.name,
                group: each.sbom_package.group,
                version: each.sbom_package.version,
                purl: vec![PurlSummary::from_entity(&each.qualified_purl)],
                cpe: vec![],
                licenses: vec![],
                licenses_ref_mapping: vec![],
            });
        }

        if log::log_enabled!(log::Level::Info) {
            log::info!("Advisories: {}", advisories.len());
            log::info!(
                "  Statuses: {}",
                advisories.values().map(|v| v.status.len()).sum::<usize>()
            );
            log::info!(
                "  Packages: {}",
                advisories
                    .values()
                    .flat_map(|v| &v.status)
                    .map(|v| v.packages.len())
                    .sum::<usize>()
            );
        }

        Ok(advisories.into_values().collect::<Vec<_>>())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct SbomStatus {
    #[serde(flatten)]
    pub vulnerability: VulnerabilityHead,
    #[deprecated(since = "0.4.0", note = "Please use `scores` instead")]
    pub average_severity: Severity,
    #[deprecated(since = "0.4.0", note = "Please use `scores` instead")]
    pub average_score: f64,
    pub status: String,
    pub context: Option<StatusContext>,
    pub packages: Vec<SbomPackage>,
    pub scores: Vec<crate::common::model::Score>,
}

impl SbomStatus {
    #[instrument(
        skip(
            advisory_vulnerability,
            vulnerability,
            packages,
            cvss3
        ),
        err(level=tracing::Level::INFO)
    )]
    pub async fn new(
        advisory_vulnerability: &advisory_vulnerability::Model,
        vulnerability: &vulnerability::Model,
        status: String,
        cpe: Option<OwnedUri>,
        packages: Vec<SbomPackage>,
        cvss3: Vec<cvss3::Model>,
    ) -> Result<Self, Error> {
        let average = Score::from_iter(cvss3.iter().map(Cvss3Base::from));
        let scores = cvss3
            .into_iter()
            .filter_map(|cvss3| crate::common::model::Score::try_from(cvss3).ok())
            .collect();

        Ok(Self {
            vulnerability: VulnerabilityHead::from_advisory_vulnerability_entity(
                advisory_vulnerability,
                vulnerability,
            ),
            context: cpe.as_ref().map(|e| StatusContext::Cpe(e.to_string())),
            #[allow(deprecated)]
            average_severity: average.severity(),
            #[allow(deprecated)]
            average_score: average.value(),
            status,
            packages,
            scores,
        })
    }

    pub fn identifier(&self) -> &str {
        &self.vulnerability.identifier
    }
}
