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
use ::cpe::uri::OwnedUri;
use sea_orm::{
    ConnectionTrait, DbBackend, DbErr, EntityTrait, FromQueryResult, JoinType, ModelTrait,
    QueryFilter, QueryResult, QuerySelect, RelationTrait, Statement,
};
use sea_query::{Asterisk, Expr, Func, PgFunc, SimpleExpr};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tracing::instrument;
use trustify_common::{db::VersionMatches, memo::Memo};
use trustify_cvss::cvss3::{Cvss3Base, score::Score, severity::Severity};
use trustify_entity::{
    advisory, advisory_vulnerability, base_purl, cpe, cvss3, organization, purl_status,
    qualified_purl, sbom, sbom_node, sbom_package, sbom_package_purl_ref, status, version_range,
    versioned_purl, vulnerability,
};
use utoipa::ToSchema;
use uuid::Uuid;

/// Lightweight struct to collect only IDs from the initial query
#[derive(Debug, Clone)]
struct IdSet {
    advisory_id: Uuid,
    qualified_purl_id: Uuid,
    sbom_id: Uuid,
    sbom_node_id: String,
    advisory_vulnerability_advisory_id: Uuid,
    advisory_vulnerability_vulnerability_id: String,
    vulnerability_id: String,
    context_cpe_id: Option<Uuid>,
    status_id: Uuid,
    organization_id: Option<Uuid>,
}

impl FromQueryResult for IdSet {
    fn from_query_result(res: &QueryResult, _pre: &str) -> Result<Self, DbErr> {
        Ok(Self {
            advisory_id: res.try_get("", "advisory_id")?,
            qualified_purl_id: res.try_get("", "qualified_purl_id")?,
            sbom_id: res.try_get("", "sbom_id")?,
            sbom_node_id: res.try_get("", "node_id")?,
            advisory_vulnerability_advisory_id: res.try_get("", "av_advisory_id")?,
            advisory_vulnerability_vulnerability_id: res.try_get("", "av_vulnerability_id")?,
            vulnerability_id: res.try_get("", "vulnerability_id")?,
            context_cpe_id: res.try_get("", "cpe_id").ok(),
            status_id: res.try_get("", "status_id")?,
            organization_id: res.try_get("", "organization_id").ok(),
        })
    }
}

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
            .distinct()
            .select_only()
            .column_as(advisory::Column::Id, "advisory_id")
            .column_as(advisory_vulnerability::Column::AdvisoryId, "av_advisory_id")
            .column_as(
                advisory_vulnerability::Column::VulnerabilityId,
                "av_vulnerability_id",
            )
            .column_as(vulnerability::Column::Id, "vulnerability_id")
            .column_as(qualified_purl::Column::Id, "qualified_purl_id")
            .column_as(sbom_package::Column::SbomId, "sbom_id")
            .column_as(sbom_package::Column::NodeId, "node_id")
            .column_as(status::Column::Id, "status_id")
            .column_as(cpe::Column::Id, "cpe_id")
            .column_as(organization::Column::Id, "organization_id")
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

        // Dual query strategy to collect vulnerability matches by both PURL and CPE:
        // 1. SeaORM query: PURL-based vulnerability matching through purl_status table
        //    - Matches packages by Package URL (e.g., pkg:maven/org.example/lib@1.2.3)
        //    - Uses version_matches() function to check if package version falls in vulnerable range
        // 2. Raw SQL query: CPE-based vulnerability matching through product_status table
        //    - Matches packages by Common Platform Enumeration (e.g., cpe:2.3:a:vendor:product:1.0)
        //    - Handles products identified by CPE rather than PURL
        // Both queries collect the same ID structure and are combined to ensure comprehensive coverage

        // Collect only IDs from the first query
        let mut id_sets: Vec<IdSet> = query
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
            .filter(Expr::col((advisory::Entity, advisory::Column::Deprecated)).eq(false))
            .join(JoinType::LeftJoin, advisory::Relation::Issuer.def())
            .join(
                JoinType::Join,
                purl_status::Relation::AdvisoryVulnerability.def(),
            )
            .join(
                JoinType::Join,
                advisory_vulnerability::Relation::Vulnerability.def(),
            )
            .into_model::<IdSet>()
            .all(tx)
            .await?;

        log::debug!("Collected {} ID sets from first query", id_sets.len());

        // Execute the raw SQL query and collect IDs
        let raw_results = tx
            .query_all(Statement::from_sql_and_values(
                DbBackend::Postgres,
                raw_sql::product_advisory_info_sql(),
                [sbom.sbom_id.into(), statuses.into()],
            ))
            .await?;

        // Convert raw SQL results to IdSet objects
        for row in raw_results {
            match IdSet::from_query_result(&row, "") {
                Ok(result) => id_sets.push(result),
                Err(err) => return Err(Error::from(err)),
            }
        }

        log::debug!("Combined {} total ID sets", id_sets.len());

        // Extract unique IDs for each entity type
        let mut advisory_ids_set: BTreeSet<Uuid> = BTreeSet::new();
        let mut qualified_purl_ids_set: BTreeSet<Uuid> = BTreeSet::new();
        let mut sbom_package_ids_set: BTreeSet<(Uuid, String)> = BTreeSet::new();
        let mut advisory_vulnerability_ids_set: BTreeSet<(Uuid, String)> = BTreeSet::new();
        let mut vulnerability_ids_set: BTreeSet<String> = BTreeSet::new();
        let mut cpe_ids_set: BTreeSet<Uuid> = BTreeSet::new();
        let mut status_ids_set: BTreeSet<Uuid> = BTreeSet::new();
        let mut organization_ids_set: BTreeSet<Uuid> = BTreeSet::new();

        for id_set in &id_sets {
            advisory_ids_set.insert(id_set.advisory_id);
            qualified_purl_ids_set.insert(id_set.qualified_purl_id);
            sbom_package_ids_set.insert((id_set.sbom_id, id_set.sbom_node_id.clone()));
            advisory_vulnerability_ids_set.insert((
                id_set.advisory_vulnerability_advisory_id,
                id_set.advisory_vulnerability_vulnerability_id.clone(),
            ));
            vulnerability_ids_set.insert(id_set.vulnerability_id.clone());
            if let Some(cpe_id) = id_set.context_cpe_id {
                cpe_ids_set.insert(cpe_id);
            }
            status_ids_set.insert(id_set.status_id);
            if let Some(org_id) = id_set.organization_id {
                organization_ids_set.insert(org_id);
            }
        }

        let advisory_ids: Vec<Uuid> = advisory_ids_set.into_iter().collect();
        let qualified_purl_ids: Vec<Uuid> = qualified_purl_ids_set.into_iter().collect();
        let sbom_package_ids: Vec<(Uuid, String)> = sbom_package_ids_set.into_iter().collect();
        let advisory_vulnerability_ids: Vec<(Uuid, String)> =
            advisory_vulnerability_ids_set.into_iter().collect();
        let vulnerability_ids: Vec<String> = vulnerability_ids_set.into_iter().collect();
        let cpe_ids: Vec<Uuid> = cpe_ids_set.into_iter().collect();
        let status_ids: Vec<Uuid> = status_ids_set.into_iter().collect();
        let organization_ids: Vec<Uuid> = organization_ids_set.into_iter().collect();

        // Pre-fetch all entities in bulk and build lookup maps with Arc
        let advisories_map: BTreeMap<Uuid, Arc<advisory::Model>> = advisory::Entity::find()
            .filter(Expr::col(advisory::Column::Id).eq(PgFunc::any(advisory_ids.clone())))
            .all(tx)
            .await?
            .into_iter()
            .map(|adv| (adv.id, Arc::new(adv)))
            .collect();
        log::debug!("Pre-fetched {} advisories", advisories_map.len());

        let qualified_purls_map: BTreeMap<Uuid, Arc<qualified_purl::Model>> =
            qualified_purl::Entity::find()
                .filter(Expr::col(qualified_purl::Column::Id).eq(PgFunc::any(qualified_purl_ids)))
                .all(tx)
                .await?
                .into_iter()
                .map(|qp| (qp.id, Arc::new(qp)))
                .collect();
        log::debug!("Pre-fetched {} qualified_purls", qualified_purls_map.len());

        let (sbom_ids, node_ids): (Vec<Uuid>, Vec<String>) =
            sbom_package_ids.iter().cloned().unzip();
        let sbom_packages_map: BTreeMap<(Uuid, String), Arc<sbom_package::Model>> =
            sbom_package::Entity::find()
                .filter(Expr::col(sbom_package::Column::SbomId).eq(PgFunc::any(sbom_ids)))
                .filter(Expr::col(sbom_package::Column::NodeId).eq(PgFunc::any(node_ids.clone())))
                .all(tx)
                .await?
                .into_iter()
                .map(|sp| ((sp.sbom_id, sp.node_id.clone()), Arc::new(sp)))
                .collect();
        log::debug!("Pre-fetched {} sbom_packages", sbom_packages_map.len());

        let sbom_nodes_map: BTreeMap<String, Arc<sbom_node::Model>> = sbom_node::Entity::find()
            .filter(Expr::col(sbom_node::Column::NodeId).eq(PgFunc::any(node_ids)))
            .all(tx)
            .await?
            .into_iter()
            .map(|sn| (sn.node_id.clone(), Arc::new(sn)))
            .collect();
        log::debug!("Pre-fetched {} sbom_nodes", sbom_nodes_map.len());

        let (av_advisory_ids, av_vulnerability_ids): (Vec<Uuid>, Vec<String>) =
            advisory_vulnerability_ids.iter().cloned().unzip();
        let advisory_vulnerabilities_map: BTreeMap<
            (Uuid, String),
            Arc<advisory_vulnerability::Model>,
        > = advisory_vulnerability::Entity::find()
            .filter(
                Expr::col(advisory_vulnerability::Column::AdvisoryId)
                    .eq(PgFunc::any(av_advisory_ids)),
            )
            .filter(
                Expr::col(advisory_vulnerability::Column::VulnerabilityId)
                    .eq(PgFunc::any(av_vulnerability_ids)),
            )
            .all(tx)
            .await?
            .into_iter()
            .map(|av| ((av.advisory_id, av.vulnerability_id.clone()), Arc::new(av)))
            .collect();
        log::debug!(
            "Pre-fetched {} advisory_vulnerabilities",
            advisory_vulnerabilities_map.len()
        );

        let vulnerabilities_map: BTreeMap<String, Arc<vulnerability::Model>> =
            vulnerability::Entity::find()
                .filter(
                    Expr::col(vulnerability::Column::Id).eq(PgFunc::any(vulnerability_ids.clone())),
                )
                .all(tx)
                .await?
                .into_iter()
                .map(|v| (v.id.clone(), Arc::new(v)))
                .collect();
        log::debug!("Pre-fetched {} vulnerabilities", vulnerabilities_map.len());

        let cpes_map: BTreeMap<Uuid, Arc<cpe::Model>> = cpe::Entity::find()
            .filter(Expr::col(cpe::Column::Id).eq(PgFunc::any(cpe_ids)))
            .all(tx)
            .await?
            .into_iter()
            .map(|c| (c.id, Arc::new(c)))
            .collect();
        log::debug!("Pre-fetched {} cpes", cpes_map.len());

        let statuses_map: BTreeMap<Uuid, Arc<status::Model>> = status::Entity::find()
            .filter(Expr::col(status::Column::Id).eq(PgFunc::any(status_ids)))
            .all(tx)
            .await?
            .into_iter()
            .map(|s| (s.id, Arc::new(s)))
            .collect();
        log::debug!("Pre-fetched {} statuses", statuses_map.len());

        let organizations_map: BTreeMap<Uuid, Arc<organization::Model>> =
            organization::Entity::find()
                .filter(Expr::col(organization::Column::Id).eq(PgFunc::any(organization_ids)))
                .all(tx)
                .await?
                .into_iter()
                .map(|o| (o.id, Arc::new(o)))
                .collect();
        log::debug!("Pre-fetched {} organizations", organizations_map.len());

        // Pre-fetch cvss3 scores
        let cvss3_scores = cvss3::Entity::find()
            .filter(Expr::col(cvss3::Column::AdvisoryId).eq(PgFunc::any(advisory_ids)))
            .filter(Expr::col(cvss3::Column::VulnerabilityId).eq(PgFunc::any(vulnerability_ids)))
            .all(tx)
            .await?;
        log::debug!("Pre-fetched {} cvss3 scores", cvss3_scores.len());

        // Build cvss3 lookup map (needs special handling for Vec aggregation)
        let mut cvss3_map: BTreeMap<(Uuid, String), Vec<cvss3::Model>> = BTreeMap::new();
        for score in cvss3_scores {
            cvss3_map
                .entry((score.advisory_id, score.vulnerability_id.clone()))
                .or_default()
                .push(score);
        }

        // Reconstruct QueryCatcher objects from IDs and lookup maps
        let mut relevant_advisory_info = Vec::with_capacity(id_sets.len());
        for id_set in id_sets {
            let advisory = advisories_map.get(&id_set.advisory_id).ok_or_else(|| {
                Error::NotFound(format!(
                    "Advisory {} not found in lookup",
                    id_set.advisory_id
                ))
            })?;
            let qualified_purl = qualified_purls_map
                .get(&id_set.qualified_purl_id)
                .ok_or_else(|| {
                    Error::NotFound(format!(
                        "QualifiedPurl {} not found in lookup",
                        id_set.qualified_purl_id
                    ))
                })?;
            let sbom_package = sbom_packages_map
                .get(&(id_set.sbom_id, id_set.sbom_node_id.clone()))
                .ok_or_else(|| {
                    Error::NotFound(format!(
                        "SbomPackage ({}, {}) not found in lookup",
                        id_set.sbom_id, id_set.sbom_node_id
                    ))
                })?;
            let sbom_node = sbom_nodes_map.get(&id_set.sbom_node_id).ok_or_else(|| {
                Error::NotFound(format!(
                    "SbomNode {} not found in lookup",
                    id_set.sbom_node_id
                ))
            })?;
            let advisory_vulnerability = advisory_vulnerabilities_map
                .get(&(
                    id_set.advisory_vulnerability_advisory_id,
                    id_set.advisory_vulnerability_vulnerability_id.clone(),
                ))
                .ok_or_else(|| {
                    Error::NotFound(format!(
                        "AdvisoryVulnerability ({}, {}) not found in lookup",
                        id_set.advisory_vulnerability_advisory_id,
                        id_set.advisory_vulnerability_vulnerability_id
                    ))
                })?;
            let vulnerability = vulnerabilities_map
                .get(&id_set.vulnerability_id)
                .ok_or_else(|| {
                    Error::NotFound(format!(
                        "Vulnerability {} not found in lookup",
                        id_set.vulnerability_id
                    ))
                })?;
            let context_cpe = id_set
                .context_cpe_id
                .and_then(|id| cpes_map.get(&id).cloned());
            let status = statuses_map.get(&id_set.status_id).ok_or_else(|| {
                Error::NotFound(format!("Status {} not found in lookup", id_set.status_id))
            })?;
            let organization = id_set
                .organization_id
                .and_then(|id| organizations_map.get(&id).cloned());

            relevant_advisory_info.push(QueryCatcher {
                advisory: Arc::clone(advisory),
                qualified_purl: Arc::clone(qualified_purl),
                sbom_package: Arc::clone(sbom_package),
                sbom_node: Arc::clone(sbom_node),
                advisory_vulnerability: Arc::clone(advisory_vulnerability),
                vulnerability: Arc::clone(vulnerability),
                context_cpe,
                status: Arc::clone(status),
                organization,
            });
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
        cvss3_map: &BTreeMap<(Uuid, String), Vec<cvss3::Model>>,
        tx: &C,
    ) -> Result<Vec<Self>, Error> {
        let mut advisories = BTreeMap::new();

        for each in statuses {
            let status_cpe = each
                .context_cpe
                .as_ref()
                .and_then(|cpe| cpe.as_ref().try_into().ok());

            let advisory = if let Some(advisory) = advisories.get_mut(&each.advisory.id) {
                advisory
            } else {
                advisories.insert(
                    each.advisory.id,
                    SbomAdvisory {
                        head: AdvisoryHead::from_advisory(
                            &each.advisory,
                            Memo::Provided(each.organization.as_deref().cloned()),
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
                    each.status.slug.clone(),
                    status_cpe,
                    vec![],
                    // Look up pre-fetched cvss3 scores from the map
                    cvss3_map
                        .get(&(each.advisory.id, each.vulnerability.id.clone()))
                        .cloned()
                        .unwrap_or_default(),
                )?;
                advisory.status.push(status);
                if let Some(status) = advisory.status.last_mut() {
                    status
                } else {
                    return Err(Error::Data("failed to build advisory status".to_string()));
                }
            };

            sbom_status.packages.push(SbomPackage {
                id: each.sbom_package.node_id.clone(),
                name: each.sbom_node.name.clone(),
                group: each.sbom_package.group.clone(),
                version: each.sbom_package.version.clone(),
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
    pub fn new(
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
