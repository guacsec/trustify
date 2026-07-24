/// Hydration layer: converts lightweight `CorrelationMatch` results into
/// the full `SbomAdvisory` API response by batch-loading entity data
/// from the database.
///
/// The hot path (identity + version matching) runs in memory. This module
/// handles the cold path: loading advisory, vulnerability, score, CPE,
/// PURL, and package metadata for the matched entities.
use crate::service::CorrelationMatch;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tracing::{Instrument, info_span, instrument};

use trustify_entity::{
    advisory, advisory_vulnerability, advisory_vulnerability_score, cpe, organization,
    qualified_purl, sbom_node, sbom_package, status, vulnerability,
};
use trustify_module_fundamental::{
    advisory::model::AdvisoryHead,
    purl::model::{details::purl::StatusContext, summary::purl::PurlSummary},
    sbom::model::{SbomPackage, details::{SbomAdvisory, SbomStatus}},
    vulnerability::model::VulnerabilityHead,
};
use uuid::Uuid;

/// A fully hydrated advisory with its vulnerability statuses and
/// matched packages, ready for API serialization.
///
/// This mirrors `SbomAdvisory` from the fundamental module but is
/// constructed from correlation matches rather than SQL query results.
#[derive(Debug, Clone)]
pub struct HydratedAdvisory {
    /// Advisory identity and metadata.
    pub advisory: advisory::Model,
    /// Optional issuing organization.
    pub organization: Option<organization::Model>,
    /// Vulnerability statuses within this advisory.
    pub statuses: Vec<HydratedStatus>,
}

/// A vulnerability status within an advisory, with matched packages.
#[derive(Debug, Clone)]
pub struct HydratedStatus {
    /// The advisory-vulnerability link.
    pub advisory_vulnerability: advisory_vulnerability::Model,
    /// The vulnerability entity.
    pub vulnerability: vulnerability::Model,
    /// The status slug (affected, fixed, etc.).
    pub status_slug: String,
    /// Optional context CPE.
    pub context_cpe: Option<cpe::Model>,
    /// CVSS scores for this advisory-vulnerability pair.
    pub scores: Vec<advisory_vulnerability_score::Model>,
    /// Matched SBOM packages.
    pub packages: Vec<HydratedPackage>,
}

/// A matched SBOM package with its PURL and node metadata.
#[derive(Debug, Clone)]
pub struct HydratedPackage {
    /// SBOM package metadata (version, etc.).
    pub sbom_package: sbom_package::Model,
    /// SBOM node metadata (name, etc.).
    pub sbom_node: sbom_node::Model,
    /// Qualified PURLs for this package.
    pub purls: Vec<qualified_purl::Model>,
}

/// Hydrate a set of correlation matches into structured advisory data.
///
/// Extracts unique entity IDs, batch-fetches from the database, and
/// assembles into the grouped advisory → status → package hierarchy.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
pub async fn hydrate_sbom_matches<C: ConnectionTrait>(
    matches: &[CorrelationMatch],
    connection: &C,
) -> Result<Vec<HydratedAdvisory>, anyhow::Error> {
    if matches.is_empty() {
        return Ok(Vec::new());
    }

    // Collect unique entity IDs.
    let mut advisory_ids = BTreeSet::new();
    let mut vulnerability_ids = BTreeSet::new();
    let mut status_ids = BTreeSet::new();
    let mut sbom_node_keys: BTreeSet<(Uuid, String)> = BTreeSet::new();

    for m in matches {
        advisory_ids.insert(m.advisory_id);
        vulnerability_ids.insert(m.vulnerability_id.clone());
        status_ids.insert(m.status_id);
        sbom_node_keys.insert((m.sbom_id, m.node_id.clone()));
    }

    // Batch-fetch all entities in parallel.
    let (advisories, vulns, av_models, _statuses, sbom_packages, sbom_nodes, scores, orgs) =
        tokio::try_join!(
            fetch_advisories(&advisory_ids, connection),
            fetch_vulnerabilities(&vulnerability_ids, connection),
            fetch_advisory_vulnerabilities(&advisory_ids, &vulnerability_ids, connection),
            fetch_statuses(&status_ids, connection),
            fetch_sbom_packages(&sbom_node_keys, connection),
            fetch_sbom_nodes(&sbom_node_keys, connection),
            fetch_scores(&advisory_ids, &vulnerability_ids, connection),
            fetch_organizations(&advisory_ids, connection),
        )?;

    // Fetch qualified PURLs for matched nodes.
    let purls = fetch_purls_for_nodes(&sbom_node_keys, connection).await?;

    // Assemble into the grouped hierarchy.
    let mut advisory_map: BTreeMap<Uuid, HydratedAdvisory> = BTreeMap::new();

    for m in matches {
        let advisory = match advisories.get(&m.advisory_id) {
            Some(a) => a,
            None => continue,
        };

        let hydrated = advisory_map.entry(m.advisory_id).or_insert_with(|| {
            let org = advisory
                .issuer_id
                .and_then(|oid| orgs.get(&oid).cloned());
            HydratedAdvisory {
                advisory: advisory.clone(),
                organization: org,
                statuses: Vec::new(),
            }
        });

        // Find or create the status entry.
        let status_idx = hydrated
            .statuses
            .iter()
            .position(|s| {
                s.advisory_vulnerability.vulnerability_id == m.vulnerability_id
                    && s.status_slug == m.status_slug
            });

        let status_entry = if let Some(idx) = status_idx {
            &mut hydrated.statuses[idx]
        } else {
            let av_key = (m.advisory_id, m.vulnerability_id.clone());
            let av = match av_models.get(&av_key) {
                Some(av) => av.clone(),
                None => continue, // Skip if we can't find the advisory-vulnerability link
            };

            let vuln = match vulns.get(&m.vulnerability_id) {
                Some(v) => v.clone(),
                None => continue, // Skip if we can't find the vulnerability
            };

            let score_key = (m.advisory_id, m.vulnerability_id.clone());
            let match_scores = scores
                .get(&score_key)
                .cloned()
                .unwrap_or_default();

            hydrated.statuses.push(HydratedStatus {
                advisory_vulnerability: av,
                vulnerability: vuln,
                status_slug: m.status_slug.clone(),
                context_cpe: None,
                scores: match_scores,
                packages: Vec::new(),
            });
            let Some(entry) = hydrated.statuses.last_mut() else {
                continue;
            };
            entry
        };

        // Add the matched package.
        let node_key = (m.sbom_id, m.node_id.clone());
        let pkg = sbom_packages.get(&node_key);
        let node = sbom_nodes.get(&node_key);

        if let (Some(pkg), Some(node)) = (pkg, node) {
            // Avoid duplicate packages in the same status entry.
            let already_present = status_entry.packages.iter().any(|p| {
                p.sbom_package.sbom_id == pkg.sbom_id
                    && p.sbom_package.node_id == pkg.node_id
            });

            if !already_present {
                let node_purls = purls
                    .get(&node_key)
                    .cloned()
                    .unwrap_or_default();

                status_entry.packages.push(HydratedPackage {
                    sbom_package: pkg.clone(),
                    sbom_node: node.clone(),
                    purls: node_purls,
                });
            }
        }
    }

    Ok(advisory_map.into_values().collect())
}

async fn fetch_advisories<C: ConnectionTrait>(
    ids: &BTreeSet<Uuid>,
    connection: &C,
) -> Result<BTreeMap<Uuid, advisory::Model>, anyhow::Error> {
    let rows = advisory::Entity::find()
        .filter(advisory::Column::Id.is_in(ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("fetch advisories"))
        .await?;
    Ok(rows.into_iter().map(|r| (r.id, r)).collect())
}

async fn fetch_advisory_vulnerabilities<C: ConnectionTrait>(
    advisory_ids: &BTreeSet<Uuid>,
    vulnerability_ids: &BTreeSet<String>,
    connection: &C,
) -> Result<BTreeMap<(Uuid, String), advisory_vulnerability::Model>, anyhow::Error> {
    let rows = advisory_vulnerability::Entity::find()
        .filter(
            advisory_vulnerability::Column::AdvisoryId.is_in(advisory_ids.iter().copied()),
        )
        .filter(
            advisory_vulnerability::Column::VulnerabilityId
                .is_in(vulnerability_ids.iter().cloned()),
        )
        .all(connection)
        .instrument(info_span!("fetch advisory vulnerabilities"))
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| ((r.advisory_id, r.vulnerability_id.clone()), r))
        .collect())
}

async fn fetch_vulnerabilities<C: ConnectionTrait>(
    ids: &BTreeSet<String>,
    connection: &C,
) -> Result<BTreeMap<String, vulnerability::Model>, anyhow::Error> {
    let rows = vulnerability::Entity::find()
        .filter(vulnerability::Column::Id.is_in(ids.iter().cloned()))
        .all(connection)
        .instrument(info_span!("fetch vulnerabilities"))
        .await?;
    Ok(rows.into_iter().map(|r| (r.id.clone(), r)).collect())
}

async fn fetch_statuses<C: ConnectionTrait>(
    ids: &BTreeSet<Uuid>,
    connection: &C,
) -> Result<BTreeMap<Uuid, status::Model>, anyhow::Error> {
    let rows = status::Entity::find()
        .filter(status::Column::Id.is_in(ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("fetch statuses"))
        .await?;
    Ok(rows.into_iter().map(|r| (r.id, r)).collect())
}

async fn fetch_sbom_packages<C: ConnectionTrait>(
    keys: &BTreeSet<(Uuid, String)>,
    connection: &C,
) -> Result<BTreeMap<(Uuid, String), sbom_package::Model>, anyhow::Error> {
    if keys.is_empty() {
        return Ok(BTreeMap::new());
    }
    // Query by sbom_id IN (...) and filter in memory by node_id.
    let sbom_ids: BTreeSet<Uuid> = keys.iter().map(|(s, _)| *s).collect();
    let rows = sbom_package::Entity::find()
        .filter(sbom_package::Column::SbomId.is_in(sbom_ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("fetch sbom packages"))
        .await?;
    let mut map = BTreeMap::new();
    for r in rows {
        let key = (r.sbom_id, r.node_id.clone());
        if keys.contains(&key) {
            map.insert(key, r);
        }
    }
    Ok(map)
}

async fn fetch_sbom_nodes<C: ConnectionTrait>(
    keys: &BTreeSet<(Uuid, String)>,
    connection: &C,
) -> Result<BTreeMap<(Uuid, String), sbom_node::Model>, anyhow::Error> {
    if keys.is_empty() {
        return Ok(BTreeMap::new());
    }
    let sbom_ids: BTreeSet<Uuid> = keys.iter().map(|(s, _)| *s).collect();
    let rows = sbom_node::Entity::find()
        .filter(sbom_node::Column::SbomId.is_in(sbom_ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("fetch sbom nodes"))
        .await?;
    let mut map = BTreeMap::new();
    for r in rows {
        let key = (r.sbom_id, r.node_id.clone());
        if keys.contains(&key) {
            map.insert(key, r);
        }
    }
    Ok(map)
}

async fn fetch_scores<C: ConnectionTrait>(
    advisory_ids: &BTreeSet<Uuid>,
    vulnerability_ids: &BTreeSet<String>,
    connection: &C,
) -> Result<HashMap<(Uuid, String), Vec<advisory_vulnerability_score::Model>>, anyhow::Error> {
    let rows = advisory_vulnerability_score::Entity::find()
        .filter(
            advisory_vulnerability_score::Column::AdvisoryId
                .is_in(advisory_ids.iter().copied()),
        )
        .filter(
            advisory_vulnerability_score::Column::VulnerabilityId
                .is_in(vulnerability_ids.iter().cloned()),
        )
        .all(connection)
        .instrument(info_span!("fetch scores"))
        .await?;
    let mut map: HashMap<(Uuid, String), Vec<_>> = HashMap::new();
    for r in rows {
        map.entry((r.advisory_id, r.vulnerability_id.clone()))
            .or_default()
            .push(r);
    }
    Ok(map)
}

async fn fetch_organizations<C: ConnectionTrait>(
    advisory_ids: &BTreeSet<Uuid>,
    connection: &C,
) -> Result<BTreeMap<Uuid, organization::Model>, anyhow::Error> {
    // First get issuer_ids from advisories, then fetch orgs.
    let advisories = advisory::Entity::find()
        .filter(advisory::Column::Id.is_in(advisory_ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("fetch advisory issuers"))
        .await?;
    let org_ids: BTreeSet<Uuid> = advisories
        .iter()
        .filter_map(|a| a.issuer_id)
        .collect();
    if org_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows = organization::Entity::find()
        .filter(organization::Column::Id.is_in(org_ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("fetch organizations"))
        .await?;
    Ok(rows.into_iter().map(|r| (r.id, r)).collect())
}

async fn fetch_purls_for_nodes<C: ConnectionTrait>(
    keys: &BTreeSet<(Uuid, String)>,
    connection: &C,
) -> Result<BTreeMap<(Uuid, String), Vec<qualified_purl::Model>>, anyhow::Error> {
    use sea_orm::{FromQueryResult, Statement};

    if keys.is_empty() {
        return Ok(BTreeMap::new());
    }

    let sbom_ids: Vec<Uuid> = keys.iter().map(|(s, _)| *s).collect();

    #[derive(Debug, FromQueryResult)]
    struct PurlRow {
        sbom_id: Uuid,
        node_id: String,
        purl_id: Uuid,
    }

    let rows: Vec<PurlRow> = PurlRow::find_by_statement(
        Statement::from_sql_and_values(
            sea_orm::DatabaseBackend::Postgres,
            r#"
            SELECT snpr.sbom_id, snpr.node_id, snpr.qualified_purl_id AS purl_id
            FROM sbom_node_purl_ref snpr
            WHERE snpr.sbom_id = ANY($1)
            "#,
            [sbom_ids.into()],
        ),
    )
    .all(connection)
    .instrument(info_span!("fetch purl refs"))
    .await?;

    // Filter to only requested nodes and collect purl IDs.
    let mut node_to_purl_ids: BTreeMap<(Uuid, String), Vec<Uuid>> = BTreeMap::new();
    let mut all_purl_ids = BTreeSet::new();
    for r in &rows {
        let key = (r.sbom_id, r.node_id.clone());
        if keys.contains(&key) {
            node_to_purl_ids.entry(key).or_default().push(r.purl_id);
            all_purl_ids.insert(r.purl_id);
        }
    }

    // Fetch qualified_purl models.
    let purl_models = qualified_purl::Entity::find()
        .filter(qualified_purl::Column::Id.is_in(all_purl_ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("fetch qualified purls"))
        .await?;
    let purl_map: BTreeMap<Uuid, qualified_purl::Model> =
        purl_models.into_iter().map(|p| (p.id, p)).collect();

    // Assemble per-node PURL lists.
    let mut result = BTreeMap::new();
    for (key, purl_ids) in node_to_purl_ids {
        let purls: Vec<qualified_purl::Model> = purl_ids
            .iter()
            .filter_map(|id| purl_map.get(id).cloned())
            .collect();
        result.insert(key, purls);
    }

    Ok(result)
}

/// Convert hydrated advisory data into the existing `SbomAdvisory` API
/// response format.
///
/// This enables the correlation engine to produce the same response type
/// as the SQL-based `GET /v3/sbom/{id}/advisory` endpoint, making it a
/// drop-in replacement.
#[allow(deprecated)]
pub fn to_sbom_advisories(hydrated: Vec<HydratedAdvisory>) -> Vec<SbomAdvisory> {
    hydrated
        .into_iter()
        .map(|ha| {
            let issuer = ha.organization.as_ref().map(|org| {
                trustify_module_fundamental::organization::model::OrganizationSummary::from_entity(
                    org,
                )
            });

            let head = AdvisoryHead {
                uuid: ha.advisory.id,
                identifier: ha.advisory.identifier.clone(),
                document_id: ha.advisory.document_id.clone(),
                issuer,
                published: ha.advisory.published,
                modified: ha.advisory.modified,
                withdrawn: ha.advisory.withdrawn,
                title: ha.advisory.title.clone(),
                labels: ha.advisory.labels.clone(),
            };

            let status = ha
                .statuses
                .into_iter()
                .map(|hs| {
                    let vuln_head = VulnerabilityHead::from_advisory_vulnerability_entity(
                        &hs.advisory_vulnerability,
                        &hs.vulnerability,
                    );

                    let context = hs.context_cpe.as_ref().and_then(|cpe_model| {
                        let uri: Result<::cpe::uri::OwnedUri, _> = cpe_model.try_into();
                        uri.ok().map(|u| StatusContext::Cpe(u.to_string()))
                    });

                    let scores = hs
                        .scores
                        .into_iter()
                        .map(trustify_module_fundamental::common::model::ScoredVector::from)
                        .collect();

                    let packages = hs
                        .packages
                        .into_iter()
                        .map(|hp| SbomPackage {
                            id: hp.sbom_package.node_id.clone(),
                            name: hp.sbom_node.name.clone(),
                            group: hp.sbom_package.group.clone(),
                            version: hp.sbom_package.version.clone(),
                            purl: PurlSummary::from_entities(&hp.purls),
                            cpe: vec![],
                            licenses: vec![],
                            licenses_ref_mapping: vec![],
                        })
                        .collect();

                    SbomStatus {
                        vulnerability: vuln_head,
                        status: hs.status_slug,
                        context,
                        packages,
                        scores,
                    }
                })
                .collect();

            SbomAdvisory { head, status }
        })
        .collect()
}
