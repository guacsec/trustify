use crate::Error;
use crate::model::{
    CorrelationMatch, PurlCorrelationMatch, PurlKey, VersionRangeData, VulnCorrelationMatch,
    VulnEntrySource, VulnIndexEntry,
};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, JoinType, QueryFilter, QuerySelect,
    RelationTrait,
};
use sea_query::Expr;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tracing::instrument;
use trustify_common::purl::Purl;
use trustify_entity::{
    advisory, advisory_vulnerability, advisory_vulnerability_score, cpe,
    package_relates_to_package, relationship::Relationship, remediation, remediation_purl_status,
    sbom, sbom_node, sbom_package, vulnerability,
};
use trustify_module_fundamental::{
    advisory::model::AdvisoryHead,
    common::model::ScoredVector,
    purl::model::{
        BasePurlHead, RecommendEntry, VexStatus, VulnerabilityStatus,
        details::{
            purl::{PurlAdvisory, PurlStatus, StatusContext},
            version_range::VersionRange,
        },
        summary::{purl::PurlSummary, remediation::RemediationSummary},
    },
    sbom::model::{
        SbomHead, SbomPackage,
        details::{SbomAdvisory, SbomStatus},
    },
    vulnerability::model::{
        VulnerabilityAdvisoryHead, VulnerabilityAdvisoryStatus, VulnerabilityAdvisorySummary,
        VulnerabilityHead, VulnerabilitySbomStatus,
        analyze::{AnalysisDetailsV3, AnalysisPurlStatus, AnalysisResponseV3, AnalysisResultV3},
    },
};
use uuid::Uuid;

/// Grouping key for a single SbomStatus entry within an advisory.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
struct StatusKey {
    vulnerability_id: String,
    status_slug: String,
    context_cpe_id: Option<Uuid>,
}

/// Hydrates in-memory correlation matches into the full SbomAdvisory API response.
///
/// Extracts unique entity IDs from the matches, runs batch DB queries for
/// advisory/vulnerability/score/CPE metadata, then groups matches into the
/// nested SbomAdvisory → SbomStatus → SbomPackage structure.
#[allow(deprecated)]
#[instrument(skip_all, err(level = tracing::Level::INFO))]
pub async fn hydrate_matches(
    matches: Vec<CorrelationMatch>,
    statuses: &HashMap<Uuid, Arc<str>>,
    connection: &impl ConnectionTrait,
) -> Result<Vec<SbomAdvisory>, Error> {
    if matches.is_empty() {
        return Ok(Vec::new());
    }

    // Collect unique IDs for batch queries
    let mut advisory_ids = HashSet::new();
    let mut vuln_ids = HashSet::new();
    let mut av_pairs: HashSet<(Uuid, String)> = HashSet::new();
    let mut cpe_ids = HashSet::new();

    for m in &matches {
        advisory_ids.insert(m.advisory_id);
        vuln_ids.insert(m.vulnerability_id.as_ref().to_string());
        av_pairs.insert((m.advisory_id, m.vulnerability_id.as_ref().to_string()));
        if let Some(cpe_id) = m.context_cpe_id {
            cpe_ids.insert(cpe_id);
        }
    }

    let advisory_id_vec: Vec<Uuid> = advisory_ids.into_iter().collect();
    let vuln_id_vec: Vec<String> = vuln_ids.into_iter().collect();

    // Batch load all needed entities in parallel
    let (advisory_models, av_models, vuln_models, score_models, cpe_models) = tokio::try_join!(
        load_advisories(&advisory_id_vec, connection),
        load_advisory_vulnerabilities(&advisory_id_vec, connection),
        load_vulnerabilities(&vuln_id_vec, connection),
        load_scores(&advisory_id_vec, connection),
        load_cpes(&cpe_ids, connection),
    )?;

    // Build advisory heads (includes issuer org batch load)
    let advisory_heads = AdvisoryHead::from_entities(&advisory_models, connection).await?;
    let advisory_head_map: HashMap<Uuid, AdvisoryHead> = advisory_models
        .iter()
        .zip(advisory_heads)
        .map(|(model, head)| (model.id, head))
        .collect();

    // Index advisory_vulnerability models by (advisory_id, vulnerability_id)
    let av_map: HashMap<(Uuid, String), advisory_vulnerability::Model> = av_models
        .into_iter()
        .map(|av| ((av.advisory_id, av.vulnerability_id.clone()), av))
        .collect();

    // Index vulnerability models by id
    let vuln_map: HashMap<String, vulnerability::Model> =
        vuln_models.into_iter().map(|v| (v.id.clone(), v)).collect();

    // Group scores by (advisory_id, vulnerability_id)
    let mut score_map: HashMap<(Uuid, String), Vec<advisory_vulnerability_score::Model>> =
        HashMap::new();
    for score in score_models {
        score_map
            .entry((score.advisory_id, score.vulnerability_id.clone()))
            .or_default()
            .push(score);
    }

    // Index CPE models by id
    let cpe_map: HashMap<Uuid, cpe::Model> = cpe_models.into_iter().map(|c| (c.id, c)).collect();

    // Group matches: advisory_id → StatusKey → Vec<SbomPackage>
    let mut advisory_groups: BTreeMap<Uuid, BTreeMap<StatusKey, Vec<SbomPackage>>> =
        BTreeMap::new();

    for m in &matches {
        let status_slug = statuses
            .get(&m.status_id)
            .map(|s| s.as_ref().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let key = StatusKey {
            vulnerability_id: m.vulnerability_id.as_ref().to_string(),
            status_slug,
            context_cpe_id: m.context_cpe_id,
        };

        let pkg = build_sbom_package(&m.purl_key, &m.version);

        advisory_groups
            .entry(m.advisory_id)
            .or_default()
            .entry(key)
            .or_default()
            .push(pkg);
    }

    // Assemble the final Vec<SbomAdvisory>
    let mut result = Vec::with_capacity(advisory_groups.len());

    for (advisory_id, status_groups) in advisory_groups {
        let head = match advisory_head_map.get(&advisory_id) {
            Some(head) => head.clone(),
            None => continue,
        };

        let mut sbom_statuses = Vec::with_capacity(status_groups.len());

        for (key, packages) in status_groups {
            let av_key = (advisory_id, key.vulnerability_id.clone());
            let av = match av_map.get(&av_key) {
                Some(av) => av,
                None => continue,
            };
            let vuln = match vuln_map.get(&key.vulnerability_id) {
                Some(v) => v,
                None => continue,
            };

            let scores: Vec<ScoredVector> = score_map
                .get(&av_key)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(ScoredVector::from)
                .collect();

            let context = key.context_cpe_id.and_then(|cpe_id| {
                cpe_map
                    .get(&cpe_id)
                    .map(|c| StatusContext::Cpe(c.to_string()))
            });

            sbom_statuses.push(SbomStatus {
                vulnerability: VulnerabilityHead::from_advisory_vulnerability_entity(av, vuln),
                status: key.status_slug,
                context,
                packages,
                scores,
            });
        }

        result.push(SbomAdvisory {
            head,
            status: sbom_statuses,
        });
    }

    Ok(result)
}

/// Builds an SbomPackage from in-memory purl key and version data.
#[allow(deprecated)]
fn build_sbom_package(purl_key: &PurlKey, version: &Arc<str>) -> SbomPackage {
    let purl = Purl {
        ty: purl_key.ty.to_string(),
        namespace: purl_key.namespace.as_ref().map(|ns| ns.to_string()),
        name: purl_key.name.to_string(),
        version: Some(version.to_string()),
        qualifiers: Default::default(),
    };

    let purl_id = match (&purl_key.namespace, purl_key.name.as_ref()) {
        (Some(ns), name) => format!("pkg:{}/{}/{}@{}", purl_key.ty, ns, name, version),
        (None, name) => format!("pkg:{}/{}@{}", purl_key.ty, name, version),
    };

    SbomPackage {
        id: purl_id,
        name: purl_key.name.to_string(),
        group: purl_key.namespace.as_ref().map(|ns| ns.to_string()),
        version: Some(version.to_string()),
        purl: vec![PurlSummary::from(purl)],
        cpe: vec![],
        licenses: vec![],
        licenses_ref_mapping: vec![],
    }
}

/// Batch loads advisory models by ID.
async fn load_advisories(
    ids: &[Uuid],
    connection: &impl ConnectionTrait,
) -> Result<Vec<advisory::Model>, Error> {
    Ok(advisory::Entity::find()
        .filter(advisory::Column::Id.is_in(ids.iter().copied()))
        .all(connection)
        .await?)
}

/// Batch loads advisory_vulnerability models for the given advisory IDs.
async fn load_advisory_vulnerabilities(
    advisory_ids: &[Uuid],
    connection: &impl ConnectionTrait,
) -> Result<Vec<advisory_vulnerability::Model>, Error> {
    Ok(advisory_vulnerability::Entity::find()
        .filter(advisory_vulnerability::Column::AdvisoryId.is_in(advisory_ids.iter().copied()))
        .all(connection)
        .await?)
}

/// Batch loads vulnerability models by ID.
async fn load_vulnerabilities(
    ids: &[String],
    connection: &impl ConnectionTrait,
) -> Result<Vec<vulnerability::Model>, Error> {
    Ok(vulnerability::Entity::find()
        .filter(vulnerability::Column::Id.is_in(ids.iter().cloned()))
        .all(connection)
        .await?)
}

/// Batch loads advisory_vulnerability_score models for the given advisory IDs.
async fn load_scores(
    advisory_ids: &[Uuid],
    connection: &impl ConnectionTrait,
) -> Result<Vec<advisory_vulnerability_score::Model>, Error> {
    Ok(advisory_vulnerability_score::Entity::find()
        .filter(
            advisory_vulnerability_score::Column::AdvisoryId.is_in(advisory_ids.iter().copied()),
        )
        .all(connection)
        .await?)
}

/// Batch loads CPE models by ID.
async fn load_cpes(
    ids: &HashSet<Uuid>,
    connection: &impl ConnectionTrait,
) -> Result<Vec<cpe::Model>, Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    Ok(cpe::Entity::find()
        .filter(cpe::Column::Id.is_in(ids.iter().copied()))
        .all(connection)
        .await?)
}

/// Batch loads remediations linked to a set of purl_status IDs.
async fn load_purl_remediations(
    purl_status_ids: &HashSet<Uuid>,
    connection: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, Vec<RemediationSummary>>, Error> {
    if purl_status_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let links = remediation_purl_status::Entity::find()
        .filter(
            remediation_purl_status::Column::PurlStatusId.is_in(purl_status_ids.iter().copied()),
        )
        .all(connection)
        .await?;

    if links.is_empty() {
        return Ok(HashMap::new());
    }

    let remediation_ids: Vec<Uuid> = links.iter().map(|l| l.remediation_id).collect();
    let remediations = remediation::Entity::find()
        .filter(remediation::Column::Id.is_in(remediation_ids))
        .all(connection)
        .await?;

    let rem_map: HashMap<Uuid, remediation::Model> =
        remediations.into_iter().map(|r| (r.id, r)).collect();

    let mut result: HashMap<Uuid, Vec<RemediationSummary>> = HashMap::new();
    for link in links {
        if let Some(rem) = rem_map.get(&link.remediation_id) {
            result
                .entry(link.purl_status_id)
                .or_default()
                .push(RemediationSummary {
                    id: rem.id,
                    category: rem.category.clone(),
                    details: rem.details.clone(),
                    url: rem.url.clone(),
                    data: rem.data.clone(),
                });
        }
    }

    Ok(result)
}

/// Converts in-memory VersionRangeData to the API VersionRange model.
fn version_range_to_api(vr: &VersionRangeData) -> Option<VersionRange> {
    match (&vr.low_version, &vr.high_version) {
        (Some(low), Some(high)) => Some(VersionRange::Full {
            version_scheme_id: vr.version_scheme.to_string(),
            low_version: low.to_string(),
            low_inclusive: vr.low_inclusive,
            high_version: high.to_string(),
            high_inclusive: vr.high_inclusive,
        }),
        (Some(low), None) => Some(VersionRange::Left {
            version_scheme_id: vr.version_scheme.to_string(),
            low_version: low.to_string(),
            low_inclusive: vr.low_inclusive,
        }),
        (None, Some(high)) => Some(VersionRange::Right {
            version_scheme_id: vr.version_scheme.to_string(),
            high_version: high.to_string(),
            high_inclusive: vr.high_inclusive,
        }),
        (None, None) => Some(VersionRange::Unbounded),
    }
}

/// Hydrates in-memory correlation matches into the AnalysisResponseV3 API response.
///
/// Filters to only "affected" and "under_investigation" statuses, then batch-loads
/// advisory/vulnerability/score/CPE/remediation metadata from the database.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
pub async fn hydrate_analysis(
    matches: HashMap<String, Vec<PurlCorrelationMatch>>,
    statuses: &HashMap<Uuid, Arc<str>>,
    connection: &impl ConnectionTrait,
) -> Result<AnalysisResponseV3, Error> {
    // Collect unique IDs across all matches for batch queries
    let mut advisory_ids = HashSet::new();
    let mut vuln_ids = HashSet::new();
    let mut cpe_ids = HashSet::new();
    let mut purl_status_ids = HashSet::new();

    for purl_matches in matches.values() {
        for m in purl_matches {
            let status_slug = statuses.get(&m.status_id);
            let is_relevant = status_slug
                .is_some_and(|s| s.as_ref() == "affected" || s.as_ref() == "under_investigation");
            if !is_relevant {
                continue;
            }
            advisory_ids.insert(m.advisory_id);
            vuln_ids.insert(m.vulnerability_id.as_ref().to_string());
            if let Some(id) = m.purl_status_id {
                purl_status_ids.insert(id);
            }
            if let Some(cpe_id) = m.context_cpe_id {
                cpe_ids.insert(cpe_id);
            }
        }
    }

    let advisory_id_vec: Vec<Uuid> = advisory_ids.into_iter().collect();
    let vuln_id_vec: Vec<String> = vuln_ids.into_iter().collect();

    // Batch load all needed entities
    let (advisory_models, av_models, vuln_models, score_models, cpe_models, remediation_map) = tokio::try_join!(
        load_advisories(&advisory_id_vec, connection),
        load_advisory_vulnerabilities(&advisory_id_vec, connection),
        load_vulnerabilities(&vuln_id_vec, connection),
        load_scores(&advisory_id_vec, connection),
        load_cpes(&cpe_ids, connection),
        load_purl_remediations(&purl_status_ids, connection),
    )?;

    // Build lookup maps
    let advisory_heads = AdvisoryHead::from_entities(&advisory_models, connection).await?;
    let advisory_head_map: HashMap<Uuid, AdvisoryHead> = advisory_models
        .iter()
        .zip(advisory_heads)
        .map(|(model, head)| (model.id, head))
        .collect();

    let av_map: HashMap<(Uuid, String), advisory_vulnerability::Model> = av_models
        .into_iter()
        .map(|av| ((av.advisory_id, av.vulnerability_id.clone()), av))
        .collect();

    let vuln_map: HashMap<String, vulnerability::Model> =
        vuln_models.into_iter().map(|v| (v.id.clone(), v)).collect();

    let mut score_map: HashMap<(Uuid, String), Vec<advisory_vulnerability_score::Model>> =
        HashMap::new();
    for score in score_models {
        score_map
            .entry((score.advisory_id, score.vulnerability_id.clone()))
            .or_default()
            .push(score);
    }

    let cpe_map: HashMap<Uuid, cpe::Model> = cpe_models.into_iter().map(|c| (c.id, c)).collect();

    // Build the response grouped by input PURL
    let mut response = BTreeMap::new();

    for (purl_str, purl_matches) in &matches {
        // Group this PURL's matches by vulnerability_id
        let mut vuln_groups: BTreeMap<String, Vec<&PurlCorrelationMatch>> = BTreeMap::new();

        for m in purl_matches {
            let status_slug = statuses.get(&m.status_id);
            let is_relevant = status_slug
                .is_some_and(|s| s.as_ref() == "affected" || s.as_ref() == "under_investigation");
            if !is_relevant {
                continue;
            }
            vuln_groups
                .entry(m.vulnerability_id.as_ref().to_string())
                .or_default()
                .push(m);
        }

        let mut details = Vec::with_capacity(vuln_groups.len());

        for (vuln_id, vuln_matches) in vuln_groups {
            let vuln = match vuln_map.get(&vuln_id) {
                Some(v) => v,
                None => continue,
            };

            // Build purl_statuses from all matches for this vulnerability
            let mut purl_statuses = Vec::with_capacity(vuln_matches.len());

            for m in &vuln_matches {
                let av_key = (m.advisory_id, vuln_id.clone());
                let av = match av_map.get(&av_key) {
                    Some(av) => av,
                    None => continue,
                };

                let advisory_head = match advisory_head_map.get(&m.advisory_id) {
                    Some(h) => h.clone(),
                    None => continue,
                };

                let scores: Vec<advisory_vulnerability_score::Model> =
                    score_map.get(&av_key).cloned().unwrap_or_default();

                let status_slug = statuses
                    .get(&m.status_id)
                    .map(|s| s.as_ref().to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                let context_cpe = m
                    .context_cpe_id
                    .and_then(|id| cpe_map.get(&id).map(|c| c.to_string()));

                let version_range = m.version_range.as_ref().and_then(version_range_to_api);

                let vuln_head = VulnerabilityHead::from_advisory_vulnerability_entity(av, vuln);

                let purl_status = PurlStatus::from_head(
                    vuln_head,
                    advisory_head,
                    status_slug,
                    version_range,
                    context_cpe,
                    &scores,
                )?;

                let remediations = m
                    .purl_status_id
                    .and_then(|id| remediation_map.get(&id))
                    .cloned()
                    .unwrap_or_default();

                purl_statuses.push(AnalysisPurlStatus {
                    purl_status,
                    remediations,
                });
            }

            if !purl_statuses.is_empty() {
                let head = VulnerabilityHead::from_vulnerability_entity_and_description(vuln, None);
                details.push(AnalysisDetailsV3 {
                    head,
                    purl_statuses,
                });
            }
        }

        response.insert(
            purl_str.clone(),
            AnalysisResultV3 {
                details,
                warnings: Vec::new(),
            },
        );
    }

    Ok(AnalysisResponseV3(response))
}

/// Hydrates in-memory PURL correlation matches into `Vec<PurlAdvisory>`.
///
/// Groups matches by advisory_id, builds PurlStatus entries with batch-loaded
/// advisory/vulnerability/score/CPE metadata, and returns the advisory list
/// for a single PURL's details response.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
pub async fn hydrate_purl_advisories(
    matches: Vec<PurlCorrelationMatch>,
    statuses: &HashMap<Uuid, Arc<str>>,
    connection: &impl ConnectionTrait,
) -> Result<Vec<PurlAdvisory>, Error> {
    if matches.is_empty() {
        return Ok(Vec::new());
    }

    let mut advisory_ids = HashSet::new();
    let mut vuln_ids = HashSet::new();
    let mut cpe_ids = HashSet::new();

    for m in &matches {
        advisory_ids.insert(m.advisory_id);
        vuln_ids.insert(m.vulnerability_id.as_ref().to_string());
        if let Some(cpe_id) = m.context_cpe_id {
            cpe_ids.insert(cpe_id);
        }
    }

    let advisory_id_vec: Vec<Uuid> = advisory_ids.into_iter().collect();
    let vuln_id_vec: Vec<String> = vuln_ids.into_iter().collect();

    let (advisory_models, av_models, vuln_models, score_models, cpe_models) = tokio::try_join!(
        load_advisories(&advisory_id_vec, connection),
        load_advisory_vulnerabilities(&advisory_id_vec, connection),
        load_vulnerabilities(&vuln_id_vec, connection),
        load_scores(&advisory_id_vec, connection),
        load_cpes(&cpe_ids, connection),
    )?;

    let advisory_heads = AdvisoryHead::from_entities(&advisory_models, connection).await?;
    let advisory_head_map: HashMap<Uuid, AdvisoryHead> = advisory_models
        .iter()
        .zip(advisory_heads)
        .map(|(model, head)| (model.id, head))
        .collect();

    let av_map: HashMap<(Uuid, String), advisory_vulnerability::Model> = av_models
        .into_iter()
        .map(|av| ((av.advisory_id, av.vulnerability_id.clone()), av))
        .collect();

    let vuln_map: HashMap<String, vulnerability::Model> =
        vuln_models.into_iter().map(|v| (v.id.clone(), v)).collect();

    let mut score_map: HashMap<(Uuid, String), Vec<advisory_vulnerability_score::Model>> =
        HashMap::new();
    for score in score_models {
        score_map
            .entry((score.advisory_id, score.vulnerability_id.clone()))
            .or_default()
            .push(score);
    }

    let cpe_map: HashMap<Uuid, cpe::Model> = cpe_models.into_iter().map(|c| (c.id, c)).collect();

    // Group matches by advisory_id
    let mut advisory_groups: BTreeMap<Uuid, Vec<&PurlCorrelationMatch>> = BTreeMap::new();
    for m in &matches {
        advisory_groups.entry(m.advisory_id).or_default().push(m);
    }

    let mut result = Vec::with_capacity(advisory_groups.len());

    for (advisory_id, group) in advisory_groups {
        let head = match advisory_head_map.get(&advisory_id) {
            Some(head) => head.clone(),
            None => continue,
        };

        let mut purl_statuses = Vec::with_capacity(group.len());

        for m in group {
            let av_key = (advisory_id, m.vulnerability_id.as_ref().to_string());
            let av = match av_map.get(&av_key) {
                Some(av) => av,
                None => continue,
            };
            let vuln = match vuln_map.get(m.vulnerability_id.as_ref()) {
                Some(v) => v,
                None => continue,
            };

            let scores: Vec<advisory_vulnerability_score::Model> =
                score_map.get(&av_key).cloned().unwrap_or_default();

            let status_slug = statuses
                .get(&m.status_id)
                .map(|s| s.as_ref().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let context_cpe = m
                .context_cpe_id
                .and_then(|id| cpe_map.get(&id).map(|c| c.to_string()));

            let version_range = m.version_range.as_ref().and_then(version_range_to_api);

            let vuln_head = VulnerabilityHead::from_advisory_vulnerability_entity(av, vuln);

            let purl_status = PurlStatus::from_head(
                vuln_head,
                head.clone(),
                status_slug,
                version_range,
                context_cpe,
                &scores,
            )?;

            purl_statuses.push(purl_status);
        }

        result.push(PurlAdvisory {
            head,
            status: purl_statuses,
        });
    }

    Ok(result)
}

/// Formats a VersionRangeData as a display string for VulnerabilityAdvisoryStatus.
fn format_version_range(vr: &VersionRangeData) -> String {
    fn open_delim(incl: bool) -> char {
        if incl { '[' } else { '(' }
    }
    fn close_delim(incl: bool) -> char {
        if incl { ']' } else { ')' }
    }

    match (&vr.low_version, &vr.high_version) {
        (Some(low), Some(high)) if low == high => low.to_string(),
        (Some(low), Some(high)) => {
            format!(
                "{}{},{}{}",
                open_delim(vr.low_inclusive),
                low,
                high,
                close_delim(vr.high_inclusive)
            )
        }
        (Some(low), None) => {
            format!(
                "{}{},{}",
                open_delim(vr.low_inclusive),
                low,
                close_delim(vr.high_inclusive)
            )
        }
        (None, Some(high)) => {
            format!(
                "{},{}{}",
                open_delim(vr.low_inclusive),
                high,
                close_delim(vr.high_inclusive)
            )
        }
        (None, None) => "*".to_string(),
    }
}

/// Batch loads sbom models by SBOM ID.
async fn load_sboms(
    sbom_ids: &[Uuid],
    connection: &impl ConnectionTrait,
) -> Result<Vec<sbom::Model>, Error> {
    if sbom_ids.is_empty() {
        return Ok(Vec::new());
    }
    Ok(sbom::Entity::find()
        .filter(sbom::Column::SbomId.is_in(sbom_ids.iter().copied()))
        .all(connection)
        .await?)
}

/// Batch loads the describing sbom_node for each sbom (sbom_node.node_id = sbom.node_id).
async fn load_describing_sbom_nodes(
    sbom_models: &[sbom::Model],
    connection: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, sbom_node::Model>, Error> {
    if sbom_models.is_empty() {
        return Ok(HashMap::new());
    }

    let mut condition = Condition::any();
    for s in sbom_models {
        condition = condition.add(
            Condition::all()
                .add(sbom_node::Column::SbomId.eq(s.sbom_id))
                .add(sbom_node::Column::NodeId.eq(&s.node_id)),
        );
    }

    let nodes = sbom_node::Entity::find()
        .filter(condition)
        .all(connection)
        .await?;

    let node_map: HashMap<Uuid, sbom_node::Model> =
        nodes.into_iter().map(|n| (n.sbom_id, n)).collect();

    Ok(node_map)
}

/// Batch counts packages per SBOM.
async fn load_package_counts(
    sbom_ids: &[Uuid],
    connection: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, u64>, Error> {
    if sbom_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let counts: Vec<(Uuid, i64)> = sbom_package::Entity::find()
        .filter(sbom_package::Column::SbomId.is_in(sbom_ids.iter().copied()))
        .select_only()
        .column(sbom_package::Column::SbomId)
        .column_as(Expr::col(sbom_package::Column::NodeId).count(), "count")
        .group_by(sbom_package::Column::SbomId)
        .into_tuple()
        .all(connection)
        .await?;

    Ok(counts
        .into_iter()
        .map(|(id, count)| (id, count as u64))
        .collect())
}

/// Batch loads the describing package version per SBOM.
async fn load_describing_versions(
    sbom_ids: &[Uuid],
    connection: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, Option<String>>, Error> {
    if sbom_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let results: Vec<(Uuid, Option<String>)> = package_relates_to_package::Entity::find()
        .join(
            JoinType::Join,
            package_relates_to_package::Relation::RightPackage.def(),
        )
        .filter(package_relates_to_package::Column::SbomId.is_in(sbom_ids.iter().copied()))
        .filter(package_relates_to_package::Column::Relationship.eq(Relationship::Describes))
        .select_only()
        .column(package_relates_to_package::Column::SbomId)
        .column(sbom_package::Column::Version)
        .into_tuple()
        .all(connection)
        .await?;

    let mut map = HashMap::with_capacity(results.len());
    for (sbom_id, version) in results {
        map.entry(sbom_id).or_insert(version);
    }
    Ok(map)
}

/// Batch counts advisory_vulnerability entries per advisory.
async fn load_advisory_vuln_counts(
    advisory_ids: &[Uuid],
    connection: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, u64>, Error> {
    if advisory_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let counts: Vec<(Uuid, i64)> = advisory_vulnerability::Entity::find()
        .filter(advisory_vulnerability::Column::AdvisoryId.is_in(advisory_ids.iter().copied()))
        .select_only()
        .column(advisory_vulnerability::Column::AdvisoryId)
        .column_as(
            Expr::col(advisory_vulnerability::Column::VulnerabilityId).count(),
            "count",
        )
        .group_by(advisory_vulnerability::Column::AdvisoryId)
        .into_tuple()
        .all(connection)
        .await?;

    Ok(counts
        .into_iter()
        .map(|(id, count)| (id, count as u64))
        .collect())
}

/// Builds an SbomHead from batch-loaded components, avoiding N+1 COUNT queries.
fn build_sbom_head_from_parts(
    sbom_model: &sbom::Model,
    sbom_node_model: &sbom_node::Model,
    package_count: u64,
) -> SbomHead {
    SbomHead {
        id: sbom_model.sbom_id,
        document_id: sbom_model.document_id.clone(),
        labels: sbom_model.labels.clone(),
        published: sbom_model.published,
        authors: sbom_model.authors.clone(),
        suppliers: sbom_model.suppliers.clone(),
        name: sbom_node_model.name.clone(),
        data_licenses: sbom_model.data_licenses.clone(),
        number_of_packages: package_count,
    }
}

/// Hydrates in-memory vulnerability correlation matches into VulnerabilityAdvisorySummary entries.
///
/// Groups matches by advisory, builds per-SBOM status entries with batch-loaded
/// metadata (sbom heads, package counts, describing versions). Falls back to
/// purl-level data from the index when no SBOM matches exist.
#[allow(deprecated)]
#[instrument(skip_all, err(level = tracing::Level::INFO))]
pub async fn hydrate_vulnerability_advisories(
    _vulnerability: &vulnerability::Model,
    advisory_vulnerabilities: &[advisory_vulnerability::Model],
    vuln_scores: &[advisory_vulnerability_score::Model],
    matches: Vec<VulnCorrelationMatch>,
    vuln_entries: &[VulnIndexEntry],
    statuses: &HashMap<Uuid, Arc<str>>,
    connection: &impl ConnectionTrait,
) -> Result<Vec<VulnerabilityAdvisorySummary>, Error> {
    let advisory_ids: Vec<Uuid> = advisory_vulnerabilities
        .iter()
        .map(|av| av.advisory_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let sbom_ids: Vec<Uuid> = matches
        .iter()
        .map(|m| m.sbom_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let mut cpe_ids = HashSet::new();
    for m in &matches {
        if let Some(cpe_id) = m.context_cpe_id {
            cpe_ids.insert(cpe_id);
        }
    }
    if matches.is_empty() {
        for entry in vuln_entries {
            if let Some(cpe_id) = entry.context_cpe_id {
                cpe_ids.insert(cpe_id);
            }
        }
    }

    // Batch load advisory metadata, SBOM data, and CPEs in parallel
    let (advisory_models, vuln_counts, cpe_models, sbom_models, pkg_counts, describing_versions) =
        tokio::try_join!(
            load_advisories(&advisory_ids, connection),
            load_advisory_vuln_counts(&advisory_ids, connection),
            load_cpes(&cpe_ids, connection),
            load_sboms(&sbom_ids, connection),
            load_package_counts(&sbom_ids, connection),
            load_describing_versions(&sbom_ids, connection),
        )?;

    // Load sbom_nodes (composite key lookup depends on sbom models)
    let sbom_node_map = load_describing_sbom_nodes(&sbom_models, connection).await?;

    // Build advisory heads
    let advisory_heads = AdvisoryHead::from_entities(&advisory_models, connection).await?;
    let advisory_head_map: HashMap<Uuid, AdvisoryHead> = advisory_models
        .iter()
        .zip(advisory_heads)
        .map(|(model, head)| (model.id, head))
        .collect();

    let sbom_map: HashMap<Uuid, &sbom::Model> =
        sbom_models.iter().map(|s| (s.sbom_id, s)).collect();

    let cpe_map: HashMap<Uuid, cpe::Model> = cpe_models.into_iter().map(|c| (c.id, c)).collect();

    // Group scores by advisory_id
    let mut score_map: HashMap<Uuid, Vec<advisory_vulnerability_score::Model>> = HashMap::new();
    for score in vuln_scores {
        score_map
            .entry(score.advisory_id)
            .or_default()
            .push(score.clone());
    }

    // Group SBOM matches: advisory_id → sbom_id → (status_slug → PurlSummary set)
    let mut advisory_sbom_groups: HashMap<
        Uuid,
        HashMap<Uuid, HashMap<String, HashSet<PurlSummary>>>,
    > = HashMap::new();

    for m in &matches {
        let status_slug = statuses
            .get(&m.status_id)
            .map(|s| s.as_ref().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let purl = Purl {
            ty: m.purl_key.ty.to_string(),
            namespace: m.purl_key.namespace.as_ref().map(|ns| ns.to_string()),
            name: m.purl_key.name.to_string(),
            version: Some(m.version.to_string()),
            qualifiers: Default::default(),
        };

        advisory_sbom_groups
            .entry(m.advisory_id)
            .or_default()
            .entry(m.sbom_id)
            .or_default()
            .entry(status_slug)
            .or_default()
            .insert(PurlSummary::from(purl));
    }

    // Build the purl fallback data (only when no SBOM matches exist)
    let purl_fallback: HashMap<Uuid, HashMap<String, Vec<VulnerabilityAdvisoryStatus>>> =
        if matches.is_empty() {
            build_purl_fallback(vuln_entries, statuses, &cpe_map)
        } else {
            HashMap::new()
        };

    // Assemble VulnerabilityAdvisorySummary per advisory
    let mut summaries = Vec::with_capacity(advisory_vulnerabilities.len());

    for av in advisory_vulnerabilities {
        let head = match advisory_head_map.get(&av.advisory_id) {
            Some(h) => h.clone(),
            None => continue,
        };

        let scores: Vec<ScoredVector> = score_map
            .get(&av.advisory_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(ScoredVector::from)
            .collect();

        let number_of_vulnerabilities = vuln_counts.get(&av.advisory_id).copied().unwrap_or(0);

        // Build SBOM statuses from correlation matches
        let sboms = if let Some(sbom_groups) = advisory_sbom_groups.get(&av.advisory_id) {
            let mut sbom_statuses = Vec::with_capacity(sbom_groups.len());
            for (&sid, purl_groups) in sbom_groups {
                let (Some(sm), Some(sn)) = (sbom_map.get(&sid), sbom_node_map.get(&sid)) else {
                    continue;
                };
                let pkg_count = pkg_counts.get(&sid).copied().unwrap_or(0);
                let version = describing_versions.get(&sid).cloned().flatten();

                sbom_statuses.push(VulnerabilitySbomStatus {
                    head: build_sbom_head_from_parts(sm, sn, pkg_count),
                    version,
                    purl_statuses: purl_groups.clone(),
                });
            }
            sbom_statuses
        } else {
            Vec::new()
        };

        let purls = purl_fallback
            .get(&av.advisory_id)
            .cloned()
            .unwrap_or_default();

        summaries.push(VulnerabilityAdvisorySummary {
            head: VulnerabilityAdvisoryHead { head, scores },
            purls,
            sboms,
            number_of_vulnerabilities,
        });
    }

    Ok(summaries)
}

/// Builds VulnerabilityAdvisoryStatus entries from raw index data for the purl fallback.
///
/// Used when correlate_vulnerability() finds no SBOM matches, replicating
/// the legacy behavior of showing raw purl status claims.
fn build_purl_fallback(
    vuln_entries: &[VulnIndexEntry],
    statuses: &HashMap<Uuid, Arc<str>>,
    cpe_map: &HashMap<Uuid, cpe::Model>,
) -> HashMap<Uuid, HashMap<String, Vec<VulnerabilityAdvisoryStatus>>> {
    let mut result: HashMap<Uuid, HashMap<String, Vec<VulnerabilityAdvisoryStatus>>> =
        HashMap::new();

    for entry in vuln_entries {
        let VulnEntrySource::Purl {
            purl_key,
            version_range,
        } = &entry.source
        else {
            continue;
        };

        let status_slug = statuses
            .get(&entry.status_id)
            .map(|s| s.as_ref().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let base_purl = Purl {
            ty: purl_key.ty.to_string(),
            namespace: purl_key.namespace.as_ref().map(|ns| ns.to_string()),
            name: purl_key.name.to_string(),
            version: None,
            qualifiers: Default::default(),
        };

        let context = entry.context_cpe_id.and_then(|cpe_id| {
            cpe_map
                .get(&cpe_id)
                .map(|c| StatusContext::Cpe(c.to_string()))
        });

        result
            .entry(entry.advisory_id)
            .or_default()
            .entry(status_slug)
            .or_default()
            .push(VulnerabilityAdvisoryStatus {
                base_purl: BasePurlHead {
                    uuid: base_purl.package_uuid(),
                    purl: base_purl,
                },
                version: format_version_range(version_range),
                context,
            });
    }

    result
}

/// Hydrates recommend matches into RecommendEntry values.
///
/// For each winner PURL string, resolves vulnerability IDs, status slugs, and
/// remediations from the database. Deduplicates by vulnerability, keeping the
/// match from the most recently modified advisory.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
pub async fn hydrate_recommend_matches(
    matches_by_purl: HashMap<String, Vec<PurlCorrelationMatch>>,
    statuses: &HashMap<Uuid, Arc<str>>,
    connection: &impl ConnectionTrait,
) -> Result<HashMap<String, Vec<RecommendEntry>>, Error> {
    let mut result = HashMap::with_capacity(matches_by_purl.len());

    let all_matches: Vec<&PurlCorrelationMatch> =
        matches_by_purl.values().flat_map(|v| v.iter()).collect();

    if all_matches.is_empty() {
        for key in matches_by_purl.keys() {
            result.insert(key.clone(), Vec::new());
        }
        return Ok(result);
    }

    let mut advisory_ids = HashSet::new();
    let mut purl_status_ids = HashSet::new();
    for m in &all_matches {
        advisory_ids.insert(m.advisory_id);
        if let Some(id) = m.purl_status_id {
            purl_status_ids.insert(id);
        }
    }

    let advisory_id_vec: Vec<Uuid> = advisory_ids.into_iter().collect();

    let (advisory_models, remediation_map) = tokio::try_join!(
        load_advisories(&advisory_id_vec, connection),
        load_purl_remediations(&purl_status_ids, connection),
    )?;

    let advisory_date_map: HashMap<Uuid, Option<time::OffsetDateTime>> = advisory_models
        .into_iter()
        .map(|a| (a.id, a.modified.or(a.published)))
        .collect();

    for (purl_string, matches) in &matches_by_purl {
        if matches.is_empty() {
            result.insert(purl_string.clone(), Vec::new());
            continue;
        }

        // Dedup by vulnerability: keep match from most recent advisory
        let mut best_by_vuln: HashMap<&str, &PurlCorrelationMatch> = HashMap::new();
        for m in matches {
            best_by_vuln
                .entry(m.vulnerability_id.as_ref())
                .and_modify(|existing| {
                    let existing_date = advisory_date_map
                        .get(&existing.advisory_id)
                        .copied()
                        .flatten();
                    let new_date = advisory_date_map.get(&m.advisory_id).copied().flatten();
                    if new_date > existing_date {
                        *existing = m;
                    }
                })
                .or_insert(m);
        }

        let vulnerabilities = best_by_vuln
            .into_values()
            .map(|m| {
                let slug = statuses
                    .get(&m.status_id)
                    .map(|s| s.as_ref())
                    .unwrap_or("unknown");

                let vex_status = match slug {
                    "affected" => VexStatus::Affected,
                    "fixed" => VexStatus::Fixed,
                    "not_affected" => VexStatus::NotAffected,
                    "under_investigation" => VexStatus::UnderInvestigation,
                    "recommended" => VexStatus::Recommended,
                    other => VexStatus::Other(other.to_string()),
                };

                let remediations = m
                    .purl_status_id
                    .and_then(|id| remediation_map.get(&id))
                    .cloned()
                    .unwrap_or_default();

                VulnerabilityStatus {
                    id: m.vulnerability_id.as_ref().to_string(),
                    status: Some(vex_status),
                    justification: None,
                    remediations,
                }
            })
            .collect();

        let entry = RecommendEntry {
            package: purl_string.clone(),
            vulnerabilities,
        };

        result.insert(purl_string.clone(), vec![entry]);
    }

    Ok(result)
}
