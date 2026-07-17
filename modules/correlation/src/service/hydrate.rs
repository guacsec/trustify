use crate::Error;
use crate::model::{CorrelationMatch, PurlKey};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tracing::instrument;
use trustify_common::purl::Purl;
use trustify_entity::{
    advisory, advisory_vulnerability, advisory_vulnerability_score, cpe, vulnerability,
};
use trustify_module_fundamental::{
    advisory::model::AdvisoryHead,
    common::model::ScoredVector,
    purl::model::{details::purl::StatusContext, summary::purl::PurlSummary},
    sbom::model::{
        SbomPackage,
        details::{SbomAdvisory, SbomStatus},
    },
    vulnerability::model::VulnerabilityHead,
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
