use crate::{
    graph::{
        Graph,
        advisory::{
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
            version::{Version, VersionInfo, VersionSpec},
        },
        cpe::CpeCreator,
        cpe_status_creator::{CpeStatusCreator, CpeStatusEntry},
        cvss::{ScoreCreator, ScoreInformation},
        vulnerability::{BaseScore, VulnerabilityInformation, creator::VulnerabilityCreator},
    },
    model::IngestResult,
    service::{Error, Warnings, advisory::nvd::schema::*},
};
use cvss::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::collections::HashSet;
use std::fmt::Debug;
use std::str::FromStr;
use time::{
    OffsetDateTime, PrimitiveDateTime, format_description::well_known::Rfc3339,
    macros::format_description,
};
use tracing::instrument;
use trustify_common::{
    cpe::{Component, Cpe},
    hashing::Digests,
};
use trustify_entity::{labels::Labels, version_scheme::VersionScheme};

/// The publisher recorded for NVD-sourced advisories.
const NVD_ISSUER: &str = "NVD";

/// Loader capable of parsing an NVD CVE API 2.0 `cve` record (as republished by the
/// `fkie-cad/nvd-json-data-feeds` mirror) and integrating it into the knowledge base.
///
/// NVD is a supplementary advisory source: its records are stored as their own
/// advisory, linked to the same vulnerability as any CVE-List / CSAF / OSV record.
/// Its value is the rich CPE applicability data (`configurations`), which is mapped
/// to `cpe_status` rows keyed by vendor/product identity plus an affected
/// `version_range`. Unlike the CVE-List path, NVD ranges are stored with the
/// [`VersionScheme::Semver`] scheme so ordered range comparison (not just exact
/// equality) is used at match time.
pub struct NvdLoader<'g> {
    graph: &'g Graph,
}

impl<'g> NvdLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, cve, tx), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        cve: NvdCve,
        digests: &Digests,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::new();
        let id = cve.id.clone();
        let labels = labels.into().add("type", "nvd");

        let published = cve.published.as_deref().and_then(parse_timestamp);
        let modified = cve.last_modified.as_deref().and_then(parse_timestamp);

        let cwes = extract_cwes(&cve.weaknesses);
        let title = None;
        let english_description = find_english_description(&cve.descriptions).map(str::to_string);

        // CVSS scores (parsed from the canonical vector strings).
        let scores = extract_scores(&id, &cve.metrics);
        let base_score = best_base_score(&scores);

        // Upsert the vulnerability. NVD does not claim to be the authoritative
        // advisory for a CVE, so we deliberately do not touch
        // `authoritative_advisory_id` (that is owned by the CVE-List path).
        let mut vuln_creator = VulnerabilityCreator::new();
        vuln_creator.add(
            &id,
            VulnerabilityInformation {
                title: title.clone(),
                reserved: None,
                published,
                modified,
                withdrawn: None,
                cwes: cwes.clone(),
                base_score,
            },
        );
        vuln_creator.create(tx).await?;

        let advisory_info = AdvisoryInformation {
            id: id.clone(),
            title: title.clone(),
            version: None,
            issuer: Some(NVD_ISSUER.to_string()),
            published,
            modified,
            withdrawn: None,
        };

        let advisory = self
            .graph
            .ingest_advisory(&id, labels, digests, advisory_info, tx)
            .await?;

        let advisory_vuln = advisory
            .link_to_vulnerability(
                &id,
                Some(AdvisoryVulnerabilityInformation {
                    title,
                    summary: None,
                    description: english_description.clone(),
                    reserved_date: None,
                    discovery_date: None,
                    release_date: published,
                    cwes,
                }),
                tx,
            )
            .await?;

        let mut score_creator = ScoreCreator::new(advisory.advisory.id);
        score_creator.extend(scores);
        score_creator.create(tx).await?;

        // CPE applicability -> cpe_status.
        let mut cpe_status_creator = CpeStatusCreator::new();
        let mut cpes = HashSet::new();

        for cpe_match in cve
            .configurations
            .iter()
            .flat_map(|c| c.nodes.iter())
            .flat_map(|n| n.cpe_match.iter())
        {
            if !cpe_match.vulnerable {
                continue;
            }

            let cpe = match Cpe::from_str(&cpe_match.criteria) {
                Ok(cpe) => cpe,
                Err(err) => {
                    let msg = format!(
                        "{id}: dropping unparseable CPE criteria {:?}: {err}",
                        cpe_match.criteria
                    );
                    tracing::warn!("{msg}");
                    warnings.add(msg);
                    continue;
                }
            };
            let identity_cpe = cpe.with_any_version();

            let Some(spec) = version_spec(cpe_match, &cpe) else {
                // No version bounds and no concrete version in the criteria (an
                // "all versions" statement). Ordered range matching can't express
                // an unbounded-both-sides range, so this is not modeled yet.
                tracing::debug!(
                    vulnerability = id,
                    criteria = cpe_match.criteria,
                    "skipping unbounded 'all versions' CPE match"
                );
                continue;
            };

            cpes.insert(identity_cpe.clone());
            cpe_status_creator.add(CpeStatusEntry {
                advisory_id: advisory_vuln.advisory.advisory.id,
                vulnerability_id: advisory_vuln
                    .advisory_vulnerability
                    .vulnerability_id
                    .clone(),
                cpe: identity_cpe,
                status: "affected".to_string(),
                version_info: VersionInfo {
                    // NVD version bounds are ordered comparisons; use the semver
                    // scheme so `version_matches` does range (not exact) matching.
                    scheme: VersionScheme::Semver,
                    spec,
                },
                context_cpe: None,
            });
        }

        let mut cpe_creator = CpeCreator::new();
        for cpe in cpes {
            cpe_creator.add(cpe);
        }
        cpe_creator.create(tx).await?;
        cpe_status_creator.create(tx).await?;

        // Manage vulnerability descriptions.
        let entries = build_descriptions(&cve.descriptions);
        Graph::drop_vulnerability_descriptions_for_advisory(advisory.advisory.id, tx).await?;
        Graph::add_vulnerability_descriptions(&id, advisory.advisory.id, entries, tx).await?;

        Ok(IngestResult {
            id: advisory.advisory.id.to_string(),
            document_id: Some(id),
            warnings: warnings.into(),
        })
    }
}

/// Derives the affected version bound for a single `cpeMatch`.
///
/// Returns `None` when the entry carries neither explicit version bounds nor a
/// concrete version in its CPE criteria (i.e. an unbounded "all versions" match).
fn version_spec(cpe_match: &CpeMatch, cpe: &Cpe) -> Option<VersionSpec> {
    let has_bounds = cpe_match.version_start_including.is_some()
        || cpe_match.version_start_excluding.is_some()
        || cpe_match.version_end_including.is_some()
        || cpe_match.version_end_excluding.is_some();

    if has_bounds {
        let low = match (
            &cpe_match.version_start_including,
            &cpe_match.version_start_excluding,
        ) {
            (Some(v), _) => Version::Inclusive(v.clone()),
            (_, Some(v)) => Version::Exclusive(v.clone()),
            _ => Version::Unbounded,
        };
        let high = match (
            &cpe_match.version_end_including,
            &cpe_match.version_end_excluding,
        ) {
            (Some(v), _) => Version::Inclusive(v.clone()),
            (_, Some(v)) => Version::Exclusive(v.clone()),
            _ => Version::Unbounded,
        };
        Some(VersionSpec::Range(low, high))
    } else if let Component::Value(version) = cpe.version() {
        Some(VersionSpec::Exact(version))
    } else {
        None
    }
}

/// Parses all CVSS vectors present in an NVD `metrics` object into [`ScoreInformation`],
/// dispatching per version bucket to the appropriate `cvss-rs` parser.
fn extract_scores(vulnerability_id: &str, metrics: &Metrics) -> Vec<ScoreInformation> {
    let mut scores = Vec::new();

    for m in &metrics.cvss_metric_v40 {
        if let Ok(cvss) = CvssV4::from_str(&m.cvss_data.vector_string) {
            scores.push((vulnerability_id.to_string(), cvss).into());
        }
    }
    // v3.0 and v3.1 share the same parser; the concrete version is read from the vector.
    for m in metrics
        .cvss_metric_v31
        .iter()
        .chain(&metrics.cvss_metric_v30)
    {
        if let Ok(cvss) = CvssV3::from_str(&m.cvss_data.vector_string) {
            scores.push((vulnerability_id.to_string(), cvss).into());
        }
    }
    for m in &metrics.cvss_metric_v2 {
        if let Ok(cvss) = CvssV2::from_str(&m.cvss_data.vector_string) {
            scores.push((vulnerability_id.to_string(), cvss).into());
        }
    }

    scores
}

/// Picks the "best" base score to represent the vulnerability: the highest score type
/// (newest CVSS version), and within a type the highest numeric score.
fn best_base_score(scores: &[ScoreInformation]) -> Option<BaseScore> {
    scores
        .iter()
        .max_by(|a, b| {
            a.r#type.cmp(&b.r#type).then(
                a.score
                    .partial_cmp(&b.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        })
        .map(|s| BaseScore {
            r#type: s.r#type,
            score: s.score as f64,
            severity: s.severity,
        })
}

/// Collects `CWE-<n>` identifiers from NVD `weaknesses`, ignoring the placeholder
/// `NVD-CWE-noinfo` / `NVD-CWE-Other` markers. Returns `None` if none are present.
fn extract_cwes(weaknesses: &[Weakness]) -> Option<Vec<String>> {
    let cwes: Vec<String> = weaknesses
        .iter()
        .flat_map(|w| w.description.iter())
        .map(|d| d.value.clone())
        .filter(|v| v.starts_with("CWE-"))
        .collect();

    if cwes.is_empty() { None } else { Some(cwes) }
}

fn find_english_description(descriptions: &[LangString]) -> Option<&str> {
    descriptions
        .iter()
        .find(|d| matches!(d.lang.as_str(), "en" | "en-US" | "en_US"))
        .map(|d| d.value.as_str())
}

fn build_descriptions(descriptions: &[LangString]) -> Vec<(&str, &str)> {
    descriptions
        .iter()
        .map(|d| (d.lang.as_str(), d.value.as_str()))
        .collect()
}

/// Parses an NVD timestamp. NVD emits UTC timestamps without an offset
/// (e.g. `2024-02-15T10:30:00.000`); RFC 3339 is also accepted defensively.
fn parse_timestamp(s: &str) -> Option<OffsetDateTime> {
    if let Ok(dt) = OffsetDateTime::parse(s, &Rfc3339) {
        return Some(dt);
    }
    let with_sub = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]");
    if let Ok(dt) = PrimitiveDateTime::parse(s, with_sub) {
        return Some(dt.assume_utc());
    }
    let no_sub = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    PrimitiveDateTime::parse(s, no_sub)
        .ok()
        .map(|dt| dt.assume_utc())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::graph::Graph;
    use hex::ToHex;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use test_context::test_context;
    use test_log::test;
    use time::macros::datetime;
    use trustify_entity::{cpe as cpe_entity, cpe_status, status, version_range, version_scheme};
    use trustify_test_context::{TrustifyContext, document};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn nvd_loader_stores_semver_range_cpe_status(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let graph = Graph::new();

        let (cve, digests): (NvdCve, _) = document("nvd/CVE-2099-1000.json").await?;

        let loader = NvdLoader::new(&graph);
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(("file", "CVE-2099-1000.json"), cve.clone(), &digests, tx)
                    .await
            })
            .await?;

        // Vulnerability + advisory were created.
        let vuln = graph.get_vulnerability("CVE-2099-1000", &ctx.db).await?;
        assert!(vuln.is_some(), "vulnerability must be ingested");
        assert_eq!(
            vuln.unwrap().vulnerability.published,
            Some(datetime!(2099-01-02 10:00:00 UTC)),
            "published timestamp must parse from the NVD naive format"
        );

        let advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?
            .expect("advisory must be ingested");

        // Exactly one cpe_status row: the vulnerable application match. The
        // `vulnerable: false` OS entry must be skipped.
        let rows = cpe_status::Entity::find()
            .filter(cpe_status::Column::AdvisoryId.eq(advisory.advisory.id))
            .all(&ctx.db)
            .await?;
        assert_eq!(rows.len(), 1, "expected 1 cpe_status row, got {rows:?}");
        let row = &rows[0];

        // Identity CPE is version-normalized to ANY.
        let cpe = cpe_entity::Entity::find_by_id(row.cpe_id)
            .one(&ctx.db)
            .await?
            .expect("referenced cpe must exist");
        assert_eq!(cpe.vendor.as_deref(), Some("example"));
        assert_eq!(cpe.product.as_deref(), Some("widget"));
        assert_eq!(cpe.version.as_deref(), Some("*"));

        let st = status::Entity::find_by_id(row.status_id)
            .one(&ctx.db)
            .await?
            .expect("status must exist");
        assert_eq!(st.slug, "affected");

        // The critical part: range stored under the `semver` scheme with
        // inclusive-low / exclusive-high bounds so ordered range matching works.
        let vr = version_range::Entity::find_by_id(row.version_range_id)
            .one(&ctx.db)
            .await?
            .expect("version_range must exist");
        assert_eq!(vr.version_scheme_id, version_scheme::VersionScheme::Semver);
        assert_eq!(vr.low_version.as_deref(), Some("1.0.0"));
        assert_eq!(vr.low_inclusive, Some(true));
        assert_eq!(vr.high_version.as_deref(), Some("2.0.0"));
        assert_eq!(vr.high_inclusive, Some(false));

        // Re-ingest must be idempotent (deterministic v5 UUIDs).
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(("file", "CVE-2099-1000.json"), cve, &digests, tx)
                    .await
            })
            .await?;
        let rows_after = cpe_status::Entity::find()
            .filter(cpe_status::Column::AdvisoryId.eq(advisory.advisory.id))
            .all(&ctx.db)
            .await?;
        assert_eq!(rows_after.len(), 1, "re-ingest must not duplicate rows");

        Ok(())
    }
}
