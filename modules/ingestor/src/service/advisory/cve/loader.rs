use crate::{
    graph::{
        Graph,
        advisory::{
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
            version::{Version, VersionInfo, VersionSpec},
        },
        purl::{
            self,
            status_creator::{PurlStatusCreator, PurlStatusEntry},
        },
        vulnerability::{VulnerabilityInformation, creator::VulnerabilityCreator},
    },
    model::IngestResult,
    service::{Error, Warnings, advisory::cve::divination::divine_purl},
};
use cve::{
    Cve, Timestamp,
    common::{Description, Product, Status, VersionRange},
};
use sea_orm::TransactionTrait;
use serde_json::Value;
use std::{collections::HashSet, fmt::Debug, str::FromStr};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{hashing::Digests, id::Id};
use trustify_cvss::cvss3::{Cvss3Base, score::Score, severity::Severity};
use trustify_entity::{labels::Labels, version_scheme::VersionScheme};

/// Loader capable of parsing a CVE Record JSON file
/// and manipulating the Graph to integrate it into
/// the knowledge base.
///
/// Should result in ensuring that a *vulnerability*
/// related to the CVE Record exists in the fetch, _along with_
/// also ensuring that the CVE *advisory* ends up also
/// in the fetch.
pub struct CveLoader<'g> {
    graph: &'g Graph,
}

impl<'g> CveLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, cve), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        cve: Cve,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::new();
        let id = cve.id();
        let labels = labels.into().add("type", "cve");

        let tx = self.graph.db.begin().await?;

        let VulnerabilityDetails {
            org_name,
            descriptions,
            assigned,
            affected,
            information,
            scores,
        } = Self::extract_vuln_info(&cve);

        let cwes = information.cwes.clone();
        let release_date = information.published;
        let reserved_date = information.reserved;
        let title = information.title.clone();
        let advisory_info = AdvisoryInformation {
            id: id.to_string(),
            title: information.title.clone(),
            // TODO: check if we have some kind of version information
            version: None,
            issuer: org_name.map(ToString::to_string),
            published: information.published,
            modified: information.modified,
            withdrawn: information.withdrawn,
        };

        // Batch create vulnerability (single entry for CVE, but using creator for consistency)
        let mut vuln_creator = VulnerabilityCreator::new();
        vuln_creator.add(id, information.clone());
        vuln_creator.create(&tx).await?;

        let entries = Self::build_descriptions(descriptions);
        let english_description = Self::find_best_description_for_title(descriptions);

        let advisory = self
            .graph
            .ingest_advisory(id, labels, digests, advisory_info, &tx)
            .await?;

        // Link the advisory to the backing vulnerability
        let advisory_vuln = advisory
            .link_to_vulnerability(
                id,
                Some(AdvisoryVulnerabilityInformation {
                    title,
                    summary: None,
                    description: english_description.map(ToString::to_string),
                    reserved_date,
                    discovery_date: assigned,
                    release_date,
                    cwes,
                }),
                &tx,
            )
            .await?;

        if !scores.is_empty() {
            for score in scores {
                advisory_vuln.ingest_cvss3_score(score, &tx).await?;
            }
        }

        // Initialize batch creator for efficient status ingestion
        let mut purl_status_creator = PurlStatusCreator::new();
        let mut base_purls = HashSet::new();

        if let Some(affected) = affected {
            for product in affected {
                if let Some(purl) = divine_purl(product) {
                    // Collect base PURL for batch creation
                    base_purls.insert(purl.clone());

                    // okay! we have a purl, now
                    // sort out version bounds & status
                    for version in &product.versions {
                        let (version_spec, version_type, status) = match version {
                            cve::common::Version::Single(version) => (
                                VersionSpec::Exact(version.version.clone()),
                                version.version_type.clone(),
                                &version.status,
                            ),
                            cve::common::Version::Range(range) => match &range.range {
                                VersionRange::LessThan(upper) => (
                                    VersionSpec::Range(
                                        Version::Inclusive(range.version.clone()),
                                        Version::Exclusive(upper.clone()),
                                    ),
                                    Some(range.version_type.clone()),
                                    &range.status,
                                ),
                                VersionRange::LessThanOrEqual(upper) => (
                                    VersionSpec::Range(
                                        Version::Inclusive(range.version.clone()),
                                        Version::Inclusive(upper.clone()),
                                    ),
                                    Some(range.version_type.clone()),
                                    &range.status,
                                ),
                            },
                        };

                        // Add package status entry to batch creator
                        purl_status_creator.add(PurlStatusEntry {
                            advisory_id: advisory_vuln.advisory.advisory.id,
                            vulnerability_id: advisory_vuln
                                .advisory_vulnerability
                                .vulnerability_id
                                .clone(),
                            purl: purl.clone(),
                            status: match status {
                                Status::Affected => "affected".to_string(),
                                Status::Unaffected => "not_affected".to_string(),
                                Status::Unknown => "unknown".to_string(),
                            },
                            version_info: VersionInfo {
                                scheme: version_type
                                    .as_deref()
                                    .map(VersionScheme::from)
                                    .unwrap_or(VersionScheme::Generic),
                                spec: version_spec,
                            },
                            context_cpe: None,
                        });
                    }
                }
            }
        }

        // Batch create base PURLs (without versions/qualifiers)
        purl::batch_create_base_purls(base_purls, &tx).await?;

        // Batch create statuses
        purl_status_creator.create(&tx).await?;

        // Manage vulnerability descriptions without needing to query the vulnerability
        Graph::drop_vulnerability_descriptions_for_advisory(advisory.advisory.id, &tx).await?;
        Graph::add_vulnerability_descriptions(id, advisory.advisory.id, entries, &tx).await?;

        tx.commit().await?;

        Ok(IngestResult {
            id: Id::Uuid(advisory.advisory.id),
            document_id: Some(id.to_string()),
            warnings: warnings.into(),
        })
    }

    /// Build descriptions
    fn build_descriptions(descriptions: &[Description]) -> Vec<(&str, &str)> {
        descriptions
            .iter()
            .map(|desc| (desc.language.as_str(), desc.value.as_str()))
            .collect()
    }

    /// Quicker version to find the best description as an alternative when not having a title.
    fn find_best_description_for_title(descriptions: &[Description]) -> Option<&str> {
        descriptions
            .iter()
            .find(|desc| matches!(desc.language.as_str(), "en-US" | "en_US"))
            .or_else(|| descriptions.iter().find(|desc| desc.language == "en"))
            .map(|desc| desc.value.as_str())
    }

    fn extract_vuln_info(cve: &Cve) -> VulnerabilityDetails<'_> {
        let reserved = cve
            .common_metadata()
            .date_reserved
            .map(Timestamp::assume_utc);
        let published = cve
            .common_metadata()
            .date_published
            .map(Timestamp::assume_utc);
        let modified = cve
            .common_metadata()
            .date_updated
            .map(Timestamp::assume_utc);

        let (title, assigned, withdrawn, descriptions, cwe, org_name, affected) = match &cve {
            Cve::Rejected(rejected) => (
                None,
                None,
                rejected.metadata.date_rejected.map(Timestamp::assume_utc),
                &rejected.containers.cna.rejected_reasons,
                None,
                rejected
                    .containers
                    .cna
                    .common
                    .provider_metadata
                    .short_name
                    .as_deref(),
                None,
            ),
            Cve::Published(published) => (
                published
                    .containers
                    .cna
                    .title
                    .as_deref()
                    .or_else(|| {
                        Self::find_best_description_for_title(
                            &published.containers.cna.descriptions,
                        )
                    })
                    .map(ToString::to_string),
                published
                    .containers
                    .cna
                    .date_assigned
                    .map(Timestamp::assume_utc),
                None,
                &published.containers.cna.descriptions,
                {
                    let cwes = published
                        .containers
                        .cna
                        .problem_types
                        .iter()
                        .flat_map(|pt| pt.descriptions.iter())
                        .flat_map(|desc| desc.cwe_id.clone())
                        .collect::<Vec<_>>();
                    if cwes.is_empty() { None } else { Some(cwes) }
                },
                published
                    .containers
                    .cna
                    .common
                    .provider_metadata
                    .short_name
                    .as_deref(),
                Some(&published.containers.cna.affected),
            ),
        };

        let mut scores = vec![];
        let mut base_score = None;
        let mut base_severity = None;
        if let Cve::Published(published) = cve.clone() {
            let all_metrics = published.containers.cna.metrics.iter().chain(
                published
                    .containers
                    .adp
                    .iter()
                    .flat_map(|adp| adp.metrics.iter()),
            );

            for metric in all_metrics {
                // Set base_score and base_severity to the first found
                // value (where CNA value have a precedence). ADP values are used as fallback.
                //
                // For the vulnerability score we are using the value of the highest CVSS version
                // available.
                //
                // TODO: With https://github.com/guacsec/trustify/issues/1656 we will start
                // saving the type of the score (CNA or ADP) to be able to distinguish between them.

                if let Some(cvss) = metric.cvss_v4_0.as_ref() {
                    (base_score, base_severity) = get_score(cvss);
                }

                if let Some(cvss) = metric.cvss_v3_1.as_ref().or(metric.cvss_v3_0.as_ref()) {
                    if let Some(vector) = cvss.get("vectorString").and_then(|v| v.as_str())
                        && let Ok(cvss3) = Cvss3Base::from_str(vector)
                    {
                        scores.push(cvss3);
                    }

                    if base_score.is_none() {
                        (base_score, base_severity) = get_score(cvss);
                    }
                }

                if let Some(cvss) = metric.cvss_v2_0.as_ref()
                    && base_score.is_none()
                {
                    (base_score, base_severity) = get_score(cvss);
                }
            }
        }

        VulnerabilityDetails {
            org_name,
            descriptions,
            assigned,
            affected,
            information: VulnerabilityInformation {
                title,
                reserved,
                published,
                modified,
                withdrawn,
                cwes: cwe,
                base_score,
                base_severity,
            },
            scores,
        }
    }
}

/// Extracts the base score and severity from a CVSS JSON object.
/// For more information on the CVSS schema, see:
/// https://github.com/CVEProject/cve-schema/tree/main/schema/imports/cvss
fn get_score(cvss: &Value) -> (Option<f64>, Option<trustify_entity::cvss3::Severity>) {
    let base_score = cvss.get("baseScore").and_then(|v| v.as_f64());

    let mut base_severity = cvss
        .get("baseSeverity")
        .and_then(|v| v.as_str())
        .and_then(|s| Severity::from_str(s).ok())
        .map(trustify_entity::cvss3::Severity::from);

    // CVSS v2.0 does not have a baseSeverity field, so we need to calculate it from the score.
    if base_score.is_some() && base_severity.is_none() {
        base_severity = base_score.map(|score| Severity::from(Score::from(score)).into());
    }

    (base_score, base_severity)
}

struct VulnerabilityDetails<'a> {
    pub org_name: Option<&'a str>,
    pub descriptions: &'a Vec<Description>,
    pub assigned: Option<OffsetDateTime>,
    pub affected: Option<&'a Vec<Product>>,
    pub information: VulnerabilityInformation,
    pub scores: Vec<Cvss3Base>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::graph::Graph;
    use hex::ToHex;
    use std::str::FromStr;
    use test_context::test_context;
    use test_log::test;
    use time::macros::datetime;
    use trustify_common::purl::Purl;
    use trustify_test_context::{TrustifyContext, document};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn cve_loader(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());

        let (cve, digests): (Cve, _) = document("mitre/CVE-2024-28111.json").await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", &ctx.db).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = CveLoader::new(&graph);
        loader
            .load(("file", "CVE-2024-28111.json"), cve, &digests)
            .await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", &ctx.db).await?;
        assert!(loaded_vulnerability.is_some());
        let loaded_vulnerability = loaded_vulnerability.unwrap();
        assert_eq!(
            loaded_vulnerability.vulnerability.reserved,
            Some(datetime!(2024-03-04 14:19:14.059 UTC))
        );

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let descriptions = loaded_vulnerability.descriptions("en", &ctx.db).await?;
        assert_eq!(1, descriptions.len());
        assert!(
            descriptions[0]
                .starts_with("Canarytokens helps track activity and actions on a network")
        );

        let loaded_advisory = loaded_advisory.unwrap();
        let advisory_vuln = loaded_advisory
            .get_vulnerability("CVE-2024-28111", &ctx.db)
            .await?;
        assert!(advisory_vuln.is_some());

        let advisory_vuln = advisory_vuln.unwrap();
        let scores = advisory_vuln.cvss3_scores(&ctx.db).await?;
        assert_eq!(1, scores.len());

        let score = scores[0];
        assert_eq!(
            score.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn divine_purls(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());

        let (cve, digests): (Cve, _) = document("cve/CVE-2024-26308.json").await?;

        let loader = CveLoader::new(&graph);
        loader
            .load(("file", "CVE-2024-26308.json"), cve, &digests)
            .await?;

        let purl = graph
            .get_package(
                &Purl::from_str("pkg:maven/org.apache.commons/commons-compress")?,
                &ctx.db,
            )
            .await?;

        assert!(purl.is_some());

        let purl = purl.unwrap();
        let purl = purl.base_purl;

        assert_eq!(purl.r#type, "maven");
        assert_eq!(purl.namespace, Some("org.apache.commons".to_string()));
        assert_eq!(purl.name, "commons-compress");

        Ok(())
    }
}
