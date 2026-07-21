use crate::{
    graph::{
        Graph,
        advisory::{
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
            version::{Version, VersionInfo, VersionSpec},
        },
        cvss::ScoreCreator,
        purl::{
            self,
            status_creator::{PurlStatusCreator, PurlStatusEntry},
        },
        vulnerability::{VulnerabilityInformation, creator::VulnerabilityCreator},
    },
    model::IngestResult,
    service::{
        Error, Warnings,
        advisory::cve::{divination::divine_purl, extract_base_score, extract_scores},
    },
};
use cve::{
    Cve, Timestamp,
    common::{Description, Product, Status, VersionRange},
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait};
use sea_query::Expr;
use std::{collections::HashSet, fmt::Debug};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_entity::{labels::Labels, version_scheme::VersionScheme, vulnerability};

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

    #[instrument(skip(self, cve, tx), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        cve: Cve,
        digests: &Digests,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::new();
        let id = cve.id();
        let labels = labels.into().add("type", "cve");

        let VulnerabilityDetails {
            org_name,
            descriptions,
            assigned,
            affected,
            information,
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
        vuln_creator.create(tx).await?;

        let entries = Self::build_descriptions(descriptions);
        let english_description = Self::find_best_description_for_title(descriptions);

        let advisory = self
            .graph
            .ingest_advisory(id, labels, digests, advisory_info, tx)
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
                tx,
            )
            .await?;

        let mut score_creator = ScoreCreator::new(advisory.advisory.id);
        extract_scores(&cve, &mut score_creator);
        score_creator.create(tx).await?;

        // A CVE advisory is always the authoritative source for its vulnerability,
        // regardless of whether it carries CVSS scores.
        vulnerability::Entity::update_many()
            .col_expr(
                vulnerability::Column::AuthoritativeAdvisoryId,
                Expr::value(advisory.advisory.id),
            )
            .filter(vulnerability::Column::Id.eq(id))
            .exec(tx)
            .await?;

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
        purl::batch_create_base_purls(base_purls, tx).await?;

        // Batch create statuses
        purl_status_creator.create(tx).await?;

        // Manage vulnerability descriptions without needing to query the vulnerability
        Graph::drop_vulnerability_descriptions_for_advisory(advisory.advisory.id, tx).await?;
        Graph::add_vulnerability_descriptions(id, advisory.advisory.id, entries, tx).await?;

        Ok(IngestResult {
            id: advisory.advisory.id.to_string(),
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

        let base_score = extract_base_score(cve);

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
            },
        }
    }
}

struct VulnerabilityDetails<'a> {
    pub org_name: Option<&'a str>,
    pub descriptions: &'a Vec<Description>,
    pub assigned: Option<OffsetDateTime>,
    pub affected: Option<&'a Vec<Product>>,
    pub information: VulnerabilityInformation,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        graph::{Graph, vulnerability::BaseScore},
        service::advisory::{
            cve::extract_base_score,
            test::{AssertScore, assert_scores},
        },
    };
    use hex::ToHex;
    use rstest::rstest;
    use serde_json::{Value, json};
    use std::str::FromStr;
    use test_context::test_context;
    use test_log::test;
    use time::macros::datetime;
    use trustify_common::purl::Purl;
    use trustify_entity::advisory_vulnerability_score::{ScoreType, Severity};
    use trustify_test_context::{TrustifyContext, document};

    // Well-known CVSS vector strings used across tests.
    // Scores are computed by `calculated_base_score()`, not taken from JSON.
    const V31_MEDIUM: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"; // 6.5
    const V31_CRITICAL: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"; // 9.8
    const V30_HIGH: &str = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"; // 7.5
    const V2_HIGH: &str = "AV:N/AC:L/Au:N/C:P/I:P/A:P"; // 7.5
    const V4_CRITICAL: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"; // 9.3

    enum MetricSource {
        Cna,
        Adp,
    }

    use MetricSource::*;

    #[derive(Default)]
    struct CveBuilder {
        cna: Vec<Value>,
        adp: Vec<Value>,
    }

    impl CveBuilder {
        fn new() -> Self {
            Self::default()
        }

        fn add(mut self, source: MetricSource, metric: Value) -> Self {
            match source {
                Cna => self.cna.push(metric),
                Adp => self.adp.push(metric),
            }
            self
        }

        /// Adds a CVSS v2.0 metric with only a vector string.
        fn add_v2(self, source: MetricSource, vector: &str) -> Self {
            self.add(source, json!({ "cvssV2_0": { "vectorString": vector } }))
        }

        /// Adds a CVSS v3.0 metric with only a vector string.
        fn add_v3_0(self, source: MetricSource, vector: &str) -> Self {
            self.add(source, json!({ "cvssV3_0": { "vectorString": vector } }))
        }

        /// Adds a CVSS v3.1 metric with only a vector string.
        fn add_v3_1(self, source: MetricSource, vector: &str) -> Self {
            self.add(source, json!({ "cvssV3_1": { "vectorString": vector } }))
        }

        /// Adds a CVSS v4.0 metric with only a vector string.
        fn add_v4(self, source: MetricSource, vector: &str) -> Self {
            self.add(source, json!({ "cvssV4_0": { "vectorString": vector } }))
        }
    }

    impl From<CveBuilder> for Cve {
        fn from(builder: CveBuilder) -> Self {
            let adp: Vec<Value> = builder
                .adp
                .into_iter()
                .map(|m| {
                    json!({
                        "providerMetadata": { "orgId": "00000000-0000-0000-0000-000000000000" },
                        "metrics": [m]
                    })
                })
                .collect();

            serde_json::from_value(json!({
                "dataType": "CVE_RECORD",
                "dataVersion": "5.2",
                "cveMetadata": {
                    "cveId": "CVE-2024-00000",
                    "assignerOrgId": "00000000-0000-0000-0000-000000000000",
                    "state": "PUBLISHED"
                },
                "containers": {
                    "cna": {
                        "providerMetadata": { "orgId": "00000000-0000-0000-0000-000000000000" },
                        "descriptions": [{ "lang": "en", "value": "test" }],
                        "affected": [],
                        "references": [],
                        "metrics": builder.cna
                    },
                    "adp": adp
                }
            }))
            .expect("CveBuilder should produce valid CVE JSON")
        }
    }

    #[rstest]
    #[case::no_metrics(CveBuilder::new(), None)]
    #[case::single_v3_1_in_cna(
        CveBuilder::new().add_v3_1(Cna, V31_MEDIUM),
        Some(BaseScore { r#type: ScoreType::V3_1, score: 6.5, severity: Severity::Medium })
    )]
    #[case::cna_preferred_over_adp(
        CveBuilder::new().add_v3_1(Cna, V31_MEDIUM).add_v3_1(Adp, V31_CRITICAL),
        Some(BaseScore { r#type: ScoreType::V3_1, score: 6.5, severity: Severity::Medium })
    )]
    #[case::adp_used_when_cna_empty(
        CveBuilder::new().add_v3_1(Adp, V31_CRITICAL),
        Some(BaseScore { r#type: ScoreType::V3_1, score: 9.8, severity: Severity::Critical })
    )]
    #[case::higher_version_wins(
        CveBuilder::new().add_v3_1(Cna, V31_CRITICAL).add_v4(Cna, V4_CRITICAL),
        // v4.0 preferred over v3.1 regardless of score
        Some(BaseScore { r#type: ScoreType::V4_0, score: 9.3, severity: Severity::Critical })
    )]
    #[case::single_v3_0_in_cna(
        CveBuilder::new().add_v3_0(Cna, V30_HIGH),
        Some(BaseScore { r#type: ScoreType::V3_0, score: 7.5, severity: Severity::High })
    )]
    #[case::v3_1_preferred_over_v3_0(
        CveBuilder::new().add_v3_0(Cna, V30_HIGH).add_v3_1(Cna, V31_MEDIUM),
        Some(BaseScore { r#type: ScoreType::V3_1, score: 6.5, severity: Severity::Medium })
    )]
    #[case::higher_score_wins_within_same_version(
        CveBuilder::new().add_v3_1(Cna, V31_MEDIUM).add_v3_1(Cna, V31_CRITICAL),
        Some(BaseScore { r#type: ScoreType::V3_1, score: 9.8, severity: Severity::Critical })
    )]
    #[case::v2_severity_derived_from_score(
        CveBuilder::new().add_v2(Cna, V2_HIGH),
        Some(BaseScore { r#type: ScoreType::V2_0, score: 7.5, severity: Severity::High })
    )]
    // Metric with no vectorString → parsed as None
    #[case::missing_vector_string_yields_none(
        CveBuilder::new().add(Cna, json!({ "cvssV3_1": { "baseScore": 9.8, "baseSeverity": "CRITICAL" } })),
        None
    )]
    // Metric with invalid vectorString → FromStr fails → None
    #[case::invalid_vector_yields_none(
        CveBuilder::new().add_v3_1(Cna, "not-a-vector"),
        None
    )]
    #[std::prelude::v1::test]
    fn extract_base_score_cases(#[case] cve: impl Into<Cve>, #[case] expected: Option<BaseScore>) {
        #[derive(Debug)]
        struct ApproxBaseScore(Option<BaseScore>);

        impl PartialEq for ApproxBaseScore {
            fn eq(&self, other: &Self) -> bool {
                match (&self.0, &other.0) {
                    (None, None) => true,
                    (Some(a), Some(b)) => {
                        a.r#type == b.r#type
                            && a.severity == b.severity
                            && (a.score - b.score).abs() < 0.02
                    }
                    _ => false,
                }
            }
        }

        assert_eq!(
            ApproxBaseScore(extract_base_score(&cve.into())),
            ApproxBaseScore(expected)
        );
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn cve_loader(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();

        let (cve, digests): (Cve, _) = document("mitre/CVE-2024-28111.json").await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", &ctx.db).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = CveLoader::new(&graph);
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(("file", "CVE-2024-28111.json"), cve, &digests, tx)
                    .await
            })
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

        assert_scores(
            &ctx.db,
            loaded_advisory.advisory.id,
            [AssertScore {
                vulnerability_id: "CVE-2024-28111",
                r#type: ScoreType::V3_1,
                severity: Severity::Medium,
                vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                score: 6.5,
            }],
        )
        .await?;

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn divine_purls(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();

        let (cve, digests): (Cve, _) = document("cve/CVE-2024-26308.json").await?;

        let loader = CveLoader::new(&graph);
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(("file", "CVE-2024-26308.json"), cve, &digests, tx)
                    .await
            })
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
