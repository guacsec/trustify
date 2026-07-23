use crate::{
    graph::{
        Graph,
        advisory::{
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
            version::{Version, VersionInfo, VersionSpec},
        },
        cpe::CpeCreator,
        cpe_status_creator::{CpeStatusCreator, CpeStatusEntry},
        cvss::{ScoreCreator, best_base_score},
        purl::{
            self,
            status_creator::{PurlStatusCreator, PurlStatusEntry},
        },
        vulnerability::{VulnerabilityInformation, creator::VulnerabilityCreator},
    },
    model::IngestResult,
    service::{
        Error, Warnings,
        advisory::cve::{divination::divine_purl, extract_scores},
    },
};
use cve::{
    Cve, Timestamp,
    common::{Description, Product, Status, VersionRange},
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait};
use sea_query::Expr;
use serde_json::Value;
use std::str::FromStr;
use std::{collections::HashSet, fmt::Debug};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{cpe::Cpe, hashing::Digests};
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
            mut information,
        } = Self::extract_vuln_info(&cve);

        // Extract scores once, derive base_score from the same data
        let scores = extract_scores(&cve);
        information.base_score = best_base_score(&scores);

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
        score_creator.extend(scores);
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

        // Initialize batch creators for efficient status ingestion
        let mut purl_status_creator = PurlStatusCreator::new();
        let mut cpe_status_creator = CpeStatusCreator::new();
        let mut base_purls = HashSet::new();
        let mut cpes = HashSet::new();

        for product in affected {
            if let Some(purl) = divine_purl(product) {
                // Collect base PURL for batch creation
                base_purls.insert(purl.clone());

                // okay! we have a purl, now
                // sort out version bounds & status
                for version in &product.versions {
                    let (version_spec, version_type, status) = version_spec_and_status(version);

                    // Add package status entry to batch creator
                    purl_status_creator.add(PurlStatusEntry {
                        advisory_id: advisory_vuln.advisory.advisory.id,
                        vulnerability_id: advisory_vuln
                            .advisory_vulnerability
                            .vulnerability_id
                            .clone(),
                        purl: purl.clone(),
                        status: status_slug(status),
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

            // CPE-keyed applicability: every parseable CPE in `cpes` is
            // stored as a vendor/product identity (version normalized to
            // ANY), with the affected version(s) expressed via
            // version_range, mirroring the purl path above.
            for cpe_str in &product.cpes {
                let Ok(cpe) = Cpe::from_str(cpe_str) else {
                    continue;
                };
                let identity_cpe = cpe.with_any_version();

                if !product.versions.is_empty() {
                    for version in &product.versions {
                        let (version_spec, version_type, status) = version_spec_and_status(version);

                        // `unknown` has no row in the `status` table and
                        // carries no applicability information; skip it
                        // instead of failing the whole document.
                        if matches!(status, Status::Unknown) {
                            continue;
                        }

                        cpes.insert(identity_cpe.clone());
                        cpe_status_creator.add(CpeStatusEntry {
                            advisory_id: advisory_vuln.advisory.advisory.id,
                            vulnerability_id: advisory_vuln
                                .advisory_vulnerability
                                .vulnerability_id
                                .clone(),
                            cpe: identity_cpe.clone(),
                            status: status_slug(status),
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
                } else if let trustify_common::cpe::Component::Value(version) = cpe.version() {
                    // no explicit versions list: fall back to the concrete
                    // version carried by the CPE itself.
                    let status = product.default_status.clone().unwrap_or(Status::Unknown);

                    // `unknown` (also the fallback for a missing
                    // `defaultStatus`) has no row in the `status` table and
                    // carries no applicability information; skip it instead
                    // of failing the whole document.
                    if matches!(status, Status::Unknown) {
                        continue;
                    }

                    cpes.insert(identity_cpe.clone());
                    cpe_status_creator.add(CpeStatusEntry {
                        advisory_id: advisory_vuln.advisory.advisory.id,
                        vulnerability_id: advisory_vuln
                            .advisory_vulnerability
                            .vulnerability_id
                            .clone(),
                        cpe: identity_cpe.clone(),
                        status: status_slug(&status),
                        version_info: VersionInfo {
                            scheme: VersionScheme::Generic,
                            spec: VersionSpec::Exact(version),
                        },
                        context_cpe: None,
                    });
                }
            }
        }

        // Batch create base PURLs (without versions/qualifiers)
        purl::batch_create_base_purls(base_purls, tx).await?;

        // Batch create CPEs (vendor/product identity, version normalized to ANY)
        let mut cpe_creator = CpeCreator::new();
        for cpe in cpes {
            cpe_creator.add(cpe);
        }
        cpe_creator.create(tx).await?;

        // Batch create statuses
        purl_status_creator.create(tx).await?;
        cpe_status_creator.create(tx).await?;

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
                Vec::new(),
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
                // CNA-reported affected entries are the primary source; ADP
                // containers (e.g. CISA vulnrichment) supplement them with
                // additional CPE/version data, particularly for older CVEs
                // the CNA never annotated with CPEs.
                published
                    .containers
                    .cna
                    .affected
                    .iter()
                    .chain(
                        published
                            .containers
                            .adp
                            .iter()
                            .flat_map(|adp| adp.affected.iter()),
                    )
                    .collect(),
            ),
        };

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
                base_score: None,
            },
        }
    }
}

/// Maps a CVE 5.x `versions[]` entry to its version bound and CVE status.
///
/// Shared by both the purl and CPE ingestion paths so that any future change
/// to the version-range mapping stays consistent between the two.
fn version_spec_and_status(
    version: &cve::common::Version,
) -> (VersionSpec, Option<String>, &Status) {
    match version {
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
    }
}

/// Maps a CVE 5.x affected-version status to the trustify status slug.
fn status_slug(status: &Status) -> String {
    match status {
        Status::Affected => "affected".to_string(),
        Status::Unaffected => "not_affected".to_string(),
        Status::Unknown => "unknown".to_string(),
    }
}


struct VulnerabilityDetails<'a> {
    pub org_name: Option<&'a str>,
    pub descriptions: &'a Vec<Description>,
    pub assigned: Option<OffsetDateTime>,
    pub affected: Vec<&'a Product>,
    pub information: VulnerabilityInformation,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        graph::{
            Graph,
            cvss::best_base_score,
            vulnerability::BaseScore,
        },
        service::advisory::test::{AssertScore, assert_scores},
    };
    use hex::ToHex;
    use rstest::rstest;
    use std::str::FromStr;
    use test_context::test_context;
    use test_log::test;
    use time::macros::datetime;
    use trustify_common::purl::Purl;
    use trustify_entity::advisory_vulnerability_score::{ScoreType, Severity};
    use trustify_test_context::{TrustifyContext, document};

    #[rstest]
    #[case::no_scores(
        vec![],
        None
    )]
    #[case::single_v3_1(
        vec![("CVE-X", ScoreType::V3_1, 6.5, Severity::Medium)],
        Some(BaseScore { r#type: ScoreType::V3_1, score: 6.5, severity: Severity::Medium })
    )]
    #[case::higher_version_wins(
        vec![
            ("CVE-X", ScoreType::V3_1, 9.8, Severity::Critical),
            ("CVE-X", ScoreType::V4_0, 6.5, Severity::Medium),
        ],
        Some(BaseScore { r#type: ScoreType::V4_0, score: 6.5, severity: Severity::Medium })
    )]
    #[case::v3_1_preferred_over_v3_0(
        vec![
            ("CVE-X", ScoreType::V3_0, 9.8, Severity::Critical),
            ("CVE-X", ScoreType::V3_1, 6.5, Severity::Medium),
        ],
        Some(BaseScore { r#type: ScoreType::V3_1, score: 6.5, severity: Severity::Medium })
    )]
    #[case::higher_score_wins_within_same_version(
        vec![
            ("CVE-X", ScoreType::V3_1, 6.5, Severity::Medium),
            ("CVE-X", ScoreType::V3_1, 9.8, Severity::Critical),
        ],
        Some(BaseScore { r#type: ScoreType::V3_1, score: 9.8, severity: Severity::Critical })
    )]
    #[case::v2_score(
        vec![("CVE-X", ScoreType::V2_0, 7.5, Severity::High)],
        Some(BaseScore { r#type: ScoreType::V2_0, score: 7.5, severity: Severity::High })
    )]
    #[std::prelude::v1::test]
    fn best_base_score_cases(
        #[case] scores: Vec<(&str, ScoreType, f32, Severity)>,
        #[case] expected: Option<BaseScore>,
    ) {
        use crate::graph::cvss::ScoreInformation;

        let scores: Vec<_> = scores
            .into_iter()
            .map(|(id, r#type, score, severity)| ScoreInformation {
                vulnerability_id: id.to_string(),
                r#type,
                vector: String::new(),
                score,
                severity,
            })
            .collect();

        #[derive(Debug)]
        struct ApproxBaseScore(Option<BaseScore>);

        impl PartialEq for ApproxBaseScore {
            fn eq(&self, other: &Self) -> bool {
                match (&self.0, &other.0) {
                    (None, None) => true,
                    (Some(a), Some(b)) => {
                        a.r#type == b.r#type
                            && a.severity == b.severity
                            && (a.score - b.score).abs() < 0.1
                    }
                    _ => false,
                }
            }
        }

        assert_eq!(
            ApproxBaseScore(best_base_score(&scores)),
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

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn cve_loader_stores_cpe_status(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        use trustify_entity::{cpe as cpe_entity, cpe_status, status, version_range};

        let graph = Graph::new();

        let (cve, digests): (Cve, _) = document("cve/CVE-2099-0001.json").await?;

        let loader = CveLoader::new(&graph);
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(("file", "CVE-2099-0001.json"), cve.clone(), &digests, tx)
                    .await
            })
            .await?;

        let advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?
            .expect("advisory must be ingested");

        // Join cpe_status -> cpe -> status -> version_range so we can assert
        // on human-readable vendor/product/status/version_range values.
        let rows = cpe_status::Entity::find()
            .filter(cpe_status::Column::AdvisoryId.eq(advisory.advisory.id))
            .all(&ctx.db)
            .await?;

        // openssl: 1 exact version + 1 range = 2 rows; busybox: no `versions`
        // list, falls back to the concrete CPE version = 1 row. Total 3.
        assert_eq!(rows.len(), 3, "expected 3 cpe_status rows, got {rows:?}");

        let mut by_vendor: std::collections::HashMap<String, Vec<cpe_status::Model>> =
            std::collections::HashMap::new();
        for row in rows {
            let cpe = cpe_entity::Entity::find_by_id(row.cpe_id)
                .one(&ctx.db)
                .await?
                .expect("referenced cpe must exist");
            by_vendor
                .entry(cpe.vendor.clone().unwrap_or_default())
                .or_default()
                .push(row);

            // the identity cpe is version-normalized to ANY
            assert_eq!(
                cpe.version.as_deref(),
                Some("*"),
                "cpe_status.cpe_id must be version-ANY"
            );
        }

        let openssl_rows = by_vendor.get("openssl").expect("openssl rows");
        assert_eq!(openssl_rows.len(), 2);
        for row in openssl_rows {
            let st = status::Entity::find_by_id(row.status_id)
                .one(&ctx.db)
                .await?
                .expect("status must exist");
            assert_eq!(st.slug, "affected");

            let vr = version_range::Entity::find_by_id(row.version_range_id)
                .one(&ctx.db)
                .await?
                .expect("version_range must exist");
            assert!(
                vr.low_version.as_deref() == Some("0.9.8w")
                    || vr.low_version.as_deref() == Some("1.0.0"),
                "unexpected version_range: {vr:?}"
            );
        }

        let busybox_rows = by_vendor.get("busybox").expect("busybox rows");
        assert_eq!(busybox_rows.len(), 1);
        let busybox_row = &busybox_rows[0];
        let st = status::Entity::find_by_id(busybox_row.status_id)
            .one(&ctx.db)
            .await?
            .expect("status must exist");
        assert_eq!(st.slug, "affected");
        let vr = version_range::Entity::find_by_id(busybox_row.version_range_id)
            .one(&ctx.db)
            .await?
            .expect("version_range must exist");
        assert_eq!(vr.low_version.as_deref(), Some("1.19.4"));

        // Re-ingest idempotency: loading the same document again must not
        // create duplicate cpe_status rows (deterministic v5 UUIDs).
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(("file", "CVE-2099-0001.json"), cve, &digests, tx)
                    .await
            })
            .await?;

        let rows_after_reingest = cpe_status::Entity::find()
            .filter(cpe_status::Column::AdvisoryId.eq(advisory.advisory.id))
            .all(&ctx.db)
            .await?;
        assert_eq!(
            rows_after_reingest.len(),
            3,
            "re-ingest must not duplicate rows"
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn cve_loader_stores_cpe_status_from_adp_container(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        use trustify_entity::{cpe as cpe_entity, cpe_status, status, version_range};

        let graph = Graph::new();

        // cna.affected is empty; the ADP (vulnrichment-style) container is
        // the only source of CPE/version data for this record.
        let (cve, digests): (Cve, _) = document("cve/CVE-2099-0002.json").await?;

        let loader = CveLoader::new(&graph);
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(("file", "CVE-2099-0002.json"), cve, &digests, tx)
                    .await
            })
            .await?;

        let advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?
            .expect("advisory must be ingested");

        let rows = cpe_status::Entity::find()
            .filter(cpe_status::Column::AdvisoryId.eq(advisory.advisory.id))
            .all(&ctx.db)
            .await?;

        assert_eq!(rows.len(), 1, "expected 1 cpe_status row, got {rows:?}");

        let row = &rows[0];
        let cpe = cpe_entity::Entity::find_by_id(row.cpe_id)
            .one(&ctx.db)
            .await?
            .expect("referenced cpe must exist");
        assert_eq!(cpe.vendor.as_deref(), Some("denx"));
        assert_eq!(cpe.product.as_deref(), Some("u-boot"));
        assert_eq!(cpe.version.as_deref(), Some("*"));

        let st = status::Entity::find_by_id(row.status_id)
            .one(&ctx.db)
            .await?
            .expect("status must exist");
        assert_eq!(st.slug, "affected");

        let vr = version_range::Entity::find_by_id(row.version_range_id)
            .one(&ctx.db)
            .await?
            .expect("version_range must exist");
        assert_eq!(vr.low_version.as_deref(), Some("2019.04"));

        Ok(())
    }
}
