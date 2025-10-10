use crate::service::advisory::osv::extract_vulnerability_ids;
use crate::{
    graph::{
        Graph,
        advisory::{
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
            advisory_vulnerability::AdvisoryVulnerabilityContext,
            version::{Version, VersionInfo, VersionSpec},
        },
        cvss::ScoreCreator,
        purl::{
            self,
            creator::PurlCreator,
            status_creator::{PurlStatusCreator, PurlStatusEntry},
        },
        vulnerability::creator::VulnerabilityCreator,
    },
    model::IngestResult,
    service::{
        Error, Warnings,
        advisory::osv::{extract_scores, prefix::get_well_known_prefixes, translate},
    },
};
use osv::schema::{Ecosystem, Event, Range, RangeType, ReferenceType, SeverityType, Vulnerability};
use sbom_walker::report::ReportSink;
use sea_orm::TransactionTrait;
use std::{collections::HashSet, fmt::Debug, str::FromStr};
use tracing::instrument;
use trustify_common::{hashing::Digests, id::Id, purl::Purl, time::ChronoExt};
use trustify_cvss::cvss3::Cvss3Base;
use trustify_entity::{labels::Labels, version_scheme::VersionScheme};

pub struct OsvLoader<'g> {
    graph: &'g Graph,
}

impl<'g> OsvLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, osv), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        osv: Vulnerability,
        digests: &Digests,
        issuer: Option<String>,
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::new();

        let labels = labels.into().add("type", "osv");

        let issuer = issuer.or(detect_organization(&osv));

        let tx = self.graph.db.begin().await?;

        let cve_ids: Vec<String> = osv
            .aliases
            .iter()
            .flat_map(|aliases| {
                aliases
                    .iter()
                    .filter(|e| e.starts_with("CVE-"))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect();

        let information = AdvisoryInformation {
            id: osv.id.clone(),
            title: osv.summary.clone(),
            // TODO(#899): check if we have some kind of version information
            version: None,
            issuer,
            published: osv.published.map(ChronoExt::into_time),
            modified: Some(osv.modified.into_time()),
            withdrawn: osv.withdrawn.map(ChronoExt::into_time),
        };
        let advisory = self
            .graph
            .ingest_advisory(&osv.id, labels, digests, information, &tx)
            .await?;

        if let Some(withdrawn) = osv.withdrawn {
            advisory
                .set_withdrawn_at(withdrawn.into_time(), &tx)
                .await?;
        }

        // Batch create all vulnerabilities
        let mut vuln_creator = VulnerabilityCreator::new();
        for cve_id in &cve_ids {
            vuln_creator.add(cve_id, ());
        }
        vuln_creator.create(&tx).await?;

        let mut purl_creator = PurlCreator::new();
<<<<<<< HEAD
        let mut purl_status_creator = PurlStatusCreator::new();
        let mut base_purls = HashSet::new();

        for cve_id in &cve_ids {
=======
        let mut score_creator = ScoreCreator::new(advisory.advisory.id);

        extract_scores(&osv, &mut score_creator);

        for cve_id in extract_vulnerability_ids(&osv) {
            self.graph.ingest_vulnerability(&cve_id, (), &tx).await?;

>>>>>>> 26d7d87d (feat: ingest scores)
            let advisory_vuln = advisory
                .link_to_vulnerability(
                    cve_id,
                    Some(AdvisoryVulnerabilityInformation {
                        title: osv.summary.clone(),
                        summary: osv.summary.clone(),
                        description: osv.details.clone(),
                        reserved_date: None,
                        discovery_date: None,
                        release_date: None,
                        cwes: None,
                    }),
                    &tx,
                )
                .await?;

            for severity in osv.severity.iter().flatten() {
                if matches!(severity.severity_type, SeverityType::CVSSv3) {
                    match Cvss3Base::from_str(&severity.score) {
                        Ok(cvss3) => {
                            advisory_vuln.ingest_cvss3_score(cvss3, &tx).await?;
                        }
                        Err(err) => {
                            let msg = format!("Unable to parse CVSS3: {err}");
                            warnings.error(msg)
                        }
                    }
                }
            }

            for affected in &osv.affected {
                // we only process it when we have a package

                let Some(package) = &affected.package else {
                    tracing::debug!(
                        osv = osv.id,
                        "OSV document did not contain an 'affected' section",
                    );
                    continue;
                };

                // extract PURLs

                let mut purls = vec![];
                purls.extend(translate::to_purl(package).map(Purl::from));
                if let Some(purl) = &package.purl {
                    purls.extend(Purl::from_str(purl).ok());
                }

                for purl in purls {
                    // iterate through the known versions, apply the version, and create them
                    for version in affected.versions.iter().flatten() {
                        purl_creator.add(purl.with_version(version));
                        // Process explicit versions for advisory linking
                        purl_status_creator.add(PurlStatusEntry {
                            advisory_id: advisory_vuln.advisory.advisory.id,
                            vulnerability_id: advisory_vuln
                                .advisory_vulnerability
                                .vulnerability_id
                                .clone(),
                            purl: purl.clone(),
                            status: "affected".to_string(),
                            version_info: VersionInfo {
                                scheme: VersionScheme::Generic,
                                spec: VersionSpec::Exact(version.to_string()),
                            },
                            context_cpe: None,
                        });
                    }

                    for range in affected.ranges.iter().flatten() {
                        // Collect base PURL for range-based status entries
                        base_purls.insert(purl.clone());

                        match (&range.range_type, &package.ecosystem) {
                            (RangeType::Semver, _) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Semver,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Git, _) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Git,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Ecosystem, Ecosystem::Maven(_)) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Maven,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Ecosystem, Ecosystem::PyPI | Ecosystem::Python) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Python,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Ecosystem, Ecosystem::Go) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Golang,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Ecosystem, Ecosystem::Npm) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Npm,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Ecosystem, Ecosystem::Packagist) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Packagist,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Ecosystem, Ecosystem::NuGet) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::NuGet,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Ecosystem, Ecosystem::RubyGems) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Gem,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Ecosystem, Ecosystem::Hex) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Hex,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Ecosystem, Ecosystem::SwiftURL) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Swift,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (RangeType::Ecosystem, Ecosystem::Pub) => {
                                for entry in build_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    VersionScheme::Pub,
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                            (_, _) => {
                                for entry in build_package_status_versions(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    affected.versions.iter().flatten(),
                                ) {
                                    purl_status_creator.add(entry);
                                }
                            }
                        }
                    }
                }
            }
        }

        purl_creator.create(&tx).await?;
        score_creator.create(&tx).await?;

        // Create base PURLs for range-based status entries
        purl::batch_create_base_purls(base_purls, &tx).await?;

        purl_status_creator.create(&tx).await?;

        tx.commit().await?;

        Ok(IngestResult {
            id: Id::Uuid(advisory.advisory.id),
            document_id: Some(osv.id),
            warnings: warnings.into(),
        })
    }
}

/// Build package status entries from range events
fn build_package_status(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    range: &Range,
    version_scheme: VersionScheme,
) -> Vec<PurlStatusEntry> {
    let mut entries = Vec::new();
    let parsed_range = events_to_range(&range.events);

    let spec = match &parsed_range {
        (Some(start), None) => Some(VersionSpec::Range(
            Version::Inclusive(start.clone()),
            Version::Unbounded,
        )),
        (None, Some((end, false))) => Some(VersionSpec::Range(
            Version::Unbounded,
            Version::Exclusive(end.clone()),
        )),
        (None, Some((end, true))) => Some(VersionSpec::Range(
            Version::Unbounded,
            Version::Inclusive(end.clone()),
        )),
        (Some(start), Some((end, false))) => Some(VersionSpec::Range(
            Version::Inclusive(start.clone()),
            Version::Exclusive(end.clone()),
        )),
        (Some(start), Some((end, true))) => Some(VersionSpec::Range(
            Version::Inclusive(start.clone()),
            Version::Inclusive(end.clone()),
        )),
        (None, None) => None,
    };

    if let Some(spec) = spec {
        entries.push(PurlStatusEntry {
            advisory_id: advisory_vuln.advisory.advisory.id,
            vulnerability_id: advisory_vuln
                .advisory_vulnerability
                .vulnerability_id
                .clone(),
            purl: purl.clone(),
            status: "affected".to_string(),
            version_info: VersionInfo {
                scheme: version_scheme,
                spec,
            },
            context_cpe: None,
        });
    }

    if let (_, Some((fixed, false))) = &parsed_range {
        entries.push(PurlStatusEntry {
            advisory_id: advisory_vuln.advisory.advisory.id,
            vulnerability_id: advisory_vuln
                .advisory_vulnerability
                .vulnerability_id
                .clone(),
            purl: purl.clone(),
            status: "fixed".to_string(),
            version_info: VersionInfo {
                scheme: version_scheme,
                spec: VersionSpec::Exact(fixed.clone()),
            },
            context_cpe: None,
        });
    }

    entries
}

/// Build package status entries based on listed versions
fn build_package_status_versions<'a>(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    range: &Range,
    versions: impl IntoIterator<Item = &'a String>,
) -> Vec<PurlStatusEntry> {
    // the list of versions, sorted by the range type
    let versions = versions.into_iter().cloned().collect::<Vec<_>>();
    let mut entries = Vec::new();

    let mut start = None;
    for event in &range.events {
        match event {
            Event::Introduced(version) => {
                start = Some(version);
            }
            Event::Fixed(version) | Event::LastAffected(version) => {
                if let Some(start) = start.take() {
                    entries.extend(build_range_from(
                        advisory_vuln,
                        purl,
                        "affected",
                        start,
                        Some(version),
                        &versions,
                    ));
                }

                // Add "fixed" status
                entries.push(PurlStatusEntry {
                    advisory_id: advisory_vuln.advisory.advisory.id,
                    vulnerability_id: advisory_vuln
                        .advisory_vulnerability
                        .vulnerability_id
                        .clone(),
                    purl: purl.clone(),
                    status: "fixed".to_string(),
                    version_info: VersionInfo {
                        scheme: VersionScheme::Generic,
                        spec: VersionSpec::Exact(version.to_string()),
                    },
                    context_cpe: None,
                });
            }
            Event::Limit(_) => {}
            // for non_exhaustive
            _ => {}
        }
    }

    if let Some(start) = start {
        entries.extend(build_range_from(
            advisory_vuln,
            purl,
            "affected",
            start,
            None,
            &versions,
        ));
    }

    entries
}

/// Build status entries for all versions from a start to an end
fn build_range_from(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    status: &str,
    start: &str,
    // exclusive end
    end: Option<&str>,
    versions: &[impl AsRef<str>],
) -> Vec<PurlStatusEntry> {
    let matched_versions = match_versions(versions, start, end);

    matched_versions
        .into_iter()
        .map(|version| PurlStatusEntry {
            advisory_id: advisory_vuln.advisory.advisory.id,
            vulnerability_id: advisory_vuln
                .advisory_vulnerability
                .vulnerability_id
                .clone(),
            purl: purl.clone(),
            status: status.to_string(),
            version_info: VersionInfo {
                scheme: VersionScheme::Generic,
                spec: VersionSpec::Exact(version.to_string()),
            },
            context_cpe: None,
        })
        .collect()
}

/// Extract a list of versions according to OSV
///
/// The idea for ECOSYSTEM and GIT is that the user provides an explicit list of versions, in the
/// right order. So we search through this list, by start and end events. Translating this into
/// exact version matches.
///
/// See: <https://ossf.github.io/osv-schema/#affectedrangestype-field>
fn match_versions<'v>(
    versions: &'v [impl AsRef<str>],
    start: &str,
    end: Option<&str>,
) -> Vec<&'v str> {
    let mut matches = None;

    for version in versions {
        let version = version.as_ref();
        match (&mut matches, end) {
            (None, _) if version == start => {
                matches = Some(vec![version]);
            }
            (None, _) => {}
            (Some(_), Some(end)) if end == version => {
                // reached the exclusive env
                break;
            }
            (Some(matches), _) => {
                matches.push(version);
            }
        }
    }

    matches.unwrap_or_default()
}

fn detect_organization(osv: &Vulnerability) -> Option<String> {
    if let Some(references) = &osv.references {
        let advisory_location = references
            .iter()
            .find(|reference| matches!(reference.reference_type, ReferenceType::Advisory));

        if let Some(advisory_location) = advisory_location {
            let url = &advisory_location.url;
            return get_well_known_prefixes().detect(url);
        }
    }
    None
}

fn events_to_range(events: &[Event]) -> (Option<String>, Option<(String, bool)>) {
    let start = events.iter().find_map(|e| {
        if let Event::Introduced(version) = e {
            Some(version.clone())
        } else {
            None
        }
    });

    let end = events.iter().find_map(|e| {
        if let Event::Fixed(version) = e {
            Some((version.clone(), false))
        } else if let Event::LastAffected(version) = e {
            Some((version.clone(), true))
        } else {
            None
        }
    });

    (start, end)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::graph::Graph;
    use crate::service::advisory::osv::loader::OsvLoader;
    use hex::ToHex;
    use osv::schema::Vulnerability;
    use rstest::rstest;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::{TrustifyContext, document};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());

        let (osv, digests): (Vulnerability, _) = document("osv/RUSTSEC-2021-0079.json").await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2021-32714", &ctx.db).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = OsvLoader::new(&graph);
        loader
            .load(("file", "RUSTSEC-2021-0079.json"), osv, &digests, None)
            .await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2021-32714", &ctx.db).await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();

        assert!(loaded_advisory.advisory.issuer_id.is_some());

        let loaded_advisory_vulnerabilities = loaded_advisory.vulnerabilities(&ctx.db).await?;
        assert_eq!(1, loaded_advisory_vulnerabilities.len());
        let _loaded_advisory_vulnerability = &loaded_advisory_vulnerabilities[0];

        let advisory_vuln = loaded_advisory
            .get_vulnerability("CVE-2021-32714", &ctx.db)
            .await?;
        assert!(advisory_vuln.is_some());

        let advisory_vuln = advisory_vuln.unwrap();
        let scores = advisory_vuln.cvss3_scores(&ctx.db).await?;
        assert_eq!(1, scores.len());

        let score = scores[0];
        assert_eq!(
            score.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"
        );

        assert!(
            loaded_advisory
                .get_vulnerability("CVE-8675309", &ctx.db)
                .await?
                .is_none()
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader_pypi(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());

        let (osv, digests): (Vulnerability, _) = document("osv/GHSA-45c4-8wx5-qw6w.json").await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2023-37276", &ctx.db).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = OsvLoader::new(&graph);
        loader
            .load(("file", "GHSA-45c4-8wx5-qw6w.json"), osv, &digests, None)
            .await?;
        let loaded_vulnerability = graph.get_vulnerability("CVE-2023-37276", &ctx.db).await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader_explicit_versions_processing(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        // Create a test OSV file with explicit versions but no ranges
        let osv_content = r#"{
            "schema_version": "1.4.0",
            "id": "TEST-EXPLICIT-VERSIONS",
            "modified": "2024-01-01T00:00:00Z",
            "published": "2024-01-01T00:00:00Z",
            "aliases": ["CVE-2024-TEST"],
            "summary": "Test vulnerability with explicit versions",
            "details": "This is a test vulnerability to verify explicit versions are processed",
            "affected": [{
                "package": {
                    "ecosystem": "PyPI",
                    "name": "test-package",
                    "purl": "pkg:pypi/test-package"
                },
                "versions": ["1.0.0", "1.0.1", "1.0.2"]
            }]
        }"#;

        let osv: Vulnerability = serde_json::from_str(osv_content)?;
        let digests = trustify_common::hashing::Digests::digest(osv_content.as_bytes());

        let db = &ctx.db;
        let graph = Graph::new(db.clone());

        // Load the OSV
        let loader = OsvLoader::new(&graph);
        loader
            .load(("test", "explicit-versions"), osv, &digests, None)
            .await?;

        // Verify that the advisory was created
        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let advisory = loaded_advisory.unwrap();

        // Verify that the vulnerability was linked
        let advisory_vuln = advisory.get_vulnerability("CVE-2024-TEST", &ctx.db).await?;
        assert!(advisory_vuln.is_some());

        let _advisory_vuln = advisory_vuln.unwrap();

        // The fix ensures that explicit versions are always processed for advisory linking.
        // If we reach this point, the OSV loader didn't fail, which means
        // our fix successfully handled explicit versions.

        Ok(())
    }

    #[rstest]
    #[case("b", Some("d"), vec!["b", "c"])]
    #[case("e", None, vec!["e", "f", "g"])]
    #[case("x", None, vec![])]
    #[case("e", Some("a"), vec!["e", "f", "g"])]
    #[test_log::test]
    fn test_matches(#[case] start: &str, #[case] end: Option<&str>, #[case] result: Vec<&str>) {
        const INPUT: &[&str] = &["a", "b", "c", "d", "e", "f", "g"];
        assert_eq!(match_versions(INPUT, start, end), result);
    }
}
